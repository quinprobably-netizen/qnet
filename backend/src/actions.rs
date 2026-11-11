//! One-shot verbs. Each returns a JSON object (`ok: true` plus details) or an
//! `ActionErr`; `main` prints one line and sets the exit code.
//!
//! Everything here goes through `NetBackend`, so the safety rules (confirm
//! before overwriting manual DNS, active profile only, no-ops) are tested
//! against a fake and never need the live network.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::config::{Config, DEFAULT_CANARY};
use crate::dnsmodel::{detect_mode, manual_override, profile_pinned, Mode};
use crate::neigh::{self, Mac};
use crate::net::*;
use crate::pihole::{ApiError, Blocking, BlockingState};
use crate::threads::{ApiLiveness, ApiProbe};
use crate::util;

#[derive(Debug, Clone, PartialEq)]
pub struct ActionErr {
    pub code: String,
    pub detail: String,
    pub extra: Option<Value>,
}

impl ActionErr {
    pub fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
            extra: None,
        }
    }

    pub fn to_json(&self) -> Value {
        let mut o = Map::new();
        o.insert("ok".into(), Value::Bool(false));
        o.insert("error".into(), Value::String(self.code.clone()));
        if !self.detail.is_empty() {
            o.insert("detail".into(), Value::String(self.detail.clone()));
        }
        if let Some(Value::Object(extra)) = &self.extra {
            for (k, v) in extra {
                o.insert(k.clone(), v.clone());
            }
        }
        Value::Object(o)
    }
}

impl From<NetError> for ActionErr {
    fn from(e: NetError) -> Self {
        ActionErr::new(e.code(), e.detail())
    }
}

impl From<ApiError> for ActionErr {
    fn from(e: ApiError) -> Self {
        let code = match &e {
            ApiError::Auth(_) => "auth",
            ApiError::Tls(_) => "tls",
            ApiError::Unreachable(_) => "unreachable",
            ApiError::Other(_) => "api",
        };
        ActionErr::new(code, e.message().to_string())
    }
}

pub type ActionResult = Result<Value, ActionErr>;

/// Asks the Pi-hole's pinned web API whether its host is alive.
pub type ApiCheck = Arc<dyn Fn(IpAddr, &ApiProbe) -> ApiLiveness + Send + Sync>;
/// The MAC address behind an IPv4 neighbour on an interface.
pub type MacLookup = Arc<dyn Fn(Ipv4Addr, &str) -> Option<Mac> + Send + Sync>;

pub struct Ctx<'a> {
    pub be: &'a dyn NetBackend,
    pub cfg: &'a Config,
    pub state_dir: PathBuf,
    /// `$XDG_RUNTIME_DIR/qnet`: the DNS lock and the Wi-Fi throttles.
    pub runtime_dir: PathBuf,
    /// How long to wait for resolved to reflect a change.
    pub settle: Duration,
    /// Set by SIGTERM/SIGINT/SIGHUP; steps finish, the next one is skipped.
    pub term: Arc<AtomicBool>,
    /// Fixed "now" (unix seconds) for tests.
    pub now: Option<f64>,
    pub api_check: ApiCheck,
    pub mac_lookup: MacLookup,
}

impl<'a> Ctx<'a> {
    pub fn new(be: &'a dyn NetBackend, cfg: &'a Config) -> Self {
        Self {
            be,
            cfg,
            state_dir: util::state_dir(),
            runtime_dir: util::runtime_qnet_dir(),
            settle: Duration::from_secs(3),
            term: Arc::new(AtomicBool::new(false)),
            now: None,
            api_check: Arc::new(|addr, probe| {
                crate::threads::check_api(addr, probe, Duration::from_millis(1500))
            }),
            mac_lookup: Arc::new(neigh::mac_of),
        }
    }

    pub fn now(&self) -> f64 {
        self.now.unwrap_or_else(util::unix_now)
    }

    pub fn interrupted(&self) -> bool {
        self.term.load(Ordering::SeqCst)
    }

    fn check_not_interrupted(&self) -> Result<(), ActionErr> {
        if self.interrupted() {
            Err(ActionErr::new(
                "interrupted",
                "stopped before changing anything",
            ))
        } else {
            Ok(())
        }
    }

    /// Only one DNS-changing operation at a time, across processes: this
    /// verb, another verb, or the watcher's failover.
    fn lock_dns(&self) -> Result<util::FileLock, ActionErr> {
        match util::try_lock(&self.runtime_dir.join("dns.lock")) {
            Ok(Some(l)) => Ok(l),
            Ok(None) => Err(ActionErr::new(
                "busy",
                "another qnet operation is changing DNS right now",
            )),
            Err(e) => Err(ActionErr::new(
                "io",
                format!("could not take the DNS lock: {e}"),
            )),
        }
    }

    fn pihole(&self) -> Result<IpAddr, ActionErr> {
        self.cfg.pihole.as_ref().map(|p| p.address).ok_or_else(|| {
            ActionErr::new(
                "unconfigured",
                "no Pi-hole configured; run `qnet pihole setup <address>`",
            )
        })
    }

    fn canary(&self) -> String {
        self.cfg
            .pihole
            .as_ref()
            .map(|p| p.canary.clone())
            .unwrap_or_else(|| DEFAULT_CANARY.to_string())
    }
}

// ---- Undo state and the pinned-network record -----------------------------------

/// `prev-dns/<uuid>.json`: what the profile's DNS settings were before qnet
/// pinned it (for undo), and the gateway of the network it was pinned on (so
/// the failover only ever trusts the *same* router as a fallback).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PrevDns {
    pub uuid: String,
    pub saved_at: u64,
    #[serde(default)]
    pub ipv4_dns: Vec<String>,
    #[serde(default)]
    pub ipv4_ignore_auto_dns: bool,
    #[serde(default)]
    pub ipv6_dns: Vec<String>,
    #[serde(default)]
    pub ipv6_ignore_auto_dns: bool,
    /// Gateway recorded when the profile was pinned (or first seen healthy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// The gateway's MAC address when that was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    /// The file only carries the gateway; there is no undo state in it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gateway_only: bool,
}

impl PrevDns {
    fn is_automatic(&self) -> bool {
        self.ipv4_dns.is_empty()
            && self.ipv6_dns.is_empty()
            && !self.ipv4_ignore_auto_dns
            && !self.ipv6_ignore_auto_dns
    }

    /// The recorded gateway, if it parses.
    pub fn gateway_addr(&self) -> Option<Ipv4Addr> {
        self.gateway.as_deref().and_then(|g| g.parse().ok())
    }

    pub fn gateway_mac_addr(&self) -> Option<Mac> {
        self.gateway_mac.as_deref().and_then(neigh::parse_mac)
    }
}

fn prev_path(dir: &Path, uuid: &str) -> PathBuf {
    dir.join("prev-dns").join(format!("{uuid}.json"))
}

fn write_prev(dir: &Path, prev: &PrevDns) -> Result<(), ActionErr> {
    let bytes = serde_json::to_vec_pretty(prev).map_err(|e| ActionErr::new("io", e.to_string()))?;
    util::atomic_write(&prev_path(dir, &prev.uuid), &bytes, 0o600)
        .map_err(|e| ActionErr::new("io", format!("could not save undo state: {e}")))
}

/// Save the settings about to be replaced, with the gateway of the network
/// the pin happens on (None for a profile that is not in use).
pub fn save_prev(
    dir: &Path,
    uuid: &str,
    dns: &DnsSettings,
    gateway: Option<Ipv4Addr>,
) -> Result<(), ActionErr> {
    if !util::is_uuid(uuid) {
        return Err(ActionErr::new("invalid", "bad connection uuid"));
    }
    write_prev(
        dir,
        &PrevDns {
            uuid: uuid.to_string(),
            saved_at: util::unix_secs(),
            ipv4_dns: dns.v4_dns.iter().map(|a| a.to_string()).collect(),
            ipv4_ignore_auto_dns: dns.v4_ignore_auto,
            ipv6_dns: dns.v6_dns.iter().map(|a| a.to_string()).collect(),
            ipv6_ignore_auto_dns: dns.v6_ignore_auto,
            gateway: gateway.map(|g| g.to_string()),
            gateway_mac: None,
            gateway_only: false,
        },
    )
}

pub fn load_prev(dir: &Path, uuid: &str) -> Option<PrevDns> {
    if !util::is_uuid(uuid) {
        return None;
    }
    let t = std::fs::read_to_string(prev_path(dir, uuid)).ok()?;
    serde_json::from_str(&t).ok()
}

/// Record which router a pinned profile belongs to: its IP *and* MAC. Keeps
/// the undo state. Callers record this only after the Pi-hole's pinned web
/// API has answered on that link, so a look-alike network cannot get itself
/// trusted.
pub fn record_link_trust(
    dir: &Path,
    uuid: &str,
    gateway: Ipv4Addr,
    mac: Mac,
) -> Result<(), ActionErr> {
    if !util::is_uuid(uuid) {
        return Err(ActionErr::new("invalid", "bad connection uuid"));
    }
    let mut prev = load_prev(dir, uuid).unwrap_or_else(|| PrevDns {
        uuid: uuid.to_string(),
        saved_at: util::unix_secs(),
        ipv4_dns: vec![],
        ipv4_ignore_auto_dns: false,
        ipv6_dns: vec![],
        ipv6_ignore_auto_dns: false,
        gateway: None,
        gateway_mac: None,
        gateway_only: true,
    });
    prev.gateway = Some(gateway.to_string());
    prev.gateway_mac = Some(neigh::format_mac(&mac));
    write_prev(dir, &prev)
}

// ---- "Automatic is my choice" ----------------------------------------------------

fn auto_path(dir: &Path) -> PathBuf {
    dir.join("auto-dns.json")
}

/// Profiles whose Automatic DNS was chosen with `qnet dns auto`.
pub fn auto_choices(dir: &Path) -> HashSet<String> {
    std::fs::read_to_string(auto_path(dir))
        .ok()
        .and_then(|t| serde_json::from_str::<Vec<String>>(&t).ok())
        .map(|v| v.into_iter().filter(|u| util::is_uuid(u)).collect())
        .unwrap_or_default()
}

/// Record (or forget) that Automatic is the user's choice for `uuid`.
pub fn set_auto_choice(dir: &Path, uuid: &str, on: bool) -> Result<(), ActionErr> {
    if !util::is_uuid(uuid) {
        return Err(ActionErr::new("invalid", "bad connection uuid"));
    }
    let mut set = auto_choices(dir);
    let changed = if on {
        set.insert(uuid.to_string())
    } else {
        set.remove(uuid)
    };
    if !changed {
        return Ok(());
    }
    let mut list: Vec<String> = set.into_iter().collect();
    list.sort();
    let bytes = serde_json::to_vec(&list).map_err(|e| ActionErr::new("io", e.to_string()))?;
    util::atomic_write(&auto_path(dir), &bytes, 0o600)
        .map_err(|e| ActionErr::new("io", format!("could not save the choice: {e}")))
}

#[cfg(test)]
impl PrevDns {
    pub fn default_for_tests(uuid: &str) -> Self {
        PrevDns {
            uuid: uuid.to_string(),
            saved_at: 1,
            ipv4_dns: vec![],
            ipv4_ignore_auto_dns: false,
            ipv6_dns: vec![],
            ipv6_ignore_auto_dns: false,
            gateway: None,
            gateway_mac: None,
            gateway_only: true,
        }
    }
}

#[cfg(test)]
pub fn write_prev_for_tests(dir: &Path, prev: &PrevDns) {
    write_prev(dir, prev).unwrap();
}

fn remove_prev(dir: &Path, uuid: &str) {
    if util::is_uuid(uuid) {
        let _ = std::fs::remove_file(prev_path(dir, uuid));
    }
}

// ---- DNS verbs ---------------------------------------------------------------

struct Active {
    iface: String,
    ifindex: u32,
    uuid: String,
    gateway: Option<Ipv4Addr>,
    profile: Profile,
}

fn active_link(ctx: &Ctx<'_>) -> Result<Active, ActionErr> {
    let snap = ctx.be.snapshot(false)?;
    let dev = snap
        .primary_device()
        .filter(|d| d.is_up())
        .ok_or_else(|| ActionErr::new("nolink", "no active network connection"))?;
    let uuid = dev
        .active
        .as_ref()
        .map(|a| a.uuid.clone())
        .ok_or_else(|| ActionErr::new("nolink", "no active network connection"))?;
    let profile = ctx
        .be
        .profiles()?
        .into_iter()
        .find(|p| p.uuid == uuid)
        .ok_or_else(|| ActionErr::new("notfound", "the active connection has no saved profile"))?;
    Ok(Active {
        iface: dev.iface.clone(),
        ifindex: dev.ifindex,
        uuid,
        gateway: dev.gateway,
        profile,
    })
}

fn link_servers(ctx: &Ctx<'_>, a: &Active) -> Vec<IpAddr> {
    ctx.be
        .resolver(&[(a.ifindex, a.iface.clone())])
        .ok()
        .and_then(|r| r.link(a.ifindex).map(|l| l.servers.clone()))
        .unwrap_or_default()
}

/// Result of the closing DNS query.
struct Verified {
    via: Option<String>,
    answers: Vec<String>,
    error: Option<String>,
    /// The canary came back as 0.0.0.0: a blocking resolver answered.
    blocked: bool,
}

/// Wait for resolved to show the expected servers on the link, then send one
/// query through resolved and report which server it is now using.
fn verify(ctx: &Ctx<'_>, a: &Active, expect: &dyn Fn(&[IpAddr]) -> bool) -> Verified {
    let start = Instant::now();
    let mut settled = false;
    loop {
        if expect(&link_servers(ctx, a)) {
            settled = true;
            break;
        }
        if start.elapsed() >= ctx.settle {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut error = if settled {
        None
    } else {
        Some("systemd-resolved did not pick up the change in time".to_string())
    };
    let (answers, resolved_ok): (Vec<IpAddr>, bool) = match ctx.be.resolve_hostname(&ctx.canary()) {
        Ok(a) => (a, true),
        Err(e) => {
            error = Some(format!("test query failed: {}", e.detail()));
            (vec![], false)
        }
    };
    let blocked = !answers.is_empty() && answers.iter().all(|x| x.is_unspecified());
    if resolved_ok && !blocked && error.is_none() {
        error = Some("the canary was not blocked: is blocking paused, or is DNS not going through the Pi-hole?".into());
    }
    let via = ctx
        .be
        .resolver(&[(a.ifindex, a.iface.clone())])
        .ok()
        .and_then(|r| {
            r.link(a.ifindex)
                .and_then(|l| l.current.or_else(|| l.servers.first().copied()))
        })
        .map(|ip| ip.to_string());
    Verified {
        via,
        answers: answers.iter().map(|x| x.to_string()).collect(),
        error,
        blocked,
    }
}

/// Attach the verification to `base`. With `require_blocked`, `verifiedVia`
/// appears only when the canary was answered with 0.0.0.0 (and then
/// `blocked: true`); otherwise there is a `verifyError` instead.
fn with_verification(mut base: Map<String, Value>, v: Verified, require_blocked: bool) -> Value {
    if require_blocked {
        base.insert("blocked".into(), json!(v.blocked));
        if v.blocked {
            base.insert("verifiedVia".into(), json!(v.via.unwrap_or_default()));
        } else {
            base.insert(
                "verifyError".into(),
                json!(v
                    .error
                    .unwrap_or_else(|| "the canary was not blocked".into())),
            );
        }
        base.insert("answers".into(), json!(v.answers));
        return Value::Object(base);
    }
    base.insert("verifiedVia".into(), json!(v.via.unwrap_or_default()));
    base.insert("answers".into(), json!(v.answers));
    if let Some(e) = v.error {
        base.insert("verifyError".into(), json!(e));
    }
    Value::Object(base)
}

fn obj(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn confirm_err(profile: &Profile, pihole: Option<IpAddr>, what: &str) -> ActionErr {
    let servers: Vec<String> = profile
        .dns
        .manual_servers()
        .iter()
        .filter(|s| Some(**s) != pihole)
        .map(|s| s.to_string())
        .collect();
    let mut e = ActionErr::new(
        "confirm",
        format!(
            "{} has DNS servers set by hand ({}) that qnet did not write; {what} would replace them",
            profile.id,
            servers.join(", ")
        ),
    );
    e.extra = Some(json!({ "connection": profile.id, "servers": servers }));
    e
}

fn dns_supported(dns: &DnsSettings) -> Result<(), ActionErr> {
    if matches!(dns.v4_method.as_str(), "auto" | "manual") {
        Ok(())
    } else {
        Err(ActionErr::new(
            "unsupported",
            format!("IPv4 method \"{}\" cannot carry DNS servers", dns.v4_method),
        ))
    }
}

/// After a verified pin: record this network's router (IP and MAC), but only
/// once the Pi-hole's pinned web API has answered here.
fn record_trust(ctx: &Ctx<'_>, a: &Active) {
    let (Some(gw), Some(p)) = (a.gateway, ctx.cfg.pihole.as_ref()) else {
        return;
    };
    let probe = ApiProbe {
        port: 443,
        pin: p.tls_sha256,
    };
    if (ctx.api_check)(p.address, &probe) != ApiLiveness::Alive {
        return;
    }
    let Some(mac) = (ctx.mac_lookup)(gw, &a.iface) else {
        return;
    };
    let _ = record_link_trust(&ctx.state_dir, &a.uuid, gw, mac);
}

/// `qnet dns pihole`: pin the active connection's saved profile to the
/// Pi-hole and apply it. Success means the canary came back blocked through
/// the system resolver, and only then is `verifiedVia` reported.
pub fn dns_pihole(ctx: &Ctx<'_>, force: bool) -> ActionResult {
    let _lock = ctx.lock_dns()?;
    dns_pihole_locked(ctx, force)
}

fn interrupted_result(mut base: Map<String, Value>) -> Value {
    base.insert("interrupted".into(), json!(true));
    base.insert("blocked".into(), json!(false));
    base.insert(
        "verifyError".into(),
        json!("interrupted before the result could be checked"),
    );
    Value::Object(base)
}

fn dns_pihole_locked(ctx: &Ctx<'_>, force: bool) -> ActionResult {
    let pihole = ctx.pihole()?;
    let a = active_link(ctx)?;
    let servers = link_servers(ctx, &a);
    let mode = detect_mode(true, false, &servers, Some(&a.profile), Some(pihole));
    let expect = move |s: &[IpAddr]| !s.is_empty() && s.iter().all(|x| *x == pihole);
    let pinned = profile_pinned(&a.profile.dns, pihole);

    // Already exactly in this mode: pinned, and nothing else in use.
    if mode == Mode::Pihole && pinned && expect(&servers) {
        // Pinning is the opposite of "Automatic is my choice".
        set_auto_choice(&ctx.state_dir, &a.uuid, false)?;
        let v = verify(ctx, &a, &expect);
        if v.blocked {
            record_trust(ctx, &a);
        }
        return Ok(with_verification(
            obj(&[
                ("ok", json!(true)),
                ("noop", json!(true)),
                ("mode", json!("pihole")),
            ]),
            v,
            true,
        ));
    }
    dns_supported(&a.profile.dns)?;
    if manual_override(&a.profile.dns, pihole) && !force {
        return Err(confirm_err(&a.profile, Some(pihole), "pinning the Pi-hole"));
    }
    ctx.check_not_interrupted()?;
    let mut wrote_profile = false;
    if !pinned {
        // The router is recorded later, once the pinned API has answered.
        save_prev(&ctx.state_dir, &a.uuid, &a.profile.dns, None)?;
        ctx.be
            .set_profile_dns(&a.uuid, &a.profile.dns.pinned_to(pihole))?;
        wrote_profile = true;
    }
    set_auto_choice(&ctx.state_dir, &a.uuid, false)?;
    // A written profile is always applied, signal or not: half a step would
    // leave the saved and the running DNS disagreeing.
    ctx.be.reapply_saved(&a.iface)?;
    let base = obj(&[
        ("ok", json!(true)),
        ("mode", json!("pihole")),
        ("profileChanged", json!(wrote_profile)),
    ]);
    if ctx.interrupted() {
        return Ok(interrupted_result(base));
    }
    let v = verify(ctx, &a, &expect);
    if v.blocked {
        record_trust(ctx, &a);
    }
    Ok(with_verification(base, v, true))
}

/// `qnet dns auto`: back to automatic DNS on the active profile.
pub fn dns_auto(ctx: &Ctx<'_>, force: bool) -> ActionResult {
    let _lock = ctx.lock_dns()?;
    let pihole = ctx.cfg.pihole.as_ref().map(|p| p.address);
    let a = active_link(ctx)?;
    let servers = link_servers(ctx, &a);
    let mode = detect_mode(true, false, &servers, Some(&a.profile), pihole);
    let expect = move |s: &[IpAddr]| match pihole {
        Some(p) => !s.is_empty() && !s.contains(&p),
        None => true,
    };
    if mode == Mode::Auto {
        // Tapping Automatic while on Automatic still says "I want this",
        // which is what clears the "you did not choose this" warning.
        set_auto_choice(&ctx.state_dir, &a.uuid, true)?;
        let v = verify(ctx, &a, &|_| true);
        return Ok(with_verification(
            obj(&[
                ("ok", json!(true)),
                ("noop", json!(true)),
                ("mode", json!("auto")),
            ]),
            v,
            false,
        ));
    }
    dns_supported(&a.profile.dns)?;
    let has_foreign = a
        .profile
        .dns
        .manual_servers()
        .iter()
        .any(|s| Some(*s) != pihole);
    if has_foreign && !force {
        return Err(confirm_err(
            &a.profile,
            pihole,
            "switching to automatic DNS",
        ));
    }
    ctx.check_not_interrupted()?;
    let prev = load_prev(&ctx.state_dir, &a.uuid);
    // Restoring the saved settings only makes sense when they were
    // automatic; Automatic must mean automatic whatever came before.
    let restored = prev
        .as_ref()
        .is_some_and(|p| !p.gateway_only && p.is_automatic());
    // Written first, so the watcher, which reacts to the profile change, can
    // already see that this Automatic is on purpose.
    set_auto_choice(&ctx.state_dir, &a.uuid, true)?;
    ctx.be
        .set_profile_dns(&a.uuid, &a.profile.dns.automatic())?;
    ctx.be.reapply_saved(&a.iface)?;
    if restored {
        remove_prev(&ctx.state_dir, &a.uuid);
    }
    let base = obj(&[
        ("ok", json!(true)),
        ("mode", json!("auto")),
        ("restoredPrevious", json!(restored)),
    ]);
    if ctx.interrupted() {
        return Ok(interrupted_result(base));
    }
    let v = verify(ctx, &a, &expect);
    Ok(with_verification(base, v, false))
}

fn is_active_uuid(ctx: &Ctx<'_>, uuid: &str) -> Result<bool, ActionErr> {
    let snap = ctx.be.snapshot(false)?;
    Ok(snap
        .primary_device()
        .filter(|d| d.is_up())
        .and_then(|d| d.active.as_ref())
        .is_some_and(|a| a.uuid == uuid))
}

/// Pin one saved profile that is not in use: write it, do not apply it.
/// Returns the profile's name and whether anything changed.
fn pin_inactive(ctx: &Ctx<'_>, uuid: &str, force: bool) -> Result<(String, bool), ActionErr> {
    let pihole = ctx.pihole()?;
    let profile = ctx
        .be
        .profiles()?
        .into_iter()
        .find(|p| p.uuid == uuid)
        .ok_or_else(|| ActionErr::new("notfound", "no saved connection with that uuid"))?;
    if !matches!(profile.kind, ProfileKind::Wifi | ProfileKind::Ethernet) {
        return Err(ActionErr::new(
            "invalid",
            "only Wi-Fi and Ethernet profiles can be pinned",
        ));
    }
    if profile_pinned(&profile.dns, pihole) {
        set_auto_choice(&ctx.state_dir, uuid, false)?;
        return Ok((profile.id, false));
    }
    dns_supported(&profile.dns)?;
    if manual_override(&profile.dns, pihole) && !force {
        return Err(confirm_err(&profile, Some(pihole), "pinning the Pi-hole"));
    }
    ctx.check_not_interrupted()?;
    save_prev(&ctx.state_dir, uuid, &profile.dns, None)?;
    set_auto_choice(&ctx.state_dir, uuid, false)?;
    ctx.be
        .set_profile_dns(uuid, &profile.dns.pinned_to(pihole))?;
    Ok((profile.id, true))
}

fn verify_current_link(ctx: &Ctx<'_>) -> Verified {
    match active_link(ctx) {
        Ok(a) => verify(ctx, &a, &|_| true),
        Err(_) => Verified {
            via: None,
            answers: vec![],
            error: Some("no active link to test".into()),
            blocked: false,
        },
    }
}

/// `qnet dns pin <uuid>`: apply the Pi-hole settings to a saved profile.
/// An inactive profile is only written; the active one is pinned like
/// `dns pihole`.
pub fn dns_pin(ctx: &Ctx<'_>, uuid: &str, force: bool) -> ActionResult {
    if !util::is_uuid(uuid) {
        return Err(ActionErr::new("invalid", "not a connection uuid"));
    }
    ctx.pihole()?;
    let _lock = ctx.lock_dns()?;
    if is_active_uuid(ctx, uuid)? {
        return dns_pihole_locked(ctx, force);
    }
    let (name, changed) = pin_inactive(ctx, uuid, force)?;
    if !changed {
        return Ok(json!({"ok": true, "noop": true, "mode": "pihole", "connection": name}));
    }
    // The pinned profile is not in use, so the query still goes through
    // whatever the active link uses; report that honestly.
    Ok(with_verification(
        obj(&[
            ("ok", json!(true)),
            ("mode", json!("pihole")),
            ("connection", json!(name)),
            ("applied", json!(false)),
        ]),
        verify_current_link(ctx),
        false,
    ))
}

/// `qnet dns pin <uuid> [<uuid>...]`. One uuid behaves exactly like
/// `dns_pin`. Several are pinned independently (one refusing does not stop
/// the others) and reported together, with one closing query.
pub fn dns_pin_many(ctx: &Ctx<'_>, uuids: &[String], force: bool) -> ActionResult {
    if uuids.len() == 1 {
        return dns_pin(ctx, &uuids[0], force);
    }
    ctx.pihole()?;
    let _lock = ctx.lock_dns()?;
    let mut results: Vec<Value> = Vec::new();
    let mut failed = 0usize;
    let mut applied_active = false;
    for u in uuids {
        let one: ActionResult = if ctx.interrupted() {
            Err(ActionErr::new("interrupted", "stopped before this profile"))
        } else if !util::is_uuid(u) {
            Err(ActionErr::new("invalid", "not a connection uuid"))
        } else if is_active_uuid(ctx, u)? {
            applied_active = true;
            dns_pihole_locked(ctx, force)
        } else {
            pin_inactive(ctx, u, force).map(|(name, changed)| {
                json!({"ok": true, "connection": name, "noop": !changed, "applied": false})
            })
        };
        match one {
            Ok(Value::Object(mut o)) => {
                o.insert("uuid".into(), json!(u));
                results.push(Value::Object(o));
            }
            Ok(other) => results.push(other),
            Err(e) => {
                failed += 1;
                let mut j = e.to_json();
                if let Some(o) = j.as_object_mut() {
                    o.insert("uuid".into(), json!(u));
                }
                results.push(j);
            }
        }
    }
    let mut summary = obj(&[("ok", json!(failed == 0)), ("results", json!(results))]);
    if !applied_active && !ctx.interrupted() {
        let v = verify_current_link(ctx);
        summary.insert("verifiedVia".into(), json!(v.via.unwrap_or_default()));
        if let Some(e) = v.error {
            summary.insert("verifyError".into(), json!(e));
        }
    }
    if failed == 0 {
        Ok(Value::Object(summary))
    } else {
        let mut e = ActionErr::new(
            "partial",
            format!("{failed} of {} profiles could not be pinned", uuids.len()),
        );
        e.extra = Some(json!({ "results": summary.remove("results") }));
        Err(e)
    }
}

// ---- Pi-hole verbs --------------------------------------------------------------

pub trait BlockingApi {
    fn set_blocking(&mut self, enabled: bool, timer: Option<u64>) -> Result<Blocking, ApiError>;
}

impl BlockingApi for crate::pihole::Pihole {
    fn set_blocking(&mut self, enabled: bool, timer: Option<u64>) -> Result<Blocking, ApiError> {
        crate::pihole::Pihole::set_blocking(self, enabled, timer)
    }
}

fn blocking_json(b: &Blocking) -> Value {
    json!({
        "ok": true,
        "blocking": b.state.as_str(),
        "timer": b.timer.map(|t| t.round() as u64),
    })
}

pub fn pihole_pause(api: &mut dyn BlockingApi, secs: u64) -> ActionResult {
    if !(1..=3600).contains(&secs) {
        return Err(ActionErr::new(
            "invalid",
            "pause length must be 1-3600 seconds",
        ));
    }
    let b = api.set_blocking(false, Some(secs))?;
    if b.state != BlockingState::Disabled {
        return Err(ActionErr::new("api", "Pi-hole did not pause blocking"));
    }
    Ok(blocking_json(&b))
}

pub fn pihole_resume(api: &mut dyn BlockingApi) -> ActionResult {
    let b = api.set_blocking(true, None)?;
    if b.state != BlockingState::Enabled {
        return Err(ActionErr::new("api", "Pi-hole did not resume blocking"));
    }
    Ok(blocking_json(&b))
}

// ---- Wi-Fi verbs ------------------------------------------------------------------

/// WPA-PSK: 8-63 printable ASCII characters or exactly 64 hex digits.
/// SAE accepts any printable string up to 128 characters.
pub fn validate_passphrase(pass: &str, sec: &Security) -> Result<(), ActionErr> {
    let printable = |c: char| !c.is_control();
    match sec {
        Security::Psk => {
            let ascii = pass.chars().all(|c| (' '..='~').contains(&c));
            let n = pass.chars().count();
            let hex64 = n == 64 && pass.chars().all(|c| c.is_ascii_hexdigit());
            if hex64 || (ascii && (8..=63).contains(&n)) {
                Ok(())
            } else {
                Err(ActionErr::new(
                    "badpass",
                    "a WPA passphrase is 8-63 characters",
                ))
            }
        }
        Security::Sae => {
            let n = pass.chars().count();
            if (1..=128).contains(&n) && pass.chars().all(printable) {
                Ok(())
            } else {
                Err(ActionErr::new(
                    "badpass",
                    "the passphrase must be 1-128 printable characters",
                ))
            }
        }
        _ => Ok(()),
    }
}

pub fn wifi_connect(ctx: &Ctx<'_>, ap_path: &str, passphrase: Option<&str>) -> ActionResult {
    if !util::is_ap_path(ap_path) {
        return Err(ActionErr::new("invalid", "not an access point path"));
    }
    let snap = ctx.be.snapshot(true)?;
    if !snap.wifi_enabled {
        return Err(ActionErr::new("radio", "Wi-Fi is turned off"));
    }
    let dev = snap
        .wifi_device()
        .ok_or_else(|| ActionErr::new("nowifi", "no Wi-Fi device"))?;
    let ap = dev
        .wifi
        .as_ref()
        .and_then(|w| w.aps.iter().find(|a| a.path == ap_path))
        .ok_or_else(|| ActionErr::new("notfound", "that network is no longer in range"))?
        .clone();
    let sec = ap.security();
    let (name, hidden) = display_ssid(&ap.ssid);
    if hidden {
        return Err(ActionErr::new(
            "hidden",
            "hidden networks cannot be joined from the list",
        ));
    }
    match sec {
        Security::Enterprise => {
            return Err(ActionErr::new("enterprise", "802.1X networks need nmtui"))
        }
        Security::Wep => {
            return Err(ActionErr::new(
                "unsupported",
                "WEP networks are not supported",
            ))
        }
        _ => {}
    }
    let pass = passphrase.filter(|p| !p.is_empty());
    if let Some(p) = pass {
        validate_passphrase(p, &sec)?;
    }
    let known = ctx
        .be
        .profiles()?
        .into_iter()
        .filter(|p| p.kind == ProfileKind::Wifi && p.ssid.as_deref() == Some(&ap.ssid[..]))
        .max_by_key(|p| p.timestamp);
    match known {
        Some(p) => {
            let new_pass = pass.filter(|_| matches!(sec, Security::Psk | Security::Sae));
            ctx.be
                .activate_known(&p.uuid, &dev.iface, ap_path, new_pass)?;
            Ok(json!({"ok": true, "connection": p.id, "known": true}))
        }
        None => {
            if matches!(sec, Security::Psk | Security::Sae) && pass.is_none() {
                return Err(ActionErr::new("badpass", "a passphrase is required"));
            }
            ctx.be.connect_new(&dev.iface, &ap, &sec, pass)?;
            Ok(json!({"ok": true, "connection": name, "known": false}))
        }
    }
}

pub fn wifi_down(ctx: &Ctx<'_>) -> ActionResult {
    let snap = ctx.be.snapshot(false)?;
    let dev = snap
        .devices
        .iter()
        .find(|d| d.kind == DeviceKind::Wifi && d.is_up())
        .ok_or_else(|| ActionErr::new("nolink", "Wi-Fi is not connected"))?;
    ctx.be.disconnect(&dev.iface)?;
    Ok(json!({"ok": true}))
}

pub fn wifi_forget(ctx: &Ctx<'_>, uuid: &str) -> ActionResult {
    if !util::is_uuid(uuid) {
        return Err(ActionErr::new("invalid", "not a connection uuid"));
    }
    let profile = ctx
        .be
        .profiles()?
        .into_iter()
        .find(|p| p.uuid == uuid)
        .ok_or_else(|| ActionErr::new("notfound", "no saved connection with that uuid"))?;
    if profile.kind != ProfileKind::Wifi {
        return Err(ActionErr::new(
            "invalid",
            "only saved Wi-Fi networks can be forgotten here",
        ));
    }
    ctx.be.forget(uuid)?;
    Ok(json!({"ok": true, "connection": profile.id}))
}

/// Two scans closer together than this are refused (the card is fragile).
pub const SCAN_MIN_GAP_S: f64 = 15.0;
/// Two radio switches closer together than this are refused.
pub const RADIO_MIN_GAP_S: f64 = 10.0;

fn stamp_path(ctx: &Ctx<'_>, name: &str) -> PathBuf {
    ctx.runtime_dir.join(name)
}

/// When a guarded operation last happened (unix seconds), from a small file
/// shared by every qnet process.
fn read_stamp(path: &Path) -> Option<f64> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    v.get("at")?.as_f64().filter(|t| t.is_finite())
}

fn write_stamp(path: &Path, at: f64) {
    if let Some(dir) = path.parent() {
        if util::ensure_private_dir(dir).is_err() {
            return;
        }
    }
    // Best effort: failing to note it only weakens the guard.
    let _ = util::atomic_write(path, json!({ "at": at }).to_string().as_bytes(), 0o600);
}

fn too_soon(wait_s: f64) -> ActionErr {
    let retry = wait_s.ceil().max(1.0) as u64;
    let mut e = ActionErr::new("too-soon", format!("try again in {retry} s"));
    e.extra = Some(json!({ "retryInS": retry }));
    e
}

/// `qnet wifi scan [--if-stale <secs>]`.
///
/// A scan is refused as `too-soon` unless both NM's `LastScan` and qnet's own
/// last request are at least 15 s old. With `if_stale`, nothing at all is done
/// (`skipped`) while either is younger than that many seconds; the 15 s rule
/// still applies on top.
pub fn wifi_scan(ctx: &Ctx<'_>, if_stale: Option<u64>) -> ActionResult {
    let snap = ctx.be.snapshot(false)?;
    if !snap.wifi_enabled {
        return Err(ActionErr::new("radio", "Wi-Fi is turned off"));
    }
    let dev = snap
        .wifi_device()
        .ok_or_else(|| ActionErr::new("nowifi", "no Wi-Fi device"))?;
    let own_path = stamp_path(ctx, "scan");
    let nm_age = dev
        .wifi
        .as_ref()
        .and_then(|w| w.last_scan_age_ms)
        .map(|ms| ms as f64 / 1000.0);
    let own_age = read_stamp(&own_path).map(|t| (ctx.now() - t).max(0.0));
    // The most recent scan from either source; None means never.
    let youngest = match (nm_age, own_age) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    if let (Some(limit), Some(age)) = (if_stale, youngest) {
        if age < limit as f64 {
            return Ok(json!({"ok": true, "skipped": true, "lastScanAgeS": age as u64}));
        }
    }
    if let Some(age) = youngest {
        if age < SCAN_MIN_GAP_S {
            return Err(too_soon(SCAN_MIN_GAP_S - age));
        }
    }
    ctx.be.request_scan(&dev.iface)?;
    write_stamp(&own_path, ctx.now());
    Ok(json!({"ok": true, "scanned": true}))
}

pub fn wifi_radio(ctx: &Ctx<'_>, on: bool) -> ActionResult {
    let snap = ctx.be.snapshot(false)?;
    if on && !snap.hw_enabled {
        return Err(ActionErr::new("rfkill", "the hardware radio switch is off"));
    }
    if snap.wifi_enabled == on {
        return Ok(json!({"ok": true, "noop": true, "wifiEnabled": on}));
    }
    // Flipping the radio of a fragile card back and forth is how it dies.
    let path = stamp_path(ctx, "radio");
    if let Some(at) = read_stamp(&path) {
        let since = (ctx.now() - at).max(0.0);
        if since < RADIO_MIN_GAP_S {
            return Err(too_soon(RADIO_MIN_GAP_S - since));
        }
    }
    ctx.be.set_wifi_enabled(on)?;
    write_stamp(&path, ctx.now());
    Ok(json!({"ok": true, "wifiEnabled": on}))
}

// ---- Captive portal ------------------------------------------------------------------

pub const DEFAULT_PORTAL_URL: &str = "http://neverssl.com";

pub fn portal_url(snap: &NetSnapshot) -> String {
    let u = snap.check_uri.as_str();
    if snap.connectivity == Connectivity::Portal
        && (u.starts_with("http://") || u.starts_with("https://"))
    {
        u.to_string()
    } else {
        DEFAULT_PORTAL_URL.to_string()
    }
}

/// A normal (incognito) browser window with a throwaway profile: a captive
/// portal page is an untrusted web page and should look and behave like one.
pub fn portal_args(url: &str, dir: &Path) -> Vec<String> {
    vec![
        format!("--user-data-dir={}", dir.display()),
        "--incognito".into(),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        url.to_string(),
    ]
}

/// A fresh 0700 directory that did not exist before.
pub fn private_temp_dir(base: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    for _ in 0..8 {
        let mut r = [0u8; 8];
        util::urandom(&mut r)?;
        let name: String = r.iter().map(|b| format!("{b:02x}")).collect();
        let dir = base.join(format!("qnet-portal-{name}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "no free temp name",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fake::*;

    #[test]
    fn error_json_shape() {
        let mut e = ActionErr::new("confirm", "needs --force");
        e.extra = Some(json!({"servers": ["9.9.9.9"]}));
        let v = e.to_json();
        assert_eq!(v["ok"], false);
        assert_eq!(v["error"], "confirm");
        assert_eq!(v["detail"], "needs --force");
        assert_eq!(v["servers"][0], "9.9.9.9");
        assert_eq!(
            ActionErr::new("x", "").to_json(),
            json!({"ok": false, "error": "x"})
        );
    }

    #[test]
    fn prev_dns_roundtrip_and_uuid_guard() {
        let dir = tempfile::tempdir().unwrap();
        let dns = DnsSettings {
            v4_method: "auto".into(),
            v4_dns: vec!["9.9.9.9".parse().unwrap()],
            v4_ignore_auto: true,
            v6_method: "auto".into(),
            v6_dns: vec![],
            v6_ignore_auto: false,
        };
        let u = "21307067-f47b-43ea-8c9c-2c746454b2bb";
        save_prev(dir.path(), u, &dns, Some("192.168.1.1".parse().unwrap())).unwrap();
        let p = load_prev(dir.path(), u).unwrap();
        assert_eq!(p.ipv4_dns, vec!["9.9.9.9"]);
        assert!(p.ipv4_ignore_auto_dns && !p.is_automatic());
        assert_eq!(p.gateway_addr(), Some("192.168.1.1".parse().unwrap()));
        assert!(save_prev(dir.path(), "../evil", &dns, None).is_err());
        assert!(load_prev(dir.path(), "../evil").is_none());
        remove_prev(dir.path(), u);
        assert!(load_prev(dir.path(), u).is_none());
    }

    #[test]
    fn passphrase_rules() {
        assert!(validate_passphrase("12345678", &Security::Psk).is_ok());
        assert!(validate_passphrase("1234567", &Security::Psk).is_err());
        assert!(
            validate_passphrase(&"a".repeat(64), &Security::Psk).is_ok(),
            "64 hex"
        );
        assert!(validate_passphrase(&"g".repeat(64), &Security::Psk).is_err());
        assert!(validate_passphrase(&"a".repeat(63), &Security::Psk).is_ok());
        assert!(validate_passphrase("pass\nword1", &Security::Psk).is_err());
        assert!(validate_passphrase("pässwörd123", &Security::Psk).is_err());
        assert!(validate_passphrase("x", &Security::Sae).is_ok());
        assert!(validate_passphrase("tab\tbed", &Security::Sae).is_err());
        assert!(validate_passphrase("", &Security::Sae).is_err());
    }

    #[test]
    fn portal_choices() {
        let mut snap = crate::dnsmodel::fixtures::snapshot(vec![]);
        assert_eq!(portal_url(&snap), DEFAULT_PORTAL_URL);
        snap.connectivity = Connectivity::Portal;
        assert_eq!(portal_url(&snap), "http://ping.omacom.io/nm-check.txt");
        snap.check_uri = "javascript:alert(1)".into();
        assert_eq!(portal_url(&snap), DEFAULT_PORTAL_URL);
        snap.check_uri.clear();
        assert_eq!(portal_url(&snap), DEFAULT_PORTAL_URL);
    }

    #[test]
    fn portal_args_are_plain_argv() {
        let a = portal_args(
            "http://x.test/a b;rm",
            Path::new("/run/user/1000/qnet-portal-ab"),
        );
        assert_eq!(a[0], "--user-data-dir=/run/user/1000/qnet-portal-ab");
        assert!(
            a.contains(&"--incognito".to_string()),
            "a normal incognito window"
        );
        assert!(
            !a.iter().any(|x| x.starts_with("--app")),
            "not an app-mode window"
        );
        assert_eq!(a.last().unwrap(), "http://x.test/a b;rm");
        assert_eq!(a.len(), 5);
    }

    #[test]
    fn private_temp_dir_is_0700_and_unique() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let a = private_temp_dir(base.path()).unwrap();
        let b = private_temp_dir(base.path()).unwrap();
        assert_ne!(a, b);
        let mode = std::fs::metadata(&a).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    // -- DNS verbs against the fake -----------------------------------------

    const MAC: Mac = [0x3c, 0x52, 0xa1, 0x00, 0x11, 0x22];

    /// A context on temp dirs, with the Pi-hole's web API "alive" and the
    /// router's MAC known, and no real network anywhere.
    fn ctx<'a>(be: &'a FakeNet, cfg: &'a Config, dir: &Path) -> Ctx<'a> {
        Ctx {
            be,
            cfg,
            state_dir: dir.to_path_buf(),
            runtime_dir: dir.join("run"),
            settle: Duration::from_millis(200),
            term: Arc::new(AtomicBool::new(false)),
            now: Some(1_800_000_000.0),
            api_check: Arc::new(|_, _| ApiLiveness::Alive),
            mac_lookup: Arc::new(|_, _| Some(MAC)),
        }
    }

    #[test]
    fn pihole_when_already_pinned_is_a_noop_with_no_writes() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["noop"], true);
        assert_eq!(r["verifiedVia"], "192.168.1.153");
        assert_eq!(
            be.writes(),
            0,
            "tapping the current mode must change nothing: {:?}",
            be.calls()
        );
    }

    #[test]
    fn auto_from_pinned_clears_and_verifies_via_router() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["mode"], "auto");
        assert_eq!(r["verifiedVia"], "192.168.1.1");
        assert!(be.profile(U_WIFI).dns.is_automatic());
        assert!(be.calls().iter().any(|c| c == "reapply_saved wlp7s0"));
        // Second tap: no-op.
        let before = be.writes();
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["noop"], true);
        assert_eq!(be.writes(), before);
    }

    #[test]
    fn pihole_after_auto_saves_undo_state_then_pins() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["mode"], "pihole");
        assert_eq!(r["verifiedVia"], "192.168.1.153");
        assert_eq!(r["profileChanged"], true);
        let p = be.profile(U_WIFI);
        assert_eq!(
            p.dns.v4_dns,
            vec!["192.168.1.153".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert!(p.dns.v4_ignore_auto && p.dns.v6_ignore_auto && p.dns.v6_dns.is_empty());
        // Undo state holds what was there before pinning (automatic).
        let prev = load_prev(dir.path(), U_WIFI).unwrap();
        assert!(prev.is_automatic());
    }

    #[test]
    fn manual_dns_needs_force() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_profile_dns_direct(
            U_WIFI,
            DnsSettings {
                v4_method: "auto".into(),
                v4_dns: vec!["9.9.9.9".parse().unwrap()],
                v4_ignore_auto: true,
                v6_method: "auto".into(),
                v6_dns: vec![],
                v6_ignore_auto: true,
            },
        );
        be.apply_saved_to_link();
        let cfg = fake_cfg();
        let before = be.writes();
        let e = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap_err();
        assert_eq!(e.code, "confirm");
        assert_eq!(e.extra.as_ref().unwrap()["servers"][0], "9.9.9.9");
        assert_eq!(be.writes(), before, "refusal must not write");
        let e = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap_err();
        assert_eq!(e.code, "confirm");
        // With --force it goes through.
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), true).unwrap();
        assert_eq!(r["mode"], "pihole");
        let prev = load_prev(dir.path(), U_WIFI).unwrap();
        assert_eq!(
            prev.ipv4_dns,
            vec!["9.9.9.9"],
            "the user's servers are kept for undo"
        );
    }

    #[test]
    fn auto_never_restores_a_custom_previous_setting() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        // Previous (custom) settings sit in the undo file; the profile is pinned.
        save_prev(
            dir.path(),
            U_WIFI,
            &DnsSettings {
                v4_method: "auto".into(),
                v4_dns: vec!["9.9.9.9".parse().unwrap()],
                v4_ignore_auto: true,
                v6_method: "auto".into(),
                v6_dns: vec![],
                v6_ignore_auto: true,
            },
            None,
        )
        .unwrap();
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["mode"], "auto");
        assert_eq!(r["restoredPrevious"], false);
        assert!(be.profile(U_WIFI).dns.is_automatic());
        assert!(
            load_prev(dir.path(), U_WIFI).is_some(),
            "custom undo state is kept"
        );
    }

    #[test]
    fn dns_requires_pihole_config_for_pinning_only() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let none = Config::default();
        let e = dns_pihole(&ctx(&be, &none, dir.path()), false).unwrap_err();
        assert_eq!(e.code, "unconfigured");
        // Clearing to automatic needs no Pi-hole, but hand-set servers still
        // need a confirmation: with no Pi-hole known, everything is foreign.
        let e = dns_auto(&ctx(&be, &none, dir.path()), false).unwrap_err();
        assert_eq!(e.code, "confirm");
        let r = dns_auto(&ctx(&be, &none, dir.path()), true).unwrap();
        assert_eq!(r["mode"], "auto");
    }

    #[test]
    fn no_link_is_an_error_not_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_link_down();
        let cfg = fake_cfg();
        let e = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap_err();
        assert_eq!(e.code, "nolink");
        assert_eq!(be.writes(), 0);
    }

    #[test]
    fn pin_inactive_profile_writes_without_reapply() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_pin(&ctx(&be, &cfg, dir.path()), U_ETH1, false).unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["applied"], false);
        assert!(crate::dnsmodel::profile_pinned(
            &be.profile(U_ETH1).dns,
            crate::dnsmodel::fixtures::pi()
        ));
        assert!(
            !be.calls().iter().any(|c| c.starts_with("reapply")),
            "{:?}",
            be.calls()
        );
        assert!(load_prev(dir.path(), U_ETH1).unwrap().is_automatic());
        // Again: no-op.
        let r = dns_pin(&ctx(&be, &cfg, dir.path()), U_ETH1, false).unwrap();
        assert_eq!(r["noop"], true);
        // Bad input.
        assert_eq!(
            dns_pin(&ctx(&be, &cfg, dir.path()), "nope", false)
                .unwrap_err()
                .code,
            "invalid"
        );
        assert_eq!(
            dns_pin(
                &ctx(&be, &cfg, dir.path()),
                "aaaaaaaa-0000-0000-0000-000000000000",
                false
            )
            .unwrap_err()
            .code,
            "notfound"
        );
    }

    #[test]
    fn pin_of_the_active_profile_is_dns_pihole() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_pin(&ctx(&be, &cfg, dir.path()), U_WIFI, false).unwrap();
        assert_eq!(r["noop"], true, "already pinned and in use");
    }

    #[test]
    fn pihole_verb_after_runtime_failover_just_reapplies_saved() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.reapply_runtime_dns("wlp7s0", &["192.168.1.1".parse().unwrap()])
            .unwrap();
        let before = be.writes();
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["profileChanged"], false);
        assert_eq!(r["verifiedVia"], "192.168.1.153");
        assert_eq!(
            be.writes() - before,
            1,
            "only the reapply: {:?}",
            be.calls()
        );
    }

    #[test]
    fn verification_failure_is_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.set_resolve_error();
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["ok"], true);
        assert!(r["verifyError"]
            .as_str()
            .unwrap()
            .contains("test query failed"));
    }

    #[test]
    fn dns_pihole_reports_verified_via_only_when_the_canary_was_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["blocked"], true);
        assert_eq!(r["verifiedVia"], "192.168.1.153");
        assert!(r.get("verifyError").is_none());

        // The Pi-hole is the resolver in use but answers with a real
        // address: blocking is off, so this is not "verified".
        let be = FakeNet::live_machine();
        be.set_canary_answer("142.250.74.14");
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["blocked"], false);
        assert!(
            r.get("verifiedVia").is_none(),
            "no verifiedVia without a blocked canary: {r}"
        );
        assert!(r["verifyError"].as_str().unwrap().contains("not blocked"));

        // A failed test query is also an error, not a verification.
        let be = FakeNet::live_machine();
        be.set_resolve_error();
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["blocked"], false);
        assert!(r.get("verifiedVia").is_none());
        assert!(r["verifyError"]
            .as_str()
            .unwrap()
            .contains("test query failed"));
    }

    #[test]
    fn dns_pihole_pins_a_profile_that_only_looks_right_by_dhcp() {
        // DHCP hands out the Pi-hole and the router; the profile is automatic.
        // resolved shows the Pi-hole among the servers, so the mode reads
        // "pihole", but nothing is pinned: tapping Pin must really pin.
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_profile_dns_direct(U_WIFI, be.profile(U_WIFI).dns.automatic());
        be.set_dhcp(vec![
            crate::dnsmodel::fixtures::pi(),
            crate::dnsmodel::fixtures::gw(),
        ]);
        be.apply_saved_to_link();
        assert_eq!(be.link_servers().len(), 2);
        let cfg = fake_cfg();
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert!(r.get("noop").is_none(), "{r}");
        assert_eq!(r["profileChanged"], true);
        assert_eq!(be.link_servers(), vec![crate::dnsmodel::fixtures::pi()]);
    }

    #[test]
    fn the_router_ip_and_mac_are_recorded_after_a_verified_pin_and_kept_with_the_undo_state() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        let prev = load_prev(dir.path(), U_WIFI).unwrap();
        assert_eq!(prev.gateway_addr(), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(prev.gateway_mac_addr(), Some(MAC));
        assert!(!prev.gateway_only);
        assert!(prev.is_automatic(), "undo state still there");
        let raw: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join("prev-dns").join(format!("{U_WIFI}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["gateway"], "192.168.1.1");
        assert_eq!(raw["gateway_mac"], "3c:52:a1:00:11:22");
        assert!(raw.get("gateway_only").is_none());
    }

    #[test]
    fn nothing_is_recorded_unless_the_pinned_web_api_answered_on_this_link() {
        for liveness in [ApiLiveness::Dead, ApiLiveness::Mismatch, ApiLiveness::Other] {
            let dir = tempfile::tempdir().unwrap();
            let be = FakeNet::live_machine();
            let cfg = fake_cfg();
            let mut c = ctx(&be, &cfg, dir.path());
            c.api_check = Arc::new(move |_, _| liveness);
            let r = dns_pihole(&c, false).unwrap();
            assert_eq!(r["blocked"], true, "the pin itself still works");
            assert!(
                load_prev(dir.path(), U_WIFI).is_none(),
                "{liveness:?}: no record"
            );
        }
        // And no MAC, no record: a half-record would not satisfy the router rule anyway.
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let mut c = ctx(&be, &cfg, dir.path());
        c.mac_lookup = Arc::new(|_, _| None);
        dns_pihole(&c, false).unwrap();
        assert!(load_prev(dir.path(), U_WIFI).is_none());
        // Nor when the canary was not blocked (the Pi-hole is not what answered).
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_canary_answer("142.250.74.14");
        dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert!(load_prev(dir.path(), U_WIFI).is_none());
    }

    #[test]
    fn already_pinned_profiles_get_their_router_recorded_on_a_no_op_tap() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        let prev = load_prev(dir.path(), U_WIFI).unwrap();
        assert!(
            prev.gateway_only,
            "only the router is on file; there is no undo state"
        );
        assert_eq!(prev.gateway_mac_addr(), Some(MAC));
        // A router-only file is not "previous settings".
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["restoredPrevious"], false);
    }

    #[test]
    fn recording_keeps_undo_state_and_replaces_the_router() {
        let dir = tempfile::tempdir().unwrap();
        let dns = DnsSettings {
            v4_method: "auto".into(),
            v4_dns: vec!["9.9.9.9".parse().unwrap()],
            v4_ignore_auto: true,
            v6_method: "auto".into(),
            v6_dns: vec![],
            v6_ignore_auto: false,
        };
        save_prev(dir.path(), U_ETH1, &dns, None).unwrap();
        record_link_trust(dir.path(), U_ETH1, "10.0.0.1".parse().unwrap(), MAC).unwrap();
        let p = load_prev(dir.path(), U_ETH1).unwrap();
        assert_eq!(p.ipv4_dns, vec!["9.9.9.9"], "undo state untouched");
        assert!(!p.gateway_only);
        record_link_trust(
            dir.path(),
            U_ETH1,
            "10.9.9.9".parse().unwrap(),
            [1, 2, 3, 4, 5, 6],
        )
        .unwrap();
        let p = load_prev(dir.path(), U_ETH1).unwrap();
        assert_eq!(p.gateway_addr(), Some("10.9.9.9".parse().unwrap()));
        assert_eq!(p.gateway_mac_addr(), Some([1, 2, 3, 4, 5, 6]));
        assert!(record_link_trust(dir.path(), "../x", "10.9.9.9".parse().unwrap(), MAC).is_err());
    }

    #[test]
    fn prev_files_from_before_the_gateway_field_still_load() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("prev-dns")).unwrap();
        std::fs::write(
            dir.path().join("prev-dns").join(format!("{U_WIFI}.json")),
            r#"{"uuid":"21307067-f47b-43ea-8c9c-2c746454b2bb","saved_at":1,"ipv4_dns":[],"ipv4_ignore_auto_dns":false,"ipv6_dns":[],"ipv6_ignore_auto_dns":false}"#,
        )
        .unwrap();
        let p = load_prev(dir.path(), U_WIFI).unwrap();
        assert!(p.is_automatic() && p.gateway_addr().is_none() && !p.gateway_only);
    }

    #[test]
    fn pin_accepts_several_uuids_and_reports_each() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_pin_many(
            &ctx(&be, &cfg, dir.path()),
            &[U_ETH1.into(), U_ETH2.into()],
            false,
        )
        .unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["results"].as_array().unwrap().len(), 2);
        assert_eq!(r["results"][0]["uuid"], U_ETH1);
        assert_eq!(r["results"][1]["connection"], "Wired connection 2");
        assert!(crate::dnsmodel::profile_pinned(
            &be.profile(U_ETH1).dns,
            crate::dnsmodel::fixtures::pi()
        ));
        assert!(crate::dnsmodel::profile_pinned(
            &be.profile(U_ETH2).dns,
            crate::dnsmodel::fixtures::pi()
        ));
        assert!(r.get("verifiedVia").is_some());
        assert!(
            !be.calls().iter().any(|c| c.starts_with("reapply")),
            "inactive profiles are never reapplied"
        );
        assert_eq!(
            be.calls()
                .iter()
                .filter(|c| c.starts_with("resolve "))
                .count(),
            1,
            "one closing query"
        );
    }

    #[test]
    fn a_partial_pin_still_pins_the_rest_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        // Wired 2 carries hand-set servers: needs --force.
        be.set_profile_dns_direct(
            U_ETH2,
            DnsSettings {
                v4_method: "auto".into(),
                v4_dns: vec!["9.9.9.9".parse().unwrap()],
                v4_ignore_auto: true,
                v6_method: "auto".into(),
                v6_dns: vec![],
                v6_ignore_auto: true,
            },
        );
        let missing = "aaaaaaaa-0000-0000-0000-000000000000".to_string();
        let e = dns_pin_many(
            &ctx(&be, &cfg, dir.path()),
            &[U_ETH1.into(), U_ETH2.into(), missing],
            false,
        )
        .unwrap_err();
        assert_eq!(e.code, "partial");
        let results = e.extra.as_ref().unwrap()["results"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(results[0]["ok"], true);
        assert_eq!(results[1]["error"], "confirm");
        assert_eq!(results[2]["error"], "notfound");
        assert!(crate::dnsmodel::profile_pinned(
            &be.profile(U_ETH1).dns,
            crate::dnsmodel::fixtures::pi()
        ));
        assert_eq!(
            be.profile(U_ETH2).dns.v4_dns,
            vec!["9.9.9.9".parse::<Ipv4Addr>().unwrap()],
            "untouched"
        );
        let j = e.to_json();
        assert_eq!(j["ok"], false);
        assert_eq!(j["results"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn pin_many_includes_the_active_profile_through_the_full_path() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_pin_many(
            &ctx(&be, &cfg, dir.path()),
            &[U_WIFI.into(), U_ETH1.into()],
            false,
        )
        .unwrap();
        assert_eq!(
            r["results"][0]["noop"], true,
            "the active one is already pinned and in use"
        );
        assert_eq!(r["results"][0]["blocked"], true);
        assert!(crate::dnsmodel::profile_pinned(
            &be.profile(U_ETH1).dns,
            crate::dnsmodel::fixtures::pi()
        ));
    }

    #[test]
    fn single_uuid_pin_keeps_its_old_shape() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = dns_pin_many(&ctx(&be, &cfg, dir.path()), &[U_ETH1.into()], false).unwrap();
        assert_eq!(r["connection"], "Wired connection 1");
        assert_eq!(r["applied"], false);
        assert!(r.get("results").is_none());
    }

    // -- Pi-hole verbs ------------------------------------------------------

    struct StubApi(Vec<(bool, Option<u64>)>, Blocking);
    impl BlockingApi for StubApi {
        fn set_blocking(&mut self, e: bool, t: Option<u64>) -> Result<Blocking, ApiError> {
            self.0.push((e, t));
            Ok(self.1)
        }
    }

    #[test]
    fn pause_resume() {
        let mut api = StubApi(
            vec![],
            Blocking {
                state: BlockingState::Disabled,
                timer: Some(300.0),
            },
        );
        let r = pihole_pause(&mut api, 300).unwrap();
        assert_eq!(r, json!({"ok": true, "blocking": "disabled", "timer": 300}));
        assert_eq!(api.0, vec![(false, Some(300))]);
        assert_eq!(pihole_pause(&mut api, 0).unwrap_err().code, "invalid");
        assert_eq!(pihole_pause(&mut api, 99999).unwrap_err().code, "invalid");
        let mut api = StubApi(
            vec![],
            Blocking {
                state: BlockingState::Enabled,
                timer: None,
            },
        );
        let r = pihole_resume(&mut api).unwrap();
        assert_eq!(r, json!({"ok": true, "blocking": "enabled", "timer": null}));
        assert_eq!(api.0, vec![(true, None)]);
        // A server that ignores the request is an error.
        let mut stuck = StubApi(
            vec![],
            Blocking {
                state: BlockingState::Enabled,
                timer: None,
            },
        );
        assert_eq!(pihole_pause(&mut stuck, 60).unwrap_err().code, "api");
    }

    // -- Wi-Fi verbs --------------------------------------------------------

    const AP_PSK: &str = "/org/freedesktop/NetworkManager/AccessPoint/12";
    const AP_NEW: &str = "/org/freedesktop/NetworkManager/AccessPoint/40";
    const AP_ENT: &str = "/org/freedesktop/NetworkManager/AccessPoint/41";
    const AP_OPEN: &str = "/org/freedesktop/NetworkManager/AccessPoint/42";
    const AP_HIDDEN: &str = "/org/freedesktop/NetworkManager/AccessPoint/43";

    #[test]
    fn connect_known_uses_the_saved_profile() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = wifi_connect(&ctx(&be, &cfg, dir.path()), AP_PSK, None).unwrap();
        assert_eq!(r["known"], true);
        assert!(be
            .calls()
            .iter()
            .any(|c| c.starts_with(&format!("activate_known {U_WIFI}"))));
        assert!(!be.calls().iter().any(|c| c.starts_with("connect_new")));
    }

    #[test]
    fn connect_unknown_secured_needs_a_passphrase_and_validates_it() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_connect(&c, AP_NEW, None).unwrap_err().code, "badpass");
        assert_eq!(
            wifi_connect(&c, AP_NEW, Some("")).unwrap_err().code,
            "badpass"
        );
        assert_eq!(
            wifi_connect(&c, AP_NEW, Some("short")).unwrap_err().code,
            "badpass"
        );
        assert_eq!(be.writes(), 0);
        let r = wifi_connect(&c, AP_NEW, Some("correct horse battery")).unwrap();
        assert_eq!(r["known"], false);
        assert!(be
            .calls()
            .iter()
            .any(|c| c == "connect_new wlp7s0 Cafe psk pass=yes"));
    }

    #[test]
    fn connect_open_network_takes_no_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = wifi_connect(&ctx(&be, &cfg, dir.path()), AP_OPEN, None).unwrap();
        assert_eq!(r["connection"], "Lobby");
        assert!(be
            .calls()
            .iter()
            .any(|c| c == "connect_new wlp7s0 Lobby open pass=no"));
    }

    #[test]
    fn enterprise_hidden_and_garbage_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(
            wifi_connect(&c, AP_ENT, Some("whatever1"))
                .unwrap_err()
                .code,
            "enterprise"
        );
        assert_eq!(
            wifi_connect(&c, AP_HIDDEN, None).unwrap_err().code,
            "hidden"
        );
        assert_eq!(
            wifi_connect(&c, "Redwood", None).unwrap_err().code,
            "invalid"
        );
        assert_eq!(
            wifi_connect(&c, "/org/freedesktop/NetworkManager/AccessPoint/999", None)
                .unwrap_err()
                .code,
            "notfound"
        );
        assert_eq!(be.writes(), 0, "{:?}", be.calls());
    }

    #[test]
    fn activation_failure_surfaces_as_auth() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.fail_next_activation(NetError::Activation {
            auth: true,
            detail: "bad key".into(),
        });
        let cfg = fake_cfg();
        let e = wifi_connect(
            &ctx(&be, &cfg, dir.path()),
            AP_NEW,
            Some("correct horse battery"),
        )
        .unwrap_err();
        assert_eq!(e.code, "auth");
    }

    fn scans(be: &FakeNet) -> usize {
        be.calls()
            .iter()
            .filter(|c| c.starts_with("request_scan"))
            .count()
    }

    #[test]
    fn scan_within_fifteen_seconds_of_nms_last_scan_is_too_soon_not_ok() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.set_last_scan_age_ms(Some(5_000));
        let e = wifi_scan(&ctx(&be, &cfg, dir.path()), None).unwrap_err();
        assert_eq!(e.code, "too-soon");
        let j = e.to_json();
        assert_eq!(j["ok"], false);
        assert_eq!(j["retryInS"], 10);
        assert_eq!(scans(&be), 0, "nothing was requested");
        be.set_last_scan_age_ms(Some(40_000));
        let r = wifi_scan(&ctx(&be, &cfg, dir.path()), None).unwrap();
        assert_eq!(r["scanned"], true);
        assert_eq!(scans(&be), 1);
        // NM has never scanned: fine, and the first request is not throttled.
        let dir = tempfile::tempdir().unwrap();
        be.set_last_scan_age_ms(None);
        assert_eq!(
            wifi_scan(&ctx(&be, &cfg, dir.path()), None).unwrap()["scanned"],
            true
        );
    }

    #[test]
    fn scan_also_throttles_on_qnets_own_last_request_even_if_nm_says_old() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.set_last_scan_age_ms(Some(120_000));
        let mut c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_scan(&c, None).unwrap()["scanned"], true);
        assert_eq!(scans(&be), 1);
        // NM has not yet reported the scan (its LastScan is still old), but
        // we asked 4 s ago: wait.
        c.now = Some(c.now() + 4.0);
        let e = wifi_scan(&c, None).unwrap_err();
        assert_eq!(e.code, "too-soon");
        assert_eq!(e.to_json()["retryInS"], 11);
        assert_eq!(scans(&be), 1);
        c.now = Some(c.now() + 11.0);
        assert_eq!(wifi_scan(&c, None).unwrap()["scanned"], true);
        assert_eq!(scans(&be), 2);
    }

    #[test]
    fn a_failed_scan_request_is_not_noted() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.set_last_scan_age_ms(Some(120_000));
        be.fail_scan(Some(NetError::Denied("polkit".into())));
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_scan(&c, None).unwrap_err().code, "denied");
        be.fail_scan(None);
        assert_eq!(
            wifi_scan(&c, None).unwrap()["scanned"],
            true,
            "the failure did not start the clock"
        );
    }

    #[test]
    fn scan_if_stale_skips_while_either_clock_is_young_and_still_obeys_the_throttle() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let mut c = ctx(&be, &cfg, dir.path());
        // NM scanned 30 s ago, limit 60: skipped, and says how old.
        be.set_last_scan_age_ms(Some(30_000));
        let r = wifi_scan(&c, Some(60)).unwrap();
        assert_eq!(r, json!({"ok": true, "skipped": true, "lastScanAgeS": 30}));
        assert_eq!(scans(&be), 0);
        // NM scanned 70 s ago: due.
        be.set_last_scan_age_ms(Some(70_000));
        assert_eq!(wifi_scan(&c, Some(60)).unwrap()["scanned"], true);
        assert_eq!(scans(&be), 1);
        // Our own request counts: NM's clock still says 70 s, ours says 20 s.
        c.now = Some(c.now() + 20.0);
        let r = wifi_scan(&c, Some(60)).unwrap();
        assert_eq!(r, json!({"ok": true, "skipped": true, "lastScanAgeS": 20}));
        assert_eq!(scans(&be), 1);
        // ...until both are older than the limit.
        c.now = Some(c.now() + 45.0);
        assert_eq!(wifi_scan(&c, Some(60)).unwrap()["scanned"], true);
        assert_eq!(scans(&be), 2);
    }

    #[test]
    fn scan_if_stale_with_a_short_limit_still_hits_the_fifteen_second_rule() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.set_last_scan_age_ms(Some(10_000));
        // 10 s is older than 5 s, so the scan is "due", but too young to repeat.
        let e = wifi_scan(&ctx(&be, &cfg, dir.path()), Some(5)).unwrap_err();
        assert_eq!(e.code, "too-soon");
        assert_eq!(scans(&be), 0);
        // Never scanned: due, and allowed.
        be.set_last_scan_age_ms(None);
        assert_eq!(
            wifi_scan(&ctx(&be, &cfg, dir.path()), Some(60)).unwrap()["scanned"],
            true
        );
    }

    #[test]
    fn scan_refused_with_radio_off() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_wifi_enabled(false).unwrap();
        let cfg = fake_cfg();
        assert_eq!(
            wifi_scan(&ctx(&be, &cfg, dir.path()), None)
                .unwrap_err()
                .code,
            "radio"
        );
        assert_eq!(
            wifi_scan(&ctx(&be, &cfg, dir.path()), Some(60))
                .unwrap_err()
                .code,
            "radio"
        );
    }

    #[test]
    fn forget_only_wifi_profiles_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_forget(&c, "x").unwrap_err().code, "invalid");
        assert_eq!(wifi_forget(&c, U_ETH1).unwrap_err().code, "invalid");
        assert_eq!(
            be.calls()
                .iter()
                .filter(|c| c.starts_with("forget"))
                .count(),
            0
        );
        let r = wifi_forget(&c, U_WIFI).unwrap();
        assert_eq!(r["connection"], "Redwood");
        assert!(be.calls().iter().any(|c| c == &format!("forget {U_WIFI}")));
    }

    #[test]
    fn radio_toggle_and_rfkill() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_radio(&c, true).unwrap()["noop"], true);
        assert_eq!(wifi_radio(&c, false).unwrap()["wifiEnabled"], false);
        be.set_hw_enabled(false);
        assert_eq!(wifi_radio(&c, true).unwrap_err().code, "rfkill");
    }

    #[test]
    fn a_second_radio_change_within_ten_seconds_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let mut c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_radio(&c, false).unwrap()["wifiEnabled"], false);
        let switches = |be: &FakeNet| {
            be.calls()
                .iter()
                .filter(|c| c.starts_with("set_wifi_enabled"))
                .count()
        };
        assert_eq!(switches(&be), 1);
        // Straight back on: too soon.
        c.now = Some(c.now() + 3.0);
        let e = wifi_radio(&c, true).unwrap_err();
        assert_eq!(e.code, "too-soon");
        let j = e.to_json();
        assert_eq!(
            (j["ok"].clone(), j["error"].clone(), j["retryInS"].clone()),
            (json!(false), json!("too-soon"), json!(7))
        );
        assert_eq!(switches(&be), 1, "the radio was not touched");
        // A no-op request is not a change and is never refused.
        assert_eq!(wifi_radio(&c, false).unwrap()["noop"], true);
        // After ten seconds it goes through, and starts the clock again.
        c.now = Some(c.now() + 8.0);
        assert_eq!(wifi_radio(&c, true).unwrap()["wifiEnabled"], true);
        assert_eq!(switches(&be), 2);
        c.now = Some(c.now() + 1.0);
        assert_eq!(wifi_radio(&c, false).unwrap_err().code, "too-soon");
    }

    #[test]
    fn the_radio_guard_is_shared_between_processes_through_the_runtime_dir() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        wifi_radio(&ctx(&be, &cfg, dir.path()), false).unwrap();
        // A brand-new Ctx (another process) sees the same stamp.
        let c2 = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_radio(&c2, true).unwrap_err().code, "too-soon");
        let stamp = std::fs::read_to_string(dir.path().join("run").join("radio")).unwrap();
        assert!(stamp.contains("\"at\""));
        // A corrupt stamp does not wedge the radio.
        std::fs::write(dir.path().join("run").join("radio"), "garbage").unwrap();
        assert_eq!(wifi_radio(&c2, true).unwrap()["wifiEnabled"], true);
    }

    #[test]
    fn down_needs_a_connected_wifi() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_down(&c).unwrap()["ok"], true);
        be.set_link_down();
        assert_eq!(wifi_down(&c).unwrap_err().code, "nolink");
    }

    // -- one DNS change at a time -----------------------------------------------

    fn hold_dns_lock(dir: &Path) -> util::FileLock {
        util::try_lock(&dir.join("run").join("dns.lock"))
            .unwrap()
            .expect("free")
    }

    #[test]
    fn every_dns_verb_is_busy_while_another_holds_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_profile_dns_direct(U_ETH1, be.profile(U_ETH1).dns.automatic());
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        let _held = hold_dns_lock(dir.path());
        let before = be.writes();
        for r in [
            dns_pihole(&c, false),
            dns_auto(&c, false),
            dns_auto(&c, true),
            dns_pin(&c, U_ETH1, false),
            dns_pin(&c, U_WIFI, false),
            dns_pin_many(&c, &[U_ETH1.into(), U_ETH2.into()], false),
        ] {
            let e = r.unwrap_err();
            assert_eq!(e.code, "busy", "{e:?}");
            assert_eq!(
                e.to_json(),
                json!({"ok": false, "error": "busy", "detail": "another qnet operation is changing DNS right now"})
            );
        }
        assert_eq!(be.writes(), before, "a busy verb touches nothing");
        assert!(!dir.path().join("auto-dns.json").exists());
    }

    #[test]
    fn the_lock_is_released_after_each_verb() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        dns_pihole(&c, false).unwrap();
        assert!(util::try_lock(&dir.path().join("run").join("dns.lock"))
            .unwrap()
            .is_some());
        dns_auto(&c, false).unwrap();
        assert!(util::try_lock(&dir.path().join("run").join("dns.lock"))
            .unwrap()
            .is_some());
        // Even a refused verb lets go.
        let _ = dns_pihole(&ctx(&be, &Config::default(), dir.path()), false);
        assert!(util::try_lock(&dir.path().join("run").join("dns.lock"))
            .unwrap()
            .is_some());
        // Non-DNS verbs never wait for it.
        let _held = hold_dns_lock(dir.path());
        assert!(wifi_scan(&c, None).is_ok() || wifi_scan(&c, None).unwrap_err().code != "busy");
    }

    // -- SIGTERM ------------------------------------------------------------------

    #[test]
    fn an_interrupt_before_the_first_write_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_profile_dns_direct(U_WIFI, be.profile(U_WIFI).dns.automatic());
        be.apply_saved_to_link();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        c.term.store(true, Ordering::SeqCst);
        let before = be.writes();
        let e = dns_pihole(&c, false).unwrap_err();
        assert_eq!(e.code, "interrupted");
        assert_eq!(be.writes(), before);
        assert!(!dir.path().join("prev-dns").exists(), "not even undo state");
        // Pin-many stops between profiles.
        let e = dns_pin_many(&c, &[U_ETH1.into(), U_ETH2.into()], false).unwrap_err();
        assert_eq!(e.code, "partial");
        assert!(e.extra.as_ref().unwrap()["results"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["error"] == "interrupted"));
        assert_eq!(be.writes(), before);
    }

    #[test]
    fn an_interrupt_in_the_middle_finishes_the_step_and_skips_the_check() {
        // The signal arrives right after the profile is written.
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_profile_dns_direct(U_WIFI, be.profile(U_WIFI).dns.automatic());
        be.apply_saved_to_link();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        be.trip_after_profile_write(c.term.clone());
        let r = dns_pihole(&c, false).unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["interrupted"], true);
        assert_eq!(r["blocked"], false);
        assert!(r.get("verifiedVia").is_none(), "no claim without a check");
        // Saved profile and running DNS agree: written *and* applied.
        assert!(crate::dnsmodel::profile_pinned(
            &be.profile(U_WIFI).dns,
            crate::dnsmodel::fixtures::pi()
        ));
        assert!(be.calls().iter().any(|c| c == "reapply_saved wlp7s0"));
        assert_eq!(be.link_servers(), vec![crate::dnsmodel::fixtures::pi()]);
        assert!(
            !be.calls().iter().any(|c| c.starts_with("resolve ")),
            "no verification query was sent"
        );
        assert!(util::try_lock(&dir.path().join("run").join("dns.lock"))
            .unwrap()
            .is_some());
    }

    #[test]
    fn dns_auto_interrupted_after_the_write_also_applies_it() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        be.trip_after_profile_write(c.term.clone());
        let r = dns_auto(&c, false).unwrap();
        assert_eq!(r["interrupted"], true);
        assert!(be.profile(U_WIFI).dns.is_automatic());
        assert!(be.calls().iter().any(|c| c == "reapply_saved wlp7s0"));
        assert!(auto_choices(dir.path()).contains(U_WIFI));
    }

    #[test]
    fn an_interrupted_activation_wait_is_reported_as_interrupted() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.fail_next_activation(NetError::Interrupted("stopped while waiting".into()));
        let cfg = fake_cfg();
        let e = wifi_connect(
            &ctx(&be, &cfg, dir.path()),
            AP_NEW,
            Some("correct horse battery"),
        )
        .unwrap_err();
        assert_eq!(e.code, "interrupted");
    }

    // -- "Automatic is my choice" -------------------------------------------------

    #[test]
    fn dns_auto_records_the_choice_and_pinning_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert!(auto_choices(dir.path()).is_empty());
        dns_auto(&c, false).unwrap();
        assert!(auto_choices(dir.path()).contains(U_WIFI));
        let raw = std::fs::read_to_string(dir.path().join("auto-dns.json")).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&raw).unwrap(),
            vec![U_WIFI]
        );
        dns_pihole(&c, false).unwrap();
        assert!(
            auto_choices(dir.path()).is_empty(),
            "pinning is the opposite choice"
        );
        // Tapping Automatic while already on Automatic records it too.
        dns_auto(&c, false).unwrap();
        let r = dns_auto(&c, false).unwrap();
        assert_eq!(r["noop"], true);
        assert!(auto_choices(dir.path()).contains(U_WIFI));
    }

    #[test]
    fn a_noop_tap_on_automatic_records_the_choice_for_a_cable_that_came_up_on_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        // The link is on automatic DNS, but nobody asked for that.
        be.set_profile_dns_direct(U_WIFI, be.profile(U_WIFI).dns.automatic());
        be.apply_saved_to_link();
        let cfg = fake_cfg();
        assert!(auto_choices(dir.path()).is_empty());
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["noop"], true);
        assert_eq!(be.writes(), 0, "no DNS change");
        assert!(auto_choices(dir.path()).contains(U_WIFI));
    }

    #[test]
    fn pinning_an_inactive_profile_forgets_its_automatic_choice() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        set_auto_choice(dir.path(), U_ETH1, true).unwrap();
        dns_pin(&ctx(&be, &cfg, dir.path()), U_ETH1, false).unwrap();
        assert!(!auto_choices(dir.path()).contains(U_ETH1));
    }

    #[test]
    fn auto_choice_file_helpers() {
        let dir = tempfile::tempdir().unwrap();
        set_auto_choice(dir.path(), U_WIFI, true).unwrap();
        set_auto_choice(dir.path(), U_ETH1, true).unwrap();
        set_auto_choice(dir.path(), U_WIFI, true).unwrap();
        assert_eq!(auto_choices(dir.path()).len(), 2);
        set_auto_choice(dir.path(), U_WIFI, false).unwrap();
        assert_eq!(
            auto_choices(dir.path()),
            HashSet::from([U_ETH1.to_string()])
        );
        assert!(set_auto_choice(dir.path(), "../x", true).is_err());
        // Garbage and bad entries are ignored.
        std::fs::write(
            dir.path().join("auto-dns.json"),
            r#"["../evil", "21307067-f47b-43ea-8c9c-2c746454b2bb"]"#,
        )
        .unwrap();
        assert_eq!(
            auto_choices(dir.path()),
            HashSet::from([U_WIFI.to_string()])
        );
        std::fs::write(dir.path().join("auto-dns.json"), "not json").unwrap();
        assert!(auto_choices(dir.path()).is_empty());
    }
}

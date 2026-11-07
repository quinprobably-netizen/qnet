//! One-shot verbs. Each returns a JSON object (`ok: true` plus details) or an
//! `ActionErr`; `main` prints one line and sets the exit code.
//!
//! Everything here goes through `NetBackend`, so the safety rules (confirm
//! before overwriting manual DNS, active profile only, no-ops) are tested
//! against a fake and never need the live network.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::config::{Config, DEFAULT_CANARY};
use crate::dnsmodel::{detect_mode, manual_override, profile_pinned, Mode};
use crate::net::*;
use crate::pihole::{ApiError, Blocking, BlockingState};
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

pub struct Ctx<'a> {
    pub be: &'a dyn NetBackend,
    pub cfg: &'a Config,
    pub state_dir: PathBuf,
    /// How long to wait for resolved to reflect a change.
    pub settle: Duration,
}

impl<'a> Ctx<'a> {
    pub fn new(be: &'a dyn NetBackend, cfg: &'a Config) -> Self {
        Self {
            be,
            cfg,
            state_dir: util::state_dir(),
            settle: Duration::from_secs(3),
        }
    }

    fn pihole(&self) -> Result<IpAddr, ActionErr> {
        self.cfg
            .pihole
            .as_ref()
            .map(|p| p.address)
            .ok_or_else(|| ActionErr::new("unconfigured", "no Pi-hole configured; run `qnet pihole setup <address>`"))
    }

    fn canary(&self) -> String {
        self.cfg
            .pihole
            .as_ref()
            .map(|p| p.canary.clone())
            .unwrap_or_else(|| DEFAULT_CANARY.to_string())
    }
}

// ---- Undo state ------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PrevDns {
    pub uuid: String,
    pub saved_at: u64,
    pub ipv4_dns: Vec<String>,
    pub ipv4_ignore_auto_dns: bool,
    pub ipv6_dns: Vec<String>,
    pub ipv6_ignore_auto_dns: bool,
}

impl PrevDns {
    fn is_automatic(&self) -> bool {
        self.ipv4_dns.is_empty()
            && self.ipv6_dns.is_empty()
            && !self.ipv4_ignore_auto_dns
            && !self.ipv6_ignore_auto_dns
    }
}

fn prev_path(dir: &Path, uuid: &str) -> PathBuf {
    dir.join("prev-dns").join(format!("{uuid}.json"))
}

pub fn save_prev(dir: &Path, uuid: &str, dns: &DnsSettings) -> Result<(), ActionErr> {
    if !util::is_uuid(uuid) {
        return Err(ActionErr::new("invalid", "bad connection uuid"));
    }
    let prev = PrevDns {
        uuid: uuid.to_string(),
        saved_at: util::unix_secs(),
        ipv4_dns: dns.v4_dns.iter().map(|a| a.to_string()).collect(),
        ipv4_ignore_auto_dns: dns.v4_ignore_auto,
        ipv6_dns: dns.v6_dns.iter().map(|a| a.to_string()).collect(),
        ipv6_ignore_auto_dns: dns.v6_ignore_auto,
    };
    let bytes = serde_json::to_vec_pretty(&prev).map_err(|e| ActionErr::new("io", e.to_string()))?;
    util::atomic_write(&prev_path(dir, uuid), &bytes, 0o600)
        .map_err(|e| ActionErr::new("io", format!("could not save undo state: {e}")))
}

pub fn load_prev(dir: &Path, uuid: &str) -> Option<PrevDns> {
    if !util::is_uuid(uuid) {
        return None;
    }
    let t = std::fs::read_to_string(prev_path(dir, uuid)).ok()?;
    serde_json::from_str(&t).ok()
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
    let answers = match ctx.be.resolve_hostname(&ctx.canary()) {
        Ok(a) => a.iter().map(|x| x.to_string()).collect(),
        Err(e) => {
            error = Some(format!("test query failed: {}", e.detail()));
            vec![]
        }
    };
    let via = ctx
        .be
        .resolver(&[(a.ifindex, a.iface.clone())])
        .ok()
        .and_then(|r| {
            r.link(a.ifindex)
                .and_then(|l| l.current.or_else(|| l.servers.first().copied()))
        })
        .map(|ip| ip.to_string());
    Verified { via, answers, error }
}

fn with_verification(mut base: Map<String, Value>, v: Verified) -> Value {
    base.insert("verifiedVia".into(), json!(v.via.unwrap_or_default()));
    base.insert("answers".into(), json!(v.answers));
    if let Some(e) = v.error {
        base.insert("verifyError".into(), json!(e));
    }
    Value::Object(base)
}

fn obj(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

fn confirm_err(a: &Active, pihole: Option<IpAddr>, what: &str) -> ActionErr {
    let servers: Vec<String> = a
        .profile
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
            a.profile.id,
            servers.join(", ")
        ),
    );
    e.extra = Some(json!({ "connection": a.profile.id, "servers": servers }));
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

/// `qnet dns pihole`: pin the active connection's saved profile to the
/// Pi-hole and apply it.
pub fn dns_pihole(ctx: &Ctx<'_>, force: bool) -> ActionResult {
    let pihole = ctx.pihole()?;
    let a = active_link(ctx)?;
    let servers = link_servers(ctx, &a);
    let mode = detect_mode(true, false, &servers, Some(&a.profile), Some(pihole));
    let expect = move |s: &[IpAddr]| !s.is_empty() && s.iter().all(|x| *x == pihole);

    if mode == Mode::Pihole {
        let v = verify(ctx, &a, &expect);
        return Ok(with_verification(
            obj(&[("ok", json!(true)), ("noop", json!(true)), ("mode", json!("pihole"))]),
            v,
        ));
    }
    dns_supported(&a.profile.dns)?;
    if manual_override(&a.profile.dns, pihole) && !force {
        return Err(confirm_err(&a, Some(pihole), "pinning the Pi-hole"));
    }
    let mut wrote_profile = false;
    if !profile_pinned(&a.profile.dns, pihole) {
        save_prev(&ctx.state_dir, &a.uuid, &a.profile.dns)?;
        ctx.be.set_profile_dns(&a.uuid, &a.profile.dns.pinned_to(pihole))?;
        wrote_profile = true;
    }
    // Also when the profile was already pinned but the device is running
    // something else (a runtime failover): apply the saved profile.
    ctx.be.reapply_saved(&a.iface)?;
    let v = verify(ctx, &a, &expect);
    Ok(with_verification(
        obj(&[
            ("ok", json!(true)),
            ("mode", json!("pihole")),
            ("profileChanged", json!(wrote_profile)),
        ]),
        v,
    ))
}

/// `qnet dns auto`: back to automatic DNS on the active profile.
pub fn dns_auto(ctx: &Ctx<'_>, force: bool) -> ActionResult {
    let pihole = ctx.cfg.pihole.as_ref().map(|p| p.address);
    let a = active_link(ctx)?;
    let servers = link_servers(ctx, &a);
    let mode = detect_mode(true, false, &servers, Some(&a.profile), pihole);
    let expect = move |s: &[IpAddr]| match pihole {
        Some(p) => !s.is_empty() && !s.iter().all(|x| *x == p),
        None => true,
    };
    if mode == Mode::Auto {
        let v = verify(ctx, &a, &|_| true);
        return Ok(with_verification(
            obj(&[("ok", json!(true)), ("noop", json!(true)), ("mode", json!("auto"))]),
            v,
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
        return Err(confirm_err(&a, pihole, "switching to automatic DNS"));
    }
    let prev = load_prev(&ctx.state_dir, &a.uuid);
    // Restoring the saved settings only makes sense when they were
    // automatic; Automatic must mean automatic whatever came before.
    let restored = prev.as_ref().is_some_and(|p| p.is_automatic());
    ctx.be.set_profile_dns(&a.uuid, &a.profile.dns.automatic())?;
    ctx.be.reapply_saved(&a.iface)?;
    if restored {
        remove_prev(&ctx.state_dir, &a.uuid);
    }
    let v = verify(ctx, &a, &expect);
    Ok(with_verification(
        obj(&[
            ("ok", json!(true)),
            ("mode", json!("auto")),
            ("restoredPrevious", json!(restored)),
        ]),
        v,
    ))
}

/// `qnet dns pin <uuid>`: apply the Pi-hole settings to a saved profile.
/// An inactive profile is only written; the active one is pinned like
/// `dns pihole`.
pub fn dns_pin(ctx: &Ctx<'_>, uuid: &str, force: bool) -> ActionResult {
    if !util::is_uuid(uuid) {
        return Err(ActionErr::new("invalid", "not a connection uuid"));
    }
    let pihole = ctx.pihole()?;
    let snap = ctx.be.snapshot(false)?;
    let is_active = snap
        .primary_device()
        .filter(|d| d.is_up())
        .and_then(|d| d.active.as_ref())
        .is_some_and(|a| a.uuid == uuid);
    if is_active {
        return dns_pihole(ctx, force);
    }
    let profile = ctx
        .be
        .profiles()?
        .into_iter()
        .find(|p| p.uuid == uuid)
        .ok_or_else(|| ActionErr::new("notfound", "no saved connection with that uuid"))?;
    if !matches!(profile.kind, ProfileKind::Wifi | ProfileKind::Ethernet) {
        return Err(ActionErr::new("invalid", "only Wi-Fi and Ethernet profiles can be pinned"));
    }
    if profile_pinned(&profile.dns, pihole) {
        return Ok(json!({"ok": true, "noop": true, "mode": "pihole", "connection": profile.id}));
    }
    dns_supported(&profile.dns)?;
    if manual_override(&profile.dns, pihole) && !force {
        let a = Active {
            iface: String::new(),
            ifindex: 0,
            uuid: profile.uuid.clone(),
            profile: profile.clone(),
        };
        return Err(confirm_err(&a, Some(pihole), "pinning the Pi-hole"));
    }
    save_prev(&ctx.state_dir, uuid, &profile.dns)?;
    ctx.be.set_profile_dns(uuid, &profile.dns.pinned_to(pihole))?;
    // The pinned profile is not in use, so the query still goes through
    // whatever the active link uses; report that honestly.
    let active = active_link(ctx).ok();
    let v = match &active {
        Some(a) => verify(ctx, a, &|_| true),
        None => Verified { via: None, answers: vec![], error: Some("no active link to test".into()) },
    };
    Ok(with_verification(
        obj(&[
            ("ok", json!(true)),
            ("mode", json!("pihole")),
            ("connection", json!(profile.id)),
            ("applied", json!(false)),
        ]),
        v,
    ))
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
        return Err(ActionErr::new("invalid", "pause length must be 1-3600 seconds"));
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
                Err(ActionErr::new("badpass", "a WPA passphrase is 8-63 characters"))
            }
        }
        Security::Sae => {
            let n = pass.chars().count();
            if (1..=128).contains(&n) && pass.chars().all(printable) {
                Ok(())
            } else {
                Err(ActionErr::new("badpass", "the passphrase must be 1-128 printable characters"))
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
        return Err(ActionErr::new("hidden", "hidden networks cannot be joined from the list"));
    }
    match sec {
        Security::Enterprise => return Err(ActionErr::new("enterprise", "802.1X networks need nmtui")),
        Security::Wep => return Err(ActionErr::new("unsupported", "WEP networks are not supported")),
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
            ctx.be.activate_known(&p.uuid, &dev.iface, ap_path, new_pass)?;
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
        return Err(ActionErr::new("invalid", "only saved Wi-Fi networks can be forgotten here"));
    }
    ctx.be.forget(uuid)?;
    Ok(json!({"ok": true, "connection": profile.id}))
}

pub const SCAN_MIN_AGE_MS: u64 = 15_000;

pub fn wifi_scan(ctx: &Ctx<'_>) -> ActionResult {
    let snap = ctx.be.snapshot(false)?;
    if !snap.wifi_enabled {
        return Err(ActionErr::new("radio", "Wi-Fi is turned off"));
    }
    let dev = snap
        .wifi_device()
        .ok_or_else(|| ActionErr::new("nowifi", "no Wi-Fi device"))?;
    let age = dev.wifi.as_ref().and_then(|w| w.last_scan_age_ms);
    if let Some(a) = age {
        if a < SCAN_MIN_AGE_MS {
            return Ok(json!({
                "ok": true, "scanned": false, "throttled": true, "lastScanAgeS": a / 1000
            }));
        }
    }
    ctx.be.request_scan(&dev.iface)?;
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
    ctx.be.set_wifi_enabled(on)?;
    Ok(json!({"ok": true, "wifiEnabled": on}))
}

// ---- Captive portal ------------------------------------------------------------------

pub const DEFAULT_PORTAL_URL: &str = "http://neverssl.com";

pub fn portal_url(snap: &NetSnapshot) -> String {
    let u = snap.check_uri.as_str();
    if snap.connectivity == Connectivity::Portal && (u.starts_with("http://") || u.starts_with("https://")) {
        u.to_string()
    } else {
        DEFAULT_PORTAL_URL.to_string()
    }
}

pub fn portal_args(url: &str, dir: &Path) -> Vec<String> {
    vec![
        format!("--user-data-dir={}", dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        format!("--app={url}"),
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
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "no free temp name"))
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
        assert_eq!(ActionErr::new("x", "").to_json(), json!({"ok": false, "error": "x"}));
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
        save_prev(dir.path(), u, &dns).unwrap();
        let p = load_prev(dir.path(), u).unwrap();
        assert_eq!(p.ipv4_dns, vec!["9.9.9.9"]);
        assert!(p.ipv4_ignore_auto_dns && !p.is_automatic());
        assert!(save_prev(dir.path(), "../evil", &dns).is_err());
        assert!(load_prev(dir.path(), "../evil").is_none());
        remove_prev(dir.path(), u);
        assert!(load_prev(dir.path(), u).is_none());
    }

    #[test]
    fn passphrase_rules() {
        assert!(validate_passphrase("12345678", &Security::Psk).is_ok());
        assert!(validate_passphrase("1234567", &Security::Psk).is_err());
        assert!(validate_passphrase(&"a".repeat(64), &Security::Psk).is_ok(), "64 hex");
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
        let a = portal_args("http://x.test/a b;rm", Path::new("/run/user/1000/qnet-portal-ab"));
        assert_eq!(a[0], "--user-data-dir=/run/user/1000/qnet-portal-ab");
        assert_eq!(a[3], "--app=http://x.test/a b;rm");
        assert_eq!(a.len(), 4);
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

    fn ctx<'a>(be: &'a FakeNet, cfg: &'a Config, dir: &Path) -> Ctx<'a> {
        Ctx {
            be,
            cfg,
            state_dir: dir.to_path_buf(),
            settle: Duration::from_millis(200),
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
        assert_eq!(be.writes(), 0, "tapping the current mode must change nothing: {:?}", be.calls());
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
        assert_eq!(p.dns.v4_dns, vec!["192.168.1.153".parse::<std::net::Ipv4Addr>().unwrap()]);
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
        assert_eq!(prev.ipv4_dns, vec!["9.9.9.9"], "the user's servers are kept for undo");
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
        )
        .unwrap();
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["mode"], "auto");
        assert_eq!(r["restoredPrevious"], false);
        assert!(be.profile(U_WIFI).dns.is_automatic());
        assert!(load_prev(dir.path(), U_WIFI).is_some(), "custom undo state is kept");
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
        assert!(crate::dnsmodel::profile_pinned(&be.profile(U_ETH1).dns, crate::dnsmodel::fixtures::pi()));
        assert!(!be.calls().iter().any(|c| c.starts_with("reapply")), "{:?}", be.calls());
        assert!(load_prev(dir.path(), U_ETH1).unwrap().is_automatic());
        // Again: no-op.
        let r = dns_pin(&ctx(&be, &cfg, dir.path()), U_ETH1, false).unwrap();
        assert_eq!(r["noop"], true);
        // Bad input.
        assert_eq!(dns_pin(&ctx(&be, &cfg, dir.path()), "nope", false).unwrap_err().code, "invalid");
        assert_eq!(
            dns_pin(&ctx(&be, &cfg, dir.path()), "aaaaaaaa-0000-0000-0000-000000000000", false)
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
        be.reapply_runtime_dns("wlp7s0", &["192.168.1.1".parse().unwrap()]).unwrap();
        let before = be.writes();
        let r = dns_pihole(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["profileChanged"], false);
        assert_eq!(r["verifiedVia"], "192.168.1.153");
        assert_eq!(be.writes() - before, 1, "only the reapply: {:?}", be.calls());
    }

    #[test]
    fn verification_failure_is_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.set_resolve_error();
        let r = dns_auto(&ctx(&be, &cfg, dir.path()), false).unwrap();
        assert_eq!(r["ok"], true);
        assert!(r["verifyError"].as_str().unwrap().contains("test query failed"));
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
        let mut api = StubApi(vec![], Blocking { state: BlockingState::Disabled, timer: Some(300.0) });
        let r = pihole_pause(&mut api, 300).unwrap();
        assert_eq!(r, json!({"ok": true, "blocking": "disabled", "timer": 300}));
        assert_eq!(api.0, vec![(false, Some(300))]);
        assert_eq!(pihole_pause(&mut api, 0).unwrap_err().code, "invalid");
        assert_eq!(pihole_pause(&mut api, 99999).unwrap_err().code, "invalid");
        let mut api = StubApi(vec![], Blocking { state: BlockingState::Enabled, timer: None });
        let r = pihole_resume(&mut api).unwrap();
        assert_eq!(r, json!({"ok": true, "blocking": "enabled", "timer": null}));
        assert_eq!(api.0, vec![(true, None)]);
        // A server that ignores the request is an error.
        let mut stuck = StubApi(vec![], Blocking { state: BlockingState::Enabled, timer: None });
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
        assert!(be.calls().iter().any(|c| c.starts_with(&format!("activate_known {U_WIFI}"))));
        assert!(!be.calls().iter().any(|c| c.starts_with("connect_new")));
    }

    #[test]
    fn connect_unknown_secured_needs_a_passphrase_and_validates_it() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_connect(&c, AP_NEW, None).unwrap_err().code, "badpass");
        assert_eq!(wifi_connect(&c, AP_NEW, Some("")).unwrap_err().code, "badpass");
        assert_eq!(wifi_connect(&c, AP_NEW, Some("short")).unwrap_err().code, "badpass");
        assert_eq!(be.writes(), 0);
        let r = wifi_connect(&c, AP_NEW, Some("correct horse battery")).unwrap();
        assert_eq!(r["known"], false);
        assert!(be.calls().iter().any(|c| c == "connect_new wlp7s0 Cafe psk pass=yes"));
    }

    #[test]
    fn connect_open_network_takes_no_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let r = wifi_connect(&ctx(&be, &cfg, dir.path()), AP_OPEN, None).unwrap();
        assert_eq!(r["connection"], "Lobby");
        assert!(be.calls().iter().any(|c| c == "connect_new wlp7s0 Lobby open pass=no"));
    }

    #[test]
    fn enterprise_hidden_and_garbage_paths_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_connect(&c, AP_ENT, Some("whatever1")).unwrap_err().code, "enterprise");
        assert_eq!(wifi_connect(&c, AP_HIDDEN, None).unwrap_err().code, "hidden");
        assert_eq!(wifi_connect(&c, "Redwood", None).unwrap_err().code, "invalid");
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
        be.fail_next_activation(NetError::Activation { auth: true, detail: "bad key".into() });
        let cfg = fake_cfg();
        let e = wifi_connect(&ctx(&be, &cfg, dir.path()), AP_NEW, Some("correct horse battery")).unwrap_err();
        assert_eq!(e.code, "auth");
    }

    #[test]
    fn scan_is_throttled_by_nm_last_scan() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        be.set_last_scan_age_ms(Some(5_000));
        let r = wifi_scan(&ctx(&be, &cfg, dir.path())).unwrap();
        assert_eq!(r["throttled"], true);
        assert!(!be.calls().iter().any(|c| c.starts_with("request_scan")));
        be.set_last_scan_age_ms(Some(40_000));
        let r = wifi_scan(&ctx(&be, &cfg, dir.path())).unwrap();
        assert_eq!(r["scanned"], true);
        assert_eq!(be.calls().iter().filter(|c| c.starts_with("request_scan")).count(), 1);
        be.set_last_scan_age_ms(None);
        assert_eq!(wifi_scan(&ctx(&be, &cfg, dir.path())).unwrap()["scanned"], true);
    }

    #[test]
    fn scan_refused_with_radio_off() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        be.set_wifi_enabled(false).unwrap();
        let cfg = fake_cfg();
        assert_eq!(wifi_scan(&ctx(&be, &cfg, dir.path())).unwrap_err().code, "radio");
    }

    #[test]
    fn forget_only_wifi_profiles_and_validates() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_forget(&c, "x").unwrap_err().code, "invalid");
        assert_eq!(wifi_forget(&c, U_ETH1).unwrap_err().code, "invalid");
        assert_eq!(be.calls().iter().filter(|c| c.starts_with("forget")).count(), 0);
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
    fn down_needs_a_connected_wifi() {
        let dir = tempfile::tempdir().unwrap();
        let be = FakeNet::live_machine();
        let cfg = fake_cfg();
        let c = ctx(&be, &cfg, dir.path());
        assert_eq!(wifi_down(&c).unwrap()["ok"], true);
        be.set_link_down();
        assert_eq!(wifi_down(&c).unwrap_err().code, "nolink");
    }
}

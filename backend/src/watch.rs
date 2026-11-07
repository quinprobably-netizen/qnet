//! `qnet watch`: the long-lived process behind the panel.
//!
//! Threads (all feeding one event channel; see `threads.rs`):
//!   * stdin reader   - `open` / `closed` / `refresh`;
//!   * signals        - SIGTERM / SIGINT / SIGHUP;
//!   * NM watcher     - NetworkManager D-Bus signals;
//!   * prober         - raw UDP DNS probes to the Pi-hole, an upstream
//!     check, the gateway gate, and (open only) an ICMP echo to the gateway;
//!   * API poller     - Pi-hole HTTPS API, only while the panel is open.
//!
//! The main thread owns the model and is the only one that touches DNS
//! settings. `Watch` takes the current time as an argument everywhere, so
//! its decisions can be tested without sleeping.

use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::actions::{self, ApiCheck, MacLookup};
use crate::config::{self, Config, Fallback};
use crate::dnsmodel::{self, pihole_candidate};
use crate::failover::{Decision, Failover, LinkKey, Obs};
use crate::ledger::Ledger;
use crate::neigh;
use crate::net::*;
use crate::state::*;
use crate::util;

pub use crate::threads::*;

/// Desktop notification sink: (title, body).
pub type Notifier = Box<dyn Fn(&str, &str) + Send>;

pub const EMIT_MIN_GAP_MS: u64 = 250;
pub const HEARTBEAT_MS: u64 = 10_000;
pub const RESOLVER_EVERY_MS: u64 = 30_000;
pub const RESOLVER_FOLLOWUP_MS: u64 = 1_500;
pub const NET_MIN_GAP_MS: u64 = 250;
pub const LEDGER_SAVE_MS: u64 = 300_000;
/// How long a gateway round trip stays valid with no new measurement.
pub const GATEWAY_MS_FRESH_S: f64 = 20.0;
/// How often resolved's view of the Pi-hole is read while the panel is open.
pub const RESOLVED_CHECK_MS: u64 = 30_000;
/// How long to wait before trying to record the router again.
pub const LEARN_RETRY_MS: u64 = 300_000;

/// Reads resolved's view of the Pi-hole; Some(reason) if it downgraded it.
pub type ResolvedCheck = Arc<dyn Fn(IpAddr) -> Option<String> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Shutdown,
}

/// One line of output.
#[derive(Debug, Clone, PartialEq)]
pub enum Line {
    State(Box<State>),
    /// Liveness only: `{"type":"hb","seq":N}` with the last state's seq.
    Hb { seq: u64 },
}

impl Line {
    pub fn to_json_line(&self) -> Vec<u8> {
        let mut v = match self {
            Line::State(s) => serde_json::to_vec(s).unwrap_or_default(),
            Line::Hb { seq } => format!("{{\"type\":\"hb\",\"seq\":{seq}}}").into_bytes(),
        };
        v.push(b'\n');
        v
    }
}

// ---- The model ------------------------------------------------------------

#[derive(Default)]
struct Dirty {
    net: bool,
    aps: bool,
    profiles: bool,
    resolver: bool,
}

pub struct Watch {
    be: Box<dyn NetBackend>,
    cfg: Config,
    cfg_error: String,
    net: Option<NetSnapshot>,
    profiles: Vec<Profile>,
    resolver: Option<ResolverSnapshot>,
    net_error: String,
    profile_error: String,
    resolver_error: String,
    op_error: String,
    open: bool,
    probes: VecDeque<ProbeRec>,
    probe_target: Option<ProbeTarget>,
    api: ApiView,
    api_cfg: Option<ApiCfg>,
    fo: Failover,
    /// The link failover was applied to; recovery goes back to this one even
    /// if the primary link has changed since.
    engaged: Option<LinkKey>,
    candidate: Option<IpAddr>,
    candidate_probed: bool,
    confirmed: Option<IpAddr>,
    /// Latest result of the upstream-resolution check.
    upstream_ok: Option<bool>,
    /// What the pinned web API said when the canary last went unanswered.
    api_state: Option<ApiLiveness>,
    /// The gateway answered the canary with 0.0.0.0 in the last failing cycle.
    gateway_forwards: bool,
    /// The fallback a failover is actually using.
    fallback_in_use: Option<Fallback>,
    resolved_downgrade: Option<String>,
    resolved_check_due_ms: u64,
    resolved_check: Option<ResolvedCheck>,
    event_tx: Option<Sender<Event>>,
    /// Profiles whose Automatic DNS was chosen with `qnet dns auto`.
    auto_set: HashSet<String>,
    api_check: ApiCheck,
    mac_lookup: MacLookup,
    /// `$XDG_RUNTIME_DIR/qnet`: the DNS lock.
    runtime_dir: PathBuf,
    /// ICMP round trip to the gateway and when it was taken (unix s).
    gateway_ms: Option<(f64, f64)>,
    ledger: Ledger,
    ledger_saved_ms: u64,
    state_dir: PathBuf,
    learned_for: Option<(String, Ipv4Addr)>,
    learn_retry_ms: u64,
    dirty: Dirty,
    aps_stale: bool,
    last_net_ms: u64,
    net_read_unix: f64,
    resolver_due_ms: u64,
    seq: u64,
    last_json: Option<serde_json::Value>,
    last_emit_ms: u64,
    emitted_once: bool,
    /// Send the full state next time, whatever the signature says (on `open`).
    force_emit: bool,
    /// Bumped whenever anything the state is built from may have changed.
    gen: u64,
    emitted_gen: u64,
    pending_change: bool,
    hb_every_ms: u64,
    builds: std::cell::Cell<u64>,
    notify: Notifier,
    probe_tx: Option<Sender<ProbeCtl>>,
    api_tx: Option<Sender<ApiCtl>>,
    config_path: PathBuf,
}

impl Watch {
    pub fn new(be: Box<dyn NetBackend>, config_path: PathBuf) -> Self {
        Self {
            be,
            cfg: Config::default(),
            cfg_error: String::new(),
            net: None,
            profiles: vec![],
            resolver: None,
            net_error: String::new(),
            profile_error: String::new(),
            resolver_error: String::new(),
            op_error: String::new(),
            open: false,
            probes: VecDeque::new(),
            probe_target: None,
            api: ApiView::unconfigured(),
            api_cfg: None,
            fo: Failover::new(),
            engaged: None,
            candidate: None,
            candidate_probed: false,
            confirmed: None,
            upstream_ok: None,
            api_state: None,
            gateway_forwards: false,
            fallback_in_use: None,
            resolved_downgrade: None,
            resolved_check_due_ms: 0,
            resolved_check: None,
            event_tx: None,
            auto_set: HashSet::new(),
            // Unit tests must never reach the real network or neighbour table.
            #[cfg(not(test))]
            api_check: Arc::new(|addr, probe| check_api(addr, probe, Duration::from_millis(1500))),
            #[cfg(test)]
            api_check: Arc::new(|_, _| ApiLiveness::Dead),
            #[cfg(not(test))]
            mac_lookup: Arc::new(neigh::mac_of),
            #[cfg(test)]
            mac_lookup: Arc::new(|_, _| None),
            runtime_dir: util::runtime_qnet_dir(),
            gateway_ms: None,
            ledger: Ledger::default(),
            ledger_saved_ms: 0,
            state_dir: util::state_dir(),
            learned_for: None,
            learn_retry_ms: 0,
            dirty: Dirty::default(),
            aps_stale: true,
            last_net_ms: 0,
            net_read_unix: 0.0,
            resolver_due_ms: 0,
            seq: 0,
            last_json: None,
            last_emit_ms: 0,
            emitted_once: false,
            force_emit: false,
            gen: 1,
            emitted_gen: 0,
            pending_change: false,
            hb_every_ms: HEARTBEAT_MS,
            builds: std::cell::Cell::new(0),
            notify: Box::new(|_, _| {}),
            probe_tx: None,
            api_tx: None,
            config_path,
        }
    }

    pub fn set_notifier(&mut self, f: Notifier) {
        self.notify = f;
    }

    /// Where undo/gateway records and the query tally live.
    #[cfg(test)]
    pub fn set_state_dir(&mut self, dir: PathBuf) {
        self.state_dir = dir;
    }

    /// Where the DNS lock lives (tests use a temp dir).
    #[cfg(test)]
    pub fn set_runtime_dir(&mut self, dir: PathBuf) {
        self.runtime_dir = dir;
    }

    #[cfg(test)]
    pub fn set_api_check(&mut self, f: ApiCheck) {
        self.api_check = f;
    }

    #[cfg(test)]
    pub fn set_mac_lookup(&mut self, f: MacLookup) {
        self.mac_lookup = f;
    }

    /// Read resolved's server state through `f` while the panel is open;
    /// results come back as `Event::Downgrade` on `tx`.
    pub fn set_resolved_check(&mut self, f: ResolvedCheck, tx: Sender<Event>) {
        self.resolved_check = Some(f);
        self.event_tx = Some(tx);
    }

    #[cfg(test)]
    pub fn set_heartbeat_ms(&mut self, ms: u64) {
        self.hb_every_ms = ms;
    }

    pub fn attach_threads(&mut self, probe: Sender<ProbeCtl>, api: Sender<ApiCtl>) {
        self.probe_tx = Some(probe);
        self.api_tx = Some(api);
    }

    fn touch(&mut self) {
        self.gen += 1;
    }

    fn ledger_path(&self) -> PathBuf {
        self.state_dir.join("self-queries.json")
    }

    // -- reading ------------------------------------------------------------

    fn load_config(&mut self) {
        match config::load(&self.config_path) {
            Ok(c) => {
                self.cfg = c;
                self.cfg_error.clear();
            }
            Err(e) => {
                // Bad config switches the Pi-hole features off, loudly.
                self.cfg = Config::default();
                self.cfg_error = e;
            }
        }
    }

    fn read_net(&mut self, now_ms: u64, with_aps: bool) {
        self.last_net_ms = now_ms;
        match self.be.snapshot(with_aps) {
            Ok(mut snap) => {
                self.net_read_unix = util::unix_now();
                // Without the AP read, keep the last list instead of
                // blanking the networks.
                if !with_aps {
                    if let Some(old) = &self.net {
                        for d in &mut snap.devices {
                            if let (Some(w), Some(ow)) = (
                                d.wifi.as_mut(),
                                old.device_by_iface(&d.iface).and_then(|o| o.wifi.as_ref()),
                            ) {
                                let active = w.active_ap.clone();
                                let fresh: Vec<Ap> = std::mem::take(&mut w.aps);
                                w.aps = ow.aps.clone();
                                for f in fresh {
                                    if let Some(slot) = w.aps.iter_mut().find(|a| a.path == f.path) {
                                        *slot = f;
                                    } else if Some(&f.path) == active.as_ref() {
                                        w.aps.push(f);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    self.aps_stale = false;
                }
                self.net = Some(snap);
                self.net_error.clear();
            }
            Err(e) => self.net_error = format!("NetworkManager: {}", e.detail()),
        }
    }

    fn read_profiles(&mut self) {
        match self.be.profiles() {
            Ok(p) => {
                self.profiles = p;
                self.profile_error.clear();
            }
            Err(e) => self.profile_error = format!("NetworkManager: {}", e.detail()),
        }
        // `qnet dns auto` writes its note before it touches the profile, so
        // by the time the change is seen the note is there.
        self.auto_set = actions::auto_choices(&self.state_dir);
    }

    fn read_resolver(&mut self, now_ms: u64) {
        let wanted: Vec<(u32, String)> = self
            .net
            .as_ref()
            .map(|n| {
                n.devices
                    .iter()
                    .filter(|d| d.is_up() && d.ifindex > 0)
                    .map(|d| (d.ifindex, d.iface.clone()))
                    .collect()
            })
            .unwrap_or_default();
        match self.be.resolver(&wanted) {
            Ok(r) => {
                self.resolver = Some(r);
                self.resolver_error.clear();
            }
            Err(e) => self.resolver_error = format!("systemd-resolved: {}", e.detail()),
        }
        self.resolver_due_ms = now_ms + RESOLVER_EVERY_MS;
    }

    fn primary(&self) -> Option<&Device> {
        self.net.as_ref().and_then(|n| n.primary_device()).filter(|d| d.is_up())
    }

    fn primary_profile(&self) -> Option<&Profile> {
        let uuid = &self.primary()?.active.as_ref()?.uuid;
        self.profiles.iter().find(|p| &p.uuid == uuid)
    }

    fn update_candidate(&mut self) {
        let next = if self.cfg.pihole.is_some() {
            None
        } else {
            let servers: Vec<IpAddr> = self
                .primary()
                .and_then(|d| self.resolver.as_ref().and_then(|r| r.link(d.ifindex)))
                .map(|l| l.servers.clone())
                .unwrap_or_default();
            let gw = self.primary().and_then(|d| d.gateway);
            pihole_candidate(&servers, gw)
        };
        if next != self.candidate {
            self.candidate = next;
            self.candidate_probed = false;
            if self.confirmed != next {
                self.confirmed = None;
            }
        }
    }

    /// The Pi-hole address the rest of the model works with: the configured
    /// one, or a detected one that has been seen blocking the canary. Only
    /// the configured one is ever shown as `pihole.address`.
    pub fn effective_pihole(&self) -> Option<IpAddr> {
        self.cfg.pihole.as_ref().map(|p| p.address).or(self.confirmed)
    }

    fn detect_pending(&self) -> bool {
        self.cfg.pihole.is_none() && self.candidate.is_some() && self.confirmed.is_none() && !self.candidate_probed
    }

    fn desired_probe_target(&self) -> Option<ProbeTarget> {
        let (addr, canary) = match &self.cfg.pihole {
            Some(p) => (p.address, p.canary.clone()),
            None => (self.candidate?, config::DEFAULT_CANARY.to_string()),
        };
        let gateway = self.primary().and_then(|d| d.gateway).map(IpAddr::V4);
        let api = self.cfg.pihole.as_ref().map(|p| ApiProbe { port: 443, pin: p.tls_sha256 });
        Some(ProbeTarget { addr, port: 53, gateway_port: 53, api, canary, gateway })
    }

    fn sync_threads(&mut self) {
        self.update_candidate();
        let want = self.desired_probe_target();
        if want != self.probe_target {
            if want.as_ref().map(|t| t.addr) != self.probe_target.as_ref().map(|t| t.addr) {
                self.probes.clear();
                self.upstream_ok = None;
                self.gateway_ms = None;
            }
            if let Some(tx) = &self.probe_tx {
                let _ = tx.send(ProbeCtl::Target(want.clone()));
            }
            self.probe_target = want;
        }
        let api_cfg = self.cfg.pihole.as_ref().map(|p| ApiCfg {
            addr: p.address,
            port: 443,
            pin: p.tls_sha256,
        });
        if api_cfg != self.api_cfg {
            self.api = if api_cfg.is_some() {
                ApiView::configured()
            } else {
                ApiView::unconfigured()
            };
            if let Some(tx) = &self.api_tx {
                let _ = tx.send(ApiCtl::Config(api_cfg.clone()));
            }
            self.api_cfg = api_cfg;
        }
    }

    // -- startup / shutdown ---------------------------------------------------

    pub fn startup(&mut self, now_ms: u64) {
        self.ledger = Ledger::load(&self.ledger_path());
        self.ledger_saved_ms = now_ms;
        self.load_config();
        self.read_net(now_ms, true);
        self.read_profiles();
        self.read_resolver(now_ms);
        self.sync_threads();
        if let Some(tx) = &self.probe_tx {
            let _ = tx.send(ProbeCtl::Open(self.open));
        }
        self.adopt_stranded_failover();
        self.touch();
    }

    /// A previous qnet may have died while failed over. If the device runs
    /// different DNS than its saved Pi-hole profile, treat that as an active
    /// failover so recovery puts it right.
    fn adopt_stranded_failover(&mut self) {
        if !self.eligible() {
            return;
        }
        let (Some(dev), Some(profile)) = (self.primary(), self.primary_profile()) else {
            return;
        };
        let (iface, saved) = (dev.iface.clone(), profile.dns.v4_dns.clone());
        let key = self.link_key();
        let gateway = self.primary().and_then(|d| d.gateway);
        if let Ok(applied) = self.be.applied_dns(&iface) {
            if applied.v4_dns != saved {
                self.fo.adopt(util::unix_secs(), "device was running different DNS than its saved profile");
                self.engaged = key;
                self.fallback_in_use = Fallback::identify(&applied.v4_dns, gateway);
            }
        }
    }

    /// Clean exit. A failover is put back only when the Pi-hole is answering
    /// again: leaving a dead Pi-hole in charge of DNS would be worse than
    /// leaving the fallback in place (the next start adopts it).
    pub fn shutdown(&mut self) {
        if self.fo.active() && self.last_probe_passed() {
            let iface = self
                .engaged
                .as_ref()
                .map(|k| k.iface.clone())
                .or_else(|| self.primary().map(|d| d.iface.clone()));
            if let Some(iface) = iface {
                if self.be.reapply_saved(&iface).is_ok() {
                    self.fo.dropped();
                    self.engaged = None;
                    self.fallback_in_use = None;
                }
            }
        }
        if self.ledger.is_dirty() {
            let path = self.ledger_path();
            let _ = self.ledger.save(&path);
        }
        if let Some(tx) = self.probe_tx.take() {
            let _ = tx.send(ProbeCtl::Stop);
        }
        if let Some(tx) = self.api_tx.take() {
            let _ = tx.send(ApiCtl::Stop);
        }
    }

    fn last_probe_passed(&self) -> bool {
        self.probes.back().is_some_and(|p| p.ok) && self.upstream_ok != Some(false)
    }

    // -- events ---------------------------------------------------------------

    pub fn handle(&mut self, ev: Event, now_ms: u64) -> Flow {
        match ev {
            Event::Cmd(line) => {
                self.on_command(line.trim(), now_ms);
                self.touch();
            }
            Event::StdinEof | Event::Signal => return Flow::Shutdown,
            Event::Nm(kind) => self.on_nm(kind, now_ms),
            Event::NmLost => {
                self.dirty = Dirty { net: true, aps: self.open, profiles: true, resolver: true };
            }
            Event::Probe(r) => {
                self.on_probe(r, now_ms);
                self.touch();
            }
            Event::Api(r) => {
                self.on_api(r);
                self.touch();
            }
            Event::Downgrade(d) => {
                self.resolved_downgrade = d;
                self.touch();
            }
        }
        Flow::Continue
    }

    fn mark_all_dirty(&mut self) {
        self.dirty = Dirty { net: true, aps: true, profiles: true, resolver: true };
    }

    fn on_command(&mut self, cmd: &str, now_ms: u64) {
        match cmd {
            "open" => {
                self.open = true;
                // Whatever was quietly swallowed while closed (probes,
                // latency) goes out in full now.
                self.force_emit = true;
                self.resolved_check_due_ms = 0;
                self.op_error.clear();
                self.mark_all_dirty();
                self.load_config();
                if let Some(tx) = &self.probe_tx {
                    let _ = tx.send(ProbeCtl::Open(true));
                }
                if let Some(tx) = &self.api_tx {
                    let _ = tx.send(ApiCtl::Open(true));
                }
                self.process_dirty(now_ms);
            }
            "closed" => {
                self.open = false;
                self.gateway_ms = None;
                if let Some(tx) = &self.probe_tx {
                    let _ = tx.send(ProbeCtl::Open(false));
                }
                if let Some(tx) = &self.api_tx {
                    let _ = tx.send(ApiCtl::Open(false));
                }
            }
            "refresh" => {
                self.mark_all_dirty();
                self.load_config();
                if let Some(tx) = &self.probe_tx {
                    let _ = tx.send(ProbeCtl::Kick);
                }
                if let Some(tx) = &self.api_tx {
                    let _ = tx.send(ApiCtl::Kick);
                }
            }
            _ => {}
        }
    }

    fn on_nm(&mut self, kind: NmKind, now_ms: u64) {
        match kind {
            NmKind::Core => {
                self.dirty.net = true;
                self.dirty.resolver = true;
                // resolved learns about the change a moment after NM does.
                self.resolver_due_ms = self.resolver_due_ms.min(now_ms + RESOLVER_FOLLOWUP_MS);
            }
            NmKind::Ap => {
                if self.open {
                    self.dirty.aps = true;
                    self.dirty.net = true;
                } else {
                    // Nothing to show while closed; the open re-reads it.
                    self.aps_stale = true;
                }
            }
            NmKind::Settings => {
                self.dirty.profiles = true;
                self.dirty.resolver = true;
                self.resolver_due_ms = self.resolver_due_ms.min(now_ms + RESOLVER_FOLLOWUP_MS);
            }
        }
    }

    fn on_api(&mut self, r: ApiReport) {
        self.api.status = r.status.to_string();
        // Remember how many of our own queries the Pi-hole had already
        // counted when it produced each reading (see `ApiView`).
        if let Some(s) = r.summary {
            self.api.today = Some(s);
            self.api.own_today = self.ledger.sums(r.at);
        }
        if let Some(h) = r.history {
            self.api.history = h;
            self.api.own_history = self.ledger.clone();
        }
        if let Some(u) = r.upstreams {
            self.api.upstreams = u;
            self.api.own_upstreams = self.ledger.sums(r.at);
        }
        if let Some(b) = r.blocking {
            self.api.blocking = Some((b, r.at));
        }
    }

    // -- probes and failover ----------------------------------------------------

    /// The profile whose DNS settings failover is about: the one it was
    /// applied to while failed over, the primary link's otherwise.
    fn watched_link(&self) -> Option<(LinkKey, &Device)> {
        let key = match (&self.engaged, self.fo.active()) {
            (Some(k), true) => k.clone(),
            _ => self.link_key()?,
        };
        let dev = self
            .net
            .as_ref()?
            .device_by_iface(&key.iface)
            .filter(|d| d.is_up() && d.active.as_ref().is_some_and(|a| a.uuid == key.uuid))?;
        Some((key, dev))
    }

    /// Failover is allowed only with a configured Pi-hole, the switch on,
    /// and the watched profile pinned to that Pi-hole.
    fn eligible(&self) -> bool {
        let Some(p) = &self.cfg.pihole else { return false };
        if !self.cfg.failover.enabled {
            return false;
        }
        let Some((key, _)) = self.watched_link() else { return false };
        self.profiles
            .iter()
            .find(|pr| pr.uuid == key.uuid)
            .is_some_and(|pr| dnsmodel::profile_pinned(&pr.dns, p.address))
    }

    fn link_key(&self) -> Option<LinkKey> {
        let d = self.primary()?;
        Some(LinkKey {
            iface: d.iface.clone(),
            uuid: d.active.as_ref()?.uuid.clone(),
        })
    }

    pub fn on_probe(&mut self, r: ProbeReport, now_ms: u64) {
        match &self.probe_target {
            Some(t) if t.addr == r.target => {}
            _ => return, // a report for a target we no longer use
        }
        self.probes.push_back(ProbeRec {
            t: r.t,
            ok: r.pihole.ok,
            ms: r.pihole.ms,
            blocked: r.pihole.blocked,
        });
        while self.probes.len() > MAX_PROBES {
            self.probes.pop_front();
        }
        self.ledger.add(r.t, r.own.total, r.own.blocked);
        match (r.pihole.ok, r.upstream) {
            (_, Some(u)) => self.upstream_ok = Some(u),
            // The Pi-hole did not answer: what upstream does is unknown.
            (false, None) => self.upstream_ok = None,
            (true, None) => {}
        }
        // Evidence from the cycles in which something was wrong.
        self.api_state = if r.pihole.ok { None } else { r.api };
        if let Some(b) = r.gateway_blocked {
            self.gateway_forwards = b;
        } else if r.gateway.is_none() {
            self.gateway_forwards = false;
        }
        if self.open {
            if let Some(ms) = r.gateway_ms {
                self.gateway_ms = Some((ms, util::unix_now()));
            }
        }
        if self.cfg.pihole.is_none() && self.candidate == Some(r.target) {
            self.candidate_probed = true;
            if r.pihole.ok && r.pihole.blocked {
                self.confirmed = Some(r.target);
            }
        }

        // The Pi-hole counts as up only if it answers the canary *and* can
        // resolve something that is not blocked.
        let healthy = r.pihole.ok && self.upstream_ok != Some(false);
        let obs = Obs {
            now_ms,
            link: self.watched_link().map(|(k, _)| k),
            eligible: self.eligible(),
            pihole_ok: healthy,
            gateway_ok: r.gateway,
            api_alive: self.api_state.is_some_and(|a| a.answered()),
        };
        match self.fo.observe(&obs) {
            Decision::Idle => {}
            Decision::Cleared(_) => {
                self.engaged = None;
                self.fallback_in_use = None;
            }
            Decision::Engage => self.engage(now_ms),
            Decision::Recover => self.recover(now_ms),
        }
        if healthy && r.pihole.blocked {
            self.learn_link(now_ms);
        }
    }

    /// First healthy sighting of a pinned profile on a link whose router is
    /// not on file (or lacks its MAC): record IP and MAC, but only after the
    /// Pi-hole's pinned web API has answered on this link. A router that is
    /// already recorded as a *different* one is never overwritten here.
    fn learn_link(&mut self, now_ms: u64) {
        if self.fo.active() || !self.eligible() || now_ms < self.learn_retry_ms {
            return;
        }
        let Some(cfg) = self.cfg.pihole.clone() else { return };
        let Some((key, dev)) = self.watched_link() else { return };
        let (Some(gw), iface) = (dev.gateway, dev.iface.clone()) else { return };
        if self.learned_for.as_ref() == Some(&(key.uuid.clone(), gw)) {
            return;
        }
        let prev = actions::load_prev(&self.state_dir, &key.uuid);
        if let Some(rec) = prev.as_ref().and_then(|p| p.gateway_addr()) {
            if rec != gw {
                self.learned_for = Some((key.uuid, gw));
                return;
            }
            if prev.as_ref().is_some_and(|p| p.gateway_mac_addr().is_some()) {
                self.learned_for = Some((key.uuid, gw));
                return;
            }
        }
        self.learn_retry_ms = now_ms + LEARN_RETRY_MS;
        let probe = ApiProbe { port: 443, pin: cfg.tls_sha256 };
        if (self.api_check)(cfg.address, &probe) != ApiLiveness::Alive {
            return;
        }
        let Some(mac) = (self.mac_lookup)(gw, &iface) else { return };
        if actions::record_link_trust(&self.state_dir, &key.uuid, gw, mac).is_ok() {
            self.learned_for = Some((key.uuid, gw));
            self.learn_retry_ms = 0;
        }
    }

    /// Servers for the fallback, and the reason to show. `router` is used
    /// only if this is verifiably the router the profile was pinned on (IP
    /// and MAC both match what was recorded) and that router does not simply
    /// forward to the Pi-hole.
    fn fallback_plan(
        &self,
        uuid: &str,
        iface: &str,
        gateway: Option<Ipv4Addr>,
    ) -> (Fallback, Vec<Ipv4Addr>, String) {
        let want = self.cfg.failover.fallback;
        if want != Fallback::Router {
            return (want, want.servers(gateway), "Pi-hole not answering".into());
        }
        let rec = actions::load_prev(&self.state_dir, uuid);
        let mac_now = gateway.and_then(|g| (self.mac_lookup)(g, iface));
        let same_router = gateway.is_some()
            && rec.as_ref().and_then(|r| r.gateway_addr()) == gateway
            && mac_now.is_some()
            && rec.as_ref().and_then(|r| r.gateway_mac_addr()) == mac_now;
        if !same_router {
            return (
                Fallback::Quad9,
                Fallback::Quad9.servers(None),
                "Pi-hole not answering; this router is not the one the profile was pinned on (address or MAC differ or are unknown), using quad9".into(),
            );
        }
        if self.gateway_forwards {
            return (
                Fallback::Quad9,
                Fallback::Quad9.servers(None),
                "Pi-hole not answering; the router forwards DNS to the Pi-hole, using quad9".into(),
            );
        }
        (Fallback::Router, Fallback::Router.servers(gateway), "Pi-hole not answering".into())
    }

    fn engage(&mut self, now_ms: u64) {
        // One DNS change at a time, across processes.
        let Ok(Some(_lock)) = util::try_lock(&self.runtime_dir.join("dns.lock")) else {
            self.op_error = "failover: another qnet operation is changing DNS".into();
            self.fo.engage_failed(now_ms);
            return;
        };
        // Re-read the link right before touching DNS.
        let Ok(snap) = self.be.snapshot(false) else {
            self.fo.engage_failed(now_ms);
            return;
        };
        let Some(dev) = snap.primary_device().filter(|d| d.is_up()) else {
            self.fo.engage_failed(now_ms);
            return;
        };
        let Some(uuid) = dev.active.as_ref().map(|a| a.uuid.clone()) else {
            self.fo.engage_failed(now_ms);
            return;
        };
        let watched = self.link_key();
        if watched.as_ref().map(|k| (k.iface.as_str(), k.uuid.as_str())) != Some((dev.iface.as_str(), uuid.as_str())) {
            self.fo.engage_failed(now_ms);
            return;
        }
        let (used, servers, reason) = self.fallback_plan(&uuid, &dev.iface, dev.gateway);
        if servers.is_empty() {
            self.op_error = "failover: no gateway address for the router fallback".into();
            self.fo.engage_failed(now_ms);
            return;
        }
        match self.be.reapply_runtime_dns(&dev.iface, &servers) {
            Ok(()) => {
                self.op_error.clear();
                self.fo.engaged(util::unix_secs(), &reason);
                self.engaged = Some(LinkKey { iface: dev.iface.clone(), uuid });
                self.fallback_in_use = Some(used);
                (self.notify)("Pi-hole unreachable", &format!("Using {} DNS", used.as_str()));
                self.resolver_due_ms = now_ms + RESOLVER_FOLLOWUP_MS;
            }
            Err(e) => {
                self.op_error = format!("failover: {}", e.detail());
                self.fo.engage_failed(now_ms);
            }
        }
    }

    fn recover(&mut self, now_ms: u64) {
        let Ok(Some(_lock)) = util::try_lock(&self.runtime_dir.join("dns.lock")) else {
            self.op_error = "failover recovery: another qnet operation is changing DNS".into();
            self.fo.recover_failed(now_ms);
            return;
        };
        let iface = self
            .engaged
            .as_ref()
            .map(|k| k.iface.clone())
            .or_else(|| self.primary().map(|d| d.iface.clone()));
        let Some(iface) = iface else {
            self.fo.recover_failed(now_ms);
            return;
        };
        match self.be.reapply_saved(&iface) {
            Ok(()) => {
                self.op_error.clear();
                self.fo.recovered(now_ms);
                self.engaged = None;
                self.fallback_in_use = None;
                (self.notify)("Pi-hole is back", "Using Pi-hole DNS again");
                self.resolver_due_ms = now_ms + RESOLVER_FOLLOWUP_MS;
            }
            Err(e) => {
                self.op_error = format!("failover recovery: {}", e.detail());
                self.fo.recover_failed(now_ms);
            }
        }
    }

    // -- the loop's work ----------------------------------------------------------

    /// Perform pending reads. Cheap when nothing is dirty.
    pub fn process_dirty(&mut self, now_ms: u64) {
        let resolver_due = now_ms >= self.resolver_due_ms;
        let net_ok = now_ms.saturating_sub(self.last_net_ms) >= NET_MIN_GAP_MS || self.last_net_ms == 0;
        let mut read = false;
        if self.dirty.net && net_ok {
            let with_aps = self.open && (self.dirty.aps || self.aps_stale);
            self.read_net(now_ms, with_aps);
            self.dirty.net = false;
            self.dirty.aps = false;
            read = true;
        }
        if self.dirty.profiles {
            self.read_profiles();
            self.dirty.profiles = false;
            read = true;
        }
        if self.dirty.resolver || resolver_due {
            self.read_resolver(now_ms);
            self.dirty.resolver = false;
            read = true;
        }
        if read {
            self.sync_threads();
            self.touch();
        }
        self.maybe_check_resolved(now_ms);
        if self.ledger.is_dirty() && now_ms.saturating_sub(self.ledger_saved_ms) >= LEDGER_SAVE_MS {
            let path = self.ledger_path();
            let _ = self.ledger.save(&path);
            self.ledger_saved_ms = now_ms;
        }
    }

    /// While the panel is open (never while closed: that would be a process
    /// spawn on a timer), ask resolved how it rates the Pi-hole. The answer
    /// arrives as an event; the slow part runs on its own thread.
    fn maybe_check_resolved(&mut self, now_ms: u64) {
        if !self.open || now_ms < self.resolved_check_due_ms {
            return;
        }
        let (Some(check), Some(tx), Some(addr)) = (self.resolved_check.clone(), self.event_tx.clone(), self.effective_pihole()) else {
            return;
        };
        self.resolved_check_due_ms = now_ms + RESOLVED_CHECK_MS;
        std::thread::spawn(move || {
            let _ = tx.send(Event::Downgrade(check(addr)));
        });
    }

    pub fn state(&self, heartbeat: bool) -> State {
        let error = [
            &self.net_error,
            &self.profile_error,
            &self.resolver_error,
            &self.cfg_error,
            &self.op_error,
        ]
        .into_iter()
        .find(|e| !e.is_empty())
        .map(|e| e.as_str())
        .unwrap_or("");
        self.builds.set(self.builds.get() + 1);
        let now = util::unix_now();
        let gateway_ms = self
            .gateway_ms
            .filter(|(_, at)| self.open && now - at < GATEWAY_MS_FRESH_S)
            .map(|(ms, _)| ms);
        build_state(
            &Inputs {
                net: self.net.as_ref(),
                profiles: &self.profiles,
                resolver: self.resolver.as_ref(),
                cfg: &self.cfg,
                pihole: self.effective_pihole(),
                detected: if self.cfg.pihole.is_none() { self.confirmed } else { None },
                detect_pending: self.detect_pending(),
                probes: &self.probes,
                upstream_ok: self.upstream_ok,
                gateway_ms,
                api_state: self.api_state,
                resolved_downgrade: self.resolved_downgrade.as_deref(),
                auto_deliberate: self
                    .primary()
                    .and_then(|d| d.active.as_ref())
                    .is_some_and(|a| self.auto_set.contains(&a.uuid)),
                engaged_iface: self.engaged.as_ref().map(|k| k.iface.as_str()),
                fallback_in_use: self.fallback_in_use,
                api: &self.api,
                failover: &self.fo,
                scan: ScanView { running: false },
                error,
                now_unix: now,
                net_age_s: now - self.net_read_unix,
            },
            self.seq,
            heartbeat,
        )
    }

    /// Decide what, if anything, goes out now. A state line only when the
    /// state changed (at most 4 per second); otherwise a bare `hb` line once
    /// nothing has been said for the heartbeat interval. Quiet wakes cost
    /// nothing: the state is not even built unless an input changed.
    ///
    /// "Changed" is judged on the signature for the panel's current state:
    /// while it is closed, the probe list, latency and bitrate do not count,
    /// so a healthy probe is an `hb`. `open` always sends the full state.
    pub fn next_emission(&mut self, now_ms: u64) -> Option<Line> {
        let since = now_ms.saturating_sub(self.last_emit_ms);
        let hb_due = self.emitted_once && since >= self.hb_every_ms;
        let inputs_changed = !self.emitted_once || self.force_emit || self.gen != self.emitted_gen;
        if !inputs_changed && !hb_due {
            self.pending_change = false;
            return None;
        }
        if inputs_changed && !hb_due && self.emitted_once && since < EMIT_MIN_GAP_MS {
            self.pending_change = true;
            return None;
        }
        let st = self.state(false);
        let json = serde_json::to_value(&st).unwrap_or(serde_json::Value::Null);
        let sig = signature_of(json.clone(), self.open);
        let last_sig = self.last_json.clone().map(|v| signature_of(v, self.open));
        self.emitted_gen = self.gen;
        self.pending_change = false;
        if !self.emitted_once || self.force_emit || last_sig.as_deref() != Some(sig.as_str()) {
            self.force_emit = false;
            self.seq += 1;
            let mut st = st;
            st.seq = self.seq;
            self.last_json = serde_json::to_value(&st).ok();
            self.last_emit_ms = now_ms;
            self.emitted_once = true;
            return Some(Line::State(Box::new(st)));
        }
        if hb_due {
            self.last_emit_ms = now_ms;
            return Some(Line::Hb { seq: self.seq });
        }
        None
    }

    /// Milliseconds until something needs attention.
    pub fn next_wake_ms(&self, now_ms: u64) -> u64 {
        let mut wake = self
            .hb_every_ms
            .saturating_sub(now_ms.saturating_sub(self.last_emit_ms));
        wake = wake.min(self.resolver_due_ms.saturating_sub(now_ms));
        if self.pending_change {
            wake = wake.min((self.last_emit_ms + EMIT_MIN_GAP_MS).saturating_sub(now_ms));
        }
        if self.dirty.net || self.dirty.profiles || self.dirty.resolver {
            wake = wake.min((self.last_net_ms + NET_MIN_GAP_MS).saturating_sub(now_ms));
        }
        if self.ledger.is_dirty() {
            wake = wake.min((self.ledger_saved_ms + LEDGER_SAVE_MS).saturating_sub(now_ms));
        }
        if self.open && self.resolved_check.is_some() {
            wake = wake.min(self.resolved_check_due_ms.saturating_sub(now_ms));
        }
        wake.max(5)
    }

    pub fn probe_pending(&self) -> bool {
        self.probe_target.is_some() && self.probes.is_empty()
    }

    #[cfg(test)]
    pub fn state_builds(&self) -> u64 {
        self.builds.get()
    }

    /// Pretend the API's blocking reading was taken `secs` ago.
    #[cfg(test)]
    pub fn age_api_blocking(&mut self, secs: f64) {
        if let Some((_, at)) = self.api.blocking.as_mut() {
            *at -= secs;
        }
    }

    #[cfg(test)]
    pub fn failover_active(&self) -> bool {
        self.fo.active()
    }
}

// ---- Entry point ----------------------------------------------------------------

/// Write one line; false when stdout is gone.
pub fn write_line(out: &mut impl Write, line: &Line) -> bool {
    out.write_all(&line.to_json_line()).and_then(|_| out.flush()).is_ok()
}

/// Ask the kernel to send SIGTERM when the parent process goes away, so an
/// orphaned `qnet watch` shuts itself down (cleanly, via the signal path).
/// Returns false when the parent is already gone.
fn die_with_parent() -> bool {
    // SAFETY: getppid/prctl take no pointers; PR_SET_PDEATHSIG only sets a
    // signal number for this process.
    unsafe {
        let ppid = libc::getppid();
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong, 0, 0, 0);
        // The parent may have exited between fork and prctl.
        libc::getppid() == ppid && ppid != 1
    }
}

/// The event loop. `out` receives each line; returning false (a closed
/// stdout) ends the loop. Returns when asked to shut down.
pub fn run_loop(w: &mut Watch, rx: &Receiver<Event>, clock: &dyn Fn() -> u64, out: &mut dyn FnMut(&Line) -> bool) {
    let mut shutdown = false;

    // Give the first probe a moment so the first line is not a false
    // "unreachable".
    let deadline = clock() + 500;
    while w.probe_pending() && clock() < deadline {
        let left = deadline.saturating_sub(clock()).max(1);
        match rx.recv_timeout(Duration::from_millis(left)) {
            Ok(ev) => {
                if w.handle(ev, clock()) == Flow::Shutdown {
                    shutdown = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }

    loop {
        let now = clock();
        w.process_dirty(now);
        if let Some(line) = w.next_emission(now) {
            if !out(&line) {
                break;
            }
        }
        if shutdown {
            break;
        }
        let wake = w.next_wake_ms(clock());
        match rx.recv_timeout(Duration::from_millis(wake)) {
            Ok(ev) => {
                if w.handle(ev, clock()) == Flow::Shutdown {
                    break;
                }
                while let Ok(ev) = rx.try_recv() {
                    if w.handle(ev, clock()) == Flow::Shutdown {
                        shutdown = true;
                        break;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

pub fn run_watch(be: Box<dyn NetBackend>) -> i32 {
    if !die_with_parent() {
        return 0;
    }
    util::harden_process();
    let (tx, rx) = mpsc::channel::<Event>();
    let mut w = Watch::new(be, util::config_path());
    w.set_notifier(Box::new(desktop_notify));
    w.set_resolved_check(Arc::new(crate::rstate::real_check), tx.clone());
    spawn_signals(tx.clone());
    spawn_stdin(tx.clone());
    spawn_nm_watcher(tx.clone());
    let (probe_tx, probe_h) = spawn_prober(tx.clone(), Cadence::default(), real_probe());
    let (api_tx, api_h) = spawn_api(tx.clone(), ApiTiming::default(), real_api_factory());
    // Keep a second sender for the final join: `shutdown` consumes the
    // watch's own copies.
    w.attach_threads(probe_tx.clone(), api_tx.clone());

    let t0 = Instant::now();
    let clock = move || t0.elapsed().as_millis() as u64;
    w.startup(clock());

    let stdout = std::io::stdout();
    run_loop(&mut w, &rx, &clock, &mut |line| write_line(&mut stdout.lock(), line));

    w.shutdown();
    stop_workers(probe_tx, probe_h, api_tx, api_h);
    0
}

/// One state snapshot with a synchronous probe, for `qnet state`.
pub fn state_once(be: Box<dyn NetBackend>) -> State {
    let mut w = Watch::new(be, util::config_path());
    w.startup(0);
    if let Some(t) = w.probe_target.clone() {
        let req = ProbeRequest { upstream: false, icmp: false };
        let report = run_probe(&t, &req, &mut CanaryState::default());
        w.on_probe(report, 0);
    }
    let mut st = w.state(false);
    st.seq = 1;
    st
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::fake::*;
    use crate::pihole::{Blocking, BlockingState, Summary};
    use std::sync::{Arc, Mutex};

    const PI: &str = "192.168.1.153";
    const MAC: neigh::Mac = [0x3c, 0x52, 0xa1, 0x00, 0x11, 0x22];

    struct Rig {
        w: Watch,
        be: Arc<FakeNet>,
        notes: Arc<Mutex<Vec<(String, String)>>>,
        dir: tempfile::TempDir,
        t: u64,
    }

    fn config_text(extra_failover: &str) -> String {
        format!(
            "[pihole]\naddress = \"{PI}\"\ntls_sha256 = \"{}\"\ncanary = \"doubleclick.net\"\n[failover]\n{extra_failover}\n",
            crate::util::format_fingerprint(&[1; 32])
        )
    }

    fn rig_with(config: Option<String>, be: FakeNet) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        if let Some(c) = config {
            std::fs::write(&path, c).unwrap();
        }
        let be = Arc::new(be);
        let mut w = Watch::new(Box::new(be.clone()), path);
        w.set_state_dir(dir.path().join("state"));
        w.set_runtime_dir(dir.path().join("run"));
        // No real network, no real neighbour table.
        w.set_api_check(Arc::new(|_, _| ApiLiveness::Alive));
        w.set_mac_lookup(Arc::new(|_, _| Some(MAC)));
        let notes: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let n2 = notes.clone();
        w.set_notifier(Box::new(move |t, b| n2.lock().unwrap().push((t.into(), b.into()))));
        w.startup(0);
        Rig { w, be, notes, dir, t: 0 }
    }

    fn rig() -> Rig {
        rig_with(Some(config_text("enabled = true\nfallback = \"router\"")), FakeNet::live_machine())
    }

    fn report(ok: bool, gw: Option<bool>) -> ProbeReport {
        ProbeReport {
            target: PI.parse().unwrap(),
            t: 1_794_000_000.0,
            pihole: ProbeOutcome {
                ok,
                ms: ok.then_some(3.1),
                blocked: ok,
            },
            gateway: gw,
            gateway_blocked: None,
            api: None,
            upstream: None,
            own: OwnQueries { total: 1, blocked: u32::from(ok) },
            gateway_ms: None,
        }
    }

    impl Rig {
        /// One probe, 15 s after the previous one.
        fn probe(&mut self, ok: bool, gw: Option<bool>) {
            self.t += 15_000;
            self.w.on_probe(report(ok, gw), self.t);
            self.w.process_dirty(self.t);
        }
        fn settle(&mut self) {
            // The link must be stable before any failover decision.
            self.t += 15_000;
            self.w.on_probe(report(true, None), self.t);
        }
        /// Three failed probes 15 s apart: 30 s of failure.
        fn fail3(&mut self) {
            for _ in 0..3 {
                self.probe(false, Some(true));
            }
        }
        fn runtime_calls(&self) -> Vec<String> {
            self.be.calls().into_iter().filter(|c| c.starts_with("reapply_runtime_dns")).collect()
        }
        fn saved_calls(&self) -> Vec<String> {
            self.be.calls().into_iter().filter(|c| c.starts_with("reapply_saved")).collect()
        }
        fn state_dir(&self) -> std::path::PathBuf {
            self.dir.path().join("state")
        }
    }

    fn state_of(l: Line) -> State {
        match l {
            Line::State(s) => *s,
            other => panic!("expected a state line, got {other:?}"),
        }
    }

    // -- failover -----------------------------------------------------------

    #[test]
    fn engages_after_thirty_seconds_of_failure_with_gateway_up() {
        let mut r = rig();
        r.settle();
        r.fail3();
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 192.168.1.1"]);
        assert!(r.w.failover_active());
        assert_eq!(
            r.notes.lock().unwrap().as_slice(),
            [("Pi-hole unreachable".to_string(), "Using router DNS".to_string())]
        );
        r.w.process_dirty(r.t + 2_000);
        let st = r.w.state(false);
        assert_eq!(st.dns.mode, "fallback");
        assert_eq!(st.dns.mode_source, "runtime-failover");
        assert!(st.dns.failover.active && st.dns.failover.enabled);
        assert!(st.dns.failover.since > 0);
        assert!(!st.dns.bypassed, "a failover is not a bypass");
        // The saved profile was never written.
        assert!(!r.be.calls().iter().any(|c| c.starts_with("set_profile_dns")));
        assert!(r.be.profile(U_WIFI).dns.v4_dns == vec![PI.parse::<std::net::Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn two_failures_then_success_does_nothing() {
        let mut r = rig();
        r.settle();
        r.probe(false, Some(true));
        r.probe(false, Some(true));
        r.probe(true, None);
        r.probe(false, Some(true));
        assert!(r.runtime_calls().is_empty());
        assert!(!r.w.failover_active());
    }

    #[test]
    fn gateway_down_means_no_failover() {
        let mut r = rig();
        r.settle();
        for _ in 0..6 {
            r.probe(false, Some(false));
        }
        assert!(r.runtime_calls().is_empty());
        // Gateway returns; the very next failing probe engages.
        r.probe(false, Some(true));
        assert_eq!(r.runtime_calls().len(), 1);
    }

    #[test]
    fn link_down_means_no_failover_even_if_gateway_claims_up() {
        let mut r = rig();
        r.settle();
        r.be.set_link_down();
        r.w.handle(Event::Nm(NmKind::Core), r.t);
        r.t += 1_000;
        r.w.process_dirty(r.t);
        for _ in 0..6 {
            r.probe(false, Some(true));
        }
        assert!(r.runtime_calls().is_empty(), "{:?}", r.be.calls());
        let st = r.w.state(false);
        assert_eq!(st.link.kind, "none");
        assert_eq!(st.dns.mode, "none");
    }

    #[test]
    fn failover_disabled_in_config_or_profile_not_pinned_never_engages() {
        let mut r = rig_with(Some(config_text("enabled = false")), FakeNet::live_machine());
        r.settle();
        r.fail3();
        r.fail3();
        assert!(r.runtime_calls().is_empty());
        assert!(!r.w.state(false).dns.failover.enabled);

        // Profile in Automatic: the Pi-hole being down is not our business.
        let be = FakeNet::live_machine();
        be.set_profile_dns_direct(U_WIFI, be.profile(U_WIFI).dns.automatic());
        be.apply_saved_to_link();
        let mut r = rig_with(Some(config_text("enabled = true")), be);
        r.settle();
        r.fail3();
        r.fail3();
        assert!(r.runtime_calls().is_empty());
    }

    /// A cycle in which the canary is answered but upstream is not, with the
    /// gateway probe the prober now takes in exactly that situation.
    fn degraded_report(gateway: Option<bool>) -> ProbeReport {
        let mut rep = report(true, gateway);
        rep.upstream = Some(false);
        rep
    }

    #[test]
    fn a_degraded_pihole_fails_over_after_thirty_seconds_when_the_gateway_answers() {
        let mut r = rig();
        r.settle();
        for _ in 0..2 {
            r.t += 15_000;
            r.w.on_probe(degraded_report(Some(true)), r.t);
        }
        assert!(r.runtime_calls().is_empty(), "30 s have not passed");
        assert_eq!(r.w.state(false).pihole.health, "degraded");
        r.t += 15_000;
        r.w.on_probe(degraded_report(Some(true)), r.t);
        assert_eq!(r.runtime_calls().len(), 1, "degraded for 30 s with the gateway up");
        assert!(r.w.failover_active());
    }

    #[test]
    fn a_degraded_pihole_without_gateway_evidence_does_not_fail_over() {
        let mut r = rig();
        r.settle();
        for _ in 0..6 {
            r.t += 15_000;
            r.w.on_probe(degraded_report(None), r.t);
        }
        assert!(r.runtime_calls().is_empty(), "no gateway evidence, no failover");
        // The gateway itself is down too: the network is the problem.
        for _ in 0..3 {
            r.t += 15_000;
            r.w.on_probe(degraded_report(Some(false)), r.t);
        }
        assert!(r.runtime_calls().is_empty());
        r.t += 15_000;
        r.w.on_probe(degraded_report(Some(true)), r.t);
        assert_eq!(r.runtime_calls().len(), 1);
    }

    #[test]
    fn a_live_pinned_web_api_stops_an_unreachable_failover_until_it_goes_quiet_too() {
        let mut r = rig();
        r.settle();
        // DNS silent for minutes, gateway fine, but the Pi-hole's API answers.
        for _ in 0..8 {
            r.t += 15_000;
            let mut rep = report(false, Some(true));
            rep.api = Some(ApiLiveness::Alive);
            r.w.on_probe(rep, r.t);
        }
        assert!(r.runtime_calls().is_empty(), "host alive: packet loss or spoofing, not an outage");
        let st = r.w.state(false);
        assert_eq!(st.pihole.health, "unreachable");
        assert!(st.pihole.health_reason.contains("web API still does"), "{}", st.pihole.health_reason);
        // A different certificate does not count as the Pi-hole being dead either.
        r.t += 15_000;
        let mut rep = report(false, Some(true));
        rep.api = Some(ApiLiveness::Mismatch);
        r.w.on_probe(rep, r.t);
        assert!(r.runtime_calls().is_empty());
        assert!(r.w.state(false).pihole.health_reason.contains("different certificate"));
        // Now the API is dead as well: fail over right away.
        r.t += 15_000;
        let mut rep = report(false, Some(true));
        rep.api = Some(ApiLiveness::Dead);
        r.w.on_probe(rep, r.t);
        assert_eq!(r.runtime_calls().len(), 1);
        assert!(r.w.failover_active());
    }

    #[test]
    fn a_degraded_pihole_is_not_held_back_by_a_web_api_that_is_up() {
        // The canary is answered, so the API is not even asked about; and an
        // old "alive" from an earlier outage must not linger.
        let mut r = rig();
        r.settle();
        let mut rep = report(false, Some(true));
        rep.api = Some(ApiLiveness::Alive);
        r.t += 15_000;
        r.w.on_probe(rep, r.t);
        for _ in 0..3 {
            r.t += 15_000;
            r.w.on_probe(degraded_report(Some(true)), r.t);
        }
        assert_eq!(r.runtime_calls().len(), 1);
    }

    #[test]
    fn recovery_waits_for_upstream_to_work_again() {
        let mut r = rig();
        r.settle();
        r.fail3();
        assert!(r.w.failover_active());
        for _ in 0..4 {
            r.t += 15_000;
            let mut rep = report(true, None);
            rep.upstream = Some(false);
            r.w.on_probe(rep, r.t);
        }
        assert!(r.w.failover_active(), "canary alone is not enough");
        assert!(r.saved_calls().is_empty());
        for _ in 0..3 {
            r.t += 15_000;
            let mut rep = report(true, None);
            rep.upstream = Some(true);
            r.w.on_probe(rep, r.t);
        }
        assert!(!r.w.failover_active());
        assert_eq!(r.saved_calls().len(), 1);
    }

    #[test]
    fn recovers_after_three_good_probes_and_notifies() {
        let mut r = rig();
        r.settle();
        r.fail3();
        assert!(r.w.failover_active());
        r.probe(true, None);
        r.probe(true, None);
        assert_eq!(r.saved_calls().len(), 0);
        r.probe(true, None);
        assert_eq!(r.saved_calls().len(), 1);
        assert!(!r.w.failover_active());
        assert_eq!(r.notes.lock().unwrap().len(), 2);
        assert_eq!(r.notes.lock().unwrap()[1].0, "Pi-hole is back");
        r.w.process_dirty(r.t + 2_000);
        assert_eq!(r.w.state(false).dns.mode, "pihole");
    }

    #[test]
    fn a_second_outage_right_after_recovery_is_held_off() {
        let mut r = rig();
        r.settle();
        r.fail3();
        r.probe(true, None);
        r.probe(true, None);
        r.probe(true, None);
        assert_eq!(r.saved_calls().len(), 1);
        // Down again at once: 60 s hold-down after the recovery.
        r.probe(false, Some(true));
        r.probe(false, Some(true));
        r.probe(false, Some(true));
        assert_eq!(r.runtime_calls().len(), 1, "still only the first failover");
        r.probe(false, Some(true));
        assert_eq!(r.runtime_calls().len(), 2, "allowed once the hold-down has passed");
    }

    #[test]
    fn failed_engage_is_reported_in_error_and_retried_later() {
        let mut r = rig();
        r.settle();
        r.be.fail_reapply(Some(NetError::Denied("polkit says no".into())));
        r.fail3();
        assert!(!r.w.failover_active());
        assert!(r.w.state(false).error.contains("polkit says no"));
        r.be.fail_reapply(None);
        r.probe(false, Some(true)); // within the 30 s cooldown (15 s later)
        assert!(!r.w.failover_active());
        r.probe(false, Some(true));
        assert!(r.w.failover_active());
        assert_eq!(r.w.state(false).error, "");
    }

    #[test]
    fn router_fallback_without_a_known_gateway_uses_quad9_not_nothing() {
        let mut r = rig();
        r.settle();
        r.be.set_gateway(None);
        r.fail3();
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 9.9.9.9,149.112.112.112"]);
    }

    #[test]
    fn quad9_fallback_uses_public_servers() {
        let mut r = rig_with(Some(config_text("fallback = \"quad9\"")), FakeNet::live_machine());
        r.settle();
        r.fail3();
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 9.9.9.9,149.112.112.112"]);
        assert_eq!(r.notes.lock().unwrap()[0].1, "Using quad9 DNS");
    }

    #[test]
    fn router_fallback_is_only_trusted_on_the_network_the_profile_was_pinned_on() {
        let mut r = rig();
        // The profile was pinned on a network with another router.
        actions::save_prev(
            &r.state_dir(),
            U_WIFI,
            &r.be.profile(U_WIFI).dns,
            Some("10.0.0.1".parse().unwrap()),
        )
        .unwrap();
        r.settle();
        r.fail3();
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 9.9.9.9,149.112.112.112"]);
        let st = r.w.state(false);
        assert!(st.dns.failover.reason.contains("quad9"), "{}", st.dns.failover.reason);
        assert!(st.dns.failover.reason.contains("not the one the profile was pinned on"));
        assert_eq!(r.notes.lock().unwrap()[0].1, "Using quad9 DNS", "the notification names what is really used");
    }

    #[test]
    fn the_gateway_is_learned_once_from_a_healthy_pinned_profile() {
        let mut r = rig();
        assert!(actions::load_prev(&r.state_dir(), U_WIFI).is_none());
        r.settle();
        let prev = actions::load_prev(&r.state_dir(), U_WIFI).expect("recorded on the first healthy probe");
        assert_eq!(prev.gateway_addr(), Some("192.168.1.1".parse().unwrap()));
        // Not rewritten on every probe, and never overwritten by a different router.
        actions::record_link_trust(&r.state_dir(), U_WIFI, "10.0.0.1".parse().unwrap(), MAC).unwrap();
        r.probe(true, None);
        r.probe(true, None);
        assert_eq!(
            actions::load_prev(&r.state_dir(), U_WIFI).unwrap().gateway_addr(),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn unhealthy_or_unpinned_profiles_learn_nothing() {
        let mut r = rig();
        r.t += 15_000;
        r.w.on_probe(report(false, Some(true)), r.t);
        assert!(actions::load_prev(&r.state_dir(), U_WIFI).is_none());
        let be = FakeNet::live_machine();
        be.set_profile_dns_direct(U_WIFI, be.profile(U_WIFI).dns.automatic());
        be.apply_saved_to_link();
        let mut r = rig_with(Some(config_text("enabled = true")), be);
        r.settle();
        assert!(actions::load_prev(&r.state_dir(), U_WIFI).is_none());
    }

    #[test]
    fn recovery_goes_back_to_the_link_that_was_failed_over_even_if_the_primary_changed() {
        let mut r = rig();
        r.settle();
        r.fail3();
        assert!(r.w.failover_active());
        // Ethernet comes up and takes the default route; Wi-Fi stays up.
        r.be.add_ethernet_primary();
        r.w.handle(Event::Nm(NmKind::Core), r.t);
        r.t += 1_000;
        r.w.process_dirty(r.t);
        assert_eq!(r.w.state(false).link.kind, "ethernet");
        assert!(r.w.failover_active(), "the engaged link is still up: nothing was reset");
        r.probe(true, None);
        r.probe(true, None);
        r.probe(true, None);
        assert_eq!(r.saved_calls(), vec!["reapply_saved wlp7s0"], "{:?}", r.be.calls());
        assert!(!r.w.failover_active());
    }

    #[test]
    fn failover_is_dropped_when_the_engaged_link_itself_goes_away() {
        let mut r = rig();
        r.settle();
        r.fail3();
        r.be.set_link_down();
        r.w.handle(Event::Nm(NmKind::Core), r.t);
        r.t += 1_000;
        r.w.process_dirty(r.t);
        r.probe(true, None);
        assert!(!r.w.failover_active(), "a new activation loads the saved profile anyway");
        assert!(r.saved_calls().is_empty(), "nothing to undo on a dead link");
    }

    #[test]
    fn shutdown_restores_only_when_the_last_probe_passed() {
        // Pi-hole answering again: put the saved profile back.
        let mut r = rig();
        r.settle();
        r.fail3();
        r.probe(true, None);
        assert!(r.w.failover_active());
        r.w.shutdown();
        assert_eq!(r.saved_calls().len(), 1);
        assert_eq!(r.be.link_servers(), vec![PI.parse::<std::net::IpAddr>().unwrap()]);

        // Pi-hole still dead: do not strand DNS on it.
        let mut r = rig();
        r.settle();
        r.fail3();
        assert!(r.w.failover_active());
        r.w.shutdown();
        assert!(r.saved_calls().is_empty(), "left on the fallback");
        assert_eq!(r.be.link_servers(), vec!["192.168.1.1".parse::<std::net::IpAddr>().unwrap()]);

        // Without failover, shutdown touches nothing.
        let mut r = rig();
        r.w.shutdown();
        assert_eq!(r.be.writes(), 0);
    }

    #[test]
    fn stranded_failover_from_a_crash_is_adopted_and_cleaned_up() {
        let be = FakeNet::live_machine();
        be.reapply_runtime_dns("wlp7s0", &["192.168.1.1".parse().unwrap()]).unwrap();
        let mut r = rig_with(Some(config_text("enabled = true")), be);
        assert!(r.w.failover_active(), "device runs router DNS but the profile says Pi-hole");
        assert_eq!(r.w.state(false).dns.mode, "fallback");
        r.settle();
        r.probe(true, None);
        r.probe(true, None);
        assert!(r.w.failover_active(), "two good probes are not enough");
        r.probe(true, None);
        assert!(!r.w.failover_active());
        assert_eq!(r.be.link_servers(), vec![PI.parse::<std::net::IpAddr>().unwrap()]);
    }

    #[test]
    fn probe_reports_for_an_old_target_are_dropped() {
        let mut r = rig();
        let mut rep = report(true, None);
        rep.target = "10.9.9.9".parse().unwrap();
        r.w.on_probe(rep, 20_000);
        assert!(r.w.state(false).pihole.probes.is_empty());
    }

    // -- detection without a config -------------------------------------------

    #[test]
    fn unconfigured_pihole_is_detected_but_never_adopted_as_the_address() {
        let mut r = rig_with(None, FakeNet::live_machine());
        let st = r.w.state(false);
        assert!(!st.pihole.configured);
        assert_eq!(st.pihole.api, "unconfigured");
        assert_eq!(st.pihole.address, "");
        assert_eq!(st.pihole.admin_url, "");
        assert_eq!(st.pihole.detected, "");
        assert_eq!(st.dns.mode, "unknown", "never 'custom' while the candidate is still being checked");
        assert_eq!(st.pihole.health, "unknown");

        r.t = 15_000;
        r.w.on_probe(report(true, None), r.t);
        let st = r.w.state(false);
        assert_eq!(st.pihole.address, "", "the address comes from the config only");
        assert_eq!(st.pihole.admin_url, "");
        assert_eq!(st.pihole.detected, PI, "display only");
        assert!(st.pihole.reachable && !st.pihole.configured);
        assert_eq!(st.pihole.blocking, "enabled");
        assert_eq!(st.dns.mode, "pihole");
        assert_eq!(st.dns.leaks.len(), 2);
        assert!(!st.dns.failover.enabled, "no failover without a config");
        assert!(!st.dns.bypassed, "bypassed needs a configured Pi-hole");
        // And no failover however long it stays down.
        r.settle();
        r.fail3();
        r.fail3();
        assert!(r.runtime_calls().is_empty());
    }

    #[test]
    fn a_resolver_that_does_not_block_ends_the_pending_state_as_custom() {
        let mut r = rig_with(None, FakeNet::live_machine());
        let mut rep = report(true, None);
        rep.pihole.blocked = false; // a LAN resolver that does not block
        r.w.on_probe(rep, 15_000);
        let st = r.w.state(false);
        assert_eq!(st.pihole.detected, "");
        assert_eq!(st.dns.mode, "custom", "the question is answered now");
    }

    // -- the panel being open ---------------------------------------------------

    #[test]
    fn opening_the_panel_never_requests_a_scan() {
        let be = FakeNet::live_machine();
        be.set_last_scan_age_ms(Some(600_000)); // as stale as it gets
        let mut r = rig_with(None, be);
        r.w.handle(Event::Cmd("open".into()), 2_000);
        r.w.handle(Event::Cmd("closed".into()), 3_000);
        r.w.handle(Event::Cmd("open".into()), 60_000);
        r.w.handle(Event::Cmd("refresh".into()), 61_000);
        r.w.process_dirty(62_000);
        assert!(!r.be.calls().iter().any(|c| c.starts_with("request_scan")), "{:?}", r.be.calls());
        assert!(!r.w.state(false).scan.running);
        // It does report how old the last scan is, counting up between reads.
        assert!(r.w.state(false).scan.last_scan_age_s.unwrap() >= 600);
    }

    #[test]
    fn ap_signals_are_ignored_while_closed_and_read_on_open() {
        let mut r = rig();
        let aps_reads = |r: &Rig| r.be.calls().iter().filter(|c| *c == "snapshot aps=true").count();
        let before = aps_reads(&r);
        r.t = 5_000;
        for _ in 0..20 {
            r.w.handle(Event::Nm(NmKind::Ap), r.t);
        }
        r.w.process_dirty(r.t);
        assert_eq!(aps_reads(&r), before, "closed panel, no AP reads");
        r.t += 1_000;
        r.w.handle(Event::Cmd("open".into()), r.t);
        r.w.process_dirty(r.t + 300);
        assert!(aps_reads(&r) > before, "open re-reads the AP list");
    }

    #[test]
    fn core_signals_are_coalesced_into_one_read() {
        let mut r = rig();
        let reads = |r: &Rig| r.be.calls().iter().filter(|c| c.starts_with("snapshot")).count();
        r.t = 10_000;
        let before = reads(&r);
        for _ in 0..50 {
            r.w.handle(Event::Nm(NmKind::Core), r.t);
        }
        r.w.process_dirty(r.t);
        assert_eq!(reads(&r) - before, 1);
    }

    #[test]
    fn nm_failure_shows_in_error_and_keeps_last_good_state() {
        let mut r = rig();
        r.be.set_snapshot_error(true);
        r.t = 10_000;
        r.w.handle(Event::Nm(NmKind::Core), r.t);
        r.w.process_dirty(r.t);
        let st = r.w.state(false);
        assert!(st.error.contains("NetworkManager"), "{}", st.error);
        assert_eq!(st.link.kind, "wifi", "stale but not blank");
        r.be.set_snapshot_error(false);
        r.t += 1_000;
        r.w.handle(Event::Nm(NmKind::Core), r.t);
        r.w.process_dirty(r.t);
        assert_eq!(r.w.state(false).error, "");
    }

    #[test]
    fn gateway_latency_exists_only_while_open_and_fresh() {
        let mut r = rig();
        let mut rep = report(true, None);
        rep.gateway_ms = Some(3.84);
        // Closed: a stray measurement is not shown.
        r.w.on_probe(rep.clone(), 10_000);
        assert_eq!(r.w.state(false).link.gateway_ms, None);
        r.w.handle(Event::Cmd("open".into()), 11_000);
        r.w.on_probe(rep.clone(), 12_000);
        assert_eq!(r.w.state(false).link.gateway_ms, Some(3.8));
        // An unanswered ping clears nothing by itself but does not refresh it.
        // Closing hides it at once.
        r.w.handle(Event::Cmd("closed".into()), 13_000);
        assert_eq!(r.w.state(false).link.gateway_ms, None);
        // And a new Pi-hole target forgets it.
        r.w.handle(Event::Cmd("open".into()), 14_000);
        r.w.on_probe(rep, 15_000);
        assert!(r.w.state(false).link.gateway_ms.is_some());
    }

    // -- numbers ----------------------------------------------------------------

    fn api_report(total: u64, blocked: u64) -> ApiReport {
        ApiReport {
            status: "ok",
            summary: Some(Summary { total, blocked, percent: 0.0 }),
            blocking: Some(Blocking { state: BlockingState::Enabled, timer: None }),
            history: None,
            upstreams: None,
            at: util::unix_now(),
        }
    }

    #[test]
    fn our_own_probes_are_subtracted_from_todays_numbers() {
        let mut r = rig();
        r.w.set_heartbeat_ms(1);
        for _ in 0..10 {
            let mut rep = report(true, None);
            rep.t = util::unix_now();
            rep.own = OwnQueries { total: 2, blocked: 1 }; // e.g. canary + upstream
            r.w.on_probe(rep, r.t);
        }
        r.w.handle(Event::Api(api_report(300, 120)), r.t);
        let st = r.w.state(false);
        assert_eq!(st.pihole.today.self_queries, 20);
        assert_eq!(st.pihole.today.total, 280);
        assert_eq!(st.pihole.today.blocked, 110);
        assert!((st.pihole.today.percent - 39.3).abs() < 0.05, "{}", st.pihole.today.percent);
        // Never negative, even if Pi-hole has not caught up with our queries.
        r.w.handle(Event::Api(api_report(5, 1)), r.t);
        let st = r.w.state(false);
        assert_eq!((st.pihole.today.total, st.pihole.today.blocked, st.pihole.today.self_queries), (0, 0, 5));
        assert_eq!(st.pihole.today.percent, 0.0);
    }

    #[test]
    fn today_does_not_dip_between_api_polls() {
        let mut r = rig();
        r.w.handle(Event::Api(api_report(100, 40)), r.t);
        assert_eq!(r.w.state(false).pihole.today.total, 100);
        // Our probes keep flying, but the Pi-hole's reading is from before
        // them: subtracting them from it would make the count fall.
        for _ in 0..3 {
            let mut rep = report(true, None);
            rep.t = util::unix_now();
            rep.own = OwnQueries { total: 2, blocked: 1 };
            r.w.on_probe(rep, r.t);
        }
        let st = r.w.state(false);
        assert_eq!((st.pihole.today.total, st.pihole.today.self_queries), (100, 0));
        // The next reading includes them, and now they are taken out.
        r.w.handle(Event::Api(api_report(106, 43)), r.t);
        let st = r.w.state(false);
        assert_eq!((st.pihole.today.total, st.pihole.today.blocked, st.pihole.today.self_queries), (100, 40, 6));
    }

    #[test]
    fn the_query_tally_survives_a_restart() {
        let mut r = rig();
        let mut rep = report(true, None);
        rep.t = util::unix_now();
        rep.own = OwnQueries { total: 7, blocked: 4 };
        r.w.on_probe(rep, 1_000);
        r.w.shutdown();
        let saved = r.state_dir().join("self-queries.json");
        assert!(saved.exists());
        let led = Ledger::load(&saved);
        assert_eq!(led.sums(util::unix_now()), (7, 4));
        // A fresh Watch on the same state dir starts from it.
        let be = Arc::new(FakeNet::live_machine());
        let mut w2 = Watch::new(Box::new(be), r.dir.path().join("config.toml"));
        w2.set_state_dir(r.state_dir());
        w2.startup(0);
        w2.on_api(api_report(100, 50));
        assert_eq!(w2.state(false).pihole.today.self_queries, 7);
    }

    #[test]
    fn health_and_canary_blocked() {
        let mut r = rig();
        let st = r.w.state(false);
        assert_eq!(st.pihole.health, "unknown");
        assert_eq!(st.pihole.canary_blocked, None);
        r.w.on_probe(report(true, None), 15_000);
        let st = r.w.state(false);
        assert_eq!(st.pihole.health, "ok");
        assert_eq!(st.pihole.canary_blocked, Some(true));
        // Paused: answered, not blocked.
        let mut rep = report(true, None);
        rep.pihole.blocked = false;
        r.w.on_probe(rep, 30_000);
        assert_eq!(r.w.state(false).pihole.canary_blocked, Some(false));
        // Canary fine, upstream failing.
        let mut rep = report(true, None);
        rep.upstream = Some(false);
        r.w.on_probe(rep, 45_000);
        assert_eq!(r.w.state(false).pihole.health, "degraded");
        // And back.
        let mut rep = report(true, None);
        rep.upstream = Some(true);
        r.w.on_probe(rep, 60_000);
        assert_eq!(r.w.state(false).pihole.health, "ok");
        // Two silent probes: unreachable, and upstream is forgotten.
        r.w.on_probe(report(false, Some(true)), 75_000);
        r.w.on_probe(report(false, Some(true)), 90_000);
        assert_eq!(r.w.state(false).pihole.health, "unreachable");
        // A canary answered after the outage is judged on its own again.
        r.w.on_probe(report(true, None), 105_000);
        assert_eq!(r.w.state(false).pihole.health, "ok");
    }

    // -- output -------------------------------------------------------------------

    #[test]
    fn emission_rules() {
        let mut r = rig();
        // First line goes out immediately.
        let a = state_of(r.w.next_emission(100).expect("first state"));
        assert_eq!(a.seq, 1);
        assert!(!a.heartbeat);
        // Nothing changed: nothing to say.
        assert!(r.w.next_emission(200).is_none());
        // A change inside the 250 ms window waits.
        r.w.handle(Event::Api(api_report(10, 2)), 300);
        assert!(r.w.next_emission(320).is_none());
        assert!(r.w.next_wake_ms(320) <= 30);
        let b = state_of(r.w.next_emission(360).expect("coalesced change"));
        assert_eq!(b.seq, 2);
        // Quiet for 10 s: a bare heartbeat that repeats the last seq.
        assert!(r.w.next_emission(9_000).is_none());
        let h = r.w.next_emission(10_600).expect("heartbeat");
        assert_eq!(h, Line::Hb { seq: 2 });
        assert_eq!(h.to_json_line(), b"{\"type\":\"hb\",\"seq\":2}\n".to_vec());
        // And again 10 s later; the state seq did not move.
        assert!(r.w.next_emission(15_000).is_none());
        assert_eq!(r.w.next_emission(20_700).unwrap(), Line::Hb { seq: 2 });
    }

    #[test]
    fn quiet_wakes_do_not_build_the_state() {
        let mut r = rig();
        r.w.next_emission(100).unwrap();
        let built = r.w.state_builds();
        for ms in (200..9_000).step_by(100) {
            assert!(r.w.next_emission(ms).is_none());
        }
        assert_eq!(r.w.state_builds(), built, "no inputs changed, so nothing was serialised");
        // An ignored AP signal while closed is also free.
        r.w.handle(Event::Nm(NmKind::Ap), 9_100);
        r.w.process_dirty(9_100);
        assert!(r.w.next_emission(9_200).is_none());
        assert_eq!(r.w.state_builds(), built);
        // The heartbeat check itself rebuilds once to see whether anything
        // time-driven changed; unchanged, it prints just hb.
        assert_eq!(r.w.next_emission(10_200).unwrap(), Line::Hb { seq: 1 });
        assert_eq!(r.w.state_builds(), built + 1);
    }

    #[test]
    fn a_clock_driven_change_is_sent_as_a_state_not_swallowed_by_the_heartbeat() {
        let mut r = rig();
        r.w.next_emission(100).unwrap();
        // The API reading goes stale on the clock alone (45 s), no event.
        r.w.handle(Event::Api(api_report(10, 1)), 200);
        state_of(r.w.next_emission(500).unwrap());
        // Simulate staleness by aging the stored reading.
        r.w.age_api_blocking(60.0);
        let line = r.w.next_emission(11_000).unwrap();
        assert!(matches!(line, Line::State(_)), "{line:?}");
    }

    #[test]
    fn the_run_loop_emits_state_then_heartbeats_and_stops_on_eof() {
        let be = Arc::new(FakeNet::live_machine());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("c.toml"), config_text("enabled = true")).unwrap();
        let mut w = Watch::new(Box::new(be), dir.path().join("c.toml"));
        w.set_state_dir(dir.path().join("state"));
        w.set_heartbeat_ms(60);
        w.startup(0);
        let (tx, rx) = mpsc::channel::<Event>();
        // The first probe is what the loop waits for before the first line.
        tx.send(Event::Probe(report(true, None))).unwrap();
        let t0 = Instant::now();
        let clock = move || t0.elapsed().as_millis() as u64;
        let lines: Arc<Mutex<Vec<Line>>> = Arc::default();
        let l2 = lines.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            tx.send(Event::StdinEof).unwrap();
        });
        run_loop(&mut w, &rx, &clock, &mut |l| {
            l2.lock().unwrap().push(l.clone());
            true
        });
        h.join().unwrap();
        let lines = lines.lock().unwrap();
        assert!(matches!(lines[0], Line::State(_)));
        let hbs = lines.iter().filter(|l| matches!(l, Line::Hb { .. })).count();
        let states = lines.iter().filter(|l| matches!(l, Line::State(_))).count();
        assert_eq!(states, 1, "nothing changed, so only the first state");
        assert!(hbs >= 2, "{} heartbeats", hbs);
    }

    #[test]
    fn a_closed_stdout_ends_the_loop() {
        let be = Arc::new(FakeNet::live_machine());
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watch::new(Box::new(be), dir.path().join("none.toml"));
        w.set_state_dir(dir.path().join("state"));
        w.startup(0);
        let (_tx, rx) = mpsc::channel::<Event>();
        let t0 = Instant::now();
        let clock = move || t0.elapsed().as_millis() as u64;
        let mut calls = 0;
        run_loop(&mut w, &rx, &clock, &mut |_| {
            calls += 1;
            false // EPIPE
        });
        assert_eq!(calls, 1);
    }

    #[test]
    fn stdin_eof_and_signal_end_the_run() {
        let mut r = rig();
        assert_eq!(r.w.handle(Event::StdinEof, 1), Flow::Shutdown);
        assert_eq!(r.w.handle(Event::Signal, 1), Flow::Shutdown);
        assert_eq!(r.w.handle(Event::Cmd("bogus".into()), 1), Flow::Continue);
    }

    #[test]
    fn config_error_turns_features_off_and_is_shown() {
        let r = rig_with(Some("this is [not toml".into()), FakeNet::live_machine());
        let st = r.w.state(false);
        assert!(st.error.contains("config.toml"));
        assert!(!st.pihole.configured);
    }

    #[test]
    fn nm_signal_paths_are_classified() {
        assert_eq!(classify_nm_signal("/org/freedesktop/NetworkManager/AccessPoint/12"), NmKind::Ap);
        assert_eq!(classify_nm_signal("/org/freedesktop/NetworkManager/Settings/3"), NmKind::Settings);
        assert_eq!(classify_nm_signal("/org/freedesktop/NetworkManager/Settings"), NmKind::Settings);
        assert_eq!(classify_nm_signal("/org/freedesktop/NetworkManager/Devices/4"), NmKind::Core);
        assert_eq!(classify_nm_signal("/org/freedesktop/NetworkManager/IP4Config/2"), NmKind::Core);
        assert_eq!(classify_nm_signal("/org/freedesktop/NetworkManager"), NmKind::Core);
    }

    // -- closed-panel quiet ---------------------------------------------------------

    fn healthy_report(ms: f64) -> ProbeReport {
        let mut rep = report(true, None);
        rep.pihole.ms = Some(ms);
        rep.t = util::unix_now();
        rep
    }

    #[test]
    fn a_closed_healthy_probe_emits_hb_only() {
        let mut r = rig();
        // As at start-up: the first probe lands before the first line.
        r.w.handle(Event::Probe(healthy_report(5.0)), 50);
        let first = state_of(r.w.next_emission(100).expect("first state"));
        assert_eq!(first.seq, 1);
        // A healthy probe arrives while the panel is closed: new latency, one
        // more point in probes[]; nothing a closed panel can show.
        r.w.handle(Event::Probe(healthy_report(7.5)), 1_000);
        assert!(r.w.next_emission(1_100).is_none(), "no state line for it");
        r.w.handle(Event::Probe(healthy_report(9.1)), 2_000);
        assert!(r.w.next_emission(2_100).is_none());
        // What does go out is the heartbeat, and the state seq did not move.
        let line = r.w.next_emission(10_200).expect("heartbeat");
        assert_eq!(line, Line::Hb { seq: 1 });
        // Yet the numbers are not lost: asking for the state shows them.
        let st = r.w.state(false);
        assert_eq!(st.pihole.probes.len(), 3);
        assert_eq!(st.pihole.latency_ms, Some(9.1));
    }

    #[test]
    fn a_closed_probe_that_matters_still_emits_a_state() {
        let mut r = rig();
        state_of(r.w.next_emission(100).unwrap());
        // Two silent probes flip reachable: that is news even when closed.
        r.w.handle(Event::Probe(report(false, Some(false))), 1_000);
        r.w.handle(Event::Probe(report(false, Some(false))), 1_500);
        let st = state_of(r.w.next_emission(1_800).expect("state"));
        assert!(!st.pihole.reachable);
        assert_eq!(st.pihole.health, "unreachable");
    }

    #[test]
    fn open_resends_the_full_state_even_if_nothing_else_changed() {
        let mut r = rig();
        r.w.handle(Event::Probe(healthy_report(5.0)), 50);
        state_of(r.w.next_emission(100).unwrap());
        for ms in [1_000u64, 2_000, 3_000] {
            r.w.handle(Event::Probe(healthy_report(ms as f64 / 100.0)), ms);
        }
        assert!(r.w.next_emission(3_100).is_none());
        r.w.handle(Event::Cmd("open".into()), 4_000);
        let st = state_of(r.w.next_emission(4_100).expect("open sends the state"));
        assert_eq!(st.seq, 2);
        assert!(st.pihole.probes.len() >= 4, "and now it carries the probes");
        // Open for real: a probe is a state line again.
        r.w.handle(Event::Probe(healthy_report(1.2)), 5_000);
        assert!(matches!(r.w.next_emission(5_100), Some(Line::State(_))));
        // Closing does not itself cause a line (the signature just shrinks)...
        r.w.handle(Event::Cmd("closed".into()), 6_000);
        let after_close = r.w.next_emission(6_100);
        assert!(after_close.is_none() || matches!(after_close, Some(Line::State(_))));
        // ...and from then on healthy probes are quiet again.
        let before = r.w.seq;
        r.w.handle(Event::Probe(healthy_report(1.4)), 7_000);
        assert!(r.w.next_emission(7_100).is_none());
        assert_eq!(r.w.seq, before + u64::from(after_close.is_some()));
    }

    #[test]
    fn a_wifi_bitrate_change_while_closed_is_not_news() {
        let mut r = rig();
        r.w.handle(Event::Probe(healthy_report(5.0)), 50);
        state_of(r.w.next_emission(100).unwrap());
        r.be.set_bitrate_kbps(433_000);
        r.w.handle(Event::Nm(NmKind::Core), 1_000);
        r.w.process_dirty(1_300);
        assert!(r.w.next_emission(1_400).is_none());
        assert_eq!(r.w.state(false).link.bitrate_mbps, 433, "still read, just not announced");
    }

    // -- router trust: IP and MAC -----------------------------------------------------

    fn record(r: &Rig, gw: &str, mac: neigh::Mac) {
        actions::record_link_trust(&r.state_dir(), U_WIFI, gw.parse().unwrap(), mac).unwrap();
    }

    #[test]
    fn router_fallback_needs_both_ip_and_mac_to_match() {
        // Recorded and unchanged: the router is used.
        let mut r = rig();
        record(&r, "192.168.1.1", MAC);
        r.settle();
        r.fail3();
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 192.168.1.1"]);
        assert_eq!(r.w.state(false).dns.failover.fallback, "router");
        assert_eq!(r.w.state(false).dns.failover.reason, "Pi-hole not answering");

        // Same IP, different MAC (another router took the address): quad9.
        let mut r = rig();
        record(&r, "192.168.1.1", [9, 9, 9, 9, 9, 9]);
        r.settle();
        r.fail3();
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 9.9.9.9,149.112.112.112"]);
        let st = r.w.state(false);
        assert_eq!(st.dns.failover.fallback, "quad9", "the one really in use");
        assert!(st.dns.failover.reason.contains("MAC"), "{}", st.dns.failover.reason);

        // The MAC cannot be determined now: not trusted either.
        let mut r = rig();
        record(&r, "192.168.1.1", MAC);
        r.w.set_mac_lookup(Arc::new(|_, _| None));
        r.settle();
        r.fail3();
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 9.9.9.9,149.112.112.112"]);
    }

    #[test]
    fn a_router_that_forwards_to_the_pihole_is_no_fallback() {
        let mut r = rig();
        record(&r, "192.168.1.1", MAC);
        r.settle();
        for _ in 0..3 {
            r.t += 15_000;
            let mut rep = report(false, Some(true));
            rep.gateway_blocked = Some(true); // the router answered the canary 0.0.0.0
            r.w.on_probe(rep, r.t);
        }
        assert_eq!(r.runtime_calls(), vec!["reapply_runtime_dns wlp7s0 9.9.9.9,149.112.112.112"]);
        let st = r.w.state(false);
        assert_eq!(st.dns.failover.fallback, "quad9");
        assert!(st.dns.failover.reason.contains("forwards DNS to the Pi-hole"), "{}", st.dns.failover.reason);
        assert_eq!(r.notes.lock().unwrap()[0].1, "Using quad9 DNS");
    }

    #[test]
    fn the_router_is_only_learned_after_a_pinned_api_answer_and_with_its_mac() {
        // API dead: the Pi-hole answering DNS is not enough to trust a router.
        let mut r = rig();
        r.w.set_api_check(Arc::new(|_, _| ApiLiveness::Dead));
        r.settle();
        assert!(actions::load_prev(&r.state_dir(), U_WIFI).is_none());
        // Wrong certificate: no.
        let mut r = rig();
        r.w.set_api_check(Arc::new(|_, _| ApiLiveness::Mismatch));
        r.settle();
        assert!(actions::load_prev(&r.state_dir(), U_WIFI).is_none());
        // No MAC in the neighbour table: no half-record.
        let mut r = rig();
        r.w.set_mac_lookup(Arc::new(|_, _| None));
        r.settle();
        assert!(actions::load_prev(&r.state_dir(), U_WIFI).is_none());
        // Everything in order.
        let mut r = rig();
        r.settle();
        let p = actions::load_prev(&r.state_dir(), U_WIFI).unwrap();
        assert_eq!(p.gateway_addr(), Some("192.168.1.1".parse().unwrap()));
        assert_eq!(p.gateway_mac_addr(), Some(MAC));
    }

    #[test]
    fn a_failed_learning_attempt_is_not_repeated_every_probe() {
        let mut r = rig();
        let calls = Arc::new(Mutex::new(0u32));
        let c2 = calls.clone();
        r.w.set_api_check(Arc::new(move |_, _| {
            *c2.lock().unwrap() += 1;
            ApiLiveness::Dead
        }));
        r.settle();
        r.probe(true, None);
        r.probe(true, None);
        r.probe(true, None);
        assert_eq!(*calls.lock().unwrap(), 1, "one HTTPS attempt, then a quiet period");
        // After the retry period it tries again.
        r.t += LEARN_RETRY_MS;
        r.probe(true, None);
        assert_eq!(*calls.lock().unwrap(), 2);
    }

    #[test]
    fn a_record_with_ip_but_no_mac_gets_its_mac_added() {
        let mut r = rig();
        // The old format: gateway only.
        let mut p = actions::PrevDns::default_for_tests(U_WIFI);
        p.gateway = Some("192.168.1.1".into());
        actions::write_prev_for_tests(&r.state_dir(), &p);
        r.settle();
        let p = actions::load_prev(&r.state_dir(), U_WIFI).unwrap();
        assert_eq!(p.gateway_mac_addr(), Some(MAC));
        // A record for a different router is left alone.
        let mut r = rig();
        record(&r, "10.0.0.1", [1, 2, 3, 4, 5, 6]);
        r.settle();
        let p = actions::load_prev(&r.state_dir(), U_WIFI).unwrap();
        assert_eq!(p.gateway_addr(), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(p.gateway_mac_addr(), Some([1, 2, 3, 4, 5, 6]));
    }

    // -- one DNS change at a time ---------------------------------------------------

    #[test]
    fn failover_engage_and_recover_wait_their_turn_for_the_dns_lock() {
        let mut r = rig();
        r.settle();
        let held = util::try_lock(&r.dir.path().join("run").join("dns.lock")).unwrap().unwrap();
        r.fail3();
        assert!(r.runtime_calls().is_empty(), "another qnet is changing DNS: no engage");
        assert!(!r.w.failover_active());
        assert!(r.w.state(false).error.contains("another qnet operation"));
        drop(held);
        // The retry comes after the cooldown, and now it goes through.
        r.probe(false, Some(true));
        r.probe(false, Some(true));
        assert_eq!(r.runtime_calls().len(), 1);
        assert!(r.w.failover_active());

        // Recovery respects the lock as well.
        let held = util::try_lock(&r.dir.path().join("run").join("dns.lock")).unwrap().unwrap();
        for _ in 0..4 {
            r.probe(true, None);
        }
        assert!(r.saved_calls().is_empty());
        assert!(r.w.failover_active());
        drop(held);
        for _ in 0..3 {
            r.probe(true, None);
        }
        assert_eq!(r.saved_calls().len(), 1);
        assert!(!r.w.failover_active());
        // And the lock was released again by the watcher itself.
        assert!(util::try_lock(&r.dir.path().join("run").join("dns.lock")).unwrap().is_some());
    }

    // -- auto is only deliberate if it was chosen ------------------------------------

    #[test]
    fn plugging_in_a_cable_with_automatic_dns_warns_until_the_user_chooses_it() {
        let be = FakeNet::live_machine();
        be.add_ethernet_primary();
        // The new cable's profile is automatic, as NetworkManager creates it,
        // and its link uses the router's DNS.
        be.set_resolver_for_primary_eth(&["192.168.1.1"]);
        let mut r = rig_with(Some(config_text("enabled = true")), be);
        let st = r.w.state(false);
        assert_eq!(st.link.kind, "ethernet");
        assert_eq!(st.dns.mode, "auto");
        assert!(st.dns.bypassed, "nobody chose Automatic for this cable");
        assert!(st.dns.leaks.iter().any(|l| l.where_ == "Wired connection 1" && l.kind == "link"));
        // The user taps Automatic: `dns auto` notes it, the profile change is seen.
        actions::set_auto_choice(&r.state_dir(), U_ETH1, true).unwrap();
        r.w.handle(Event::Nm(NmKind::Settings), 10_000);
        r.w.process_dirty(10_000);
        let st = r.w.state(false);
        assert_eq!(st.dns.mode, "auto");
        assert!(!st.dns.bypassed, "a choice, not an accident");
        assert!(st.dns.leaks.iter().all(|l| l.where_ != "Wired connection 1" || l.kind == "profile"));
        // Choosing the Pi-hole again forgets it.
        actions::set_auto_choice(&r.state_dir(), U_ETH1, false).unwrap();
        r.w.handle(Event::Nm(NmKind::Settings), 20_000);
        r.w.process_dirty(20_000);
        assert!(r.w.state(false).dns.bypassed);
    }

    // -- failover on one link while another is primary -------------------------------

    #[test]
    fn mode_is_fallback_only_on_the_link_that_failed_over() {
        let mut r = rig();
        r.settle();
        r.fail3();
        assert_eq!(r.w.state(false).dns.mode, "fallback");
        r.be.add_ethernet_primary();
        r.be.set_resolver_for_primary_eth(&[PI]);
        r.be.pin_profile_dns(U_ETH1);
        r.w.handle(Event::Nm(NmKind::Core), r.t);
        r.w.handle(Event::Nm(NmKind::Settings), r.t);
        r.t += 1_000;
        r.w.process_dirty(r.t);
        let st = r.w.state(false);
        assert_eq!(st.link.kind, "ethernet");
        assert_eq!(st.dns.mode, "pihole", "the cable's own link is healthy");
        assert!(st.dns.failover.active, "Wi-Fi is still failed over");
        assert_eq!(st.dns.failover.fallback, "router");
        assert_eq!(st.dns.mode_source, "profile");
        assert!(st.dns.leaks.iter().all(|l| l.where_ != "Redwood"), "the failed-over link is not a leak");
    }

    // -- resolved's downgrade ------------------------------------------------------------

    #[test]
    fn a_resolved_downgrade_makes_the_pihole_degraded_with_a_reason() {
        let mut r = rig();
        r.w.on_probe(report(true, None), 15_000);
        assert_eq!(r.w.state(false).pihole.health, "ok");
        r.w.handle(
            Event::Downgrade(Some("systemd-resolved dropped 192.168.1.153 to plain UDP (EDNS0 is failing)".into())),
            16_000,
        );
        let st = r.w.state(false);
        assert_eq!(st.pihole.health, "degraded");
        assert!(st.pihole.health_reason.contains("EDNS0"));
        // It is only a health note: it never feeds the failover.
        for _ in 0..6 {
            r.probe(true, None);
        }
        assert!(r.runtime_calls().is_empty());
        r.w.handle(Event::Downgrade(None), 200_000);
        assert_eq!(r.w.state(false).pihole.health, "ok");
    }

    #[test]
    fn resolved_is_asked_only_while_open_and_on_a_slow_timer() {
        let mut r = rig();
        let asked = Arc::new(Mutex::new(Vec::<IpAddr>::new()));
        let a2 = asked.clone();
        let (tx, rx) = mpsc::channel::<Event>();
        r.w.set_resolved_check(
            Arc::new(move |ip| {
                a2.lock().unwrap().push(ip);
                Some("systemd-resolved dropped it".to_string())
            }),
            tx,
        );
        // Closed: never.
        r.w.process_dirty(40_000);
        r.w.process_dirty(100_000);
        std::thread::sleep(Duration::from_millis(100));
        assert!(asked.lock().unwrap().is_empty(), "no process spawns while closed");
        assert!(rx.try_recv().is_err());
        // Open: once right away...
        r.w.handle(Event::Cmd("open".into()), 100_000);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(asked.lock().unwrap().len(), 1);
        match rx.try_recv() {
            Ok(Event::Downgrade(Some(s))) => assert!(s.contains("dropped")),
            _ => panic!("expected the downgrade event"),
        }
        // ...then every 30 s, not on every loop turn.
        r.w.process_dirty(110_000);
        r.w.process_dirty(120_000);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(asked.lock().unwrap().len(), 1);
        r.w.process_dirty(131_000);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(asked.lock().unwrap().len(), 2);
        assert_eq!(asked.lock().unwrap()[0], PI.parse::<IpAddr>().unwrap());
        // Closing stops it.
        r.w.handle(Event::Cmd("closed".into()), 140_000);
        r.w.process_dirty(200_000);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(asked.lock().unwrap().len(), 2);
    }

    // -- resolver and upstream numbers -----------------------------------------------------

    #[test]
    fn resolved_fallback_dns_shows_up_as_a_leak_once_resolved_picked_it() {
        let mut r = rig();
        assert!(r.w.state(false).dns.leaks.iter().all(|l| l.kind != "resolved-fallback"));
        r.be.set_global_current(Some("9.9.9.9"));
        r.w.handle(Event::Nm(NmKind::Core), 5_000);
        r.w.process_dirty(5_300);
        let st = r.w.state(false);
        assert!(st.dns.leaks.iter().any(|l| l.kind == "resolved-fallback"));
        assert_eq!(st.dns.mode, "pihole", "it is a leak line, not a mode change");
        assert!(!st.dns.bypassed);
    }

    #[test]
    fn upstream_stats_arrive_with_the_api_and_our_probes_come_out_of_the_blocklist_figure() {
        let mut r = rig();
        for _ in 0..4 {
            let mut rep = report(true, None);
            rep.t = util::unix_now();
            rep.own = OwnQueries { total: 2, blocked: 1 };
            r.w.on_probe(rep, r.t);
        }
        let mut rep = api_report(100, 50);
        rep.upstreams = Some(crate::pihole::Upstreams {
            list: vec![crate::pihole::Upstream {
                name: "dns9.quad9.net".into(),
                ip: "9.9.9.9".parse().unwrap(),
                port: 53,
                count: 40,
                response_ms: Some(15.5),
            }],
            answered_by: crate::pihole::AnsweredBy { blocklist: 50, cache: 10, forwarded: 40 },
        });
        r.w.handle(Event::Api(rep), r.t);
        let st = r.w.state(false);
        assert_eq!(st.pihole.upstreams.len(), 1);
        let u = &st.pihole.upstreams[0];
        assert_eq!((u.name.as_str(), u.ip.as_str(), u.port, u.count, u.response_ms), ("dns9.quad9.net", "9.9.9.9", 53, 40, Some(15.5)));
        // 4 cycles x (1 blocked + 1 forwarded) of our own are in those numbers.
        assert_eq!(st.pihole.answered_by.blocklist, 46);
        assert_eq!(st.pihole.answered_by.cache, 10);
        assert_eq!(st.pihole.answered_by.forwarded, 36);
        assert_eq!(st.pihole.today.blocked, 46, "consistent with today");
        // A poll without upstreams keeps the last ones.
        r.w.handle(Event::Api(api_report(101, 50)), r.t);
        assert_eq!(r.w.state(false).pihole.upstreams.len(), 1);
    }
}

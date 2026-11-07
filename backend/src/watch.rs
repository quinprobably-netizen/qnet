//! `qnet watch`: the long-lived process behind the panel.
//!
//! Threads (all feeding one event channel):
//!   * stdin reader   - `open` / `closed` / `refresh`;
//!   * signals        - SIGTERM / SIGINT / SIGHUP;
//!   * NM watcher     - NetworkManager D-Bus signals;
//!   * prober         - raw UDP DNS probes to the Pi-hole (and the gateway
//!     while the Pi-hole probe is failing);
//!   * API poller     - Pi-hole HTTPS API, only while the panel is open.
//!
//! The main thread owns the model and is the only one that touches DNS
//! settings. `Watch` takes the current time as an argument everywhere, so
//! its decisions can be tested without sleeping.

use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::net::IpAddr;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::{self, Config};
use crate::dnsmodel::{self, pihole_candidate};
use crate::dnswire;
use crate::failover::{Decision, Failover, LinkKey, Obs};
use crate::net::*;
use crate::pihole::{ApiError, Blocking, Bucket, Pihole, Summary};
use crate::state::*;
use crate::util;

/// Desktop notification sink: (title, body).
pub type Notifier = Box<dyn Fn(&str, &str) + Send>;

pub const EMIT_MIN_GAP_MS: u64 = 250;
pub const HEARTBEAT_MS: u64 = 10_000;
pub const RESOLVER_EVERY_MS: u64 = 30_000;
pub const RESOLVER_FOLLOWUP_MS: u64 = 1_500;
pub const NET_MIN_GAP_MS: u64 = 250;
pub const SCAN_STALE_MS: u64 = 30_000;
pub const SCAN_MIN_GAP_MS: u64 = 15_000;
pub const SCAN_RUNNING_MAX_MS: u64 = 20_000;
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
pub const PROBE_EVERY_CLOSED: Duration = Duration::from_secs(15);
pub const PROBE_EVERY_OPEN: Duration = Duration::from_secs(5);
pub const API_EVERY: Duration = Duration::from_secs(10);
pub const HISTORY_EVERY: Duration = Duration::from_secs(60);

// ---- Events and thread messages ------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NmKind {
    /// Devices, active connections, IP config, connectivity.
    Core,
    /// Access points came, went or changed.
    Ap,
    /// Saved profiles changed.
    Settings,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeOutcome {
    pub ok: bool,
    pub ms: Option<f64>,
    pub blocked: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeReport {
    pub target: IpAddr,
    pub t: f64,
    pub pihole: ProbeOutcome,
    /// Gateway probe result; only taken when the Pi-hole probe failed.
    pub gateway: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ApiReport {
    pub status: &'static str,
    pub summary: Option<Summary>,
    pub blocking: Option<Blocking>,
    pub history: Option<Vec<Bucket>>,
    pub at: f64,
}

pub enum Event {
    Cmd(String),
    StdinEof,
    Signal,
    Nm(NmKind),
    NmLost,
    Probe(ProbeReport),
    Api(ApiReport),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub addr: IpAddr,
    pub canary: String,
    pub gateway: Option<IpAddr>,
}

pub enum ProbeCtl {
    Target(Option<ProbeTarget>),
    Open(bool),
    Kick,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiCfg {
    pub addr: IpAddr,
    pub pin: [u8; 32],
}

pub enum ApiCtl {
    Config(Option<ApiCfg>),
    Open(bool),
    Kick,
    Stop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Shutdown,
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
    candidate: Option<IpAddr>,
    confirmed: Option<IpAddr>,
    scan_running: bool,
    scan_requested_ms: Option<u64>,
    scan_age_at_request: Option<u64>,
    dirty: Dirty,
    aps_stale: bool,
    last_net_ms: u64,
    net_read_unix: f64,
    resolver_due_ms: u64,
    seq: u64,
    last_sig: String,
    last_emit_ms: u64,
    emitted_once: bool,
    pending_change: bool,
    notify: Notifier,
    probe_tx: Option<Sender<ProbeCtl>>,
    api_tx: Option<Sender<ApiCtl>>,
    config_path: std::path::PathBuf,
}

impl Watch {
    pub fn new(be: Box<dyn NetBackend>, config_path: std::path::PathBuf) -> Self {
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
            candidate: None,
            confirmed: None,
            scan_running: false,
            scan_requested_ms: None,
            scan_age_at_request: None,
            dirty: Dirty::default(),
            aps_stale: true,
            last_net_ms: 0,
            net_read_unix: 0.0,
            resolver_due_ms: 0,
            seq: 0,
            last_sig: String::new(),
            last_emit_ms: 0,
            emitted_once: false,
            pending_change: false,
            notify: Box::new(|_, _| {}),
            probe_tx: None,
            api_tx: None,
            config_path,
        }
    }

    pub fn set_notifier(&mut self, f: Notifier) {
        self.notify = f;
    }

    pub fn attach_threads(&mut self, probe: Sender<ProbeCtl>, api: Sender<ApiCtl>) {
        self.probe_tx = Some(probe);
        self.api_tx = Some(api);
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
        self.update_scan_running(now_ms);
    }

    fn read_profiles(&mut self) {
        match self.be.profiles() {
            Ok(p) => {
                self.profiles = p;
                self.profile_error.clear();
            }
            Err(e) => self.profile_error = format!("NetworkManager: {}", e.detail()),
        }
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
            if self.confirmed != next {
                self.confirmed = None;
            }
        }
    }

    /// The Pi-hole address the rest of the model works with.
    pub fn effective_pihole(&self) -> Option<IpAddr> {
        self.cfg.pihole.as_ref().map(|p| p.address).or(self.confirmed)
    }

    fn desired_probe_target(&self) -> Option<ProbeTarget> {
        let (addr, canary) = match &self.cfg.pihole {
            Some(p) => (p.address, p.canary.clone()),
            None => (self.candidate?, config::DEFAULT_CANARY.to_string()),
        };
        let gateway = self.primary().and_then(|d| d.gateway).map(IpAddr::V4);
        Some(ProbeTarget { addr, canary, gateway })
    }

    fn sync_threads(&mut self) {
        self.update_candidate();
        let want = self.desired_probe_target();
        if want != self.probe_target {
            if want.as_ref().map(|t| t.addr) != self.probe_target.as_ref().map(|t| t.addr) {
                self.probes.clear();
            }
            if let Some(tx) = &self.probe_tx {
                let _ = tx.send(ProbeCtl::Target(want.clone()));
            }
            self.probe_target = want;
        }
        let api_cfg = self.cfg.pihole.as_ref().map(|p| ApiCfg {
            addr: p.address,
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
        self.load_config();
        self.read_net(now_ms, true);
        self.read_profiles();
        self.read_resolver(now_ms);
        self.sync_threads();
        if let Some(tx) = &self.probe_tx {
            let _ = tx.send(ProbeCtl::Open(self.open));
        }
        self.adopt_stranded_failover();
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
        if let Ok(applied) = self.be.applied_dns(&iface) {
            if applied.v4_dns != saved {
                self.fo.adopt(util::unix_secs(), "device was running different DNS than its saved profile");
            }
        }
    }

    pub fn shutdown(&mut self) {
        if self.fo.active() {
            if let Some(iface) = self.primary().map(|d| d.iface.clone()) {
                let _ = self.be.reapply_saved(&iface);
            }
            self.fo.recovered();
        }
        if let Some(tx) = self.probe_tx.take() {
            let _ = tx.send(ProbeCtl::Stop);
        }
        if let Some(tx) = self.api_tx.take() {
            let _ = tx.send(ApiCtl::Stop);
        }
    }

    // -- events ---------------------------------------------------------------

    pub fn handle(&mut self, ev: Event, now_ms: u64) -> Flow {
        match ev {
            Event::Cmd(line) => self.on_command(line.trim(), now_ms),
            Event::StdinEof | Event::Signal => return Flow::Shutdown,
            Event::Nm(kind) => self.on_nm(kind, now_ms),
            Event::NmLost => {
                self.dirty = Dirty { net: true, aps: self.open, profiles: true, resolver: true };
            }
            Event::Probe(r) => self.on_probe(r, now_ms),
            Event::Api(r) => self.on_api(r),
        }
        Flow::Continue
    }

    fn mark_all_dirty(&mut self) {
        self.dirty = Dirty { net: true, aps: true, profiles: true, resolver: true };
    }

    fn on_command(&mut self, cmd: &str, now_ms: u64) {
        match cmd {
            "open" => {
                let was_open = self.open;
                self.open = true;
                self.op_error.clear();
                self.mark_all_dirty();
                self.load_config();
                // Read now (not at the next loop turn) so the stale-scan
                // rule looks at fresh data.
                self.process_dirty(now_ms);
                if !was_open {
                    self.maybe_scan_on_open(now_ms);
                }
                if let Some(tx) = &self.probe_tx {
                    let _ = tx.send(ProbeCtl::Open(true));
                }
                if let Some(tx) = &self.api_tx {
                    let _ = tx.send(ApiCtl::Open(true));
                }
            }
            "closed" => {
                self.open = false;
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
        if let Some(s) = r.summary {
            self.api.today = Some(s);
        }
        if let Some(h) = r.history {
            self.api.history = h;
        }
        if let Some(b) = r.blocking {
            self.api.blocking = Some((b, r.at));
        }
    }

    // -- probes and failover ----------------------------------------------------

    /// Failover is allowed only with a configured Pi-hole, the switch on,
    /// and the active profile pinned to that Pi-hole.
    fn eligible(&self) -> bool {
        let Some(p) = &self.cfg.pihole else { return false };
        if !self.cfg.failover.enabled {
            return false;
        }
        self.primary_profile()
            .is_some_and(|prof| dnsmodel::profile_pinned(&prof.dns, p.address))
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
        if self.cfg.pihole.is_none() && self.candidate == Some(r.target) && r.pihole.ok && r.pihole.blocked {
            self.confirmed = Some(r.target);
        }

        let obs = Obs {
            now_ms,
            link: self.link_key(),
            eligible: self.eligible(),
            pihole_ok: r.pihole.ok,
            gateway_ok: r.gateway,
        };
        match self.fo.observe(&obs) {
            Decision::Idle | Decision::Cleared(_) => {}
            Decision::Engage => self.engage(now_ms),
            Decision::Recover => self.recover(now_ms),
        }
    }

    fn engage(&mut self, now_ms: u64) {
        // Re-read the link right before touching DNS.
        let Ok(snap) = self.be.snapshot(false) else {
            self.fo.engage_failed(now_ms);
            return;
        };
        let Some(dev) = snap.primary_device().filter(|d| d.is_up()) else {
            self.fo.engage_failed(now_ms);
            return;
        };
        let same_link = dev.active.as_ref().map(|a| a.uuid.as_str())
            == self.link_key().as_ref().map(|k| k.uuid.as_str());
        if !same_link {
            self.fo.engage_failed(now_ms);
            return;
        }
        let fallback = self.cfg.failover.fallback;
        let servers = fallback.servers(dev.gateway);
        if servers.is_empty() {
            self.op_error = "failover: no gateway address for the router fallback".into();
            self.fo.engage_failed(now_ms);
            return;
        }
        match self.be.reapply_runtime_dns(&dev.iface, &servers) {
            Ok(()) => {
                self.op_error.clear();
                self.fo.engaged(util::unix_secs(), "Pi-hole not answering");
                (self.notify)("Pi-hole unreachable", &format!("Using {} DNS", fallback.as_str()));
                self.resolver_due_ms = now_ms + RESOLVER_FOLLOWUP_MS;
            }
            Err(e) => {
                self.op_error = format!("failover: {}", e.detail());
                self.fo.engage_failed(now_ms);
            }
        }
    }

    fn recover(&mut self, now_ms: u64) {
        let Some(iface) = self.primary().map(|d| d.iface.clone()) else {
            self.fo.recover_failed(now_ms);
            return;
        };
        match self.be.reapply_saved(&iface) {
            Ok(()) => {
                self.op_error.clear();
                self.fo.recovered();
                (self.notify)("Pi-hole is back", "Using Pi-hole DNS again");
                self.resolver_due_ms = now_ms + RESOLVER_FOLLOWUP_MS;
            }
            Err(e) => {
                self.op_error = format!("failover recovery: {}", e.detail());
                self.fo.recover_failed(now_ms);
            }
        }
    }

    // -- scanning -----------------------------------------------------------------

    fn update_scan_running(&mut self, now_ms: u64) {
        if !self.scan_running {
            return;
        }
        let age_now = self
            .net
            .as_ref()
            .and_then(|n| n.wifi_device())
            .and_then(|d| d.wifi.as_ref())
            .and_then(|w| w.last_scan_age_ms);
        let progressed = match (age_now, self.scan_age_at_request) {
            (Some(now), Some(then)) => now < then,
            (Some(_), None) => true,
            _ => false,
        };
        let expired = self
            .scan_requested_ms
            .is_some_and(|t| now_ms.saturating_sub(t) >= SCAN_RUNNING_MAX_MS);
        if progressed || expired {
            self.scan_running = false;
        }
    }

    /// The one automatic scan: on open, when NM's last scan is stale.
    fn maybe_scan_on_open(&mut self, now_ms: u64) {
        #[cfg(debug_assertions)]
        if std::env::var_os("QNET_DEV_NO_SCAN").is_some() {
            return;
        }
        let Some(net) = &self.net else { return };
        if !net.wifi_enabled {
            return;
        }
        let Some(dev) = net.wifi_device() else { return };
        if dev.state < NM_DEVICE_STATE_DISCONNECTED {
            return;
        }
        let age = dev.wifi.as_ref().and_then(|w| w.last_scan_age_ms);
        let stale = age.is_none_or(|a| a > SCAN_STALE_MS);
        let spaced = self
            .scan_requested_ms
            .is_none_or(|t| now_ms.saturating_sub(t) >= SCAN_MIN_GAP_MS);
        if !(stale && spaced) {
            return;
        }
        let iface = dev.iface.clone();
        match self.be.request_scan(&iface) {
            Ok(()) => {
                self.scan_running = true;
                self.scan_requested_ms = Some(now_ms);
                self.scan_age_at_request = age;
            }
            Err(e) => self.op_error = format!("scan: {}", e.detail()),
        }
    }

    // -- the loop's work ----------------------------------------------------------

    /// Perform pending reads. Cheap when nothing is dirty.
    pub fn process_dirty(&mut self, now_ms: u64) {
        let resolver_due = now_ms >= self.resolver_due_ms;
        let net_ok = now_ms.saturating_sub(self.last_net_ms) >= NET_MIN_GAP_MS || self.last_net_ms == 0;
        if self.dirty.net && net_ok {
            let with_aps = self.open && (self.dirty.aps || self.aps_stale);
            self.read_net(now_ms, with_aps);
            self.dirty.net = false;
            self.dirty.aps = false;
        }
        if self.dirty.profiles {
            self.read_profiles();
            self.dirty.profiles = false;
        }
        if self.dirty.resolver || resolver_due {
            self.read_resolver(now_ms);
            self.dirty.resolver = false;
        }
        self.sync_threads();
        self.update_scan_running(now_ms);
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
        let mut st = build_state(
            &Inputs {
                net: self.net.as_ref(),
                profiles: &self.profiles,
                resolver: self.resolver.as_ref(),
                cfg: &self.cfg,
                pihole: self.effective_pihole(),
                probes: &self.probes,
                api: &self.api,
                failover: &self.fo,
                scan: ScanView { running: self.scan_running },
                error,
                now_unix: util::unix_now(),
                net_age_s: util::unix_now() - self.net_read_unix,
            },
            self.seq,
            heartbeat,
        );
        st.seq = self.seq;
        st
    }

    /// Decide whether a line goes out now. Updates sequence bookkeeping.
    pub fn next_emission(&mut self, now_ms: u64) -> Option<State> {
        let preview = self.state(false);
        let sig = change_signature(&preview);
        let changed = sig != self.last_sig || !self.emitted_once;
        self.pending_change = changed;
        let since = now_ms.saturating_sub(self.last_emit_ms);
        let throttled = self.emitted_once && since < EMIT_MIN_GAP_MS;
        let heartbeat_due = self.emitted_once && since >= HEARTBEAT_MS;
        if (changed && !throttled) || heartbeat_due {
            self.seq += 1;
            let mut st = self.state(heartbeat_due && !changed);
            st.seq = self.seq;
            self.last_sig = sig;
            self.last_emit_ms = now_ms;
            self.emitted_once = true;
            self.pending_change = false;
            Some(st)
        } else {
            None
        }
    }

    /// Milliseconds until something needs attention.
    pub fn next_wake_ms(&self, now_ms: u64) -> u64 {
        let mut wake = HEARTBEAT_MS.saturating_sub(now_ms.saturating_sub(self.last_emit_ms));
        wake = wake.min(self.resolver_due_ms.saturating_sub(now_ms));
        if self.pending_change {
            wake = wake.min((self.last_emit_ms + EMIT_MIN_GAP_MS).saturating_sub(now_ms));
        }
        if self.dirty.net || self.dirty.profiles || self.dirty.resolver {
            wake = wake.min((self.last_net_ms + NET_MIN_GAP_MS).saturating_sub(now_ms));
        }
        if self.scan_running {
            if let Some(t) = self.scan_requested_ms {
                wake = wake.min((t + SCAN_RUNNING_MAX_MS).saturating_sub(now_ms));
            }
        }
        wake.max(5)
    }

    pub fn probe_pending(&self) -> bool {
        self.probe_target.is_some() && self.probes.is_empty()
    }

    #[cfg(test)]
    pub fn failover_active(&self) -> bool {
        self.fo.active()
    }
}

// ---- Threads ----------------------------------------------------------------

pub fn spawn_stdin(tx: Sender<Event>) {
    thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
                    if tx.send(Event::Cmd(l)).is_err() {
                        return;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = tx.send(Event::StdinEof);
    });
}

pub fn spawn_signals(tx: Sender<Event>) {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    if let Ok(mut sigs) = signal_hook::iterator::Signals::new([SIGTERM, SIGINT, SIGHUP]) {
        thread::spawn(move || {
            for _ in sigs.forever() {
                let _ = tx.send(Event::Signal);
            }
        });
    }
}

/// Watch NetworkManager's D-Bus signals and turn them into coarse events.
pub fn spawn_nm_watcher(tx: Sender<Event>) {
    use zbus::blocking::{Connection, MessageIterator};
    use zbus::message::Type;
    use zbus::MatchRule;
    thread::spawn(move || loop {
        if let Ok(conn) = Connection::system() {
            let rule = MatchRule::builder()
                .msg_type(Type::Signal)
                .path_namespace("/org/freedesktop/NetworkManager")
                .map(|b| b.build());
            if let Ok(rule) = rule {
                if let Ok(iter) = MessageIterator::for_match_rule(rule, &conn, Some(512)) {
                    for msg in iter {
                        let Ok(msg) = msg else { break };
                        let hdr = msg.header();
                        let path = hdr.path().map(|p| p.as_str().to_string()).unwrap_or_default();
                        let kind = classify_nm_signal(&path);
                        if tx.send(Event::Nm(kind)).is_err() {
                            return;
                        }
                    }
                }
            }
        }
        if tx.send(Event::NmLost).is_err() {
            return;
        }
        thread::sleep(Duration::from_secs(2));
    });
}

pub fn classify_nm_signal(path: &str) -> NmKind {
    if path.starts_with("/org/freedesktop/NetworkManager/Settings") {
        NmKind::Settings
    } else if path.starts_with("/org/freedesktop/NetworkManager/AccessPoint/") {
        NmKind::Ap
    } else {
        NmKind::Core
    }
}

pub fn run_probe(t: &ProbeTarget) -> ProbeReport {
    let started = util::unix_now();
    let pihole = match dnswire::probe_server(t.addr, &t.canary, PROBE_TIMEOUT) {
        Ok(p) => {
            let v = dnswire::judge(&p.reply, t.addr);
            ProbeOutcome {
                ok: v.ok,
                ms: if v.ok { Some(p.rtt.as_secs_f64() * 1000.0) } else { None },
                blocked: v.ok && v.blocked,
            }
        }
        Err(_) => ProbeOutcome { ok: false, ms: None, blocked: false },
    };
    let gateway = if pihole.ok {
        None
    } else {
        t.gateway.map(|g| {
            matches!(
                dnswire::probe_server(g, &t.canary, PROBE_TIMEOUT),
                Ok(p) if p.reply.rcode == dnswire::RCODE_NOERROR || p.reply.rcode == dnswire::RCODE_NXDOMAIN
            )
        })
    };
    ProbeReport {
        target: t.addr,
        t: started,
        pihole,
        gateway,
    }
}

pub fn spawn_prober(tx: Sender<Event>) -> (Sender<ProbeCtl>, JoinHandle<()>) {
    let (ctl_tx, ctl_rx) = mpsc::channel::<ProbeCtl>();
    let h = thread::spawn(move || {
        let mut target: Option<ProbeTarget> = None;
        let mut open = false;
        let mut last = Instant::now() - Duration::from_secs(3600);
        let mut next_due = Instant::now();
        let interval = |open: bool| if open { PROBE_EVERY_OPEN } else { PROBE_EVERY_CLOSED };
        loop {
            let now = Instant::now();
            let wait = if target.is_some() {
                next_due.saturating_duration_since(now)
            } else {
                Duration::from_secs(3600)
            };
            match ctl_rx.recv_timeout(wait) {
                Ok(ProbeCtl::Target(t)) => {
                    target = t;
                    next_due = Instant::now();
                }
                Ok(ProbeCtl::Open(o)) => {
                    open = o;
                    next_due = if o && last.elapsed() > Duration::from_secs(2) {
                        Instant::now()
                    } else {
                        last + interval(o)
                    };
                }
                Ok(ProbeCtl::Kick) => {
                    next_due = (last + Duration::from_secs(1)).max(Instant::now());
                }
                Ok(ProbeCtl::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(t) = &target {
                        let report = run_probe(t);
                        last = Instant::now();
                        next_due = last + interval(open);
                        if tx.send(Event::Probe(report)).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    (ctl_tx, h)
}

fn password_fn(addr: IpAddr) -> crate::pihole::PasswordFn {
    Box::new(move || {
        config::lookup_password(addr).map_err(|e| match e {
            config::SecretError::Missing(m) => ApiError::Auth(m),
            config::SecretError::Failed(m) => ApiError::Other(m),
        })
    })
}

pub fn spawn_api(tx: Sender<Event>) -> (Sender<ApiCtl>, JoinHandle<()>) {
    let (ctl_tx, ctl_rx) = mpsc::channel::<ApiCtl>();
    let h = thread::spawn(move || {
        let mut cfg: Option<ApiCfg> = None;
        let mut client: Option<Pihole> = None;
        let mut open = false;
        let mut next_poll = Instant::now();
        let mut last_poll = Instant::now() - Duration::from_secs(3600);
        let mut last_history: Option<Instant> = None;
        loop {
            let now = Instant::now();
            let wait = if open && cfg.is_some() {
                next_poll.saturating_duration_since(now)
            } else {
                Duration::from_secs(3600)
            };
            match ctl_rx.recv_timeout(wait) {
                Ok(ApiCtl::Config(c)) => {
                    if let Some(mut old) = client.take() {
                        old.logout();
                    }
                    cfg = c;
                    last_history = None;
                    next_poll = Instant::now();
                }
                Ok(ApiCtl::Open(o)) => {
                    open = o;
                    if o {
                        next_poll = Instant::now();
                    } else if let Some(c) = client.as_mut() {
                        c.close_idle();
                    }
                }
                Ok(ApiCtl::Kick) => {
                    next_poll = (last_poll + Duration::from_secs(1)).max(Instant::now());
                }
                Ok(ApiCtl::Stop) | Err(RecvTimeoutError::Disconnected) => {
                    if let Some(mut c) = client.take() {
                        c.logout();
                    }
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {
                    let Some(c) = cfg.clone() else { continue };
                    if client.is_none() {
                        let made = Pihole::new(c.addr, c.pin, password_fn(c.addr)).map(|p| match util::sid_path() {
                            Some(path) => p.with_sid_file(path),
                            None => p,
                        });
                        match made {
                            Ok(mut p) => {
                                // A session left behind by a killed predecessor.
                                p.resume_session();
                                client = Some(p);
                            }
                            Err(e) => {
                                let _ = tx.send(Event::Api(failure(&e)));
                                next_poll = Instant::now() + Duration::from_secs(30);
                                continue;
                            }
                        }
                    }
                    let api = client.as_mut().expect("just created");
                    last_poll = Instant::now();
                    let history_due = last_history.is_none_or(|t| t.elapsed() >= HISTORY_EVERY);
                    let res = poll(api, history_due);
                    api.close_idle();
                    match res {
                        Ok(report) => {
                            if report.history.is_some() {
                                last_history = Some(Instant::now());
                            }
                            next_poll = Instant::now() + API_EVERY;
                            if tx.send(Event::Api(report)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            // Do not hammer logins or a dead host.
                            next_poll = Instant::now()
                                + match e {
                                    ApiError::Auth(_) => Duration::from_secs(60),
                                    ApiError::Tls(_) => Duration::from_secs(30),
                                    _ => API_EVERY,
                                };
                            if matches!(e, ApiError::Auth(_)) {
                                client = None;
                            }
                            if tx.send(Event::Api(failure(&e))).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });
    (ctl_tx, h)
}

fn failure(e: &ApiError) -> ApiReport {
    ApiReport {
        status: e.status(),
        summary: None,
        blocking: None,
        history: None,
        at: util::unix_now(),
    }
}

fn poll(api: &mut Pihole, with_history: bool) -> Result<ApiReport, ApiError> {
    let summary = api.summary()?;
    let blocking = api.blocking()?;
    let history = if with_history { Some(api.history()?) } else { None };
    Ok(ApiReport {
        status: "ok",
        summary: Some(summary),
        blocking: Some(blocking),
        history,
        at: util::unix_now(),
    })
}

/// `notify-send` in the background; failures are ignored.
pub fn desktop_notify(title: &str, body: &str) {
    let (t, b) = (title.to_string(), body.to_string());
    thread::spawn(move || {
        let _ = crate::proc::run(
            "notify-send",
            &["-a", "qnet", &t, &b],
            None,
            Duration::from_secs(5),
            1024,
        );
    });
}

// ---- Entry point ----------------------------------------------------------------

/// Write each state as one JSON line; false when stdout is gone.
pub fn write_line(out: &mut impl Write, st: &State) -> bool {
    let Ok(mut line) = serde_json::to_vec(st) else { return true };
    line.push(b'\n');
    out.write_all(&line).and_then(|_| out.flush()).is_ok()
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

pub fn run_watch(be: Box<dyn NetBackend>) -> i32 {
    if !die_with_parent() {
        return 0;
    }
    let (tx, rx) = mpsc::channel::<Event>();
    let mut w = Watch::new(be, util::config_path());
    w.set_notifier(Box::new(desktop_notify));
    spawn_signals(tx.clone());
    spawn_stdin(tx.clone());
    spawn_nm_watcher(tx.clone());
    let (probe_tx, probe_h) = spawn_prober(tx.clone());
    let (api_tx, api_h) = spawn_api(tx.clone());
    w.attach_threads(probe_tx, api_tx);

    let t0 = Instant::now();
    let ms = move || t0.elapsed().as_millis() as u64;
    w.startup(ms());

    let stdout = std::io::stdout();
    let mut shutdown = false;

    // Give the first probe a moment so the first line is not a false
    // "unreachable".
    let deadline = ms() + 500;
    while w.probe_pending() && ms() < deadline {
        let left = deadline.saturating_sub(ms()).max(1);
        match rx.recv_timeout(Duration::from_millis(left)) {
            Ok(ev) => {
                if w.handle(ev, ms()) == Flow::Shutdown {
                    shutdown = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }

    loop {
        let now = ms();
        w.process_dirty(now);
        if let Some(st) = w.next_emission(now) {
            if !write_line(&mut stdout.lock(), &st) {
                break;
            }
        }
        if shutdown {
            break;
        }
        let wake = w.next_wake_ms(ms());
        match rx.recv_timeout(Duration::from_millis(wake)) {
            Ok(ev) => {
                if w.handle(ev, ms()) == Flow::Shutdown {
                    break;
                }
                while let Ok(ev) = rx.try_recv() {
                    if w.handle(ev, ms()) == Flow::Shutdown {
                        shutdown = true;
                        break;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    w.shutdown();
    let _ = probe_h.join();
    let _ = api_h.join();
    0
}

/// One state snapshot with a synchronous probe, for `qnet state`.
pub fn state_once(be: Box<dyn NetBackend>) -> State {
    let mut w = Watch::new(be, util::config_path());
    w.startup(0);
    if let Some(t) = w.probe_target.clone() {
        let report = run_probe(&t);
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
    use std::sync::{Arc, Mutex};

    const PI: &str = "192.168.1.153";

    struct Rig {
        w: Watch,
        be: Arc<FakeNet>,
        notes: Arc<Mutex<Vec<(String, String)>>>,
        _dir: tempfile::TempDir,
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
        let notes: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let n2 = notes.clone();
        w.set_notifier(Box::new(move |t, b| n2.lock().unwrap().push((t.into(), b.into()))));
        w.startup(0);
        Rig { w, be, notes, _dir: dir, t: 0 }
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
        fn fail3(&mut self) {
            for _ in 0..3 {
                self.probe(false, Some(true));
            }
        }
        fn runtime_calls(&self) -> Vec<String> {
            self.be.calls().into_iter().filter(|c| c.starts_with("reapply_runtime_dns")).collect()
        }
        fn saved_calls(&self) -> usize {
            self.be.calls().iter().filter(|c| c.starts_with("reapply_saved")).count()
        }
    }

    #[test]
    fn engages_after_three_failures_with_gateway_up() {
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
        let mut r = rig_with(
            Some(config_text("enabled = false")),
            FakeNet::live_machine(),
        );
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

    #[test]
    fn recovers_after_three_good_probes_and_notifies() {
        let mut r = rig();
        r.settle();
        r.fail3();
        assert!(r.w.failover_active());
        r.probe(true, None);
        r.probe(true, None);
        assert_eq!(r.saved_calls(), 0);
        r.probe(true, None);
        assert_eq!(r.saved_calls(), 1);
        assert!(!r.w.failover_active());
        assert_eq!(r.notes.lock().unwrap().len(), 2);
        assert_eq!(r.notes.lock().unwrap()[1].0, "Pi-hole is back");
        r.w.process_dirty(r.t + 2_000);
        assert_eq!(r.w.state(false).dns.mode, "pihole");
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
    fn router_fallback_without_gateway_does_not_engage() {
        let mut r = rig();
        r.settle();
        r.be.set_gateway(None);
        r.fail3();
        assert!(r.runtime_calls().is_empty());
        assert!(r.w.state(false).error.contains("no gateway"));
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
    fn shutdown_returns_a_runtime_failover_to_the_saved_profile() {
        let mut r = rig();
        r.settle();
        r.fail3();
        assert!(r.w.failover_active());
        r.w.shutdown();
        assert_eq!(r.saved_calls(), 1);
        assert_eq!(r.be.link_servers(), vec![PI.parse::<std::net::IpAddr>().unwrap()]);
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

    #[test]
    fn unconfigured_pihole_is_detected_after_it_blocks_the_canary() {
        let mut r = rig_with(None, FakeNet::live_machine());
        let st = r.w.state(false);
        assert!(!st.pihole.configured);
        assert_eq!(st.pihole.api, "unconfigured");
        assert_eq!(st.pihole.address, "", "not trusted yet");
        assert_eq!(st.dns.mode, "custom");
        assert!(st.dns.leaks.is_empty());

        r.t = 15_000;
        r.w.on_probe(report(true, None), r.t);
        let st = r.w.state(false);
        assert_eq!(st.pihole.address, PI);
        assert!(st.pihole.reachable && !st.pihole.configured);
        assert_eq!(st.pihole.blocking, "enabled");
        assert_eq!(st.dns.mode, "pihole");
        assert_eq!(st.dns.leaks.len(), 2);
        assert!(!st.dns.failover.enabled, "no failover without a config");
        // And no failover however long it stays down.
        r.settle();
        r.fail3();
        r.fail3();
        assert!(r.runtime_calls().is_empty());
    }

    #[test]
    fn detection_requires_blocking_not_just_an_answer() {
        let mut r = rig_with(None, FakeNet::live_machine());
        let mut rep = report(true, None);
        rep.pihole.blocked = false; // a LAN resolver that does not block
        r.w.on_probe(rep, 15_000);
        let st = r.w.state(false);
        assert_eq!(st.pihole.address, "");
        assert_eq!(st.dns.mode, "custom");
    }

    #[test]
    fn open_scans_only_when_the_last_scan_is_stale() {
        let be = FakeNet::live_machine();
        be.set_last_scan_age_ms(Some(40_000));
        let mut r = rig_with(None, be);
        let scans = |r: &Rig| r.be.calls().iter().filter(|c| c.starts_with("request_scan")).count();
        r.t = 2_000;
        r.w.handle(Event::Cmd("open".into()), r.t);
        assert_eq!(scans(&r), 1);
        assert!(r.w.state(false).scan.running);
        // Close and reopen right away: not within 15 s of the last request.
        r.w.handle(Event::Cmd("closed".into()), r.t + 100);
        r.w.handle(Event::Cmd("open".into()), r.t + 200);
        assert_eq!(scans(&r), 1);
        // The scan completes (age drops): running clears.
        r.be.set_last_scan_age_ms(Some(500));
        r.t += 1_000;
        r.w.handle(Event::Nm(NmKind::Core), r.t);
        r.w.process_dirty(r.t + 300);
        assert!(!r.w.state(false).scan.running);
    }

    #[test]
    fn open_with_a_fresh_scan_and_refresh_never_scan() {
        let be = FakeNet::live_machine();
        be.set_last_scan_age_ms(Some(12_000));
        let mut r = rig_with(None, be);
        r.w.handle(Event::Cmd("open".into()), 2_000);
        r.w.handle(Event::Cmd("refresh".into()), 3_000);
        r.w.handle(Event::Cmd("closed".into()), 4_000);
        assert!(!r.be.calls().iter().any(|c| c.starts_with("request_scan")));
        // Stale but via refresh only: still no scan.
        r.be.set_last_scan_age_ms(Some(120_000));
        r.w.handle(Event::Cmd("refresh".into()), 60_000);
        r.w.process_dirty(60_500);
        assert!(!r.be.calls().iter().any(|c| c.starts_with("request_scan")));
    }

    #[test]
    fn no_scan_when_the_radio_is_off() {
        let be = FakeNet::live_machine();
        be.set_last_scan_age_ms(None);
        be.set_wifi_enabled(false).unwrap();
        let mut r = rig_with(None, be);
        r.w.handle(Event::Cmd("open".into()), 2_000);
        assert!(!r.be.calls().iter().any(|c| c.starts_with("request_scan")));
        assert!(r.w.state(false).networks.is_empty());
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
    fn emission_rules() {
        let mut r = rig();
        // First line goes out immediately.
        let a = r.w.next_emission(100).expect("first state");
        assert_eq!(a.seq, 1);
        assert!(!a.heartbeat);
        // Nothing changed: nothing to say.
        assert!(r.w.next_emission(200).is_none());
        // A change inside the 250 ms window waits.
        r.w.on_probe(report(true, None), 300);
        assert!(r.w.next_emission(320).is_none());
        assert!(r.w.next_wake_ms(320) <= 30);
        let b = r.w.next_emission(360).expect("coalesced change");
        assert_eq!(b.seq, 2);
        // Quiet for 10 s: heartbeat, with a fresh seq.
        assert!(r.w.next_emission(9_000).is_none());
        let h = r.w.next_emission(10_600).expect("heartbeat");
        assert!(h.heartbeat);
        assert_eq!(h.seq, 3);
        // Clock-only differences do not trigger lines.
        assert!(r.w.next_emission(11_000).is_none());
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

    #[test]
    fn real_probe_against_a_local_dns_server() {
        use std::net::UdpSocket;
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = srv.local_addr().unwrap().port();
        // run_probe sends to port 53, so test the pieces: judge + a live
        // exchange on a custom port through dnswire.
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((n, from)) = srv.recv_from(&mut buf) {
                let mut resp = buf[..n].to_vec();
                resp[2] = 0x81;
                resp[3] = 0x80;
                resp[7] = 1; // one answer
                resp.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 2, 0, 4, 0, 0, 0, 0]);
                let _ = srv.send_to(&resp, from);
            }
        });
        let p = dnswire::query_a(
            format!("127.0.0.1:{port}").parse().unwrap(),
            "doubleclick.net",
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        let v = dnswire::judge(&p.reply, "127.0.0.1".parse().unwrap());
        assert!(v.ok && v.blocked);
    }
}

//! The worker threads behind `qnet watch` and the messages they exchange with
//! the main thread. Everything environment-specific (what a probe does, how
//! an API client is made) is injected, so the thread logic itself is tested
//! with fakes: cadence, kick/stop handling and the order things shut down in.

use std::io::BufRead;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config;
use crate::dnswire::{self, DnsError};
use crate::icmp;
use crate::pihole::{ApiError, Blocking, Bucket, Pihole, Summary, Upstreams};
use crate::setup::DEDICATED_CANARY;
use crate::util;

// ---- Messages ---------------------------------------------------------------

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

/// Queries one probe cycle sent to the Pi-hole (it logs every datagram), for
/// the stats subtraction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OwnQueries {
    pub total: u32,
    pub blocked: u32,
}

/// What the Pi-hole's pinned web API said when asked whether its host is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiLiveness {
    /// A TLS handshake with the pinned certificate completed: the host is
    /// alive, whatever it thinks of DNS.
    Alive,
    /// Connection refused, unreachable or timed out.
    Dead,
    /// Something answered with a different certificate.
    Mismatch,
    /// It answered, but not in a way that proves the Pi-hole is up.
    Other,
}

impl ApiLiveness {
    /// Anything that answered at all argues against calling it an outage.
    pub fn answered(self) -> bool {
        !matches!(self, ApiLiveness::Dead)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProbeReport {
    pub target: IpAddr,
    pub t: f64,
    /// The canary probe.
    pub pihole: ProbeOutcome,
    /// Gateway DNS probe; taken when the Pi-hole probe failed or its upstream
    /// check did.
    pub gateway: Option<bool>,
    /// The gateway answered the canary with 0.0.0.0: it forwards to the
    /// Pi-hole, so it is no alternative to it.
    pub gateway_blocked: Option<bool>,
    /// The pinned web API, asked when the canary went unanswered.
    pub api: Option<ApiLiveness>,
    /// Upstream-resolution check (random name); only when it was due and the
    /// canary answered. `Some(false)` means SERVFAIL or timeout.
    pub upstream: Option<bool>,
    pub own: OwnQueries,
    /// ICMP round trip to the gateway, when asked for and answered.
    pub gateway_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct ApiReport {
    pub status: &'static str,
    pub summary: Option<Summary>,
    pub blocking: Option<Blocking>,
    pub history: Option<Vec<Bucket>>,
    /// Per-upstream statistics; fetched on the history schedule and on open.
    pub upstreams: Option<Upstreams>,
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
    /// systemd-resolved's view of the Pi-hole: Some(reason) if downgraded.
    Downgrade(Option<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub addr: IpAddr,
    /// DNS port of the Pi-hole (53; tests use a local fake).
    pub port: u16,
    /// DNS port of the gateway (53).
    pub gateway_port: u16,
    /// Port and pinned certificate of the Pi-hole's web API, when configured.
    pub api: Option<ApiProbe>,
    /// The configured canary: a real blocklisted name. Used when the
    /// dedicated one is not on the deny list.
    pub canary: String,
    pub gateway: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiProbe {
    pub port: u16,
    pub pin: [u8; 32],
}

/// Is the Pi-hole's host up? One pinned HTTPS GET; any answer from the pinned
/// certificate (even 401) says yes.
pub fn check_api(addr: IpAddr, probe: &ApiProbe, timeout: Duration) -> ApiLiveness {
    use crate::https::{HttpError, HttpsClient};
    let Ok(client) = HttpsClient::new(SocketAddr::new(addr, probe.port), Some(probe.pin)) else {
        return ApiLiveness::Other;
    };
    let mut client = client.with_timeout(timeout);
    match client.request("GET", "/api/dns/blocking", &[], None) {
        Ok(_) => ApiLiveness::Alive,
        Err(HttpError::Connect(_)) | Err(HttpError::Timeout) => ApiLiveness::Dead,
        Err(HttpError::PinMismatch(_)) => ApiLiveness::Mismatch,
        Err(_) => ApiLiveness::Other,
    }
}

/// What one probe cycle should include besides the canary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeRequest {
    pub upstream: bool,
    pub icmp: bool,
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
    pub port: u16,
    pub pin: [u8; 32],
}

pub enum ApiCtl {
    Config(Option<ApiCfg>),
    Open(bool),
    Kick,
    Stop,
}

// ---- Prober -----------------------------------------------------------------------

pub const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_millis(2000);
pub const GATEWAY_ICMP_TIMEOUT: Duration = Duration::from_millis(800);
/// How long to wait before looking for the dedicated canary again.
pub const DEDICATED_RECHECK: Duration = Duration::from_secs(600);
/// A real domain whose subdomains do not exist: the answer must come from
/// upstream, not from the Pi-hole's cache.
pub const UPSTREAM_DOMAIN: &str = "example.com";

#[derive(Debug, Clone, Copy)]
pub struct Cadence {
    pub closed: Duration,
    pub open: Duration,
    pub upstream_closed: Duration,
    pub upstream_open: Duration,
    /// After a failed cycle, probe this often (open or closed) until
    /// `settle_good` good cycles in a row: failover and recovery stay quick
    /// while the healthy closed cadence stays cheap.
    pub suspect: Duration,
    pub settle_good: u32,
    /// Never probe more often than this, whatever is asked.
    pub min_gap: Duration,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            // The dedicated canary and the own-query subtraction keep the
            // Pi-hole's numbers clean, so the closed cadence can stay at 15 s.
            closed: Duration::from_secs(15),
            open: Duration::from_secs(5),
            upstream_closed: Duration::from_secs(60),
            upstream_open: Duration::from_secs(15),
            suspect: Duration::from_secs(5),
            settle_good: 6,
            min_gap: Duration::from_secs(1),
        }
    }
}

/// What the prober has learned about which canary name to use.
#[derive(Debug, Default)]
pub struct CanaryState {
    /// Some(true): `qnet-canary.invalid` is on the Pi-hole's deny list.
    dedicated: Option<bool>,
    checked: Option<Instant>,
}

pub type ProbeFn =
    Arc<dyn Fn(&ProbeTarget, &ProbeRequest, &mut CanaryState) -> ProbeReport + Send + Sync>;

pub fn real_probe() -> ProbeFn {
    Arc::new(run_probe)
}

struct NameProbe {
    ok: bool,
    ms: Option<f64>,
    blocked: bool,
}

/// One name, one server. A timeout is retried once at once (new id): Wi-Fi
/// loses datagrams, and an outage should be 30 s of failures, not one drop.
/// Every datagram sent is added to `own`.
fn probe_name(
    addr: IpAddr,
    port: u16,
    name: &str,
    strict: bool,
    own: &mut OwnQueries,
) -> NameProbe {
    for attempt in 0..2 {
        let (sent, res) = dnswire::query_a_counted(
            SocketAddr::new(addr, port),
            name,
            PROBE_TIMEOUT,
            Some(PROBE_TIMEOUT / 2),
        );
        own.total += sent;
        match res {
            Ok(p) => {
                let v = dnswire::judge(&p.reply, addr, strict);
                if v.ok && v.blocked {
                    own.blocked += sent;
                }
                return NameProbe {
                    ok: v.ok,
                    ms: v.ok.then_some(p.rtt.as_secs_f64() * 1000.0),
                    blocked: v.ok && v.blocked,
                };
            }
            Err(DnsError::Timeout) if attempt == 0 => continue,
            Err(_) => break,
        }
    }
    NameProbe {
        ok: false,
        ms: None,
        blocked: false,
    }
}

fn outcome(p: &NameProbe) -> ProbeOutcome {
    ProbeOutcome {
        ok: p.ok,
        ms: p.ms,
        blocked: p.blocked,
    }
}

/// The canary probe: the dedicated name when the Pi-hole blocks it, the
/// configured one otherwise.
fn canary_probe(t: &ProbeTarget, st: &mut CanaryState, own: &mut OwnQueries) -> ProbeOutcome {
    let look =
        st.dedicated == Some(true) || st.checked.is_none_or(|c| c.elapsed() >= DEDICATED_RECHECK);
    if !look {
        return outcome(&probe_name(t.addr, t.port, &t.canary, false, own));
    }
    let was_known = st.dedicated == Some(true);
    let first = probe_name(t.addr, t.port, DEDICATED_CANARY, true, own);
    if !was_known {
        st.checked = Some(Instant::now());
    }
    if first.blocked {
        st.dedicated = Some(true);
        return outcome(&first);
    }
    if !first.ok {
        // The Pi-hole did not answer at all.
        return outcome(&first);
    }
    // It answered but did not block the dedicated name: the deny entry is
    // missing, or blocking is paused. The configured canary tells which.
    let second = probe_name(t.addr, t.port, &t.canary, false, own);
    if second.blocked {
        st.dedicated = Some(false);
    } else if !was_known {
        st.dedicated = None;
    }
    outcome(&second)
}

fn upstream_probe(addr: IpAddr, port: u16, own: &mut OwnQueries) -> bool {
    for attempt in 0..2 {
        let name = dnswire::random_name_under(UPSTREAM_DOMAIN);
        let (sent, res) = dnswire::query_a_counted(
            SocketAddr::new(addr, port),
            &name,
            UPSTREAM_TIMEOUT,
            Some(UPSTREAM_TIMEOUT / 2),
        );
        own.total += sent;
        match res {
            Ok(p) => {
                return p.reply.rcode == dnswire::RCODE_NOERROR
                    || p.reply.rcode == dnswire::RCODE_NXDOMAIN
            }
            Err(DnsError::Timeout) if attempt == 0 => continue,
            Err(_) => return false,
        }
    }
    false
}

pub fn run_probe(t: &ProbeTarget, req: &ProbeRequest, st: &mut CanaryState) -> ProbeReport {
    let started = util::unix_now();
    let mut own = OwnQueries::default();
    let pihole = canary_probe(t, st, &mut own);
    let upstream = (req.upstream && pihole.ok).then(|| upstream_probe(t.addr, t.port, &mut own));
    // The gateway gate: asked whenever the Pi-hole is in trouble, whether it
    // is silent or merely cannot resolve.
    let in_trouble = !pihole.ok || upstream == Some(false);
    let (gateway, gateway_blocked) = match (in_trouble, t.gateway) {
        (true, Some(g)) => {
            let mut spent = OwnQueries::default();
            let r = probe_name(g, t.gateway_port, &t.canary, false, &mut spent);
            // Whether the *gateway* answers the way a resolver should: the
            // rcode is what `probe_name` already judged as `ok`.
            (Some(r.ok), Some(r.ok && r.blocked))
        }
        _ => (None, None),
    };
    let api = match (&t.api, pihole.ok) {
        (Some(a), false) => Some(check_api(t.addr, a, Duration::from_millis(1500))),
        _ => None,
    };
    let gateway_ms = match (req.icmp, t.gateway) {
        (true, Some(IpAddr::V4(g))) => {
            icmp::echo_rtt(g, GATEWAY_ICMP_TIMEOUT).map(|d| d.as_secs_f64() * 1000.0)
        }
        _ => None,
    };
    ProbeReport {
        target: t.addr,
        t: started,
        pihole,
        gateway,
        gateway_blocked,
        api,
        upstream,
        own,
        gateway_ms,
    }
}

/// The probe thread: one probe cycle per interval, immediately on a new
/// target, and no more often than `min_gap` however often it is kicked.
pub fn spawn_prober(
    tx: Sender<Event>,
    cadence: Cadence,
    probe: ProbeFn,
) -> (Sender<ProbeCtl>, JoinHandle<()>) {
    let (ctl_tx, ctl_rx) = mpsc::channel::<ProbeCtl>();
    let h = thread::spawn(move || {
        let mut target: Option<ProbeTarget> = None;
        let mut open = false;
        let mut canary = CanaryState::default();
        let mut last = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        let mut last_upstream: Option<Instant> = None;
        let mut next_due = Instant::now();
        // Good cycles still needed before leaving the fast `suspect` cadence.
        let mut unsettled: u32 = 0;
        let interval = |open: bool, unsettled: u32| {
            let base = if open { cadence.open } else { cadence.closed };
            if unsettled > 0 {
                base.min(cadence.suspect)
            } else {
                base
            }
        };
        let upstream_every = |open: bool| {
            if open {
                cadence.upstream_open
            } else {
                cadence.upstream_closed
            }
        };
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
                    canary = CanaryState::default();
                    last_upstream = None;
                    next_due = Instant::now();
                }
                Ok(ProbeCtl::Open(o)) => {
                    open = o;
                    // Opening: probe now if the last probe is a full open
                    // interval old, otherwise keep to the schedule.
                    next_due = if o && last.elapsed() >= interval(true, unsettled) {
                        Instant::now()
                    } else {
                        last + interval(o, unsettled)
                    };
                }
                Ok(ProbeCtl::Kick) => {
                    next_due = (last + cadence.min_gap).max(Instant::now());
                }
                Ok(ProbeCtl::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(t) = &target {
                        let req = ProbeRequest {
                            upstream: last_upstream
                                .is_none_or(|u| u.elapsed() >= upstream_every(open)),
                            icmp: open,
                        };
                        let report = probe(t, &req, &mut canary);
                        last = Instant::now();
                        if report.upstream.is_some() {
                            last_upstream = Some(last);
                        } else if !report.pihole.ok {
                            // Check upstream again on the first good cycle.
                            last_upstream = None;
                        }
                        let failed = !report.pihole.ok || report.upstream == Some(false);
                        unsettled = if failed {
                            cadence.settle_good
                        } else {
                            unsettled.saturating_sub(1)
                        };
                        next_due = last + interval(open, unsettled);
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

// ---- API poller -------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct ApiTiming {
    pub every: Duration,
    pub history_every: Duration,
    pub min_gap: Duration,
    pub auth_backoff: Duration,
    pub tls_backoff: Duration,
    pub setup_backoff: Duration,
}

impl Default for ApiTiming {
    fn default() -> Self {
        Self {
            every: Duration::from_secs(10),
            history_every: Duration::from_secs(60),
            min_gap: Duration::from_secs(1),
            auth_backoff: Duration::from_secs(60),
            tls_backoff: Duration::from_secs(30),
            setup_backoff: Duration::from_secs(30),
        }
    }
}

/// Builds the API client for a configuration (and picks up a saved session).
pub type ApiFactory = Arc<dyn Fn(&ApiCfg) -> Result<Pihole, ApiError> + Send + Sync>;

/// Both a missing secret and a keyring that will not answer are "auth"
/// problems: they get the long backoff, not a retry every few seconds.
fn password_fn(addr: IpAddr) -> crate::pihole::PasswordFn {
    Box::new(move || config::lookup_password(addr).map_err(|e| ApiError::Auth(e.to_string())))
}

pub fn real_api_factory() -> ApiFactory {
    Arc::new(|c: &ApiCfg| {
        let mut p = Pihole::at(SocketAddr::new(c.addr, c.port), c.pin, password_fn(c.addr))?;
        if let Some(path) = util::sid_path() {
            p = p.with_sid_file(path);
            // A session left behind by a killed predecessor.
            p.resume_session();
        }
        Ok(p)
    })
}

fn failure(e: &ApiError) -> ApiReport {
    ApiReport {
        status: e.status(),
        summary: None,
        blocking: None,
        history: None,
        upstreams: None,
        at: util::unix_now(),
    }
}

fn poll(api: &mut Pihole, with_history: bool, with_upstreams: bool) -> Result<ApiReport, ApiError> {
    let summary = api.summary()?;
    let blocking = api.blocking()?;
    let history = if with_history {
        Some(api.history()?)
    } else {
        None
    };
    // Nice to have: an older Pi-hole or an odd answer must not fail the poll.
    let upstreams = if with_upstreams {
        api.upstreams().ok()
    } else {
        None
    };
    Ok(ApiReport {
        status: "ok",
        summary: Some(summary),
        blocking: Some(blocking),
        history,
        upstreams,
        at: util::unix_now(),
    })
}

/// The API thread: polls only while open, reuses its session, and logs it
/// out when told to stop (so `Stop` followed by `join` means "logged out").
pub fn spawn_api(
    tx: Sender<Event>,
    timing: ApiTiming,
    factory: ApiFactory,
) -> (Sender<ApiCtl>, JoinHandle<()>) {
    let (ctl_tx, ctl_rx) = mpsc::channel::<ApiCtl>();
    let h = thread::spawn(move || {
        let mut cfg: Option<ApiCfg> = None;
        let mut client: Option<Pihole> = None;
        let mut open = false;
        let mut next_poll = Instant::now();
        let mut last_poll = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap_or_else(Instant::now);
        let mut last_history: Option<Instant> = None;
        let mut last_upstreams: Option<Instant> = None;
        // A failure's backoff: neither `Kick` nor `Open` may shorten it.
        let mut backoff_until: Option<Instant> = None;
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
                    last_upstreams = None;
                    backoff_until = None;
                    next_poll = Instant::now();
                }
                Ok(ApiCtl::Open(o)) => {
                    open = o;
                    if o {
                        // The Route view wants fresh upstream figures on open.
                        last_upstreams = None;
                        next_poll = backoff_until
                            .unwrap_or_else(Instant::now)
                            .max(Instant::now());
                    } else if let Some(c) = client.as_mut() {
                        c.close_idle();
                    }
                }
                Ok(ApiCtl::Kick) => {
                    let floor = backoff_until.unwrap_or_else(Instant::now);
                    next_poll = (last_poll + timing.min_gap).max(Instant::now()).max(floor);
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
                        match factory(&c) {
                            Ok(p) => client = Some(p),
                            Err(e) => {
                                let _ = tx.send(Event::Api(failure(&e)));
                                next_poll = Instant::now() + timing.setup_backoff;
                                backoff_until = Some(next_poll);
                                continue;
                            }
                        }
                    }
                    let api = client.as_mut().expect("just created");
                    last_poll = Instant::now();
                    let history_due =
                        last_history.is_none_or(|t| t.elapsed() >= timing.history_every);
                    let upstreams_due =
                        last_upstreams.is_none_or(|t| t.elapsed() >= timing.history_every);
                    let res = poll(api, history_due, upstreams_due);
                    api.close_idle();
                    match res {
                        Ok(report) => {
                            if report.history.is_some() {
                                last_history = Some(Instant::now());
                            }
                            if report.upstreams.is_some() {
                                last_upstreams = Some(Instant::now());
                            }
                            backoff_until = None;
                            next_poll = Instant::now() + timing.every;
                            if tx.send(Event::Api(report)).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            // Do not hammer logins or a dead host.
                            next_poll = Instant::now()
                                + match e {
                                    ApiError::Auth(_) => timing.auth_backoff,
                                    ApiError::Tls(_) => timing.tls_backoff,
                                    _ => timing.every,
                                };
                            backoff_until = Some(next_poll);
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

/// Stop both workers and wait for them. The API thread is joined last so its
/// logout has really happened when this returns.
pub fn stop_workers(
    probe: Sender<ProbeCtl>,
    probe_h: JoinHandle<()>,
    api: Sender<ApiCtl>,
    api_h: JoinHandle<()>,
) {
    let _ = probe.send(ProbeCtl::Stop);
    let _ = api.send(ApiCtl::Stop);
    let _ = probe_h.join();
    let _ = api_h.join();
}

// ---- Input and system threads -----------------------------------------------------

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
                        let path = hdr
                            .path()
                            .map(|p| p.as_str().to_string())
                            .unwrap_or_default();
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

/// The `notify-send` arguments for a notification. The `--` ends the options,
/// so a title that starts with `-` is text, never an option.
fn notify_args<'a>(title: &'a str, body: &'a str) -> [&'a str; 5] {
    ["-a", "qnet", "--", title, body]
}

/// `notify-send` in the background; failures are ignored.
pub fn desktop_notify(title: &str, body: &str) {
    let (t, b) = (title.to_string(), body.to_string());
    thread::spawn(move || {
        let _ = crate::proc::run(
            "notify-send",
            &notify_args(&t, &b),
            None,
            Duration::from_secs(5),
            1024,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::https::testutil::{ok_json, serve, TestServer};

    #[test]
    fn notify_send_gets_a_double_dash_before_the_title() {
        assert_eq!(
            notify_args("Title", "Body"),
            ["-a", "qnet", "--", "Title", "Body"]
        );
        // Text that looks like options stays after the `--`.
        let args = notify_args("--help", "-a evil");
        assert_eq!(args[2], "--");
        assert_eq!(&args[3..], ["--help", "-a evil"]);
    }
    use std::net::{Ipv4Addr, UdpSocket};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    fn tgt(port: u16) -> ProbeTarget {
        ProbeTarget {
            addr: "127.0.0.1".parse().unwrap(),
            port,
            gateway_port: port,
            api: None,
            canary: "doubleclick.net".into(),
            gateway: None,
        }
    }

    fn ok_report(t: &ProbeTarget, req: &ProbeRequest) -> ProbeReport {
        ProbeReport {
            target: t.addr,
            t: util::unix_now(),
            pihole: ProbeOutcome {
                ok: true,
                ms: Some(1.0),
                blocked: true,
            },
            gateway: None,
            gateway_blocked: None,
            api: None,
            upstream: req.upstream.then_some(true),
            own: OwnQueries {
                total: 1,
                blocked: 1,
            },
            gateway_ms: req.icmp.then_some(0.5),
        }
    }

    fn fast() -> Cadence {
        Cadence {
            closed: Duration::from_millis(200),
            open: Duration::from_millis(30),
            upstream_closed: Duration::from_millis(200),
            upstream_open: Duration::from_millis(100),
            suspect: Duration::from_millis(40),
            settle_good: 3,
            min_gap: Duration::from_millis(15),
        }
    }

    type Seen = Arc<Mutex<Vec<(Instant, ProbeRequest)>>>;

    fn recording_probe(seen: Seen) -> ProbeFn {
        Arc::new(move |t, req, _| {
            seen.lock().unwrap().push((Instant::now(), *req));
            ok_report(t, req)
        })
    }

    fn drain_probes(rx: &mpsc::Receiver<Event>) -> usize {
        let mut n = 0;
        while let Ok(ev) = rx.try_recv() {
            if matches!(ev, Event::Probe(_)) {
                n += 1;
            }
        }
        n
    }

    fn sleep(ms: u64) {
        thread::sleep(Duration::from_millis(ms));
    }

    // -- prober ---------------------------------------------------------------

    #[test]
    fn prober_waits_for_a_target_then_probes_at_once_and_on_the_closed_cadence() {
        let (tx, rx) = mpsc::channel();
        let seen: Seen = Arc::default();
        let (ctl, h) = spawn_prober(tx, fast(), recording_probe(seen.clone()));
        sleep(100);
        assert!(seen.lock().unwrap().is_empty(), "no target, no probes");
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        sleep(60);
        assert_eq!(seen.lock().unwrap().len(), 1, "immediately on a new target");
        assert!(
            seen.lock().unwrap()[0].1.upstream,
            "the first cycle includes the upstream check"
        );
        assert!(!seen.lock().unwrap()[0].1.icmp, "closed: no ICMP");
        sleep(450);
        let n = seen.lock().unwrap().len();
        assert!((3..=4).contains(&n), "about every 200 ms, got {n}");
        ctl.send(ProbeCtl::Stop).unwrap();
        h.join().unwrap();
        assert!(drain_probes(&rx) >= 3);
    }

    #[test]
    fn a_failed_probe_switches_to_the_suspect_cadence_until_it_settles() {
        let (tx, _rx) = mpsc::channel();
        let seen: Seen = Arc::default();
        let fails = Arc::new(Mutex::new(2u32));
        let probe: ProbeFn = {
            let (seen, fails) = (seen.clone(), fails.clone());
            Arc::new(move |t, req, _| {
                seen.lock().unwrap().push((Instant::now(), *req));
                let mut r = ok_report(t, req);
                let mut f = fails.lock().unwrap();
                if *f > 0 {
                    *f -= 1;
                    r.pihole = ProbeOutcome {
                        ok: false,
                        ms: None,
                        blocked: false,
                    };
                }
                r
            })
        };
        let (ctl, h) = spawn_prober(tx, fast(), probe);
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        // Closed cadence is 200 ms, suspect 40 ms: 2 failures + 3 settling
        // good cycles all land well inside 400 ms.
        sleep(400);
        let n = seen.lock().unwrap().len();
        assert!(n >= 5, "fast while failing and settling, got {n}");
        // Settled: back to the 200 ms closed cadence.
        let before = seen.lock().unwrap().len();
        sleep(300);
        let after = seen.lock().unwrap().len();
        assert!(
            after - before <= 2,
            "settled cadence is slow again, got {}",
            after - before
        );
        ctl.send(ProbeCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn open_speeds_probing_up_and_adds_icmp_and_a_slower_upstream_check() {
        let (tx, _rx) = mpsc::channel();
        let seen: Seen = Arc::default();
        let (ctl, h) = spawn_prober(tx, fast(), recording_probe(seen.clone()));
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        sleep(50);
        let before = seen.lock().unwrap().len();
        ctl.send(ProbeCtl::Open(true)).unwrap();
        sleep(400);
        {
            let s = seen.lock().unwrap();
            let open: Vec<_> = s.iter().skip(before).collect();
            assert!(
                open.len() >= 8,
                "open cadence is ~30 ms, got {}",
                open.len()
            );
            assert!(
                open.iter().all(|(_, r)| r.icmp),
                "every open cycle pings the gateway"
            );
            let upstream = open.iter().filter(|(_, r)| r.upstream).count();
            assert!(
                upstream >= 2 && upstream < open.len() / 2,
                "upstream every ~100 ms: {upstream} of {}",
                open.len()
            );
        }
        ctl.send(ProbeCtl::Open(false)).unwrap();
        sleep(60);
        let at_close = seen.lock().unwrap().len();
        sleep(350);
        let after = seen.lock().unwrap().len() - at_close;
        assert!(after <= 3, "back to ~200 ms: {after}");
        assert!(!seen.lock().unwrap().last().unwrap().1.icmp);
        ctl.send(ProbeCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn kick_probes_soon_but_never_faster_than_the_minimum_gap() {
        let (tx, _rx) = mpsc::channel();
        let seen: Seen = Arc::default();
        let mut c = fast();
        c.closed = Duration::from_secs(30);
        c.min_gap = Duration::from_millis(150);
        let (ctl, h) = spawn_prober(tx, c, recording_probe(seen.clone()));
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        sleep(40);
        assert_eq!(seen.lock().unwrap().len(), 1);
        // A burst of kicks right after a probe: one probe, a gap later.
        for _ in 0..10 {
            ctl.send(ProbeCtl::Kick).unwrap();
        }
        sleep(60);
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "held back by the minimum gap"
        );
        sleep(250);
        assert_eq!(seen.lock().unwrap().len(), 2, "ten kicks, one probe");
        let s = seen.lock().unwrap();
        assert!(s[1].0.duration_since(s[0].0) >= Duration::from_millis(140));
        drop(s);
        ctl.send(ProbeCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn removing_the_target_silences_the_prober_and_a_new_one_starts_fresh() {
        let (tx, _rx) = mpsc::channel();
        let seen: Seen = Arc::default();
        let (ctl, h) = spawn_prober(tx, fast(), recording_probe(seen.clone()));
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        sleep(60);
        ctl.send(ProbeCtl::Target(None)).unwrap();
        sleep(30);
        let n = seen.lock().unwrap().len();
        sleep(500);
        assert_eq!(seen.lock().unwrap().len(), n, "silent without a target");
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        sleep(60);
        assert_eq!(seen.lock().unwrap().len(), n + 1);
        assert!(
            seen.lock().unwrap().last().unwrap().1.upstream,
            "a new target gets a full first cycle"
        );
        ctl.send(ProbeCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn stop_ends_the_prober_even_in_the_middle_of_a_long_wait_and_so_does_a_dropped_sender() {
        let (tx, _rx) = mpsc::channel();
        let mut c = fast();
        c.closed = Duration::from_secs(3600);
        let (ctl, h) = spawn_prober(tx.clone(), c, recording_probe(Arc::default()));
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        sleep(50);
        let t0 = Instant::now();
        ctl.send(ProbeCtl::Stop).unwrap();
        h.join().unwrap();
        assert!(t0.elapsed() < Duration::from_millis(500));

        let (ctl, h) = spawn_prober(tx, c, recording_probe(Arc::default()));
        drop(ctl);
        let t0 = Instant::now();
        h.join().unwrap();
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "owner gone, thread gone"
        );
    }

    #[test]
    fn upstream_is_checked_again_first_thing_after_an_outage() {
        let (tx, _rx) = mpsc::channel();
        let seen: Seen = Arc::default();
        let calls = Arc::new(Mutex::new(0u32));
        let c2 = calls.clone();
        let s2 = seen.clone();
        // Cycle 2 and 3: the Pi-hole does not answer.
        let probe: ProbeFn = Arc::new(move |t, req, _| {
            let mut n = c2.lock().unwrap();
            *n += 1;
            s2.lock().unwrap().push((Instant::now(), *req));
            let mut rep = ok_report(t, req);
            if (2..=3).contains(&*n) {
                rep.pihole = ProbeOutcome {
                    ok: false,
                    ms: None,
                    blocked: false,
                };
                rep.upstream = None;
            }
            rep
        });
        let mut c = fast();
        c.open = Duration::from_millis(25);
        c.upstream_open = Duration::from_secs(3600); // never due on time alone
        let (ctl, h) = spawn_prober(tx, c, probe);
        ctl.send(ProbeCtl::Open(true)).unwrap();
        ctl.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        sleep(300);
        ctl.send(ProbeCtl::Stop).unwrap();
        h.join().unwrap();
        let s = seen.lock().unwrap();
        assert!(s.len() >= 5, "{}", s.len());
        assert!(s[0].1.upstream, "first cycle");
        assert!(!s[1].1.upstream, "just done, not due again on the clock");
        // Cycles 2 and 3 get no answer, so upstream was not (and could not
        // be) checked: it is asked for again every time until it runs.
        assert!(
            s[2].1.upstream && s[3].1.upstream,
            "cycle 4 is the first answered one after the outage"
        );
        assert!(
            !s[4].1.upstream,
            "and once it has run it waits for its schedule again"
        );
    }

    // -- canary and upstream probing against a fake DNS server ---------------

    struct FakeDns {
        port: u16,
        names: Arc<Mutex<Vec<String>>>,
        /// For each query: did it carry an EDNS0 OPT record?
        edns: Arc<Mutex<Vec<bool>>>,
    }

    /// Answer every query with `reply(name)`. `None` drops it silently.
    fn fake_dns<F>(reply: F) -> FakeDns
    where
        F: Fn(&str, usize) -> Option<(u8, Vec<Ipv4Addr>)> + Send + 'static,
    {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let names: Arc<Mutex<Vec<String>>> = Arc::default();
        let edns_seen: Arc<Mutex<Vec<bool>>> = Arc::default();
        let (n2, e2) = (names.clone(), edns_seen.clone());
        thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let q = &buf[..n];
                // question name
                let mut labels = vec![];
                let mut p = 12;
                while q[p] != 0 {
                    let l = q[p] as usize;
                    labels.push(String::from_utf8_lossy(&q[p + 1..p + 1 + l]).to_string());
                    p += l + 1;
                }
                let name = labels.join(".");
                let question_end = p + 1 + 4; // root label + type + class
                let edns = q.len() > question_end
                    && q[question_end] == 0
                    && q[question_end + 1] == 0
                    && q[question_end + 2] == 41;
                e2.lock().unwrap().push(edns);
                let idx = {
                    let mut g = n2.lock().unwrap();
                    g.push(name.clone());
                    g.len()
                };
                let Some((rcode, ips)) = reply(&name, idx) else {
                    continue;
                };
                // Echo the header and question only (the probes ask with an
                // EDNS0 OPT record, which the answers must not be glued after).
                let mut r = q[..question_end].to_vec();
                r[2] = 0x81;
                r[3] = 0x80 | rcode;
                r[6] = 0;
                r[7] = ips.len() as u8;
                r[10] = 0;
                r[11] = 0;
                for ip in ips {
                    r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 2, 0, 4]);
                    r.extend_from_slice(&ip.octets());
                }
                if edns {
                    // Answer with an OPT record too, as a real server does.
                    r[11] = 1;
                    r.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
                }
                let _ = sock.send_to(&r, from);
            }
        });
        FakeDns {
            port,
            names,
            edns: edns_seen,
        }
    }

    const NULL: Ipv4Addr = Ipv4Addr::UNSPECIFIED;
    const REAL: Ipv4Addr = Ipv4Addr::new(142, 250, 74, 14);

    fn req(upstream: bool) -> ProbeRequest {
        ProbeRequest {
            upstream,
            icmp: false,
        }
    }

    #[test]
    fn the_dedicated_canary_is_used_once_the_pihole_blocks_it() {
        let dns = fake_dns(|name, _| match name {
            "qnet-canary.invalid" => Some((0, vec![NULL])),
            "doubleclick.net" => Some((0, vec![NULL])),
            _ => Some((3, vec![])),
        });
        let t = tgt(dns.port);
        let mut st = CanaryState::default();
        let r = run_probe(&t, &req(false), &mut st);
        assert!(r.pihole.ok && r.pihole.blocked);
        assert_eq!(
            r.own,
            OwnQueries {
                total: 1,
                blocked: 1
            }
        );
        let r = run_probe(&t, &req(false), &mut st);
        assert!(r.pihole.blocked);
        assert_eq!(
            *dns.names.lock().unwrap(),
            vec!["qnet-canary.invalid", "qnet-canary.invalid"],
            "never the real domain"
        );
    }

    #[test]
    fn without_a_deny_entry_the_configured_canary_is_used_and_the_dedicated_one_rechecked_rarely() {
        let dns = fake_dns(|name, _| match name {
            "doubleclick.net" => Some((0, vec![NULL])),
            _ => Some((3, vec![])), // .invalid is NXDOMAIN upstream
        });
        let t = tgt(dns.port);
        let mut st = CanaryState::default();
        let r = run_probe(&t, &req(false), &mut st);
        // First cycle looks for the dedicated name, then falls back.
        assert!(r.pihole.ok && r.pihole.blocked);
        assert_eq!(
            r.own,
            OwnQueries {
                total: 2,
                blocked: 1
            }
        );
        // NXDOMAIN on the dedicated name must not read as "blocked".
        assert_eq!(
            *dns.names.lock().unwrap(),
            vec!["qnet-canary.invalid", "doubleclick.net"]
        );
        let r = run_probe(&t, &req(false), &mut st);
        assert_eq!(
            r.own,
            OwnQueries {
                total: 1,
                blocked: 1
            },
            "only the configured canary now"
        );
        assert_eq!(dns.names.lock().unwrap().len(), 3);
        // Ten minutes later it looks again.
        st.checked = Instant::now().checked_sub(DEDICATED_RECHECK + Duration::from_secs(1));
        run_probe(&t, &req(false), &mut st);
        assert_eq!(dns.names.lock().unwrap()[3], "qnet-canary.invalid");
    }

    #[test]
    fn a_paused_pihole_is_not_blocking_and_does_not_forget_the_dedicated_entry() {
        let paused = Arc::new(Mutex::new(false));
        let p2 = paused.clone();
        let dns = fake_dns(move |name, _| {
            if *p2.lock().unwrap() {
                return Some(if name == "qnet-canary.invalid" {
                    (3, vec![])
                } else {
                    (0, vec![REAL])
                });
            }
            Some((0, vec![NULL]))
        });
        let t = tgt(dns.port);
        let mut st = CanaryState::default();
        assert!(run_probe(&t, &req(false), &mut st).pihole.blocked);
        *paused.lock().unwrap() = true;
        let r = run_probe(&t, &req(false), &mut st);
        assert!(r.pihole.ok && !r.pihole.blocked, "answering, not blocking");
        assert_eq!(r.own.blocked, 0);
        assert_eq!(
            st.dedicated,
            Some(true),
            "pause is not a missing deny entry"
        );
        *paused.lock().unwrap() = false;
        assert!(run_probe(&t, &req(false), &mut st).pihole.blocked);
    }

    #[test]
    fn a_timed_out_probe_is_retried_once_at_once_and_every_datagram_is_counted() {
        // Swallow the first attempt (its datagram and the half-time resend),
        // answer the second attempt.
        let dns = fake_dns(|_, idx| {
            if idx <= 2 {
                None
            } else {
                Some((0, vec![NULL]))
            }
        });
        let t = tgt(dns.port);
        let mut st = CanaryState::default();
        let t0 = Instant::now();
        let r = run_probe(&t, &req(false), &mut st);
        assert!(r.pihole.ok && r.pihole.blocked, "the retry got through");
        assert_eq!(
            r.own.total, 3,
            "two lost datagrams and the one that was answered"
        );
        assert!(
            t0.elapsed() >= Duration::from_millis(1400) && t0.elapsed() < Duration::from_secs(4)
        );
    }

    #[test]
    fn upstream_check_uses_a_fresh_random_name_and_judges_the_rcode() {
        let mode = Arc::new(Mutex::new(3u8));
        let m2 = mode.clone();
        let dns = fake_dns(move |name, _| {
            if name.ends_with(".example.com") {
                Some((*m2.lock().unwrap(), vec![]))
            } else {
                Some((0, vec![NULL]))
            }
        });
        let t = tgt(dns.port);
        let mut st = CanaryState::default();
        // NXDOMAIN from upstream: healthy.
        let r = run_probe(&t, &req(true), &mut st);
        assert_eq!(r.upstream, Some(true));
        // The canary (1, or 2 while looking for the dedicated one) plus one upstream.
        assert!(r.own.total >= 2);
        *mode.lock().unwrap() = 2; // SERVFAIL
        let r = run_probe(&t, &req(true), &mut st);
        assert_eq!(r.upstream, Some(false));
        *mode.lock().unwrap() = 5; // REFUSED
        assert_eq!(run_probe(&t, &req(true), &mut st).upstream, Some(false));
        *mode.lock().unwrap() = 0; // NOERROR with nothing: fine too
        assert_eq!(run_probe(&t, &req(true), &mut st).upstream, Some(true));
        let names = dns.names.lock().unwrap();
        let upstream: Vec<&String> = names
            .iter()
            .filter(|n| n.ends_with(".example.com"))
            .collect();
        assert_eq!(upstream.len(), 4);
        let mut uniq = upstream.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), 4, "a fresh label every time, never cached");
        assert!(upstream
            .iter()
            .all(|n| n.split('.').next().unwrap().len() == 16));
    }

    #[test]
    fn upstream_is_skipped_when_the_canary_is_not_answered_and_the_gateway_probe_is_reported() {
        let dns = fake_dns(|_, _| None);
        let mut t = tgt(dns.port);
        t.gateway = None;
        let mut st = CanaryState::default();
        let r = run_probe(&t, &req(true), &mut st);
        assert!(!r.pihole.ok);
        assert_eq!(
            r.upstream, None,
            "no point asking a silent server for upstream"
        );
        assert_eq!(r.gateway, None, "no gateway known, no gate evidence");
    }

    #[test]
    fn gateway_ping_is_taken_only_when_asked_for() {
        if icmp::echo_rtt(Ipv4Addr::LOCALHOST, Duration::from_secs(1)).is_none() {
            eprintln!("skipped: no ping socket permission");
            return;
        }
        let dns = fake_dns(|_, _| Some((0, vec![NULL])));
        let mut t = tgt(dns.port);
        t.gateway = Some("127.0.0.1".parse().unwrap());
        let mut st = CanaryState::default();
        let r = run_probe(
            &t,
            &ProbeRequest {
                upstream: false,
                icmp: true,
            },
            &mut st,
        );
        assert!(r.gateway_ms.is_some_and(|ms| ms < 500.0));
        let r = run_probe(
            &t,
            &ProbeRequest {
                upstream: false,
                icmp: false,
            },
            &mut st,
        );
        assert_eq!(r.gateway_ms, None);
    }

    #[test]
    fn every_probe_carries_an_edns0_opt_record() {
        let dns = fake_dns(|name, _| {
            if name.ends_with(".example.com") {
                Some((3, vec![]))
            } else {
                Some((0, vec![NULL]))
            }
        });
        let t = tgt(dns.port);
        let mut st = CanaryState::default();
        let r = run_probe(&t, &req(true), &mut st);
        assert!(r.pihole.ok && r.upstream == Some(true));
        let seen = dns.edns.lock().unwrap();
        assert!(seen.len() >= 2, "canary and upstream were both asked");
        assert!(
            seen.iter().all(|e| *e),
            "{seen:?}: EDNS0 like systemd-resolved, so a server that mishandles it shows up here"
        );
    }

    #[test]
    fn the_gateway_is_asked_when_the_canary_works_but_upstream_does_not() {
        // The Pi-hole blocks the canary but SERVFAILs everything else; the
        // gateway (here the same fake) answers the canary normally.
        let dns = fake_dns(|name, _| {
            if name.ends_with(".example.com") {
                Some((2, vec![]))
            } else {
                Some((0, vec![REAL]))
            }
        });
        let mut t = tgt(dns.port);
        t.gateway = Some("127.0.0.1".parse().unwrap());
        let mut st = CanaryState::default();
        let r = run_probe(&t, &req(true), &mut st);
        assert!(r.pihole.ok);
        assert_eq!(r.upstream, Some(false));
        assert_eq!(
            r.gateway,
            Some(true),
            "gate evidence collected for a degraded Pi-hole too"
        );
        assert_eq!(
            r.gateway_blocked,
            Some(false),
            "this router resolves for real"
        );
        assert_eq!(
            r.api, None,
            "the canary was answered: no need to ask the web API"
        );
        // A healthy Pi-hole is not bothering the router at all.
        let mut st = CanaryState::default();
        let dns2 = fake_dns(|_, _| Some((0, vec![NULL])));
        let mut t2 = tgt(dns2.port);
        t2.gateway = Some("127.0.0.1".parse().unwrap());
        let r = run_probe(&t2, &req(true), &mut st);
        assert_eq!((r.gateway, r.gateway_blocked), (None, None));
        assert_eq!(
            dns2.names
                .lock()
                .unwrap()
                .iter()
                .filter(|n| *n == "doubleclick.net")
                .count(),
            0
        );
    }

    #[test]
    fn a_router_that_blocks_the_canary_forwards_to_the_pihole() {
        // Pi-hole silent; the "router" answers 0.0.0.0, i.e. it forwards to it.
        let pihole = fake_dns(|_, _| None);
        let router = fake_dns(|_, _| Some((0, vec![NULL])));
        let mut t = tgt(pihole.port);
        t.gateway = Some("127.0.0.1".parse().unwrap());
        t.gateway_port = router.port;
        let mut st = CanaryState::default();
        let r = run_probe(&t, &req(false), &mut st);
        assert!(!r.pihole.ok);
        assert_eq!(r.gateway, Some(true));
        assert_eq!(r.gateway_blocked, Some(true));
    }

    #[test]
    fn the_web_api_is_asked_only_when_the_canary_goes_unanswered() {
        let srv = serve(3, |_, _| Some(ok_json("{}")));
        let silent = fake_dns(|_, _| None);
        let mut t = tgt(silent.port);
        t.api = Some(ApiProbe {
            port: srv.addr.port(),
            pin: srv.fingerprint,
        });
        let mut st = CanaryState::default();
        let r = run_probe(&t, &req(false), &mut st);
        assert!(!r.pihole.ok);
        assert_eq!(r.api, Some(ApiLiveness::Alive), "DNS dead, web API alive");
        // Answering canary: the API is left alone.
        let fine = fake_dns(|_, _| Some((0, vec![NULL])));
        let mut t = tgt(fine.port);
        t.api = Some(ApiProbe {
            port: srv.addr.port(),
            pin: srv.fingerprint,
        });
        assert_eq!(
            run_probe(&t, &req(false), &mut CanaryState::default()).api,
            None
        );
    }

    #[test]
    fn api_liveness_cases() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let t = Duration::from_millis(600);
        // Pinned handshake completes: alive, even if the page is a 401.
        let srv = serve(1, |_, _| {
            Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}".to_vec())
        });
        assert_eq!(
            check_api(
                ip,
                &ApiProbe {
                    port: srv.addr.port(),
                    pin: srv.fingerprint
                },
                t
            ),
            ApiLiveness::Alive
        );
        // Another certificate: not the Pi-hole.
        let srv = serve(1, |_, _| Some(ok_json("{}")));
        let mut wrong = srv.fingerprint;
        wrong[0] ^= 1;
        assert_eq!(
            check_api(
                ip,
                &ApiProbe {
                    port: srv.addr.port(),
                    pin: wrong
                },
                t
            ),
            ApiLiveness::Mismatch
        );
        // Nothing listening: dead.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        assert_eq!(
            check_api(ip, &ApiProbe { port, pin: [0; 32] }, t),
            ApiLiveness::Dead
        );
        // A host that accepts and never speaks: the deadline makes it dead.
        let srv = serve(1, |_, _| {
            thread::sleep(Duration::from_secs(2));
            None
        });
        let t0 = Instant::now();
        assert_eq!(
            check_api(
                ip,
                &ApiProbe {
                    port: srv.addr.port(),
                    pin: srv.fingerprint
                },
                Duration::from_millis(300)
            ),
            ApiLiveness::Dead
        );
        assert!(t0.elapsed() < Duration::from_secs(2));
        assert!(
            ApiLiveness::Alive.answered()
                && ApiLiveness::Mismatch.answered()
                && ApiLiveness::Other.answered()
        );
        assert!(!ApiLiveness::Dead.answered());
    }

    // -- API poller ----------------------------------------------------------

    const LOGIN: &str = r#"{"session":{"valid":true,"sid":"SID-1","validity":300}}"#;

    type Log = Arc<Mutex<Vec<String>>>;

    fn fake_api(log: Log) -> TestServer {
        serve(50, move |_, req| {
            let first = req.lines().next().unwrap_or("").to_string();
            log.lock().unwrap().push(first.clone());
            if first.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN))
            } else if first.starts_with("GET /api/stats/summary") {
                Some(ok_json(
                    r#"{"queries":{"total":10,"blocked":2,"percent_blocked":20.0}}"#,
                ))
            } else if first.starts_with("GET /api/dns/blocking") {
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            } else if first.starts_with("GET /api/stats/upstreams") {
                Some(ok_json(
                    r#"{"upstreams":[{"ip":"blocklist","name":"blocklist","port":-1,"count":5},{"ip":"9.9.9.9","name":"dns9.quad9.net","port":53,"count":9,"statistics":{"response":0.05}}],"forwarded_queries":9}"#,
                ))
            } else if first.starts_with("GET /api/history") {
                Some(ok_json(
                    r#"{"history":[{"timestamp":600,"total":3,"blocked":1}]}"#,
                ))
            } else if first.starts_with("DELETE /api/auth") {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            } else {
                Some(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            }
        })
    }

    fn count(log: &Log, prefix: &str) -> usize {
        log.lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with(prefix))
            .count()
    }

    fn timing() -> ApiTiming {
        ApiTiming {
            every: Duration::from_millis(80),
            history_every: Duration::from_millis(500),
            min_gap: Duration::from_millis(20),
            auth_backoff: Duration::from_secs(30),
            tls_backoff: Duration::from_secs(30),
            setup_backoff: Duration::from_secs(30),
        }
    }

    fn factory_for(srv: &TestServer) -> ApiFactory {
        let (addr, fp) = (srv.addr, srv.fingerprint);
        Arc::new(move |_c| Pihole::at(addr, fp, Box::new(|| Ok(Zeroizing::new("pw".to_string())))))
    }

    fn cfg() -> ApiCfg {
        ApiCfg {
            addr: "127.0.0.1".parse().unwrap(),
            port: 443,
            pin: [0; 32],
        }
    }

    fn api_events(rx: &mpsc::Receiver<Event>) -> Vec<ApiReport> {
        let mut v = vec![];
        while let Ok(ev) = rx.try_recv() {
            if let Event::Api(r) = ev {
                v.push(r);
            }
        }
        v
    }

    #[test]
    fn the_api_poller_is_idle_until_open_stops_when_closed_and_logs_out_on_stop() {
        let log: Log = Arc::default();
        let srv = fake_api(log.clone());
        let (tx, rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory_for(&srv));
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        sleep(200);
        assert!(
            log.lock().unwrap().is_empty(),
            "closed panel: no HTTPS at all"
        );
        assert!(api_events(&rx).is_empty());

        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(300);
        let reports = api_events(&rx);
        assert!(reports.len() >= 2, "{} reports", reports.len());
        assert_eq!(reports[0].status, "ok");
        assert_eq!(reports[0].summary.unwrap().total, 10);
        assert!(
            reports[0].history.is_some(),
            "history comes with the first poll"
        );
        assert!(reports[1].history.is_none(), "and not on every poll");
        assert_eq!(count(&log, "POST /api/auth"), 1, "one login for all of it");

        ctl.send(ApiCtl::Open(false)).unwrap();
        sleep(60);
        let frozen = count(&log, "GET /api/stats/summary");
        sleep(300);
        assert_eq!(
            count(&log, "GET /api/stats/summary"),
            frozen,
            "closed again: silent"
        );

        let t0 = Instant::now();
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
        assert_eq!(
            count(&log, "DELETE /api/auth"),
            1,
            "logged out before the thread ended"
        );
        assert!(t0.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn upstreams_come_on_open_and_then_on_the_slow_schedule_only_while_open() {
        let log: Log = Arc::default();
        let srv = fake_api(log.clone());
        let (tx, rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory_for(&srv));
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        sleep(150);
        assert_eq!(
            count(&log, "GET /api/stats/upstreams"),
            0,
            "closed: nothing"
        );
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(250);
        let first = api_events(&rx);
        let with_up: Vec<_> = first.iter().filter(|r| r.upstreams.is_some()).collect();
        assert_eq!(with_up.len(), 1, "once on open, not on every 80 ms poll");
        let u = with_up[0].upstreams.as_ref().unwrap();
        assert_eq!(u.answered_by.blocklist, 5);
        assert_eq!(u.list[0].response_ms, Some(50.0));
        assert_eq!(count(&log, "GET /api/stats/upstreams"), 1);
        // The history cadence (500 ms in this test) brings the next one.
        sleep(600);
        assert_eq!(count(&log, "GET /api/stats/upstreams"), 2);
        // Closing and reopening fetches again straight away.
        ctl.send(ApiCtl::Open(false)).unwrap();
        sleep(120);
        let frozen = count(&log, "GET /api/stats/upstreams");
        sleep(300);
        assert_eq!(count(&log, "GET /api/stats/upstreams"), frozen);
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(200);
        assert_eq!(count(&log, "GET /api/stats/upstreams"), frozen + 1);
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn a_broken_upstreams_endpoint_does_not_fail_the_poll() {
        let log: Log = Arc::default();
        let l2 = log.clone();
        let srv = serve(40, move |_, req| {
            let first = req.lines().next().unwrap_or("").to_string();
            l2.lock().unwrap().push(first.clone());
            if first.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN))
            } else if first.starts_with("GET /api/stats/summary") {
                Some(ok_json(
                    r#"{"queries":{"total":10,"blocked":2,"percent_blocked":20.0}}"#,
                ))
            } else if first.starts_with("GET /api/dns/blocking") {
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            } else if first.starts_with("GET /api/history") {
                Some(ok_json(r#"{"history":[]}"#))
            } else if first.starts_with("GET /api/stats/upstreams") {
                Some(ok_json(r#"{"surprise": true}"#))
            } else if first.starts_with("DELETE") {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            } else {
                None
            }
        });
        let (tx, rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory_for(&srv));
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(250);
        let reports = api_events(&rx);
        assert!(!reports.is_empty());
        assert!(reports
            .iter()
            .all(|r| r.status == "ok" && r.upstreams.is_none()));
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn history_is_refreshed_on_its_own_slower_schedule() {
        let log: Log = Arc::default();
        let srv = fake_api(log.clone());
        let (tx, _rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory_for(&srv));
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(900);
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
        let polls = count(&log, "GET /api/stats/summary");
        let hist = count(&log, "GET /api/history");
        assert!(polls >= 5, "polls every ~80 ms over 900 ms, got {polls}");
        assert!(
            (2..=3).contains(&hist),
            "history every ~500 ms, got {hist} for {polls} polls"
        );
    }

    #[test]
    fn changing_the_config_logs_the_old_session_out() {
        let log: Log = Arc::default();
        let srv = fake_api(log.clone());
        let (tx, rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory_for(&srv));
        ctl.send(ApiCtl::Open(true)).unwrap();
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        sleep(250);
        assert_eq!(count(&log, "POST /api/auth"), 1);
        ctl.send(ApiCtl::Config(None)).unwrap();
        sleep(100);
        assert_eq!(
            count(&log, "DELETE /api/auth"),
            1,
            "unconfigured: session ended"
        );
        let before = count(&log, "GET /api/stats/summary");
        sleep(250);
        assert_eq!(
            count(&log, "GET /api/stats/summary"),
            before,
            "nothing to poll"
        );
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        sleep(250);
        assert_eq!(
            count(&log, "POST /api/auth"),
            2,
            "a new configuration logs in afresh"
        );
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
        assert_eq!(count(&log, "DELETE /api/auth"), 2);
        assert!(!api_events(&rx).is_empty());
    }

    #[test]
    fn a_keyring_failure_gets_the_long_backoff_and_refresh_cannot_shorten_it() {
        let attempts = Arc::new(Mutex::new(0u32));
        let a2 = attempts.clone();
        let srv = fake_api(Arc::default());
        let (addr, fp) = (srv.addr, srv.fingerprint);
        let factory: ApiFactory = Arc::new(move |_c| {
            let a3 = a2.clone();
            Pihole::at(
                addr,
                fp,
                Box::new(move || {
                    *a3.lock().unwrap() += 1;
                    Err(ApiError::Auth("keyring did not answer".into()))
                }),
            )
        });
        let (tx, rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory);
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(200);
        let first = api_events(&rx);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].status, "auth");
        for _ in 0..5 {
            ctl.send(ApiCtl::Kick).unwrap();
        }
        ctl.send(ApiCtl::Open(false)).unwrap();
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(400);
        assert!(
            api_events(&rx).is_empty(),
            "refresh and reopening do not hammer the keyring"
        );
        assert_eq!(*attempts.lock().unwrap(), 1);
        // A new configuration (e.g. after setup) does reset it.
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        sleep(250);
        assert_eq!(*attempts.lock().unwrap(), 2);
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn a_client_that_cannot_be_built_is_reported_and_retried_later() {
        let tries = Arc::new(Mutex::new(0u32));
        let t2 = tries.clone();
        let factory: ApiFactory = Arc::new(move |_c| {
            *t2.lock().unwrap() += 1;
            Err(ApiError::Tls("no usable TLS configuration".into()))
        });
        let (tx, rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory);
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(250);
        let r = api_events(&rx);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].status, "tls");
        assert_eq!(*tries.lock().unwrap(), 1);
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn stop_workers_returns_only_after_the_api_session_is_closed() {
        let log: Log = Arc::default();
        let srv = fake_api(log.clone());
        let (tx, rx) = mpsc::channel();
        let (ptx, ph) = spawn_prober(tx.clone(), fast(), recording_probe(Arc::default()));
        let (atx, ah) = spawn_api(tx, timing(), factory_for(&srv));
        ptx.send(ProbeCtl::Target(Some(tgt(53)))).unwrap();
        atx.send(ApiCtl::Config(Some(cfg()))).unwrap();
        atx.send(ApiCtl::Open(true)).unwrap();
        sleep(250);
        assert_eq!(count(&log, "POST /api/auth"), 1);
        assert_eq!(count(&log, "DELETE /api/auth"), 0);
        let t0 = Instant::now();
        stop_workers(ptx, ph, atx, ah);
        assert_eq!(
            count(&log, "DELETE /api/auth"),
            1,
            "no sleep needed: the join waited for the logout"
        );
        assert!(t0.elapsed() < Duration::from_secs(2));
        // Nothing keeps running afterwards.
        while rx.try_recv().is_ok() {}
        sleep(200);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_hung_pihole_cannot_stall_shutdown_beyond_the_request_timeout() {
        // The server accepts and never answers; Stop arrives mid-poll.
        let srv = serve(5, |_, _| {
            thread::sleep(Duration::from_secs(6));
            None
        });
        let (tx, _rx) = mpsc::channel();
        let (ctl, h) = spawn_api(tx, timing(), factory_for(&srv));
        ctl.send(ApiCtl::Config(Some(cfg()))).unwrap();
        ctl.send(ApiCtl::Open(true)).unwrap();
        sleep(300);
        let t0 = Instant::now();
        ctl.send(ApiCtl::Stop).unwrap();
        h.join().unwrap();
        assert!(
            t0.elapsed() < Duration::from_secs(8),
            "bounded by the 3 s request timeout: {:?}",
            t0.elapsed()
        );
    }

    /// Read-only checks against the real machine: `cargo test live_ -- --ignored`.
    #[test]
    #[ignore = "needs the owner's live network and config"]
    fn live_api_liveness_and_the_gateway_mac() {
        let cfg = crate::config::load(&util::config_path()).expect("config");
        let p = cfg.pihole.expect("a configured Pi-hole");
        let probe = ApiProbe {
            port: 443,
            pin: p.tls_sha256,
        };
        assert_eq!(
            check_api(p.address, &probe, Duration::from_millis(1500)),
            ApiLiveness::Alive
        );
        let mut wrong = probe;
        wrong.pin[0] ^= 1;
        assert_eq!(
            check_api(p.address, &wrong, Duration::from_millis(1500)),
            ApiLiveness::Mismatch
        );
        let gw: Ipv4Addr = std::env::var("QNET_LIVE_GATEWAY")
            .unwrap_or_else(|_| "192.168.1.1".into())
            .parse()
            .unwrap();
        let iface = std::env::var("QNET_LIVE_IFACE").unwrap_or_else(|_| "wlp7s0".into());
        let mac = crate::neigh::mac_of(gw, &iface).expect("gateway in the neighbour table");
        eprintln!(
            "gateway {gw} on {iface} is {}",
            crate::neigh::format_mac(&mac)
        );
        let q = crate::rstate::real_check(p.address);
        eprintln!("resolved's view of {}: {q:?}", p.address);
    }
}

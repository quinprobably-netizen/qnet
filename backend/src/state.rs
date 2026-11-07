//! The state JSON (the contract with the QML panel) and the pure function
//! that builds it from what the watcher knows.

use std::collections::VecDeque;
use std::net::IpAddr;

use serde::Serialize;

use crate::config::{Config, Fallback};
use crate::dnsmodel::{self, classify, detect_leaks, detect_mode, is_bypassed, LeakInput, Mode};
use crate::failover::Failover;
use crate::ledger::Ledger;
use crate::net::*;
use crate::pihole::{Blocking, BlockingState, Bucket, Summary, Upstreams};
use crate::threads::ApiLiveness;
use crate::util::round1;

pub const MAX_NETWORKS: usize = 40;
pub const MAX_PROBES: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProbeRec {
    pub t: f64,
    pub ok: bool,
    pub ms: Option<f64>,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct ApiView {
    /// ok | auth | tls | unreachable | unconfigured
    pub status: String,
    pub today: Option<Summary>,
    pub history: Vec<Bucket>,
    /// Blocking state from the API with the unix time it was read.
    pub blocking: Option<(Blocking, f64)>,
    /// Our own queries (total, blocked) as of the moment `today` was read.
    /// Subtracting the live tally instead would make the numbers dip between
    /// polls, since the Pi-hole's reading does not know about newer probes.
    pub own_today: (u64, u64),
    /// The tally as of the moment `history` was read.
    pub own_history: Ledger,
    /// Per-upstream statistics, and the tally when they were read.
    pub upstreams: Upstreams,
    pub own_upstreams: (u64, u64),
}

impl ApiView {
    pub fn unconfigured() -> Self {
        Self {
            status: "unconfigured".into(),
            today: None,
            history: vec![],
            blocking: None,
            own_today: (0, 0),
            own_history: Ledger::default(),
            upstreams: Upstreams::default(),
            own_upstreams: (0, 0),
        }
    }
    pub fn configured() -> Self {
        Self {
            status: "ok".into(),
            ..Self::unconfigured()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScanView {
    pub running: bool,
}

pub struct Inputs<'a> {
    pub net: Option<&'a NetSnapshot>,
    pub profiles: &'a [Profile],
    pub resolver: Option<&'a ResolverSnapshot>,
    pub cfg: &'a Config,
    /// Configured address, or an auto-detected one that has been seen
    /// blocking the canary. Drives roles, modes and leaks; it is *not* what
    /// is shown as `pihole.address`.
    pub pihole: Option<IpAddr>,
    /// A LAN Pi-hole seen blocking the canary while none is configured.
    pub detected: Option<IpAddr>,
    /// A candidate exists but no probe has answered for it yet.
    pub detect_pending: bool,
    pub probes: &'a VecDeque<ProbeRec>,
    /// Latest upstream-resolution check: Some(false) means SERVFAIL/timeout.
    pub upstream_ok: Option<bool>,
    /// Gateway ICMP round trip, only while the panel is open.
    pub gateway_ms: Option<f64>,
    /// What the pinned web API said the last time the canary went unanswered.
    pub api_state: Option<ApiLiveness>,
    /// systemd-resolved has dropped the Pi-hole to a lower feature level.
    pub resolved_downgrade: Option<&'a str>,
    /// `qnet dns auto` recorded Automatic as the choice for the primary profile.
    pub auto_deliberate: bool,
    /// The link a runtime failover is on, and the fallback it uses.
    pub engaged_iface: Option<&'a str>,
    pub fallback_in_use: Option<Fallback>,
    pub api: &'a ApiView,
    pub failover: &'a Failover,
    pub scan: ScanView,
    pub error: &'a str,
    pub now_unix: f64,
    /// Seconds since `net` was read; NM's "last scan" age keeps growing.
    pub net_age_s: f64,
}

// ---- Output types ---------------------------------------------------------

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LinkOut {
    pub kind: &'static str,
    pub device: String,
    pub connection: String,
    pub uuid: String,
    pub ssid: String,
    pub signal: u32,
    pub band: String,
    pub bitrate_mbps: u32,
    /// Channel frequency of the active access point, MHz; null off Wi-Fi.
    pub frequency_mhz: Option<u32>,
    /// IPv4 prefix length of `ip4`; null without an address.
    pub prefix: Option<u32>,
    /// Signal strength in dBm. NetworkManager does not expose it over D-Bus
    /// (only a percentage), and polling `iw` is off the table: always null.
    pub signal_dbm: Option<i32>,
    pub ip4: String,
    pub gateway: String,
    pub gateway_ms: Option<f64>,
    pub connectivity: &'static str,
    pub portal_url: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RadioOut {
    pub wifi_enabled: bool,
    pub hw_enabled: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NetworkOut {
    pub id: String,
    pub ssid: String,
    pub hidden: bool,
    pub signal: u32,
    pub security: &'static str,
    pub known: bool,
    pub uuid: String,
    pub active: bool,
    pub band: String,
    pub frequency_mhz: u32,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ScanOut {
    pub running: bool,
    pub last_scan_age_s: Option<u64>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct ServerOut {
    pub addr: String,
    pub link: String,
    pub current: bool,
    pub role: &'static str,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct LeakOut {
    pub kind: &'static str,
    #[serde(rename = "where")]
    pub where_: String,
    pub uuid: String,
    pub detail: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct FailoverOut {
    pub enabled: bool,
    pub fallback: &'static str,
    pub active: bool,
    pub since: u64,
    pub reason: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsOut {
    pub mode: &'static str,
    pub mode_source: &'static str,
    pub servers: Vec<ServerOut>,
    pub leaks: Vec<LeakOut>,
    pub failover: FailoverOut,
    pub manual_override: bool,
    /// A Pi-hole is configured and queries on the primary link can skip it.
    pub bypassed: bool,
    /// First of resolved's compiled FallbackDNS servers; only for mode "none".
    pub resolved_fallback: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TodayOut {
    pub total: u64,
    pub blocked: u64,
    pub percent: f64,
    /// Queries qnet's own probes sent, already taken out of the numbers.
    pub self_queries: u64,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamOut {
    pub name: String,
    pub ip: String,
    pub port: u16,
    pub count: u64,
    pub response_ms: Option<f64>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
pub struct AnsweredByOut {
    pub blocklist: u64,
    pub cache: u64,
    pub forwarded: u64,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct BucketOut {
    pub t: i64,
    pub total: u64,
    pub blocked: u64,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct ProbeOut {
    pub t: f64,
    pub ok: bool,
    pub ms: Option<f64>,
    pub blocked: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PiholeOut {
    pub configured: bool,
    pub address: String,
    pub admin_url: String,
    pub reachable: bool,
    pub latency_ms: Option<f64>,
    pub blocking: &'static str,
    pub pause_remaining_s: u64,
    pub api: String,
    /// ok | degraded | unreachable | unknown
    pub health: &'static str,
    /// Why, in a short sentence; empty when `ok` or `unknown`.
    pub health_reason: String,
    /// The last canary answered 0.0.0.0 (true) or did not (false).
    pub canary_blocked: Option<bool>,
    pub today: TodayOut,
    pub history: Vec<BucketOut>,
    /// Seconds of non-empty history (for fitting the graph's x axis).
    pub history_span_s: u64,
    /// The busiest real resolvers behind the Pi-hole (at most four).
    pub upstreams: Vec<UpstreamOut>,
    /// Who answered: the blocklist, the cache, or an upstream.
    pub answered_by: AnsweredByOut,
    /// A LAN Pi-hole seen blocking the canary while none is configured.
    /// Display only; never used as the address.
    pub detected: String,
    pub probes: Vec<ProbeOut>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct State {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub seq: u64,
    pub link: LinkOut,
    pub radio: RadioOut,
    pub networks: Vec<NetworkOut>,
    pub scan: ScanOut,
    pub dns: DnsOut,
    pub pihole: PiholeOut,
    pub error: String,
    /// Present (and true) only on the periodic heartbeat line.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub heartbeat: bool,
}

// ---- Builders -------------------------------------------------------------

fn gateways(net: Option<&NetSnapshot>) -> Vec<IpAddr> {
    net.map(|n| {
        n.devices
            .iter()
            .filter(|d| d.is_up())
            .filter_map(|d| d.gateway.map(IpAddr::V4))
            .collect()
    })
    .unwrap_or_default()
}

pub fn build_link(net: Option<&NetSnapshot>, profiles: &[Profile], gateway_ms: Option<f64>) -> LinkOut {
    let mut out = LinkOut {
        kind: "none",
        device: String::new(),
        connection: String::new(),
        uuid: String::new(),
        ssid: String::new(),
        signal: 0,
        band: String::new(),
        bitrate_mbps: 0,
        frequency_mhz: None,
        prefix: None,
        signal_dbm: None,
        ip4: String::new(),
        gateway: String::new(),
        gateway_ms: None,
        connectivity: Connectivity::Unknown.as_str(),
        portal_url: String::new(),
    };
    let Some(net) = net else { return out };
    out.connectivity = net.connectivity.as_str();
    if net.connectivity == Connectivity::Portal {
        out.portal_url = net.check_uri.clone();
    }
    let Some(dev) = net.primary_device().filter(|d| d.is_up()) else {
        return out;
    };
    let _ = profiles;
    out.device = dev.iface.clone();
    out.ip4 = dev.ip4.map(|a| a.to_string()).unwrap_or_default();
    out.prefix = dev.ip4.and(dev.prefix);
    out.gateway = dev.gateway.map(|a| a.to_string()).unwrap_or_default();
    out.gateway_ms = gateway_ms.map(round1);
    if let Some(a) = &dev.active {
        out.connection = a.id.clone();
        out.uuid = a.uuid.clone();
    }
    match dev.kind {
        DeviceKind::Wifi => {
            out.kind = "wifi";
            if let Some(w) = &dev.wifi {
                out.bitrate_mbps = w.bitrate_kbps / 1000;
                if let Some(ap) = w
                    .active_ap
                    .as_ref()
                    .and_then(|p| w.aps.iter().find(|a| &a.path == p))
                {
                    out.ssid = display_ssid(&ap.ssid).0;
                    out.signal = ap.strength as u32;
                    out.band = band_of(ap.freq).to_string();
                    out.frequency_mhz = Some(ap.freq).filter(|f| *f > 0);
                }
            }
        }
        DeviceKind::Ethernet => {
            out.kind = "ethernet";
            out.bitrate_mbps = dev.speed_mbps;
        }
    }
    out
}

pub fn build_networks(net: Option<&NetSnapshot>, profiles: &[Profile]) -> Vec<NetworkOut> {
    let Some(net) = net else { return vec![] };
    if !net.wifi_enabled {
        return vec![];
    }
    let Some(dev) = net.wifi_device() else { return vec![] };
    let Some(w) = &dev.wifi else { return vec![] };

    // Group by SSID bytes; every hidden entry shares one group.
    let mut groups: Vec<(Vec<u8>, Vec<&Ap>)> = Vec::new();
    for ap in &w.aps {
        let key = if display_ssid(&ap.ssid).1 { Vec::new() } else { ap.ssid.clone() };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(ap),
            None => groups.push((key, vec![ap])),
        }
    }
    let mut out: Vec<NetworkOut> = groups
        .into_iter()
        .map(|(key, aps)| {
            let active_ap = aps.iter().find(|a| Some(&a.path) == w.active_ap.as_ref()).copied();
            let strongest = aps.iter().max_by_key(|a| a.strength).copied().expect("non-empty group");
            let shown = active_ap.unwrap_or(strongest);
            let (name, hidden) = display_ssid(&shown.ssid);
            let profile = if hidden {
                None
            } else {
                profiles
                    .iter()
                    .filter(|p| p.kind == ProfileKind::Wifi && p.ssid.as_deref() == Some(&key[..]))
                    .max_by_key(|p| p.timestamp)
            };
            NetworkOut {
                id: shown.path.clone(),
                ssid: name,
                hidden,
                signal: shown.strength as u32,
                security: shown.security().as_str(),
                known: profile.is_some(),
                uuid: profile.map(|p| p.uuid.clone()).unwrap_or_default(),
                active: active_ap.is_some() && dev.is_up(),
                band: band_of(shown.freq).to_string(),
                frequency_mhz: shown.freq,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then(b.known.cmp(&a.known))
            .then(b.signal.cmp(&a.signal))
            .then(a.ssid.cmp(&b.ssid))
    });
    out.truncate(MAX_NETWORKS);
    out
}

fn reachable(probes: &VecDeque<ProbeRec>) -> bool {
    let n = probes.len();
    match n {
        0 => false,
        1 => probes[0].ok,
        _ => probes[n - 1].ok || probes[n - 2].ok,
    }
}

pub fn build_state(i: &Inputs<'_>, seq: u64, heartbeat: bool) -> State {
    let link = build_link(i.net, i.profiles, i.gateway_ms);
    let networks = build_networks(i.net, i.profiles);

    let primary = i.net.and_then(|n| n.primary_device()).filter(|d| d.is_up());
    let gws = gateways(i.net);
    let primary_profile = primary
        .and_then(|d| d.active.as_ref())
        .and_then(|a| i.profiles.iter().find(|p| p.uuid == a.uuid));
    let primary_link = primary.and_then(|d| i.resolver.and_then(|r| r.link(d.ifindex)));
    let link_servers: Vec<IpAddr> = primary_link.map(|l| l.servers.clone()).unwrap_or_default();

    // Only the link that actually failed over is in "fallback".
    let failed_over_here = i.failover.active()
        && match (i.engaged_iface, primary) {
            (Some(e), Some(d)) => e == d.iface,
            (Some(_), None) => false,
            (None, _) => true,
        };
    let mut mode = detect_mode(
        primary.is_some(),
        failed_over_here,
        &link_servers,
        primary_profile,
        i.pihole,
    );
    // While a Pi-hole candidate is still being checked, "custom" would be a
    // guess that may be wrong in a moment: say so instead.
    if i.detect_pending && mode == Mode::Custom {
        mode = Mode::Unknown;
    }

    // Servers resolved will use, per link.
    let mut servers: Vec<ServerOut> = Vec::new();
    if let Some(r) = i.resolver {
        for l in &r.links {
            let is_primary = primary.is_some_and(|d| d.ifindex == l.ifindex);
            if !is_primary && !l.default_route {
                continue;
            }
            for s in &l.servers {
                servers.push(ServerOut {
                    addr: s.to_string(),
                    link: l.name.clone(),
                    current: l.current == Some(*s),
                    role: classify(*s, i.pihole, &gws).as_str(),
                });
            }
        }
        for s in &r.global {
            servers.push(ServerOut {
                addr: s.to_string(),
                link: "global".into(),
                current: false,
                role: classify(*s, i.pihole, &gws).as_str(),
            });
        }
        if servers.is_empty() && primary.is_some() {
            for s in &r.fallback {
                servers.push(ServerOut {
                    addr: s.to_string(),
                    link: "fallback".into(),
                    current: false,
                    role: classify(*s, i.pihole, &gws).as_str(),
                });
            }
        }
    }

    let leaks: Vec<LeakOut> = match (i.pihole, i.net) {
        (Some(p), Some(net)) => detect_leaks(&LeakInput {
            net,
            profiles: i.profiles,
            resolver: i.resolver,
            pihole: p,
            gateways: &gws,
            mode,
            primary_iface: primary.map(|d| d.iface.as_str()),
            auto_deliberate: i.auto_deliberate,
            engaged_iface: if i.failover.active() { i.engaged_iface } else { None },
        })
        .into_iter()
        .map(|l| LeakOut {
            kind: l.kind.as_str(),
            where_: l.where_,
            uuid: l.uuid,
            detail: l.detail,
        })
        .collect(),
        _ => vec![],
    };

    let manual_override = match (i.pihole, primary_profile) {
        (Some(p), Some(prof)) => dnsmodel::manual_override(&prof.dns, p),
        _ => false,
    };

    let configured = i.cfg.pihole.is_some();
    let configured_addr = i.cfg.pihole.as_ref().map(|p| p.address);
    let bypassed = match configured_addr {
        Some(p) if primary.is_some() => is_bypassed(mode, &link_servers, primary_profile, p, i.auto_deliberate),
        _ => false,
    };
    let resolved_fallback = match (mode, i.resolver) {
        (Mode::None, Some(r)) if primary.is_some() => r.fallback.first().map(|a| a.to_string()).unwrap_or_default(),
        _ => String::new(),
    };
    let dns = DnsOut {
        mode: mode.as_str(),
        mode_source: if mode == Mode::Fallback { "runtime-failover" } else { "profile" },
        servers,
        leaks,
        failover: FailoverOut {
            enabled: configured && i.cfg.failover.enabled,
            // What is in use while failed over, what would be otherwise.
            fallback: if i.failover.active() {
                i.fallback_in_use.unwrap_or(i.cfg.failover.fallback).as_str()
            } else {
                i.cfg.failover.fallback.as_str()
            },
            active: i.failover.active(),
            since: i.failover.since(),
            reason: i.failover.reason().to_string(),
        },
        manual_override,
        bypassed,
        resolved_fallback,
    };

    // Pi-hole.
    let last_ok = i.probes.iter().rev().find(|p| p.ok);
    let api_fresh = i
        .api
        .blocking
        .filter(|(b, at)| b.state != BlockingState::Unknown && i.now_unix - at < 45.0);
    let blocking = match api_fresh {
        Some((b, _)) => b.state,
        None => match last_ok {
            Some(p) if p.blocked => BlockingState::Enabled,
            Some(_) => BlockingState::Disabled,
            None => BlockingState::Unknown,
        },
    };
    let pause_remaining_s = match api_fresh {
        Some((b, at)) if b.state == BlockingState::Disabled => b
            .timer
            .map(|t| (t - (i.now_unix - at)).max(0.0).ceil() as u64)
            .unwrap_or(0),
        _ => 0,
    };
    let last = i.probes.back();
    let latency_ms = last.filter(|p| p.ok).and_then(|p| p.ms).map(round1);
    // Address and admin URL come from the configuration and nothing else.
    let address = configured_addr.map(|a| a.to_string()).unwrap_or_default();
    let admin_url = match configured_addr {
        Some(IpAddr::V6(a)) => format!("https://[{a}]/admin/"),
        Some(a) => format!("https://{a}/admin/"),
        None => String::new(),
    };
    let is_reachable = i.pihole.is_some() && reachable(i.probes);
    let (health, health_reason): (&'static str, String) = if i.pihole.is_none() || i.probes.is_empty() {
        ("unknown", String::new())
    } else if !is_reachable {
        let why = match i.api_state {
            Some(ApiLiveness::Alive) => "DNS probes get no answer, but the web API still does: not failing over",
            Some(ApiLiveness::Mismatch) => "DNS probes get no answer and the web API presents a different certificate",
            _ => "no answer to DNS probes",
        };
        ("unreachable", why.to_string())
    } else if i.upstream_ok == Some(false) {
        ("degraded", "upstream resolution is failing (SERVFAIL, REFUSED or timeout)".to_string())
    } else if let Some(d) = i.resolved_downgrade {
        ("degraded", d.to_string())
    } else {
        ("ok", String::new())
    };
    let canary_blocked = if i.pihole.is_some() { last_ok.map(|p| p.blocked) } else { None };

    // Our own probes are in Pi-hole's numbers; take them out.
    let raw = i.api.today.unwrap_or(Summary { total: 0, blocked: 0, percent: 0.0 });
    let (own_total, own_blocked) = i.api.own_today;
    let have_today = i.api.today.is_some();
    let total = raw.total.saturating_sub(own_total);
    let blocked = raw.blocked.saturating_sub(own_blocked);
    let percent = if have_today && total > 0 { blocked as f64 / total as f64 * 100.0 } else { 0.0 };
    let history: Vec<BucketOut> = i
        .api
        .history
        .iter()
        .map(|b| {
            let (ot, ob) = i.api.own_history.bucket(b.t);
            BucketOut {
                t: b.t,
                total: b.total.saturating_sub(ot),
                blocked: b.blocked.saturating_sub(ob),
            }
        })
        .collect();
    let history_span_s = history_span(&history);
    let pihole = PiholeOut {
        configured,
        address,
        admin_url,
        reachable: is_reachable,
        latency_ms,
        blocking: blocking.as_str(),
        pause_remaining_s,
        api: if configured { i.api.status.clone() } else { "unconfigured".into() },
        health,
        health_reason,
        canary_blocked,
        today: TodayOut {
            total,
            blocked,
            percent: round1(percent),
            self_queries: if have_today { own_total.min(raw.total) } else { 0 },
        },
        history,
        history_span_s,
        upstreams: i
            .api
            .upstreams
            .list
            .iter()
            .map(|u| UpstreamOut {
                name: u.name.clone(),
                ip: u.ip.to_string(),
                port: u.port,
                count: u.count,
                response_ms: u.response_ms,
            })
            .collect(),
        answered_by: {
            // Our own probes are in these figures too: the blocked ones in
            // the blocklist, the rest among what was forwarded.
            let a = i.api.upstreams.answered_by;
            let (own_total, own_blocked) = i.api.own_upstreams;
            AnsweredByOut {
                blocklist: a.blocklist.saturating_sub(own_blocked),
                cache: a.cache,
                forwarded: a.forwarded.saturating_sub(own_total.saturating_sub(own_blocked)),
            }
        },
        detected: i.detected.map(|a| a.to_string()).unwrap_or_default(),
        probes: i
            .probes
            .iter()
            .map(|p| ProbeOut {
                t: (p.t * 10.0).round() / 10.0,
                ok: p.ok,
                ms: p.ms.map(round1),
                blocked: p.blocked,
            })
            .collect(),
    };

    let (wifi_enabled, hw_enabled) = i.net.map(|n| (n.wifi_enabled, n.hw_enabled)).unwrap_or((false, true));
    let last_scan_age_s = i
        .net
        .and_then(|n| n.wifi_device())
        .and_then(|d| d.wifi.as_ref())
        .and_then(|w| w.last_scan_age_ms)
        .map(|ms| (ms as f64 / 1000.0 + i.net_age_s.max(0.0)) as u64);

    State {
        type_: "state",
        seq,
        link,
        radio: RadioOut { wifi_enabled, hw_enabled },
        networks,
        scan: ScanOut { running: i.scan.running, last_scan_age_s },
        dns,
        pihole,
        error: i.error.to_string(),
        heartbeat,
    }
}

/// Seconds covered by the history from its first non-empty bucket to the end
/// of the last one, at most a day. Pi-hole zero-fills the time before it
/// started recording, which must not stretch the graph.
pub fn history_span(history: &[BucketOut]) -> u64 {
    const BUCKET_S: i64 = 600;
    let (Some(first), Some(last)) = (history.iter().find(|b| b.total > 0), history.last()) else {
        return 0;
    };
    (last.t + BUCKET_S - first.t).clamp(0, 24 * 3600) as u64
}

/// What decides whether a new line is worth sending: the state without the
/// fields that merely tick with the clock and, while the panel is closed,
/// without the ones that only a visible graph needs (`probes`, `latencyMs`,
/// the Wi-Fi `bitrateMbps`). A healthy closed probe then changes nothing.
pub fn signature_of(mut v: serde_json::Value, open: bool) -> String {
    if let Some(o) = v.as_object_mut() {
        o.remove("seq");
        o.remove("heartbeat");
        if let Some(scan) = o.get_mut("scan").and_then(|s| s.as_object_mut()) {
            scan.remove("lastScanAgeS");
        }
        if let Some(p) = o.get_mut("pihole").and_then(|s| s.as_object_mut()) {
            p.remove("pauseRemainingS");
            if !open {
                p.remove("probes");
                p.remove("latencyMs");
            }
        }
        if !open {
            if let Some(l) = o.get_mut("link").and_then(|s| s.as_object_mut()) {
                l.remove("bitrateMbps");
            }
        }
    }
    v.to_string()
}

#[cfg(test)]
pub fn change_signature(s: &State, open: bool) -> String {
    signature_of(serde_json::to_value(s).unwrap_or(serde_json::Value::Null), open)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FailoverCfg, PiholeCfg};
    use crate::dnsmodel::fixtures as fx;
    use crate::net::fake::{fake_cfg, FakeNet, U_ETH1, U_WIFI};
    use crate::pihole::{AnsweredBy, Upstream};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    struct Fixture {
        net: NetSnapshot,
        profiles: Vec<Profile>,
        resolver: ResolverSnapshot,
        cfg: Config,
        probes: VecDeque<ProbeRec>,
        api: ApiView,
        fo: Failover,
        upstream_ok: Option<bool>,
        gateway_ms: Option<f64>,
        detected: Option<IpAddr>,
        detect_pending: bool,
        auto_deliberate: bool,
        engaged_iface: Option<String>,
        fallback_in_use: Option<Fallback>,
        resolved_downgrade: Option<String>,
        api_state: Option<ApiLiveness>,
    }

    fn fixture() -> Fixture {
        let be = FakeNet::live_machine();
        let net = be.snapshot(true).unwrap();
        let profiles = be.profiles().unwrap();
        let resolver = be.resolver(&[]).unwrap();
        Fixture {
            net,
            profiles,
            resolver,
            cfg: fake_cfg(),
            probes: VecDeque::from([
                ProbeRec { t: 1_794_000_000.0, ok: true, ms: Some(3.13), blocked: true },
                ProbeRec { t: 1_794_000_005.0, ok: true, ms: Some(2.96), blocked: true },
            ]),
            api: ApiView {
                status: "ok".into(),
                today: Some(Summary { total: 1204, blocked: 164, percent: 13.62 }),
                history: vec![Bucket { t: 1_794_034_800, total: 40, blocked: 6 }],
                blocking: Some((
                    Blocking { state: BlockingState::Enabled, timer: None },
                    1_794_000_004.0,
                )),
                own_today: (0, 0),
                own_history: Ledger::default(),
                upstreams: Upstreams {
                    list: vec![Upstream {
                        name: "dns9.quad9.net".into(),
                        ip: "9.9.9.9".parse().unwrap(),
                        port: 53,
                        count: 287,
                        response_ms: Some(159.2),
                    }],
                    answered_by: AnsweredBy { blocklist: 1734, cache: 1075, forwarded: 430 },
                },
                own_upstreams: (0, 0),
            },
            fo: Failover::new(),
            upstream_ok: Some(true),
            gateway_ms: Some(3.84),
            detected: None,
            detect_pending: false,
            auto_deliberate: false,
            engaged_iface: None,
            fallback_in_use: None,
            resolved_downgrade: None,
            api_state: None,
        }
    }

    fn build(f: &Fixture) -> State {
        build_state(
            &Inputs {
                net: Some(&f.net),
                profiles: &f.profiles,
                resolver: Some(&f.resolver),
                cfg: &f.cfg,
                pihole: f.cfg.pihole.as_ref().map(|p| p.address),
                detected: f.detected,
                detect_pending: f.detect_pending,
                probes: &f.probes,
                upstream_ok: f.upstream_ok,
                gateway_ms: f.gateway_ms,
                api_state: f.api_state,
                resolved_downgrade: f.resolved_downgrade.as_deref(),
                auto_deliberate: f.auto_deliberate,
                engaged_iface: f.engaged_iface.as_deref(),
                fallback_in_use: f.fallback_in_use,
                api: &f.api,
                failover: &f.fo,
                scan: ScanView { running: false },
                error: "",
                now_unix: 1_794_000_006.0,
                net_age_s: 0.0,
            },
            42,
            false,
        )
    }

    fn to_json(s: &State) -> Value {
        serde_json::to_value(s).unwrap()
    }

    #[test]
    fn json_snapshot_of_the_live_machine_shape() {
        let st = build(&fixture());
        let got = to_json(&st);
        let want = json!({
            "type": "state",
            "seq": 42,
            "link": {
                "kind": "wifi", "device": "wlp7s0", "connection": "Redwood",
                "uuid": U_WIFI, "ssid": "Redwood", "signal": 72, "band": "5 GHz",
                "bitrateMbps": 866, "frequencyMhz": 5180, "prefix": 24, "signalDbm": null, "ip4": "192.168.1.242", "gateway": "192.168.1.1",
                "gatewayMs": 3.8, "connectivity": "full", "portalUrl": ""
            },
            "radio": {"wifiEnabled": true, "hwEnabled": true},
            "networks": [
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/12", "ssid": "Redwood",
                 "hidden": false, "signal": 72, "security": "psk", "known": true,
                 "uuid": U_WIFI, "active": true, "band": "5 GHz", "frequencyMhz": 5180},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/41", "ssid": "Corp",
                 "hidden": false, "signal": 60, "security": "enterprise", "known": false,
                 "uuid": "", "active": false, "band": "5 GHz", "frequencyMhz": 5180},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/40", "ssid": "Cafe",
                 "hidden": false, "signal": 50, "security": "psk", "known": false,
                 "uuid": "", "active": false, "band": "2.4 GHz", "frequencyMhz": 2437},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/42", "ssid": "Lobby",
                 "hidden": false, "signal": 40, "security": "open", "known": false,
                 "uuid": "", "active": false, "band": "2.4 GHz", "frequencyMhz": 2437},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/43", "ssid": "",
                 "hidden": true, "signal": 30, "security": "psk", "known": false,
                 "uuid": "", "active": false, "band": "2.4 GHz", "frequencyMhz": 2437}
            ],
            "scan": {"running": false, "lastScanAgeS": 12},
            "dns": {
                "mode": "pihole", "modeSource": "profile",
                "servers": [{"addr": "192.168.1.153", "link": "wlp7s0", "current": true, "role": "pihole"}],
                "leaks": [
                    {"kind": "profile", "where": "Wired connection 1", "uuid": U_ETH1,
                     "detail": "uses router DNS (automatic)"},
                    {"kind": "profile", "where": "Wired connection 2",
                     "uuid": "10e2035e-2c2c-3815-ab60-f18f6b0e39d5",
                     "detail": "uses router DNS (automatic)"}
                ],
                "failover": {"enabled": true, "fallback": "router", "active": false, "since": 0, "reason": ""},
                "manualOverride": false,
                "bypassed": false,
                "resolvedFallback": ""
            },
            "pihole": {
                "configured": true, "address": "192.168.1.153",
                "adminUrl": "https://192.168.1.153/admin/", "reachable": true,
                "latencyMs": 3.0, "blocking": "enabled", "pauseRemainingS": 0, "api": "ok",
                "health": "ok", "healthReason": "", "canaryBlocked": true,
                "today": {"total": 1204, "blocked": 164, "percent": 13.6, "selfQueries": 0},
                "history": [{"t": 1794034800, "total": 40, "blocked": 6}],
                "historySpanS": 600,
                "upstreams": [{"name": "dns9.quad9.net", "ip": "9.9.9.9", "port": 53, "count": 287, "responseMs": 159.2}],
                "answeredBy": {"blocklist": 1734, "cache": 1075, "forwarded": 430},
                "detected": "",
                "probes": [
                    {"t": 1794000000.0, "ok": true, "ms": 3.1, "blocked": true},
                    {"t": 1794000005.0, "ok": true, "ms": 3.0, "blocked": true}
                ]
            },
            "error": ""
        });
        assert_eq!(got, want, "\n{}", serde_json::to_string_pretty(&got).unwrap());
    }

    fn shape(v: &Value, path: &str, out: &mut BTreeMap<String, &'static str>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    shape(x, &format!("{path}.{k}"), out);
                }
            }
            Value::Array(a) => {
                out.insert(path.to_string(), "array");
                if let Some(first) = a.first() {
                    shape(first, &format!("{path}[]"), out);
                }
            }
            Value::String(_) => {
                out.insert(path.to_string(), "string");
            }
            Value::Number(_) => {
                out.insert(path.to_string(), "number");
            }
            Value::Bool(_) => {
                out.insert(path.to_string(), "bool");
            }
            Value::Null => {
                out.insert(path.to_string(), "null");
            }
        }
    }

    /// The first ```json block of SPEC.md is the contract.
    fn spec_sample() -> Value {
        let spec = include_str!("../../SPEC.md");
        let start = spec.find("```json").expect("spec has a json block") + "```json".len();
        let end = start + spec[start..].find("```").expect("json block ends");
        serde_json::from_str(&spec[start..end]).expect("spec json parses")
    }

    #[test]
    fn output_matches_the_spec_contract_key_for_key() {
        let mut want = BTreeMap::new();
        shape(&spec_sample(), "", &mut want);
        let mut got = BTreeMap::new();
        shape(&to_json(&build(&fixture())), "", &mut got);
        // The spec shows `lastScanAgeS` etc. as numbers; compare every path.
        for (path, ty) in &want {
            assert_eq!(got.get(path), Some(ty), "contract path {path} missing or wrong type");
        }
        for path in got.keys() {
            assert!(want.contains_key(path), "undeclared field {path}");
        }
    }

    #[test]
    fn heartbeat_flag_only_appears_on_heartbeats() {
        let f = fixture();
        let mut st = build(&f);
        assert!(to_json(&st).get("heartbeat").is_none());
        st.heartbeat = true;
        assert_eq!(to_json(&st)["heartbeat"], true);
        assert_eq!(to_json(&st)["type"], "state");
    }

    #[test]
    fn active_group_shows_the_active_ap_not_the_strongest() {
        let mut f = fixture();
        let dev = &mut f.net.devices[0];
        let w = dev.wifi.as_mut().unwrap();
        // Same SSID also seen on 2.4 GHz, stronger, plus the 5 GHz active AP.
        w.aps.push(Ap {
            path: "/org/freedesktop/NetworkManager/AccessPoint/99".into(),
            ssid: b"Redwood".to_vec(),
            strength: 90,
            freq: 2437,
            flags: 3,
            wpa: 0,
            rsn: 0x188,
        });
        let nets = build_networks(Some(&f.net), &f.profiles);
        let r: Vec<_> = nets.iter().filter(|n| n.ssid == "Redwood").collect();
        assert_eq!(r.len(), 1, "grouped by SSID");
        assert_eq!(r[0].id, "/org/freedesktop/NetworkManager/AccessPoint/12");
        assert_eq!(r[0].signal, 72);
        assert_eq!(r[0].band, "5 GHz");
        assert!(r[0].active);
    }

    #[test]
    fn inactive_group_shows_the_strongest_ap_and_the_list_is_capped() {
        let mut f = fixture();
        let w = f.net.devices[0].wifi.as_mut().unwrap();
        w.aps.clear();
        w.active_ap = None;
        for i in 0..60u32 {
            w.aps.push(Ap {
                path: format!("/org/freedesktop/NetworkManager/AccessPoint/{}", 100 + i),
                ssid: format!("net{i:02}").into_bytes(),
                strength: (i % 100) as u8,
                freq: 2437,
                flags: 0,
                wpa: 0,
                rsn: 0,
            });
        }
        for (k, str_) in [(1000u32, 20u8), (1001, 85)] {
            w.aps.push(Ap {
                path: format!("/org/freedesktop/NetworkManager/AccessPoint/{k}"),
                ssid: b"dual".to_vec(),
                strength: str_,
                freq: if k == 1000 { 5180 } else { 2437 },
                flags: 0,
                wpa: 0,
                rsn: 0,
            });
        }
        let nets = build_networks(Some(&f.net), &f.profiles);
        assert_eq!(nets.len(), MAX_NETWORKS);
        let dual = nets.iter().find(|n| n.ssid == "dual").unwrap();
        assert_eq!(dual.signal, 85);
        assert_eq!(dual.id, "/org/freedesktop/NetworkManager/AccessPoint/1001");
        // Strongest first among the unknown ones.
        assert_eq!(nets[0].ssid, "dual");
        assert!(nets.windows(2).all(|p| p[0].signal >= p[1].signal));
        assert!(nets.iter().all(|n| !n.active));
    }

    #[test]
    fn networks_sort_active_then_known_then_signal() {
        let mut f = fixture();
        // Cafe becomes a known (weaker) profile.
        f.profiles.push(fx::profile(
            "11111111-2222-3333-4444-555555555555",
            "Cafe",
            ProfileKind::Wifi,
            fx::dns_auto(),
        ));
        let nets = build_networks(Some(&f.net), &f.profiles);
        let order: Vec<&str> = nets.iter().map(|n| n.ssid.as_str()).collect();
        assert_eq!(order[0], "Redwood");
        assert_eq!(order[1], "Cafe");
        assert!(nets[1].known && nets[1].uuid == "11111111-2222-3333-4444-555555555555");
        assert_eq!(order[2], "Corp");
    }

    #[test]
    fn hostile_ssids_are_sanitized_and_hidden_ones_flagged() {
        let mut f = fixture();
        let w = f.net.devices[0].wifi.as_mut().unwrap();
        w.aps.clear();
        w.active_ap = None;
        let mk = |n: u32, ssid: &[u8], s: u8| Ap {
            path: format!("/org/freedesktop/NetworkManager/AccessPoint/{n}"),
            ssid: ssid.to_vec(),
            strength: s,
            freq: 2437,
            flags: 0,
            wpa: 0,
            rsn: 0,
        };
        w.aps.push(mk(1, b"Evil\x1b[2J\nName", 50));
        w.aps.push(mk(2, &[0xFF, 0xFE, b'x'], 40));
        w.aps.push(mk(3, &[0, 0, 0], 30));
        w.aps.push(mk(4, b"", 20));
        let nets = build_networks(Some(&f.net), &f.profiles);
        assert_eq!(nets.len(), 3, "both hidden entries collapse into one");
        assert_eq!(nets[0].ssid, "Evil[2JName");
        assert!(nets[1].ssid.contains('\u{FFFD}') && nets[1].ssid.ends_with('x'));
        assert!(nets[2].hidden && nets[2].ssid.is_empty());
        let j = serde_json::to_string(&nets).unwrap();
        assert!(!j.contains("\\u001b"));
    }

    #[test]
    fn radio_off_hides_networks() {
        let mut f = fixture();
        f.net.wifi_enabled = false;
        let st = build(&f);
        assert!(st.networks.is_empty());
        assert!(!st.radio.wifi_enabled);
    }

    #[test]
    fn no_link_state() {
        let mut f = fixture();
        f.net.devices[0].state = 30;
        f.net.devices[0].active = None;
        f.net.primary_conn = None;
        f.resolver.links.clear();
        let st = build(&f);
        assert_eq!(st.link.kind, "none");
        assert_eq!(st.link.ssid, "");
        assert_eq!(st.link.signal, 0);
        assert_eq!(st.dns.mode, "none");
        assert!(!st.dns.manual_override);
        assert!(st.dns.servers.iter().all(|s| s.link == "fallback"));
    }

    #[test]
    fn ethernet_link_and_portal_url() {
        let mut f = fixture();
        let mut eth = f.net.devices[0].clone();
        eth.kind = DeviceKind::Ethernet;
        eth.iface = "enp8s0".into();
        eth.wifi = None;
        eth.speed_mbps = 1000;
        f.net.devices = vec![eth];
        f.net.connectivity = Connectivity::Portal;
        let st = build(&f);
        assert_eq!(st.link.kind, "ethernet");
        assert_eq!(st.link.bitrate_mbps, 1000);
        assert_eq!(st.link.ssid, "");
        assert_eq!(st.link.connectivity, "portal");
        assert_eq!(st.link.portal_url, "http://ping.omacom.io/nm-check.txt");
        assert!(st.networks.is_empty(), "no wifi device, no list");
    }

    #[test]
    fn mode_custom_manual_override_and_leaks_for_a_9_9_9_9_profile() {
        let mut f = fixture();
        f.profiles[0].dns.v4_dns = vec!["9.9.9.9".parse().unwrap()];
        f.resolver.links[0].servers = vec!["9.9.9.9".parse().unwrap()];
        f.resolver.links[0].current = Some("9.9.9.9".parse().unwrap());
        let st = build(&f);
        assert_eq!(st.dns.mode, "custom");
        assert!(st.dns.manual_override);
        assert_eq!(st.dns.servers[0].role, "public");
        let active = st.dns.leaks.iter().find(|l| l.where_ == "Redwood").unwrap();
        assert_eq!(active.kind, "link");
        assert_eq!(active.uuid, U_WIFI);
        assert_eq!(active.detail, "uses 9.9.9.9 (public)");
    }

    #[test]
    fn automatic_mode_is_not_a_leak_and_lights_auto() {
        let mut f = fixture();
        f.auto_deliberate = true;
        f.profiles[0].dns = fx::dns_auto();
        f.resolver.links[0].servers = vec![fx::gw()];
        f.resolver.links[0].current = Some(fx::gw());
        let st = build(&f);
        assert_eq!(st.dns.mode, "auto");
        assert!(st.dns.leaks.iter().all(|l| l.where_ != "Redwood"));
        assert_eq!(st.dns.servers[0].role, "router");
        assert!(!st.dns.manual_override);
    }

    #[test]
    fn runtime_failover_is_fallback_mode() {
        let mut f = fixture();
        f.fo.adopt(1_794_000_000, "Pi-hole not answering");
        f.resolver.links[0].servers = vec![fx::gw()];
        let st = build(&f);
        assert_eq!(st.dns.mode, "fallback");
        assert_eq!(st.dns.mode_source, "runtime-failover");
        assert!(st.dns.failover.active);
        assert_eq!(st.dns.failover.since, 1_794_000_000);
        assert_eq!(st.dns.failover.reason, "Pi-hole not answering");
        assert!(st.dns.leaks.iter().all(|l| l.where_ != "Redwood"), "failover is not a leak");
    }

    #[test]
    fn unconfigured_has_no_pihole_features() {
        let mut f = fixture();
        f.cfg = Config::default();
        let st = {
            let pihole = None;
            build_state(
                &Inputs {
                    net: Some(&f.net),
                    profiles: &f.profiles,
                    resolver: Some(&f.resolver),
                    cfg: &f.cfg,
                    pihole,
                    detected: None,
                    detect_pending: false,
                    probes: &VecDeque::new(),
                    upstream_ok: None,
                    gateway_ms: None,
                api_state: None,
                resolved_downgrade: None,
                auto_deliberate: false,
                engaged_iface: None,
                fallback_in_use: None,
                    api: &ApiView::unconfigured(),
                    failover: &f.fo,
                    scan: ScanView::default(),
                    error: "",
                    now_unix: 1.0,
                    net_age_s: 0.0,
                },
                1,
                false,
            )
        };
        assert!(!st.pihole.configured);
        assert_eq!(st.pihole.api, "unconfigured");
        assert_eq!(st.pihole.address, "");
        assert_eq!(st.pihole.admin_url, "");
        assert!(!st.pihole.reachable);
        assert_eq!(st.pihole.latency_ms, None);
        assert_eq!(st.pihole.blocking, "unknown");
        assert!(st.dns.leaks.is_empty());
        assert!(!st.dns.failover.enabled);
        assert_eq!(st.dns.mode, "custom");
    }

    #[test]
    fn reachability_needs_two_misses_and_latency_hides_when_failing() {
        let mut f = fixture();
        f.probes.push_back(ProbeRec { t: 1_794_000_010.0, ok: false, ms: None, blocked: false });
        let st = build(&f);
        assert!(st.pihole.reachable, "one miss is a blip");
        assert_eq!(st.pihole.latency_ms, None);
        f.probes.push_back(ProbeRec { t: 1_794_000_015.0, ok: false, ms: None, blocked: false });
        let st = build(&f);
        assert!(!st.pihole.reachable);
        assert_eq!(to_json(&st)["pihole"]["probes"][3]["ms"], Value::Null);
        // Still known to be blocking from the API; a fresh probe flips it back.
        assert_eq!(st.pihole.blocking, "enabled");
    }

    #[test]
    fn pause_countdown_and_blocking_sources() {
        let mut f = fixture();
        f.api.blocking = Some((Blocking { state: BlockingState::Disabled, timer: Some(300.0) }, 1_794_000_000.0));
        let st = build(&f); // now = +6 s
        assert_eq!(st.pihole.blocking, "disabled");
        assert_eq!(st.pihole.pause_remaining_s, 294);
        // Stale API data (> 45 s) falls back to the canary.
        f.api.blocking = Some((Blocking { state: BlockingState::Disabled, timer: Some(300.0) }, 1_793_999_900.0));
        let st = build(&f);
        assert_eq!(st.pihole.blocking, "enabled");
        assert_eq!(st.pihole.pause_remaining_s, 0);
        // No API at all: paused is visible from the canary alone.
        f.api = ApiView::configured();
        f.probes.push_back(ProbeRec { t: 1_794_000_010.0, ok: true, ms: Some(4.0), blocked: false });
        assert_eq!(build(&f).pihole.blocking, "disabled");
        // Timer never goes negative.
        f.api.blocking = Some((Blocking { state: BlockingState::Disabled, timer: Some(2.0) }, 1_794_000_000.0));
        assert_eq!(build(&f).pihole.pause_remaining_s, 0);
    }

    #[test]
    fn change_signature_ignores_clock_driven_fields_only() {
        let mut f = fixture();
        f.api.blocking = Some((Blocking { state: BlockingState::Disabled, timer: Some(300.0) }, 1_794_000_000.0));
        let a = build(&f);
        let mut b = a.clone();
        b.seq = 99;
        b.heartbeat = true;
        b.scan.last_scan_age_s = Some(500);
        b.pihole.pause_remaining_s = 12;
        assert_eq!(change_signature(&a, true), change_signature(&b, true));
        let mut c = a.clone();
        c.dns.mode = "auto";
        assert_ne!(change_signature(&a, true), change_signature(&c, true));
        let mut d = a.clone();
        d.pihole.today.total += 1;
        assert_ne!(change_signature(&a, true), change_signature(&d, true));
    }

    #[test]
    fn disabled_failover_reports_enabled_false() {
        let mut f = fixture();
        f.cfg.failover = FailoverCfg { enabled: false, ..FailoverCfg::default() };
        assert!(!build(&f).dns.failover.enabled);
        f.cfg.pihole = Some(PiholeCfg { ..f.cfg.pihole.clone().unwrap() });
        f.cfg.failover.enabled = true;
        assert!(build(&f).dns.failover.enabled);
    }

    #[test]
    fn bypassed_dns_none_unknown_and_fallback_fields() {
        // Healthy: not bypassed.
        let f = fixture();
        let st = build(&f);
        assert!(!st.dns.bypassed);
        assert_eq!(st.dns.resolved_fallback, "");

        // Pi-hole in use, but the router answers too: still "pihole", bypassed.
        let mut f = fixture();
        f.resolver.links[0].servers = vec![fx::pi(), fx::gw()];
        let st = build(&f);
        assert_eq!(st.dns.mode, "pihole");
        assert!(st.dns.bypassed);

        // Unpinned profile (automatic, DHCP handing out the Pi-hole).
        let mut f = fixture();
        f.profiles[0].dns = fx::dns_auto();
        let st = build(&f);
        assert_eq!(st.dns.mode, "pihole");
        assert!(st.dns.bypassed, "Pin has something to fix");

        // Automatic that `qnet dns auto` recorded is the user's choice; any other
        // Automatic (a cable that came up on its own) is a bypass.
        let mut f = fixture();
        f.profiles[0].dns = fx::dns_auto();
        f.resolver.links[0].servers = vec![fx::gw()];
        let st = build(&f);
        assert_eq!(st.dns.mode, "auto");
        assert!(st.dns.bypassed, "nobody chose this");
        assert!(st.dns.leaks.iter().any(|l| l.where_ == "Redwood"), "and the active link says so");
        f.auto_deliberate = true;
        let st = build(&f);
        assert_eq!(st.dns.mode, "auto");
        assert!(!st.dns.bypassed);
        assert!(st.dns.leaks.iter().all(|l| l.where_ != "Redwood"));

        // Link up, no DNS servers at all: mode none, resolved's fallback shown.
        let mut f = fixture();
        f.resolver.links.clear();
        let st = build(&f);
        assert_eq!(st.dns.mode, "none");
        assert_eq!(st.dns.resolved_fallback, "9.9.9.9");
        assert!(!st.dns.bypassed);

        // No link: no fallback line either.
        let mut f = fixture();
        f.net.devices[0].state = 30;
        f.net.devices[0].active = None;
        f.net.primary_conn = None;
        f.resolver.links.clear();
        let st = build(&f);
        assert_eq!(st.dns.mode, "none");
        assert_eq!(st.dns.resolved_fallback, "");

        // Unconfigured: never bypassed, and the pending candidate reads unknown.
        let mut f = fixture();
        f.cfg.pihole = None;
        f.resolver.links[0].servers = vec![fx::pi()];
        f.detect_pending = true;
        let st = {
            let i = Inputs {
                net: Some(&f.net),
                profiles: &f.profiles,
                resolver: Some(&f.resolver),
                cfg: &f.cfg,
                pihole: None,
                detected: None,
                detect_pending: true,
                probes: &f.probes,
                upstream_ok: None,
                gateway_ms: None,
                api_state: None,
                resolved_downgrade: None,
                auto_deliberate: false,
                engaged_iface: None,
                fallback_in_use: None,
                api: &f.api,
                failover: &f.fo,
                scan: ScanView::default(),
                error: "",
                now_unix: 1_794_000_006.0,
                net_age_s: 0.0,
            };
            build_state(&i, 1, false)
        };
        assert_eq!(st.dns.mode, "unknown");
        assert!(!st.dns.bypassed);
    }

    #[test]
    fn health_degraded_and_unreachable() {
        let mut f = fixture();
        f.upstream_ok = Some(false);
        let st = build(&f);
        assert_eq!(st.pihole.health, "degraded");
        assert!(st.pihole.reachable);
        f.probes.push_back(ProbeRec { t: 1_794_000_010.0, ok: false, ms: None, blocked: false });
        f.probes.push_back(ProbeRec { t: 1_794_000_015.0, ok: false, ms: None, blocked: false });
        assert_eq!(build(&f).pihole.health, "unreachable");
        f.probes.clear();
        assert_eq!(build(&f).pihole.health, "unknown");
        assert_eq!(build(&f).pihole.canary_blocked, None);
    }

    #[test]
    fn canary_blocked_reflects_the_last_answered_probe() {
        let mut f = fixture();
        assert_eq!(build(&f).pihole.canary_blocked, Some(true));
        f.probes.push_back(ProbeRec { t: 1_794_000_010.0, ok: true, ms: Some(3.0), blocked: false });
        assert_eq!(build(&f).pihole.canary_blocked, Some(false), "paused");
        // A probe that got no answer says nothing new.
        f.probes.push_back(ProbeRec { t: 1_794_000_015.0, ok: false, ms: None, blocked: false });
        assert_eq!(build(&f).pihole.canary_blocked, Some(false));
    }

    #[test]
    fn address_and_admin_url_come_from_the_config_only() {
        let mut f = fixture();
        f.cfg.pihole = None;
        let st = {
            let i = Inputs {
                net: Some(&f.net),
                profiles: &f.profiles,
                resolver: Some(&f.resolver),
                cfg: &f.cfg,
                pihole: Some(fx::pi()), // a confirmed detection drives the model
                detected: Some(fx::pi()),
                detect_pending: false,
                probes: &f.probes,
                upstream_ok: None,
                gateway_ms: None,
                api_state: None,
                resolved_downgrade: None,
                auto_deliberate: false,
                engaged_iface: None,
                fallback_in_use: None,
                api: &ApiView::unconfigured(),
                failover: &f.fo,
                scan: ScanView::default(),
                error: "",
                now_unix: 1_794_000_006.0,
                net_age_s: 0.0,
            };
            build_state(&i, 1, false)
        };
        assert_eq!(st.pihole.address, "");
        assert_eq!(st.pihole.admin_url, "");
        assert_eq!(st.pihole.detected, "192.168.1.153");
        assert_eq!(st.dns.mode, "pihole", "the detection still drives the truth shown");
        assert!(!st.pihole.configured);
        // With a config the address is the configured one.
        let st = build(&fixture());
        assert_eq!(st.pihole.address, "192.168.1.153");
        assert_eq!(st.pihole.admin_url, "https://192.168.1.153/admin/");
        assert_eq!(st.pihole.detected, "");
    }

    #[test]
    fn own_queries_leave_today_and_the_history_buckets() {
        let mut f = fixture();
        f.api.history = vec![
            Bucket { t: 1_794_034_200, total: 0, blocked: 0 },
            Bucket { t: 1_794_034_800, total: 40, blocked: 6 },
            Bucket { t: 1_794_035_400, total: 12, blocked: 3 },
        ];
        // 10 of our queries (all blocked) landed in the last bucket, plus 2
        // plain ones; 4 in the middle one.
        let mut ledger = Ledger::default();
        ledger.add(1_794_035_450.0, 10, 10);
        ledger.add(1_794_035_460.0, 2, 0);
        ledger.add(1_794_034_850.0, 4, 0);
        f.api.own_today = ledger.sums(1_794_035_500.0);
        f.api.own_history = ledger.clone();
        let st = build(&f);
        let h = &st.pihole.history;
        assert_eq!((h[0].total, h[0].blocked), (0, 0));
        assert_eq!((h[1].total, h[1].blocked), (36, 6));
        assert_eq!((h[2].total, h[2].blocked), (0, 0), "saturates instead of going negative");
        assert_eq!(st.pihole.today.self_queries, 16);
        assert_eq!(st.pihole.today.total, 1204 - 16);
        assert_eq!(st.pihole.today.blocked, 164 - 10);
        let want = (164.0 - 10.0) / (1204.0 - 16.0) * 100.0;
        assert!((st.pihole.today.percent - want).abs() < 0.06);
    }

    #[test]
    fn history_span_counts_from_the_first_non_empty_bucket() {
        let b = |t: i64, n: u64| BucketOut { t, total: n, blocked: 0 };
        assert_eq!(history_span(&[]), 0);
        assert_eq!(history_span(&[b(0, 0), b(600, 0)]), 0, "all empty");
        // Zero-filled before Pi-hole started recording.
        assert_eq!(history_span(&[b(0, 0), b(600, 0), b(1200, 5), b(1800, 7)]), 1200);
        assert_eq!(history_span(&[b(1800, 7)]), 600);
        // Never more than a day.
        let long: Vec<BucketOut> = (0..200).map(|i| b(i * 600, 1)).collect();
        assert_eq!(history_span(&long), 86_400);
        // The zero-filled stretch in front is not counted.
        let mut f = fixture();
        f.api.history = vec![
            Bucket { t: 1_794_030_000, total: 0, blocked: 0 },
            Bucket { t: 1_794_034_800, total: 40, blocked: 6 },
            Bucket { t: 1_794_035_400, total: 12, blocked: 3 },
        ];
        assert_eq!(build(&f).pihole.history_span_s, 1_200);
    }

    #[test]
    fn gateway_latency_is_rounded_and_optional() {
        let mut f = fixture();
        f.gateway_ms = Some(12.345);
        assert_eq!(build(&f).link.gateway_ms, Some(12.3));
        f.gateway_ms = None;
        assert_eq!(to_json(&build(&f))["link"]["gatewayMs"], Value::Null);
    }

    #[test]
    fn closed_signature_ignores_probes_latency_and_bitrate_but_open_does_not() {
        let f = fixture();
        let a = build(&f);
        let mut b = a.clone();
        b.pihole.probes.push(ProbeOut { t: 1_794_000_020.0, ok: true, ms: Some(9.0), blocked: true });
        b.pihole.latency_ms = Some(9.0);
        b.link.bitrate_mbps = 433;
        assert_eq!(change_signature(&a, false), change_signature(&b, false), "closed: nothing worth a line");
        assert_ne!(change_signature(&a, true), change_signature(&b, true), "open: the graph needs them");
        // Everything else still counts while closed.
        let mut c = a.clone();
        c.pihole.reachable = false;
        assert_ne!(change_signature(&a, false), change_signature(&c, false));
        let mut d = a.clone();
        d.pihole.health = "degraded";
        assert_ne!(change_signature(&a, false), change_signature(&d, false));
        let mut e = a.clone();
        e.link.signal = 40;
        assert_ne!(change_signature(&a, false), change_signature(&e, false));
    }

    #[test]
    fn history_buckets_labelled_by_their_centre_are_matched() {
        // Live /api/history timestamps are bucket centres: t % 600 == 300.
        let mut f = fixture();
        let start = 1_794_034_200i64; // a multiple of 600
        assert_eq!(start % 600, 0);
        f.api.history = vec![
            Bucket { t: start + 300, total: 50, blocked: 10 },
            Bucket { t: start + 900, total: 40, blocked: 6 },
        ];
        let mut ledger = Ledger::default();
        ledger.add(start as f64 + 100.0, 12, 8); // inside the first bucket
        ledger.add(start as f64 + 700.0, 4, 0); // inside the second
        f.api.own_history = ledger.clone();
        f.api.own_today = ledger.sums(start as f64 + 800.0);
        let st = build(&f);
        let h = &st.pihole.history;
        assert_eq!((h[0].t, h[0].total, h[0].blocked), (start + 300, 38, 2), "own queries leave the right bucket");
        assert_eq!((h[1].t, h[1].total, h[1].blocked), (start + 900, 36, 6));
        // The same with start-labelled buckets (tests, older Pi-holes).
        f.api.history = vec![Bucket { t: start, total: 50, blocked: 10 }];
        let st = build(&f);
        assert_eq!((st.pihole.history[0].total, st.pihole.history[0].blocked), (38, 2));
    }

    #[test]
    fn failover_fallback_is_the_one_in_use_and_reason_is_shown() {
        let mut f = fixture();
        assert_eq!(build(&f).dns.failover.fallback, "router", "configured, nothing in use");
        f.fo.adopt(1_794_000_000, "Pi-hole not answering; this router is not the one the profile was pinned on, using quad9");
        f.fallback_in_use = Some(Fallback::Quad9);
        f.engaged_iface = Some("wlp7s0".into());
        f.resolver.links[0].servers = vec!["9.9.9.9".parse().unwrap()];
        let st = build(&f);
        assert!(st.dns.failover.active);
        assert_eq!(st.dns.failover.fallback, "quad9", "what is really running, not what was configured");
        assert!(st.dns.failover.reason.contains("quad9"));
        assert_eq!(st.dns.mode, "fallback");
        assert_eq!(st.dns.mode_source, "runtime-failover");
        // Unknown in-use value (an adopted failover we could not identify).
        f.fallback_in_use = None;
        assert_eq!(build(&f).dns.failover.fallback, "router");
    }

    #[test]
    fn mode_is_fallback_only_for_the_link_that_failed_over() {
        // Wi-Fi failed over; Ethernet came up and is now the primary link
        // with the Pi-hole pinned on it.
        let mut f = fixture();
        f.fo.adopt(1_794_000_000, "x");
        f.engaged_iface = Some("wlp7s0".into());
        f.fallback_in_use = Some(Fallback::Router);
        let mut eth = f.net.devices[0].clone();
        eth.kind = DeviceKind::Ethernet;
        eth.iface = "enp8s0".into();
        eth.ifindex = 2;
        eth.wifi = None;
        eth.active = Some(ActiveConn {
            path: "/org/freedesktop/NetworkManager/ActiveConnection/9".into(),
            uuid: U_ETH1.into(),
            id: "Wired connection 1".into(),
            state: 2,
        });
        f.net.primary_conn = eth.active.as_ref().map(|a| a.path.clone());
        f.net.devices.push(eth);
        f.profiles[1].dns = fx::dns_pinned();
        f.resolver.links.push(fx::link(2, "enp8s0", &[fx::PI], true));
        let st = build(&f);
        assert_eq!(st.link.kind, "ethernet");
        assert_eq!(st.dns.mode, "pihole", "the primary link is fine");
        assert_eq!(st.dns.mode_source, "profile");
        assert!(st.dns.failover.active, "the failover itself is still real");
        assert!(!st.dns.bypassed);
        // The failed-over link, still primary, is "fallback".
        let mut g = fixture();
        g.fo.adopt(1_794_000_000, "x");
        g.engaged_iface = Some("wlp7s0".into());
        assert_eq!(build(&g).dns.mode, "fallback");
        // And a failover whose link we cannot name is assumed to be here.
        g.engaged_iface = None;
        assert_eq!(build(&g).dns.mode, "fallback");
    }

    #[test]
    fn health_reason_explains_each_state() {
        let mut f = fixture();
        let st = build(&f);
        assert_eq!((st.pihole.health, st.pihole.health_reason.as_str()), ("ok", ""));
        f.upstream_ok = Some(false);
        let st = build(&f);
        assert_eq!(st.pihole.health, "degraded");
        assert!(st.pihole.health_reason.contains("upstream"));
        f.upstream_ok = Some(true);
        f.resolved_downgrade = Some("systemd-resolved dropped 192.168.1.153 to plain UDP (EDNS0 is failing)".into());
        let st = build(&f);
        assert_eq!(st.pihole.health, "degraded");
        assert!(st.pihole.health_reason.contains("EDNS0"));
        // A real outage outranks a downgrade; the web API's word is added.
        f.probes.push_back(ProbeRec { t: 1_794_000_010.0, ok: false, ms: None, blocked: false });
        f.probes.push_back(ProbeRec { t: 1_794_000_015.0, ok: false, ms: None, blocked: false });
        f.api_state = Some(ApiLiveness::Dead);
        let st = build(&f);
        assert_eq!(st.pihole.health, "unreachable");
        assert_eq!(st.pihole.health_reason, "no answer to DNS probes");
        f.api_state = Some(ApiLiveness::Alive);
        assert!(build(&f).pihole.health_reason.contains("web API still does"));
        f.probes.clear();
        let st = build(&f);
        assert_eq!((st.pihole.health, st.pihole.health_reason.as_str()), ("unknown", ""));
    }

    #[test]
    fn resolved_fallback_leak_shows_in_the_state() {
        let mut f = fixture();
        f.resolver.global_current = Some("9.9.9.9".parse().unwrap());
        let st = build(&f);
        let l = st.dns.leaks.iter().find(|l| l.kind == "resolved-fallback").expect("flagged");
        assert_eq!(l.where_, "systemd-resolved");
        assert!(l.detail.contains("9.9.9.9") && l.detail.contains("1.1.1.1"));
        assert!(!st.dns.bypassed, "it is a leak line, not the hero's bypass");
        f.resolver.global_current = None;
        assert!(build(&f).dns.leaks.iter().all(|l| l.kind != "resolved-fallback"));
    }

    #[test]
    fn channel_frequency_and_prefix_for_the_active_card() {
        let f = fixture();
        let st = build(&f);
        assert_eq!(st.link.frequency_mhz, Some(5180));
        assert_eq!(st.link.prefix, Some(24));
        let j = to_json(&st);
        assert_eq!(j["link"]["frequencyMhz"], 5180);
        assert_eq!(j["link"]["prefix"], 24);
        // The scan list carries each network's own channel.
        let by = |ssid: &str| st.networks.iter().find(|n| n.ssid == ssid).unwrap().frequency_mhz;
        assert_eq!((by("Redwood"), by("Cafe")), (5180, 2437));
        assert_eq!(j["networks"][0]["frequencyMhz"], 5180);

        // Ethernet: no channel, but the prefix is still there.
        let mut f = fixture();
        let mut eth = f.net.devices[0].clone();
        eth.kind = DeviceKind::Ethernet;
        eth.wifi = None;
        f.net.devices = vec![eth];
        let st = build(&f);
        assert_eq!((st.link.kind, st.link.frequency_mhz, st.link.prefix), ("ethernet", None, Some(24)));
        assert_eq!(to_json(&st)["link"]["frequencyMhz"], Value::Null);

        // No address yet: no prefix, whatever NM left lying about.
        let mut f = fixture();
        f.net.devices[0].ip4 = None;
        assert_eq!(build(&f).link.prefix, None);
        // Offline: both null.
        let mut f = fixture();
        f.net.devices[0].state = 30;
        f.net.devices[0].active = None;
        f.net.primary_conn = None;
        let st = build(&f);
        assert_eq!((st.link.frequency_mhz, st.link.prefix), (None, None));
    }
}

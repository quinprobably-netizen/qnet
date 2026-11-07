//! The state JSON (the contract with the QML panel) and the pure function
//! that builds it from what the watcher knows.

use std::collections::VecDeque;
use std::net::IpAddr;

use serde::Serialize;

use crate::config::Config;
use crate::dnsmodel::{self, classify, detect_leaks, detect_mode, LeakInput};
use crate::failover::Failover;
use crate::net::*;
use crate::pihole::{Blocking, BlockingState, Bucket, Summary};
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
}

impl ApiView {
    pub fn unconfigured() -> Self {
        Self {
            status: "unconfigured".into(),
            today: None,
            history: vec![],
            blocking: None,
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
    /// blocking the canary.
    pub pihole: Option<IpAddr>,
    pub probes: &'a VecDeque<ProbeRec>,
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
    pub ip4: String,
    pub gateway: String,
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
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct TodayOut {
    pub total: u64,
    pub blocked: u64,
    pub percent: f64,
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
    pub today: TodayOut,
    pub history: Vec<BucketOut>,
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

pub fn build_link(net: Option<&NetSnapshot>, profiles: &[Profile]) -> LinkOut {
    let mut out = LinkOut {
        kind: "none",
        device: String::new(),
        connection: String::new(),
        uuid: String::new(),
        ssid: String::new(),
        signal: 0,
        band: String::new(),
        bitrate_mbps: 0,
        ip4: String::new(),
        gateway: String::new(),
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
    out.gateway = dev.gateway.map(|a| a.to_string()).unwrap_or_default();
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
    let link = build_link(i.net, i.profiles);
    let networks = build_networks(i.net, i.profiles);

    let primary = i.net.and_then(|n| n.primary_device()).filter(|d| d.is_up());
    let gws = gateways(i.net);
    let primary_profile = primary
        .and_then(|d| d.active.as_ref())
        .and_then(|a| i.profiles.iter().find(|p| p.uuid == a.uuid));
    let primary_link = primary.and_then(|d| i.resolver.and_then(|r| r.link(d.ifindex)));
    let link_servers: Vec<IpAddr> = primary_link.map(|l| l.servers.clone()).unwrap_or_default();

    let mode = detect_mode(
        primary.is_some(),
        i.failover.active(),
        &link_servers,
        primary_profile,
        i.pihole,
    );

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
    let dns = DnsOut {
        mode: mode.as_str(),
        mode_source: if i.failover.active() { "runtime-failover" } else { "profile" },
        servers,
        leaks,
        failover: FailoverOut {
            enabled: configured && i.cfg.failover.enabled,
            fallback: i.cfg.failover.fallback.as_str(),
            active: i.failover.active(),
            since: i.failover.since(),
            reason: i.failover.reason().to_string(),
        },
        manual_override,
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
    let address = i.pihole.map(|a| a.to_string()).unwrap_or_default();
    let admin_url = if i.pihole.is_some() {
        match i.pihole {
            Some(IpAddr::V6(a)) => format!("https://[{a}]/admin/"),
            _ => format!("https://{address}/admin/"),
        }
    } else {
        String::new()
    };
    let today = i.api.today.unwrap_or(Summary { total: 0, blocked: 0, percent: 0.0 });
    let pihole = PiholeOut {
        configured,
        address,
        admin_url,
        reachable: i.pihole.is_some() && reachable(i.probes),
        latency_ms,
        blocking: blocking.as_str(),
        pause_remaining_s,
        api: if configured { i.api.status.clone() } else { "unconfigured".into() },
        today: TodayOut {
            total: today.total,
            blocked: today.blocked,
            percent: round1(today.percent),
        },
        history: i
            .api
            .history
            .iter()
            .map(|b| BucketOut { t: b.t, total: b.total, blocked: b.blocked })
            .collect(),
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

/// Fields that tick with the clock and must not, on their own, cause a new
/// line to be emitted.
pub fn change_signature(s: &State) -> String {
    let mut v = serde_json::to_value(s).unwrap_or(serde_json::Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.remove("seq");
        o.remove("heartbeat");
        if let Some(scan) = o.get_mut("scan").and_then(|s| s.as_object_mut()) {
            scan.remove("lastScanAgeS");
        }
        if let Some(p) = o.get_mut("pihole").and_then(|s| s.as_object_mut()) {
            p.remove("pauseRemainingS");
        }
    }
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FailoverCfg, PiholeCfg};
    use crate::dnsmodel::fixtures as fx;
    use crate::net::fake::{fake_cfg, FakeNet, U_ETH1, U_WIFI};
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
            },
            fo: Failover::new(),
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
                probes: &f.probes,
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
                "bitrateMbps": 866, "ip4": "192.168.1.242", "gateway": "192.168.1.1",
                "connectivity": "full", "portalUrl": ""
            },
            "radio": {"wifiEnabled": true, "hwEnabled": true},
            "networks": [
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/12", "ssid": "Redwood",
                 "hidden": false, "signal": 72, "security": "psk", "known": true,
                 "uuid": U_WIFI, "active": true, "band": "5 GHz"},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/41", "ssid": "Corp",
                 "hidden": false, "signal": 60, "security": "enterprise", "known": false,
                 "uuid": "", "active": false, "band": "5 GHz"},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/40", "ssid": "Cafe",
                 "hidden": false, "signal": 50, "security": "psk", "known": false,
                 "uuid": "", "active": false, "band": "2.4 GHz"},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/42", "ssid": "Lobby",
                 "hidden": false, "signal": 40, "security": "open", "known": false,
                 "uuid": "", "active": false, "band": "2.4 GHz"},
                {"id": "/org/freedesktop/NetworkManager/AccessPoint/43", "ssid": "",
                 "hidden": true, "signal": 30, "security": "psk", "known": false,
                 "uuid": "", "active": false, "band": "2.4 GHz"}
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
                "manualOverride": false
            },
            "pihole": {
                "configured": true, "address": "192.168.1.153",
                "adminUrl": "https://192.168.1.153/admin/", "reachable": true,
                "latencyMs": 3.0, "blocking": "enabled", "pauseRemainingS": 0, "api": "ok",
                "today": {"total": 1204, "blocked": 164, "percent": 13.6},
                "history": [{"t": 1794034800, "total": 40, "blocked": 6}],
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
                    probes: &VecDeque::new(),
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
        assert_eq!(change_signature(&a), change_signature(&b));
        let mut c = a.clone();
        c.dns.mode = "auto";
        assert_ne!(change_signature(&a), change_signature(&c));
        let mut d = a.clone();
        d.pihole.today.total += 1;
        assert_ne!(change_signature(&a), change_signature(&d));
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
}

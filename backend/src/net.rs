//! Network model shared by the watcher and the one-shot verbs, and the
//! `NetBackend` seam: the D-Bus implementation lives in `nm.rs`, tests use
//! the fake at the bottom of this file.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const NM_DEVICE_STATE_ACTIVATED: u32 = 100;
pub const NM_DEVICE_STATE_DISCONNECTED: u32 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    Unknown,
    None,
    Portal,
    Limited,
    Full,
}

impl Connectivity {
    pub fn from_nm(v: u32) -> Self {
        match v {
            1 => Connectivity::None,
            2 => Connectivity::Portal,
            3 => Connectivity::Limited,
            4 => Connectivity::Full,
            _ => Connectivity::Unknown,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Connectivity::Unknown => "unknown",
            Connectivity::None => "none",
            Connectivity::Portal => "portal",
            Connectivity::Limited => "limited",
            Connectivity::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Wifi,
    Ethernet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    Open,
    Wep,
    Psk,
    Sae,
    Owe,
    Enterprise,
}

impl Security {
    pub fn as_str(&self) -> &'static str {
        match self {
            Security::Open => "open",
            Security::Wep => "wep",
            Security::Psk => "psk",
            Security::Sae => "sae",
            Security::Owe => "owe",
            Security::Enterprise => "enterprise",
        }
    }
}

const AP_FLAG_PRIVACY: u32 = 0x1;
const SEC_KEY_PSK: u32 = 0x100;
const SEC_KEY_8021X: u32 = 0x200;
const SEC_KEY_SAE: u32 = 0x400;
const SEC_KEY_OWE: u32 = 0x800;
const SEC_KEY_OWE_TM: u32 = 0x1000;
const SEC_KEY_SUITE_B_192: u32 = 0x2000;

/// Classify an access point from NM's Flags / WpaFlags / RsnFlags.
pub fn classify_security(flags: u32, wpa: u32, rsn: u32) -> Security {
    let sec = wpa | rsn;
    if sec & SEC_KEY_PSK != 0 {
        // Also covers WPA2/WPA3 transition networks.
        Security::Psk
    } else if sec & SEC_KEY_SAE != 0 {
        Security::Sae
    } else if sec & (SEC_KEY_8021X | SEC_KEY_SUITE_B_192) != 0 {
        Security::Enterprise
    } else if sec & (SEC_KEY_OWE | SEC_KEY_OWE_TM) != 0 {
        Security::Owe
    } else if flags & AP_FLAG_PRIVACY != 0 || sec != 0 {
        Security::Wep
    } else {
        Security::Open
    }
}

pub fn band_of(freq_mhz: u32) -> &'static str {
    match freq_mhz {
        2400..=2500 => "2.4 GHz",
        4900..=5900 => "5 GHz",
        5925..=7125 => "6 GHz",
        _ => "",
    }
}

/// Display form of an SSID: lossy UTF-8 with control characters and bidi
/// controls removed. The second value is true for hidden networks (empty,
/// all-NUL, or nothing printable left).
pub fn display_ssid(bytes: &[u8]) -> (String, bool) {
    if bytes.is_empty() || bytes.iter().all(|b| *b == 0) {
        return (String::new(), true);
    }
    let s: String = String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| {
            !c.is_control()
                // Bidi embedding/override/isolate controls and zero-width marks
                // can disguise one network as another.
                && !matches!(*c,
                    '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
        })
        .collect();
    if s.trim().is_empty() {
        (String::new(), true)
    } else {
        (s, false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ap {
    pub path: String,
    pub ssid: Vec<u8>,
    pub strength: u8,
    pub freq: u32,
    pub flags: u32,
    pub wpa: u32,
    pub rsn: u32,
}

impl Ap {
    pub fn security(&self) -> Security {
        classify_security(self.flags, self.wpa, self.rsn)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveConn {
    pub path: String,
    pub uuid: String,
    pub id: String,
    pub state: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WifiDev {
    pub active_ap: Option<String>,
    pub bitrate_kbps: u32,
    /// Milliseconds since NM last completed a scan; None when never.
    pub last_scan_age_ms: Option<u64>,
    pub aps: Vec<Ap>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub path: String,
    pub iface: String,
    pub ifindex: u32,
    pub kind: DeviceKind,
    pub state: u32,
    pub active: Option<ActiveConn>,
    pub ip4: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub speed_mbps: u32,
    pub wifi: Option<WifiDev>,
}

impl Device {
    pub fn is_up(&self) -> bool {
        self.state == NM_DEVICE_STATE_ACTIVATED
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetSnapshot {
    pub wifi_enabled: bool,
    pub hw_enabled: bool,
    pub connectivity: Connectivity,
    pub check_uri: String,
    /// Object path of NM's PrimaryConnection (the active connection that
    /// owns the default route), if any.
    pub primary_conn: Option<String>,
    pub devices: Vec<Device>,
}

impl NetSnapshot {
    /// The device carrying the default route; falls back to any activated
    /// Wi-Fi or Ethernet device when NM has no primary connection yet.
    pub fn primary_device(&self) -> Option<&Device> {
        if let Some(pc) = &self.primary_conn {
            if let Some(d) = self
                .devices
                .iter()
                .find(|d| d.active.as_ref().is_some_and(|a| &a.path == pc))
            {
                return Some(d);
            }
        }
        let usable = |d: &&Device| {
            matches!(d.kind, DeviceKind::Wifi | DeviceKind::Ethernet)
                && d.active.is_some()
                && d.is_up()
        };
        self.devices
            .iter()
            .filter(usable)
            .find(|d| d.kind == DeviceKind::Wifi)
            .or_else(|| self.devices.iter().find(usable))
    }

    pub fn wifi_device(&self) -> Option<&Device> {
        let primary = self.primary_device().filter(|d| d.kind == DeviceKind::Wifi);
        primary.or_else(|| self.devices.iter().find(|d| d.kind == DeviceKind::Wifi))
    }

    pub fn device_by_iface(&self, iface: &str) -> Option<&Device> {
        self.devices.iter().find(|d| d.iface == iface)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    Wifi,
    Ethernet,
    Other,
}

/// The DNS-relevant slice of a connection profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    pub v4_method: String,
    pub v4_dns: Vec<Ipv4Addr>,
    pub v4_ignore_auto: bool,
    pub v6_method: String,
    pub v6_dns: Vec<Ipv6Addr>,
    pub v6_ignore_auto: bool,
}

impl DnsSettings {
    /// What `qnet dns pihole` writes.
    pub fn pinned_to(&self, pihole: IpAddr) -> DnsSettings {
        let mut s = self.clone();
        s.v4_dns = match pihole {
            IpAddr::V4(a) => vec![a],
            IpAddr::V6(_) => Vec::new(),
        };
        s.v4_ignore_auto = true;
        s.v6_dns = match pihole {
            IpAddr::V6(a) => vec![a],
            IpAddr::V4(_) => Vec::new(),
        };
        s.v6_ignore_auto = true;
        s
    }

    /// What `qnet dns auto` writes: no manual servers, DHCP/RA DNS accepted.
    pub fn automatic(&self) -> DnsSettings {
        let mut s = self.clone();
        s.v4_dns.clear();
        s.v4_ignore_auto = false;
        s.v6_dns.clear();
        s.v6_ignore_auto = false;
        s
    }

    pub fn manual_servers(&self) -> Vec<IpAddr> {
        self.v4_dns
            .iter()
            .map(|a| IpAddr::V4(*a))
            .chain(self.v6_dns.iter().map(|a| IpAddr::V6(*a)))
            .collect()
    }

    /// No manual servers and automatic DNS accepted on both families.
    pub fn is_automatic(&self) -> bool {
        self.v4_dns.is_empty()
            && self.v6_dns.is_empty()
            && !self.v4_ignore_auto
            && !self.v6_ignore_auto
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub path: String,
    pub uuid: String,
    pub id: String,
    pub kind: ProfileKind,
    pub ssid: Option<Vec<u8>>,
    pub autoconnect: bool,
    pub timestamp: u64,
    pub dns: DnsSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDns {
    pub ifindex: u32,
    pub name: String,
    pub servers: Vec<IpAddr>,
    pub current: Option<IpAddr>,
    pub default_route: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolverSnapshot {
    pub links: Vec<LinkDns>,
    /// Servers from resolved.conf (`DNS=`), ifindex 0.
    pub global: Vec<IpAddr>,
    /// resolved's compiled-in `FallbackDNS=`. Used only when nothing else
    /// is configured, so never a leak by itself.
    pub fallback: Vec<IpAddr>,
}

impl ResolverSnapshot {
    pub fn link(&self, ifindex: u32) -> Option<&LinkDns> {
        self.links.iter().find(|l| l.ifindex == ifindex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The named object does not exist.
    NotFound(String),
    /// Refused by policy (polkit) or by NM.
    Denied(String),
    /// A request that cannot be honoured (no such device, bad input).
    Invalid(String),
    /// Activation failed; `auth` is true when it looks like a bad passphrase.
    Activation { auth: bool, detail: String },
    Timeout(String),
    /// D-Bus or NM misbehaved.
    Bus(String),
}

impl NetError {
    pub fn code(&self) -> &'static str {
        match self {
            NetError::NotFound(_) => "notfound",
            NetError::Denied(_) => "denied",
            NetError::Invalid(_) => "invalid",
            NetError::Activation { auth: true, .. } => "auth",
            NetError::Activation { .. } => "activation",
            NetError::Timeout(_) => "timeout",
            NetError::Bus(_) => "dbus",
        }
    }
    pub fn detail(&self) -> String {
        match self {
            NetError::NotFound(s)
            | NetError::Denied(s)
            | NetError::Invalid(s)
            | NetError::Timeout(s)
            | NetError::Bus(s) => s.clone(),
            NetError::Activation { detail, .. } => detail.clone(),
        }
    }
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail())
    }
}

impl std::error::Error for NetError {}

pub type NetResult<T> = Result<T, NetError>;

/// Everything qnet needs from NetworkManager and systemd-resolved.
pub trait NetBackend: Send {
    /// Read devices, active connections, IP config and (optionally) the
    /// access-point lists. `with_aps = false` skips the per-AP reads.
    fn snapshot(&self, with_aps: bool) -> NetResult<NetSnapshot>;
    /// All saved profiles (no secrets).
    fn profiles(&self) -> NetResult<Vec<Profile>>;
    /// resolved's view: global servers, fallback, and for each link in
    /// `ifindexes` plus every link that has servers, servers/current/route.
    fn resolver(&self, ifindexes: &[(u32, String)]) -> NetResult<ResolverSnapshot>;
    /// DNS settings the device is running right now (applied connection).
    fn applied_dns(&self, iface: &str) -> NetResult<DnsSettings>;
    /// Write DNS settings into a saved profile, keeping its secrets.
    fn set_profile_dns(&self, uuid: &str, dns: &DnsSettings) -> NetResult<()>;
    /// `Device.Reapply` of the saved profile.
    fn reapply_saved(&self, iface: &str) -> NetResult<()>;
    /// `Device.Reapply` with the applied connection's IPv4 DNS replaced by
    /// `servers` (runtime only; the saved profile is not touched).
    fn reapply_runtime_dns(&self, iface: &str, servers: &[Ipv4Addr]) -> NetResult<()>;
    fn request_scan(&self, iface: &str) -> NetResult<()>;
    fn set_wifi_enabled(&self, on: bool) -> NetResult<()>;
    fn disconnect(&self, iface: &str) -> NetResult<()>;
    fn forget(&self, uuid: &str) -> NetResult<()>;
    /// Activate a saved profile on `iface`, optionally against one AP.
    /// With `new_passphrase` the profile's PSK is replaced first.
    fn activate_known(
        &self,
        uuid: &str,
        iface: &str,
        ap_path: &str,
        new_passphrase: Option<&str>,
    ) -> NetResult<()>;
    /// Create a profile for `ap` and activate it. On failure the new
    /// profile is deleted again.
    fn connect_new(
        &self,
        iface: &str,
        ap: &Ap,
        security: &Security,
        passphrase: Option<&str>,
    ) -> NetResult<()>;
    /// `ResolveHostname` through systemd-resolved (A records).
    fn resolve_hostname(&self, name: &str) -> NetResult<Vec<IpAddr>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssid_plain_and_hidden() {
        assert_eq!(display_ssid(b"Redwood"), ("Redwood".into(), false));
        assert_eq!(display_ssid(b""), (String::new(), true));
        assert_eq!(display_ssid(&[0, 0, 0, 0]), (String::new(), true));
        assert_eq!(display_ssid(b"\x01\x02\x7f"), (String::new(), true));
        assert_eq!(display_ssid(b"   "), (String::new(), true));
    }

    #[test]
    fn ssid_strips_control_characters() {
        assert_eq!(display_ssid(b"Ca\x00fe\n\r\t\x1b[31m"), ("Cafe[31m".into(), false));
        // C1 controls (U+0080..U+009F) as UTF-8.
        assert_eq!(display_ssid("a\u{85}b\u{9b}c".as_bytes()), ("abc".into(), false));
    }

    #[test]
    fn ssid_strips_bidi_and_zero_width() {
        let evil = "free\u{202E}ofni\u{202C}wifi\u{200B}!\u{FEFF}";
        assert_eq!(display_ssid(evil.as_bytes()), ("freeofniwifi!".into(), false));
        assert_eq!(display_ssid("\u{2066}\u{2069}".as_bytes()), (String::new(), true));
    }

    #[test]
    fn ssid_invalid_utf8_is_lossy_not_fatal() {
        let (s, hidden) = display_ssid(&[b'a', 0xFF, 0xFE, b'b', 0xC3]);
        assert!(!hidden);
        assert!(s.starts_with('a') && s.contains('b'));
        assert!(s.contains('\u{FFFD}'));
        // Valid multi-byte names survive intact.
        assert_eq!(display_ssid("Café ☕".as_bytes()), ("Café ☕".into(), false));
    }

    #[test]
    fn security_classification() {
        assert_eq!(classify_security(0, 0, 0), Security::Open);
        assert_eq!(classify_security(1, 0, 0), Security::Wep);
        assert_eq!(classify_security(1, 0x100, 0), Security::Psk);
        assert_eq!(classify_security(1, 0, 0x100), Security::Psk);
        assert_eq!(classify_security(1, 0, 0x400), Security::Sae);
        // WPA2/WPA3 transition: PSK and SAE both set -> connectable as PSK.
        assert_eq!(classify_security(1, 0, 0x500), Security::Psk);
        assert_eq!(classify_security(1, 0, 0x200), Security::Enterprise);
        assert_eq!(classify_security(1, 0x200, 0x200), Security::Enterprise);
        assert_eq!(classify_security(1, 0, 0x2000), Security::Enterprise);
        assert_eq!(classify_security(1, 0, 0x800), Security::Owe);
        assert_eq!(classify_security(0, 0, 0x1000), Security::Owe);
        // Cipher bits alone mean "something is set", not open.
        assert_eq!(classify_security(0, 0x8, 0), Security::Wep);
    }

    #[test]
    fn bands() {
        assert_eq!(band_of(2412), "2.4 GHz");
        assert_eq!(band_of(5180), "5 GHz");
        assert_eq!(band_of(5985), "6 GHz");
        assert_eq!(band_of(0), "");
    }

    #[test]
    fn dns_settings_helpers() {
        let base = DnsSettings {
            v4_method: "auto".into(),
            v4_dns: vec![],
            v4_ignore_auto: false,
            v6_method: "auto".into(),
            v6_dns: vec!["2001:db8::1".parse().unwrap()],
            v6_ignore_auto: false,
        };
        let pi: IpAddr = "192.168.1.153".parse().unwrap();
        let pinned = base.pinned_to(pi);
        assert_eq!(pinned.v4_dns, vec!["192.168.1.153".parse::<Ipv4Addr>().unwrap()]);
        assert!(pinned.v4_ignore_auto && pinned.v6_ignore_auto);
        assert!(pinned.v6_dns.is_empty());
        assert!(pinned.automatic().is_automatic());
        assert!(!base.is_automatic());
        assert_eq!(base.manual_servers(), vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }
}

/// A scripted `NetBackend` for tests: holds a snapshot, saved profiles and
/// what "resolved" would show, and records every call.
#[cfg(test)]
pub mod fake {
    use super::*;
    use crate::dnsmodel::fixtures as fx;
    use std::sync::Mutex;

    pub use fx::{U_ETH1, U_WIFI};

    pub fn fake_cfg() -> crate::config::Config {
        crate::config::Config {
            pihole: Some(crate::config::PiholeCfg {
                address: fx::pi(),
                tls_sha256: [1; 32],
                canary: "doubleclick.net".into(),
            }),
            failover: crate::config::FailoverCfg::default(),
        }
    }

    pub struct Inner {
        pub snap: NetSnapshot,
        pub profiles: Vec<Profile>,
        pub applied: DnsSettings,
        pub link_servers: Vec<IpAddr>,
        pub dhcp: Vec<IpAddr>,
        pub calls: Vec<String>,
        pub writes: usize,
        pub resolve_error: bool,
        pub activation_error: Option<NetError>,
        pub reapply_error: Option<NetError>,
        pub snapshot_error: bool,
    }

    pub struct FakeNet {
        pub inner: Mutex<Inner>,
    }

    fn ap(n: u32, ssid: &str, strength: u8, freq: u32, flags: u32, wpa: u32, rsn: u32) -> Ap {
        Ap {
            path: format!("/org/freedesktop/NetworkManager/AccessPoint/{n}"),
            ssid: ssid.as_bytes().to_vec(),
            strength,
            freq,
            flags,
            wpa,
            rsn,
        }
    }

    fn servers_of(applied: &DnsSettings, dhcp: &[IpAddr]) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = applied.v4_dns.iter().map(|a| IpAddr::V4(*a)).collect();
        out.extend(applied.v6_dns.iter().map(|a| IpAddr::V6(*a)));
        if !applied.v4_ignore_auto {
            out.extend(dhcp.iter().copied());
        }
        out
    }

    impl FakeNet {
        /// The owner's machine: Wi-Fi on Redwood pinned to the Pi-hole, two
        /// inactive automatic wired profiles.
        pub fn live_machine() -> Self {
            let mut dev = fx::wifi_device(true);
            if let Some(w) = dev.wifi.as_mut() {
                w.aps = vec![
                    ap(12, "Redwood", 72, 5180, 3, 0, 0x188),
                    ap(40, "Cafe", 50, 2437, 3, 0, 0x188),
                    ap(41, "Corp", 60, 5180, 3, 0, 0x288),
                    ap(42, "Lobby", 40, 2437, 0, 0, 0),
                    ap(43, "", 30, 2437, 3, 0, 0x188),
                ];
            }
            let snap = fx::snapshot(vec![dev]);
            let profiles = vec![fx::redwood(), fx::eth1(), fx::eth2()];
            let dhcp = vec![fx::gw()];
            let applied = profiles[0].dns.clone();
            let link_servers = servers_of(&applied, &dhcp);
            FakeNet {
                inner: Mutex::new(Inner {
                    snap,
                    profiles,
                    applied,
                    link_servers,
                    dhcp,
                    calls: vec![],
                    writes: 0,
                    resolve_error: false,
                    activation_error: None,
                    reapply_error: None,
                    snapshot_error: false,
                }),
            }
        }

        pub fn calls(&self) -> Vec<String> {
            self.inner.lock().unwrap().calls.clone()
        }
        pub fn writes(&self) -> usize {
            self.inner.lock().unwrap().writes
        }
        pub fn profile(&self, uuid: &str) -> Profile {
            self.inner
                .lock()
                .unwrap()
                .profiles
                .iter()
                .find(|p| p.uuid == uuid)
                .cloned()
                .expect("profile")
        }
        pub fn set_profile_dns_direct(&self, uuid: &str, dns: DnsSettings) {
            let mut g = self.inner.lock().unwrap();
            g.profiles.iter_mut().find(|p| p.uuid == uuid).unwrap().dns = dns;
        }
        /// Make the running link match the active profile (as after a reapply).
        pub fn apply_saved_to_link(&self) {
            let mut g = self.inner.lock().unwrap();
            let uuid = g.snap.devices[0].active.as_ref().map(|a| a.uuid.clone());
            if let Some(u) = uuid {
                g.applied = g.profiles.iter().find(|p| p.uuid == u).unwrap().dns.clone();
                g.link_servers = servers_of(&g.applied, &g.dhcp);
            }
        }
        pub fn set_link_down(&self) {
            let mut g = self.inner.lock().unwrap();
            g.snap.devices[0].state = 30;
            g.snap.devices[0].active = None;
            g.snap.primary_conn = None;
        }
        pub fn set_resolve_error(&self) {
            self.inner.lock().unwrap().resolve_error = true;
        }
        pub fn fail_next_activation(&self, e: NetError) {
            self.inner.lock().unwrap().activation_error = Some(e);
        }
        pub fn fail_reapply(&self, e: Option<NetError>) {
            self.inner.lock().unwrap().reapply_error = e;
        }
        pub fn set_last_scan_age_ms(&self, v: Option<u64>) {
            let mut g = self.inner.lock().unwrap();
            g.snap.devices[0].wifi.as_mut().unwrap().last_scan_age_ms = v;
        }
        pub fn set_hw_enabled(&self, on: bool) {
            self.inner.lock().unwrap().snap.hw_enabled = on;
        }
        pub fn set_gateway(&self, gw: Option<std::net::Ipv4Addr>) {
            self.inner.lock().unwrap().snap.devices[0].gateway = gw;
        }
        pub fn link_servers(&self) -> Vec<IpAddr> {
            self.inner.lock().unwrap().link_servers.clone()
        }
        pub fn set_snapshot_error(&self, on: bool) {
            self.inner.lock().unwrap().snapshot_error = on;
        }
    }

    impl NetBackend for FakeNet {
        fn snapshot(&self, with_aps: bool) -> NetResult<NetSnapshot> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("snapshot aps={with_aps}"));
            if g.snapshot_error {
                return Err(NetError::Bus("fake: NetworkManager is gone".into()));
            }
            Ok(g.snap.clone())
        }
        fn profiles(&self) -> NetResult<Vec<Profile>> {
            Ok(self.inner.lock().unwrap().profiles.clone())
        }
        fn resolver(&self, _w: &[(u32, String)]) -> NetResult<ResolverSnapshot> {
            let g = self.inner.lock().unwrap();
            let up = g.snap.devices[0].is_up();
            let links = if up && !g.link_servers.is_empty() {
                vec![LinkDns {
                    ifindex: g.snap.devices[0].ifindex,
                    name: g.snap.devices[0].iface.clone(),
                    servers: g.link_servers.clone(),
                    current: g.link_servers.first().copied(),
                    default_route: true,
                }]
            } else {
                vec![]
            };
            Ok(ResolverSnapshot {
                links,
                global: vec![],
                fallback: vec!["9.9.9.9".parse().unwrap(), "1.1.1.1".parse().unwrap()],
            })
        }
        fn applied_dns(&self, iface: &str) -> NetResult<DnsSettings> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("applied_dns {iface}"));
            Ok(g.applied.clone())
        }
        fn set_profile_dns(&self, uuid: &str, dns: &DnsSettings) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("set_profile_dns {uuid}"));
            g.writes += 1;
            match g.profiles.iter_mut().find(|p| p.uuid == uuid) {
                Some(p) => {
                    p.dns = dns.clone();
                    Ok(())
                }
                None => Err(NetError::NotFound("no such profile".into())),
            }
        }
        fn reapply_saved(&self, iface: &str) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("reapply_saved {iface}"));
            g.writes += 1;
            if let Some(e) = g.reapply_error.clone() {
                return Err(e);
            }
            let uuid = g.snap.devices[0].active.as_ref().map(|a| a.uuid.clone());
            if let Some(u) = uuid {
                g.applied = g.profiles.iter().find(|p| p.uuid == u).unwrap().dns.clone();
                g.link_servers = servers_of(&g.applied, &g.dhcp);
            }
            Ok(())
        }
        fn reapply_runtime_dns(&self, iface: &str, servers: &[std::net::Ipv4Addr]) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!(
                "reapply_runtime_dns {iface} {}",
                servers.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(",")
            ));
            g.writes += 1;
            if let Some(e) = g.reapply_error.clone() {
                return Err(e);
            }
            g.applied.v4_dns = servers.to_vec();
            g.applied.v4_ignore_auto = true;
            g.applied.v6_ignore_auto = true;
            g.applied.v6_dns.clear();
            g.link_servers = servers_of(&g.applied, &g.dhcp);
            Ok(())
        }
        fn request_scan(&self, iface: &str) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("request_scan {iface}"));
            g.writes += 1;
            Ok(())
        }
        fn set_wifi_enabled(&self, on: bool) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("set_wifi_enabled {on}"));
            g.writes += 1;
            g.snap.wifi_enabled = on;
            Ok(())
        }
        fn disconnect(&self, iface: &str) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("disconnect {iface}"));
            g.writes += 1;
            Ok(())
        }
        fn forget(&self, uuid: &str) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("forget {uuid}"));
            g.writes += 1;
            g.profiles.retain(|p| p.uuid != uuid);
            Ok(())
        }
        fn activate_known(
            &self,
            uuid: &str,
            iface: &str,
            ap_path: &str,
            new_passphrase: Option<&str>,
        ) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!(
                "activate_known {uuid} {iface} {ap_path} pass={}",
                if new_passphrase.is_some() { "yes" } else { "no" }
            ));
            g.writes += 1;
            match g.activation_error.take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        fn connect_new(
            &self,
            iface: &str,
            ap: &Ap,
            security: &Security,
            passphrase: Option<&str>,
        ) -> NetResult<()> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!(
                "connect_new {iface} {} {} pass={}",
                display_ssid(&ap.ssid).0,
                security.as_str(),
                if passphrase.is_some() { "yes" } else { "no" }
            ));
            g.writes += 1;
            match g.activation_error.take() {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
        fn resolve_hostname(&self, name: &str) -> NetResult<Vec<IpAddr>> {
            let mut g = self.inner.lock().unwrap();
            g.calls.push(format!("resolve {name}"));
            if g.resolve_error {
                return Err(NetError::Timeout("fake: no answer".into()));
            }
            // A blocking resolver answers 0.0.0.0; anyone else the real thing.
            let pihole_only = !g.link_servers.is_empty() && g.link_servers.iter().all(|s| *s == fx::pi());
            Ok(vec![if pihole_only {
                "0.0.0.0".parse().unwrap()
            } else {
                "142.250.74.14".parse().unwrap()
            }])
        }
    }
}

#[cfg(test)]
impl<T: NetBackend + Sync> NetBackend for std::sync::Arc<T> {
    fn snapshot(&self, with_aps: bool) -> NetResult<NetSnapshot> {
        (**self).snapshot(with_aps)
    }
    fn profiles(&self) -> NetResult<Vec<Profile>> {
        (**self).profiles()
    }
    fn resolver(&self, w: &[(u32, String)]) -> NetResult<ResolverSnapshot> {
        (**self).resolver(w)
    }
    fn applied_dns(&self, iface: &str) -> NetResult<DnsSettings> {
        (**self).applied_dns(iface)
    }
    fn set_profile_dns(&self, uuid: &str, dns: &DnsSettings) -> NetResult<()> {
        (**self).set_profile_dns(uuid, dns)
    }
    fn reapply_saved(&self, iface: &str) -> NetResult<()> {
        (**self).reapply_saved(iface)
    }
    fn reapply_runtime_dns(&self, iface: &str, servers: &[Ipv4Addr]) -> NetResult<()> {
        (**self).reapply_runtime_dns(iface, servers)
    }
    fn request_scan(&self, iface: &str) -> NetResult<()> {
        (**self).request_scan(iface)
    }
    fn set_wifi_enabled(&self, on: bool) -> NetResult<()> {
        (**self).set_wifi_enabled(on)
    }
    fn disconnect(&self, iface: &str) -> NetResult<()> {
        (**self).disconnect(iface)
    }
    fn forget(&self, uuid: &str) -> NetResult<()> {
        (**self).forget(uuid)
    }
    fn activate_known(&self, uuid: &str, iface: &str, ap: &str, p: Option<&str>) -> NetResult<()> {
        (**self).activate_known(uuid, iface, ap, p)
    }
    fn connect_new(&self, iface: &str, ap: &Ap, sec: &Security, p: Option<&str>) -> NetResult<()> {
        (**self).connect_new(iface, ap, sec, p)
    }
    fn resolve_hostname(&self, name: &str) -> NetResult<Vec<IpAddr>> {
        (**self).resolve_hostname(name)
    }
}

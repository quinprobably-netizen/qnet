//! What the DNS situation actually is: resolver roles, mode, leaks and the
//! "did someone else set these servers" test. Pure functions over the
//! snapshots from `net.rs`; no I/O.

use std::net::{IpAddr, Ipv4Addr};

use crate::net::{
    DeviceKind, DnsSettings, NetSnapshot, Profile, ProfileKind, ResolverSnapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Pihole,
    Router,
    Public,
    Other,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Pihole => "pihole",
            Role::Router => "router",
            Role::Public => "public",
            Role::Other => "other",
        }
    }
}

/// Addresses that are not on the public internet.
pub fn is_local_addr(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT, Tailscale
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            a.is_loopback()
                || (s[0] & 0xFFC0) == 0xFE80 // link-local
                || (s[0] & 0xFE00) == 0xFC00 // unique local
        }
    }
}

fn is_v6_link_local(addr: IpAddr) -> bool {
    matches!(addr, IpAddr::V6(a) if (a.segments()[0] & 0xFFC0) == 0xFE80)
}

/// Classify one resolver address.
///
/// `gateways` are the default gateways of the active links. An IPv6
/// link-local server is the router advertising itself (RDNSS), so it counts
/// as the router too.
pub fn classify(addr: IpAddr, pihole: Option<IpAddr>, gateways: &[IpAddr]) -> Role {
    if Some(addr) == pihole {
        Role::Pihole
    } else if gateways.contains(&addr) || is_v6_link_local(addr) {
        Role::Router
    } else if !is_local_addr(addr) {
        Role::Public
    } else {
        Role::Other
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Pihole,
    Fallback,
    Auto,
    Custom,
    /// No link, or the link has no DNS servers (resolved would use its
    /// compiled fallback list): no tile should light.
    None,
    /// Not decidable yet: a Pi-hole candidate is still being checked.
    Unknown,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Pihole => "pihole",
            Mode::Fallback => "fallback",
            Mode::Auto => "auto",
            Mode::Custom => "custom",
            Mode::None => "none",
            Mode::Unknown => "unknown",
        }
    }
}

/// Mode from resolver truth.
///
/// * `servers` are the servers resolved holds for the primary link;
/// * `profile` is the primary link's saved profile, used only to tell an
///   automatic setup (DHCP/RA supplied) from a manually configured one.
pub fn detect_mode(
    link_present: bool,
    failover_active: bool,
    servers: &[IpAddr],
    profile: Option<&Profile>,
    pihole: Option<IpAddr>,
) -> Mode {
    if !link_present {
        return Mode::None;
    }
    if failover_active {
        return Mode::Fallback;
    }
    if servers.is_empty() {
        return Mode::None;
    }
    // The Pi-hole is among the servers: the mode is Pi-hole, and whether
    // anything else can still answer is `is_bypassed`'s business.
    if let Some(p) = pihole {
        if servers.contains(&p) {
            return Mode::Pihole;
        }
    }
    match profile {
        Some(p) if p.dns.is_automatic() => Mode::Auto,
        _ => Mode::Custom,
    }
}

/// With a Pi-hole configured: can queries on the primary link skip it?
///
/// * mode Pi-hole, but other servers are in use alongside it, or the
///   profile is not pinned (so DHCP or router advertisements may add some);
/// * mode custom: the Pi-hole is not among the servers at all;
/// * mode Auto, unless `qnet dns auto` recorded that choice for this very
///   profile (`auto_deliberate`): an Ethernet cable that came up with
///   automatic DNS is a bypass nobody asked for.
///
/// A failover and "no DNS" are states of their own, not bypasses.
pub fn is_bypassed(
    mode: Mode,
    servers: &[IpAddr],
    profile: Option<&Profile>,
    pihole: IpAddr,
    auto_deliberate: bool,
) -> bool {
    match mode {
        Mode::Pihole => {
            servers.iter().any(|s| *s != pihole) || profile.is_none_or(|p| !profile_pinned(&p.dns, pihole))
        }
        Mode::Custom => true,
        Mode::Auto => !auto_deliberate,
        Mode::Fallback | Mode::None | Mode::Unknown => false,
    }
}

/// True when the profile carries manual servers other than the Pi-hole,
/// i.e. something qnet would overwrite and did not write itself.
pub fn manual_override(dns: &DnsSettings, pihole: IpAddr) -> bool {
    dns.manual_servers().iter().any(|s| *s != pihole)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakKind {
    Link,
    Profile,
    Ipv6Ra,
    /// resolved's compiled-in FallbackDNS is being used next to the links'
    /// own servers.
    ResolvedFallback,
}

impl LeakKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LeakKind::Link => "link",
            LeakKind::Profile => "profile",
            LeakKind::Ipv6Ra => "ipv6-ra",
            LeakKind::ResolvedFallback => "resolved-fallback",
        }
    }
}

fn v4_supplies_dns(method: &str) -> bool {
    matches!(method, "auto" | "manual")
}

fn v6_auto(method: &str) -> bool {
    matches!(method, "auto" | "dhcp")
}

/// Why a saved profile would not send every query to the Pi-hole, if it
/// would not. `None` means the profile is pinned.
pub fn profile_leak(dns: &DnsSettings, pihole: IpAddr) -> Option<(LeakKind, String)> {
    if v4_supplies_dns(&dns.v4_method) {
        if dns.v4_method == "auto" && !dns.v4_ignore_auto {
            return Some((LeakKind::Profile, "uses router DNS (automatic)".into()));
        }
        let others: Vec<String> = dns
            .v4_dns
            .iter()
            .filter(|a| IpAddr::V4(**a) != pihole)
            .map(|a| a.to_string())
            .collect();
        if !others.is_empty() {
            return Some((LeakKind::Profile, format!("uses {}", others.join(", "))));
        }
        let has_pihole = dns.v4_dns.iter().any(|a| IpAddr::V4(*a) == pihole);
        if !has_pihole && pihole.is_ipv4() {
            return Some((LeakKind::Profile, "has no Pi-hole DNS server set".into()));
        }
    }
    if v6_auto(&dns.v6_method) && !dns.v6_ignore_auto {
        return Some((
            LeakKind::Ipv6Ra,
            "IPv6 router advertisements can supply DNS".into(),
        ));
    }
    let others6: Vec<String> = dns
        .v6_dns
        .iter()
        .filter(|a| IpAddr::V6(**a) != pihole)
        .map(|a| a.to_string())
        .collect();
    if !others6.is_empty() {
        return Some((LeakKind::Profile, format!("uses {}", others6.join(", "))));
    }
    None
}

pub fn profile_pinned(dns: &DnsSettings, pihole: IpAddr) -> bool {
    profile_leak(dns, pihole).is_none()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    pub kind: LeakKind,
    pub where_: String,
    pub uuid: String,
    pub detail: String,
}

pub struct LeakInput<'a> {
    pub net: &'a NetSnapshot,
    pub profiles: &'a [Profile],
    pub resolver: Option<&'a ResolverSnapshot>,
    pub pihole: IpAddr,
    pub gateways: &'a [IpAddr],
    pub mode: Mode,
    pub primary_iface: Option<&'a str>,
    /// The primary profile's Automatic DNS was chosen with `qnet dns auto`.
    pub auto_deliberate: bool,
    /// The link a runtime failover was applied to; its servers are the
    /// fallback on purpose.
    pub engaged_iface: Option<&'a str>,
}

fn describe(servers: &[IpAddr], pihole: IpAddr, gateways: &[IpAddr]) -> String {
    servers
        .iter()
        .map(|s| {
            let role = classify(*s, Some(pihole), gateways);
            match role {
                Role::Router => format!("{s} (router)"),
                Role::Public => format!("{s} (public)"),
                _ => s.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Everything that sends or would send queries around the Pi-hole.
///
/// resolved's compiled-in FallbackDNS is deliberately absent: it is used only
/// when no link has servers, which shows up as mode `None` instead.
pub fn detect_leaks(inp: &LeakInput<'_>) -> Vec<Leak> {
    let mut out = Vec::new();
    let mut active_uuids: Vec<&str> = Vec::new();

    // 1. Links resolved is using right now.
    for dev in inp.net.devices.iter() {
        let Some(active) = dev.active.as_ref() else { continue };
        active_uuids.push(&active.uuid);
        if !matches!(dev.kind, DeviceKind::Wifi | DeviceKind::Ethernet) {
            continue;
        }
        let is_primary = inp.primary_iface == Some(dev.iface.as_str());
        if inp.engaged_iface == Some(dev.iface.as_str()) {
            continue;
        }
        // The user's chosen Automatic (and Fallback/None) state on the primary
        // link is not a leak; it is the current mode. An Automatic nobody
        // chose is.
        let deliberate_mode = match inp.mode {
            Mode::Auto => inp.auto_deliberate,
            Mode::Fallback | Mode::None | Mode::Unknown => true,
            Mode::Pihole | Mode::Custom => false,
        };
        if is_primary && deliberate_mode {
            continue;
        }
        let Some(link) = inp
            .resolver
            .and_then(|r| r.links.iter().find(|l| l.ifindex == dev.ifindex))
        else {
            continue;
        };
        if !link.default_route && !is_primary {
            continue;
        }
        let others: Vec<IpAddr> = link
            .servers
            .iter()
            .copied()
            .filter(|s| *s != inp.pihole)
            .collect();
        if others.is_empty() {
            continue;
        }
        let profile = inp.profiles.iter().find(|p| p.uuid == active.uuid);
        let all_v6 = others.iter().all(|s| s.is_ipv6());
        let ra = all_v6 && profile.is_some_and(|p| v6_auto(&p.dns.v6_method) && !p.dns.v6_ignore_auto);
        let has_pihole = link.servers.contains(&inp.pihole);
        let desc = describe(&others, inp.pihole, inp.gateways);
        let detail = match (ra, has_pihole) {
            (true, _) => format!("IPv6 router advertisement adds {desc}"),
            (false, true) => format!("also uses {desc}"),
            (false, false) => format!("uses {desc}"),
        };
        out.push(Leak {
            kind: if ra { LeakKind::Ipv6Ra } else { LeakKind::Link },
            where_: active.id.clone(),
            uuid: active.uuid.clone(),
            detail,
        });
    }

    // Links resolved knows that NM does not manage (VPN, containers...).
    if let Some(r) = inp.resolver {
        for link in &r.links {
            let known = inp.net.devices.iter().any(|d| d.ifindex == link.ifindex);
            if known || !link.default_route {
                continue;
            }
            let others: Vec<IpAddr> = link
                .servers
                .iter()
                .copied()
                .filter(|s| *s != inp.pihole)
                .collect();
            if !others.is_empty() {
                out.push(Leak {
                    kind: LeakKind::Link,
                    where_: link.name.clone(),
                    uuid: String::new(),
                    detail: format!("uses {}", describe(&others, inp.pihole, inp.gateways)),
                });
            }
        }
        // 1b. resolved's compiled-in FallbackDNS, once it has actually been
        // picked while links have servers of their own.
        if let Some(cur) = r.global_current {
            let links_have_servers = r.links.iter().any(|l| !l.servers.is_empty());
            if r.global.is_empty() && links_have_servers && r.fallback.contains(&cur) {
                let mut names: Vec<String> = Vec::new();
                for s in &r.fallback {
                    let s = s.to_string();
                    if !names.contains(&s) {
                        names.push(s);
                    }
                }
                out.push(Leak {
                    kind: LeakKind::ResolvedFallback,
                    where_: "systemd-resolved".into(),
                    uuid: String::new(),
                    detail: format!(
                        "compiled-in fallback DNS is in use ({cur} now; {}); set FallbackDNS= empty in resolved.conf",
                        names.join(", ")
                    ),
                });
            }
        }
        // 2. Global servers from resolved.conf.
        let others: Vec<IpAddr> = r
            .global
            .iter()
            .copied()
            .filter(|s| *s != inp.pihole)
            .collect();
        if !others.is_empty() {
            out.push(Leak {
                kind: LeakKind::Link,
                where_: "systemd-resolved".into(),
                uuid: String::new(),
                detail: format!("global DNS uses {}", describe(&others, inp.pihole, inp.gateways)),
            });
        }
    }

    // 3. Saved profiles that are not active: what they would do when used.
    for p in inp.profiles {
        if !matches!(p.kind, ProfileKind::Wifi | ProfileKind::Ethernet) {
            continue;
        }
        if active_uuids.contains(&p.uuid.as_str()) {
            continue;
        }
        if let Some((kind, detail)) = profile_leak(&p.dns, inp.pihole) {
            out.push(Leak {
                kind,
                where_: p.id.clone(),
                uuid: p.uuid.clone(),
                detail,
            });
        }
    }
    out
}

/// Pick a Pi-hole candidate when none is configured: the first server on the
/// primary link that is on the LAN but is not the gateway. It only counts
/// once a probe has shown it blocking the canary.
pub fn pihole_candidate(servers: &[IpAddr], gateway: Option<Ipv4Addr>) -> Option<IpAddr> {
    servers.iter().copied().find(|s| {
        is_local_addr(*s)
            && !s.is_loopback()
            && !is_v6_link_local(*s)
            && Some(*s) != gateway.map(IpAddr::V4)
            && !matches!(s, IpAddr::V4(a) if a.is_link_local())
    })
}

#[cfg(test)]
pub mod fixtures {
    use super::*;
    use crate::net::*;

    pub const PI: &str = "192.168.1.153";
    pub const GW: &str = "192.168.1.1";

    pub fn pi() -> IpAddr {
        PI.parse().unwrap()
    }
    pub fn gw() -> IpAddr {
        GW.parse().unwrap()
    }

    pub fn dns_auto() -> DnsSettings {
        DnsSettings {
            v4_method: "auto".into(),
            v4_dns: vec![],
            v4_ignore_auto: false,
            v6_method: "auto".into(),
            v6_dns: vec![],
            v6_ignore_auto: false,
        }
    }

    pub fn dns_pinned() -> DnsSettings {
        DnsSettings {
            v4_dns: vec![PI.parse().unwrap()],
            v4_ignore_auto: true,
            v6_ignore_auto: true,
            ..dns_auto()
        }
    }

    pub fn profile(uuid: &str, id: &str, kind: ProfileKind, dns: DnsSettings) -> Profile {
        Profile {
            path: format!("/org/freedesktop/NetworkManager/Settings/{id}"),
            uuid: uuid.into(),
            id: id.into(),
            kind,
            ssid: if kind == ProfileKind::Wifi {
                Some(id.as_bytes().to_vec())
            } else {
                None
            },
            autoconnect: true,
            timestamp: 0,
            dns,
        }
    }

    pub const U_WIFI: &str = "21307067-f47b-43ea-8c9c-2c746454b2bb";
    pub const U_ETH1: &str = "f5520df2-a482-3ff6-a770-64b74a740967";
    pub const U_ETH2: &str = "10e2035e-2c2c-3815-ab60-f18f6b0e39d5";

    pub fn redwood() -> Profile {
        profile(U_WIFI, "Redwood", ProfileKind::Wifi, dns_pinned())
    }
    pub fn eth1() -> Profile {
        profile(U_ETH1, "Wired connection 1", ProfileKind::Ethernet, dns_auto())
    }
    pub fn eth2() -> Profile {
        profile(U_ETH2, "Wired connection 2", ProfileKind::Ethernet, dns_auto())
    }

    pub fn wifi_device(active: bool) -> Device {
        Device {
            path: "/org/freedesktop/NetworkManager/Devices/3".into(),
            iface: "wlp7s0".into(),
            ifindex: 4,
            kind: DeviceKind::Wifi,
            state: if active { NM_DEVICE_STATE_ACTIVATED } else { 30 },
            active: active.then(|| ActiveConn {
                path: "/org/freedesktop/NetworkManager/ActiveConnection/2".into(),
                uuid: U_WIFI.into(),
                id: "Redwood".into(),
                state: 2,
            }),
            ip4: active.then(|| "192.168.1.242".parse().unwrap()),
            prefix: active.then_some(24),
            gateway: active.then(|| GW.parse().unwrap()),
            speed_mbps: 0,
            wifi: Some(WifiDev {
                active_ap: Some("/org/freedesktop/NetworkManager/AccessPoint/12".into()),
                bitrate_kbps: 866_000,
                last_scan_age_ms: Some(12_000),
                aps: vec![],
            }),
        }
    }

    pub fn snapshot(devices: Vec<Device>) -> NetSnapshot {
        NetSnapshot {
            wifi_enabled: true,
            hw_enabled: true,
            connectivity: Connectivity::Full,
            check_uri: "http://ping.omacom.io/nm-check.txt".into(),
            primary_conn: devices
                .iter()
                .find_map(|d| d.active.as_ref().map(|a| a.path.clone())),
            devices,
        }
    }

    pub fn link(ifindex: u32, name: &str, servers: &[&str], route: bool) -> LinkDns {
        let servers: Vec<IpAddr> = servers.iter().map(|s| s.parse().unwrap()).collect();
        LinkDns {
            ifindex,
            name: name.into(),
            current: servers.first().copied(),
            servers,
            default_route: route,
        }
    }

    pub fn resolver(links: Vec<LinkDns>) -> ResolverSnapshot {
        ResolverSnapshot {
            links,
            global: vec![],
            fallback: vec![
                "9.9.9.9".parse().unwrap(),
                "1.1.1.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            ],
            global_current: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::net::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn roles() {
        let gws = [gw()];
        assert_eq!(classify(ip(PI), Some(pi()), &gws), Role::Pihole);
        assert_eq!(classify(gw(), Some(pi()), &gws), Role::Router);
        assert_eq!(classify(ip("9.9.9.9"), Some(pi()), &gws), Role::Public);
        assert_eq!(classify(ip("2606:4700:4700::1111"), Some(pi()), &gws), Role::Public);
        assert_eq!(classify(ip("192.168.1.50"), Some(pi()), &gws), Role::Other);
        assert_eq!(classify(ip("100.100.100.100"), Some(pi()), &gws), Role::Other);
        assert_eq!(classify(ip("fd00::53"), Some(pi()), &gws), Role::Other);
        // RA-supplied link-local resolver is the router.
        assert_eq!(classify(ip("fe80::1"), Some(pi()), &gws), Role::Router);
        // Without a known Pi-hole nothing is classified as one.
        assert_eq!(classify(ip(PI), None, &gws), Role::Other);
        // A gateway that is also the pihole address is the Pi-hole.
        assert_eq!(classify(gw(), Some(gw()), &[gw()]), Role::Pihole);
    }

    #[test]
    fn mode_detection() {
        let pinned = redwood();
        let auto = profile(U_WIFI, "Redwood", ProfileKind::Wifi, dns_auto());
        let one = [ip(PI)];
        assert_eq!(detect_mode(true, false, &one, Some(&pinned), Some(pi())), Mode::Pihole);
        // DHCP that happens to hand out the Pi-hole is still the Pi-hole.
        assert_eq!(detect_mode(true, false, &one, Some(&auto), Some(pi())), Mode::Pihole);
        let router = [gw()];
        assert_eq!(detect_mode(true, false, &router, Some(&auto), Some(pi())), Mode::Auto);
        // Pinned profile but resolved shows the router: not Pi-hole, not auto.
        assert_eq!(detect_mode(true, false, &router, Some(&pinned), Some(pi())), Mode::Custom);
        let custom = [ip("9.9.9.9")];
        let custom_prof = profile(
            U_WIFI,
            "Redwood",
            ProfileKind::Wifi,
            DnsSettings { v4_dns: vec!["9.9.9.9".parse().unwrap()], v4_ignore_auto: true, ..dns_auto() },
        );
        assert_eq!(detect_mode(true, false, &custom, Some(&custom_prof), Some(pi())), Mode::Custom);
        // Pi-hole + router: still the Pi-hole mode; `is_bypassed` flags it.
        let mixed = [ip(PI), gw()];
        assert_eq!(detect_mode(true, false, &mixed, Some(&pinned), Some(pi())), Mode::Pihole);
        // Failover wins over the servers; no link / no servers light nothing.
        assert_eq!(detect_mode(true, true, &router, Some(&pinned), Some(pi())), Mode::Fallback);
        assert_eq!(detect_mode(false, false, &one, Some(&pinned), Some(pi())), Mode::None);
        assert_eq!(detect_mode(true, false, &[], Some(&pinned), Some(pi())), Mode::None);
        // No Pi-hole known: auto or custom only.
        assert_eq!(detect_mode(true, false, &router, Some(&auto), None), Mode::Auto);
        assert_eq!(detect_mode(true, false, &one, Some(&pinned), None), Mode::Custom);
        assert_eq!(Mode::None.as_str(), "none");
        assert_eq!(Mode::Unknown.as_str(), "unknown");
        // Unknown profile with servers is custom, not auto.
        assert_eq!(detect_mode(true, false, &router, None, Some(pi())), Mode::Custom);
    }

    #[test]
    fn manual_override_cases() {
        assert!(!manual_override(&dns_auto(), pi()));
        assert!(!manual_override(&dns_pinned(), pi()));
        let custom = DnsSettings { v4_dns: vec!["9.9.9.9".parse().unwrap()], ..dns_auto() };
        assert!(manual_override(&custom, pi()));
        let both = DnsSettings {
            v4_dns: vec![PI.parse().unwrap(), "1.1.1.1".parse().unwrap()],
            ..dns_pinned()
        };
        assert!(manual_override(&both, pi()));
        let v6 = DnsSettings { v6_dns: vec!["2001:db8::53".parse().unwrap()], ..dns_pinned() };
        assert!(manual_override(&v6, pi()));
    }

    #[test]
    fn profile_leak_cases() {
        assert_eq!(profile_leak(&dns_pinned(), pi()), None);
        let (k, d) = profile_leak(&dns_auto(), pi()).unwrap();
        assert_eq!(k, LeakKind::Profile);
        assert_eq!(d, "uses router DNS (automatic)");
        // v4 pinned but IPv6 RA may still supply DNS.
        let ra = DnsSettings { v6_ignore_auto: false, ..dns_pinned() };
        assert_eq!(profile_leak(&ra, pi()).unwrap().0, LeakKind::Ipv6Ra);
        // IPv6 disabled/ignored: nothing to leak.
        let v6off = DnsSettings { v6_method: "disabled".into(), v6_ignore_auto: false, ..dns_pinned() };
        assert_eq!(profile_leak(&v6off, pi()), None);
        let v6ignore = DnsSettings { v6_method: "ignore".into(), v6_ignore_auto: false, ..dns_pinned() };
        assert_eq!(profile_leak(&v6ignore, pi()), None);
        // Other manual servers.
        let other = DnsSettings { v4_dns: vec!["1.1.1.1".parse().unwrap()], v4_ignore_auto: true, ..dns_pinned() };
        assert_eq!(profile_leak(&other, pi()).unwrap().1, "uses 1.1.1.1");
        // Ignoring auto DNS with nothing set leaves no Pi-hole at all.
        let empty = DnsSettings { v4_dns: vec![], ..dns_pinned() };
        assert_eq!(profile_leak(&empty, pi()).unwrap().1, "has no Pi-hole DNS server set");
        // Manual IPv6 DNS.
        let v6dns = DnsSettings { v6_dns: vec!["2001:db8::53".parse().unwrap()], ..dns_pinned() };
        assert_eq!(profile_leak(&v6dns, pi()).unwrap().1, "uses 2001:db8::53");
        // Shared (hotspot) profile supplies no upstream DNS.
        let shared = DnsSettings { v4_method: "shared".into(), v6_method: "ignore".into(), ..dns_auto() };
        assert_eq!(profile_leak(&shared, pi()), None);
    }

    #[test]
    fn leaks_live_machine_shape() {
        // Redwood active and pinned; two inactive automatic wired profiles.
        let net = snapshot(vec![wifi_device(true)]);
        let profiles = vec![redwood(), eth1(), eth2()];
        let res = resolver(vec![link(4, "wlp7s0", &[PI], true)]);
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Pihole,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert_eq!(leaks.len(), 2, "{leaks:?}");
        assert_eq!(leaks[0].where_, "Wired connection 1");
        assert_eq!(leaks[0].uuid, U_ETH1);
        assert_eq!(leaks[0].kind, LeakKind::Profile);
        assert_eq!(leaks[0].detail, "uses router DNS (automatic)");
        assert_eq!(leaks[1].where_, "Wired connection 2");
    }

    #[test]
    fn compiled_fallback_is_not_a_leak() {
        let net = snapshot(vec![wifi_device(true)]);
        let profiles = vec![redwood()];
        let res = resolver(vec![link(4, "wlp7s0", &[PI], true)]);
        assert!(!res.fallback.is_empty());
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Pihole,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert!(leaks.is_empty(), "{leaks:?}");
    }

    #[test]
    fn active_link_with_extra_servers_is_a_leak() {
        let net = snapshot(vec![wifi_device(true)]);
        let profiles = vec![redwood()];
        let res = resolver(vec![link(4, "wlp7s0", &[PI, "192.168.1.1"], true)]);
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Custom,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].kind, LeakKind::Link);
        assert_eq!(leaks[0].where_, "Redwood");
        assert_eq!(leaks[0].detail, "also uses 192.168.1.1 (router)");
    }

    #[test]
    fn ipv6_ra_leak_on_active_link() {
        let net = snapshot(vec![wifi_device(true)]);
        let mut p = redwood();
        p.dns.v6_ignore_auto = false;
        let profiles = vec![p];
        let res = resolver(vec![link(4, "wlp7s0", &[PI, "fe80::1"], true)]);
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Custom,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].kind, LeakKind::Ipv6Ra);
        assert!(leaks[0].detail.contains("fe80::1 (router)"));
    }

    #[test]
    fn deliberate_auto_mode_is_not_a_leak_but_other_links_are() {
        // Wi-Fi in Automatic on purpose; an Ethernet link is also up with
        // router DNS and a default route: that one is a leak.
        let mut eth = wifi_device(false);
        eth.path = "/org/freedesktop/NetworkManager/Devices/2".into();
        eth.iface = "enp8s0".into();
        eth.ifindex = 2;
        eth.kind = DeviceKind::Ethernet;
        eth.wifi = None;
        eth.state = NM_DEVICE_STATE_ACTIVATED;
        eth.active = Some(ActiveConn {
            path: "/org/freedesktop/NetworkManager/ActiveConnection/9".into(),
            uuid: U_ETH1.into(),
            id: "Wired connection 1".into(),
            state: 2,
        });
        let wifi_auto = profile(U_WIFI, "Redwood", ProfileKind::Wifi, dns_auto());
        let net = snapshot(vec![wifi_device(true), eth]);
        let profiles = vec![wifi_auto, eth1()];
        let res = resolver(vec![
            link(4, "wlp7s0", &["192.168.1.1"], true),
            link(2, "enp8s0", &["192.168.1.1"], true),
        ]);
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Auto,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: true,
            engaged_iface: None,
        });
        assert_eq!(leaks.len(), 1, "{leaks:?}");
        assert_eq!(leaks[0].where_, "Wired connection 1");
        assert_eq!(leaks[0].kind, LeakKind::Link);
        // The active ethernet profile is reported once, not also as a profile.
    }

    #[test]
    fn non_default_route_links_and_global_servers() {
        let net = snapshot(vec![wifi_device(true)]);
        let profiles = vec![redwood()];
        let mut res = resolver(vec![
            link(4, "wlp7s0", &[PI], true),
            link(9, "tailscale0", &["100.100.100.100"], false),
        ]);
        let none = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Pihole,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert!(none.is_empty(), "scoped links are not leaks: {none:?}");

        res.links[1].default_route = true;
        res.global = vec![ip("8.8.8.8")];
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Pihole,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert_eq!(leaks.len(), 2, "{leaks:?}");
        assert_eq!(leaks[0].where_, "tailscale0");
        assert_eq!(leaks[1].where_, "systemd-resolved");
        assert!(leaks[1].detail.contains("8.8.8.8 (public)"));
    }

    #[test]
    fn non_wifi_profiles_are_ignored() {
        let net = snapshot(vec![wifi_device(true)]);
        let vpn = profile("aaaaaaaa-0000-0000-0000-000000000000", "work-vpn", ProfileKind::Other, dns_auto());
        let profiles = vec![redwood(), vpn];
        let res = resolver(vec![link(4, "wlp7s0", &[PI], true)]);
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Pihole,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert!(leaks.is_empty());
    }

    #[test]
    fn candidate_detection() {
        let gwv4: Ipv4Addr = GW.parse().unwrap();
        assert_eq!(pihole_candidate(&[gw(), pi()], Some(gwv4)), Some(pi()));
        assert_eq!(pihole_candidate(&[gw()], Some(gwv4)), None);
        assert_eq!(pihole_candidate(&[ip("9.9.9.9")], Some(gwv4)), None);
        assert_eq!(pihole_candidate(&[ip("127.0.0.53")], Some(gwv4)), None);
        assert_eq!(pihole_candidate(&[ip("fe80::1")], Some(gwv4)), None);
        assert_eq!(pihole_candidate(&[ip("fd00::53")], Some(gwv4)), Some(ip("fd00::53")));
    }

    #[test]
    fn bypassed_cases() {
        let pinned = redwood();
        let auto = profile(U_WIFI, "Redwood", ProfileKind::Wifi, dns_auto());
        let (one, mixed, router) = ([ip(PI)], [ip(PI), gw()], [gw()]);
        // Healthy: pinned, only the Pi-hole.
        assert!(!is_bypassed(Mode::Pihole, &one, Some(&pinned), pi(), false));
        // Pinned but something else is in the server list too.
        assert!(is_bypassed(Mode::Pihole, &mixed, Some(&pinned), pi(), false));
        // DHCP happens to hand out only the Pi-hole, but nothing is pinned.
        assert!(is_bypassed(Mode::Pihole, &one, Some(&auto), pi(), false));
        // Pinned v4 but IPv6 router advertisements may still add servers.
        let ra = profile(U_WIFI, "Redwood", ProfileKind::Wifi, DnsSettings { v6_ignore_auto: false, ..dns_pinned() });
        assert!(is_bypassed(Mode::Pihole, &one, Some(&ra), pi(), false));
        // No profile known: cannot call it pinned.
        assert!(is_bypassed(Mode::Pihole, &one, None, pi(), false));
        // The Pi-hole is not used at all.
        assert!(is_bypassed(Mode::Custom, &[ip("9.9.9.9")], Some(&pinned), pi(), false));
        // Deliberate Automatic, failover, no DNS, undecided: not a bypass.
        // Automatic only counts as the user's choice if `qnet dns auto` said so.
        assert!(!is_bypassed(Mode::Auto, &router, Some(&auto), pi(), true));
        assert!(is_bypassed(Mode::Auto, &router, Some(&auto), pi(), false), "an Ethernet cable that came up on its own");
        assert!(!is_bypassed(Mode::Fallback, &router, Some(&pinned), pi(), false));
        assert!(!is_bypassed(Mode::None, &[], Some(&pinned), pi(), false));
        assert!(!is_bypassed(Mode::Unknown, &one, Some(&pinned), pi(), false));
    }

    #[test]
    fn mixed_servers_on_a_pinned_active_link_are_still_listed_as_a_leak() {
        let net = snapshot(vec![wifi_device(true)]);
        let profiles = vec![redwood()];
        let res = resolver(vec![link(4, "wlp7s0", &[PI, "192.168.1.1"], true)]);
        let leaks = detect_leaks(&LeakInput {
            net: &net,
            profiles: &profiles,
            resolver: Some(&res),
            pihole: pi(),
            gateways: &[gw()],
            mode: Mode::Pihole,
            primary_iface: Some("wlp7s0"),
            auto_deliberate: false,
            engaged_iface: None,
        });
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].detail, "also uses 192.168.1.1 (router)");
    }

    fn leaks_for(
        net: &NetSnapshot,
        profiles: &[Profile],
        res: &ResolverSnapshot,
        mode: Mode,
        auto_deliberate: bool,
        engaged: Option<&str>,
    ) -> Vec<Leak> {
        detect_leaks(&LeakInput {
            net,
            profiles,
            resolver: Some(res),
            pihole: pi(),
            gateways: &[gw()],
            mode,
            primary_iface: Some("wlp7s0"),
            auto_deliberate,
            engaged_iface: engaged,
        })
    }

    #[test]
    fn an_automatic_nobody_chose_is_listed_on_the_primary_link() {
        let net = snapshot(vec![wifi_device(true)]);
        let auto = profile(U_WIFI, "Redwood", ProfileKind::Wifi, dns_auto());
        let res = resolver(vec![link(4, "wlp7s0", &["192.168.1.1"], true)]);
        let chosen = leaks_for(&net, std::slice::from_ref(&auto), &res, Mode::Auto, true, None);
        assert!(chosen.is_empty(), "{chosen:?}");
        let unchosen = leaks_for(&net, &[auto], &res, Mode::Auto, false, None);
        assert_eq!(unchosen.len(), 1, "{unchosen:?}");
        assert_eq!(unchosen[0].where_, "Redwood");
        assert_eq!(unchosen[0].uuid, U_WIFI);
        assert_eq!(unchosen[0].detail, "uses 192.168.1.1 (router)");
    }

    #[test]
    fn the_failed_over_link_is_not_listed_as_a_leak() {
        let net = snapshot(vec![wifi_device(true)]);
        let profiles = vec![redwood()];
        let res = resolver(vec![link(4, "wlp7s0", &["192.168.1.1"], true)]);
        assert!(!leaks_for(&net, &profiles, &res, Mode::Custom, false, None).is_empty(), "custom would be one");
        assert!(leaks_for(&net, &profiles, &res, Mode::Custom, false, Some("wlp7s0")).is_empty());
    }

    #[test]
    fn compiled_fallback_dns_is_a_leak_only_once_resolved_has_picked_it() {
        let net = snapshot(vec![wifi_device(true)]);
        let profiles = vec![redwood()];
        let mut res = resolver(vec![link(4, "wlp7s0", &[PI], true)]);
        // Configured but never picked: quiet.
        assert!(leaks_for(&net, &profiles, &res, Mode::Pihole, false, None).is_empty());
        // The Manager's current server is a fallback address while the link has servers.
        res.global_current = Some(ip("9.9.9.9"));
        let leaks = leaks_for(&net, &profiles, &res, Mode::Pihole, false, None);
        assert_eq!(leaks.len(), 1, "{leaks:?}");
        assert_eq!(leaks[0].kind, LeakKind::ResolvedFallback);
        assert_eq!(leaks[0].kind.as_str(), "resolved-fallback");
        assert_eq!(leaks[0].where_, "systemd-resolved");
        assert!(leaks[0].detail.contains("9.9.9.9 now"), "{}", leaks[0].detail);
        assert!(leaks[0].detail.contains("1.1.1.1") && leaks[0].detail.contains("8.8.8.8"), "names the servers");
        // Not a fallback address (a configured global server is reported the old way).
        res.global_current = Some(ip("10.1.1.1"));
        assert!(leaks_for(&net, &profiles, &res, Mode::Pihole, false, None).is_empty());
        // No link has servers: resolved *has* to use its fallback, that is mode "none".
        let mut res = resolver(vec![]);
        res.global_current = Some(ip("9.9.9.9"));
        assert!(leaks_for(&net, &profiles, &res, Mode::None, false, None).is_empty());
        // Servers from resolved.conf are a leak of their own kind, not this one.
        let mut res = resolver(vec![link(4, "wlp7s0", &[PI], true)]);
        res.global = vec![ip("8.8.8.8")];
        res.global_current = Some(ip("8.8.8.8"));
        let leaks = leaks_for(&net, &profiles, &res, Mode::Pihole, false, None);
        assert!(leaks.iter().all(|l| l.kind != LeakKind::ResolvedFallback));
    }
}

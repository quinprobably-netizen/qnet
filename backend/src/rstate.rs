//! What systemd-resolved thinks of the Pi-hole as a server: its "feature
//! level". resolved quietly drops a server from UDP+EDNS0 to plain UDP and
//! then to TCP after a few lost or mangled replies, and only says so in the
//! journal. `resolvectl show-server-state` reads the same thing from the
//! running daemon.

use std::net::IpAddr;
use std::time::Duration;

/// A reason to show if resolved has downgraded `pihole`, else None.
pub fn downgrade_in(text: &str, pihole: IpAddr) -> Option<String> {
    let want = pihole.to_string();
    let mut in_block = false;
    let mut is_link = false;
    let mut possible = String::new();
    let mut verified = String::new();
    let mut hit: Option<(String, String)> = None;
    let flush = |in_block: bool,
                 is_link: bool,
                 possible: &str,
                 verified: &str,
                 hit: &mut Option<(String, String)>| {
        if in_block && is_link {
            *hit = Some((possible.to_string(), verified.to_string()));
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Server:") {
            flush(in_block, is_link, &possible, &verified, &mut hit);
            let addr = rest.trim().split('#').next().unwrap_or("").trim();
            in_block = addr == want;
            is_link = false;
            possible.clear();
            verified.clear();
        } else if let Some(v) = line.strip_prefix("Type:") {
            is_link = v.trim() == "link";
        } else if let Some(v) = line.strip_prefix("Possible feature level:") {
            possible = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("Verified feature level:") {
            verified = v.trim().to_string();
        }
    }
    flush(in_block, is_link, &possible, &verified, &mut hit);
    let (possible, verified) = hit?;
    // The level that is currently allowed; the verified one lags behind.
    let level = if possible.is_empty() || possible == "n/a" {
        verified
    } else {
        possible
    };
    describe(&level, &want)
}

fn describe(level: &str, addr: &str) -> Option<String> {
    match level {
        "TCP" => Some(format!(
            "systemd-resolved dropped {addr} to TCP only (UDP is failing)"
        )),
        "UDP" => Some(format!(
            "systemd-resolved dropped {addr} to plain UDP (EDNS0 is failing)"
        )),
        _ => None,
    }
}

/// Ask the running resolved. None when `resolvectl` is missing or fails.
pub fn real_check(pihole: IpAddr) -> Option<String> {
    let out = crate::proc::run(
        "resolvectl",
        &["show-server-state"],
        None,
        Duration::from_secs(3),
        64 * 1024,
    )
    .ok()?;
    if !out.success() {
        return None;
    }
    downgrade_in(&String::from_utf8_lossy(&out.stdout), pihole)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(addr: &str, kind: &str, possible: &str, verified: &str) -> String {
        format!(
            "Server: {addr}\n                              Type: {kind}\n                         Interface: wlp7s0\n            Verified feature level: {verified}\n            Possible feature level: {possible}\n                       DNSSEC Mode: no\n               Failed UDP attempts: 0\n\n"
        )
    }

    fn pi() -> IpAddr {
        "192.168.1.153".parse().unwrap()
    }

    #[test]
    fn healthy_server_is_not_a_downgrade() {
        let t = block("9.9.9.9#dns.quad9.net", "fallback", "TLS+EDNS0+DO", "n/a")
            + &block("192.168.1.153", "link", "UDP+EDNS0", "UDP+EDNS0");
        assert_eq!(downgrade_in(&t, pi()), None);
    }

    #[test]
    fn udp_and_tcp_levels_are_reported_with_the_address() {
        let t = block("192.168.1.153", "link", "UDP", "UDP+EDNS0");
        let d = downgrade_in(&t, pi()).unwrap();
        assert!(d.contains("192.168.1.153") && d.contains("EDNS0"), "{d}");
        let t = block("192.168.1.153", "link", "TCP", "UDP");
        let d = downgrade_in(&t, pi()).unwrap();
        assert!(d.contains("TCP only"), "{d}");
    }

    #[test]
    fn only_the_pihole_link_entry_counts() {
        // A downgraded fallback server, or the same address as a different
        // type, says nothing about the link's Pi-hole.
        let t = block("9.9.9.9#dns.quad9.net", "fallback", "TCP", "n/a");
        assert_eq!(downgrade_in(&t, pi()), None);
        let t = block("192.168.1.153", "system", "TCP", "n/a");
        assert_eq!(downgrade_in(&t, pi()), None);
        let t = block("192.168.1.135", "link", "TCP", "TCP");
        assert_eq!(downgrade_in(&t, pi()), None);
        // 192.168.1.13 must not match 192.168.1.153 by prefix.
        let t = block("192.168.1.13", "link", "TCP", "TCP");
        assert_eq!(downgrade_in(&t, pi()), None);
    }

    #[test]
    fn missing_levels_and_junk_are_not_downgrades() {
        assert_eq!(downgrade_in("", pi()), None);
        assert_eq!(downgrade_in("nonsense\nServer:\n", pi()), None);
        let t = block("192.168.1.153", "link", "n/a", "n/a");
        assert_eq!(downgrade_in(&t, pi()), None);
        // The verified level is used when no possible level is given.
        let t = block("192.168.1.153", "link", "", "UDP");
        assert!(downgrade_in(&t, pi()).is_some());
    }

    #[test]
    fn the_last_block_is_read_too() {
        let t = block("1.1.1.1", "fallback", "TLS+EDNS0+DO", "n/a")
            + "Server: 192.168.1.153\n   Type: link\n   Possible feature level: UDP\n";
        assert!(downgrade_in(&t, pi()).is_some());
    }

    #[test]
    fn a_real_dump_from_this_machine_parses() {
        let real = "Server: 192.168.1.153               \n                              Type: link\n                         Interface: wlp7s0\n                   Interface Index: 4\n            Verified feature level: UDP+EDNS0\n            Possible feature level: UDP+EDNS0\n                       DNSSEC Mode: no\n                  DNSSEC Supported: yes\nMaximum UDP fragment size received: 512\n               Failed UDP attempts: 0\n               Failed TCP attempts: 0\n";
        assert_eq!(downgrade_in(real, pi()), None);
        assert!(downgrade_in(
            &real.replace(
                "Possible feature level: UDP+EDNS0",
                "Possible feature level: UDP"
            ),
            pi()
        )
        .is_some());
    }
}

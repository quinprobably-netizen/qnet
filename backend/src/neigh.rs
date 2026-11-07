//! The neighbour table: the MAC address behind the gateway's IP. Read from
//! `/proc/net/arp`; nothing is sent.
//!
//! The pair (IP, MAC) is what "this is the router the profile was pinned on"
//! means: an address alone is trivially reproduced by another network.

use std::net::Ipv4Addr;

pub type Mac = [u8; 6];

pub fn format_mac(m: &Mac) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

pub fn parse_mac(s: &str) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut it = s.trim().split(':');
    for slot in &mut out {
        let part = it.next()?;
        if part.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    it.next().is_none().then_some(out)
}

/// ARP flag `ATF_COM`: the entry is complete.
const ATF_COM: u32 = 0x2;

/// The MAC for `ip` on `iface` from the text of `/proc/net/arp`. Incomplete
/// entries and the all-zero address do not count.
pub fn lookup_in(text: &str, ip: Ipv4Addr, iface: &str) -> Option<Mac> {
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // IP address, HW type, Flags, HW address, Mask, Device
        if f.len() < 6 || f[5] != iface || f[0].parse::<Ipv4Addr>().ok()? != ip {
            continue;
        }
        let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).ok()?;
        let mac = parse_mac(f[3])?;
        if flags & ATF_COM != 0 && mac != [0; 6] {
            return Some(mac);
        }
    }
    None
}

pub fn mac_of(ip: Ipv4Addr, iface: &str) -> Option<Mac> {
    lookup_in(&std::fs::read_to_string("/proc/net/arp").ok()?, ip, iface)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP: &str = "IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         3c:52:a1:00:11:22     *        wlp7s0
192.168.1.153    0x1         0x2         b8:27:eb:aa:bb:cc     *        wlp7s0
192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        wlp7s0
192.168.1.1      0x1         0x2         de:ad:be:ef:00:01     *        enp8s0
";

    #[test]
    fn finds_the_mac_for_the_right_interface() {
        let gw: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert_eq!(format_mac(&lookup_in(ARP, gw, "wlp7s0").unwrap()), "3c:52:a1:00:11:22");
        assert_eq!(format_mac(&lookup_in(ARP, gw, "enp8s0").unwrap()), "de:ad:be:ef:00:01");
        assert_eq!(lookup_in(ARP, gw, "wlan9"), None);
    }

    #[test]
    fn incomplete_and_missing_entries_are_not_answers() {
        assert_eq!(lookup_in(ARP, "192.168.1.77".parse().unwrap(), "wlp7s0"), None, "flags 0x0");
        assert_eq!(lookup_in(ARP, "192.168.1.9".parse().unwrap(), "wlp7s0"), None);
        assert_eq!(lookup_in("", "192.168.1.1".parse().unwrap(), "wlp7s0"), None);
        assert_eq!(lookup_in("garbage\nmore garbage here now x y\n", "192.168.1.1".parse().unwrap(), "x"), None);
    }

    #[test]
    fn mac_text_roundtrip_and_rejects() {
        let m = parse_mac("3c:52:a1:00:11:22").unwrap();
        assert_eq!(format_mac(&m), "3c:52:a1:00:11:22");
        assert_eq!(parse_mac("3C:52:A1:00:11:22"), Some(m));
        for bad in ["", "3c:52:a1:00:11", "3c:52:a1:00:11:22:33", "3c:52:a1:00:11:zz", "3c-52-a1-00-11-22", "3:52:a1:00:11:22"] {
            assert_eq!(parse_mac(bad), None, "{bad:?}");
        }
    }
}

//! The patch bay's sample data, for the golden fixtures (tests only).
//!
//! The approved mockup (`watchdog-r2`) draws one sample network: 30 devices at
//! 192.0.2.N, the first 8 at rest, a threat on ·40 and a new device ·216, a
//! gate on ·23, three devices on the ADS PASS list, the router and qbp
//! `always`, the printer `fixed`. [`reports`] makes the watchdog's report for
//! each of the five screens the panel's tests need, as the poller would build
//! it (`annotate`, `unreported`); `state.rs` turns them into full state lines
//! and compares them with `tests/fixtures/watchdog-*.json` (the contract the
//! panel's JS is tested against; `QNET_UPDATE_FIXTURES=1 cargo test` rewrites
//! them).

use std::collections::HashSet;

use crate::watchdog::{annotate, unreported, Alert, Device, WatchdogReport};
use crate::wdstore::Store;

/// The JS tests' clock: `tests/helpers.js` `NOW_S`.
pub const NOW_S: u64 = 1_794_122_700;

/// When the Pi's devices were read, and the alerts last asked for.
pub const DEVICES_AT: u64 = NOW_S - 45;
pub const POLLED_AT: u64 = NOW_S - 15;

/// How a device is wired by the Pi's own configuration.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flag {
    None,
    /// The router or the Pi: never ADS PASS.
    Always,
    /// The Pi's configuration passes it.
    FixedPass,
    /// Not reported by the Pi (this PC remembers it).
    Offline,
}

/// `(n, label, hostname, the first screen that has it, flag)` of the mockup's
/// `RAW`: the device at 192.0.2.`n`, which shows from `tier` devices on.
const RAW: [(u32, &str, &str, u32, Flag); 30] = [
    (1, "router", "gateway", 3, Flag::Always),
    (2, "qbp", "qbp", 3, Flag::Always),
    (10, "This PC", "desk", 3, Flag::None),
    (12, "Work laptop", "laptop-01", 8, Flag::None),
    (23, "Sam's phone", "phone-7a", 8, Flag::None),
    (40, "Living room TV", "tv-40", 8, Flag::None),
    (51, "Kitchen speaker", "speaker", 8, Flag::None),
    (216, "", "", 8, Flag::None),
    (14, "Tablet", "tablet", 16, Flag::None),
    (27, "Alex's phone", "phone-2c", 16, Flag::None),
    (31, "Printer", "printer", 16, Flag::FixedPass),
    (44, "Bedroom TV", "tv-44", 16, Flag::None),
    (52, "Thermostat", "thermostat", 16, Flag::None),
    (55, "Doorbell", "doorbell", 16, Flag::None),
    (60, "Game console", "console", 16, Flag::None),
    (63, "NAS", "nas", 16, Flag::None),
    (15, "Old laptop", "laptop-00", 30, Flag::Offline),
    (28, "Guest phone", "phone-91", 30, Flag::None),
    (33, "E-reader", "reader", 30, Flag::None),
    (46, "Streaming stick", "stick-46", 30, Flag::None),
    (57, "Vacuum", "vacuum", 30, Flag::None),
    (58, "Garage door", "garage", 30, Flag::None),
    (61, "Smart plug 1", "plug-1", 30, Flag::None),
    (62, "Smart plug 2", "plug-2", 30, Flag::None),
    (64, "Weather station", "weather", 30, Flag::None),
    (66, "Baby monitor", "monitor", 30, Flag::None),
    (70, "Porch camera", "cam-1", 30, Flag::None),
    (71, "Yard camera", "cam-2", 30, Flag::None),
    (101, "", "", 30, Flag::None),
    (102, "Soundbar", "soundbar", 30, Flag::Offline),
];

/// 18:00 UTC on 2, 3, 5 and 7 November 2026: the days devices were first seen
/// (the mockup's `SINCE`, moved to before the fixtures' clock).
const FIRST_SEEN: [u64; 4] = [1_793_642_400, 1_793_728_800, 1_793_901_600, 1_794_074_400];

/// The mockup's ADS PASS list (with the mode off).
const ADS_PASS: [u32; 3] = [40, 44, 46];
/// The block list (it only counts with the mode on): this PC and the work
/// laptop, both on the 8-device board.
const BLOCKED: [u32; 2] = [10, 12];
/// The device that is new, and the one that has a gate open.
const NEW: u32 = 216;
const GATED: u32 = 23;
/// Seconds that ·23's gate has left at [`NOW_S`].
const GATE_LEFT_AT_NOW: u64 = 872;

pub fn mac_of(n: u32) -> String {
    format!("02:00:00:00:{:02x}:{:02x}", n >> 8, n & 0xff)
}

fn first_seen(index: usize, n: u32) -> u64 {
    if n == NEW {
        NOW_S - 29 * 60
    } else {
        FIRST_SEEN[index % 4] + index as u64 * 61
    }
}

/// Which alerts are held.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Alerts {
    None,
    /// The threat on ·40 and the new device ·216.
    Rest,
    /// Those and the ARP spoof.
    Arp,
}

/// One of the five screens.
struct Screen {
    name: &'static str,
    /// Devices shown at most: the mockup's tier.
    tier: u32,
    alerts: Alerts,
    /// ·216 is on this PC's known list (and the Pi's).
    known_216: bool,
    gate: bool,
    /// The exempt-by-default mode, on this PC and on the Pi, with the block
    /// list.
    mode: bool,
}

const SCREENS: [Screen; 5] = [
    Screen {
        name: "rest",
        tier: 8,
        alerts: Alerts::Rest,
        known_216: false,
        gate: true,
        mode: false,
    },
    Screen {
        name: "n30",
        tier: 30,
        alerts: Alerts::Rest,
        known_216: false,
        gate: true,
        mode: false,
    },
    Screen {
        name: "arp",
        tier: 8,
        alerts: Alerts::Arp,
        known_216: false,
        gate: true,
        mode: false,
    },
    Screen {
        name: "calm",
        tier: 8,
        alerts: Alerts::None,
        known_216: true,
        gate: false,
        mode: false,
    },
    Screen {
        name: "mode",
        tier: 8,
        alerts: Alerts::Rest,
        known_216: false,
        gate: true,
        mode: true,
    },
];

fn alert(id: u64, kind: &str, severity: &str, client: Option<&str>, subject: &str) -> Alert {
    Alert {
        id,
        key: format!("a1b2c3d4{id:08x}"),
        rev: id,
        kind: kind.into(),
        severity: severity.into(),
        client: client.map(String::from),
        subject: subject.into(),
        first_unix: 0,
        last_unix: 0,
        count: 1,
        acked: false,
    }
}

/// The alerts, newest change first.
fn alerts_of(which: Alerts) -> Vec<Alert> {
    let threat = Alert {
        count: 3,
        first_unix: NOW_S - 12 * 60,
        last_unix: NOW_S - 8 * 60,
        ..alert(
            1,
            "threat",
            "high",
            Some("192.0.2.40"),
            "malware.example.org",
        )
    };
    let new = Alert {
        first_unix: NOW_S - 29 * 60,
        last_unix: NOW_S - 29 * 60,
        ..alert(2, "new_device", "warn", None, &mac_of(NEW))
    };
    let arp = Alert {
        count: 12,
        first_unix: NOW_S - 3 * 60,
        last_unix: NOW_S - 60,
        ..alert(3, "arp_spoof", "high", Some("192.0.2.1"), &mac_of(NEW))
    };
    match which {
        Alerts::None => vec![],
        Alerts::Rest => vec![new, threat],
        Alerts::Arp => vec![arp, new, threat],
    }
}

/// What the Pi's effective ADS PASS is for a device.
fn passes_on_pi(n: u32, flag: Flag, mode: bool) -> bool {
    match flag {
        Flag::Always => false,
        Flag::FixedPass => true,
        _ if mode => !BLOCKED.contains(&n),
        _ => ADS_PASS.contains(&n),
    }
}

/// The report the watcher would send for `s`.
fn report_of(s: &Screen) -> WatchdogReport {
    let mut store = Store::default();
    let mut devices = Vec::new();
    for (index, &(n, label, host, tier, flag)) in RAW.iter().enumerate() {
        if tier > s.tier {
            continue;
        }
        let (mac, seen) = (mac_of(n), first_seen(index, n));
        let label = (!label.is_empty()).then_some(label);
        let known = n != NEW || s.known_216;
        if known {
            store.know(&mac, label, seen);
        }
        if !s.mode && ADS_PASS.contains(&n) {
            store.add_exempt(&mac, label, seen);
        }
        if flag == Flag::Offline {
            continue;
        }
        devices.push(Device {
            mac,
            ipv4: vec![format!("192.0.2.{n}")],
            hostname: host.into(),
            first_unix: seen,
            last_unix: NOW_S - 20 - index as u64 * 17,
            known,
            exempt: passes_on_pi(n, flag, s.mode),
            blocked: s.mode && BLOCKED.contains(&n),
            label: label.filter(|_| known).map(String::from),
            gate_left_secs: (s.gate && n == GATED)
                .then_some(GATE_LEFT_AT_NOW + (NOW_S - DEVICES_AT)),
            fixed: flag == Flag::FixedPass,
            always: flag == Flag::Always,
        });
    }
    if s.mode {
        store.exempt_default = true;
        for (index, &(n, label, ..)) in RAW.iter().enumerate() {
            if BLOCKED.contains(&n) {
                store.add_block(&mac_of(n), Some(label), first_seen(index, n));
            }
        }
    }

    // As `Poller::report` does it.
    let reported: HashSet<&str> = devices.iter().map(|d| d.mac.as_str()).collect();
    let offline = unreported(&store, &reported).merged();
    devices.sort_by_key(|d| std::cmp::Reverse(d.last_unix));
    let alerts = alerts_of(s.alerts);
    WatchdogReport {
        status: "ok",
        rev: alerts.iter().map(|a| a.rev).max().unwrap_or(2),
        suppressed: 0,
        unacked: alerts.len() as u64,
        alerts,
        known_list: "received".into(),
        devices: annotate(devices, &store),
        known_count: store.known.len() as u64,
        pushed_at: NOW_S - 3600,
        push_error: String::new(),
        polled_at: POLLED_AT,
        exempt_default: s.mode,
        exempt_default_on_pi: s.mode,
        pin_set: true,
        devices_at: DEVICES_AT,
        offline,
    }
}

/// The five reports by the fixture's name: `rest`, `n30`, `arp`, `calm`, `mode`.
pub fn reports() -> Vec<(&'static str, WatchdogReport)> {
    SCREENS.iter().map(|s| (s.name, report_of(s))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bay::{build, BayOut, Input};

    fn bay_of(name: &str) -> BayOut {
        let r = reports()
            .into_iter()
            .find(|(n, _)| *n == name)
            .expect("a screen of that name")
            .1;
        build(&Input {
            devices: &r.devices,
            offline: &r.offline,
            alerts: &r.alerts,
            exempt_default: r.exempt_default,
            devices_at: r.devices_at,
        })
    }

    fn tails(b: &BayOut) -> Vec<&str> {
        b.jacks.iter().map(|j| j.tail.as_str()).collect()
    }

    fn patch_of<'a>(b: &'a BayOut, tail: &str) -> (&'a str, &'a str, bool) {
        let j = b.jacks.iter().find(|j| j.tail == tail).unwrap();
        (j.patch, j.row, j.cord)
    }

    #[test]
    fn the_times_are_a_minute_or_less_before_the_clock() {
        for (name, r) in reports() {
            assert!(
                NOW_S - r.polled_at <= 60 && NOW_S - r.devices_at <= 60,
                "{name}"
            );
            assert_eq!(r.status, "ok");
        }
    }

    #[test]
    fn rest_is_eight_devices_with_a_threat_a_new_device_and_a_gate() {
        let b = bay_of("rest");
        assert_eq!(
            tails(&b),
            ["·40", "·216", "·1", "·2", "·10", "·12", "·23", "·51"]
        );
        assert_eq!(
            b.jacks.iter().map(|j| j.rank).collect::<Vec<_>>(),
            [0, 0, 1, 1, 1, 1, 1, 1]
        );
        assert_eq!(b.calls.iter().map(|c| c.id).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(b.jacks[0].alert_id, Some(1));
        assert_eq!(b.jacks[0].lamp, "high");
        assert_eq!(
            (b.jacks[1].alert_id, b.jacks[1].lamp, b.jacks[1].is_new),
            (Some(2), "warn", true)
        );
        let phone = b.jacks.iter().find(|j| j.tail == "·23").unwrap();
        assert_eq!(
            phone.gate_until,
            Some(NOW_S + 872),
            "14:32 left at the clock"
        );
        assert_eq!(patch_of(&b, "·40"), ("pass", "pass", true));
        assert_eq!(patch_of(&b, "·1"), ("always", "blocked", false));
        assert_eq!(patch_of(&b, "·2"), ("always", "blocked", false));
        assert_eq!(patch_of(&b, "·10"), ("blocked", "blocked", false));
        // ·10, ·12, ·51 and ·216 would start to see ads; ·23's gate shows them already.
        assert_eq!(b.flip_count, 4);
        assert_eq!(
            b.lamps
                .iter()
                .map(|l| (l.count, l.tone))
                .collect::<Vec<_>>(),
            [(1, "high"), (1, "warn"), (0, ""), (0, ""), (0, "")]
        );
        assert_eq!(b.quiet_since, NOW_S - 8 * 60);
    }

    #[test]
    fn n30_has_all_thirty_with_two_offline_at_the_end_and_a_flip_of_23() {
        let b = bay_of("n30");
        assert_eq!(b.jacks.len(), 30);
        assert_eq!(tails(&b)[28..], [":0f", ":66"]);
        assert!(b.jacks[28..]
            .iter()
            .all(|j| j.offline && j.rank == 3 && j.known));
        assert_eq!(b.jacks[28].name, "Old laptop");
        assert_eq!(b.jacks[29].name, "Soundbar");
        let unnamed: Vec<_> = b.jacks.iter().filter(|j| j.name.is_empty()).collect();
        assert_eq!(
            unnamed
                .iter()
                .map(|j| (j.tail.as_str(), j.rank))
                .collect::<Vec<_>>(),
            [("·216", 0), ("·101", 2)]
        );
        assert_eq!(patch_of(&b, "·31"), ("fixed", "pass", false));
        for tail in ["·40", "·44", "·46"] {
            assert_eq!(patch_of(&b, tail), ("pass", "pass", true), "{tail}");
        }
        // 30 less the router, qbp, the printer, three passed, and the gate.
        assert_eq!(b.flip_count, 23);
    }

    #[test]
    fn arp_adds_a_call_with_no_jack_that_names_the_second_card() {
        let b = bay_of("arp");
        assert_eq!(b.jacks.len(), 8);
        assert_eq!(b.calls.iter().map(|c| c.id).collect::<Vec<_>>(), [3, 1, 2]);
        let arp = &b.calls[0];
        assert_eq!(arp.kind, "arp_spoof");
        assert_eq!(
            (arp.mac.clone(), arp.related_mac.clone()),
            (None, Some(mac_of(NEW)))
        );
        assert_eq!(b.lamps[2].alert_id, Some(3));
        assert_eq!(b.lamps[2].tone, "high");
        assert_eq!(b.quiet_since, NOW_S - 60);
    }

    #[test]
    fn calm_has_nothing_waiting_a_known_216_and_no_gate() {
        let b = bay_of("calm");
        assert!(b.calls.is_empty() && b.lamps.iter().all(|l| l.count == 0));
        assert_eq!(b.quiet_since, 0);
        assert!(b
            .jacks
            .iter()
            .all(|j| !j.is_new && j.gate_until.is_none() && j.alert_id.is_none()));
        assert_eq!(
            tails(&b),
            ["·1", "·2", "·10", "·12", "·23", "·40", "·51", "·216"]
        );
        assert!(b.jacks.iter().all(|j| j.rank == 1 || j.tail == "·216"));
    }

    #[test]
    fn mode_wires_the_normal_to_ads_pass_with_two_cords_to_blocked() {
        let b = bay_of("mode");
        assert_eq!(b.flip_count, 0);
        assert_eq!(patch_of(&b, "·10"), ("blocked", "blocked", true));
        assert_eq!(patch_of(&b, "·12"), ("blocked", "blocked", true));
        assert_eq!(patch_of(&b, "·51"), ("pass", "pass", false));
        assert_eq!(
            patch_of(&b, "·40"),
            ("pass", "pass", false),
            "its ADS PASS entry counts for nothing"
        );
        assert_eq!(patch_of(&b, "·1"), ("always", "blocked", false));
        assert_eq!(
            b.jacks.len(),
            8,
            "every device on the block list is on the board"
        );
        assert!(b.jacks.iter().all(|j| !j.offline));
        let r = &reports()[4].1;
        assert!(r.exempt_default && r.exempt_default_on_pi && r.pin_set);
    }
}

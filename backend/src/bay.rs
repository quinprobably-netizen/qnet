//! The patch bay: what the watchdog tab draws, worked out here so that the
//! panel stays a view. One jack column per device (a strip with its name, the
//! address, three jacks, a word), five lamps over the board, the queue of calls
//! waiting. [`build`] is a pure function of the Pi's devices as annotated with
//! this PC's lists, the entries only this PC knows (offline), the alerts held,
//! the mode and the time of the device read; the result is the `watchdog.bay`
//! object of the state JSON (SPEC "State JSON").
//!
//! The rules, in short (each has a test below):
//!
//! - **patch**: `always` for the router and the Pi (never ADS PASS); `fixed`
//!   when the Pi's configuration decides the device (its row follows what the
//!   Pi says, `exemptOnPi`); else, with the exempt-by-default mode off, `pass`
//!   if the device is on this PC's ADS PASS list (a cord) and `blocked` if not
//!   (the normal wire); with the mode on, `blocked` if it is on the block list
//!   (a cord) and `pass` if not.
//! - **ringing**: a `new_device` alert rings the jack whose address is its
//!   subject; an `arp_spoof` rings no jack (it points at the second card with
//!   `relatedMac`); any other alert rings the jack that holds its `client`.
//! - **lamps**: `threat`, `new_device`, `arp_spoof`, `rebind`, and `lookups`
//!   for everything else (dga, tunnel, beacon, burst and kinds not yet known).
//! - **order**: alerting or new first (0), then labelled (1), then the rest
//!   (2), offline last (3); within a rank by IPv4 numerically, then devices
//!   without one by MAC.
//!
//! [`strip_lines`] breaks a name into the two lines of eight characters that a
//! label strip holds; it is the approved mockup's `strip2`, ported.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::watchdog::{normalize_mac, Alert, OfflineEntry, ReportDevice};

/// Characters on one line of a label strip.
const STRIP_CHARS: usize = 8;

/// The five lamps over the board, in the order they are drawn.
pub const LAMP_KINDS: [&str; 5] = ["threat", "new_device", "arp_spoof", "rebind", "lookups"];

// ---- Output ---------------------------------------------------------------

/// One column of the board: a device, online or not.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JackOut {
    pub mac: String,
    /// The first IPv4 address the Pi heard it with, "" for none (and always
    /// for an offline entry).
    pub ip: String,
    /// What the column is headed with: `·40` (the address's last number), or
    /// `:d8` (the last byte of the MAC) without an address.
    pub tail: String,
    pub hostname: String,
    /// This PC's label, else the one the Pi was given, else "".
    pub name: String,
    /// `name` on the label strip: two lines at most ([`strip_lines`]), none
    /// for no name.
    pub strip: Vec<String>,
    /// On this PC's known list.
    pub known: bool,
    /// Neither this PC nor the Pi counts it as known (never for offline).
    pub is_new: bool,
    /// On one of this PC's lists, but not in the Pi's inventory.
    pub offline: bool,
    pub first_unix: u64,
    /// 0 for an offline entry: this PC does not keep when it was seen.
    pub last_unix: u64,
    /// `blocked`, `pass`, `always` or `fixed`.
    pub patch: &'static str,
    /// The row the cord, the normal wire or the rivet bar runs to: `blocked`
    /// or `pass`.
    pub row: &'static str,
    /// Off the normal wiring: on the ADS PASS list with the mode off, on the
    /// block list with the mode on.
    pub cord: bool,
    /// When the open gate shuts, unix; `null` while none is open.
    pub gate_until: Option<u64>,
    /// `""`, `warn` or `high`: the lamp over the jack.
    pub lamp: &'static str,
    /// The newest unacknowledged alert that rings this jack.
    pub alert_id: Option<u64>,
    /// 0 alerting or new, 1 labelled, 2 the rest, 3 offline.
    pub rank: u8,
}

/// One of the five lamps over the board.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LampOut {
    /// One of [`LAMP_KINDS`].
    pub kind: &'static str,
    /// Calls waiting of this kind.
    pub count: u64,
    /// `""` (dark), `warn`, or `high` when any of them is.
    pub tone: &'static str,
    /// The newest call of this kind.
    pub alert_id: Option<u64>,
}

/// An alert waiting (not acknowledged).
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CallOut {
    pub id: u64,
    pub key: String,
    pub kind: String,
    /// The lamp that rings for it (one of [`LAMP_KINDS`]).
    pub lamp: &'static str,
    pub severity: String,
    /// `high` for a high severity, else `warn`.
    pub tone: &'static str,
    /// The jack it rings; `null` for none (it queues as "LAN").
    pub mac: Option<String>,
    /// For an ARP spoof: the jack of the second card, when there is one.
    pub related_mac: Option<String>,
    pub subject: String,
    pub count: u64,
    pub first_unix: u64,
    pub last_unix: u64,
}

/// The `watchdog.bay` object.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BayOut {
    pub jacks: Vec<JackOut>,
    /// How many jacks would get ADS PASS if the normal wiring became ADS PASS;
    /// 0 when it already is.
    pub flip_count: u64,
    /// Always the five of [`LAMP_KINDS`], in that order.
    pub lamps: Vec<LampOut>,
    /// Newest `lastUnix` first.
    pub calls: Vec<CallOut>,
    /// The newest `lastUnix` of any alert held (acknowledged or not), 0 = none.
    pub quiet_since: u64,
}

impl BayOut {
    /// A board with nothing on it: no jacks, no calls, the five lamps dark.
    pub fn empty() -> Self {
        Self {
            jacks: Vec::new(),
            flip_count: 0,
            lamps: LAMP_KINDS
                .iter()
                .map(|&kind| LampOut {
                    kind,
                    count: 0,
                    tone: "",
                    alert_id: None,
                })
                .collect(),
            calls: Vec::new(),
            quiet_since: 0,
        }
    }
}

// ---- Input ----------------------------------------------------------------

/// What [`build`] works from.
pub struct Input<'a> {
    /// The Pi's devices, with this PC's lists applied.
    pub devices: &'a [ReportDevice],
    /// Entries of this PC's lists that the Pi did not report.
    pub offline: &'a [OfflineEntry],
    /// The alerts held, acknowledged ones included (for `quiet_since`).
    pub alerts: &'a [Alert],
    /// This PC's exempt-by-default mode.
    pub exempt_default: bool,
    /// Unix time of the device read (0 = none): what `gateUntil` counts from.
    pub devices_at: u64,
}

// ---- Rules ----------------------------------------------------------------

/// The lamp an alert kind rings.
pub fn lamp_for(kind: &str) -> &'static str {
    match kind {
        "threat" => "threat",
        "new_device" => "new_device",
        "arp_spoof" => "arp_spoof",
        "rebind" => "rebind",
        _ => "lookups",
    }
}

/// `high` for a high severity, else `warn`.
pub fn tone_for(severity: &str) -> &'static str {
    if severity == "high" {
        "high"
    } else {
        "warn"
    }
}

/// How a device is wired: what decides it.
struct Wiring {
    always: bool,
    fixed: bool,
    /// For a fixed device: the Pi passes it.
    fixed_pass: bool,
    /// On this PC's ADS PASS list.
    exempt: bool,
    /// On this PC's block list.
    block: bool,
}

/// `(patch, row, cord)` for a device.
fn wire(w: &Wiring, exempt_default: bool) -> (&'static str, &'static str, bool) {
    if w.always {
        return ("always", "blocked", false);
    }
    if w.fixed {
        return (
            "fixed",
            if w.fixed_pass { "pass" } else { "blocked" },
            false,
        );
    }
    if exempt_default {
        if w.block {
            ("blocked", "blocked", true)
        } else {
            ("pass", "pass", false)
        }
    } else if w.exempt {
        ("pass", "pass", true)
    } else {
        ("blocked", "blocked", false)
    }
}

/// The heading of a column: `·40`, or `:d8` without an address.
fn tail_of(ip: &str, mac: &str) -> String {
    match ip.rsplit('.').next().filter(|_| !ip.is_empty()) {
        Some(last) => format!("·{last}"),
        None => format!(":{}", mac.rsplit(':').next().unwrap_or("")),
    }
}

/// The order within a rank: addresses numerically, devices without one last.
fn ip_order(ip: &str) -> (bool, u32) {
    match ip.parse::<Ipv4Addr>() {
        Ok(a) => (false, u32::from(a)),
        Err(_) => (true, 0),
    }
}

/// A column while it is being worked out.
struct Entry<'a> {
    jack: JackOut,
    /// Every address the Pi heard it with (what a `client` is looked up in).
    ipv4: &'a [String],
    /// On this PC's block list.
    on_block: bool,
}

fn online_entry<'a>(d: &'a ReportDevice, i: &Input) -> Entry<'a> {
    let dev = &d.device;
    let ip = dev.ipv4.first().cloned().unwrap_or_default();
    let name = if d.label.is_empty() {
        dev.label.clone().unwrap_or_default()
    } else {
        d.label.clone()
    };
    let (patch, row, cord) = wire(
        &Wiring {
            always: dev.always,
            fixed: dev.fixed,
            fixed_pass: dev.exempt,
            exempt: d.exempt,
            block: d.blocked,
        },
        i.exempt_default,
    );
    Entry {
        jack: JackOut {
            mac: dev.mac.clone(),
            tail: tail_of(&ip, &dev.mac),
            ip,
            hostname: dev.hostname.clone(),
            strip: strip_lines(&name),
            name,
            known: d.known,
            is_new: !(d.known || dev.known),
            offline: false,
            first_unix: dev.first_unix,
            last_unix: dev.last_unix,
            patch,
            row,
            cord,
            gate_until: dev
                .gate_left_secs
                .filter(|_| i.devices_at > 0)
                .map(|left| i.devices_at + left),
            lamp: "",
            alert_id: None,
            rank: 2,
        },
        ipv4: &dev.ipv4,
        on_block: d.blocked,
    }
}

fn offline_entry<'a>(o: &OfflineEntry, i: &Input) -> Entry<'a> {
    let (patch, row, cord) = wire(
        &Wiring {
            always: false,
            fixed: false,
            fixed_pass: false,
            exempt: o.exempt,
            block: o.block,
        },
        i.exempt_default,
    );
    Entry {
        jack: JackOut {
            mac: o.mac.clone(),
            ip: String::new(),
            tail: tail_of("", &o.mac),
            hostname: String::new(),
            strip: strip_lines(&o.label),
            name: o.label.clone(),
            known: o.known,
            is_new: false,
            offline: true,
            first_unix: o.first_seen,
            last_unix: 0,
            patch,
            row,
            cord,
            gate_until: None,
            lamp: "",
            alert_id: None,
            rank: 3,
        },
        ipv4: &[],
        on_block: o.block,
    }
}

/// Which columns an alert rings: the jack it is for, and for an ARP spoof the
/// jack of the second card.
struct Ring {
    jack: Option<usize>,
    related: Option<usize>,
}

fn ring_of(a: &Alert, by_mac: &HashMap<&str, usize>, by_ip: &HashMap<&str, usize>) -> Ring {
    let subject_jack = || normalize_mac(&a.subject).and_then(|m| by_mac.get(m.as_str()).copied());
    match a.kind.as_str() {
        "new_device" => Ring {
            jack: subject_jack(),
            related: None,
        },
        "arp_spoof" => Ring {
            jack: None,
            related: subject_jack(),
        },
        _ => Ring {
            jack: a.client.as_deref().and_then(|c| by_ip.get(c).copied()),
            related: None,
        },
    }
}

/// The board, the lamps and the queue from what is known.
pub fn build(i: &Input) -> BayOut {
    let mut entries: Vec<Entry> = i.devices.iter().map(|d| online_entry(d, i)).collect();
    let present: HashSet<&str> = i.devices.iter().map(|d| d.device.mac.as_str()).collect();
    entries.extend(
        i.offline
            .iter()
            .filter(|o| !present.contains(o.mac.as_str()))
            .map(|o| offline_entry(o, i)),
    );

    // The alerts waiting, newest first.
    let mut waiting: Vec<&Alert> = i.alerts.iter().filter(|a| !a.acked).collect();
    waiting.sort_by_key(|a| std::cmp::Reverse((a.last_unix, a.rev, a.id)));
    let rings: Vec<Ring> = {
        let by_mac: HashMap<&str, usize> = entries
            .iter()
            .enumerate()
            .map(|(n, e)| (e.jack.mac.as_str(), n))
            .collect();
        // An address held by two devices (a stale lease) belongs to the one
        // seen last.
        let mut by_ip: HashMap<&str, usize> = HashMap::new();
        for (n, e) in entries.iter().enumerate() {
            for ip in e.ipv4 {
                let held_later = by_ip
                    .get(ip.as_str())
                    .is_some_and(|&m| entries[m].jack.last_unix >= e.jack.last_unix);
                if !held_later {
                    by_ip.insert(ip.as_str(), n);
                }
            }
        }
        waiting
            .iter()
            .map(|a| ring_of(a, &by_mac, &by_ip))
            .collect()
    };

    let mut calls = Vec::with_capacity(waiting.len());
    for (a, ring) in waiting.iter().zip(&rings) {
        if let Some(n) = ring.jack {
            // Newest first: the first alert to ring a jack is its newest.
            let jack = &mut entries[n].jack;
            if jack.alert_id.is_none() {
                jack.alert_id = Some(a.id);
                jack.lamp = tone_for(&a.severity);
            }
        }
        calls.push(CallOut {
            id: a.id,
            key: a.key.clone(),
            kind: a.kind.clone(),
            lamp: lamp_for(&a.kind),
            severity: a.severity.clone(),
            tone: tone_for(&a.severity),
            mac: ring.jack.map(|n| entries[n].jack.mac.clone()),
            related_mac: ring.related.map(|n| entries[n].jack.mac.clone()),
            subject: a.subject.clone(),
            count: a.count,
            first_unix: a.first_unix,
            last_unix: a.last_unix,
        });
    }

    let lamps = LAMP_KINDS
        .iter()
        .map(|&kind| {
            let of_kind = || calls.iter().filter(|c| c.lamp == kind);
            let count = of_kind().count() as u64;
            LampOut {
                kind,
                count,
                tone: if of_kind().any(|c| c.tone == "high") {
                    "high"
                } else if count > 0 {
                    "warn"
                } else {
                    ""
                },
                alert_id: of_kind().next().map(|c| c.id),
            }
        })
        .collect();

    for e in &mut entries {
        let j = &mut e.jack;
        j.rank = if j.offline {
            3
        } else if j.alert_id.is_some() || j.is_new {
            0
        } else if !j.name.is_empty() {
            1
        } else {
            2
        };
    }
    // What a flip of the normal wiring would change: the devices on the normal
    // wire, blocked now, that no cord keeps blocked and no open gate already
    // passes.
    let flip_count = if i.exempt_default {
        0
    } else {
        entries
            .iter()
            .filter(|e| e.jack.patch == "blocked" && e.jack.gate_until.is_none() && !e.on_block)
            .count() as u64
    };
    entries.sort_by(|a, b| {
        (a.jack.rank, ip_order(&a.jack.ip))
            .cmp(&(b.jack.rank, ip_order(&b.jack.ip)))
            .then_with(|| a.jack.mac.cmp(&b.jack.mac))
    });

    BayOut {
        jacks: entries.into_iter().map(|e| e.jack).collect(),
        flip_count,
        lamps,
        calls,
        quiet_since: i.alerts.iter().map(|a| a.last_unix).max().unwrap_or(0),
    }
}

// ---- The label strip -------------------------------------------------------

/// The places where a name may be broken (the index of the first character of
/// the next line): at a space, after `-_./`, at a lower-case to upper-case
/// change, and at a letter to digit change.
fn joints(t: &[char]) -> Vec<usize> {
    let mut p = Vec::new();
    for i in 1..t.len() {
        let (a, b) = (t[i - 1], t[i]);
        if b == ' '
            || (a != ' ' && matches!(a, '-' | '_' | '.' | '/'))
            || (a.is_ascii_lowercase() && b.is_ascii_uppercase())
            || (a.is_ascii_alphabetic() && b.is_ascii_digit())
        {
            p.push(i);
        }
    }
    p
}

/// `t` without the spaces at both ends, as text.
fn trimmed(t: &[char]) -> String {
    t.iter().collect::<String>().trim().to_string()
}

fn first_chars(t: &[char], n: usize) -> String {
    t.iter().take(n).collect()
}

/// The second line when the rest of a name is too long for it: whole words as
/// far as they fit in seven characters, then an ellipsis.
fn cut_tail(rest: &str) -> String {
    let r: Vec<char> = rest.chars().collect();
    if r.len() <= STRIP_CHARS {
        return rest.to_string();
    }
    let best = joints(&r)
        .into_iter()
        .rfind(|&p| trimmed(&r[..p]).chars().count() < STRIP_CHARS);
    let head = match best {
        Some(p) => trimmed(&r[..p]),
        None => first_chars(&r, STRIP_CHARS - 1),
    };
    format!("{head}…")
}

/// A name as the two lines of a label strip, eight characters each: in one
/// line if it fits; else broken at the most even joint where both halves fit;
/// else the longest first line that fits and what follows cut short with an
/// ellipsis; else (no joint) one line of seven characters and an ellipsis.
/// Counted in characters. No name, no lines.
pub fn strip_lines(name: &str) -> Vec<String> {
    let t: Vec<char> = name.trim().chars().collect();
    if t.is_empty() {
        return Vec::new();
    }
    if t.len() <= STRIP_CHARS {
        return vec![t.iter().collect()];
    }
    let pts = joints(&t);
    // The best even break whose two halves both fit, and the last joint whose
    // first half fits.
    let mut best: Option<(usize, String, String)> = None;
    let mut last_fit = None;
    for &p in &pts {
        let (x, y) = (trimmed(&t[..p]), trimmed(&t[p..]));
        let (lx, ly) = (x.chars().count(), y.chars().count());
        let gap = lx.abs_diff(ly);
        if lx <= STRIP_CHARS && ly <= STRIP_CHARS && best.as_ref().is_none_or(|(g, _, _)| gap < *g)
        {
            best = Some((gap, x, y));
        }
        if lx <= STRIP_CHARS {
            last_fit = Some(p);
        }
    }
    if let Some((_, x, y)) = best {
        return vec![x, y];
    }
    if let Some(p) = last_fit {
        return vec![trimmed(&t[..p]), cut_tail(&trimmed(&t[p..]))];
    }
    let cut = format!("{}…", first_chars(&t, STRIP_CHARS - 1));
    match pts.first() {
        None => vec![cut],
        Some(&p) => vec![cut, cut_tail(&trimmed(&t[p..]))],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watchdog::Device;

    // -- the label strip ---------------------------------------------------------

    fn strip(name: &str) -> Vec<String> {
        strip_lines(name)
    }

    #[test]
    fn a_strip_breaks_the_mockups_names_where_they_have_a_joint() {
        assert_eq!(strip("Living room TV"), ["Living", "room TV"]);
        assert_eq!(strip("Kitchen speaker"), ["Kitchen", "speaker"]);
        assert_eq!(strip("Smart plug 1"), ["Smart", "plug 1"]);
        assert_eq!(strip("Weather station"), ["Weather", "station"]);
        assert_eq!(strip("Sam's phone"), ["Sam's", "phone"]);
        assert_eq!(strip("Bedroom TV"), ["Bedroom", "TV"]);
        assert_eq!(strip("Work laptop"), ["Work", "laptop"]);
        assert_eq!(strip("Game console"), ["Game", "console"]);
        assert_eq!(strip("Garage door"), ["Garage", "door"]);
        assert_eq!(strip("Baby monitor"), ["Baby", "monitor"]);
    }

    #[test]
    fn a_name_that_fits_one_line_stays_on_it() {
        assert_eq!(strip("Doorbell"), ["Doorbell"]);
        assert_eq!(strip("NAS"), ["NAS"]);
        assert_eq!(strip("Printer"), ["Printer"]);
        assert_eq!(strip("This PC"), ["This PC"]);
        assert_eq!(strip("12345678"), ["12345678"]);
        assert_eq!(strip("  Tablet  "), ["Tablet"], "trimmed");
    }

    #[test]
    fn no_name_gives_no_lines() {
        assert!(strip("").is_empty());
        assert!(strip("   ").is_empty());
    }

    #[test]
    fn a_name_without_a_joint_is_cut_at_seven_with_an_ellipsis() {
        assert_eq!(strip("Thermostat"), ["Thermos…"]);
        assert_eq!(strip("123456789"), ["1234567…"]);
    }

    #[test]
    fn a_first_line_that_fits_and_a_rest_that_does_not_cuts_the_rest() {
        assert_eq!(strip("Streaming stick"), ["Streami…", "stick"]);
        assert_eq!(strip("Hall Light Switch Left"), ["Hall", "Light…"]);
        assert_eq!(strip("tv-livingroom"), ["tv-", "livingr…"]);
        assert_eq!(strip("Alex's old Galaxy phone"), ["Alex's", "old…"]);
    }

    #[test]
    fn the_most_even_break_wins_and_the_first_of_equals() {
        // Joints at 2, 5, 8 and 11: the halves 5 and 7 are the most even.
        assert_eq!(strip("ab cd ef gh i"), ["ab cd", "ef gh i"]);
        // Joints at 1 and 8, both 7 apart: the first.
        assert_eq!(strip("a bcdefg h"), ["a", "bcdefg h"]);
    }

    #[test]
    fn a_strip_breaks_at_a_case_change_a_digit_and_after_a_punctuation_mark() {
        assert_eq!(
            strip("LivingRoom"),
            ["Living", "Room"],
            "lower to upper case"
        );
        assert_eq!(
            strip("Echo2Kitchen"),
            ["Echo", "2Kitchen"],
            "letter to digit"
        );
        assert_eq!(strip("Living.Room.TV"), ["Living.", "Room.TV"]);
        assert_eq!(strip("Room-1-Left"), ["Room-", "1-Left"]);
        assert_eq!(strip("cam_front_door"), ["cam_", "front_…"]);
    }

    #[test]
    fn a_strip_counts_characters_not_bytes() {
        // Nine two-byte characters, no joint.
        assert_eq!(strip("ÄÖÜÄÖÜÄÖÜ"), ["ÄÖÜÄÖÜÄ…"]);
        assert_eq!(strip("Zimmer-Küche"), ["Zimmer-", "Küche"]);
        assert_eq!(strip("Küchenradio"), ["Küchenr…"]);
        assert_eq!(
            strip("Café Zoë"),
            ["Café Zoë"],
            "eight characters, ten bytes"
        );
    }

    /// What the mockup's own `strip2` says for each of these names (the table
    /// was made by running that function from `index.html` on them).
    const MOCKUP: &[(&str, &[&str])] = &[
        ("Living room TV", &["Living", "room TV"]),
        ("Kitchen speaker", &["Kitchen", "speaker"]),
        ("Streaming stick", &["Streami…", "stick"]),
        ("Thermostat", &["Thermos…"]),
        ("Doorbell", &["Doorbell"]),
        ("Smart plug 1", &["Smart", "plug 1"]),
        ("Weather station", &["Weather", "station"]),
        ("Sam's phone", &["Sam's", "phone"]),
        ("Bedroom TV", &["Bedroom", "TV"]),
        ("Work laptop", &["Work", "laptop"]),
        ("Game console", &["Game", "console"]),
        ("Garage door", &["Garage", "door"]),
        ("Baby monitor", &["Baby", "monitor"]),
        ("Porch camera", &["Porch", "camera"]),
        ("Yard camera", &["Yard", "camera"]),
        ("Alex's phone", &["Alex's", "phone"]),
        ("Smart plug 2", &["Smart", "plug 2"]),
        ("Old laptop", &["Old", "laptop"]),
        ("Guest phone", &["Guest", "phone"]),
        ("E-reader", &["E-reader"]),
        ("Vacuum", &["Vacuum"]),
        ("Soundbar", &["Soundbar"]),
        ("NAS", &["NAS"]),
        ("Printer", &["Printer"]),
        ("This PC", &["This PC"]),
        ("Tablet", &["Tablet"]),
        ("router", &["router"]),
        ("qbp", &["qbp"]),
        ("Echo2Kitchen", &["Echo", "2Kitchen"]),
        ("Big TVroom", &["Big", "TVroom"]),
        ("a bcdefg h", &["a", "bcdefg h"]),
        ("ab cd ef gh i", &["ab cd", "ef gh i"]),
        ("LivingRoom", &["Living", "Room"]),
        ("cam_front_door", &["cam_", "front_…"]),
        ("tv-livingroom", &["tv-", "livingr…"]),
        ("Hall Light Switch Left", &["Hall", "Light…"]),
        ("Alex's old Galaxy phone", &["Alex's", "old…"]),
        ("Zimmer-Küche", &["Zimmer-", "Küche"]),
        ("Küchenradio", &["Küchenr…"]),
        ("Café Zoë", &["Café Zoë"]),
        ("ÄÖÜÄÖÜÄÖÜ", &["ÄÖÜÄÖÜÄ…"]),
        ("123456789", &["1234567…"]),
        ("12345678", &["12345678"]),
        ("1234567890123456", &["1234567…"]),
        ("Dad's iPhone 14 Pro", &["Dad's i", "Phone…"]),
        ("iPhone14Pro", &["iPhone", "14Pro"]),
        ("MacBookPro", &["Mac", "BookPro"]),
        ("Living.Room.TV", &["Living.", "Room.TV"]),
        ("a/b/c/d/e/f/g/h/i", &["a/b/c/d/", "e/f/g/…"]),
        ("ThisIsAVeryLongDeviceName", &["ThisIs", "AVery…"]),
        ("Front door camera 2", &["Front", "door…"]),
        ("Lights 1", &["Lights 1"]),
        ("x", &["x"]),
        ("xx xx xx xx xx xx xx", &["xx xx xx", "xx xx…"]),
        ("abcdefgh ijklmnop", &["abcdefgh", "ijklmnop"]),
        ("abcdefghi jklmnop", &["abcdefg…", "jklmnop"]),
        ("abcdefgh ijklmnopq", &["abcdefgh", "ijklmno…"]),
        ("abcdefghijkl mnop", &["abcdefg…", "mnop"]),
        ("Mom & Dad's room", &["Mom &", "Dad's…"]),
        ("Room-1-Left", &["Room-", "1-Left"]),
        ("Room 12 Left Light", &["Room 12", "Left…"]),
        ("HP LaserJet", &["HP Laser", "Jet"]),
        ("Raspberry Pi 4 Model B", &["Raspber…", "Pi 4…"]),
        ("Pi-hole", &["Pi-hole"]),
        ("ESP32-Cam", &["ESP", "32-Cam"]),
        ("Sam's  phone", &["Sam's", "phone"]),
        ("-leading", &["-leading"]),
        ("trailing-", &["trailin…"]),
        ("a-b", &["a-b"]),
        ("Kitchen", &["Kitchen"]),
        ("Kitchen Hub", &["Kitchen", "Hub"]),
        ("Master bedroom speaker", &["Master", "bedroom…"]),
        ("TV", &["TV"]),
        ("Roku Ultra 4800R", &["Roku", "Ultra…"]),
    ];

    #[test]
    fn a_strip_agrees_with_the_mockups_strip2_on_every_name_of_a_table() {
        for (name, lines) in MOCKUP {
            assert_eq!(strip(name), *lines, "{name:?}");
        }
    }

    // -- the rules, one device at a time ------------------------------------------

    const NOW: u64 = 1_794_122_700;

    fn mac_of(n: u32) -> String {
        format!("02:00:00:00:{:02x}:{:02x}", n >> 8, n & 0xff)
    }

    /// A device at 192.0.2.n that this PC and the Pi both know, with nothing
    /// else to say.
    fn dev(n: u32) -> ReportDevice {
        ReportDevice {
            device: Device {
                mac: mac_of(n),
                ipv4: vec![format!("192.0.2.{n}")],
                hostname: String::new(),
                first_unix: 1_793_000_000 + n as u64,
                last_unix: NOW - 30,
                known: true,
                exempt: false,
                blocked: false,
                label: None,
                gate_left_secs: None,
                fixed: false,
                always: false,
            },
            known: true,
            label: String::new(),
            exempt: false,
            blocked: false,
        }
    }

    fn named(n: u32, label: &str) -> ReportDevice {
        let mut d = dev(n);
        d.label = label.into();
        d
    }

    fn alert(id: u64, kind: &str, severity: &str, client: Option<&str>, subject: &str) -> Alert {
        Alert {
            id,
            key: format!("a1b2c3d4{id:08x}"),
            rev: id,
            kind: kind.into(),
            severity: severity.into(),
            client: client.map(String::from),
            subject: subject.into(),
            first_unix: NOW - 600 + id,
            last_unix: NOW - 300 + id,
            count: 1,
            acked: false,
        }
    }

    fn offline_of(n: u32, label: &str) -> OfflineEntry {
        OfflineEntry {
            mac: mac_of(n),
            label: label.into(),
            first_seen: 1_793_000_000 + n as u64,
            known: true,
            exempt: false,
            block: false,
        }
    }

    fn board(devices: &[ReportDevice], alerts: &[Alert], exempt_default: bool) -> BayOut {
        board_with(devices, &[], alerts, exempt_default)
    }

    fn board_with(
        devices: &[ReportDevice],
        offline: &[OfflineEntry],
        alerts: &[Alert],
        exempt_default: bool,
    ) -> BayOut {
        build(&Input {
            devices,
            offline,
            alerts,
            exempt_default,
            devices_at: NOW - 60,
        })
    }

    fn jack(b: &BayOut, n: u32) -> &JackOut {
        b.jacks
            .iter()
            .find(|j| j.mac == mac_of(n))
            .unwrap_or_else(|| panic!("no jack ·{n}: {:?}", b.jacks))
    }

    fn wiring_of(b: &BayOut, n: u32) -> (&'static str, &'static str, bool) {
        let j = jack(b, n);
        (j.patch, j.row, j.cord)
    }

    #[test]
    fn with_the_mode_off_the_normal_wire_blocks_and_an_adspass_entry_is_a_cord() {
        let mut passed = dev(2);
        passed.exempt = true;
        let mut also_blocked = dev(3);
        also_blocked.blocked = true; // the block list says nothing in this mode
        let b = board(&[dev(1), passed, also_blocked], &[], false);
        assert_eq!(wiring_of(&b, 1), ("blocked", "blocked", false));
        assert_eq!(wiring_of(&b, 2), ("pass", "pass", true));
        assert_eq!(wiring_of(&b, 3), ("blocked", "blocked", false));
    }

    #[test]
    fn with_the_mode_on_the_normal_wire_passes_and_a_block_entry_is_a_cord() {
        let mut blocked = dev(2);
        blocked.blocked = true;
        let mut also_passed = dev(3);
        also_passed.exempt = true; // the ADS PASS list says nothing in this mode
        let b = board(&[dev(1), blocked, also_passed], &[], true);
        assert_eq!(wiring_of(&b, 1), ("pass", "pass", false));
        assert_eq!(wiring_of(&b, 2), ("blocked", "blocked", true));
        assert_eq!(wiring_of(&b, 3), ("pass", "pass", false));
    }

    #[test]
    fn always_is_a_rivet_to_the_blocked_row_whatever_the_lists_and_the_mode_say() {
        let mut router = dev(1);
        router.device.always = true;
        router.device.fixed = true; // always comes first
        router.device.exempt = true;
        router.exempt = true;
        router.blocked = true;
        for mode in [false, true] {
            let b = board(&[router.clone()], &[], mode);
            assert_eq!(
                wiring_of(&b, 1),
                ("always", "blocked", false),
                "mode {mode}"
            );
        }
    }

    #[test]
    fn fixed_rides_the_row_the_pi_says_and_the_pcs_lists_do_not_move_it() {
        let mut passes = dev(1);
        passes.device.fixed = true;
        passes.device.exempt = true;
        let mut blocks = dev(2);
        blocks.device.fixed = true;
        blocks.exempt = true; // this PC's list is not what decides it
        for mode in [false, true] {
            let b = board(&[passes.clone(), blocks.clone()], &[], mode);
            assert_eq!(wiring_of(&b, 1), ("fixed", "pass", false), "mode {mode}");
            assert_eq!(wiring_of(&b, 2), ("fixed", "blocked", false), "mode {mode}");
        }
    }

    #[test]
    fn a_gate_shuts_at_the_time_of_the_read_plus_the_seconds_left() {
        let mut gated = dev(1);
        gated.device.gate_left_secs = Some(872);
        let b = build(&Input {
            devices: &[gated.clone(), dev(2)],
            offline: &[],
            alerts: &[],
            exempt_default: false,
            devices_at: NOW,
        });
        assert_eq!(jack(&b, 1).gate_until, Some(NOW + 872));
        assert_eq!(jack(&b, 2).gate_until, None);
        // The seconds left count from the read, not from when the state is built.
        let c = build(&Input {
            devices: &[gated.clone()],
            offline: &[],
            alerts: &[],
            exempt_default: false,
            devices_at: NOW - 5,
        });
        assert_eq!(jack(&c, 1).gate_until, Some(NOW - 5 + 872));
        // Without a read there is nothing to count from.
        let d = build(&Input {
            devices: &[gated],
            offline: &[],
            alerts: &[],
            exempt_default: false,
            devices_at: 0,
        });
        assert_eq!(jack(&d, 1).gate_until, None);
    }

    #[test]
    fn the_name_is_this_pcs_label_then_the_pis_then_none() {
        let mut both = named(1, "Desk");
        both.device.label = Some("Pi's name".into());
        let mut pi_only = dev(2);
        pi_only.device.label = Some("Pi's name".into());
        let b = board(&[both, pi_only, dev(3)], &[], false);
        assert_eq!(
            (jack(&b, 1).name.as_str(), &jack(&b, 1).strip[..]),
            ("Desk", &["Desk".to_string()][..])
        );
        assert_eq!(jack(&b, 2).name, "Pi's name");
        assert_eq!(jack(&b, 2).strip, ["Pi's", "name"]);
        assert_eq!(jack(&b, 3).name, "");
        assert!(jack(&b, 3).strip.is_empty());
    }

    #[test]
    fn the_tail_is_the_last_octet_or_the_last_mac_byte() {
        let mut v6 = dev(0xd9);
        v6.device.ipv4.clear();
        let b = board(&[dev(40), v6, dev(216)], &[], false);
        assert_eq!(jack(&b, 40).tail, "·40");
        assert_eq!(jack(&b, 40).ip, "192.0.2.40");
        assert_eq!(jack(&b, 216).tail, "·216");
        assert_eq!(jack(&b, 0xd9).tail, ":d9");
        assert_eq!(jack(&b, 0xd9).ip, "");
    }

    #[test]
    fn new_means_neither_this_pc_nor_the_pi_counts_it_known() {
        let mut neither = dev(1);
        neither.known = false;
        neither.device.known = false;
        let mut only_pi = dev(2);
        only_pi.known = false;
        let mut only_pc = dev(3);
        only_pc.device.known = false;
        let b = board(&[neither, only_pi, only_pc, dev(4)], &[], false);
        assert_eq!(
            [1, 2, 3, 4].map(|n| (jack(&b, n).known, jack(&b, n).is_new)),
            [(false, true), (false, false), (true, false), (true, false)]
        );
    }

    #[test]
    fn a_jack_carries_what_the_pi_said() {
        let mut d = dev(40);
        d.device.hostname = "tv-40".into();
        let b = board(&[d.clone()], &[], false);
        let j = jack(&b, 40);
        assert_eq!(j.hostname, "tv-40");
        assert_eq!(
            (j.first_unix, j.last_unix),
            (d.device.first_unix, d.device.last_unix)
        );
        assert!(!j.offline);
        assert_eq!((j.lamp, j.alert_id), ("", None));
    }

    // -- which jack an alert rings -------------------------------------------------

    #[test]
    fn a_threat_rings_the_jack_that_holds_its_client() {
        let a = alert(
            5,
            "threat",
            "high",
            Some("192.0.2.40"),
            "malware.example.org",
        );
        let b = board(&[dev(40), dev(41)], &[a], false);
        assert_eq!(
            (jack(&b, 40).lamp, jack(&b, 40).alert_id),
            ("high", Some(5))
        );
        assert_eq!((jack(&b, 41).lamp, jack(&b, 41).alert_id), ("", None));
        assert_eq!(b.calls[0].mac.as_deref(), Some(mac_of(40).as_str()));
        assert_eq!(b.calls[0].related_mac, None);
    }

    #[test]
    fn a_new_device_rings_the_jack_whose_address_is_the_subject_in_any_case() {
        let upper = mac_of(216).to_uppercase();
        let a = alert(6, "new_device", "warn", None, &upper);
        let b = board(&[dev(40), dev(216)], &[a], false);
        assert_eq!(
            (jack(&b, 216).lamp, jack(&b, 216).alert_id),
            ("warn", Some(6))
        );
        assert_eq!(jack(&b, 40).alert_id, None);
        assert_eq!(b.calls[0].mac.as_deref(), Some(mac_of(216).as_str()));
        // The client of a new_device alert (if the Pi gave one) is not the key.
        let c = alert(7, "new_device", "warn", Some("192.0.2.40"), &mac_of(216));
        let b = board(&[dev(40), dev(216)], &[c], false);
        assert_eq!(jack(&b, 40).alert_id, None);
        assert_eq!(jack(&b, 216).alert_id, Some(7));
    }

    #[test]
    fn an_arp_spoof_rings_no_jack_and_names_the_second_card() {
        // `client` is the router's address, `subject` the second card.
        let a = alert(8, "arp_spoof", "high", Some("192.0.2.1"), &mac_of(216));
        let b = board(&[dev(1), dev(216)], std::slice::from_ref(&a), false);
        assert!(b
            .jacks
            .iter()
            .all(|j| j.alert_id.is_none() && j.lamp.is_empty()));
        let call = &b.calls[0];
        assert_eq!(call.mac, None);
        assert_eq!(call.related_mac.as_deref(), Some(mac_of(216).as_str()));
        assert_eq!(call.lamp, "arp_spoof");
        // No jack for the second card: no related MAC either.
        let b = board(&[dev(1)], &[a], false);
        assert_eq!(
            (b.calls[0].mac.clone(), b.calls[0].related_mac.clone()),
            (None, None)
        );
        // The lamp still rings.
        assert_eq!(
            (b.lamps[2].kind, b.lamps[2].count, b.lamps[2].tone),
            ("arp_spoof", 1, "high")
        );
    }

    #[test]
    fn other_and_unknown_kinds_look_up_the_client_and_ring_the_lookups_lamp() {
        let kinds = ["dga", "tunnel", "beacon", "burst", "something_new"];
        let alerts: Vec<Alert> = kinds
            .iter()
            .enumerate()
            .map(|(n, k)| {
                alert(
                    10 + n as u64,
                    k,
                    "warn",
                    Some("192.0.2.40"),
                    "x.example.org",
                )
            })
            .collect();
        let b = board(&[dev(40)], &alerts, false);
        assert!(b.calls.iter().all(|c| c.lamp == "lookups"));
        assert_eq!(b.calls.len(), 5);
        let lookups = &b.lamps[4];
        assert_eq!((lookups.kind, lookups.count), ("lookups", 5));
        assert!(b.lamps[..4].iter().all(|l| l.count == 0));
        assert_eq!(jack(&b, 40).alert_id, Some(14), "the newest of five");
    }

    #[test]
    fn a_client_that_is_no_device_on_the_board_rings_the_lamp_only() {
        let a = alert(
            9,
            "threat",
            "high",
            Some("192.0.2.99"),
            "malware.example.org",
        );
        let none = alert(10, "dga", "warn", None, "x.example.org");
        let b = board(&[dev(40)], &[a, none], false);
        assert!(b.jacks.iter().all(|j| j.alert_id.is_none()));
        assert!(b.calls.iter().all(|c| c.mac.is_none()));
        assert_eq!(b.calls.len(), 2);
        assert_eq!((b.lamps[0].count, b.lamps[0].tone), (1, "high"));
    }

    #[test]
    fn a_device_with_several_addresses_answers_to_each() {
        let mut d = dev(40);
        d.device.ipv4.push("192.0.2.141".into());
        let a = alert(9, "threat", "warn", Some("192.0.2.141"), "x.example.org");
        let b = board(&[d], &[a], false);
        assert_eq!(jack(&b, 40).alert_id, Some(9));
        assert_eq!(jack(&b, 40).ip, "192.0.2.40", "the first is the one shown");
    }

    #[test]
    fn an_address_held_by_two_devices_belongs_to_the_one_seen_last() {
        let mut old = dev(40);
        old.device.last_unix = NOW - 5000;
        let mut now = dev(41);
        now.device.ipv4 = vec!["192.0.2.40".into()];
        let a = alert(9, "threat", "warn", Some("192.0.2.40"), "x.example.org");
        let b = board(&[old.clone(), now.clone()], std::slice::from_ref(&a), false);
        assert_eq!(jack(&b, 41).alert_id, Some(9));
        assert_eq!(jack(&b, 40).alert_id, None);
        let b = board(&[now, old], &[a], false);
        assert_eq!(jack(&b, 41).alert_id, Some(9), "whatever the order");
    }

    #[test]
    fn an_acknowledged_alert_rings_nothing_and_is_no_call() {
        let mut a = alert(5, "threat", "high", Some("192.0.2.40"), "x.example.org");
        a.acked = true;
        let b = board(&[dev(40)], &[a], false);
        assert_eq!(jack(&b, 40).alert_id, None);
        assert!(b.calls.is_empty());
        assert!(b
            .lamps
            .iter()
            .all(|l| l.count == 0 && l.tone.is_empty() && l.alert_id.is_none()));
    }

    #[test]
    fn a_jack_shows_its_newest_alert_and_that_ones_tone() {
        let mut older = alert(5, "threat", "high", Some("192.0.2.40"), "a.example.org");
        older.last_unix = NOW - 900;
        let mut newer = alert(6, "dga", "info", Some("192.0.2.40"), "b.example.org");
        newer.last_unix = NOW - 100;
        let b = board(&[dev(40)], &[older, newer], false);
        // `info` reads as a warn.
        assert_eq!(
            (jack(&b, 40).lamp, jack(&b, 40).alert_id),
            ("warn", Some(6))
        );
        assert_eq!(b.calls.iter().map(|c| c.id).collect::<Vec<_>>(), [6, 5]);
        assert_eq!(b.calls[0].tone, "warn");
        assert_eq!(b.calls[0].severity, "info");
        assert_eq!(b.calls[1].tone, "high");
    }

    // -- ranks and the order --------------------------------------------------------

    #[test]
    fn ranks_are_alerting_or_new_then_labelled_then_the_rest_then_offline() {
        let mut fresh = dev(216);
        fresh.known = false;
        fresh.device.known = false;
        let alerting = dev(40);
        let labelled = named(12, "Work laptop");
        let mut pi_labelled = dev(13);
        pi_labelled.device.label = Some("Pi's name".into());
        let plain = dev(101);
        let a = alert(5, "threat", "high", Some("192.0.2.40"), "x.example.org");
        let off = offline_of(15, "Old laptop");
        let b = board_with(
            &[plain, labelled, alerting, fresh, pi_labelled],
            &[off],
            &[a],
            false,
        );
        assert_eq!(
            b.jacks
                .iter()
                .map(|j| (j.tail.as_str(), j.rank))
                .collect::<Vec<_>>(),
            [
                ("·40", 0),
                ("·216", 0),
                ("·12", 1),
                ("·13", 1),
                ("·101", 2),
                (":0f", 3),
            ]
        );
    }

    #[test]
    fn a_labelled_alerting_device_is_rank_zero_and_an_alert_on_an_offline_one_keeps_it_last() {
        let a = alert(5, "new_device", "warn", None, &mac_of(15));
        let b = board_with(
            &[named(12, "Work laptop")],
            &[offline_of(15, "")],
            &[a],
            false,
        );
        assert_eq!(
            jack(&b, 15).alert_id,
            Some(5),
            "the jack exists, so it rings"
        );
        assert_eq!(jack(&b, 15).rank, 3);
        assert_eq!(b.jacks.last().unwrap().mac, mac_of(15));
    }

    #[test]
    fn within_a_rank_addresses_go_by_number_and_devices_without_one_by_mac() {
        let mut no_ip_b = dev(0xb0);
        no_ip_b.device.ipv4.clear();
        let mut no_ip_a = dev(0xa0);
        no_ip_a.device.ipv4.clear();
        let b = board(
            &[dev(100), no_ip_b, dev(9), dev(10), no_ip_a, dev(2)],
            &[],
            false,
        );
        assert_eq!(
            b.jacks.iter().map(|j| j.tail.as_str()).collect::<Vec<_>>(),
            ["·2", "·9", "·10", "·100", ":a0", ":b0"]
        );
    }

    #[test]
    fn the_board_holds_the_pis_devices_then_this_pcs_offline_ones() {
        let b = board_with(
            &[dev(2), dev(1)],
            &[offline_of(0x66, "Soundbar"), offline_of(0x0f, "Old laptop")],
            &[],
            false,
        );
        assert_eq!(
            b.jacks
                .iter()
                .map(|j| (j.tail.as_str(), j.offline))
                .collect::<Vec<_>>(),
            [("·1", false), ("·2", false), (":0f", true), (":66", true)]
        );
    }

    // -- offline entries --------------------------------------------------------------

    #[test]
    fn an_offline_jack_has_no_address_no_gate_and_no_last_seen() {
        let b = board_with(&[], &[offline_of(0x0f, "Old laptop")], &[], false);
        let j = jack(&b, 0x0f);
        assert_eq!(
            (
                j.ip.as_str(),
                j.tail.as_str(),
                j.hostname.as_str(),
                j.name.as_str()
            ),
            ("", ":0f", "", "Old laptop")
        );
        assert_eq!(j.strip, ["Old", "laptop"]);
        assert_eq!(
            (j.offline, j.rank, j.known, j.is_new),
            (true, 3, true, false)
        );
        assert_eq!(
            (j.first_unix, j.last_unix, j.gate_until),
            (1_793_000_000 + 15, 0, None)
        );
        assert_eq!((j.patch, j.row, j.cord), ("blocked", "blocked", false));
    }

    #[test]
    fn an_offline_entry_follows_the_wiring_of_its_lists_in_both_modes() {
        let mut passed = offline_of(2, "A");
        passed.known = false;
        passed.exempt = true;
        let mut blocked = offline_of(3, "B");
        blocked.known = false;
        blocked.block = true;
        let both = [passed, blocked, offline_of(4, "C")];
        let off = board_with(&[], &both, &[], false);
        assert_eq!(wiring_of(&off, 2), ("pass", "pass", true));
        assert_eq!(wiring_of(&off, 3), ("blocked", "blocked", false));
        assert_eq!(wiring_of(&off, 4), ("blocked", "blocked", false));
        let on = board_with(&[], &both, &[], true);
        assert_eq!(wiring_of(&on, 2), ("pass", "pass", false));
        assert_eq!(wiring_of(&on, 3), ("blocked", "blocked", true));
        assert_eq!(wiring_of(&on, 4), ("pass", "pass", false));
        // Not on the known list, and not new either: it was seen once.
        assert_eq!((jack(&on, 2).known, jack(&on, 2).is_new), (false, false));
    }

    #[test]
    fn an_offline_entry_that_the_pi_reports_after_all_is_one_jack() {
        let b = board_with(&[dev(2)], &[offline_of(2, "Stale")], &[], false);
        assert_eq!(b.jacks.len(), 1);
        assert!(!b.jacks[0].offline);
    }

    // -- the flip count ----------------------------------------------------------------

    #[test]
    fn the_flip_counts_the_blocked_devices_that_would_start_to_pass() {
        let mut router = dev(1);
        router.device.always = true;
        let mut printer = dev(31);
        printer.device.fixed = true;
        let mut passed = dev(40);
        passed.exempt = true; // already passes by its cord
        let mut pinned = dev(10);
        pinned.blocked = true; // a block-list entry keeps it blocked after a flip
        let mut gated = dev(23);
        gated.device.gate_left_secs = Some(872); // sees ads already
        let counted = [dev(51), dev(216)];
        let mut all = vec![router, printer, passed, pinned, gated];
        all.extend(counted);
        let off = [offline_of(0x0f, "Old laptop")];
        let b = board_with(&all, &off, &[], false);
        assert_eq!(b.flip_count, 3, "·51, ·216 and the offline one");
        // Nothing to flip when the mode is on already.
        let b = board_with(&all, &off, &[], true);
        assert_eq!(b.flip_count, 0);
    }

    // -- the lamps and the calls ----------------------------------------------------------

    #[test]
    fn five_dark_lamps_without_alerts_and_a_quiet_since_of_zero() {
        let b = board(&[dev(1)], &[], false);
        assert_eq!(
            b.lamps.iter().map(|l| l.kind).collect::<Vec<_>>(),
            ["threat", "new_device", "arp_spoof", "rebind", "lookups"]
        );
        assert!(b
            .lamps
            .iter()
            .all(|l| l.count == 0 && l.tone.is_empty() && l.alert_id.is_none()));
        assert!(b.calls.is_empty());
        assert_eq!(b.quiet_since, 0);
        assert_eq!(BayOut::empty(), board(&[], &[], false));
    }

    #[test]
    fn a_lamp_counts_its_calls_takes_the_worst_tone_and_points_at_the_newest() {
        let mut t1 = alert(1, "threat", "warn", Some("192.0.2.40"), "a.example.org");
        t1.last_unix = NOW - 400;
        let mut t2 = alert(2, "threat", "high", Some("192.0.2.40"), "b.example.org");
        t2.last_unix = NOW - 500;
        let mut t3 = alert(3, "threat", "warn", Some("192.0.2.41"), "c.example.org");
        t3.last_unix = NOW - 100;
        let reb = alert(4, "rebind", "warn", None, "d.example.org");
        let b = board(&[dev(40)], &[t1, t2, t3, reb], false);
        let threat = &b.lamps[0];
        assert_eq!(
            (threat.count, threat.tone, threat.alert_id),
            (3, "high", Some(3))
        );
        let rebind = &b.lamps[3];
        assert_eq!(
            (rebind.count, rebind.tone, rebind.alert_id),
            (1, "warn", Some(4))
        );
        assert_eq!((b.lamps[1].count, b.lamps[1].tone), (0, ""));
    }

    #[test]
    fn calls_are_the_unacknowledged_alerts_newest_first_with_every_field() {
        let mut first = alert(
            1,
            "threat",
            "high",
            Some("192.0.2.40"),
            "malware.example.org",
        );
        first.count = 3;
        first.first_unix = NOW - 900;
        first.last_unix = NOW - 700;
        let mut second = alert(2, "new_device", "warn", None, &mac_of(216));
        second.last_unix = NOW - 200;
        let mut done = alert(3, "dga", "warn", None, "x.example.org");
        done.acked = true;
        done.last_unix = NOW - 50;
        let b = board(
            &[dev(40), dev(216)],
            &[first.clone(), second.clone(), done],
            false,
        );
        assert_eq!(b.calls.len(), 2);
        assert_eq!(
            b.calls[0],
            CallOut {
                id: 2,
                key: second.key.clone(),
                kind: "new_device".into(),
                lamp: "new_device",
                severity: "warn".into(),
                tone: "warn",
                mac: Some(mac_of(216)),
                related_mac: None,
                subject: mac_of(216),
                count: 1,
                first_unix: second.first_unix,
                last_unix: NOW - 200,
            }
        );
        assert_eq!(
            b.calls[1],
            CallOut {
                id: 1,
                key: first.key,
                kind: "threat".into(),
                lamp: "threat",
                severity: "high".into(),
                tone: "high",
                mac: Some(mac_of(40)),
                related_mac: None,
                subject: "malware.example.org".into(),
                count: 3,
                first_unix: NOW - 900,
                last_unix: NOW - 700,
            }
        );
    }

    #[test]
    fn quiet_since_is_the_newest_alert_acknowledged_or_not() {
        let mut gone = alert(1, "dga", "warn", None, "x.example.org");
        gone.acked = true;
        gone.last_unix = NOW - 20;
        let mut live = alert(2, "dga", "warn", None, "y.example.org");
        live.last_unix = NOW - 400;
        let b = board(&[], &[live, gone], false);
        assert_eq!(b.quiet_since, NOW - 20);
        assert_eq!(b.calls.len(), 1);
    }

    #[test]
    fn calls_with_the_same_time_come_by_revision_then_id() {
        let mut a = alert(1, "dga", "warn", None, "a.example.org");
        let mut b2 = alert(2, "dga", "warn", None, "b.example.org");
        let mut c = alert(3, "dga", "warn", None, "c.example.org");
        for x in [&mut a, &mut b2, &mut c] {
            x.last_unix = NOW - 10;
        }
        a.rev = 9;
        let b = board(&[], &[a, b2, c], false);
        assert_eq!(b.calls.iter().map(|x| x.id).collect::<Vec<_>>(), [1, 3, 2]);
    }

    #[test]
    fn the_json_is_camel_case_with_the_plans_keys() {
        let a = alert(5, "threat", "high", Some("192.0.2.40"), "x.example.org");
        let b = board_with(&[dev(40)], &[offline_of(15, "Old")], &[a], false);
        let v = serde_json::to_value(&b).unwrap();
        let keys = |x: &serde_json::Value| -> Vec<String> {
            x.as_object().unwrap().keys().cloned().collect()
        };
        let mut want: Vec<String> = [
            "alertId",
            "cord",
            "firstUnix",
            "gateUntil",
            "hostname",
            "ip",
            "isNew",
            "known",
            "lamp",
            "lastUnix",
            "mac",
            "name",
            "offline",
            "patch",
            "rank",
            "row",
            "strip",
            "tail",
        ]
        .map(String::from)
        .to_vec();
        want.sort();
        let mut got = keys(&v["jacks"][0]);
        got.sort();
        assert_eq!(got, want);
        assert_eq!(
            keys(&v),
            ["calls", "flipCount", "jacks", "lamps", "quietSince"]
        );
        assert_eq!(v["lamps"][1]["alertId"], serde_json::Value::Null);
        assert_eq!(v["jacks"][0]["gateUntil"], serde_json::Value::Null);
        assert_eq!(v["calls"][0]["relatedMac"], serde_json::Value::Null);
    }
}

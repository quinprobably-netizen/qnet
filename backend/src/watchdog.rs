//! Support for the qberrypi watchdog: the `/api/qbp/` calls behind the
//! Pi-hole login, the tolerant parsers for their answers, notification text
//! (titles, markup escaping, burst folding) and the chunking of the two
//! lists that are pushed to the Pi (acknowledged alerts, known devices).
//!
//! A real Pi-hole answers 404 on every `/api/qbp/` path. The calls here turn
//! that into [`Qbp::Absent`], so the caller can treat the watchdog as not
//! there and behave exactly as it did before.

// Tasks 2 and 3 (the watcher cycle and the CLI verbs) wire these items in.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};

use serde_json::{json, Value};

use crate::pihole::{ApiError, Pihole};

/// The largest request body sent to the Pi: its cap is 4096 bytes, this
/// leaves room for the headers' share of whatever the Pi counts.
pub const QBP_BODY_MAX: usize = 4000;

/// Alerts kept from one answer (the newest changes).
pub const MAX_ALERTS: usize = 256;
/// Devices kept from one answer (the ones seen last).
pub const MAX_DEVICES: usize = 512;
/// IPv4 addresses kept per device.
pub const MAX_IPV4: usize = 4;
/// Longest subject kept, in bytes.
pub const SUBJECT_MAX: usize = 255;
/// Longest host name kept, in bytes.
pub const HOSTNAME_MAX: usize = 64;
/// Longest notification title or body, in characters.
pub const NOTIFY_MAX: usize = 200;

/// At most this many individual notifications per [`FOLD_WINDOW_S`].
pub const FOLD_LIMIT: usize = 3;
/// The rolling window of [`Folder`], in seconds.
pub const FOLD_WINDOW_S: u64 = 60;

// -- wire types ---------------------------------------------------------------

/// One alert as the Pi reports it, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// Restarts at a Pi reboot; use `key` to recognise an alert across one.
    pub id: u64,
    /// 16 lower-case hex digits, stable across Pi reboots.
    pub key: String,
    /// The Pi's revision of the last change to this alert.
    pub rev: u64,
    /// 1 to 32 characters of `[a-z0-9_]`.
    pub kind: String,
    /// `info`, `warn` or `high`.
    pub severity: String,
    /// The client's address in canonical text form, when it names one.
    pub client: Option<String>,
    /// Control characters removed, at most [`SUBJECT_MAX`] bytes.
    pub subject: String,
    pub first_unix: u64,
    pub last_unix: u64,
    /// How often it was raised (1 when the Pi did not say).
    pub count: u64,
    pub acked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertsPage {
    pub rev: u64,
    pub suppressed: u64,
    /// Oldest change first, as the Pi sent them.
    pub alerts: Vec<Alert>,
}

/// One device the Pi has heard, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Lower-case colon form.
    pub mac: String,
    /// At most [`MAX_IPV4`] addresses in canonical text form.
    pub ipv4: Vec<String>,
    /// Control characters removed, at most [`HOSTNAME_MAX`] bytes.
    pub hostname: String,
    pub first_unix: u64,
    pub last_unix: u64,
    /// Whether the Pi counts it as known.
    pub known: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// `waiting`, `learned`, `received`, or "" for anything else.
    pub known_list: String,
    /// As the Pi sent them (last seen first).
    pub devices: Vec<Device>,
}

// -- validation helpers -------------------------------------------------------

/// An alert key: exactly 16 lower-case hex digits.
pub fn valid_key(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// An alert kind: 1 to 32 characters of `[a-z0-9_]`.
fn valid_kind(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// A hardware address written as 17 characters with `:` or `-` between the
/// six pairs (one kind throughout) and hex digits in either case, as
/// lower-case colon form. Anything else is `None`.
pub fn normalize_mac(s: &str) -> Option<String> {
    let b = s.as_bytes();
    if b.len() != 17 {
        return None;
    }
    let sep = b[2];
    if sep != b':' && sep != b'-' {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, &c) in b.iter().enumerate() {
        if i % 3 == 2 {
            if c != sep {
                return None;
            }
            out.push(':');
        } else if c.is_ascii_hexdigit() {
            out.push(c.to_ascii_lowercase() as char);
        } else {
            return None;
        }
    }
    Some(out)
}

/// `s` without control characters (the C0 and C1 ranges and DEL), cut to at
/// most `max_bytes` bytes on a character boundary.
pub fn clean_text(s: &str, max_bytes: usize) -> String {
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > max_bytes {
            break;
        }
        out.push(c);
    }
    out
}

/// A non-negative whole number, from a JSON integer or a whole float.
fn whole(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let f = v.as_f64()?;
    (f.is_finite() && f >= 0.0 && f.fract() == 0.0).then_some(f as u64)
}

fn num(v: &Value, name: &str, default: u64) -> u64 {
    v.get(name).and_then(whole).unwrap_or(default)
}

fn text<'a>(v: &'a Value, name: &str) -> Option<&'a str> {
    v.get(name).and_then(Value::as_str)
}

// -- parsers ------------------------------------------------------------------

/// One alert, or `None` when it has no usable `id`, `key` or `kind`. The
/// other fields fall back to harmless defaults.
fn parse_alert(v: &Value) -> Option<Alert> {
    let id = whole(v.get("id")?)?;
    let key = text(v, "key").filter(|k| valid_key(k))?;
    let kind = text(v, "kind").filter(|k| valid_kind(k))?;
    let severity = text(v, "severity")
        .filter(|s| matches!(*s, "info" | "warn" | "high"))
        .unwrap_or("info");
    let client = text(v, "client")
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(|a| a.to_string());
    Some(Alert {
        id,
        key: key.to_string(),
        rev: num(v, "rev", 0),
        kind: kind.to_string(),
        severity: severity.to_string(),
        client,
        subject: clean_text(text(v, "subject").unwrap_or(""), SUBJECT_MAX),
        first_unix: num(v, "first_unix", 0),
        last_unix: num(v, "last_unix", 0),
        count: num(v, "count", 1),
        acked: v.get("acked").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Validate a `GET alerts` answer. `None` when `rev` or `alerts` is missing
/// or of the wrong type. Entries that do not validate are dropped; when more
/// than [`MAX_ALERTS`] remain the newest changes (the end of the list, which
/// the Pi sends oldest first) are kept.
pub fn parse_alerts(v: &Value) -> Option<AlertsPage> {
    let rev = whole(v.get("rev")?)?;
    let items = v.get("alerts")?.as_array()?;
    let mut alerts: Vec<Alert> = items.iter().filter_map(parse_alert).collect();
    if alerts.len() > MAX_ALERTS {
        alerts.drain(..alerts.len() - MAX_ALERTS);
    }
    Some(AlertsPage {
        rev,
        suppressed: num(v, "suppressed", 0),
        alerts,
    })
}

/// One device, or `None` when its `mac` does not parse.
fn parse_device(v: &Value) -> Option<Device> {
    let mac = normalize_mac(text(v, "mac")?)?;
    let ipv4 = v
        .get("ipv4")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str()?.parse::<Ipv4Addr>().ok())
                .map(|ip| ip.to_string())
                .take(MAX_IPV4)
                .collect()
        })
        .unwrap_or_default();
    Some(Device {
        mac,
        ipv4,
        hostname: clean_text(text(v, "hostname").unwrap_or(""), HOSTNAME_MAX),
        first_unix: num(v, "first_unix", 0),
        last_unix: num(v, "last_unix", 0),
        known: v.get("known").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Validate a `GET devices` answer. `None` when `devices` is missing or not a
/// list. Entries without a valid MAC are dropped; at most [`MAX_DEVICES`]
/// are kept (the Pi sends the one seen last first, so those are kept).
pub fn parse_devices(v: &Value) -> Option<Inventory> {
    let items = v.get("devices")?.as_array()?;
    let mut devices: Vec<Device> = items.iter().filter_map(parse_device).collect();
    devices.truncate(MAX_DEVICES);
    let known_list = text(v, "known_list")
        .filter(|s| matches!(*s, "waiting" | "learned" | "received"))
        .unwrap_or_default();
    Some(Inventory {
        known_list: known_list.to_string(),
        devices,
    })
}

// -- the qbp calls ------------------------------------------------------------

/// The answer of a qbp call: the data, or the server saying 404.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qbp<T> {
    Present(T),
    /// HTTP 404: there is no watchdog behind this login.
    Absent,
}

fn odd(what: &str) -> ApiError {
    ApiError::Other(format!("unexpected {what} answer"))
}

/// `GET /api/qbp/alerts?since=<since>`: the alerts that changed after
/// revision `since` (0 for all). The query is always sent. A 2xx answer that
/// does not parse is an error, not `Absent`.
pub fn get_alerts(api: &mut Pihole, since: u64) -> Result<Qbp<AlertsPage>, ApiError> {
    let path = format!("/api/qbp/alerts?since={since}");
    match api.json_opt("GET", &path, None)? {
        None => Ok(Qbp::Absent),
        Some(v) => parse_alerts(&v)
            .map(Qbp::Present)
            .ok_or_else(|| odd("alerts")),
    }
}

/// `POST /api/qbp/alerts/{id}/ack`.
///
/// `Absent` means HTTP 404, which the Pi gives both when there is no
/// watchdog and when no alert has this id; the call cannot tell them apart,
/// so the caller decides (it usually knows from an earlier answer whether the
/// watchdog is there).
pub fn ack(api: &mut Pihole, id: u64) -> Result<Qbp<()>, ApiError> {
    let path = format!("/api/qbp/alerts/{id}/ack");
    Ok(match api.json_opt("POST", &path, None)? {
        None => Qbp::Absent,
        Some(_) => Qbp::Present(()),
    })
}

/// `PUT /api/qbp/alerts/acked` with `{"acked":[…]}`: tell the Pi which alerts
/// (by key) are acknowledged. The keys go out in as many bodies as it takes
/// to keep each under [`QBP_BODY_MAX`] bytes; keys that are not 16 lower-case
/// hex digits are skipped (the Pi would refuse the whole body for one).
/// Nothing is sent for an empty list. Returns the number of keys the Pi says
/// it restored, summed over the bodies; `Absent` as soon as one answer is 404.
pub fn restore_acked(api: &mut Pihole, keys: &[String]) -> Result<Qbp<u64>, ApiError> {
    let keys: Vec<String> = keys.iter().filter(|k| valid_key(k)).cloned().collect();
    let mut restored = 0u64;
    for body in acked_chunks(&keys, QBP_BODY_MAX) {
        match api.json_opt("PUT", "/api/qbp/alerts/acked", Some(&body))? {
            None => return Ok(Qbp::Absent),
            Some(v) => restored += num(&v, "restored", 0),
        }
    }
    Ok(Qbp::Present(restored))
}

/// `GET /api/qbp/devices`.
pub fn get_devices(api: &mut Pihole) -> Result<Qbp<Inventory>, ApiError> {
    match api.json_opt("GET", "/api/qbp/devices", None)? {
        None => Ok(Qbp::Absent),
        Some(v) => parse_devices(&v)
            .map(Qbp::Present)
            .ok_or_else(|| odd("devices")),
    }
}

/// `PUT /api/qbp/devices/known`: replace the Pi's known list with `macs`,
/// chunked by [`known_chunks`] (the list takes effect on the last chunk).
/// Entries that are not hardware addresses are skipped and the rest are sent
/// in lower-case colon form. An empty list is sent as one empty body, so the
/// caller decides whether it wants that (it makes the Pi raise every device).
/// Returns the size of the Pi's set after the last chunk; `Absent` as soon as
/// one answer is 404. If a chunk fails midway the Pi keeps its old list, and
/// the next push starts over with `append: false`.
pub fn put_known(api: &mut Pihole, macs: &[String]) -> Result<Qbp<u64>, ApiError> {
    let macs: Vec<String> = macs.iter().filter_map(|m| normalize_mac(m)).collect();
    let mut known = 0u64;
    for body in known_chunks(&macs, QBP_BODY_MAX) {
        match api.json_opt("PUT", "/api/qbp/devices/known", Some(&body))? {
            None => return Ok(Qbp::Absent),
            Some(v) => known = num(&v, "known", 0),
        }
    }
    Ok(Qbp::Present(known))
}

// -- chunking -----------------------------------------------------------------

/// The serialized length of `v`.
fn body_len(v: &Value) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX, |b| b.len())
}

/// Split `items` into consecutive runs whose JSON array text (the items'
/// serialized forms joined by commas) is at most `room` bytes. A run always
/// holds at least one item, so a `room` too small for one item still makes
/// progress (and that run is over the room).
fn pack(items: &[String], room: usize) -> Vec<&[String]> {
    let mut runs = Vec::new();
    let mut start = 0;
    let mut used = 0usize;
    for (i, item) in items.iter().enumerate() {
        let cost = serde_json::to_vec(item).map_or(item.len() + 2, |b| b.len());
        let add = if i == start { cost } else { cost + 1 };
        if i > start && used + add > room {
            runs.push(&items[start..i]);
            start = i;
            used = cost;
        } else {
            used += add;
        }
    }
    if start < items.len() {
        runs.push(&items[start..]);
    }
    runs
}

fn known_body(macs: &[String], append: bool, complete: bool) -> Value {
    json!({ "known": macs, "append": append, "complete": complete })
}

/// The bodies of `PUT devices/known` for `macs`, each at most `max_body`
/// bytes when serialized, the MACs in their given order. The first has
/// `append: false`, every one but the last `complete: false`, the last
/// `complete: true`; a list that fits is one body `append: false, complete:
/// true`. An empty list gives exactly one body with `"known": []`.
pub fn known_chunks(macs: &[String], max_body: usize) -> Vec<Value> {
    // The widest flags (`false`, `false`) set the room; others are shorter.
    let overhead = body_len(&known_body(&[], false, false));
    let runs = pack(macs, max_body.saturating_sub(overhead));
    if runs.is_empty() {
        return vec![known_body(&[], false, true)];
    }
    let last = runs.len() - 1;
    runs.into_iter()
        .enumerate()
        .map(|(i, run)| known_body(run, i > 0, i == last))
        .collect()
}

/// The bodies of `PUT alerts/acked` for `keys` (`{"acked":[…]}`), each at
/// most `max_body` bytes when serialized, the keys in their given order. An
/// empty list gives no bodies.
pub fn acked_chunks(keys: &[String], max_body: usize) -> Vec<Value> {
    let overhead = body_len(&json!({ "acked": Vec::<String>::new() }));
    pack(keys, max_body.saturating_sub(overhead))
        .into_iter()
        .map(|run| json!({ "acked": run }))
        .collect()
}

// -- notification text --------------------------------------------------------

/// The notification title for an alert kind.
pub fn title_for(kind: &str) -> &'static str {
    match kind {
        "new_device" => "New device on the network",
        "arp_spoof" => "Router impersonation (ARP spoofing)",
        "dga" => "Suspicious lookups (DGA)",
        "tunnel" => "Possible DNS tunnel",
        "beacon" => "Regular beaconing",
        "burst" => "Burst of lookups",
        "threat" => "Threat blocked",
        "rebind" => "DNS rebinding blocked",
        _ => "Watchdog alert",
    }
}

fn escape_char(c: char, buf: &mut [u8; 4]) -> &str {
    match c {
        '&' => "&amp;",
        '<' => "&lt;",
        '>' => "&gt;",
        c if c.is_control() => " ",
        c => c.encode_utf8(buf),
    }
}

/// Make `s` safe for a notification daemon that reads its text as markup:
/// `&`, `<` and `>` become entities, every control character (C0, DEL and
/// the Unicode C1 range, newline and tab included) becomes one space, and
/// the result is at most [`NOTIFY_MAX`] characters (characters, not bytes;
/// entities count with all their characters). When the text is cut, the last
/// character of the allowance is `…`, so the whole result still fits, and an
/// entity is never cut in half.
pub fn escape_markup(s: &str) -> String {
    let mut out = String::new();
    let mut n = 0; // characters of `out`
    let mut keep = 0; // length of `out` at the last point with room for `…`
    let mut cut = false;
    let mut buf = [0u8; 4];
    for c in s.chars() {
        let piece = escape_char(c, &mut buf);
        let width = piece.chars().count();
        if n + width > NOTIFY_MAX {
            cut = true;
            break;
        }
        out.push_str(piece);
        n += width;
        if n < NOTIFY_MAX {
            keep = out.len();
        }
    }
    if cut {
        out.truncate(keep);
        out.push('…');
    }
    out
}

/// The desktop notification for an alert: the escaped title for its kind and
/// the escaped body `"<subject> · <client>"` (just the subject without a
/// client). Both are ready to hand to `notify-send` after a `--`.
pub fn notification_for(a: &Alert) -> (String, String) {
    let body = match &a.client {
        Some(client) => format!("{} · {}", a.subject, client),
        None => a.subject.clone(),
    };
    (escape_markup(title_for(&a.kind)), escape_markup(&body))
}

// -- folding ------------------------------------------------------------------

/// Keeps a burst of alerts from flooding the desktop. A pure state machine:
/// time is passed in, as unix seconds.
///
/// Rules, for the `now` of each [`take`](Folder::take):
///
/// - An individual notification sent at `t` counts against the limit while
///   `t <= now < t + FOLD_WINDOW_S`. At most [`FOLD_LIMIT`] (3) individual
///   notifications are let through while that many are in the window; each
///   further alert is not shown but counted into a pending total.
/// - When the pending total is above zero and no fold has gone out in the
///   last [`FOLD_WINDOW_S`] (60) seconds (`now >= last_fold + 60`, or none
///   ever), one `("Watchdog", "N more alerts")` goes out (`"1 more alert"`
///   for one), and the pending total resets to zero. So a fold is sent at
///   most once per 60 s and carries everything held back since the last one.
/// - That check runs on every call, also with no new alerts, so a pending
///   fold is sent by the first call at or after the end of its gate.
/// - The individual notifications come first in the result, the fold last.
/// - A clock that steps back counts as time that has passed: times in the
///   future are forgotten, never waited for.
#[derive(Debug, Clone, Default)]
pub struct Folder {
    /// When the individual notifications in the window were sent.
    sent: VecDeque<u64>,
    /// Alerts held back since the last fold.
    pending: u64,
    last_fold: Option<u64>,
}

impl Folder {
    pub fn new() -> Self {
        Self::default()
    }

    /// The notifications to show now, given the new ones as `(title, body)`.
    pub fn take(&mut self, now: u64, new: Vec<(String, String)>) -> Vec<(String, String)> {
        self.sent.retain(|&t| t <= now && now - t < FOLD_WINDOW_S);
        if self.last_fold.is_some_and(|t| t > now) {
            self.last_fold = None;
        }
        let mut out = Vec::new();
        for n in new {
            if self.sent.len() < FOLD_LIMIT {
                self.sent.push_back(now);
                out.push(n);
            } else {
                self.pending += 1;
            }
        }
        let gate_open = self.last_fold.is_none_or(|t| now - t >= FOLD_WINDOW_S);
        if self.pending > 0 && gate_open {
            let body = if self.pending == 1 {
                "1 more alert".to_string()
            } else {
                format!("{} more alerts", self.pending)
            };
            out.push(("Watchdog".to_string(), body));
            self.pending = 0;
            self.last_fold = Some(now);
        }
        out
    }

    /// Alerts held back and not yet reported by a fold.
    pub fn pending(&self) -> u64 {
        self.pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::https::testutil::{ok_json, serve, TestServer};
    use crate::pihole::PasswordFn;
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    // Test data uses documentation addresses (192.0.2.x) and locally
    // administered MACs (02:00:00:…) only.

    fn mac(i: usize) -> String {
        format!(
            "02:00:00:{:02x}:{:02x}:{:02x}",
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        )
    }
    fn macs(n: usize) -> Vec<String> {
        (1..=n).map(mac).collect()
    }
    fn key(i: usize) -> String {
        format!("{:016x}", 0x1234_5678_0000_0000u64 + i as u64)
    }
    fn keys(n: usize) -> Vec<String> {
        (1..=n).map(key).collect()
    }

    fn alert_json(id: u64) -> Value {
        json!({
            "id": id, "key": key(id as usize), "rev": id + 100, "kind": "new_device",
            "severity": "warn", "client": "192.0.2.7", "subject": "02:00:00:00:00:07",
            "first_unix": 1_800_000_000u64, "last_unix": 1_800_000_050u64,
            "count": 2, "acked": false
        })
    }

    // -- parsing --------------------------------------------------------------

    #[test]
    fn a_full_alerts_answer_parses() {
        let v = json!({"rev": 41, "suppressed": 3, "alerts": [alert_json(7), alert_json(8)]});
        let page = parse_alerts(&v).unwrap();
        assert_eq!(page.rev, 41);
        assert_eq!(page.suppressed, 3);
        assert_eq!(page.alerts.len(), 2);
        assert_eq!(
            page.alerts[0],
            Alert {
                id: 7,
                key: key(7),
                rev: 107,
                kind: "new_device".into(),
                severity: "warn".into(),
                client: Some("192.0.2.7".into()),
                subject: "02:00:00:00:00:07".into(),
                first_unix: 1_800_000_000,
                last_unix: 1_800_000_050,
                count: 2,
                acked: false,
            }
        );
        assert_eq!(page.alerts[1].id, 8, "the Pi's order is kept");
    }

    #[test]
    fn an_alerts_answer_needs_rev_and_a_list() {
        assert!(parse_alerts(&json!({"alerts": []})).is_none());
        assert!(parse_alerts(&json!({"rev": 1})).is_none());
        assert!(parse_alerts(&json!({"rev": "1", "alerts": []})).is_none());
        assert!(parse_alerts(&json!({"rev": 1, "alerts": {}})).is_none());
        assert!(parse_alerts(&json!({"rev": -1, "alerts": []})).is_none());
        assert!(parse_alerts(&json!(null)).is_none());
        assert!(parse_alerts(&json!([])).is_none());
        let page = parse_alerts(&json!({"rev": 1, "alerts": []})).unwrap();
        assert_eq!((page.rev, page.suppressed, page.alerts.len()), (1, 0, 0));
    }

    #[test]
    fn alerts_with_a_bad_key_kind_or_id_are_dropped() {
        let mut bad = vec![];
        for k in [
            "ABCDEF0123456789",   // upper case
            "abcdef012345678",    // 15
            "abcdef01234567890",  // 17
            "abcdef012345678g",   // not hex
            "abcdef0123456789\n", // trailing newline
            "",
        ] {
            let mut a = alert_json(1);
            a["key"] = json!(k);
            bad.push(a);
        }
        let mut no_key = alert_json(2);
        no_key.as_object_mut().unwrap().remove("key");
        bad.push(no_key);
        for kind in ["", "New_Device", "new-device", "a b", &"x".repeat(33)] {
            let mut a = alert_json(3);
            a["kind"] = json!(kind);
            bad.push(a);
        }
        let mut no_id = alert_json(4);
        no_id.as_object_mut().unwrap().remove("id");
        bad.push(no_id);
        let mut text_id = alert_json(5);
        text_id["id"] = json!("5");
        bad.push(text_id);
        bad.push(json!("not an object"));
        bad.push(json!(null));

        let mut items = bad.clone();
        items.push(alert_json(9));
        let page = parse_alerts(&json!({"rev": 1, "alerts": items})).unwrap();
        assert_eq!(page.alerts.len(), 1, "{:?}", page.alerts);
        assert_eq!(page.alerts[0].id, 9);

        // A kind at the limits is fine.
        let mut a = alert_json(10);
        a["kind"] = json!("x".repeat(32));
        let page = parse_alerts(&json!({"rev": 1, "alerts": [a]})).unwrap();
        assert_eq!(page.alerts.len(), 1);
    }

    #[test]
    fn a_client_that_is_not_an_address_becomes_none() {
        let client_of = |c: Value| {
            let mut a = alert_json(1);
            a["client"] = c;
            parse_alerts(&json!({"rev": 1, "alerts": [a]}))
                .unwrap()
                .alerts[0]
                .client
                .clone()
        };
        assert_eq!(client_of(json!("192.0.2.9")), Some("192.0.2.9".into()));
        assert_eq!(client_of(json!("2001:db8::1")), Some("2001:db8::1".into()));
        assert_eq!(client_of(json!(null)), None);
        assert_eq!(client_of(json!("router.example")), None);
        assert_eq!(client_of(json!("192.0.2.9; rm -rf")), None);
        assert_eq!(client_of(json!("")), None);
        assert_eq!(client_of(json!(7)), None);
    }

    #[test]
    fn a_severity_outside_the_known_three_is_info() {
        let sev = |s: Value| {
            let mut a = alert_json(1);
            a["severity"] = s;
            parse_alerts(&json!({"rev": 1, "alerts": [a]}))
                .unwrap()
                .alerts[0]
                .severity
                .clone()
        };
        assert_eq!(sev(json!("info")), "info");
        assert_eq!(sev(json!("warn")), "warn");
        assert_eq!(sev(json!("high")), "high");
        assert_eq!(sev(json!("critical")), "info");
        assert_eq!(sev(json!("HIGH")), "info");
        assert_eq!(sev(json!(null)), "info");
        assert_eq!(sev(json!(3)), "info");
    }

    #[test]
    fn missing_optional_fields_get_harmless_defaults() {
        let v = json!({"rev": 5, "alerts": [{"id": 1, "key": key(1), "kind": "dga"}]});
        let a = &parse_alerts(&v).unwrap().alerts[0];
        assert_eq!(
            (a.rev, a.first_unix, a.last_unix, a.count, a.acked),
            (0, 0, 0, 1, false)
        );
        assert_eq!((a.severity.as_str(), a.subject.as_str()), ("info", ""));
        assert_eq!(a.client, None);
    }

    #[test]
    fn subjects_lose_control_characters_and_are_capped_on_a_char_boundary() {
        let subj = |s: &str| {
            let mut a = alert_json(1);
            a["subject"] = json!(s);
            parse_alerts(&json!({"rev": 1, "alerts": [a]}))
                .unwrap()
                .alerts[0]
                .subject
                .clone()
        };
        assert_eq!(
            subj("a\u{0}b\nc\td\u{7f}e\u{85}f\u{1b}[31mg"),
            "abcdef[31mg"
        );
        assert_eq!(subj("plain"), "plain");
        // 255 bytes exactly fits; one more does not.
        assert_eq!(subj(&"a".repeat(255)).len(), 255);
        assert_eq!(subj(&"a".repeat(300)).len(), 255);
        // Two-byte characters: 127 of them are 254 bytes, the 128th would
        // reach 256, so the cut lands on a boundary at 254.
        let s = subj(&"é".repeat(200));
        assert_eq!(s.len(), 254);
        assert_eq!(s.chars().count(), 127);
        // Three-byte characters: 85 are 255 bytes.
        assert_eq!(subj(&"€".repeat(200)).len(), 255);
    }

    #[test]
    fn alerts_are_capped_at_256_keeping_the_newest() {
        let items: Vec<Value> = (1..=300).map(alert_json).collect();
        let page = parse_alerts(&json!({"rev": 500, "alerts": items})).unwrap();
        assert_eq!(page.alerts.len(), MAX_ALERTS);
        assert_eq!(page.alerts[0].id, 45);
        assert_eq!(page.alerts.last().unwrap().id, 300);
    }

    #[test]
    fn a_full_devices_answer_parses() {
        let v = json!({"known_list": "learned", "devices": [
            {"mac": "02:00:00:00:00:07", "ipv4": ["192.0.2.7", "192.0.2.8"],
             "hostname": "printer", "first_unix": 10, "last_unix": 20, "known": true},
            {"mac": "02-00-00-00-00-AB", "ipv4": [], "hostname": "",
             "first_unix": 1, "last_unix": 2, "known": false},
        ]});
        let inv = parse_devices(&v).unwrap();
        assert_eq!(inv.known_list, "learned");
        assert_eq!(
            inv.devices[0],
            Device {
                mac: "02:00:00:00:00:07".into(),
                ipv4: vec!["192.0.2.7".into(), "192.0.2.8".into()],
                hostname: "printer".into(),
                first_unix: 10,
                last_unix: 20,
                known: true,
            }
        );
        assert_eq!(inv.devices[1].mac, "02:00:00:00:00:ab", "normalised");
        assert!(!inv.devices[1].known);
    }

    #[test]
    fn known_list_values_outside_the_three_become_empty() {
        let kl = |v: Value| {
            parse_devices(&json!({"known_list": v, "devices": []}))
                .unwrap()
                .known_list
        };
        assert_eq!(kl(json!("waiting")), "waiting");
        assert_eq!(kl(json!("learned")), "learned");
        assert_eq!(kl(json!("received")), "received");
        assert_eq!(kl(json!("Waiting")), "");
        assert_eq!(kl(json!("pending")), "");
        assert_eq!(kl(json!(null)), "");
        assert_eq!(kl(json!(1)), "");
        assert_eq!(
            parse_devices(&json!({"devices": []})).unwrap().known_list,
            ""
        );
    }

    #[test]
    fn devices_with_bad_macs_or_addresses_are_cleaned() {
        let v = json!({"devices": [
            {"mac": "not a mac"},
            {"mac": "02:00:00:00:00"},
            {"mac": "02:00:00:00:00:0g"},
            {"mac": "02:00-00:00:00:01"},
            {"mac": 5},
            {"hostname": "no-mac"},
            "junk",
            {"mac": "02:00:00:00:00:09",
             "ipv4": ["192.0.2.1", "bad", "999.0.0.1", "2001:db8::1", 7, "192.0.2.2",
                      "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6"],
             "hostname": "a\nb\u{0}c\u{9b}d"},
        ]});
        let inv = parse_devices(&v).unwrap();
        assert_eq!(inv.devices.len(), 1);
        let d = &inv.devices[0];
        assert_eq!(d.mac, "02:00:00:00:00:09");
        assert_eq!(
            d.ipv4,
            ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"],
            "bad ones dropped, at most four"
        );
        assert_eq!(d.hostname, "abcd");
        assert_eq!((d.first_unix, d.last_unix, d.known), (0, 0, false));
    }

    #[test]
    fn hostnames_are_capped_at_64_bytes() {
        let host = |h: &str| {
            let v = json!({"devices": [{"mac": mac(1), "hostname": h}]});
            parse_devices(&v).unwrap().devices[0].hostname.clone()
        };
        assert_eq!(host(&"h".repeat(64)).len(), 64);
        assert_eq!(host(&"h".repeat(100)).len(), 64);
        assert_eq!(host(&"é".repeat(100)).len(), 64);
        assert_eq!(host(&"€".repeat(100)).len(), 63);
    }

    #[test]
    fn devices_are_capped_at_512_keeping_the_first() {
        let items: Vec<Value> = (1..=600).map(|i| json!({"mac": mac(i)})).collect();
        let inv = parse_devices(&json!({"devices": items})).unwrap();
        assert_eq!(inv.devices.len(), MAX_DEVICES);
        assert_eq!(inv.devices[0].mac, mac(1));
        assert_eq!(inv.devices.last().unwrap().mac, mac(512));
    }

    #[test]
    fn a_devices_answer_needs_a_list() {
        assert!(parse_devices(&json!({})).is_none());
        assert!(parse_devices(&json!({"devices": "x"})).is_none());
        assert!(parse_devices(&json!({"devices": null})).is_none());
        assert!(parse_devices(&json!(null)).is_none());
    }

    #[test]
    fn mac_normalisation() {
        assert_eq!(
            normalize_mac("02:00:00:00:00:AB").as_deref(),
            Some("02:00:00:00:00:ab")
        );
        assert_eq!(
            normalize_mac("02-00-00-00-00-aB").as_deref(),
            Some("02:00:00:00:00:ab")
        );
        assert_eq!(
            normalize_mac("0A:1b:2C:3d:4E:5f").as_deref(),
            Some("0a:1b:2c:3d:4e:5f")
        );
        for bad in [
            "",
            "02:00:00:00:00",
            "02:00:00:00:00:0",
            "02:00:00:00:00:001",
            "02:00-00:00:00:01", // mixed separators
            "02.00.00.00.00.01",
            "0200.0000.0001",
            "020000000001",
            "02:00:00:00:00:0g",
            "02:00:00:00:00:0é", // 17 bytes, not ASCII
            " 02:00:00:00:00:01",
            "02:00:00:00:00:01\n",
            "02::00:00:00:01:0",
        ] {
            assert_eq!(normalize_mac(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn keys_are_sixteen_lower_case_hex_digits() {
        assert!(valid_key("0123456789abcdef"));
        assert!(!valid_key("0123456789ABCDEF"));
        assert!(!valid_key("0123456789abcde"));
        assert!(!valid_key("0123456789abcdefa"));
        assert!(!valid_key("0123456789abcdeg"));
        assert!(!valid_key(""));
    }

    // -- the qbp calls against a fake Pi --------------------------------------

    const LOGIN_OK: &str = r#"{"session":{"valid":true,"sid":"SID-1","validity":300}}"#;
    const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}";
    const NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

    type Log = Arc<Mutex<Vec<String>>>;

    fn pw() -> PasswordFn {
        Box::new(|| Ok(Zeroizing::new("pw".to_string())))
    }
    fn client(srv: &TestServer) -> Pihole {
        Pihole::at(srv.addr, srv.fingerprint, pw()).unwrap()
    }
    fn first_line(req: &str) -> &str {
        req.lines().next().unwrap_or("")
    }
    fn body_of(req: &str) -> Value {
        serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap_or("")).unwrap()
    }
    /// The first lines of the logged requests that are not login or logout.
    fn qbp_lines(log: &Log) -> Vec<String> {
        log.lock()
            .unwrap()
            .iter()
            .map(|r| first_line(r).to_string())
            .filter(|l| !l.contains("/api/auth"))
            .collect()
    }
    fn puts(log: &Log, path: &str) -> Vec<Value> {
        log.lock()
            .unwrap()
            .iter()
            .filter(|r| first_line(r).starts_with(&format!("PUT {path} ")))
            .map(|r| body_of(r))
            .collect()
    }

    /// A Pi without a watchdog: logs in, answers 404 for everything else.
    fn real_pihole(log: Log) -> TestServer {
        serve(32, move |_, req| {
            log.lock().unwrap().push(req.to_string());
            let first = first_line(req);
            if first.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else if first.starts_with("DELETE /api/auth") {
                Some(NO_CONTENT.to_vec())
            } else {
                Some(NOT_FOUND.to_vec())
            }
        })
    }

    /// A Pi with a watchdog. The known list's size follows the chunks.
    fn watchdog_pi(log: Log) -> TestServer {
        let set = Arc::new(Mutex::new(0usize));
        serve(64, move |_, req| {
            log.lock().unwrap().push(req.to_string());
            let first = first_line(req);
            if first.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else if first.starts_with("DELETE /api/auth") {
                Some(NO_CONTENT.to_vec())
            } else if first.starts_with("GET /api/qbp/alerts?since=") {
                Some(ok_json(
                    &json!({"rev": 41, "suppressed": 1, "alerts": [alert_json(7)]}).to_string(),
                ))
            } else if first.starts_with("POST /api/qbp/alerts/") && first.contains("/ack ") {
                Some(ok_json(r#"{"acked":true}"#))
            } else if first.starts_with("PUT /api/qbp/alerts/acked ") {
                let n = body_of(req)["acked"].as_array().unwrap().len();
                Some(ok_json(&format!(r#"{{"restored":{n}}}"#)))
            } else if first.starts_with("GET /api/qbp/devices ") {
                Some(ok_json(
                    r#"{"known_list":"waiting","devices":[{"mac":"02:00:00:00:00:07","ipv4":["192.0.2.7"],"hostname":"","first_unix":1,"last_unix":2,"known":false}]}"#,
                ))
            } else if first.starts_with("PUT /api/qbp/devices/known ") {
                let b = body_of(req);
                let n = b["known"].as_array().unwrap().len();
                let mut set = set.lock().unwrap();
                *set = if b["append"] == json!(true) {
                    *set + n
                } else {
                    n
                };
                Some(ok_json(&format!(r#"{{"known":{}}}"#, *set)))
            } else {
                Some(NOT_FOUND.to_vec())
            }
        })
    }

    #[test]
    fn every_qbp_call_is_absent_on_a_pihole_without_a_watchdog() {
        let log: Log = Arc::default();
        let srv = real_pihole(log.clone());
        let mut api = client(&srv);
        assert_eq!(get_alerts(&mut api, 0).unwrap(), Qbp::Absent);
        assert_eq!(ack(&mut api, 7).unwrap(), Qbp::Absent);
        assert_eq!(restore_acked(&mut api, &keys(2)).unwrap(), Qbp::Absent);
        assert_eq!(get_devices(&mut api).unwrap(), Qbp::Absent);
        assert_eq!(put_known(&mut api, &macs(2)).unwrap(), Qbp::Absent);
        assert_eq!(
            qbp_lines(&log),
            [
                "GET /api/qbp/alerts?since=0 HTTP/1.1",
                "POST /api/qbp/alerts/7/ack HTTP/1.1",
                "PUT /api/qbp/alerts/acked HTTP/1.1",
                "GET /api/qbp/devices HTTP/1.1",
                "PUT /api/qbp/devices/known HTTP/1.1",
            ]
        );
    }

    #[test]
    fn the_since_query_is_always_sent() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        get_alerts(&mut api, 0).unwrap();
        get_alerts(&mut api, 41).unwrap();
        assert_eq!(
            qbp_lines(&log),
            [
                "GET /api/qbp/alerts?since=0 HTTP/1.1",
                "GET /api/qbp/alerts?since=41 HTTP/1.1"
            ]
        );
    }

    #[test]
    fn present_answers_are_parsed() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);

        let Qbp::Present(page) = get_alerts(&mut api, 0).unwrap() else {
            panic!("alerts absent")
        };
        assert_eq!((page.rev, page.suppressed, page.alerts.len()), (41, 1, 1));
        assert_eq!(page.alerts[0].id, 7);

        assert_eq!(ack(&mut api, 7).unwrap(), Qbp::Present(()));
        assert_eq!(restore_acked(&mut api, &keys(3)).unwrap(), Qbp::Present(3));

        let Qbp::Present(inv) = get_devices(&mut api).unwrap() else {
            panic!("devices absent")
        };
        assert_eq!(inv.known_list, "waiting");
        assert_eq!(inv.devices[0].ipv4, ["192.0.2.7"]);

        assert_eq!(put_known(&mut api, &macs(3)).unwrap(), Qbp::Present(3));
    }

    #[test]
    fn a_2xx_that_does_not_parse_is_an_error_not_absent() {
        let srv = serve(16, |_, req| {
            if first_line(req).starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else {
                Some(ok_json(r#"{"unexpected":true}"#))
            }
        });
        let mut api = client(&srv);
        assert!(matches!(get_alerts(&mut api, 0), Err(ApiError::Other(_))));
        assert!(matches!(get_devices(&mut api), Err(ApiError::Other(_))));
        // Ack and the two puts only need a 2xx.
        assert_eq!(ack(&mut api, 1).unwrap(), Qbp::Present(()));
        assert_eq!(restore_acked(&mut api, &keys(1)).unwrap(), Qbp::Present(0));
        assert_eq!(put_known(&mut api, &macs(1)).unwrap(), Qbp::Present(0));
    }

    #[test]
    fn a_401_logs_in_again_and_the_qbp_call_then_succeeds() {
        let logins = Arc::new(Mutex::new(0usize));
        let l2 = logins.clone();
        let srv = serve(16, move |_, req| {
            let first = first_line(req);
            if first.starts_with("POST /api/auth") {
                let mut n = l2.lock().unwrap();
                *n += 1;
                Some(ok_json(&LOGIN_OK.replace("SID-1", &format!("SID-{}", *n))))
            } else if first.starts_with("GET /api/qbp/alerts") {
                if req.contains("X-FTL-SID: SID-1") {
                    Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}".to_vec())
                } else {
                    assert!(req.contains("X-FTL-SID: SID-2"), "{req}");
                    Some(ok_json(r#"{"rev":9,"alerts":[]}"#))
                }
            } else {
                Some(NO_CONTENT.to_vec())
            }
        });
        let mut api = client(&srv);
        let Qbp::Present(page) = get_alerts(&mut api, 0).unwrap() else {
            panic!("absent")
        };
        assert_eq!(page.rev, 9);
        assert_eq!(*logins.lock().unwrap(), 2);
        assert_eq!(api.logins(), 2);
    }

    #[test]
    fn a_failing_server_is_an_error_not_absent() {
        let srv = serve(16, |_, req| {
            if first_line(req).starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else {
                Some(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            }
        });
        let mut api = client(&srv);
        assert!(get_alerts(&mut api, 0).is_err());
        assert!(ack(&mut api, 1).is_err());
        assert!(put_known(&mut api, &macs(1)).is_err());
    }

    // -- chunking -------------------------------------------------------------

    fn sizes(chunks: &[Value]) -> Vec<usize> {
        chunks.iter().map(body_len).collect()
    }

    fn check_known_chunks(n: usize, want_chunks: usize) {
        let input = macs(n);
        let chunks = known_chunks(&input, QBP_BODY_MAX);
        assert_eq!(chunks.len(), want_chunks, "{n} macs");
        for (i, c) in chunks.iter().enumerate() {
            let real = serde_json::to_vec(c).unwrap().len();
            assert!(real <= QBP_BODY_MAX, "chunk {i} of {n}: {real} bytes");
            assert_eq!(c["append"], json!(i > 0), "append of chunk {i}");
            assert_eq!(
                c["complete"],
                json!(i + 1 == chunks.len()),
                "complete of chunk {i}"
            );
            assert_eq!(c.as_object().unwrap().len(), 3);
        }
        let joined: Vec<String> = chunks
            .iter()
            .flat_map(|c| {
                c["known"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m.as_str().unwrap().to_string())
            })
            .collect();
        assert_eq!(joined, input, "order kept, nothing lost or repeated");
        if want_chunks > 1 {
            // Packed full: the next MAC would not have fitted.
            let first = sizes(&chunks)[0];
            assert!(first + 20 > QBP_BODY_MAX, "first chunk is {first} bytes");
        }
    }

    #[test]
    fn a_short_known_list_is_one_complete_chunk() {
        check_known_chunks(1, 1);
        let one = known_chunks(&macs(1), QBP_BODY_MAX);
        assert_eq!(
            one[0],
            json!({"known": [mac(1)], "append": false, "complete": true})
        );
        check_known_chunks(197, 1);
    }

    #[test]
    fn a_known_list_of_250_is_two_chunks() {
        check_known_chunks(250, 2);
    }

    #[test]
    fn a_known_list_of_1024_is_six_chunks() {
        check_known_chunks(1024, 6);
        // The Pi keeps at most 1024, so this is the largest list that is sent.
        let flags: Vec<(bool, bool)> = known_chunks(&macs(1024), QBP_BODY_MAX)
            .iter()
            .map(|c| {
                (
                    c["append"].as_bool().unwrap(),
                    c["complete"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            flags,
            [
                (false, false),
                (true, false),
                (true, false),
                (true, false),
                (true, false),
                (true, true)
            ]
        );
    }

    #[test]
    fn an_empty_known_list_is_one_empty_body() {
        let c = known_chunks(&[], QBP_BODY_MAX);
        assert_eq!(
            c,
            vec![json!({"known": [], "append": false, "complete": true})]
        );
    }

    #[test]
    fn known_chunks_respect_any_cap_and_never_split_a_mac() {
        let input = macs(100);
        for cap in [100, 150, 500, 1234, 4000] {
            let chunks = known_chunks(&input, cap);
            for c in &chunks {
                assert!(body_len(c) <= cap, "cap {cap}: {}", body_len(c));
            }
            let n: usize = chunks
                .iter()
                .map(|c| c["known"].as_array().unwrap().len())
                .sum();
            assert_eq!(n, 100, "cap {cap}");
        }
    }

    #[test]
    fn acked_chunks_split_by_size_and_keep_order() {
        assert!(acked_chunks(&[], QBP_BODY_MAX).is_empty());
        for (n, want) in [(1, 1), (209, 1), (210, 2), (1024, 5)] {
            let input = keys(n);
            let chunks = acked_chunks(&input, QBP_BODY_MAX);
            assert_eq!(chunks.len(), want, "{n} keys");
            for c in &chunks {
                assert!(body_len(c) <= QBP_BODY_MAX);
                assert_eq!(c.as_object().unwrap().len(), 1);
            }
            let joined: Vec<String> = chunks
                .iter()
                .flat_map(|c| {
                    c["acked"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|k| k.as_str().unwrap().to_string())
                })
                .collect();
            assert_eq!(joined, input);
        }
    }

    #[test]
    fn put_known_sends_the_chunks_in_order_with_the_bodies_intact() {
        for (n, want) in [(1usize, 1usize), (250, 2), (1024, 6)] {
            let log: Log = Arc::default();
            let srv = watchdog_pi(log.clone());
            let mut api = client(&srv);
            let input = macs(n);
            assert_eq!(
                put_known(&mut api, &input).unwrap(),
                Qbp::Present(n as u64),
                "the Pi's count after the last chunk"
            );
            let sent = puts(&log, "/api/qbp/devices/known");
            assert_eq!(sent.len(), want, "{n} macs");
            assert_eq!(sent, known_chunks(&input, QBP_BODY_MAX), "bodies intact");
            // The request text really carried bodies under the cap.
            for r in log.lock().unwrap().iter() {
                if first_line(r).starts_with("PUT /api/qbp/devices/known") {
                    let len: usize = r
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    assert!(len <= QBP_BODY_MAX, "{len}");
                }
            }
        }
    }

    #[test]
    fn put_known_normalises_and_skips_bad_entries() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        let list = vec![
            "02-00-00-00-00-AA".to_string(),
            "nonsense".to_string(),
            "02:00:00:00:00:bb".to_string(),
        ];
        assert_eq!(put_known(&mut api, &list).unwrap(), Qbp::Present(2));
        assert_eq!(
            puts(&log, "/api/qbp/devices/known"),
            [json!({"known": ["02:00:00:00:00:aa", "02:00:00:00:00:bb"],
                    "append": false, "complete": true})]
        );
    }

    #[test]
    fn put_known_with_an_empty_list_sends_the_one_empty_body() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        assert_eq!(put_known(&mut api, &[]).unwrap(), Qbp::Present(0));
        assert_eq!(
            puts(&log, "/api/qbp/devices/known"),
            [json!({"known": [], "append": false, "complete": true})]
        );
    }

    #[test]
    fn restore_acked_splits_into_bodies_and_sums_the_answers() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        let input = keys(1024);
        assert_eq!(restore_acked(&mut api, &input).unwrap(), Qbp::Present(1024));
        let sent = puts(&log, "/api/qbp/alerts/acked");
        assert_eq!(sent.len(), 5);
        assert_eq!(sent, acked_chunks(&input, QBP_BODY_MAX));
        for b in &sent {
            assert!(body_len(b) <= QBP_BODY_MAX);
        }
    }

    #[test]
    fn restore_acked_sends_nothing_for_an_empty_list_and_skips_bad_keys() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        assert_eq!(restore_acked(&mut api, &[]).unwrap(), Qbp::Present(0));
        assert!(log.lock().unwrap().is_empty(), "not even a login");

        let list = vec![key(1), "BAD".to_string(), key(2), "".to_string()];
        assert_eq!(restore_acked(&mut api, &list).unwrap(), Qbp::Present(2));
        assert_eq!(
            puts(&log, "/api/qbp/alerts/acked"),
            [json!({"acked": [key(1), key(2)]})]
        );
        // Only bad keys: again nothing to send.
        let before = log.lock().unwrap().len();
        assert_eq!(
            restore_acked(&mut api, &["nope".to_string()]).unwrap(),
            Qbp::Present(0)
        );
        assert_eq!(log.lock().unwrap().len(), before);
    }

    #[test]
    fn restore_acked_stops_at_the_first_404() {
        let log: Log = Arc::default();
        let srv = real_pihole(log.clone());
        let mut api = client(&srv);
        assert_eq!(restore_acked(&mut api, &keys(1024)).unwrap(), Qbp::Absent);
        assert_eq!(puts(&log, "/api/qbp/alerts/acked").len(), 1);
    }

    // -- titles and escaping --------------------------------------------------

    #[test]
    fn every_kind_has_its_title() {
        for (kind, title) in [
            ("new_device", "New device on the network"),
            ("arp_spoof", "Router impersonation (ARP spoofing)"),
            ("dga", "Suspicious lookups (DGA)"),
            ("tunnel", "Possible DNS tunnel"),
            ("beacon", "Regular beaconing"),
            ("burst", "Burst of lookups"),
            ("threat", "Threat blocked"),
            ("rebind", "DNS rebinding blocked"),
            ("something_new", "Watchdog alert"),
            ("", "Watchdog alert"),
        ] {
            assert_eq!(title_for(kind), title, "{kind}");
        }
    }

    #[test]
    fn markup_characters_are_escaped() {
        assert_eq!(escape_markup("<b>&x</b>"), "&lt;b&gt;&amp;x&lt;/b&gt;");
        assert_eq!(escape_markup("&amp;"), "&amp;amp;", "no double meaning");
        assert_eq!(escape_markup("plain text"), "plain text");
        assert_eq!(escape_markup(""), "");
        assert_eq!(escape_markup("é€😀"), "é€😀");
    }

    #[test]
    fn control_characters_become_one_space_each() {
        assert_eq!(escape_markup("a\nb\tc\rd"), "a b c d");
        assert_eq!(escape_markup("a\u{0}b\u{1b}c\u{7f}d"), "a b c d");
        assert_eq!(
            escape_markup("a\u{80}b\u{85}c\u{9f}d"),
            "a b c d",
            "C1 range"
        );
        assert_eq!(escape_markup("a\n\nb"), "a  b", "one space each");
        // Not a control character: the no-break space is text.
        assert_eq!(escape_markup("a\u{a0}b"), "a\u{a0}b");
    }

    #[test]
    fn long_text_is_cut_at_200_characters_with_an_ellipsis() {
        let exact = "a".repeat(200);
        assert_eq!(escape_markup(&exact), exact, "200 fits");
        let cut = escape_markup(&"a".repeat(201));
        assert_eq!(cut.chars().count(), 200);
        assert_eq!(cut, format!("{}…", "a".repeat(199)));
        assert!(escape_markup(&"a".repeat(5000)).ends_with('…'));
        // Characters, not bytes: 4-byte characters.
        let emoji = escape_markup(&"😀".repeat(300));
        assert_eq!(emoji.chars().count(), 200);
        assert_eq!(emoji, format!("{}…", "😀".repeat(199)));
        // An entity is never cut in half.
        let s = format!("{}&{}", "a".repeat(197), "b".repeat(10));
        let e = escape_markup(&s);
        assert_eq!(e, format!("{}…", "a".repeat(197)));
        let s = format!("{}<>", "a".repeat(195));
        assert_eq!(
            escape_markup(&s),
            format!("{}&lt;…", "a".repeat(195)),
            "the second entity would not fit"
        );
        // The escaped length is what is capped: 49 whole entities and the
        // ellipsis (the 50th would leave no room for it).
        assert_eq!(
            escape_markup(&"<".repeat(100)),
            format!("{}…", "&lt;".repeat(49))
        );
    }

    fn alert_with(kind: &str, subject: &str, client: Option<&str>) -> Alert {
        Alert {
            id: 1,
            key: key(1),
            rev: 1,
            kind: kind.into(),
            severity: "info".into(),
            client: client.map(String::from),
            subject: subject.into(),
            first_unix: 0,
            last_unix: 0,
            count: 1,
            acked: false,
        }
    }

    #[test]
    fn a_notification_is_title_by_kind_and_subject_with_client() {
        let (t, b) = notification_for(&alert_with("new_device", "02:00:00:00:00:07", None));
        assert_eq!(t, "New device on the network");
        assert_eq!(b, "02:00:00:00:00:07");
        let (t, b) = notification_for(&alert_with("dga", "x.example", Some("192.0.2.7")));
        assert_eq!(t, "Suspicious lookups (DGA)");
        assert_eq!(b, "x.example · 192.0.2.7");
    }

    #[test]
    fn notification_text_is_escaped_and_a_leading_dash_is_just_text() {
        let (t, b) = notification_for(&alert_with("dga", "<b>x</b>\n& more", Some("192.0.2.7")));
        assert_eq!(t, "Suspicious lookups (DGA)");
        assert_eq!(b, "&lt;b&gt;x&lt;/b&gt; &amp; more · 192.0.2.7");
        let (_, b) = notification_for(&alert_with("burst", "--help -a evil", None));
        assert_eq!(b, "--help -a evil", "survives as text");
        let (t, _) = notification_for(&alert_with("weird", "s", None));
        assert_eq!(t, "Watchdog alert");
    }

    // -- folding --------------------------------------------------------------

    fn alerts_n(n: usize) -> Vec<(String, String)> {
        (0..n).map(|i| (format!("t{i}"), format!("b{i}"))).collect()
    }
    fn fold_note(n: u64) -> (String, String) {
        let body = if n == 1 {
            "1 more alert".to_string()
        } else {
            format!("{n} more alerts")
        };
        ("Watchdog".to_string(), body)
    }

    #[test]
    fn two_alerts_are_two_notifications() {
        let mut f = Folder::new();
        let out = f.take(1000, alerts_n(2));
        assert_eq!(out, alerts_n(2));
        assert_eq!(f.pending(), 0);
        assert!(f.take(1001, vec![]).is_empty());
    }

    #[test]
    fn three_alerts_are_still_all_individual() {
        let mut f = Folder::new();
        assert_eq!(f.take(1000, alerts_n(3)), alerts_n(3));
    }

    #[test]
    fn ten_at_once_are_three_and_one_fold_of_seven() {
        let mut f = Folder::new();
        let out = f.take(1000, alerts_n(10));
        let mut want = alerts_n(3);
        want.push(fold_note(7));
        assert_eq!(out, want);
        assert_eq!(f.pending(), 0, "the fold reset the count");
    }

    #[test]
    fn a_single_extra_alert_folds_as_one_more_alert() {
        let mut f = Folder::new();
        let out = f.take(1000, alerts_n(4));
        assert_eq!(out.last(), Some(&fold_note(1)));
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn a_second_burst_is_held_until_sixty_seconds_after_the_last_fold() {
        let mut f = Folder::new();
        // t=1000: 3 individual + a fold of 7.
        assert_eq!(f.take(1000, alerts_n(10)).len(), 4);
        // t=1010: ten more. Nothing individual (the window is full), no fold
        // (the last one was 10 s ago); all ten are carried.
        assert!(f.take(1010, alerts_n(10)).is_empty());
        assert_eq!(f.pending(), 10);
        // Still held at 1030 and 1059, and more alerts add to the count.
        assert!(f.take(1030, alerts_n(2)).is_empty());
        assert_eq!(f.pending(), 12);
        assert!(f.take(1059, vec![]).is_empty());
        // At 1060 the gate opens: one fold with everything carried, and
        // with no new alert needed to trigger it.
        assert_eq!(f.take(1060, vec![]), vec![fold_note(12)]);
        assert_eq!(f.pending(), 0);
        assert!(f.take(1061, vec![]).is_empty(), "nothing left to say");
    }

    #[test]
    fn the_fold_gate_is_per_fold_not_per_window() {
        let mut f = Folder::new();
        assert_eq!(f.take(0, alerts_n(5)), {
            let mut v = alerts_n(3);
            v.push(fold_note(2));
            v
        });
        // 59 s later the individual window is still full (3 sent at t=0).
        assert!(f.take(59, alerts_n(1)).is_empty());
        // At 60 the window has reopened: this alert is individual, and the
        // fold gate is open too, carrying the one held back at 59.
        let out = f.take(60, alerts_n(1));
        assert_eq!(out, vec![alerts_n(1).remove(0), fold_note(1)]);
        // That fold was at 60: the next one cannot come before 120.
        assert_eq!(f.take(61, alerts_n(10)).len(), 2, "two more individuals");
        assert_eq!(f.pending(), 8);
        assert!(f.take(119, vec![]).is_empty());
        assert_eq!(f.take(120, vec![]), vec![fold_note(8)]);
    }

    #[test]
    fn after_a_quiet_minute_the_limit_resets() {
        let mut f = Folder::new();
        assert_eq!(f.take(1000, alerts_n(10)).len(), 4);
        // Quiet for 60 s.
        assert!(f.take(1030, vec![]).is_empty());
        let out = f.take(1060, alerts_n(5));
        let mut want = alerts_n(3);
        want.push(fold_note(2));
        assert_eq!(out, want, "three individual again, the rest folded");
    }

    #[test]
    fn a_clock_that_steps_back_never_stalls_the_folder() {
        let mut f = Folder::new();
        assert_eq!(f.take(10_000, alerts_n(10)).len(), 4);
        // An hour back: the old send times are in the future, so forgotten.
        let out = f.take(6_000, alerts_n(2));
        assert_eq!(out, alerts_n(2));
    }
}

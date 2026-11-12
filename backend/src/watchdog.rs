//! Support for the qberrypi watchdog: the `/api/qbp/` calls behind the
//! Pi-hole login, the tolerant parsers for their answers, notification text
//! (titles, markup escaping, burst folding) and the chunking of the two
//! lists that are pushed in chunks to the Pi (acknowledged alerts, known
//! devices). The exempt list (devices that skip ad blocking) is pushed with
//! it, in one body of at most 64 addresses, and a Pi that answers 404 for it
//! (an older one) is simply not sent it again in that session.
//!
//! A real Pi-hole answers 404 on every `/api/qbp/` path. The calls here turn
//! that into [`Qbp::Absent`], so the caller can treat the watchdog as not
//! there and behave exactly as it did before.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use serde_json::{json, Value};

use crate::pihole::{ApiError, Pihole};
use crate::wdstore::{self, Store};

/// The largest request body sent to the Pi: its cap is 4096 bytes, this
/// leaves room for the headers' share of whatever the Pi counts.
pub const QBP_BODY_MAX: usize = 4000;

/// Alerts kept from one answer (the newest changes).
pub const MAX_ALERTS: usize = 256;
/// Devices kept from one answer (the ones seen last).
pub const MAX_DEVICES: usize = 512;
/// Exempt addresses kept from one answer.
pub const MAX_EXEMPT_MACS: usize = 512;
/// The most addresses `PUT devices/exempt` takes (the Pi's cap).
pub const EXEMPT_MAX: usize = wdstore::MAX_EXEMPT;
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
    /// Whether the Pi skips ad blocking for it (false when it does not say,
    /// as an older Pi does not).
    pub exempt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// `waiting`, `learned`, `received`, or "" for anything else.
    pub known_list: String,
    /// As the Pi sent them (last seen first).
    pub devices: Vec<Device>,
    /// The Pi's effective exempt list: its own config file's plus the one
    /// pushed to it. Lower-case colon form, each address once, at most
    /// [`MAX_EXEMPT_MACS`]; empty when the Pi does not say.
    pub exempt_macs: Vec<String>,
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
        exempt: v.get("exempt").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// The Pi's `exempt_macs`: the entries that are hardware addresses, in lower-case
/// colon form, each once, at most [`MAX_EXEMPT_MACS`]. Anything else (no list,
/// a list of another shape) is empty.
fn parse_exempt_macs(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(items) = v.get("exempt_macs").and_then(Value::as_array) else {
        return out;
    };
    for m in items.iter().filter_map(|x| normalize_mac(x.as_str()?)) {
        if out.len() >= MAX_EXEMPT_MACS {
            break;
        }
        if !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

/// Validate a `GET devices` answer. `None` when `devices` is missing or not a
/// list. Entries without a valid MAC are dropped; at most [`MAX_DEVICES`]
/// are kept (the Pi sends the one seen last first, so those are kept). The
/// exempt fields (`exempt` on a device, `exempt_macs` on top) are optional:
/// an older Pi has neither.
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
        exempt_macs: parse_exempt_macs(v),
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

/// `PUT /api/qbp/devices/exempt`: replace the Pi's pushed exempt list with
/// `macs`: one body `{"exempt":[…]}`, no chunking. Entries that are not
/// hardware addresses are skipped, the rest are sent in lower-case colon form,
/// each once, and no more than [`EXEMPT_MAX`] (the Pi refuses a longer list
/// with a 400; the store never holds more). An empty list is sent as it is: it
/// clears the Pi's list, so the caller decides whether it wants that.
/// Returns the size of the Pi's pushed list. `Absent` is the Pi saying 404
/// for the route: it has no exempt support (when the watchdog itself is
/// there, which the caller knows from its other calls). A 400 or any other
/// failure is an error.
pub fn put_exempt(api: &mut Pihole, macs: &[String]) -> Result<Qbp<u64>, ApiError> {
    let mut list: Vec<String> = Vec::new();
    for m in macs.iter().filter_map(|m| normalize_mac(m)) {
        if !list.contains(&m) {
            list.push(m);
        }
    }
    list.truncate(EXEMPT_MAX);
    let body = json!({ "exempt": list });
    Ok(
        match api.json_opt("PUT", "/api/qbp/devices/exempt", Some(&body))? {
            None => Qbp::Absent,
            Some(v) => Qbp::Present(num(&v, "exempt", 0)),
        },
    )
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
    // Read by the tests only.
    #[allow(dead_code)]
    pub fn pending(&self) -> u64 {
        self.pending
    }
}

// -- the poller ---------------------------------------------------------------

/// Whether the Pi behind this login has a watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// No qbp call has been answered yet (or a new session may know better).
    Unknown,
    Present,
    /// A qbp call was answered 404: a real Pi-hole.
    Absent,
}

/// Alerts the report carries (the newest changes).
pub const REPORT_ALERTS: usize = 50;
/// Devices the report carries (the ones seen last).
pub const REPORT_DEVICES: usize = 128;

/// A device of the Pi's inventory with what this PC knows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportDevice {
    pub device: Device,
    /// On this PC's known list.
    pub known: bool,
    /// The label from the known list, "" when there is none.
    pub label: String,
    /// On this PC's exempt list.
    pub exempt: bool,
}

/// `devices` with what this PC's known and exempt lists say about each, in
/// the same order.
pub fn annotate(devices: Vec<Device>, store: &Store) -> Vec<ReportDevice> {
    let mine: HashMap<&str, Option<&str>> = store
        .known
        .iter()
        .map(|k| (k.mac.as_str(), k.label.as_deref()))
        .collect();
    let exempt: HashSet<&str> = store.exempt.iter().map(|e| e.mac.as_str()).collect();
    devices
        .into_iter()
        .map(|d| {
            let entry = mine.get(d.mac.as_str());
            ReportDevice {
                known: entry.is_some(),
                label: entry.and_then(|l| *l).unwrap_or_default().to_string(),
                exempt: exempt.contains(d.mac.as_str()),
                device: d,
            }
        })
        .collect()
}

/// What the API thread tells the main thread after a watchdog cycle: the
/// final display data, so building the state costs nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchdogReport {
    /// `unknown`, `ok`, `absent`, `auth`, `tls` or `unreachable`.
    pub status: &'static str,
    /// The Pi's alert revision at the last answer.
    pub rev: u64,
    pub suppressed: u64,
    /// Alerts not acknowledged, among those held in memory.
    pub unacked: u64,
    /// Newest change first, at most [`REPORT_ALERTS`].
    pub alerts: Vec<Alert>,
    /// `waiting`, `learned`, `received`, or "" (not fetched yet).
    pub known_list: String,
    /// Last seen first, at most [`REPORT_DEVICES`]; empty until fetched.
    pub devices: Vec<ReportDevice>,
    /// Entries on this PC's known list.
    pub known_count: u64,
    /// Unix time of the last push that sent something (0 = never).
    pub pushed_at: u64,
    /// Why the last push failed, "" when it did not.
    pub push_error: String,
    /// Unix time of the last cycle the Pi answered (0 = never).
    pub polled_at: u64,
}

/// What one [`Poller::cycle`] produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CycleOut {
    /// Desktop notifications to show now, as `(title, body)`, already folded.
    pub notifications: Vec<(String, String)>,
    /// Whether the watchdog became present or absent during the cycle.
    pub presence_changed: bool,
}

/// How a push attempt ended (when it did not fail the cycle).
#[derive(Debug, PartialEq, Eq)]
enum Pushed {
    /// Done, or nothing was due.
    Ok,
    /// The Pi answered 404: there is no watchdog.
    Absent,
    /// Failed with an error that does not stop the cycle (it is in
    /// `push_error` and the push stays due).
    Failed,
}

/// The watchdog's state between cycles, for one API client: what the Pi
/// last said, what was already pushed to it, and what needs pushing. All
/// the logic of "one watchdog cycle" lives in [`cycle`](Poller::cycle); the
/// thread only decides when to call it. Time is passed in, as unix seconds.
#[derive(Debug)]
pub struct Poller {
    presence: Presence,
    /// The Pi's `rev` at the last alerts answer that was recorded.
    cursor: u64,
    /// The alerts seen, by id, at most [`MAX_ALERTS`] (lowest `rev` dropped).
    alerts: BTreeMap<u64, Alert>,
    inventory: Option<Inventory>,
    folder: Folder,
    /// `api.logins()` after the last successful push; `None` = never pushed
    /// with this client.
    pushed_logins: Option<u64>,
    /// A push was asked for (a restart, a `waiting` Pi) beyond what the
    /// other triggers say.
    push_due: bool,
    /// `api.logins()` when the absence was seen: a different value is a new
    /// session, which gets one more look.
    absent_logins: u64,
    /// `api.logins()` when the last alerts page was taken in; `None` = no
    /// page yet from this client. A different value later means a new
    /// session, so the Pi may have rebooted since: see
    /// [`restart`](Self::restart).
    alerts_logins: Option<u64>,
    /// `api.logins()` after the last exempt push the Pi answered (a 404
    /// counts: that was settled for the session); `None` = none with this
    /// client. The exempt list rides on the known list's triggers, but is
    /// tracked apart so that one failing never holds up the other.
    exempt_pushed_logins: Option<u64>,
    /// An exempt push was asked for (a restart, a `waiting` Pi) or the last
    /// attempt failed, beyond what the other triggers say.
    exempt_due: bool,
    /// `api.logins()` when the Pi answered 404 for the exempt route: it has
    /// no exempt support. While the session is the same the list is not
    /// sent again (the store keeps it due); a new session, a restart or a
    /// new client gets one more look, as the watchdog's own absence does.
    exempt_absent_logins: Option<u64>,
    /// Why the last exempt push failed, "" when it did not.
    exempt_error: String,
    /// `"<address>|<pin>"` of the Pi-hole this poller talks to: what the
    /// store's `absent_for` is compared with. `None` = no verdict is kept.
    verdict_key: Option<String>,
    /// The store may still say "absent" for this Pi-hole (it did when the
    /// poller started, or this poller wrote it): the first time the watchdog
    /// is seen present, that is cleared.
    verdict_stale: bool,
    pushed_at: u64,
    push_error: String,
    polled_at: u64,
    status: &'static str,
    rev: u64,
    suppressed: u64,
}

impl Default for Poller {
    fn default() -> Self {
        Self::new()
    }
}

impl Poller {
    pub fn new() -> Self {
        Self {
            presence: Presence::Unknown,
            cursor: 0,
            alerts: BTreeMap::new(),
            inventory: None,
            folder: Folder::new(),
            pushed_logins: None,
            push_due: false,
            absent_logins: 0,
            alerts_logins: None,
            exempt_pushed_logins: None,
            exempt_due: false,
            exempt_absent_logins: None,
            exempt_error: String::new(),
            verdict_key: None,
            verdict_stale: false,
            pushed_at: 0,
            push_error: String::new(),
            polled_at: 0,
            status: "unknown",
            rev: 0,
            suppressed: 0,
        }
    }

    pub fn presence(&self) -> Presence {
        self.presence
    }

    /// Keep the "no watchdog here" verdict in the store under `key` (see
    /// [`Store::absent_for`]): written when the Pi-hole turns out to have no
    /// watchdog, cleared when one is seen.
    pub fn with_verdict_key(mut self, key: String) -> Self {
        self.verdict_key = Some(key);
        self.verdict_stale = true;
        self
    }

    /// The thread made a new API client: it has pushed nothing, and its
    /// login counter starts again, so a remembered absence is void, and so
    /// is what was learned from the Pi before: it may have rebooted while
    /// there was no client, so the next answer is taken from 0.
    pub fn client_replaced(&mut self) {
        self.pushed_logins = None;
        self.exempt_pushed_logins = None;
        self.exempt_absent_logins = None;
        self.alerts_logins = None;
        self.cursor = 0;
        self.alerts.clear();
        self.inventory = None;
        if self.presence == Presence::Absent {
            self.presence = Presence::Unknown;
        }
    }

    /// A cycle failed with `e`: the status says why, the data stays.
    pub fn fail(&mut self, e: &ApiError) {
        self.status = e.status();
    }

    /// The Pi has no watchdog: forget what it said, and keep the verdict in
    /// the store so a closed qnet does not ask again after a restart.
    fn mark_absent(&mut self, api: &Pihole, store_path: &Path, now: u64) {
        self.presence = Presence::Absent;
        self.absent_logins = api.logins();
        if let Some(key) = self.verdict_key.clone() {
            // Best effort: without it a closed qnet asks once per start.
            let _ = wdstore::update(store_path, |s| s.absent_for = Some(key));
            self.verdict_stale = true;
        }
        self.alerts_logins = None;
        self.alerts.clear();
        self.inventory = None;
        self.cursor = 0;
        self.rev = 0;
        self.suppressed = 0;
        self.push_error.clear();
        self.exempt_error.clear();
        self.exempt_absent_logins = None;
        self.status = "absent";
        self.polled_at = now;
    }

    /// One watchdog cycle on `api`; see the plan's "One watchdog cycle".
    ///
    /// 1. When absent, nothing is asked unless a new login session began.
    /// 2. Push what is due (acknowledged keys, then the known list, then the
    ///    exempt list, whose trouble never fails the cycle).
    /// 3. Fetch the alerts changed since the cursor. If the Pi may have
    ///    restarted (a new login session since the last page, a `rev` below
    ///    the cursor, or an `id` the map holds under another key) the cursor,
    ///    the alerts and the devices are reset, a push is made and the alerts
    ///    come again from 0 (once per cycle at most).
    /// 4. Record the page in the store (acknowledged alerts, notified ones).
    ///    If the store cannot be written (its lock stays taken) the cursor
    ///    does not move: the next cycle gets the same alerts again and tries
    ///    again, so a notification is late but never lost. Meanwhile no
    ///    notification goes out, since it could not be recorded as sent.
    /// 5. Fold the new notifications (also called with none, so a held fold
    ///    goes out).
    /// 6. With `with_devices`: fetch the inventory; a `waiting` Pi and a
    ///    non-empty known list make another push at once. A failing devices
    ///    read or push here never fails the cycle (the alerts were done).
    ///
    /// An `Err` means the Pi could not be talked to (or the alerts answer was
    /// bad) and nothing was recorded; the caller reports it with
    /// [`fail`](Self::fail).
    pub fn cycle(
        &mut self,
        api: &mut Pihole,
        store_path: &Path,
        now: u64,
        with_devices: bool,
    ) -> Result<CycleOut, ApiError> {
        let before = self.presence;
        let notifications = self.run_cycle(api, store_path, now, with_devices)?;
        Ok(CycleOut {
            notifications,
            presence_changed: self.presence != before,
        })
    }

    fn run_cycle(
        &mut self,
        api: &mut Pihole,
        store_path: &Path,
        now: u64,
        with_devices: bool,
    ) -> Result<Vec<(String, String)>, ApiError> {
        // 1.
        if self.presence == Presence::Absent {
            if api.logins() == self.absent_logins {
                return Ok(Vec::new());
            }
            self.presence = Presence::Unknown;
        }
        // 2. and 3.
        if self.push(api, store_path, now)? == Pushed::Absent {
            return Ok(Vec::new());
        }
        let mut restarted = false;
        let page = loop {
            match get_alerts(api, self.cursor)? {
                Qbp::Absent => {
                    self.mark_absent(api, store_path, now);
                    return Ok(Vec::new());
                }
                Qbp::Present(p) => {
                    // Once per cycle: after the restart the cursor is 0, so
                    // nothing here can fail the checks for want of history.
                    let restart = if restarted {
                        None
                    } else {
                        self.restart_reason(api, &p)
                    };
                    let Some(force_push) = restart else {
                        break p;
                    };
                    restarted = true;
                    self.restart(force_push);
                    if self.push(api, store_path, now)? == Pushed::Absent {
                        return Ok(Vec::new());
                    }
                }
            }
        };
        self.alerts_logins = Some(api.logins());
        self.presence = Presence::Present;
        self.rev = page.rev;
        self.suppressed = page.suppressed;
        // 4.
        let new = match record(store_path, &page, now) {
            Ok(new) => {
                self.cursor = page.rev;
                self.clear_verdict(store_path);
                new
            }
            Err(_) => Vec::new(),
        };
        self.merge(page.alerts);
        // 5.
        let notifications = self.folder.take(now, new);
        // 6.
        if with_devices {
            match get_devices(api) {
                Ok(Qbp::Present(inv)) => {
                    let waiting = inv.known_list == "waiting";
                    self.inventory = Some(inv);
                    if waiting && !Store::load(store_path).known_macs().is_empty() {
                        self.push_due = true;
                        self.exempt_due = true;
                        // Failures are in `push_error`; an absence is below.
                        let _ = self.push(api, store_path, now);
                    }
                }
                Ok(Qbp::Absent) => self.mark_absent(api, store_path, now),
                Err(_) => {}
            }
        }
        if self.presence == Presence::Present {
            self.polled_at = now;
            self.status = "ok";
        }
        Ok(notifications)
    }

    /// A watchdog was seen: the store must not say "absent" for this Pi-hole
    /// any more (a closed qnet would never poll it). Tried again on every
    /// cycle until the store took it.
    fn clear_verdict(&mut self, store_path: &Path) {
        if self.verdict_stale && self.verdict_key.is_some() {
            let cleared = wdstore::update(store_path, |s| s.absent_for = None);
            self.verdict_stale = cleared.is_err();
        }
    }

    /// Whether `page` (asked for with the current cursor) shows that the Pi
    /// is not the one the cursor and the alert map came from, so they cannot
    /// be trusted. `Some(force_push)`: a restart is due, and `force_push`
    /// says the lists must be pushed again whatever the session counter says.
    ///
    /// - A new login session since the last page (`logins()` changed, also
    ///   when the stats poll was the one to log in again): the Pi may have
    ///   rebooted, and a reboot that has already made as many changes as the
    ///   cursor looks like no restart at all by its `rev`. The session
    ///   counter makes the push due by itself.
    /// - `rev` below the cursor: it went backwards.
    /// - An alert whose `id` the map holds under another key: ids restart at
    ///   a reboot, so this is a different alert.
    fn restart_reason(&self, api: &Pihole, page: &AlertsPage) -> Option<bool> {
        if self.alerts_logins.is_some_and(|l| l != api.logins()) {
            return Some(false);
        }
        let collides = page
            .alerts
            .iter()
            .any(|a| self.alerts.get(&a.id).is_some_and(|old| old.key != a.key));
        (page.rev < self.cursor || collides).then_some(true)
    }

    /// The Pi restarted (or may have): forget its alerts and devices and
    /// start from revision 0. `force_push` marks the lists due as well.
    fn restart(&mut self, force_push: bool) {
        self.cursor = 0;
        self.alerts.clear();
        self.inventory = None;
        // It may be newer software now: ask again for the exempt list.
        self.exempt_absent_logins = None;
        if force_push {
            self.push_due = true;
            self.exempt_due = true;
        }
    }

    /// Step 2: push what is due. `Err` only for the failures that mean the
    /// Pi cannot be talked to at all (auth, tls, unreachable); any other
    /// failure is kept in `push_error` and does not stop the cycle.
    fn push(&mut self, api: &mut Pihole, store_path: &Path, now: u64) -> Result<Pushed, ApiError> {
        match self.try_push(api, store_path, now) {
            Ok(Qbp::Absent) => {
                self.mark_absent(api, store_path, now);
                Ok(Pushed::Absent)
            }
            Ok(Qbp::Present(())) => Ok(Pushed::Ok),
            Err(e) => {
                self.push_error = e.message().to_string();
                self.push_due = true;
                match e {
                    ApiError::Auth(_) | ApiError::Tls(_) | ApiError::Unreachable(_) => Err(e),
                    ApiError::Other(_) => Ok(Pushed::Failed),
                }
            }
        }
    }

    fn try_push(
        &mut self,
        api: &mut Pihole,
        store_path: &Path,
        now: u64,
    ) -> Result<Qbp<()>, ApiError> {
        let store = Store::load(store_path);
        let due = self.pushed_logins != Some(api.logins()) || self.push_due || store.push_due();
        let lists = if due {
            self.push_lists(api, store_path, &store, now)
        } else {
            Ok(Qbp::Present(()))
        };
        // The exempt list goes after the other lists, but not behind them: a
        // known list or acks that keep failing (the Pi answered, with an
        // error) must not keep the exempt devices ad-blocked. It is left out
        // only when there is nothing to talk to: no watchdog (a real
        // Pi-hole, which answered 404 to the lists) or a Pi that cannot be
        // reached at all (the same failure, slowly, a second time). Its own
        // trouble never fails the cycle: see `push_exempt`.
        match &lists {
            Ok(Qbp::Absent)
            | Err(ApiError::Auth(_) | ApiError::Tls(_) | ApiError::Unreachable(_)) => {}
            _ => self.push_exempt(api, store_path, &store, now),
        }
        lists
    }

    /// The acknowledged keys and the known list, which are due: `store` is
    /// what was read at the start of the push.
    fn push_lists(
        &mut self,
        api: &mut Pihole,
        store_path: &Path,
        store: &Store,
        now: u64,
    ) -> Result<Qbp<()>, ApiError> {
        let mut sent = false;
        let keys = store.acked_keys();
        if !keys.is_empty() {
            if restore_acked(api, &keys)? == Qbp::Absent {
                return Ok(Qbp::Absent);
            }
            sent = true;
        }
        // An empty list is pushed only when an edit emptied it: otherwise it
        // would make the Pi raise every device.
        let macs = store.known_macs();
        let send_known = !macs.is_empty() || store.push_due();
        if send_known {
            if put_known(api, &macs)? == Qbp::Absent {
                return Ok(Qbp::Absent);
            }
            sent = true;
        }
        // Read after the calls: a re-login during the push is this session.
        self.pushed_logins = Some(api.logins());
        self.push_due = false;
        self.push_error.clear();
        if sent {
            self.pushed_at = now;
        }
        if send_known {
            // `store` was read before the push: an edit made while it was on
            // the wire stays due.
            let generation = store.known_gen;
            if let Err(e) = wdstore::update(store_path, |s| s.mark_pushed(generation)) {
                self.push_error = format!("the push could not be recorded: {e}");
            }
        }
        Ok(Qbp::Present(()))
    }

    /// The exempt list, when it is due: in a new login session (with the
    /// known list's), after a restart or a `waiting` Pi (the same flags that
    /// make the lists due), after an edit of it, and after a failed attempt.
    /// It never fails the push and never stops the cycle: whatever it
    /// runs into is kept in `exempt_error` and the list stays due (on the same
    /// schedule as a failed known list), and a 404 (a Pi without exempt
    /// support) is a verdict for the session, not an error. (A real Pi-hole
    /// has answered 404 to the lists above, as a rule, and to the alerts at
    /// the latest.) Unlike the known list, an empty list is sent too: see
    /// the comment where it is decided.
    fn push_exempt(&mut self, api: &mut Pihole, store_path: &Path, store: &Store, now: u64) {
        if self.exempt_absent_logins == Some(api.logins()) {
            return;
        }
        let due = self.exempt_pushed_logins != Some(api.logins())
            || self.exempt_due
            || store.exempt_push_due();
        if !due {
            return;
        }
        let macs = store.exempt_macs();
        // An empty list is pushed too, not only after an edit: this PC's list
        // is the master, so a Pi that still holds exemptions from a store
        // that was lost or reset must hear that there are none. Only once the
        // watchdog has been seen, so that a real Pi-hole is never asked for
        // it; until then it is asked again at the next cycle.
        if macs.is_empty() && !store.exempt_push_due() && self.presence != Presence::Present {
            return;
        }
        match put_exempt(api, &macs) {
            Ok(Qbp::Present(_)) => {}
            Ok(Qbp::Absent) => {
                self.exempt_absent_logins = Some(api.logins());
                self.exempt_pushed_logins = Some(api.logins());
                self.exempt_due = false;
                self.exempt_error.clear();
                return;
            }
            Err(e) => {
                self.exempt_error = e.message().to_string();
                self.exempt_due = true;
                return;
            }
        }
        // Read after the call: a re-login during the push is this session.
        self.exempt_pushed_logins = Some(api.logins());
        self.exempt_due = false;
        self.exempt_error.clear();
        self.pushed_at = now;
        if store.exempt_push_due() {
            // `store` was read before the push: an edit made while it was on
            // the wire stays due.
            let generation = store.exempt_gen;
            if let Err(e) = wdstore::update(store_path, |s| s.mark_exempt_pushed(generation)) {
                self.exempt_error = format!("the push could not be recorded: {e}");
            }
        }
    }

    /// Merge a page into the alert map: by id, the lowest `rev` dropped
    /// beyond [`MAX_ALERTS`].
    fn merge(&mut self, alerts: Vec<Alert>) {
        for a in alerts {
            self.alerts.insert(a.id, a);
        }
        while self.alerts.len() > MAX_ALERTS {
            let Some(lowest) = self.alerts.values().min_by_key(|a| a.rev).map(|a| a.id) else {
                break;
            };
            self.alerts.remove(&lowest);
        }
    }

    /// Why the last push failed: the known list's or acks' reason, else the
    /// exempt list's (marked as such), "" when none did.
    fn push_error(&self) -> String {
        if !self.push_error.is_empty() || self.exempt_error.is_empty() {
            self.push_error.clone()
        } else {
            format!("exempt list: {}", self.exempt_error)
        }
    }

    /// The display data for the main thread; `store` is this PC's list (for
    /// the `known` flags and labels).
    pub fn report(&self, store: &Store) -> WatchdogReport {
        let mut alerts: Vec<Alert> = self.alerts.values().cloned().collect();
        alerts.sort_by(|a, b| b.rev.cmp(&a.rev).then(b.id.cmp(&a.id)));
        alerts.truncate(REPORT_ALERTS);
        let unacked = self.alerts.values().filter(|a| !a.acked).count() as u64;

        let (known_list, mut devices) = match &self.inventory {
            Some(inv) => (inv.known_list.clone(), inv.devices.clone()),
            None => (String::new(), Vec::new()),
        };
        // The Pi sends the one seen last first; do not rely on it.
        devices.sort_by_key(|d| std::cmp::Reverse(d.last_unix));
        devices.truncate(REPORT_DEVICES);
        let devices = annotate(devices, store);

        WatchdogReport {
            status: self.status,
            rev: self.rev,
            suppressed: self.suppressed,
            unacked,
            alerts,
            known_list,
            devices,
            known_count: store.known.len() as u64,
            pushed_at: self.pushed_at,
            push_error: self.push_error(),
            polled_at: self.polled_at,
        }
    }
}

/// Step 4: record a page in the store, in one locked update. Acknowledged
/// alerts add their key to `acked`; the others that still need their
/// notification are marked as notified and returned as `(title, body)`.
/// Nothing is written (or locked) for an empty page.
fn record(
    store_path: &Path,
    page: &AlertsPage,
    now: u64,
) -> std::io::Result<Vec<(String, String)>> {
    if page.alerts.is_empty() {
        return Ok(Vec::new());
    }
    wdstore::update(store_path, |s| {
        let mut new = Vec::new();
        for a in &page.alerts {
            if a.acked {
                s.add_acked(&a.key, now);
            } else if s.should_notify(&a.key, a.first_unix) {
                new.push(notification_for(a));
                s.mark_notified(&a.key, a.first_unix, now);
            }
        }
        new
    })
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
                exempt: false,
            }
        );
        assert_eq!(inv.devices[1].mac, "02:00:00:00:00:ab", "normalised");
        assert!(!inv.devices[1].known);
        // An older Pi sends no exempt fields: no flags, no list.
        assert!(inv.devices.iter().all(|d| !d.exempt));
        assert!(inv.exempt_macs.is_empty());
    }

    #[test]
    fn the_exempt_fields_of_a_devices_answer_parse() {
        let v = json!({"known_list": "received",
            "exempt_macs": ["02:00:00:00:00:07", "02-00-00-00-00-AB"],
            "devices": [
            {"mac": "02:00:00:00:00:07", "known": true, "exempt": true},
            {"mac": "02:00:00:00:00:08", "known": true, "exempt": false},
            {"mac": "02:00:00:00:00:09", "known": true},
        ]});
        let inv = parse_devices(&v).unwrap();
        assert_eq!(inv.exempt_macs, ["02:00:00:00:00:07", "02:00:00:00:00:ab"]);
        let flags: Vec<bool> = inv.devices.iter().map(|d| d.exempt).collect();
        assert_eq!(flags, [true, false, false]);
    }

    #[test]
    fn odd_exempt_fields_are_read_tolerantly() {
        let exempt_of = |d: Value| {
            let v = json!({"devices": [{"mac": mac(1), "exempt": d}]});
            parse_devices(&v).unwrap().devices[0].exempt
        };
        assert!(exempt_of(json!(true)));
        assert!(!exempt_of(json!(false)));
        for odd in [json!(null), json!("true"), json!(1), json!([]), json!({})] {
            assert!(!exempt_of(odd.clone()), "{odd}");
        }
        let list_of = |l: Value| {
            parse_devices(&json!({"devices": [], "exempt_macs": l}))
                .unwrap()
                .exempt_macs
        };
        assert!(list_of(json!(null)).is_empty());
        assert!(list_of(json!("02:00:00:00:00:01")).is_empty());
        assert!(list_of(json!({})).is_empty());
        assert!(list_of(json!([])).is_empty());
        // Bad entries are dropped, the rest is normalised, kept in order and
        // listed once.
        assert_eq!(
            list_of(json!([
                "nonsense",
                5,
                null,
                "02:00:00:00:00:0B",
                "02:00:00:00:00:0a",
                "02-00-00-00-00-0b",
                "02:00:00:00:00"
            ])),
            ["02:00:00:00:00:0b", "02:00:00:00:00:0a"]
        );
        // A list from a Pi that has gone wild is bounded.
        let many: Vec<String> = (1..=2000).map(mac).collect();
        let got = list_of(json!(many));
        assert_eq!(got.len(), MAX_EXEMPT_MACS);
        assert_eq!(got[0], mac(1));
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
            } else if first.starts_with("PUT /api/qbp/devices/exempt ") {
                let n = body_of(req)["exempt"].as_array().unwrap().len();
                Some(ok_json(&format!(r#"{{"exempt":{n}}}"#)))
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
        assert_eq!(put_exempt(&mut api, &macs(2)).unwrap(), Qbp::Absent);
        assert_eq!(
            qbp_lines(&log),
            [
                "GET /api/qbp/alerts?since=0 HTTP/1.1",
                "POST /api/qbp/alerts/7/ack HTTP/1.1",
                "PUT /api/qbp/alerts/acked HTTP/1.1",
                "GET /api/qbp/devices HTTP/1.1",
                "PUT /api/qbp/devices/known HTTP/1.1",
                "PUT /api/qbp/devices/exempt HTTP/1.1",
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
        assert_eq!(put_exempt(&mut api, &macs(1)).unwrap(), Qbp::Present(0));
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
        assert!(put_exempt(&mut api, &macs(1)).is_err());
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
    fn put_exempt_sends_the_whole_list_in_one_body() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        assert_eq!(put_exempt(&mut api, &macs(3)).unwrap(), Qbp::Present(3));
        assert_eq!(
            puts(&log, "/api/qbp/devices/exempt"),
            [json!({"exempt": [mac(1), mac(2), mac(3)]})],
            "exactly this body: no append, no complete"
        );
    }

    #[test]
    fn put_exempt_normalises_dedups_and_skips_bad_entries() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        let list = vec![
            "02-00-00-00-00-AA".to_string(),
            "nonsense".to_string(),
            "02:00:00:00:00:bb".to_string(),
            "02:00:00:00:00:AA".to_string(),
        ];
        assert_eq!(put_exempt(&mut api, &list).unwrap(), Qbp::Present(2));
        assert_eq!(
            puts(&log, "/api/qbp/devices/exempt"),
            [json!({"exempt": ["02:00:00:00:00:aa", "02:00:00:00:00:bb"]})]
        );
    }

    #[test]
    fn put_exempt_with_an_empty_list_clears_the_pis_list() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        assert_eq!(put_exempt(&mut api, &[]).unwrap(), Qbp::Present(0));
        assert_eq!(
            puts(&log, "/api/qbp/devices/exempt"),
            [json!({"exempt": []})]
        );
    }

    #[test]
    fn put_exempt_never_sends_more_than_the_pi_takes() {
        let log: Log = Arc::default();
        let srv = watchdog_pi(log.clone());
        let mut api = client(&srv);
        let input = macs(100);
        put_exempt(&mut api, &input).unwrap();
        let sent = puts(&log, "/api/qbp/devices/exempt");
        assert_eq!(sent.len(), 1, "one body, no chunking");
        assert_eq!(sent[0], json!({"exempt": &input[..64]}), "the first 64");
        assert!(body_len(&sent[0]) <= QBP_BODY_MAX);
    }

    #[test]
    fn put_exempt_answers_absent_on_a_404_and_an_error_on_a_refusal() {
        let log: Log = Arc::default();
        let srv = real_pihole(log.clone());
        let mut api = client(&srv);
        assert_eq!(put_exempt(&mut api, &macs(1)).unwrap(), Qbp::Absent);
        assert_eq!(puts(&log, "/api/qbp/devices/exempt").len(), 1);

        // 400: the body was refused. An error, not an absence.
        let srv = serve(16, |_, req| {
            if first_line(req).starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else {
                Some(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            }
        });
        let mut api = client(&srv);
        assert!(matches!(
            put_exempt(&mut api, &macs(1)),
            Err(ApiError::Other(m)) if m.contains("400")
        ));
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

    // -- the poller against a fake Pi ------------------------------------------

    use crate::fakeqbp::{self, FakePi, T0};
    use std::path::PathBuf;

    /// A poller, its client and its store, against a fake Pi.
    struct Rig {
        pi: FakePi,
        api: Pihole,
        dir: tempfile::TempDir,
        poller: Poller,
    }

    impl Rig {
        fn new() -> Self {
            Self::on(FakePi::start(200))
        }
        fn on(pi: FakePi) -> Self {
            let api = pi.client();
            Self {
                pi,
                api,
                dir: tempfile::tempdir().unwrap(),
                poller: Poller::new(),
            }
        }
        fn path(&self) -> PathBuf {
            self.dir.path().join("watchdog.json")
        }
        fn store(&self) -> Store {
            Store::load(&self.path())
        }
        fn edit<R>(&self, f: impl FnOnce(&mut Store) -> R) -> R {
            wdstore::update(&self.path(), f).unwrap()
        }
        fn try_cycle(&mut self, now: u64, devices: bool) -> Result<CycleOut, ApiError> {
            let path = self.path();
            let res = self.poller.cycle(&mut self.api, &path, now, devices);
            // As the thread does: the fake serves one connection at a time.
            self.api.close_idle();
            res
        }
        fn cycle(&mut self, now: u64) -> CycleOut {
            self.try_cycle(now, false).unwrap()
        }
        fn cycle_with_devices(&mut self, now: u64) -> CycleOut {
            self.try_cycle(now, true).unwrap()
        }
        fn report(&self) -> WatchdogReport {
            self.poller.report(&self.store())
        }
        fn acked_puts(&self) -> Vec<Value> {
            self.pi.with(|s| s.acked_puts.clone())
        }
        fn known_puts(&self) -> Vec<Value> {
            self.pi.with(|s| s.known_puts.clone())
        }
        fn since(&self) -> Vec<u64> {
            self.pi.with(|s| s.since.clone())
        }
        /// 3 acknowledged keys and a known list of `n` MACs, as the CLI and
        /// an earlier watcher would have left them.
        fn prepare(&self, n: usize) {
            self.edit(|s| {
                for i in 1..=3 {
                    s.add_acked(&fakeqbp::key(100 + i), T0);
                }
                for i in 1..=n {
                    s.know(&fakeqbp::mac(i), None, T0);
                }
            });
        }
    }

    fn assert_chunks(puts: &[Value], macs: &[String]) {
        assert!(puts.len() >= 2, "{} chunks", puts.len());
        let last = puts.len() - 1;
        let mut all = Vec::new();
        for (i, body) in puts.iter().enumerate() {
            assert_eq!(body["append"], json!(i > 0), "chunk {i}: append");
            assert_eq!(body["complete"], json!(i == last), "chunk {i}: complete");
            assert!(body.to_string().len() <= QBP_BODY_MAX, "chunk {i} too big");
            all.extend(
                body["known"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m.as_str().unwrap().to_string()),
            );
        }
        assert_eq!(all, macs, "every MAC, once, in order");
    }

    /// Index of the first logged request that begins with `prefix`.
    fn first_at(pi: &FakePi, prefix: &str) -> usize {
        pi.with(|s| s.log.iter().position(|l| l.starts_with(prefix)))
            .unwrap_or_else(|| panic!("no request {prefix}"))
    }

    #[test]
    fn the_first_cycle_pushes_the_acks_then_the_known_list_in_chunks_then_fetches_alerts() {
        let mut rig = Rig::new();
        rig.prepare(250);
        let out = rig.cycle(T0 + 1);
        assert!(out.notifications.is_empty());
        assert!(out.presence_changed, "unknown to present");
        assert_eq!(rig.poller.presence(), Presence::Present);

        let keys: Vec<String> = (1..=3).map(|i| fakeqbp::key(100 + i)).collect();
        assert_eq!(rig.acked_puts(), vec![json!({ "acked": keys })]);
        let macs: Vec<String> = (1..=250).map(fakeqbp::mac).collect();
        assert_chunks(&rig.known_puts(), &macs);
        assert_eq!(rig.known_puts().len(), 2);
        assert_eq!(rig.since(), vec![0]);

        // Acks first, then the list, then the alerts.
        let acked = first_at(&rig.pi, "PUT /api/qbp/alerts/acked");
        let known = first_at(&rig.pi, "PUT /api/qbp/devices/known");
        let alerts = first_at(&rig.pi, "GET /api/qbp/alerts");
        assert!(acked < known && known < alerts);

        assert!(!rig.store().push_due(), "the push was recorded");
        let r = rig.report();
        assert_eq!(
            (r.status, r.pushed_at, r.push_error.as_str()),
            ("ok", T0 + 1, "")
        );
        assert_eq!((r.known_count, r.polled_at), (250, T0 + 1));

        // Nothing is due any more: only the alerts come.
        rig.cycle(T0 + 2);
        assert_eq!(rig.acked_puts().len(), 1);
        assert_eq!(rig.known_puts().len(), 2);
        assert_eq!(rig.since(), vec![0, 0]);
    }

    #[test]
    fn an_empty_known_list_is_never_pushed_unless_an_edit_emptied_it() {
        let mut rig = Rig::new();
        // Nothing to push at all: not a request, and not a "pushed at".
        rig.cycle(T0);
        assert!(rig.acked_puts().is_empty() && rig.known_puts().is_empty());
        assert_eq!(rig.report().pushed_at, 0);

        // Acks only: they go, the empty list does not, also not when the
        // Pi says it is waiting for one.
        rig.edit(|s| s.add_acked(&fakeqbp::key(101), T0));
        rig.poller.client_replaced();
        rig.cycle_with_devices(T0 + 1);
        assert_eq!(rig.acked_puts().len(), 1);
        rig.pi.set_known_list("waiting");
        rig.cycle_with_devices(T0 + 2);
        assert!(rig.known_puts().is_empty(), "{:?}", rig.known_puts());
        assert_eq!(rig.report().known_list, "waiting");
        assert_eq!(rig.report().pushed_at, T0 + 1);

        // An edit that emptied the list is a change the Pi has to hear.
        rig.edit(|s| {
            s.know(&fakeqbp::mac(1), None, T0);
            s.forget(&fakeqbp::mac(1));
        });
        assert!(rig.store().push_due() && rig.store().known.is_empty());
        rig.cycle(T0 + 3);
        assert_eq!(
            rig.known_puts(),
            vec![json!({"known": [], "append": false, "complete": true})]
        );
        assert!(!rig.store().push_due());
        rig.cycle(T0 + 4);
        assert_eq!(rig.known_puts().len(), 1, "and only once");
    }

    #[test]
    fn a_new_login_session_restarts_the_cycle_and_pushes_in_the_same_cycle() {
        let mut rig = Rig::new();
        rig.prepare(250);
        rig.cycle(T0);
        assert_eq!((rig.acked_puts().len(), rig.known_puts().len()), (1, 2));
        assert_eq!(rig.pi.with(|s| s.logins), 1);

        // The Pi forgets the session. The re-login happens inside the alerts
        // request: a new session means the Pi may have rebooted, so the
        // cycle takes its restart path (push, then the alerts from 0 again)
        // right away.
        rig.pi.invalidate();
        rig.cycle(T0 + 1);
        assert_eq!(rig.pi.with(|s| s.logins), 2);
        assert_eq!(rig.acked_puts().len(), 2);
        let puts = rig.known_puts();
        assert_eq!(puts.len(), 4, "the whole list again, in two chunks");
        let macs: Vec<String> = (1..=250).map(fakeqbp::mac).collect();
        assert_chunks(&puts[2..], &macs);
        assert_eq!(rig.since(), vec![0, 0, 0], "asked again from 0");
        // And then it is quiet again.
        rig.cycle(T0 + 2);
        assert_eq!((rig.acked_puts().len(), rig.known_puts().len()), (2, 4));
        assert_eq!(rig.since(), vec![0, 0, 0, 0]);
    }

    /// 3 alerts seen (cursor 3), then the Pi reboots and has already raised 5
    /// by the time it is asked again. The first of the five repeats an old
    /// key (a later instance of it).
    fn reboot_with_five(rig: &mut Rig) -> CycleOut {
        rig.prepare(250);
        for i in 1..=3 {
            rig.pi.raise("dga", "old.example", Some("192.0.2.5"), i);
        }
        assert_eq!(rig.cycle(T0 + 1).notifications.len(), 3);
        rig.cycle(T0 + 2);
        assert_eq!(rig.since(), vec![0, 3]);
        rig.pi.reboot();
        for (i, k) in [1, 12, 13, 14, 15].into_iter().enumerate() {
            rig.pi
                .raise("beacon", &format!("new{i}.example"), Some("192.0.2.6"), k);
        }
        rig.cycle(T0 + 200)
    }

    fn check_the_five_after_a_reboot(rig: &Rig, out: &CycleOut) {
        // All five are new alerts: 3 shown, the other 2 folded.
        assert_eq!(out.notifications.len(), 4, "{:?}", out.notifications);
        assert_eq!(
            out.notifications[3],
            ("Watchdog".to_string(), "2 more alerts".to_string())
        );
        let store = rig.store();
        for k in [1, 12, 13, 14, 15] {
            let n = store.notified.iter().find(|n| n.key == fakeqbp::key(k));
            assert!(
                n.is_some_and(|n| n.first_unix > T0 + 100),
                "key {k} was announced as a new-boot alert: {n:?}"
            );
        }
        // The map holds the new boot's alerts only (ids 1 to 5, new subjects).
        let r = rig.report();
        assert_eq!(r.rev, 5);
        let mut ids: Vec<u64> = r.alerts.iter().map(|a| a.id).collect();
        ids.sort();
        assert_eq!(ids, [1, 2, 3, 4, 5], "{:?}", r.alerts);
        assert!(
            r.alerts.iter().all(|a| a.kind == "beacon"),
            "no alert of the old boot is left: {:?}",
            r.alerts
        );
        assert_eq!(r.unacked, 5);
        // The new Pi has the acks and the list again.
        assert_eq!(rig.acked_puts().len(), 2);
        let puts = rig.known_puts();
        assert_eq!(puts.len(), 4);
        let macs: Vec<String> = (1..=250).map(fakeqbp::mac).collect();
        assert_chunks(&puts[2..], &macs);
        assert_eq!(rig.pi.with(|s| s.known.len()), 250);
    }

    #[test]
    fn a_reboot_that_already_made_as_many_changes_as_the_cursor_is_noticed_by_its_session() {
        let mut rig = Rig::new();
        let out = reboot_with_five(&mut rig);
        // rev 5 is not below the cursor 3, so only the new session shows it:
        // asked from 3 first (that request logged in again), then from 0.
        assert_eq!(rig.since(), vec![0, 3, 3, 0]);
        check_the_five_after_a_reboot(&rig, &out);
        // One restart, not one per cycle.
        rig.cycle(T0 + 201);
        assert_eq!(rig.since(), vec![0, 3, 3, 0, 5]);
        assert_eq!(rig.acked_puts().len(), 2);
        assert_eq!(rig.known_puts().len(), 4);
    }

    #[test]
    fn a_session_that_the_stats_poll_logged_in_again_still_restarts_without_a_second_push() {
        let mut rig = Rig::new();
        rig.prepare(5);
        for i in 1..=3 {
            rig.pi.raise("dga", "old.example", Some("192.0.2.5"), i);
        }
        rig.cycle(T0 + 1);
        rig.cycle(T0 + 2);
        assert_eq!(rig.since(), vec![0, 3]);
        assert_eq!((rig.acked_puts().len(), rig.known_puts().len()), (1, 1));
        rig.pi.reboot();
        for k in 11..=15 {
            rig.pi.raise("beacon", "new.example", None, k);
        }
        // In an open panel the stats poll goes first and logs in again.
        rig.api.summary().unwrap();
        rig.api.close_idle();
        assert_eq!(rig.pi.with(|s| s.logins), 2);
        rig.cycle(T0 + 200);
        assert_eq!(rig.since(), vec![0, 3, 3, 0], "from 3, then from 0");
        // The push was due at the start of the cycle (new session) and is not
        // repeated by the restart.
        assert_eq!((rig.acked_puts().len(), rig.known_puts().len()), (2, 2));
        let ids: Vec<u64> = rig.report().alerts.iter().map(|a| a.id).collect();
        assert_eq!(ids.len(), 5);
        assert!(rig.report().alerts.iter().all(|a| a.kind == "beacon"));
    }

    #[test]
    fn an_id_the_map_holds_under_another_key_is_a_restart_even_with_the_same_session() {
        let mut rig = Rig::new();
        rig.prepare(5);
        rig.pi.raise("dga", "old.example", None, 1);
        rig.pi.raise("dga", "old.example", None, 2);
        rig.pi.repeat(1);
        rig.cycle(T0 + 1);
        assert_eq!(rig.report().alerts.len(), 2);
        assert_eq!((rig.acked_puts().len(), rig.known_puts().len()), (1, 1));
        // A reboot the session survived; the new boot made as many changes
        // as the cursor (3) and more, with ids 1 and 2 again.
        rig.pi.reboot_keeping_session();
        rig.pi.raise("beacon", "new.example", None, 21);
        rig.pi.raise("beacon", "new.example", None, 22);
        for _ in 0..3 {
            rig.pi.repeat(1);
        }
        let out = rig.cycle(T0 + 200);
        assert_eq!(rig.pi.with(|s| s.logins), 1, "no new session");
        assert_eq!(rig.since(), vec![0, 3, 0]);
        // Both new alerts (key 22 was not in the page asked from 3) notify,
        // and the old ones are gone from the map.
        assert_eq!(out.notifications.len(), 2, "{:?}", out.notifications);
        let r = rig.report();
        let mut keys: Vec<String> = r.alerts.iter().map(|a| a.key.clone()).collect();
        keys.sort();
        assert_eq!(keys, [fakeqbp::key(21), fakeqbp::key(22)]);
        // The lists went to the rebooted Pi.
        assert_eq!((rig.acked_puts().len(), rig.known_puts().len()), (2, 2));
        assert_eq!(rig.pi.with(|s| s.known.len()), 5);
    }

    #[test]
    fn a_pi_restart_resets_the_cursor_pushes_again_and_refetches_from_zero() {
        let mut rig = Rig::new();
        rig.prepare(250);
        for i in 1..=3 {
            rig.pi.raise("dga", "x.example", Some("192.0.2.5"), i);
        }
        rig.cycle(T0 + 1);
        assert_eq!(rig.since(), vec![0]);
        rig.cycle(T0 + 2);
        assert_eq!(rig.since(), vec![0, 3], "the cursor is the Pi's rev");
        assert_eq!(rig.report().alerts.len(), 3);

        // Reboot: rev and ids restart; the same key is a fresh instance.
        rig.pi.reboot();
        rig.pi.raise("dga", "x.example", Some("192.0.2.5"), 1);
        let out = rig.cycle(T0 + 3);
        assert_eq!(rig.since(), vec![0, 3, 3, 0], "asked from 3, then from 0");
        assert_eq!(rig.acked_puts().len(), 2, "acks pushed to the new Pi");
        let puts = rig.known_puts();
        assert_eq!(puts.len(), 4);
        let macs: Vec<String> = (1..=250).map(fakeqbp::mac).collect();
        assert_chunks(&puts[2..], &macs);
        assert_eq!(rig.pi.with(|s| s.known.len()), 250);
        let r = rig.report();
        assert_eq!(r.rev, 1);
        assert_eq!(r.alerts.len(), 1, "the old map is gone: {:?}", r.alerts);
        assert_eq!(r.alerts[0].id, 1);
        assert_eq!(
            out.notifications.len(),
            1,
            "a later first_unix for an old key is a new alert"
        );
        // One push for it, not one per cycle.
        rig.cycle(T0 + 4);
        assert_eq!(rig.acked_puts().len(), 2);
        assert_eq!(rig.since(), vec![0, 3, 3, 0, 1]);
    }

    #[test]
    fn a_waiting_pi_gets_the_list_when_the_devices_are_read() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            for i in 1..=5 {
                s.know(&fakeqbp::mac(i), None, T0);
            }
        });
        rig.cycle(T0);
        assert_eq!(rig.known_puts().len(), 1);
        assert_eq!(rig.pi.with(|s| s.known_list), "received");

        // The Pi lost its list without a new session (say, its process was
        // restarted behind a proxy). Without a devices read nobody knows.
        rig.pi.set_known_list("waiting");
        rig.cycle(T0 + 1);
        assert_eq!(rig.known_puts().len(), 1);
        // Reading the devices shows it, and the push follows in that cycle.
        rig.cycle_with_devices(T0 + 2);
        assert_eq!(rig.known_puts().len(), 2);
        assert_eq!(rig.pi.with(|s| s.known_list), "received");
        assert_eq!(
            rig.report().known_list,
            "waiting",
            "as read, before the push"
        );
        rig.cycle_with_devices(T0 + 3);
        assert_eq!(rig.known_puts().len(), 2, "received: nothing to do");
        assert_eq!(rig.report().known_list, "received");
    }

    #[test]
    fn a_failing_push_is_reported_and_stays_due_while_the_alerts_still_come() {
        let mut rig = Rig::new();
        rig.prepare(5);
        rig.pi.with(|s| s.fail_puts = true);
        rig.pi.raise("beacon", "x.example", None, 1);
        let out = rig.cycle(T0 + 1);
        let r = rig.report();
        assert_eq!(r.status, "ok", "the Pi answered the alerts");
        assert!(r.push_error.contains("500"), "{}", r.push_error);
        assert_eq!((r.pushed_at, r.alerts.len()), (0, 1));
        assert_eq!(out.notifications.len(), 1);
        assert!(rig.store().push_due());

        rig.pi.with(|s| s.fail_puts = false);
        rig.cycle(T0 + 2);
        let r = rig.report();
        assert_eq!((r.push_error.as_str(), r.pushed_at), ("", T0 + 2));
        assert_eq!(rig.pi.with(|s| s.known.len()), 5);
        assert!(!rig.store().push_due());
    }

    #[test]
    fn errors_that_mean_no_contact_end_the_cycle_and_keep_the_push_due() {
        let mut rig = Rig::new();
        rig.prepare(5);
        // A dead port: unreachable, before any request is answered.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        rig.api = Pihole::at(addr, [0; 32], pw()).unwrap();
        let e = rig.try_cycle(T0, false).unwrap_err();
        assert_eq!(e.status(), "unreachable");
        rig.poller.fail(&e);
        let r = rig.report();
        assert_eq!((r.status, r.polled_at, r.pushed_at), ("unreachable", 0, 0));
        assert!(!r.push_error.is_empty(), "the failed push is shown");
        assert_eq!(rig.poller.presence(), Presence::Unknown);
        // Back on a working Pi it goes through and the status recovers.
        rig.api = rig.pi.client();
        rig.cycle(T0 + 1);
        let r = rig.report();
        assert_eq!(
            (r.status, r.push_error.as_str(), r.pushed_at),
            ("ok", "", T0 + 1)
        );
    }

    #[test]
    fn a_real_pihole_is_absent_after_one_request_and_stays_so_for_the_session() {
        let mut rig = Rig::on(FakePi::pihole_only(50));
        let out = rig.cycle(T0);
        assert!(out.presence_changed);
        assert_eq!(rig.poller.presence(), Presence::Absent);
        assert_eq!(rig.pi.qbp_requests(), 1, "just the alerts");
        let r = rig.report();
        assert_eq!((r.status, r.polled_at), ("absent", T0));
        assert!(r.alerts.is_empty() && r.devices.is_empty());
        for i in 1..=5 {
            let out = rig.cycle_with_devices(T0 + i);
            assert!(!out.presence_changed);
        }
        assert_eq!(rig.pi.qbp_requests(), 1, "no request per cycle");

        // A new session (here: logged out, then used again) gets one look.
        rig.api.logout();
        rig.api.summary().unwrap();
        let out = rig.cycle(T0 + 10);
        assert!(!out.presence_changed, "absent before and after");
        assert_eq!(rig.pi.qbp_requests(), 2);
        rig.cycle(T0 + 11);
        assert_eq!(rig.pi.qbp_requests(), 2);

        // A new client forgets the absence as well.
        rig.poller.client_replaced();
        assert_eq!(rig.poller.presence(), Presence::Unknown);
    }

    #[test]
    fn an_absence_found_by_a_push_needs_no_alerts_request() {
        let mut rig = Rig::on(FakePi::pihole_only(50));
        rig.prepare(5);
        rig.cycle(T0);
        assert_eq!(rig.poller.presence(), Presence::Absent);
        assert_eq!(rig.pi.qbp_requests(), 1);
        assert_eq!(rig.pi.count("PUT /api/qbp/alerts/acked"), 1);
        assert_eq!(rig.pi.count("GET /api/qbp/alerts"), 0);
        assert!(rig.store().push_due(), "nothing was pushed");
    }

    #[test]
    fn the_absent_verdict_is_saved_when_absent_and_cleared_when_a_watchdog_is_seen() {
        // A poller with a key saves the verdict ...
        let mut rig = Rig::on(FakePi::pihole_only(50));
        rig.poller = Poller::new().with_verdict_key("192.0.2.9|ab".into());
        rig.cycle(T0);
        assert_eq!(rig.poller.presence(), Presence::Absent);
        assert_eq!(rig.store().absent_for.as_deref(), Some("192.0.2.9|ab"));
        // ... also when a push is what found the absence.
        let mut rig = Rig::on(FakePi::pihole_only(50));
        rig.poller = Poller::new().with_verdict_key("k".into());
        rig.prepare(5);
        rig.cycle(T0);
        assert_eq!(rig.store().absent_for.as_deref(), Some("k"));

        // A poller without one leaves the store alone: no file at all.
        let mut rig = Rig::on(FakePi::pihole_only(50));
        rig.cycle(T0);
        assert_eq!(rig.poller.presence(), Presence::Absent);
        assert!(!rig.path().exists());

        // A Pi with a watchdog clears a verdict that was saved earlier (by
        // the same address before it was replaced), once it answers.
        let mut rig = Rig::new();
        rig.edit(|s| s.absent_for = Some("k".into()));
        rig.poller = Poller::new().with_verdict_key("k".into());
        rig.cycle(T0);
        assert_eq!(rig.poller.presence(), Presence::Present);
        assert_eq!(rig.store().absent_for, None);
        // The rest of the store is as it was.
        rig.prepare(3);
        rig.cycle(T0 + 1);
        assert_eq!(rig.store().known.len(), 3);
        assert_eq!(rig.store().absent_for, None);
    }

    #[test]
    fn a_failed_clear_of_the_verdict_is_tried_again_on_the_next_cycle() {
        let mut rig = Rig::new();
        rig.edit(|s| s.absent_for = Some("k".into()));
        rig.poller = Poller::new().with_verdict_key("k".into());
        // The store cannot be taken for the moment: hold its lock.
        let lock_path = rig.dir.path().join("watchdog.lock");
        let held = crate::util::try_lock(&lock_path).unwrap().expect("free");
        rig.cycle(T0);
        assert_eq!(rig.store().absent_for.as_deref(), Some("k"), "still saved");
        drop(held);
        rig.cycle(T0 + 1);
        assert_eq!(rig.store().absent_for, None, "cleared by the next cycle");
    }

    // -- the exempt list -------------------------------------------------------

    impl Rig {
        fn exempt_puts(&self) -> Vec<Value> {
            self.pi.with(|s| s.exempt_puts.clone())
        }
        /// A known list of `known` MACs of which the first `exempt` are
        /// also exempt, as the CLI would have left them.
        fn prepare_exempt(&self, known: usize, exempt: usize) {
            self.edit(|s| {
                for i in 1..=known {
                    s.know(&fakeqbp::mac(i), None, T0);
                }
                for i in 1..=exempt {
                    s.add_exempt(&fakeqbp::mac(i), None, T0);
                }
            });
        }
        fn exempt_body(n: usize) -> Value {
            json!({ "exempt": (1..=n).map(fakeqbp::mac).collect::<Vec<_>>() })
        }
    }

    #[test]
    fn the_first_cycle_pushes_the_exempt_list_right_after_the_known_list() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 3);
        rig.cycle(T0 + 1);
        assert_eq!(rig.known_puts().len(), 1);
        assert_eq!(rig.exempt_puts(), vec![Rig::exempt_body(3)]);
        assert_eq!(
            rig.pi.with(|s| s.exempt.clone()),
            (1..=3).map(fakeqbp::mac).collect::<Vec<_>>()
        );
        let known = first_at(&rig.pi, "PUT /api/qbp/devices/known");
        let exempt = first_at(&rig.pi, "PUT /api/qbp/devices/exempt");
        let alerts = first_at(&rig.pi, "GET /api/qbp/alerts");
        assert!(known < exempt && exempt < alerts);
        let store = rig.store();
        assert!(!store.push_due() && !store.exempt_push_due());
        let r = rig.report();
        assert_eq!(
            (r.status, r.pushed_at, r.push_error.as_str()),
            ("ok", T0 + 1, "")
        );
        // Nothing is due any more.
        rig.cycle(T0 + 2);
        rig.cycle_with_devices(T0 + 3);
        assert_eq!(rig.exempt_puts().len(), 1);
        assert_eq!(rig.known_puts().len(), 1);
    }

    #[test]
    fn an_empty_exempt_list_is_pushed_with_every_session_push_not_only_after_an_edit() {
        let mut rig = Rig::new();
        rig.prepare(3);
        // The first cycle does not know yet that there is a watchdog (a
        // real Pi-hole is never asked for an exempt list), so it sends none.
        rig.cycle(T0);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 0);
        // The next one has seen it: the empty list goes, once.
        rig.cycle(T0 + 1);
        assert_eq!(rig.exempt_puts(), vec![json!({"exempt": []})]);
        assert!(!rig.store().exempt_push_due(), "it was no edit");
        rig.cycle(T0 + 2);
        assert_eq!(rig.exempt_puts().len(), 1, "and not at every cycle");

        // Again for a new login session, a new client and a waiting Pi.
        rig.pi.invalidate();
        rig.cycle(T0 + 3);
        assert_eq!(rig.exempt_puts().len(), 2);
        rig.poller.client_replaced();
        rig.cycle(T0 + 4);
        assert_eq!(rig.exempt_puts().len(), 3);
        rig.pi.set_known_list("waiting");
        rig.cycle_with_devices(T0 + 5);
        assert_eq!(rig.exempt_puts().len(), 4);
        rig.cycle_with_devices(T0 + 6);
        assert_eq!(rig.exempt_puts().len(), 4);
        assert!(rig
            .exempt_puts()
            .iter()
            .all(|b| *b == json!({"exempt": []})));

        // An edit that emptied the list is pushed at the next cycle too.
        rig.edit(|s| {
            s.add_exempt(&fakeqbp::mac(1), None, T0);
            s.remove_exempt(&fakeqbp::mac(1));
        });
        assert!(rig.store().exempt_push_due() && rig.store().exempt.is_empty());
        rig.cycle(T0 + 7);
        assert_eq!(rig.exempt_puts().len(), 5);
        assert!(!rig.store().exempt_push_due());
        rig.cycle(T0 + 8);
        assert_eq!(rig.exempt_puts().len(), 5);
    }

    #[test]
    fn a_lost_store_does_not_leave_old_exemptions_on_the_pi() {
        // The Pi was given exemptions by an earlier store. This PC's store is
        // new (lost, reset): its session push clears what is stale.
        let mut rig = Rig::new();
        rig.pi
            .with(|s| s.exempt = vec![fakeqbp::mac(1), fakeqbp::mac(2)]);
        rig.prepare(3);
        rig.cycle(T0);
        rig.cycle(T0 + 1);
        assert!(rig.pi.with(|s| s.exempt.is_empty()), "cleared");
        // The same whenever a new session begins: the list this PC holds is
        // the master.
        rig.pi.with(|s| s.exempt = vec![fakeqbp::mac(3)]);
        rig.pi.invalidate();
        rig.cycle(T0 + 2);
        assert!(rig.pi.with(|s| s.exempt.is_empty()));
    }

    #[test]
    fn an_empty_exempt_list_is_asked_of_an_older_pi_once_per_session_and_never_of_a_real_pihole() {
        let mut rig = Rig::on(FakePi::without_exempt(200));
        rig.prepare(3);
        for i in 0..4 {
            rig.cycle(T0 + i);
        }
        assert_eq!(
            rig.pi.count("PUT /api/qbp/devices/exempt"),
            1,
            "404, remembered"
        );
        rig.pi.invalidate();
        rig.cycle(T0 + 5);
        rig.cycle(T0 + 6);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 2);
        assert_eq!(rig.report().push_error, "");

        let mut real = Rig::on(FakePi::pihole_only(50));
        for i in 0..4 {
            real.cycle_with_devices(T0 + i);
        }
        assert_eq!(real.pi.qbp_requests(), 1, "just the alerts, as before");
    }

    #[test]
    fn an_exempt_edit_is_pushed_alone_and_a_known_edit_pushes_no_exempt_list() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 2);
        rig.cycle(T0);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (1, 1));

        rig.edit(|s| s.add_exempt(&fakeqbp::mac(3), Some("TV"), T0));
        rig.cycle(T0 + 1);
        assert_eq!(rig.known_puts().len(), 1, "the known list did not change");
        assert_eq!(
            rig.exempt_puts(),
            vec![Rig::exempt_body(2), Rig::exempt_body(3)]
        );
        assert!(!rig.store().exempt_push_due());

        rig.edit(|s| s.know(&fakeqbp::mac(9), None, T0));
        rig.cycle(T0 + 2);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));

        // Taking a device off the list is pushed too, the device stays known.
        rig.edit(|s| s.remove_exempt(&fakeqbp::mac(1)));
        rig.cycle(T0 + 3);
        assert_eq!(rig.exempt_puts().len(), 3);
        assert_eq!(
            rig.pi.with(|s| s.exempt.clone()),
            [fakeqbp::mac(2), fakeqbp::mac(3)]
        );
        assert!(rig.store().is_known(&fakeqbp::mac(1)));
    }

    #[test]
    fn a_new_login_session_and_a_new_client_push_the_exempt_list_again() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 3);
        rig.cycle(T0);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (1, 1));
        rig.pi.invalidate();
        rig.cycle(T0 + 1);
        assert_eq!(rig.pi.with(|s| s.logins), 2);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));
        assert_eq!(rig.exempt_puts()[1], Rig::exempt_body(3));
        rig.cycle(T0 + 2);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));
        // A new client has pushed nothing, whatever its login counter says.
        rig.poller.client_replaced();
        rig.cycle(T0 + 3);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (3, 3));
    }

    #[test]
    fn a_pi_that_rebooted_gets_the_exempt_list_again_next_to_the_known_list() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 3);
        rig.pi.with(|s| s.exempt_config = vec![fakeqbp::mac(40)]);
        for i in 1..=3 {
            rig.pi.raise("dga", "x.example", Some("192.0.2.5"), i);
        }
        rig.cycle(T0 + 1);
        rig.cycle(T0 + 2);
        assert_eq!(rig.since(), vec![0, 3]);
        assert_eq!(rig.exempt_puts().len(), 1);

        // The restart is seen through the new session.
        rig.pi.reboot();
        assert!(rig.pi.with(|s| s.exempt.is_empty()), "memory only");
        rig.pi.raise("dga", "x.example", Some("192.0.2.5"), 1);
        rig.cycle(T0 + 3);
        assert_eq!(rig.since(), vec![0, 3, 3, 0]);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 3);
        // The Pi's config list is its own and was not sent back to it.
        assert_eq!(rig.exempt_puts()[1], Rig::exempt_body(3));
        // One push for the restart, not one per cycle.
        rig.cycle(T0 + 4);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));
    }

    #[test]
    fn a_reboot_the_session_survived_still_pushes_the_exempt_list_again() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 3);
        for i in 1..=3 {
            rig.pi.raise("dga", "x.example", None, i);
        }
        rig.cycle(T0 + 1);
        rig.cycle(T0 + 2);
        assert_eq!(rig.exempt_puts().len(), 1);
        // rev goes below the cursor: a restart, and the session is the same.
        rig.pi.reboot_keeping_session();
        rig.cycle(T0 + 3);
        assert_eq!(rig.pi.with(|s| s.logins), 1, "no new session");
        assert_eq!(rig.since(), vec![0, 3, 3, 0]);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 3);
    }

    #[test]
    fn a_waiting_pi_gets_the_exempt_list_too() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 2);
        rig.cycle(T0);
        assert_eq!(rig.exempt_puts().len(), 1);
        // Its memory is gone without a new session; reading the devices
        // shows it, and both lists follow in that cycle.
        rig.pi.set_known_list("waiting");
        rig.pi.with(|s| s.exempt.clear());
        rig.cycle(T0 + 1);
        assert_eq!(rig.exempt_puts().len(), 1, "nobody knows yet");
        rig.cycle_with_devices(T0 + 2);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 2);
        rig.cycle_with_devices(T0 + 3);
        assert_eq!((rig.known_puts().len(), rig.exempt_puts().len()), (2, 2));
    }

    #[test]
    fn a_failing_exempt_push_stops_neither_the_known_push_nor_the_alerts_and_is_retried() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 2);
        rig.pi.with(|s| s.fail_exempt = true);
        rig.pi.raise("beacon", "x.example", None, 1);
        let out = rig.cycle(T0 + 1);
        // The known list got through and was recorded; the alert came.
        assert_eq!(rig.known_puts().len(), 1);
        assert_eq!(rig.pi.with(|s| s.known.len()), 5);
        assert!(!rig.store().push_due());
        assert_eq!(out.notifications.len(), 1);
        let r = rig.report();
        assert_eq!((r.status, r.alerts.len()), ("ok", 1));
        assert!(
            r.push_error.starts_with("exempt list: ") && r.push_error.contains("500"),
            "{}",
            r.push_error
        );
        assert_eq!(rig.exempt_puts().len(), 1);
        assert!(rig.store().exempt_push_due());

        // Retried on the next cycle, as a failed known push would be, and
        // the known list is not pushed again meanwhile.
        rig.cycle(T0 + 2);
        assert_eq!(rig.exempt_puts().len(), 2);
        assert_eq!(rig.known_puts().len(), 1);
        rig.pi.with(|s| s.fail_exempt = false);
        rig.cycle(T0 + 3);
        assert_eq!(rig.exempt_puts().len(), 3);
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 2);
        let r = rig.report();
        assert_eq!((r.push_error.as_str(), r.pushed_at), ("", T0 + 3));
        assert!(!rig.store().exempt_push_due());
        rig.cycle(T0 + 4);
        assert_eq!(rig.exempt_puts().len(), 3);
    }

    #[test]
    fn a_failing_known_push_does_not_keep_the_exempt_list_from_reaching_the_pi() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 2);
        rig.pi.with(|s| s.fail_known = true);
        rig.pi.raise("beacon", "x.example", None, 1);
        let out = rig.cycle(T0 + 1);
        // The known list keeps failing, the exempt list and the alert came.
        assert_eq!(rig.known_puts().len(), 0, "refused with 500");
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/known"), 1);
        assert_eq!(rig.exempt_puts(), vec![Rig::exempt_body(2)]);
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 2);
        assert_eq!(out.notifications.len(), 1);
        let store = rig.store();
        assert!(store.push_due(), "the known list stays due");
        assert!(!store.exempt_push_due(), "the exempt list is recorded");
        let r = rig.report();
        assert!(
            r.push_error.contains("500") && !r.push_error.starts_with("exempt list"),
            "the known list's failure is the one shown: {}",
            r.push_error
        );

        // Later cycles: the known list is retried, the exempt list is not
        // sent again while it keeps its place.
        rig.cycle(T0 + 2);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/known"), 2);
        assert_eq!(rig.exempt_puts().len(), 1);

        // A Pi restart while the known list still fails: the exempt list
        // goes to the new Pi anyway.
        rig.pi.reboot();
        assert!(rig.pi.with(|s| s.exempt.is_empty()));
        rig.cycle(T0 + 3);
        assert_eq!(rig.exempt_puts().len(), 2);
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 2);
        assert!(rig.store().push_due());

        // The known list comes through once it works again.
        rig.pi.with(|s| s.fail_known = false);
        rig.cycle(T0 + 4);
        assert_eq!(rig.pi.with(|s| s.known.len()), 5);
        assert!(!rig.store().push_due());
        assert_eq!(rig.report().push_error, "");
    }

    #[test]
    fn a_failed_exempt_push_at_a_new_session_is_retried_though_nothing_else_is_due() {
        let mut rig = Rig::new();
        rig.prepare_exempt(5, 2);
        rig.cycle(T0);
        rig.pi.with(|s| s.fail_exempt = true);
        rig.pi.invalidate();
        rig.cycle(T0 + 1);
        assert_eq!(rig.known_puts().len(), 2, "the known list went out");
        assert_eq!(rig.exempt_puts().len(), 2);
        // The store says nothing is due: the poller's own memory does.
        assert!(!rig.store().exempt_push_due());
        rig.pi.with(|s| s.fail_exempt = false);
        rig.cycle(T0 + 2);
        assert_eq!(rig.exempt_puts().len(), 3);
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 2);
        assert_eq!(rig.report().push_error, "");
        rig.cycle(T0 + 3);
        assert_eq!(rig.exempt_puts().len(), 3);
    }

    #[test]
    fn an_older_pi_answers_404_once_and_is_not_asked_every_cycle() {
        let mut rig = Rig::on(FakePi::without_exempt(200));
        rig.prepare_exempt(5, 2);
        rig.pi.raise("beacon", "x.example", None, 1);
        let out = rig.cycle_with_devices(T0 + 1);
        // The 404 is not a failure of anything.
        assert_eq!(rig.poller.presence(), Presence::Present);
        let r = rig.report();
        assert_eq!((r.status, r.push_error.as_str()), ("ok", ""));
        assert_eq!(out.notifications.len(), 1);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 1);
        assert_eq!(rig.known_puts().len(), 1, "the known list went out");
        assert!(!rig.store().push_due());
        assert!(rig.store().exempt_push_due(), "kept: it was never taken");

        // Not again, not at the next cycles, not for a waiting Pi, not for
        // an edit; the alerts and devices keep coming.
        let alerts = rig.pi.count("GET /api/qbp/alerts");
        rig.cycle_with_devices(T0 + 2);
        rig.edit(|s| s.add_exempt(&fakeqbp::mac(4), None, T0));
        rig.cycle(T0 + 3);
        rig.pi.set_known_list("waiting");
        rig.cycle_with_devices(T0 + 4);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 1);
        assert_eq!(rig.pi.count("GET /api/qbp/alerts"), alerts + 3);
        assert_eq!(
            rig.known_puts().len(),
            2,
            "the waiting Pi got its known list"
        );
        assert_eq!(rig.report().devices.len(), 3);

        // A new login session gets one more look.
        rig.pi.invalidate();
        rig.cycle(T0 + 5);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 2);
        rig.cycle(T0 + 6);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 2);
        // So does a new client.
        rig.poller.client_replaced();
        rig.cycle(T0 + 7);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 3);
        rig.cycle(T0 + 8);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 3);
    }

    #[test]
    fn a_pi_that_was_upgraded_gets_the_exempt_list_after_it_restarts() {
        let mut rig = Rig::on(FakePi::without_exempt(200));
        rig.prepare_exempt(5, 2);
        for i in 1..=3 {
            rig.pi.raise("dga", "x.example", None, i);
        }
        rig.cycle(T0 + 1);
        rig.cycle(T0 + 2);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 1);
        assert!(rig.pi.with(|s| s.exempt.is_empty()));

        // Restarted with newer software; the session survived, rev went back.
        rig.pi.with(|s| s.exempt_support = true);
        rig.pi.reboot_keeping_session();
        rig.cycle(T0 + 3);
        assert_eq!(rig.pi.with(|s| s.logins), 1);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 2);
        assert_eq!(rig.pi.with(|s| s.exempt.len()), 2);
        assert_eq!(rig.report().push_error, "");
        assert!(!rig.store().exempt_push_due());
    }

    #[test]
    fn on_a_real_pihole_the_exempt_list_is_not_even_tried() {
        let mut rig = Rig::on(FakePi::pihole_only(50));
        rig.prepare_exempt(3, 2);
        rig.cycle(T0);
        assert_eq!(rig.poller.presence(), Presence::Absent);
        assert_eq!(rig.pi.qbp_requests(), 1, "the known list, answered 404");
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 0);
        assert!(rig.store().exempt_push_due());
    }

    #[test]
    fn exempt_devices_are_marked_on_both_sides_in_the_report() {
        let mut rig = Rig::new();
        rig.pi.with(|s| s.exempt_config = vec![fakeqbp::mac(3)]);
        rig.edit(|s| {
            s.know(&fakeqbp::mac(1), None, T0);
            s.add_exempt(&fakeqbp::mac(1), Some("TV"), T0);
        });
        rig.cycle_with_devices(T0 + 1);
        let r = rig.report();
        let by_mac = |n: usize| {
            r.devices
                .iter()
                .find(|d| d.device.mac == fakeqbp::mac(n))
                .unwrap()
        };
        // Mac 1: on this PC's list and so pushed, the Pi says so too.
        assert_eq!((by_mac(1).exempt, by_mac(1).device.exempt), (true, true));
        // Mac 3: only in the Pi's config file.
        assert_eq!((by_mac(3).exempt, by_mac(3).device.exempt), (false, true));
        // Mac 2: neither.
        assert_eq!((by_mac(2).exempt, by_mac(2).device.exempt), (false, false));
        // An older Pi says nothing: its devices are not exempt on the Pi.
        let mut old = Rig::on(FakePi::without_exempt(200));
        old.edit(|s| s.add_exempt(&fakeqbp::mac(1), None, T0));
        old.cycle_with_devices(T0 + 1);
        let r = old.report();
        assert!(r.devices.iter().all(|d| !d.device.exempt));
        assert_eq!(r.devices.iter().filter(|d| d.exempt).count(), 1);
    }

    // -- notifications ---------------------------------------------------------

    fn note_titles(out: &CycleOut) -> Vec<&str> {
        out.notifications.iter().map(|n| n.0.as_str()).collect()
    }

    #[test]
    fn five_new_alerts_are_three_notifications_and_a_fold_with_escaped_text() {
        let mut rig = Rig::new();
        rig.pi.raise("new_device", "02:00:00:00:00:07", None, 1);
        rig.pi.raise("arp_spoof", "<b>&", Some("192.0.2.9"), 2);
        rig.pi.raise("dga", "x.example", Some("192.0.2.5"), 3);
        rig.pi.raise("tunnel", "y.example", None, 4);
        rig.pi.raise("beacon", "z.example", None, 5);
        let out = rig.cycle(T0 + 100);
        assert_eq!(
            out.notifications,
            vec![
                (
                    "New device on the network".to_string(),
                    "02:00:00:00:00:07".to_string()
                ),
                (
                    "Router impersonation (ARP spoofing)".to_string(),
                    "&lt;b&gt;&amp; · 192.0.2.9".to_string()
                ),
                (
                    "Suspicious lookups (DGA)".to_string(),
                    "x.example · 192.0.2.5".to_string()
                ),
                ("Watchdog".to_string(), "2 more alerts".to_string()),
            ]
        );
        // All five are recorded, the folded ones too.
        let st = rig.store();
        assert_eq!(st.notified.len(), 5);
        assert!(!st.should_notify(&fakeqbp::key(5), T0 + 50));
    }

    #[test]
    fn acked_alerts_give_no_notification_and_their_key_is_stored() {
        let mut rig = Rig::new();
        let id = rig.pi.raise("dga", "x.example", None, 1);
        rig.pi.ack(id);
        let out = rig.cycle(T0 + 100);
        assert!(out.notifications.is_empty(), "{:?}", out.notifications);
        assert_eq!(rig.store().acked_keys(), vec![fakeqbp::key(1)]);
        assert!(rig.store().notified.is_empty());
        let r = rig.report();
        assert_eq!((r.unacked, r.alerts.len()), (0, 1));
        assert!(r.alerts[0].acked);
    }

    #[test]
    fn a_repeated_alert_and_a_restarted_watcher_do_not_notify_again() {
        let mut rig = Rig::new();
        let a = rig.pi.raise("new_device", "02:00:00:00:00:07", None, 1);
        rig.pi.raise("dga", "x.example", None, 2);
        let acked = rig.pi.raise("beacon", "z.example", None, 3);
        rig.pi.ack(acked);
        assert_eq!(rig.cycle(T0 + 100).notifications.len(), 2);

        // The same alert again: a higher rev and count, the same first_unix.
        rig.pi.repeat(a);
        let out = rig.cycle(T0 + 200);
        assert!(out.notifications.is_empty());
        let r = rig.report();
        assert_eq!(r.alerts[0].id, a, "newest change first");
        assert_eq!(r.alerts[0].count, 2);

        // A new watcher process: a new poller and client, the same store. It
        // reads everything from 0 and finds nothing to announce.
        let mut api2 = rig.pi.client();
        let mut p2 = Poller::new();
        let out = p2.cycle(&mut api2, &rig.path(), T0 + 300, false).unwrap();
        api2.close_idle();
        assert!(out.notifications.is_empty(), "{:?}", out.notifications);
        assert_eq!(p2.report(&rig.store()).alerts.len(), 3);
        assert_eq!(rig.since().last(), Some(&0));

        // But a different alert is news.
        rig.pi.raise("tunnel", "w.example", None, 9);
        let out = p2.cycle(&mut api2, &rig.path(), T0 + 400, false).unwrap();
        assert_eq!(note_titles(&out), vec!["Possible DNS tunnel"]);
    }

    #[test]
    fn a_held_fold_goes_out_on_a_later_cycle_with_nothing_new() {
        let mut rig = Rig::new();
        for i in 1..=5 {
            rig.pi.raise("dga", "x.example", None, i);
        }
        let out = rig.cycle(T0 + 100);
        assert_eq!(out.notifications.len(), 4, "3 and the fold of 2");
        // 30 s later 4 more: inside the window, so all of them are held.
        for i in 6..=9 {
            rig.pi.raise("dga", "x.example", None, i);
        }
        assert!(rig.cycle(T0 + 130).notifications.is_empty());
        assert!(rig.cycle(T0 + 159).notifications.is_empty());
        // A cycle with nothing new at 160 opens the gate.
        let out = rig.cycle(T0 + 160);
        assert_eq!(
            out.notifications,
            vec![("Watchdog".to_string(), "4 more alerts".to_string())]
        );
        assert!(rig.cycle(T0 + 161).notifications.is_empty());
    }

    #[test]
    fn a_store_that_cannot_be_written_keeps_the_cursor_and_notifies_late() {
        let mut rig = Rig::new();
        rig.pi.raise("dga", "x.example", None, 1);
        // Another process holds the store's lock for longer than the wait.
        let lock = crate::util::try_lock(&rig.dir.path().join("watchdog.lock"))
            .unwrap()
            .expect("the lock was free");
        let out = rig.cycle(T0 + 100);
        assert!(out.notifications.is_empty(), "nothing could be recorded");
        let r = rig.report();
        assert_eq!(r.status, "ok");
        assert_eq!(r.alerts.len(), 1, "still shown");
        drop(lock);
        // The cursor did not move, so the same alert comes again and is
        // announced now.
        let out = rig.cycle(T0 + 101);
        assert_eq!(note_titles(&out), vec!["Suspicious lookups (DGA)"]);
        assert_eq!(rig.since(), vec![0, 0]);
        assert!(rig.cycle(T0 + 102).notifications.is_empty());
        assert_eq!(rig.since(), vec![0, 0, 1]);
    }

    // -- the report ------------------------------------------------------------

    #[test]
    fn the_report_holds_the_newest_fifty_alerts_and_the_map_is_bounded() {
        let mut rig = Rig::new();
        for i in 1..=200 {
            rig.pi.raise("dga", "x.example", None, i);
        }
        rig.cycle(T0 + 1);
        for i in 201..=300 {
            rig.pi.raise("dga", "x.example", None, i);
        }
        rig.cycle(T0 + 2);
        let r = rig.report();
        assert_eq!(r.rev, 300);
        assert_eq!(r.unacked, 256, "at most 256 are kept, the oldest go");
        assert_eq!(r.alerts.len(), REPORT_ALERTS);
        assert_eq!(r.alerts[0].id, 300);
        assert_eq!(r.alerts[49].id, 251);
        assert!(r.alerts.windows(2).all(|w| w[0].rev > w[1].rev));
        // An acknowledgement on the Pi shows as a change of that alert.
        rig.pi.ack(300);
        rig.cycle(T0 + 3);
        let r = rig.report();
        assert_eq!(
            (r.alerts[0].id, r.alerts[0].acked, r.unacked),
            (300, true, 255)
        );
        assert!(rig.store().acked_keys().contains(&fakeqbp::key(300)));
    }

    #[test]
    fn the_device_list_is_last_seen_first_capped_and_merged_with_the_pcs_list() {
        let mut rig = Rig::new();
        rig.pi.with(|s| {
            s.devices = (1..=200)
                .map(|i| (fakeqbp::mac(i), format!("192.0.2.{}", i % 250 + 1)))
                .collect();
        });
        rig.edit(|s| {
            s.know(&fakeqbp::mac(190), Some("Printer"), T0);
            s.know(&fakeqbp::mac(300), Some("Not seen"), T0);
        });
        rig.cycle(T0 + 1);
        assert!(
            rig.report().devices.is_empty(),
            "not read without a request"
        );
        // The Pi got the PC's list; its own flags are what it reports.
        rig.pi.with(|s| s.known.clear());
        rig.cycle_with_devices(T0 + 2);
        let r = rig.report();
        assert_eq!(r.devices.len(), REPORT_DEVICES);
        // The fake lists the oldest first; the last seen is mac 200.
        assert_eq!(r.devices[0].device.mac, fakeqbp::mac(200));
        assert!(r
            .devices
            .windows(2)
            .all(|w| w[0].device.last_unix >= w[1].device.last_unix));
        assert_eq!(r.known_count, 2);
        let printer = r
            .devices
            .iter()
            .find(|d| d.device.mac == fakeqbp::mac(190))
            .expect("mac 190 is among the 128 last seen");
        assert_eq!((printer.known, printer.label.as_str()), (true, "Printer"));
        assert!(!printer.device.known, "the Pi's own view is separate");
        assert_eq!(printer.device.ipv4, vec!["192.0.2.191".to_string()]);
        let other = &r.devices[1];
        assert_eq!((other.known, other.label.as_str()), (false, ""));
        assert_eq!(r.known_list, "received");
    }

    #[test]
    fn an_unknown_status_before_any_cycle_and_a_failure_keeps_the_data() {
        let mut rig = Rig::new();
        let r = rig.report();
        assert_eq!((r.status, r.rev, r.polled_at), ("unknown", 0, 0));
        rig.pi.raise("dga", "x.example", None, 1);
        rig.cycle(T0 + 5);
        rig.poller.fail(&ApiError::Tls("pin".into()));
        let r = rig.report();
        assert_eq!((r.status, r.polled_at, r.alerts.len()), ("tls", T0 + 5, 1));
        rig.cycle(T0 + 6);
        assert_eq!(rig.report().status, "ok");
    }
}

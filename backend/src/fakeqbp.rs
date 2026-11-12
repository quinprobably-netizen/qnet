//! A fake Pi for the watchdog tests: the Pi-hole login and stats endpoints
//! plus qberrypi's `/api/qbp/` watchdog (alerts, ack, acked, devices, known,
//! exempt), behind the throwaway TLS server of `https::testutil`.
//!
//! The model lives in [`PiState`], shared with the test through [`FakePi`], so
//! a test can raise alerts, invalidate the session ("the Pi forgot it") or
//! "reboot" the Pi (rev and ids restart, the known list is back to `waiting`,
//! the pushed exempt list is gone, every session is gone) while a poller is
//! running. An older Pi that has no exempt support (404 on its route, none of
//! its fields in the devices answer) is [`FakePi::without_exempt`]. Test data uses
//! documentation addresses (192.0.2.x) and locally administered MACs
//! (02:00:00:...) only.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::https::testutil::{ok_json, serve, TestServer};
use crate::pihole::Pihole;

/// The clock the fake starts at (unix seconds); every alert raised moves it.
pub const T0: u64 = 1_800_000_000;

const NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}";
const UNAUTHORIZED: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}";
const SERVER_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}";
const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\n\r\n{}";

/// The most addresses the Pi takes in one `PUT devices/exempt`.
pub const EXEMPT_MAX: usize = 64;

/// The `n`-th alert key: 16 lower-case hex digits, stable across "reboots".
pub fn key(n: usize) -> String {
    format!("{:016x}", 0xa1b2_c3d4_0000_0000u64 + n as u64)
}

/// The `n`-th MAC, `02:00:00:xx:xx:xx`.
pub fn mac(n: usize) -> String {
    format!(
        "02:00:00:{:02x}:{:02x}:{:02x}",
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff
    )
}

#[derive(Debug, Clone)]
pub struct PiAlert {
    pub id: u64,
    pub key: String,
    pub rev: u64,
    pub kind: String,
    pub client: Option<String>,
    pub subject: String,
    pub first_unix: u64,
    pub last_unix: u64,
    pub count: u64,
    pub acked: bool,
}

impl PiAlert {
    fn json(&self) -> Value {
        json!({
            "id": self.id, "key": self.key, "rev": self.rev, "kind": self.kind,
            "severity": "warn", "client": self.client, "subject": self.subject,
            "first_unix": self.first_unix, "last_unix": self.last_unix,
            "count": self.count, "acked": self.acked
        })
    }
}

#[derive(Debug)]
pub struct PiState {
    /// False: a real Pi-hole, which answers 404 on every `/api/qbp/` path.
    pub watchdog: bool,
    /// True: every `/api/qbp/` request fails with HTTP 500.
    pub fail_qbp: bool,
    /// True: every `PUT` under `/api/qbp/` fails with HTTP 500.
    pub fail_puts: bool,
    /// False: an older Pi. `PUT devices/exempt` is answered 404 and the
    /// devices answer has neither `exempt` nor `exempt_macs`.
    pub exempt_support: bool,
    /// True: `PUT devices/exempt` fails with HTTP 500 (the other routes work).
    pub fail_exempt: bool,
    /// True: `PUT devices/known` fails with HTTP 500 (the other routes work).
    pub fail_known: bool,
    pub rev: u64,
    next_id: u64,
    /// Moves 10 s with every alert raised.
    pub clock: u64,
    pub alerts: Vec<PiAlert>,
    /// `waiting` until a known list arrives, then `received`.
    pub known_list: &'static str,
    /// The known list in effect.
    pub known: Vec<String>,
    staged: Vec<String>,
    /// The exempt list that was pushed (memory only: a reboot clears it).
    pub exempt: Vec<String>,
    /// The exempt list from the Pi's own config file: it survives a reboot
    /// and is never touched by a push.
    pub exempt_config: Vec<String>,
    /// (mac, ipv4) of the devices `GET devices` lists. Each is seen later than
    /// the one before it, so the list comes oldest first: the poller must
    /// sort, not trust the Pi's order.
    pub devices: Vec<(String, String)>,
    /// The valid session id, if any.
    sid: Option<String>,
    pub logins: u64,
    /// The first line of every request the Pi accepted (and logins and
    /// logouts); requests answered 401 are only counted in `rejected`.
    pub log: Vec<String>,
    /// When each entry of `log` came in.
    pub times: Vec<Instant>,
    pub rejected: u64,
    /// The bodies of `PUT alerts/acked`.
    pub acked_puts: Vec<Value>,
    /// The bodies of `PUT devices/known`.
    pub known_puts: Vec<Value>,
    /// The bodies of `PUT devices/exempt`, every one that reached the route
    /// (also the ones answered 400 or 500).
    pub exempt_puts: Vec<Value>,
    /// The `since` of every `GET alerts`.
    pub since: Vec<u64>,
}

impl PiState {
    fn new(watchdog: bool) -> Self {
        Self {
            watchdog,
            fail_qbp: false,
            fail_puts: false,
            exempt_support: true,
            fail_exempt: false,
            fail_known: false,
            rev: 0,
            next_id: 1,
            clock: T0,
            alerts: Vec::new(),
            known_list: "waiting",
            known: Vec::new(),
            staged: Vec::new(),
            exempt: Vec::new(),
            exempt_config: Vec::new(),
            devices: (1..=3).map(|i| (mac(i), format!("192.0.2.{i}"))).collect(),
            sid: None,
            logins: 0,
            log: Vec::new(),
            times: Vec::new(),
            rejected: 0,
            acked_puts: Vec::new(),
            known_puts: Vec::new(),
            exempt_puts: Vec::new(),
            since: Vec::new(),
        }
    }

    fn bump(&mut self) -> u64 {
        self.rev += 1;
        self.rev
    }

    fn alerts_json(&mut self, since: u64) -> Value {
        self.since.push(since);
        let alerts: Vec<Value> = self
            .alerts
            .iter()
            .filter(|a| a.rev > since)
            .map(PiAlert::json)
            .collect();
        json!({ "rev": self.rev, "suppressed": 0, "alerts": alerts })
    }

    /// The Pi's effective exempt list: its config file's, then the pushed
    /// one (each address once).
    pub fn exempt_macs(&self) -> Vec<String> {
        let mut all = self.exempt_config.clone();
        for m in &self.exempt {
            if !all.contains(m) {
                all.push(m.clone());
            }
        }
        all
    }

    fn devices_json(&self) -> Value {
        let effective = self.exempt_macs();
        let devices: Vec<Value> = self
            .devices
            .iter()
            .enumerate()
            .map(|(i, (m, ip))| {
                let mut d = json!({
                    "mac": m, "ipv4": [ip], "hostname": "",
                    "first_unix": T0, "last_unix": T0 + 100 + i as u64,
                    "known": self.known.contains(m)
                });
                if self.exempt_support {
                    d["exempt"] = json!(effective.contains(m));
                }
                d
            })
            .collect();
        let mut v = json!({ "known_list": self.known_list, "devices": devices });
        if self.exempt_support {
            v["exempt_macs"] = json!(effective);
        }
        v
    }
}

/// The request's first line and its JSON body (null when it has none).
fn split(req: &str) -> (String, Value) {
    let first = req.lines().next().unwrap_or("").to_string();
    let body = req
        .split("\r\n\r\n")
        .nth(1)
        .and_then(|b| serde_json::from_str(b).ok())
        .unwrap_or(Value::Null);
    (first, body)
}

fn note(st: &mut PiState, first: &str) {
    st.log.push(first.to_string());
    st.times.push(Instant::now());
}

fn respond(st: &mut PiState, req: &str) -> Vec<u8> {
    let (first, body) = split(req);
    if first.starts_with("POST /api/auth") {
        note(st, &first);
        st.logins += 1;
        let sid = format!("SID-{}", st.logins);
        st.sid = Some(sid.clone());
        return ok_json(&format!(
            r#"{{"session":{{"valid":true,"sid":"{sid}","validity":300}}}}"#
        ));
    }
    let sent = req.lines().find_map(|l| l.strip_prefix("X-FTL-SID: "));
    let authed = st.sid.is_some() && sent == st.sid.as_deref();
    if first.starts_with("DELETE /api/auth") {
        note(st, &first);
        if authed {
            st.sid = None;
        }
        return NO_CONTENT.to_vec();
    }
    if !authed {
        st.rejected += 1;
        return UNAUTHORIZED.to_vec();
    }
    note(st, &first);
    let path = first.split(' ').nth(1).unwrap_or("");
    let method = first.split(' ').next().unwrap_or("");

    // The Pi-hole's own endpoints.
    match (method, path) {
        ("GET", "/api/stats/summary") => {
            return ok_json(r#"{"queries":{"total":10,"blocked":2,"percent_blocked":20.0}}"#)
        }
        ("GET", "/api/dns/blocking") => return ok_json(r#"{"blocking":"enabled","timer":null}"#),
        ("GET", "/api/stats/upstreams") => {
            return ok_json(
                r#"{"upstreams":[{"ip":"9.9.9.9","name":"dns9.quad9.net","port":53,"count":9}],"forwarded_queries":9}"#,
            )
        }
        ("GET", "/api/history") => {
            return ok_json(r#"{"history":[{"timestamp":600,"total":3,"blocked":1}]}"#)
        }
        _ => {}
    }

    // qberrypi's watchdog.
    if !path.starts_with("/api/qbp/") || !st.watchdog {
        return NOT_FOUND.to_vec();
    }
    if st.fail_qbp || (st.fail_puts && method == "PUT") {
        return SERVER_ERROR.to_vec();
    }
    if method == "GET" && path.starts_with("/api/qbp/alerts?since=") {
        let since = path["/api/qbp/alerts?since=".len()..].parse().unwrap_or(0);
        return ok_json(&st.alerts_json(since).to_string());
    }
    if method == "POST" && path.starts_with("/api/qbp/alerts/") && path.ends_with("/ack") {
        let id: u64 = path["/api/qbp/alerts/".len()..path.len() - "/ack".len()]
            .parse()
            .unwrap_or(0);
        let rev = st.rev + 1;
        return match st.alerts.iter_mut().find(|a| a.id == id) {
            Some(a) => {
                a.acked = true;
                a.rev = rev;
                st.rev = rev;
                ok_json(r#"{"acked":true}"#)
            }
            None => NOT_FOUND.to_vec(),
        };
    }
    if method == "PUT" && path == "/api/qbp/alerts/acked" {
        let keys: Vec<String> = body["acked"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|k| k.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        st.acked_puts.push(body);
        for k in &keys {
            let rev = st.rev + 1;
            if let Some(a) = st.alerts.iter_mut().find(|a| &a.key == k && !a.acked) {
                a.acked = true;
                a.rev = rev;
                st.rev = rev;
            }
        }
        return ok_json(&format!(r#"{{"restored":{}}}"#, keys.len()));
    }
    if method == "GET" && path == "/api/qbp/devices" {
        return ok_json(&st.devices_json().to_string());
    }
    if method == "PUT" && path == "/api/qbp/devices/known" {
        if st.fail_known {
            return SERVER_ERROR.to_vec();
        }
        let macs: Vec<String> = body["known"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if body["append"] != json!(true) {
            st.staged.clear();
        }
        st.staged.extend(macs);
        if body["complete"] == json!(true) {
            st.known = std::mem::take(&mut st.staged);
            st.known_list = "received";
        }
        let n = if body["complete"] == json!(true) {
            st.known.len()
        } else {
            st.staged.len()
        };
        st.known_puts.push(body);
        return ok_json(&format!(r#"{{"known":{n}}}"#));
    }
    if method == "PUT" && path == "/api/qbp/devices/exempt" {
        if !st.exempt_support {
            return NOT_FOUND.to_vec();
        }
        st.exempt_puts.push(body.clone());
        if st.fail_exempt {
            return SERVER_ERROR.to_vec();
        }
        // The Pi refuses a body that is not `{"exempt": [<mac>, ...]}` with
        // at most 64 lower-case colon-separated addresses.
        let list = body["exempt"].as_array().filter(|a| a.len() <= EXEMPT_MAX);
        let macs: Option<Vec<String>> = list.and_then(|a| {
            a.iter()
                .map(|m| {
                    let m = m.as_str()?;
                    (crate::watchdog::normalize_mac(m).as_deref() == Some(m)).then(|| m.to_string())
                })
                .collect()
        });
        let Some(macs) = macs else {
            return BAD_REQUEST.to_vec();
        };
        st.exempt = macs;
        return ok_json(&format!(r#"{{"exempt":{}}}"#, st.exempt.len()));
    }
    NOT_FOUND.to_vec()
}

pub struct FakePi {
    pub srv: TestServer,
    pub st: Arc<Mutex<PiState>>,
}

impl FakePi {
    /// A Pi with a watchdog; `conns` bounds how many connections it takes.
    pub fn start(conns: usize) -> Self {
        Self::build(conns, true)
    }

    /// A real Pi-hole: 404 on every `/api/qbp/` path.
    pub fn pihole_only(conns: usize) -> Self {
        Self::build(conns, false)
    }

    /// An older qberrypi: a watchdog without exempt support.
    pub fn without_exempt(conns: usize) -> Self {
        let pi = Self::build(conns, true);
        pi.with(|s| s.exempt_support = false);
        pi
    }

    fn build(conns: usize, watchdog: bool) -> Self {
        let st = Arc::new(Mutex::new(PiState::new(watchdog)));
        let st2 = st.clone();
        let srv = serve(conns, move |_, req| {
            Some(respond(&mut st2.lock().unwrap(), req))
        });
        Self { srv, st }
    }

    pub fn with<R>(&self, f: impl FnOnce(&mut PiState) -> R) -> R {
        f(&mut self.st.lock().unwrap())
    }

    /// A client for the Pi (password "pw").
    pub fn client(&self) -> Pihole {
        Pihole::at(
            self.srv.addr,
            self.srv.fingerprint,
            Box::new(|| Ok(Zeroizing::new("pw".to_string()))),
        )
        .unwrap()
    }

    /// Raise an alert of `kind` for the key `key(key_n)`; returns its id.
    pub fn raise(&self, kind: &str, subject: &str, client: Option<&str>, key_n: usize) -> u64 {
        self.with(|s| {
            s.clock += 10;
            let rev = s.bump();
            let id = s.next_id;
            s.next_id += 1;
            let clock = s.clock;
            s.alerts.push(PiAlert {
                id,
                key: key(key_n),
                rev,
                kind: kind.to_string(),
                client: client.map(String::from),
                subject: subject.to_string(),
                first_unix: clock,
                last_unix: clock,
                count: 1,
                acked: false,
            });
            id
        })
    }

    /// The same alert again: a higher rev and count, the same `first_unix`.
    pub fn repeat(&self, id: u64) {
        self.with(|s| {
            s.clock += 10;
            let rev = s.bump();
            let clock = s.clock;
            let a = s.alerts.iter_mut().find(|a| a.id == id).expect("alert");
            a.rev = rev;
            a.count += 1;
            a.last_unix = clock;
        })
    }

    /// Acknowledge an alert on the Pi's own panel.
    pub fn ack(&self, id: u64) {
        self.with(|s| {
            let rev = s.bump();
            let a = s.alerts.iter_mut().find(|a| a.id == id).expect("alert");
            a.acked = true;
            a.rev = rev;
        })
    }

    /// The Pi forgets the session: every request is answered 401 until the
    /// next login.
    pub fn invalidate(&self) {
        self.with(|s| s.sid = None);
    }

    /// A reboot: rev and ids restart, the alerts and the known list are gone
    /// (the list is `waiting` again), the pushed exempt list is gone (the one
    /// from the Pi's config file stays), and so is every session.
    pub fn reboot(&self) {
        self.reboot_inner(false);
    }

    /// A reboot that the login session survives (a Pi that kept its
    /// sessions): the client sees no 401, so only the alerts can tell.
    pub fn reboot_keeping_session(&self) {
        self.reboot_inner(true);
    }

    fn reboot_inner(&self, keep_session: bool) {
        self.with(|s| {
            s.rev = 0;
            s.next_id = 1;
            s.alerts.clear();
            s.known.clear();
            s.staged.clear();
            s.exempt.clear();
            s.known_list = "waiting";
            if !keep_session {
                s.sid = None;
            }
            s.clock += 100;
        })
    }

    pub fn set_known_list(&self, v: &'static str) {
        self.with(|s| s.known_list = v);
    }

    /// How many accepted requests began with `prefix` (e.g. `"GET /api/qbp/alerts"`).
    pub fn count(&self, prefix: &str) -> usize {
        self.with(|s| s.log.iter().filter(|l| l.starts_with(prefix)).count())
    }

    /// When the accepted requests that began with `prefix` came in.
    pub fn times(&self, prefix: &str) -> Vec<Instant> {
        self.with(|s| {
            s.log
                .iter()
                .zip(&s.times)
                .filter(|(l, _)| l.starts_with(prefix))
                .map(|(_, t)| *t)
                .collect()
        })
    }

    /// How many accepted requests were for `/api/qbp/` paths.
    pub fn qbp_requests(&self) -> usize {
        self.with(|s| s.log.iter().filter(|l| l.contains(" /api/qbp/")).count())
    }
}

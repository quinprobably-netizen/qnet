//! Pi-hole v6 REST API client.
//!
//! One session at a time: log in once, keep the SID in memory, reuse it until
//! a 401, log in once more, and `DELETE /api/auth` when done. The password is
//! fetched through the supplied callback at login time only.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::https::{HttpError, HttpsClient};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Bad or missing credentials.
    Auth(String),
    /// Certificate pin mismatch or other TLS failure.
    Tls(String),
    /// Could not connect / timed out.
    Unreachable(String),
    Other(String),
}

impl ApiError {
    /// The `pihole.api` status string for this failure.
    pub fn status(&self) -> &'static str {
        match self {
            ApiError::Auth(_) => "auth",
            ApiError::Tls(_) => "tls",
            ApiError::Unreachable(_) => "unreachable",
            ApiError::Other(_) => "unreachable",
        }
    }
    pub fn message(&self) -> &str {
        match self {
            ApiError::Auth(s) | ApiError::Tls(s) | ApiError::Unreachable(s) | ApiError::Other(s) => s,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl From<HttpError> for ApiError {
    fn from(e: HttpError) -> Self {
        match e {
            HttpError::PinMismatch(_) | HttpError::Tls(_) => ApiError::Tls(e.to_string()),
            HttpError::Connect(_) | HttpError::Timeout | HttpError::Io(_) => {
                ApiError::Unreachable(e.to_string())
            }
            HttpError::TooLarge | HttpError::Protocol(_) => ApiError::Other(e.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Summary {
    pub total: u64,
    pub blocked: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockingState {
    Enabled,
    Disabled,
    Unknown,
}

impl BlockingState {
    pub fn as_str(self) -> &'static str {
        match self {
            BlockingState::Enabled => "enabled",
            BlockingState::Disabled => "disabled",
            BlockingState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Blocking {
    pub state: BlockingState,
    /// Seconds until blocking comes back, when paused with a timer.
    pub timer: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    pub t: i64,
    pub total: u64,
    pub blocked: u64,
}

pub const MAX_BUCKETS: usize = 144;

#[derive(Deserialize)]
struct SummaryDoc {
    queries: Option<QueriesDoc>,
}
#[derive(Deserialize)]
struct QueriesDoc {
    #[serde(default)]
    total: f64,
    #[serde(default)]
    blocked: f64,
    #[serde(default)]
    percent_blocked: f64,
}

pub fn parse_summary(v: &Value) -> Result<Summary, ApiError> {
    let d: SummaryDoc = serde_json::from_value(v.clone()).map_err(|e| ApiError::Other(e.to_string()))?;
    let q = d
        .queries
        .ok_or_else(|| ApiError::Other("summary has no queries".into()))?;
    Ok(Summary {
        total: q.total.max(0.0) as u64,
        blocked: q.blocked.max(0.0) as u64,
        percent: q.percent_blocked,
    })
}

pub fn parse_blocking(v: &Value) -> Blocking {
    let state = match v.get("blocking").and_then(Value::as_str) {
        Some("enabled") => BlockingState::Enabled,
        Some("disabled") => BlockingState::Disabled,
        _ => BlockingState::Unknown,
    };
    Blocking {
        state,
        timer: v.get("timer").and_then(Value::as_f64),
    }
}

pub fn parse_history(v: &Value) -> Vec<Bucket> {
    let mut out: Vec<Bucket> = v
        .get("history")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    Some(Bucket {
                        t: e.get("timestamp")?.as_f64()? as i64,
                        total: e.get("total").and_then(Value::as_f64).unwrap_or(0.0).max(0.0) as u64,
                        blocked: e.get("blocked").and_then(Value::as_f64).unwrap_or(0.0).max(0.0) as u64,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if out.len() > MAX_BUCKETS {
        out.drain(..out.len() - MAX_BUCKETS);
    }
    out
}

fn error_message(v: &Value) -> String {
    v.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("request failed")
        .to_string()
}

pub type PasswordFn = Box<dyn FnMut() -> Result<Zeroizing<String>, ApiError> + Send>;

/// A session id we are willing to put in a header and in a file: visible
/// ASCII only, bounded.
pub fn sid_is_sane(sid: &str) -> bool {
    !sid.is_empty() && sid.len() <= 512 && sid.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

#[derive(Serialize)]
struct LoginBody<'a> {
    password: &'a str,
}

pub struct Pihole {
    http: HttpsClient,
    sid: Option<String>,
    password: PasswordFn,
    addr: IpAddr,
    sid_file: Option<std::path::PathBuf>,
}

impl Pihole {
    pub fn new(addr: IpAddr, pin: [u8; 32], password: PasswordFn) -> Result<Self, ApiError> {
        Self::at(SocketAddr::new(addr, 443), pin, password)
    }

    pub fn at(addr: SocketAddr, pin: [u8; 32], password: PasswordFn) -> Result<Self, ApiError> {
        Ok(Self {
            http: HttpsClient::new(addr, Some(pin))?,
            sid: None,
            password,
            addr: addr.ip(),
            sid_file: None,
        })
    }

    /// Keep the session id in `path` (mode 0600 in a 0700 directory) so a
    /// process that is killed without logging out does not leak a session
    /// slot: the next one picks the same session up again.
    pub fn with_sid_file(mut self, path: std::path::PathBuf) -> Self {
        self.sid_file = Some(path);
        self
    }

    fn read_saved_sid(&self) -> Option<String> {
        let path = self.sid_file.as_ref()?;
        if !crate::util::is_private_file(path) {
            return None;
        }
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
        if v.get("address").and_then(Value::as_str)? != self.addr.to_string() {
            return None;
        }
        let sid = v.get("sid").and_then(Value::as_str)?;
        sid_is_sane(sid).then(|| sid.to_string())
    }

    fn save_sid(&self) {
        let (Some(path), Some(sid)) = (&self.sid_file, &self.sid) else { return };
        let Some(dir) = path.parent() else { return };
        let body = json!({ "address": self.addr.to_string(), "sid": sid }).to_string();
        // A failure only means a restart logs in again.
        if crate::util::ensure_private_dir(dir).is_ok() {
            let _ = crate::util::atomic_write(path, body.as_bytes(), 0o600);
        }
    }

    fn forget_saved_sid(&self) {
        if let Some(path) = &self.sid_file {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Pick up the saved session if the Pi-hole still considers it valid.
    /// Returns true when a session is in use afterwards. If the Pi-hole
    /// cannot be reached the saved id is kept: the first real request will
    /// find out.
    pub fn resume_session(&mut self) -> bool {
        let Some(sid) = self.read_saved_sid() else { return false };
        self.sid = Some(sid);
        match self.send("GET", "/api/auth", None) {
            Ok((200, v)) if v.pointer("/session/valid").and_then(Value::as_bool) == Some(true) => true,
            Ok(_) => {
                self.sid = None;
                self.forget_saved_sid();
                false
            }
            Err(_) => true,
        }
    }

    #[cfg(test)]
    pub fn http_mut(&mut self) -> &mut HttpsClient {
        &mut self.http
    }

    #[cfg(test)]
    pub fn has_session(&self) -> bool {
        self.sid.is_some()
    }

    /// Log in with an explicit password (setup uses the web password).
    pub fn login_with(&mut self, password: &str) -> Result<(), ApiError> {
        let body = Zeroizing::new(
            serde_json::to_vec(&LoginBody { password }).map_err(|e| ApiError::Other(e.to_string()))?,
        );
        // Never reuse a connection for the login POST.
        self.http.close();
        let r = self.http.request("POST", "/api/auth", &[], Some(&body[..]))?;
        let v: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        match r.status {
            200 => {
                let session = v.get("session");
                let valid = session
                    .and_then(|s| s.get("valid"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let sid = session.and_then(|s| s.get("sid")).and_then(Value::as_str);
                match (valid, sid) {
                    (true, Some(sid)) if sid_is_sane(sid) => {
                        self.sid = Some(sid.to_string());
                        self.save_sid();
                        Ok(())
                    }
                    _ => Err(ApiError::Auth("login was not accepted".into())),
                }
            }
            401 | 403 => Err(ApiError::Auth(error_message(&v))),
            429 => Err(ApiError::Other("Pi-hole is rate limiting logins".into())),
            s => Err(ApiError::Other(format!("login failed (HTTP {s}): {}", error_message(&v)))),
        }
    }

    fn login(&mut self) -> Result<(), ApiError> {
        let pw = (self.password)()?;
        self.login_with(pw.as_str())
    }

    fn send(&mut self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), ApiError> {
        let sid = self.sid.clone().unwrap_or_default();
        let headers: Vec<(&str, &str)> = if sid.is_empty() {
            vec![]
        } else {
            vec![("X-FTL-SID", sid.as_str())]
        };
        let bytes = match body {
            Some(b) => Some(serde_json::to_vec(b).map_err(|e| ApiError::Other(e.to_string()))?),
            None => None,
        };
        let r = self.http.request(method, path, &headers, bytes.as_deref())?;
        let v = if r.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&r.body).unwrap_or(Value::Null)
        };
        Ok((r.status, v))
    }

    /// Authenticated JSON request. Logs in if there is no session, and once
    /// more after a 401.
    pub fn json(&mut self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, ApiError> {
        if self.sid.is_none() {
            self.login()?;
        }
        let (mut status, mut v) = self.send(method, path, body)?;
        if status == 401 {
            self.sid = None;
            self.forget_saved_sid();
            self.login()?;
            (status, v) = self.send(method, path, body)?;
        }
        match status {
            200..=299 => Ok(v),
            401 | 403 => Err(ApiError::Auth(error_message(&v))),
            429 => Err(ApiError::Other("Pi-hole is rate limiting requests".into())),
            s => Err(ApiError::Other(format!("HTTP {s}: {}", error_message(&v)))),
        }
    }

    pub fn summary(&mut self) -> Result<Summary, ApiError> {
        parse_summary(&self.json("GET", "/api/stats/summary", None)?)
    }

    pub fn blocking(&mut self) -> Result<Blocking, ApiError> {
        Ok(parse_blocking(&self.json("GET", "/api/dns/blocking", None)?))
    }

    pub fn history(&mut self) -> Result<Vec<Bucket>, ApiError> {
        Ok(parse_history(&self.json("GET", "/api/history", None)?))
    }

    /// Pause (`enabled = false`, optional timer in seconds) or resume.
    pub fn set_blocking(&mut self, enabled: bool, timer: Option<u64>) -> Result<Blocking, ApiError> {
        let body = json!({ "blocking": enabled, "timer": timer });
        Ok(parse_blocking(&self.json("POST", "/api/dns/blocking", Some(&body))?))
    }

    /// End the session. Best effort: the server expires it anyway.
    pub fn logout(&mut self) {
        if self.sid.is_some() {
            let _ = self.send("DELETE", "/api/auth", None);
        }
        self.sid = None;
        self.forget_saved_sid();
        self.http.close();
    }

    /// Drop the kept-alive connection but keep the session.
    pub fn close_idle(&mut self) {
        self.http.close();
    }
}

impl Drop for Pihole {
    fn drop(&mut self) {
        self.logout();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::https::testutil::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn parses_summary() {
        let v = json!({"queries":{"total":1204,"blocked":164,"percent_blocked":13.62,"unique_domains":1},"took":0.1});
        assert_eq!(
            parse_summary(&v).unwrap(),
            Summary { total: 1204, blocked: 164, percent: 13.62 }
        );
        assert!(parse_summary(&json!({})).is_err());
        assert!(parse_summary(&json!({"queries":"x"})).is_err());
    }

    #[test]
    fn parses_blocking_states() {
        let b = parse_blocking(&json!({"blocking":"enabled","timer":null}));
        assert_eq!(b, Blocking { state: BlockingState::Enabled, timer: None });
        let b = parse_blocking(&json!({"blocking":"disabled","timer":271.5}));
        assert_eq!(b.state, BlockingState::Disabled);
        assert_eq!(b.timer, Some(271.5));
        assert_eq!(parse_blocking(&json!({"blocking":"failed"})).state, BlockingState::Unknown);
        assert_eq!(parse_blocking(&json!(null)).state, BlockingState::Unknown);
    }

    #[test]
    fn history_is_trimmed_to_144_newest() {
        let items: Vec<Value> = (0..200)
            .map(|i| json!({"timestamp": 1_000 + i * 600, "total": i, "blocked": i / 2, "cached": 0}))
            .collect();
        let h = parse_history(&json!({"history": items}));
        assert_eq!(h.len(), MAX_BUCKETS);
        assert_eq!(h.last().unwrap().t, 1_000 + 199 * 600);
        assert_eq!(h[0].t, 1_000 + 56 * 600);
        assert_eq!(h.last().unwrap().blocked, 99);
        // Entries without a timestamp are skipped, missing counts are zero.
        let h = parse_history(&json!({"history":[{"total":5},{"timestamp":10}]}));
        assert_eq!(h, vec![Bucket { t: 10, total: 0, blocked: 0 }]);
    }

    fn pw(s: &'static str) -> PasswordFn {
        Box::new(move || Ok(Zeroizing::new(s.to_string())))
    }

    const LOGIN_OK: &str = r#"{"session":{"valid":true,"totp":false,"sid":"SID-1","csrf":"c","validity":300},"took":0.01}"#;

    #[test]
    fn logs_in_once_reuses_sid_and_logs_out() {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen2 = seen.clone();
        let srv = serve(3, move |_, req| {
            let first = req.lines().next().unwrap().to_string();
            seen2.lock().unwrap().push(req.to_string());
            if first.starts_with("POST /api/auth") {
                assert!(req.contains(r#"{"password":"app-pw"}"#));
                Some(ok_json(LOGIN_OK))
            } else if first.starts_with("GET /api/stats/summary") {
                assert!(req.contains("X-FTL-SID: SID-1"));
                Some(ok_json(r#"{"queries":{"total":10,"blocked":2,"percent_blocked":20.0}}"#))
            } else if first.starts_with("GET /api/dns/blocking") {
                assert!(req.contains("X-FTL-SID: SID-1"));
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            } else if first.starts_with("DELETE /api/auth") {
                assert!(req.contains("X-FTL-SID: SID-1"));
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            } else {
                None
            }
        });
        {
            let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("app-pw")).unwrap();
            assert_eq!(p.summary().unwrap().total, 10);
            assert_eq!(p.blocking().unwrap().state, BlockingState::Enabled);
            assert!(p.has_session());
            p.logout();
            assert!(!p.has_session());
        }
        let log = seen.lock().unwrap();
        let logins = log.iter().filter(|r| r.starts_with("POST /api/auth")).count();
        let logouts = log.iter().filter(|r| r.starts_with("DELETE /api/auth")).count();
        assert_eq!(logins, 1, "one login for two requests");
        assert_eq!(logouts, 1);
    }

    #[test]
    fn relogs_in_once_after_401() {
        let logins = Arc::new(AtomicUsize::new(0));
        let l2 = logins.clone();
        let srv = serve(4, move |_, req| {
            let first = req.lines().next().unwrap();
            if first.starts_with("POST /api/auth") {
                let n = l2.fetch_add(1, Ordering::SeqCst);
                Some(ok_json(&LOGIN_OK.replace("SID-1", &format!("SID-{}", n + 1))))
            } else if first.starts_with("GET /api/dns/blocking") {
                if req.contains("X-FTL-SID: SID-1") {
                    Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}".to_vec())
                } else {
                    assert!(req.contains("X-FTL-SID: SID-2"));
                    Some(ok_json(r#"{"blocking":"disabled","timer":120}"#))
                }
            } else {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        let b = p.blocking().unwrap();
        assert_eq!(b.state, BlockingState::Disabled);
        assert_eq!(b.timer, Some(120.0));
        assert_eq!(logins.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn persistent_401_is_auth_error_not_a_login_storm() {
        let logins = Arc::new(AtomicUsize::new(0));
        let l2 = logins.clone();
        let srv = serve(6, move |_, req| {
            if req.starts_with("POST /api/auth") {
                l2.fetch_add(1, Ordering::SeqCst);
                Some(ok_json(LOGIN_OK))
            } else {
                Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        assert!(matches!(p.summary(), Err(ApiError::Auth(_))));
        assert_eq!(logins.load(Ordering::SeqCst), 2, "initial + exactly one retry");
    }

    #[test]
    fn rejected_login_is_auth() {
        let srv = serve(1, |_, _| {
            Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 63\r\n\r\n{\"error\":{\"key\":\"unauthorized\",\"message\":\"Unauthorized\",\"hint\":null}}".to_vec())
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("bad")).unwrap();
        let e = p.summary().unwrap_err();
        assert_eq!(e.status(), "auth");
        assert!(!p.has_session());
    }

    #[test]
    fn wrong_pin_is_tls_status() {
        let srv = serve(1, |_, _| Some(ok_json(LOGIN_OK)));
        let mut pin = srv.fingerprint;
        pin[5] ^= 1;
        let mut p = Pihole::at(srv.addr, pin, pw("x")).unwrap();
        let e = p.summary().unwrap_err();
        assert_eq!(e.status(), "tls", "{e:?}");
    }

    #[test]
    fn closed_port_is_unreachable() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let mut p = Pihole::at(addr, [0; 32], pw("x")).unwrap();
        assert_eq!(p.summary().unwrap_err().status(), "unreachable");
    }

    #[test]
    fn password_callback_error_propagates_without_network() {
        let mut p = Pihole::at(
            "127.0.0.1:9".parse().unwrap(),
            [0; 32],
            Box::new(|| Err(ApiError::Auth("no app password in the keyring".into()))),
        )
        .unwrap();
        assert_eq!(p.summary().unwrap_err().status(), "auth");
    }

    #[test]
    fn pause_and_resume_bodies() {
        let bodies = Arc::new(Mutex::new(Vec::<String>::new()));
        let b2 = bodies.clone();
        let srv = serve(3, move |_, req| {
            if req.starts_with("POST /api/auth") {
                return Some(ok_json(LOGIN_OK));
            }
            if req.starts_with("POST /api/dns/blocking") {
                let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                b2.lock().unwrap().push(body.clone());
                let paused = body.contains("false");
                return Some(ok_json(if paused {
                    r#"{"blocking":"disabled","timer":300}"#
                } else {
                    r#"{"blocking":"enabled","timer":null}"#
                }));
            }
            Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        let b = p.set_blocking(false, Some(300)).unwrap();
        assert_eq!(b, Blocking { state: BlockingState::Disabled, timer: Some(300.0) });
        let b = p.set_blocking(true, None).unwrap();
        assert_eq!(b.state, BlockingState::Enabled);
        let sent = bodies.lock().unwrap().clone();
        assert_eq!(sent[0], r#"{"blocking":false,"timer":300}"#);
        assert_eq!(sent[1], r#"{"blocking":true,"timer":null}"#);
    }

    #[test]
    fn oversized_response_is_other_not_panic() {
        let srv = serve(2, |_, req| {
            if req.starts_with("POST /api/auth") {
                return Some(ok_json(LOGIN_OK));
            }
            let big = "x".repeat(300 * 1024);
            Some(ok_json(&format!("{{\"history\":\"{big}\"}}")))
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        let e = p.history().unwrap_err();
        assert!(matches!(e, ApiError::Other(_)), "{e:?}");
        let _ = p.http_mut();
    }

    // -- saved session (survives a SIGKILL) ---------------------------------

    use std::os::unix::fs::PermissionsExt;

    fn write_sid(dir: &std::path::Path, addr: &str, sid: &str, mode: u32) -> std::path::PathBuf {
        let p = dir.join("qnet").join("sid");
        crate::util::ensure_private_dir(p.parent().unwrap()).unwrap();
        std::fs::write(&p, json!({"address": addr, "sid": sid}).to_string()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn login_persists_the_sid_privately_and_logout_removes_it() {
        let srv = serve(3, |_, req| {
            if req.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else if req.starts_with("DELETE") {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            } else {
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qnet").join("sid");
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
            .unwrap()
            .with_sid_file(path.clone());
        p.blocking().unwrap();
        let mode = |q: &std::path::Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["sid"], "SID-1");
        assert_eq!(v["address"], "127.0.0.1");
        p.logout();
        assert!(!path.exists(), "clean exit removes the saved session");
    }

    #[test]
    fn a_valid_saved_session_is_reused_without_logging_in() {
        let logins = Arc::new(AtomicUsize::new(0));
        let l2 = logins.clone();
        let srv = serve(2, move |_, req| {
            if req.starts_with("POST /api/auth") {
                l2.fetch_add(1, Ordering::SeqCst);
                Some(ok_json(LOGIN_OK))
            } else if req.starts_with("GET /api/auth") {
                assert!(req.contains("X-FTL-SID: SAVED-SID"));
                Some(ok_json(r#"{"session":{"valid":true,"sid":"SAVED-SID","validity":1700}}"#))
            } else {
                assert!(req.contains("X-FTL-SID: SAVED-SID"), "{req}");
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = write_sid(dir.path(), "127.0.0.1", "SAVED-SID", 0o600);
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap().with_sid_file(path);
        assert!(p.resume_session());
        assert_eq!(p.blocking().unwrap().state, BlockingState::Enabled);
        assert_eq!(logins.load(Ordering::SeqCst), 0, "a restart must not consume a new slot");
    }

    #[test]
    fn an_expired_saved_session_is_dropped_and_replaced() {
        let srv = serve(4, |_, req| {
            if req.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else if req.starts_with("GET /api/auth") {
                Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 40\r\n\r\n{\"session\":{\"valid\":false,\"sid\":null}}  ".to_vec())
            } else {
                assert!(req.contains("X-FTL-SID: SID-1"), "uses the fresh login: {req}");
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = write_sid(dir.path(), "127.0.0.1", "OLD-SID", 0o600);
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap().with_sid_file(path.clone());
        assert!(!p.resume_session());
        assert!(p.blocking().is_ok());
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["sid"], "SID-1", "the file now holds the new session");
    }

    #[test]
    fn saved_sid_for_another_pihole_or_with_loose_permissions_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let p = write_sid(dir.path(), "10.9.9.9", "THEIRS", 0o600);
        let mut c = Pihole::at(addr, [0; 32], pw("x")).unwrap().with_sid_file(p);
        assert!(!c.resume_session(), "different address");

        let dir2 = tempfile::tempdir().unwrap();
        let p2 = write_sid(dir2.path(), "127.0.0.1", "LOOSE", 0o644);
        let mut c = Pihole::at(addr, [0; 32], pw("x")).unwrap().with_sid_file(p2);
        assert!(!c.resume_session(), "world-readable file is not trusted");

        let dir3 = tempfile::tempdir().unwrap();
        let p3 = dir3.path().join("qnet").join("sid");
        std::fs::create_dir_all(p3.parent().unwrap()).unwrap();
        std::fs::write(&p3, "not json").unwrap();
        std::fs::set_permissions(&p3, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = Pihole::at(addr, [0; 32], pw("x")).unwrap().with_sid_file(p3);
        assert!(!c.resume_session());

        let mut none = Pihole::at(addr, [0; 32], pw("x")).unwrap();
        assert!(!none.resume_session(), "no sid file configured");
    }

    #[test]
    fn unreachable_pihole_keeps_the_saved_session() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let dir = tempfile::tempdir().unwrap();
        let path = write_sid(dir.path(), "127.0.0.1", "KEEP", 0o600);
        let mut c = Pihole::at(addr, [0; 32], pw("x")).unwrap().with_sid_file(path.clone());
        assert!(c.resume_session());
        assert!(path.exists());
        std::mem::forget(c); // a SIGKILL would not run Drop either
    }

    #[test]
    fn a_session_id_with_control_characters_is_refused_and_never_saved() {
        for bad in [
            r#"{"session":{"valid":true,"sid":"abc\ndef","validity":300}}"#,
            r#"{"session":{"valid":true,"sid":"abc def","validity":300}}"#,
            r#"{"session":{"valid":true,"sid":"abc\u0000def","validity":300}}"#,
            r#"{"session":{"valid":true,"sid":"","validity":300}}"#,
        ] {
            let srv = serve(1, move |_, _| Some(ok_json(bad)));
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("qnet").join("sid");
            let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap().with_sid_file(path.clone());
            assert!(matches!(p.summary(), Err(ApiError::Auth(_))), "{bad}");
            assert!(!p.has_session());
            assert!(!path.exists(), "nothing written for {bad}");
        }
        assert!(sid_is_sane("Abc123+/=_-"));
        assert!(!sid_is_sane("a b"));
        assert!(!sid_is_sane("a\tb"));
        assert!(!sid_is_sane(&"a".repeat(513)));
        assert!(!sid_is_sane("é"));
    }
}

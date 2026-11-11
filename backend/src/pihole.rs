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
            ApiError::Auth(s)
            | ApiError::Tls(s)
            | ApiError::Unreachable(s)
            | ApiError::Other(s) => s,
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
pub const MAX_UPSTREAMS: usize = 4;

/// One real upstream resolver from `GET /api/stats/upstreams`.
#[derive(Debug, Clone, PartialEq)]
pub struct Upstream {
    /// Reverse-resolved name, "" when Pi-hole has none.
    pub name: String,
    pub ip: IpAddr,
    pub port: u16,
    pub count: u64,
    /// Average response time in ms, None when Pi-hole has no figure.
    pub response_ms: Option<f64>,
}

/// Where Pi-hole's answers came from: the pseudo-upstreams and the rest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnsweredBy {
    pub blocklist: u64,
    pub cache: u64,
    pub forwarded: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Upstreams {
    pub list: Vec<Upstream>,
    pub answered_by: AnsweredBy,
}

fn count_of(v: &Value) -> Option<u64> {
    let n = v.as_f64()?;
    (n.is_finite() && n >= 0.0).then_some(n as u64)
}

fn clean_hostname(s: &str) -> String {
    let ok = !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if ok {
        s.to_string()
    } else {
        String::new()
    }
}

/// Validate and tidy `/api/stats/upstreams`. The pseudo-entries `blocklist`
/// and `cache` become `answered_by`; real resolvers are checked (address
/// parses, port in range, count a plain number), sorted by count and capped.
pub fn parse_upstreams(v: &Value) -> Result<Upstreams, ApiError> {
    let arr = v
        .get("upstreams")
        .and_then(Value::as_array)
        .ok_or_else(|| ApiError::Other("unexpected upstreams answer".into()))?;
    let mut out = Upstreams::default();
    let mut forwarded_sum = 0u64;
    for e in arr {
        let Some(ip) = e.get("ip").and_then(Value::as_str) else {
            continue;
        };
        let count = e.get("count").and_then(count_of);
        match ip {
            "blocklist" => out.answered_by.blocklist = count.unwrap_or(0),
            "cache" => out.answered_by.cache = count.unwrap_or(0),
            _ => {
                let (Ok(addr), Some(count)) = (ip.parse::<IpAddr>(), count) else {
                    continue;
                };
                let port = match e.get("port").and_then(Value::as_i64) {
                    Some(p) if (1..=65535).contains(&p) => p as u16,
                    _ => continue,
                };
                forwarded_sum += count;
                let name = e
                    .get("name")
                    .and_then(Value::as_str)
                    .map(clean_hostname)
                    .unwrap_or_default();
                let response_ms = e
                    .pointer("/statistics/response")
                    .and_then(Value::as_f64)
                    .filter(|s| s.is_finite() && *s > 0.0)
                    .map(|s| crate::util::round1(s * 1000.0));
                out.list.push(Upstream {
                    name: if name == ip { String::new() } else { name },
                    ip: addr,
                    port,
                    count,
                    response_ms,
                });
            }
        }
    }
    out.answered_by.forwarded = v
        .get("forwarded_queries")
        .and_then(count_of)
        .unwrap_or(forwarded_sum);
    out.list
        .sort_by(|a, b| b.count.cmp(&a.count).then(a.ip.cmp(&b.ip)));
    out.list.truncate(MAX_UPSTREAMS);
    Ok(out)
}

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
    let d: SummaryDoc =
        serde_json::from_value(v.clone()).map_err(|e| ApiError::Other(e.to_string()))?;
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
                        total: e
                            .get("total")
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0)
                            .max(0.0) as u64,
                        blocked: e
                            .get("blocked")
                            .and_then(Value::as_f64)
                            .unwrap_or(0.0)
                            .max(0.0) as u64,
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

/// The login request body, written straight into a buffer that is large
/// enough for the worst case (every byte escaped as `\u00XX`), so it never
/// reallocates and leaves a stray copy of the password behind. Wiped on drop.
fn login_body(password: &str) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let mut body = Zeroizing::new(Vec::with_capacity(password.len() * 6 + 32));
    serde_json::to_writer(&mut *body, &LoginBody { password })
        .map_err(|e| ApiError::Other(e.to_string()))?;
    Ok(body)
}

pub struct Pihole {
    http: HttpsClient,
    sid: Option<String>,
    password: PasswordFn,
    addr: IpAddr,
    sid_file: Option<std::path::PathBuf>,
    logins: u64,
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
            logins: 0,
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
        let (Some(path), Some(sid)) = (&self.sid_file, &self.sid) else {
            return;
        };
        let Some(dir) = path.parent() else { return };
        let body = json!({ "address": self.addr.to_string(), "sid": sid }).to_string();
        // A failure only means a restart logs in again.
        if crate::util::ensure_private_dir(dir).is_ok() {
            let _ = crate::util::atomic_write(path, body.as_bytes(), 0o600);
        }
    }

    /// Remove the saved session, but only if the file still holds `sid`:
    /// another qnet may have logged in since and saved its own, which must
    /// not be pulled out from under it.
    fn forget_saved_sid(&self, sid: &str) {
        let Some(path) = &self.sid_file else { return };
        let still_ours = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.get("sid").and_then(Value::as_str).map(|s| s == sid))
            .unwrap_or(false);
        if still_ours {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Pick up the saved session if the Pi-hole still considers it valid.
    /// Returns true when a session is in use afterwards. If the Pi-hole
    /// cannot be reached the saved id is kept: the first real request will
    /// find out.
    pub fn resume_session(&mut self) -> bool {
        let Some(sid) = self.read_saved_sid() else {
            return false;
        };
        self.sid = Some(sid);
        match self.send("GET", "/api/auth", None) {
            Ok((200, v)) if v.pointer("/session/valid").and_then(Value::as_bool) == Some(true) => {
                true
            }
            Ok(_) => {
                if let Some(old) = self.sid.take() {
                    self.forget_saved_sid(&old);
                }
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
        let body = login_body(password)?;
        // Never reuse a connection for the login POST.
        self.http.close();
        let r = self
            .http
            .request("POST", "/api/auth", &[], Some(&body[..]))?;
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
                        self.logins += 1;
                        self.save_sid();
                        Ok(())
                    }
                    _ => Err(ApiError::Auth("login was not accepted".into())),
                }
            }
            401 | 403 => Err(ApiError::Auth(error_message(&v))),
            429 => Err(ApiError::Other("Pi-hole is rate limiting logins".into())),
            s => Err(ApiError::Other(format!(
                "login failed (HTTP {s}): {}",
                error_message(&v)
            ))),
        }
    }

    fn login(&mut self) -> Result<(), ApiError> {
        let pw = (self.password)()?;
        self.login_with(pw.as_str())
    }

    fn send(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value), ApiError> {
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
        let r = self
            .http
            .request(method, path, &headers, bytes.as_deref())?;
        let v = if r.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&r.body).unwrap_or(Value::Null)
        };
        Ok((r.status, v))
    }

    /// How many sessions this client has opened with a successful login. It
    /// starts at 0, `resume_session` does not count, and a re-login after a
    /// 401 does: a changed value means "this is a new session".
    // The watchdog cycle (a later task) reads it.
    #[allow(dead_code)]
    pub fn logins(&self) -> u64 {
        self.logins
    }

    /// Send an authenticated request: log in if there is no session, and
    /// once more after a 401. Returns the status and body of the final
    /// answer, whatever the status is.
    fn send_authed(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value), ApiError> {
        if self.sid.is_none() {
            self.login()?;
        }
        let (mut status, mut v) = self.send(method, path, body)?;
        if status == 401 {
            if let Some(old) = self.sid.take() {
                self.forget_saved_sid(&old);
            }
            self.login()?;
            (status, v) = self.send(method, path, body)?;
        }
        Ok((status, v))
    }

    /// The body of a 2xx answer, or the error for any other status.
    fn ok_body(status: u16, v: Value) -> Result<Value, ApiError> {
        match status {
            200..=299 => Ok(v),
            401 | 403 => Err(ApiError::Auth(error_message(&v))),
            429 => Err(ApiError::Other("Pi-hole is rate limiting requests".into())),
            s => Err(ApiError::Other(format!("HTTP {s}: {}", error_message(&v)))),
        }
    }

    /// Authenticated JSON request. Logs in if there is no session, and once
    /// more after a 401.
    pub fn json(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, ApiError> {
        let (status, v) = self.send_authed(method, path, body)?;
        Self::ok_body(status, v)
    }

    /// Like [`json`](Self::json), but HTTP 404 is `Ok(None)`: the endpoint
    /// does not exist (or, for an id in the path, the thing it names does
    /// not). Every other status behaves exactly as in `json`.
    pub fn json_opt(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Option<Value>, ApiError> {
        let (status, v) = self.send_authed(method, path, body)?;
        if status == 404 {
            return Ok(None);
        }
        Self::ok_body(status, v).map(Some)
    }

    pub fn summary(&mut self) -> Result<Summary, ApiError> {
        parse_summary(&self.json("GET", "/api/stats/summary", None)?)
    }

    pub fn upstreams(&mut self) -> Result<Upstreams, ApiError> {
        parse_upstreams(&self.json("GET", "/api/stats/upstreams", None)?)
    }

    pub fn blocking(&mut self) -> Result<Blocking, ApiError> {
        Ok(parse_blocking(&self.json(
            "GET",
            "/api/dns/blocking",
            None,
        )?))
    }

    pub fn history(&mut self) -> Result<Vec<Bucket>, ApiError> {
        Ok(parse_history(&self.json("GET", "/api/history", None)?))
    }

    /// Pause (`enabled = false`, optional timer in seconds) or resume.
    pub fn set_blocking(
        &mut self,
        enabled: bool,
        timer: Option<u64>,
    ) -> Result<Blocking, ApiError> {
        let body = json!({ "blocking": enabled, "timer": timer });
        Ok(parse_blocking(&self.json(
            "POST",
            "/api/dns/blocking",
            Some(&body),
        )?))
    }

    /// End the session. Best effort: the server expires it anyway.
    pub fn logout(&mut self) {
        if self.sid.is_some() {
            let _ = self.send("DELETE", "/api/auth", None);
        }
        if let Some(old) = self.sid.take() {
            self.forget_saved_sid(&old);
        }
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
            Summary {
                total: 1204,
                blocked: 164,
                percent: 13.62
            }
        );
        assert!(parse_summary(&json!({})).is_err());
        assert!(parse_summary(&json!({"queries":"x"})).is_err());
    }

    #[test]
    fn parses_blocking_states() {
        let b = parse_blocking(&json!({"blocking":"enabled","timer":null}));
        assert_eq!(
            b,
            Blocking {
                state: BlockingState::Enabled,
                timer: None
            }
        );
        let b = parse_blocking(&json!({"blocking":"disabled","timer":271.5}));
        assert_eq!(b.state, BlockingState::Disabled);
        assert_eq!(b.timer, Some(271.5));
        assert_eq!(
            parse_blocking(&json!({"blocking":"failed"})).state,
            BlockingState::Unknown
        );
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
        assert_eq!(
            h,
            vec![Bucket {
                t: 10,
                total: 0,
                blocked: 0
            }]
        );
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
                Some(ok_json(
                    r#"{"queries":{"total":10,"blocked":2,"percent_blocked":20.0}}"#,
                ))
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
        let logins = log
            .iter()
            .filter(|r| r.starts_with("POST /api/auth"))
            .count();
        let logouts = log
            .iter()
            .filter(|r| r.starts_with("DELETE /api/auth"))
            .count();
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
                Some(ok_json(
                    &LOGIN_OK.replace("SID-1", &format!("SID-{}", n + 1)),
                ))
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
        assert_eq!(
            logins.load(Ordering::SeqCst),
            2,
            "initial + exactly one retry"
        );
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
        assert_eq!(
            b,
            Blocking {
                state: BlockingState::Disabled,
                timer: Some(300.0)
            }
        );
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
                Some(ok_json(
                    r#"{"session":{"valid":true,"sid":"SAVED-SID","validity":1700}}"#,
                ))
            } else {
                assert!(req.contains("X-FTL-SID: SAVED-SID"), "{req}");
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = write_sid(dir.path(), "127.0.0.1", "SAVED-SID", 0o600);
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
            .unwrap()
            .with_sid_file(path);
        assert!(p.resume_session());
        assert_eq!(p.blocking().unwrap().state, BlockingState::Enabled);
        assert_eq!(
            logins.load(Ordering::SeqCst),
            0,
            "a restart must not consume a new slot"
        );
    }

    #[test]
    fn an_expired_saved_session_is_dropped_and_replaced() {
        let srv = serve(4, |_, req| {
            if req.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else if req.starts_with("GET /api/auth") {
                Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 40\r\n\r\n{\"session\":{\"valid\":false,\"sid\":null}}  ".to_vec())
            } else {
                assert!(
                    req.contains("X-FTL-SID: SID-1"),
                    "uses the fresh login: {req}"
                );
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = write_sid(dir.path(), "127.0.0.1", "OLD-SID", 0o600);
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
            .unwrap()
            .with_sid_file(path.clone());
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
        let mut c = Pihole::at(addr, [0; 32], pw("x"))
            .unwrap()
            .with_sid_file(p2);
        assert!(!c.resume_session(), "world-readable file is not trusted");

        let dir3 = tempfile::tempdir().unwrap();
        let p3 = dir3.path().join("qnet").join("sid");
        std::fs::create_dir_all(p3.parent().unwrap()).unwrap();
        std::fs::write(&p3, "not json").unwrap();
        std::fs::set_permissions(&p3, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut c = Pihole::at(addr, [0; 32], pw("x"))
            .unwrap()
            .with_sid_file(p3);
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
        let mut c = Pihole::at(addr, [0; 32], pw("x"))
            .unwrap()
            .with_sid_file(path.clone());
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
            let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
                .unwrap()
                .with_sid_file(path.clone());
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

    #[test]
    fn login_body_never_reallocates_even_when_every_byte_is_escaped() {
        for pw in [
            "hunter2".to_string(),
            "quote\"back\\slash".to_string(),
            "\u{1}\u{2}\u{3}".repeat(100), // control bytes become \u00XX
            "é☕😀".repeat(50),
            String::new(),
        ] {
            let reserved = pw.len() * 6 + 32;
            let body = login_body(&pw).unwrap();
            assert_eq!(body.capacity(), reserved, "no growth for {pw:?}");
            let v: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(v["password"].as_str().unwrap(), pw);
            assert_eq!(v.as_object().unwrap().len(), 1);
        }
    }

    #[test]
    fn logout_leaves_a_session_file_that_another_process_wrote() {
        let srv = serve(5, |_, req| {
            if req.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qnet").join("sid");
        let mut a = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
            .unwrap()
            .with_sid_file(path.clone());
        a.login_with("x").unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["sid"], "SID-1");
        // A newer qnet logs in and saves its own session in the same place.
        std::fs::write(
            &path,
            json!({"address": "127.0.0.1", "sid": "SID-OTHER"}).to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        a.logout();
        assert!(path.exists(), "A must not delete B's session file");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["sid"], "SID-OTHER");
        // Its owner does remove it.
        std::fs::write(
            &path,
            json!({"address": "127.0.0.1", "sid": "SID-1"}).to_string(),
        )
        .unwrap();
        let mut b = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
            .unwrap()
            .with_sid_file(path.clone());
        b.login_with("x").unwrap();
        b.logout();
        assert!(!path.exists());
    }

    #[test]
    fn a_401_relogin_does_not_remove_a_newer_neighbours_file() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let srv = serve(6, move |_, req| {
            if req.starts_with("POST /api/auth") {
                let k = n2.fetch_add(1, Ordering::SeqCst) + 1;
                Some(ok_json(&LOGIN_OK.replace("SID-1", &format!("SID-{k}"))))
            } else if req.contains("X-FTL-SID: SID-1") {
                Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            } else {
                Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qnet").join("sid");
        let mut a = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
            .unwrap()
            .with_sid_file(path.clone());
        a.login_with("x").unwrap(); // SID-1, saved
        std::fs::write(
            &path,
            json!({"address": "127.0.0.1", "sid": "SID-NEIGHBOUR"}).to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        a.blocking().unwrap(); // 401 -> relogin as SID-2 -> saved over it
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["sid"], "SID-2", "the relogin saves the new session");
    }

    #[test]
    fn upstreams_real_pihole_shape() {
        // Verbatim from the live Pi-hole (v6.5).
        let v = json!({
            "upstreams": [
                {"ip":"blocklist","name":"blocklist","port":-1,"count":1734,"statistics":{"response":0,"variance":0}},
                {"ip":"cache","name":"cache","port":-1,"count":1075,"statistics":{"response":0,"variance":0}},
                {"ip":"9.9.9.9","name":"dns9.quad9.net","port":53,"count":287,"statistics":{"response":0.15915417671203613,"variance":0}},
                {"ip":"149.112.112.112","name":"dns.quad9.net","port":53,"count":143,"statistics":{"response":0.045138109714613045,"variance":0.0096}}
            ],
            "total_queries": 3248, "forwarded_queries": 430, "took": 0.0001
        });
        let u = parse_upstreams(&v).unwrap();
        assert_eq!(
            u.answered_by,
            AnsweredBy {
                blocklist: 1734,
                cache: 1075,
                forwarded: 430
            }
        );
        assert_eq!(u.list.len(), 2, "the pseudo-entries are not upstreams");
        assert_eq!(u.list[0].ip, "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(
            (u.list[0].name.as_str(), u.list[0].port, u.list[0].count),
            ("dns9.quad9.net", 53, 287)
        );
        assert_eq!(
            u.list[0].response_ms,
            Some(159.2),
            "seconds become milliseconds"
        );
        assert_eq!(u.list[1].response_ms, Some(45.1));
    }

    #[test]
    fn upstreams_are_validated_sorted_and_capped() {
        let mut items = vec![
            json!({"ip":"blocklist","name":"blocklist","port":-1,"count":10}),
            // Junk that must not get through.
            json!({"ip":"not-an-ip","port":53,"count":999}),
            json!({"ip":"1.2.3.4","port":0,"count":999}),
            json!({"ip":"1.2.3.5","port":70000,"count":999}),
            json!({"ip":"1.2.3.6","port":53,"count":-5}),
            json!({"ip":"1.2.3.7","port":53,"count":"many"}),
            json!({"port":53,"count":999}),
            json!("a string"),
            json!({"ip":"2606:4700:4700::1111","name":"one.one.one.one","port":53,"count":50,"statistics":{"response":0.02}}),
        ];
        for i in 0..6u64 {
            items.push(json!({"ip": format!("10.0.0.{}", i + 1), "name": "", "port": 53, "count": 100 + i, "statistics": {"response": 0}}));
        }
        let u = parse_upstreams(&json!({"upstreams": items})).unwrap();
        assert_eq!(u.list.len(), MAX_UPSTREAMS, "capped");
        let counts: Vec<u64> = u.list.iter().map(|x| x.count).collect();
        assert_eq!(counts, vec![105, 104, 103, 102], "busiest first");
        assert!(u.list.iter().all(|x| x.name.is_empty()));
        assert!(
            u.list.iter().all(|x| x.response_ms.is_none()),
            "a zero response is no figure"
        );
        // No forwarded_queries field: the sum of the valid ones (the capped-off included).
        assert_eq!(
            u.answered_by.forwarded,
            100 + 101 + 102 + 103 + 104 + 105 + 50
        );
        assert_eq!(u.answered_by.blocklist, 10);
        assert_eq!(u.answered_by.cache, 0);
    }

    #[test]
    fn upstream_names_are_cleaned_and_an_ip_as_name_means_no_name() {
        let v = json!({"upstreams":[
            {"ip":"9.9.9.9","name":"9.9.9.9","port":53,"count":3},
            {"ip":"9.9.9.10","name":"evil\u{1b}[2J name","port":53,"count":2},
            {"ip":"9.9.9.11","name":"ok-host_1.example.net","port":53,"count":1}
        ]});
        let u = parse_upstreams(&v).unwrap();
        assert_eq!(u.list[0].name, "");
        assert_eq!(u.list[1].name, "");
        assert_eq!(u.list[2].name, "ok-host_1.example.net");
    }

    #[test]
    fn upstreams_answer_without_the_list_is_an_error() {
        assert!(parse_upstreams(&json!({})).is_err());
        assert!(parse_upstreams(&json!({"upstreams": "x"})).is_err());
        assert_eq!(
            parse_upstreams(&json!({"upstreams": []})).unwrap(),
            Upstreams::default()
        );
    }

    #[test]
    fn upstreams_request_goes_to_the_stats_endpoint() {
        let srv = serve(2, |_, req| {
            if req.starts_with("POST /api/auth") {
                return Some(ok_json(LOGIN_OK));
            }
            assert!(
                req.starts_with("GET /api/stats/upstreams HTTP/1.1"),
                "{req}"
            );
            Some(ok_json(
                r#"{"upstreams":[{"ip":"cache","name":"cache","port":-1,"count":7}],"forwarded_queries":0}"#,
            ))
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        let u = p.upstreams().unwrap();
        assert_eq!(u.answered_by.cache, 7);
    }

    // -- json_opt and the login counter -------------------------------------

    const NOT_FOUND_404: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}";
    const UNAUTHORIZED_401: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}";

    #[test]
    fn json_opt_answers_none_for_404_and_some_for_2xx() {
        let srv = serve(16, |_, req| {
            let first = req.lines().next().unwrap();
            if first.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else if first.starts_with("GET /api/here ") {
                Some(ok_json(r#"{"x":1}"#))
            } else if first.starts_with("GET /api/gone ") {
                Some(NOT_FOUND_404.to_vec())
            } else if first.starts_with("PUT /api/gone ") {
                assert!(req.ends_with(r#"{"a":1}"#), "{req}");
                Some(NOT_FOUND_404.to_vec())
            } else {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        assert_eq!(
            p.json_opt("GET", "/api/here", None).unwrap(),
            Some(json!({"x": 1}))
        );
        assert_eq!(p.json_opt("GET", "/api/gone", None).unwrap(), None);
        assert_eq!(
            p.json_opt("PUT", "/api/gone", Some(&json!({"a": 1})))
                .unwrap(),
            None
        );
    }

    #[test]
    fn json_still_treats_404_as_an_error() {
        let srv = serve(16, |_, req| {
            if req.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else {
                Some(NOT_FOUND_404.to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        let e = p.json("GET", "/api/gone", None).unwrap_err();
        assert!(
            matches!(e, ApiError::Other(ref m) if m.starts_with("HTTP 404")),
            "{e:?}"
        );
    }

    #[test]
    fn json_opt_keeps_the_other_statuses_as_errors() {
        let srv = serve(16, |_, req| {
            let first = req.lines().next().unwrap();
            if first.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else if first.starts_with("GET /api/limited ") {
                Some(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            } else if first.starts_with("GET /api/forbidden ") {
                Some(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            } else if first.starts_with("GET /api/broken ") {
                Some(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            } else {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        assert!(matches!(
            p.json_opt("GET", "/api/limited", None),
            Err(ApiError::Other(_))
        ));
        assert!(matches!(
            p.json_opt("GET", "/api/forbidden", None),
            Err(ApiError::Auth(_))
        ));
        assert!(matches!(
            p.json_opt("GET", "/api/broken", None),
            Err(ApiError::Other(_))
        ));
    }

    #[test]
    fn json_opt_relogs_in_once_after_a_401_and_then_answers() {
        let logins = Arc::new(AtomicUsize::new(0));
        let l2 = logins.clone();
        let srv = serve(16, move |_, req| {
            let first = req.lines().next().unwrap();
            if first.starts_with("POST /api/auth") {
                let n = l2.fetch_add(1, Ordering::SeqCst);
                Some(ok_json(
                    &LOGIN_OK.replace("SID-1", &format!("SID-{}", n + 1)),
                ))
            } else if first.starts_with("GET /api/qbp/x ") {
                if req.contains("X-FTL-SID: SID-1") {
                    Some(UNAUTHORIZED_401.to_vec())
                } else {
                    assert!(req.contains("X-FTL-SID: SID-2"), "{req}");
                    Some(NOT_FOUND_404.to_vec())
                }
            } else {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        assert_eq!(p.json_opt("GET", "/api/qbp/x", None).unwrap(), None);
        assert_eq!(logins.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn json_opt_with_a_persistent_401_is_an_auth_error() {
        let srv = serve(16, |_, req| {
            if req.starts_with("POST /api/auth") {
                Some(ok_json(LOGIN_OK))
            } else {
                Some(UNAUTHORIZED_401.to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        assert!(matches!(
            p.json_opt("GET", "/api/qbp/x", None),
            Err(ApiError::Auth(_))
        ));
    }

    #[test]
    fn json_opt_does_not_call_the_password_when_there_is_no_network_login() {
        let mut p = Pihole::at(
            "127.0.0.1:9".parse().unwrap(),
            [0; 32],
            Box::new(|| Err(ApiError::Auth("no app password in the keyring".into()))),
        )
        .unwrap();
        assert_eq!(
            p.json_opt("GET", "/api/qbp/x", None).unwrap_err().status(),
            "auth"
        );
        assert_eq!(p.logins(), 0);
    }

    #[test]
    fn logins_counts_each_new_session_and_not_a_resumed_one() {
        let n = Arc::new(AtomicUsize::new(0));
        let n2 = n.clone();
        let expire = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let expire2 = expire.clone();
        let srv = serve(16, move |_, req| {
            let first = req.lines().next().unwrap();
            if first.starts_with("POST /api/auth") {
                let k = n2.fetch_add(1, Ordering::SeqCst);
                Some(ok_json(
                    &LOGIN_OK.replace("SID-1", &format!("SID-{}", k + 1)),
                ))
            } else if first.starts_with("GET /api/auth") {
                Some(ok_json(
                    r#"{"session":{"valid":true,"sid":"SAVED-SID","validity":1700}}"#,
                ))
            } else if first.starts_with("GET /api/dns/blocking") {
                if expire2.swap(false, Ordering::SeqCst) {
                    Some(UNAUTHORIZED_401.to_vec())
                } else {
                    Some(ok_json(r#"{"blocking":"enabled","timer":null}"#))
                }
            } else {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            }
        });
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("x")).unwrap();
        assert_eq!(p.logins(), 0, "starts at zero");
        p.blocking().unwrap();
        assert_eq!(p.logins(), 1, "the first login");
        expire.store(true, Ordering::SeqCst);
        p.blocking().unwrap();
        assert_eq!(p.logins(), 2, "a 401 forced a second login");
        p.blocking().unwrap();
        assert_eq!(p.logins(), 2, "a kept session does not count again");
        p.logout();
        p.blocking().unwrap();
        assert_eq!(p.logins(), 3, "a fresh session after a logout");

        // A resumed session is not a login.
        let dir = tempfile::tempdir().unwrap();
        let path = write_sid(dir.path(), "127.0.0.1", "SAVED-SID", 0o600);
        let mut q = Pihole::at(srv.addr, srv.fingerprint, pw("x"))
            .unwrap()
            .with_sid_file(path);
        assert!(q.resume_session());
        assert_eq!(q.logins(), 0);
        std::mem::forget(q);
    }

    #[test]
    fn a_rejected_login_does_not_count() {
        let srv = serve(16, |_, _| Some(UNAUTHORIZED_401.to_vec()));
        let mut p = Pihole::at(srv.addr, srv.fingerprint, pw("bad")).unwrap();
        assert!(p.login_with("bad").is_err());
        assert_eq!(p.logins(), 0);
    }
}

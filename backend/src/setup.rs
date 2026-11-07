//! `qnet pihole setup <addr>`: pin the Pi-hole's certificate, create an app
//! password, keep it in the keyring and write the config.
//!
//! Interactive by design: the web password is typed at a prompt (never an
//! argument), and the certificate fingerprint is shown for the user to
//! accept before anything is sent to the server.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::actions::{ActionErr, ActionResult};
use crate::config;
use crate::https::fetch_fingerprint;
use crate::pihole::{ApiError, Pihole};
use crate::util::format_fingerprint;

/// The dedicated canary: a name that exists only as an exact deny entry, so
/// the health probe never touches gravity stats or a real domain.
pub const DEDICATED_CANARY: &str = "qnet-canary.invalid";

pub trait Prompter {
    fn say(&mut self, text: &str);
    fn confirm(&mut self, question: &str) -> bool;
    /// Read one visible line (an address, a typed "yes").
    fn line(&mut self, prompt: &str) -> Result<String, String>;
    /// Read a secret without echo.
    fn password(&mut self, prompt: &str) -> Result<Zeroizing<String>, String>;
}

pub trait SecretStore {
    fn exists(&self, addr: IpAddr) -> bool;
    fn store(&self, addr: IpAddr, secret: &str) -> Result<(), String>;
}

pub struct Keyring;

impl SecretStore for Keyring {
    fn exists(&self, addr: IpAddr) -> bool {
        config::lookup_password(addr).is_ok()
    }
    fn store(&self, addr: IpAddr, secret: &str) -> Result<(), String> {
        config::store_password(addr, secret).map_err(|e| e.to_string())
    }
}

fn api_err(e: ApiError) -> ActionErr {
    e.into()
}

fn no_password() -> crate::pihole::PasswordFn {
    Box::new(|| Err(ApiError::Auth("no password supplied".into())))
}

/// Creating an app password invalidates running sessions on the Pi-hole, so
/// the setup session must be able to log in again with the web password.
fn web_password(pw: &str) -> crate::pihole::PasswordFn {
    let pw = Zeroizing::new(pw.to_string());
    Box::new(move || Ok(pw.clone()))
}

/// Add the dedicated canary to the Pi-hole's exact deny list. Already being
/// there counts as success.
fn add_canary_domain(ph: &mut Pihole) -> Result<bool, String> {
    let body = json!({
        "domain": DEDICATED_CANARY,
        "comment": "qnet canary",
        "groups": [0],
        "enabled": true,
    });
    match ph.json("POST", "/api/domains/deny/exact", Some(&body)) {
        Ok(_) => Ok(true),
        Err(e) if e.message().to_lowercase().contains("already present") => Ok(false),
        Err(e) => Err(e.message().to_string()),
    }
}

/// `addr` comes from the command line or, if absent, from the user typing it
/// at the prompt. It is never taken from the network.
pub fn run(
    addr: Option<IpAddr>,
    port: u16,
    prompt: &mut dyn Prompter,
    secrets: &dyn SecretStore,
    config_path: &Path,
) -> ActionResult {
    let addr = match addr {
        Some(a) => a,
        None => {
            let typed = prompt.line("Pi-hole address: ").map_err(|e| ActionErr::new("io", e))?;
            typed
                .trim()
                .parse::<IpAddr>()
                .map_err(|_| ActionErr::new("invalid", "that is not an IP address"))?
        }
    };
    let target = SocketAddr::new(addr, port);

    // 1. Trust on first use, or loudly on change.
    let existing_pin = config::load(config_path)
        .ok()
        .and_then(|c| c.pihole)
        .filter(|p| p.address == addr)
        .map(|p| p.tls_sha256);
    let pin = fetch_fingerprint(target, Duration::from_secs(5))
        .map_err(|e| ActionErr::new("unreachable", format!("could not reach {target}: {e}")))?;
    match existing_pin {
        Some(old) if old == pin => {
            prompt.say(&format!("Certificate matches the pinned fingerprint ({}).", format_fingerprint(&pin)));
        }
        Some(old) => {
            prompt.say("!!! CERTIFICATE CHANGED !!!");
            prompt.say(&format!("CERTIFICATE CHANGED (was {}, now {})", format_fingerprint(&old), format_fingerprint(&pin)));
            prompt.say("The Pi-hole's certificate is not the one pinned earlier. That happens when you reinstall it");
            prompt.say("or renew its certificate, and also when something is impersonating it.");
            let typed = prompt
                .line("Type \"yes\" to trust the new certificate and send the password: ")
                .map_err(|e| ActionErr::new("io", e))?;
            if typed.trim() != "yes" {
                return Err(ActionErr::new("declined", "certificate change not accepted"));
            }
        }
        None => {
            prompt.say(&format!("{addr} presents a certificate with SHA-256:"));
            prompt.say(&format!("  {}", format_fingerprint(&pin)));
            prompt.say("Compare it with the value on the Pi-hole (Settings > System, or `openssl x509 -fingerprint -sha256`).");
            if !prompt.confirm("Trust this certificate?") {
                return Err(ActionErr::new("declined", "certificate not accepted"));
            }
        }
    }

    // 2. Log in with the web password.
    let web_pw = prompt
        .password("Pi-hole web password: ")
        .map_err(|e| ActionErr::new("io", e))?;
    if web_pw.is_empty() {
        return Err(ActionErr::new("invalid", "an empty password was entered"));
    }
    let mut ph = Pihole::at(target, pin, web_password(&web_pw)).map_err(api_err)?;
    ph.login_with(&web_pw).map_err(api_err)?;
    drop(web_pw);

    // 3. Is there already an app password? Replacing it breaks its users.
    // If this cannot be read, stop: a later rollback would otherwise "restore"
    // an empty hash over an app password that was really there.
    let current = match ph.json("GET", "/api/config/webserver/api", None) {
        Ok(v) if v.pointer("/config/webserver/api").is_some_and(Value::is_object) => v,
        Ok(_) => {
            ph.logout();
            return Err(ActionErr::new(
                "api",
                "the Pi-hole's answer about its app password setting was not understood; nothing was changed",
            ));
        }
        Err(e) => {
            ph.logout();
            return Err(ActionErr::new(
                "api",
                format!(
                    "could not read the Pi-hole's current app password setting ({}); nothing was changed",
                    e.message()
                ),
            ));
        }
    };
    let old_hash = current
        .pointer("/config/webserver/api/app_pwhash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let in_keyring = secrets.exists(addr);
    if !old_hash.is_empty() || in_keyring {
        prompt.say("This Pi-hole already has an app password (or one is stored for it here).");
        prompt.say("Creating a new one REPLACES it: anything using the old password stops working.");
        if !prompt.confirm("Replace the existing app password?") {
            ph.logout();
            return Err(ActionErr::new("declined", "kept the existing app password"));
        }
    }

    // 4. Create the app password and enable it.
    let app = ph.json("GET", "/api/auth/app", None).map_err(api_err)?;
    let app_pw = Zeroizing::new(
        app.pointer("/app/password")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ActionErr::new("api", "the Pi-hole did not return an app password"))?
            .to_string(),
    );
    let app_hash = app
        .pointer("/app/hash")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ActionErr::new("api", "the Pi-hole did not return an app password hash"))?
        .to_string();
    drop(app);
    ph.json(
        "PATCH",
        "/api/config",
        Some(&json!({"config": {"webserver": {"api": {"app_pwhash": app_hash}}}})),
    )
    .map_err(api_err)?;

    // 5. Keep it; if that fails, put the old hash back.
    if let Err(e) = secrets.store(addr, &app_pw) {
        let _ = ph.json(
            "PATCH",
            "/api/config",
            Some(&json!({"config": {"webserver": {"api": {"app_pwhash": old_hash}}}})),
        );
        ph.logout();
        return Err(ActionErr::new("keyring", e));
    }

    // 6. The dedicated canary. Best effort: without it the health probe
    //    falls back to the configured canary.
    let canary = match add_canary_domain(&mut ph) {
        Ok(true) => {
            prompt.say(&format!("Added {DEDICATED_CANARY} to the deny list (comment \"qnet canary\")."));
            "added"
        }
        Ok(false) => "present",
        Err(e) => {
            prompt.say(&format!("Could not add {DEDICATED_CANARY} to the deny list ({e}); the configured canary will be used."));
            "unavailable"
        }
    };

    // 7. Prove the stored password works before declaring success.
    {
        let mut check = Pihole::at(target, pin, no_password()).map_err(api_err)?;
        if let Err(e) = check.login_with(&app_pw) {
            ph.logout();
            return Err(ActionErr::new(
                "verify",
                format!("the new app password did not log in: {}", e.message()),
            ));
        }
        check.logout();
    }

    // 8. Config last, so a half-finished setup leaves no config behind.
    config::save_pihole(config_path, addr, &pin, None).map_err(|e| ActionErr::new("io", e))?;
    ph.logout();
    Ok(json!({
        "ok": true,
        "address": addr.to_string(),
        "tlsSha256": format_fingerprint(&pin),
        "replacedExisting": !old_hash.is_empty() || in_keyring,
        "canary": canary,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::https::testutil::{ok_json, serve};
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};

    struct Script {
        said: Vec<String>,
        confirms: Vec<bool>,
        questions: Vec<String>,
        password: String,
        lines: Vec<String>,
        asked_lines: Vec<String>,
    }
    impl Prompter for Script {
        fn say(&mut self, t: &str) {
            self.said.push(t.to_string());
        }
        fn confirm(&mut self, q: &str) -> bool {
            self.questions.push(q.to_string());
            if self.confirms.is_empty() {
                false
            } else {
                self.confirms.remove(0)
            }
        }
        fn line(&mut self, p: &str) -> Result<String, String> {
            self.asked_lines.push(p.to_string());
            if self.lines.is_empty() {
                Err("no input".into())
            } else {
                Ok(self.lines.remove(0))
            }
        }
        fn password(&mut self, _p: &str) -> Result<Zeroizing<String>, String> {
            Ok(Zeroizing::new(self.password.clone()))
        }
    }

    struct Store {
        has: bool,
        stored: RefCell<Vec<String>>,
        fail: bool,
    }
    impl SecretStore for Store {
        fn exists(&self, _a: IpAddr) -> bool {
            self.has
        }
        fn store(&self, _a: IpAddr, s: &str) -> Result<(), String> {
            if self.fail {
                return Err("keyring locked".into());
            }
            self.stored.borrow_mut().push(s.to_string());
            Ok(())
        }
    }

    type Log = Arc<Mutex<Vec<String>>>;

    /// A fake Pi-hole. `existing_hash` is what the config reports. Like the
    /// real one, creating an app password kills the session that asked.
    fn fake_pihole(existing_hash: &'static str, log: Log) -> crate::https::testutil::TestServer {
        fake_pihole_with(existing_hash, "ok", log)
    }

    fn fake_pihole_with(
        existing_hash: &'static str,
        domain_mode: &'static str,
        log: Log,
    ) -> crate::https::testutil::TestServer {
        let logins = Arc::new(Mutex::new(0u32));
        let dead: Arc<Mutex<Vec<String>>> = Arc::default();
        serve(30, move |_, req| {
            let first = req.lines().next().unwrap_or("").to_string();
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            log.lock().unwrap().push(format!("{first} | {body}"));
            let sid = req
                .lines()
                .find_map(|l| l.strip_prefix("X-FTL-SID: "))
                .unwrap_or("")
                .to_string();
            let unauthorized = || Some(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}".to_vec());
            if first.starts_with("POST /api/auth") {
                let pw_ok = body.contains("web-secret") || body.contains("app-secret");
                if pw_ok {
                    let mut n = logins.lock().unwrap();
                    *n += 1;
                    let kind = if body.contains("web-secret") { "WEB" } else { "APP" };
                    Some(ok_json(&format!(
                        r#"{{"session":{{"valid":true,"sid":"{kind}{n}","validity":300}}}}"#
                    )))
                } else {
                    unauthorized()
                }
            } else if !first.starts_with("DELETE") && dead.lock().unwrap().contains(&sid) {
                unauthorized()
            } else if first.starts_with("GET /api/config/webserver/api") && existing_hash == "@500" {
                Some(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            } else if first.starts_with("GET /api/config/webserver/api") && existing_hash == "@shape" {
                Some(ok_json(r#"{"took":0.1}"#))
            } else if first.starts_with("GET /api/config/webserver/api") {
                Some(ok_json(&format!(
                    r#"{{"config":{{"webserver":{{"api":{{"app_pwhash":"{existing_hash}"}}}}}}}}"#
                )))
            } else if first.starts_with("POST /api/domains/deny/exact") {
                match domain_mode {
                    "ok" => Some(b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec()),
                    "dup" => {
                        let b = r#"{"error":{"key":"database_error","message":"Database error: The item is already present","hint":null}}"#;
                        Some(format!("HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{b}", b.len()).into_bytes())
                    }
                    _ => Some(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}".to_vec()),
                }
            } else if first.starts_with("GET /api/auth/app") {
                dead.lock().unwrap().push(sid);
                Some(ok_json(r#"{"app":{"password":"app-secret","hash":"$BALLOON-HASH"}}"#))
            } else if first.starts_with("PATCH /api/config") {
                Some(ok_json(r#"{"config":{}}"#))
            } else if first.starts_with("DELETE /api/auth") {
                Some(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())
            } else {
                Some(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}".to_vec())
            }
        })
    }

    /// Run setup against a fake server with the address given on the command line.
    fn go(
        addr: SocketAddr,
        p: &mut Script,
        store: &Store,
        cfg: &std::path::Path,
    ) -> ActionResult {
        run(Some(addr.ip()), addr.port(), p, store, cfg)
    }

    fn script(confirms: Vec<bool>) -> Script {
        Script {
            said: vec![],
            confirms,
            questions: vec![],
            password: "web-secret".into(),
            lines: vec![],
            asked_lines: vec![],
        }
    }

    #[test]
    fn happy_path_creates_stores_verifies_and_writes_config() {
        let log: Log = Arc::default();
        let srv = fake_pihole("", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("qnet").join("config.toml");
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![true]);
        let r = go(srv.addr, &mut p, &store, &cfgp).unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["replacedExisting"], false);
        assert_eq!(store.stored.borrow().as_slice(), ["app-secret"]);
        // The fingerprint was shown.
        assert!(p.said.iter().any(|l| l.contains(&format_fingerprint(&srv.fingerprint))));
        // Config pins exactly that certificate.
        let c = config::load(&cfgp).unwrap();
        assert_eq!(c.pihole.unwrap().tls_sha256, srv.fingerprint);
        let log = log.lock().unwrap();
        // Only the new app-password hash was patched.
        let patch = log.iter().find(|l| l.starts_with("PATCH /api/config")).unwrap();
        assert!(patch.contains(r#"{"config":{"webserver":{"api":{"app_pwhash":"$BALLOON-HASH"}}}}"#), "{patch}");
        // The web session was killed by the app-password creation, so setup
        // logged in a second time to apply the hash; every session it
        // opened was closed again (two web sessions + the verification one).
        assert_eq!(log.iter().filter(|l| l.starts_with("POST /api/auth")).count(), 3);
        assert_eq!(log.iter().filter(|l| l.starts_with("DELETE /api/auth")).count(), 2);
        // The app password never appears in a request except the verify login.
        assert_eq!(log.iter().filter(|l| l.contains("app-secret")).count(), 1);
    }

    #[test]
    fn declining_the_certificate_sends_nothing() {
        let log: Log = Arc::default();
        let srv = fake_pihole("", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![false]);
        let e = go(srv.addr, &mut p, &store, &cfgp).unwrap_err();
        assert_eq!(e.code, "declined");
        assert!(log.lock().unwrap().is_empty(), "no request before the user accepts the pin");
        assert!(!cfgp.exists());
    }

    #[test]
    fn existing_app_password_requires_a_second_confirmation() {
        let log: Log = Arc::default();
        let srv = fake_pihole("$OLD-HASH", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![true, false]);
        let e = go(srv.addr, &mut p, &store, &cfgp).unwrap_err();
        assert_eq!(e.code, "declined");
        assert!(p.questions[1].contains("Replace"));
        assert!(p.said.iter().any(|l| l.contains("REPLACES")));
        assert!(!log.lock().unwrap().iter().any(|l| l.starts_with("PATCH")), "nothing changed");
        assert!(!cfgp.exists());
        assert!(store.stored.borrow().is_empty());

        // Accepting replaces it and says so.
        let log2: Log = Arc::default();
        let srv2 = fake_pihole("$OLD-HASH", log2);
        let mut p = script(vec![true, true]);
        let r = go(srv2.addr, &mut p, &store, &cfgp).unwrap();
        assert_eq!(r["replacedExisting"], true);
    }

    #[test]
    fn wrong_web_password_is_auth_and_writes_nothing() {
        let log: Log = Arc::default();
        let srv = fake_pihole("", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![true]);
        p.password = "wrong".into();
        let e = go(srv.addr, &mut p, &store, &cfgp).unwrap_err();
        assert_eq!(e.code, "auth");
        assert!(!cfgp.exists());
        assert!(store.stored.borrow().is_empty());
    }

    #[test]
    fn keyring_failure_restores_the_old_hash_and_writes_no_config() {
        let log: Log = Arc::default();
        let srv = fake_pihole("$OLD-HASH", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: true };
        let mut p = script(vec![true, true]);
        let e = go(srv.addr, &mut p, &store, &cfgp).unwrap_err();
        assert_eq!(e.code, "keyring");
        assert!(!cfgp.exists());
        let log = log.lock().unwrap();
        let patches: Vec<&String> = log.iter().filter(|l| l.starts_with("PATCH")).collect();
        assert!(patches.iter().any(|p| p.contains("$BALLOON-HASH")));
        assert!(
            patches.last().unwrap().contains("$OLD-HASH"),
            "the original hash goes back last: {patches:?}"
        );
    }

    #[test]
    fn unreachable_server_is_reported() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let dir = tempfile::tempdir().unwrap();
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![true]);
        let e = go(addr, &mut p, &store, &dir.path().join("c.toml")).unwrap_err();
        assert_eq!(e.code, "unreachable");
    }

    #[test]
    fn the_dedicated_canary_is_added_to_the_deny_list_once() {
        let log: Log = Arc::default();
        let srv = fake_pihole("", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![true]);
        let r = go(srv.addr, &mut p, &store, &cfgp).unwrap();
        assert_eq!(r["canary"], "added");
        let log = log.lock().unwrap();
        let post = log.iter().find(|l| l.starts_with("POST /api/domains/deny/exact")).unwrap();
        assert!(post.contains(r#""domain":"qnet-canary.invalid""#), "{post}");
        assert!(post.contains(r#""comment":"qnet canary""#));
        assert_eq!(log.iter().filter(|l| l.starts_with("POST /api/domains")).count(), 1);
    }

    #[test]
    fn an_existing_canary_entry_is_fine_and_a_failure_is_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };

        let srv = fake_pihole_with("", "dup", Arc::default());
        let mut p = script(vec![true]);
        let r = go(srv.addr, &mut p, &store, &dir.path().join("a.toml")).unwrap();
        assert_eq!(r["canary"], "present");

        let srv = fake_pihole_with("", "boom", Arc::default());
        let mut p = script(vec![true]);
        let r = go(srv.addr, &mut p, &store, &dir.path().join("b.toml")).unwrap();
        assert_eq!(r["ok"], true);
        assert_eq!(r["canary"], "unavailable");
        assert!(p.said.iter().any(|l| l.contains("configured canary will be used")));
    }

    #[test]
    fn no_address_means_the_user_types_it_and_nothing_is_detected() {
        let log: Log = Arc::default();
        let srv = fake_pihole("", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![true]);
        p.lines = vec![srv.addr.ip().to_string()];
        let r = run(None, srv.addr.port(), &mut p, &store, &cfgp).unwrap();
        assert_eq!(r["address"], "127.0.0.1");
        assert_eq!(p.asked_lines, vec!["Pi-hole address: "]);

        // Garbage and empty input are refused before any connection.
        for bad in ["pi.hole", "", "192.168.1.999", "1.2.3.4; reboot"] {
            let mut p = script(vec![true]);
            p.lines = vec![bad.to_string()];
            let e = run(None, 443, &mut p, &store, &cfgp).unwrap_err();
            assert_eq!(e.code, "invalid", "{bad:?}");
        }
        // No input at all (stdin closed).
        let mut p = script(vec![true]);
        assert_eq!(run(None, 443, &mut p, &store, &cfgp).unwrap_err().code, "io");
    }

    #[test]
    fn a_changed_certificate_is_shouted_about_and_needs_a_typed_yes() {
        let log: Log = Arc::default();
        let srv = fake_pihole("", log.clone());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        // An earlier setup pinned a different certificate for this address.
        let old = [9u8; 32];
        config::save_pihole(&cfgp, srv.addr.ip(), &old, None).unwrap();
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };

        // y/N is not enough, and neither is anything but "yes".
        for answer in ["y", "Y", "yes please", "", "YES"] {
            let mut p = script(vec![true]);
            p.lines = vec![answer.to_string()];
            let e = go(srv.addr, &mut p, &store, &cfgp).unwrap_err();
            assert_eq!(e.code, "declined", "{answer:?}");
            assert!(
                p.said.iter().any(|l| l.contains("CERTIFICATE CHANGED (was ")
                    && l.contains(&format_fingerprint(&old))
                    && l.contains(&format_fingerprint(&srv.fingerprint))),
                "{:?}",
                p.said
            );
            assert!(log.lock().unwrap().is_empty(), "the password must not be sent: {answer:?}");
            assert_eq!(config::load(&cfgp).unwrap().pihole.unwrap().tls_sha256, old, "pin untouched");
        }

        // Typing yes proceeds and re-pins.
        let mut p = script(vec![]);
        p.lines = vec!["yes".into()];
        let r = go(srv.addr, &mut p, &store, &cfgp).unwrap();
        assert_eq!(r["ok"], true);
        assert!(p.questions.is_empty(), "no extra y/N prompt on top of the typed yes");
        assert_eq!(config::load(&cfgp).unwrap().pihole.unwrap().tls_sha256, srv.fingerprint);
    }

    #[test]
    fn an_unchanged_certificate_on_resetup_is_not_a_scare() {
        let srv = fake_pihole("", Arc::default());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        config::save_pihole(&cfgp, srv.addr.ip(), &srv.fingerprint, None).unwrap();
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![]);
        let r = go(srv.addr, &mut p, &store, &cfgp).unwrap();
        assert_eq!(r["ok"], true);
        assert!(p.said.iter().any(|l| l.contains("matches the pinned fingerprint")));
        assert!(!p.said.iter().any(|l| l.contains("CHANGED")));
        assert!(p.questions.is_empty());
    }

    #[test]
    fn a_pin_for_another_address_does_not_count_as_a_change() {
        let srv = fake_pihole("", Arc::default());
        let dir = tempfile::tempdir().unwrap();
        let cfgp = dir.path().join("config.toml");
        config::save_pihole(&cfgp, "10.9.9.9".parse().unwrap(), &[9u8; 32], None).unwrap();
        let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
        let mut p = script(vec![true]);
        let r = go(srv.addr, &mut p, &store, &cfgp).unwrap();
        assert_eq!(r["ok"], true);
        assert!(!p.said.iter().any(|l| l.contains("CHANGED")));
    }

    #[test]
    fn an_unreadable_app_password_setting_aborts_before_anything_is_changed() {
        for mode in ["@500", "@shape"] {
            let log: Log = Arc::default();
            let srv = fake_pihole(mode, log.clone());
            let dir = tempfile::tempdir().unwrap();
            let cfgp = dir.path().join("config.toml");
            let store = Store { has: false, stored: RefCell::new(vec![]), fail: false };
            let mut p = script(vec![true]);
            let e = go(srv.addr, &mut p, &store, &cfgp).unwrap_err();
            assert_eq!(e.code, "api", "{mode}: {e:?}");
            assert!(e.detail.contains("nothing was changed"), "{}", e.detail);
            let log = log.lock().unwrap();
            assert!(!log.iter().any(|l| l.starts_with("GET /api/auth/app")), "{mode}: no app password made");
            assert!(!log.iter().any(|l| l.starts_with("PATCH")), "{mode}: nothing patched, nothing to roll back");
            assert!(!log.iter().any(|l| l.starts_with("POST /api/domains")));
            assert!(log.iter().any(|l| l.starts_with("DELETE /api/auth")), "the web session was closed");
            assert!(!cfgp.exists());
            assert!(store.stored.borrow().is_empty());
        }
    }
}

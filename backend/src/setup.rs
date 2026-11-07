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

use crate::actions::{ActionErr, ActionResult};
use crate::config;
use crate::https::fetch_fingerprint;
use crate::pihole::{ApiError, Pihole};
use crate::util::format_fingerprint;

pub trait Prompter {
    fn say(&mut self, text: &str);
    fn confirm(&mut self, question: &str) -> bool;
    /// Read a secret without echo.
    fn password(&mut self, prompt: &str) -> Result<String, String>;
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
    let pw = pw.to_string();
    Box::new(move || Ok(pw.clone()))
}

pub fn run(
    target: SocketAddr,
    prompt: &mut dyn Prompter,
    secrets: &dyn SecretStore,
    config_path: &Path,
) -> ActionResult {
    let addr = target.ip();

    // 1. Trust on first use: show the fingerprint, ask.
    let pin = fetch_fingerprint(target, Duration::from_secs(5))
        .map_err(|e| ActionErr::new("unreachable", format!("could not reach {target}: {e}")))?;
    prompt.say(&format!("{addr} presents a certificate with SHA-256:"));
    prompt.say(&format!("  {}", format_fingerprint(&pin)));
    prompt.say("Compare it with the value on the Pi-hole (Settings > System, or `openssl x509 -fingerprint -sha256`).");
    if !prompt.confirm("Trust this certificate?") {
        return Err(ActionErr::new("declined", "certificate not accepted"));
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
    let old_hash = ph
        .json("GET", "/api/config/webserver/api", None)
        .ok()
        .and_then(|v| {
            v.pointer("/config/webserver/api/app_pwhash")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
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
    let app_pw = app
        .pointer("/app/password")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ActionErr::new("api", "the Pi-hole did not return an app password"))?
        .to_string();
    let app_hash = app
        .pointer("/app/hash")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ActionErr::new("api", "the Pi-hole did not return an app password hash"))?
        .to_string();
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

    // 6. Prove the stored password works before declaring success.
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

    // 7. Config last, so a half-finished setup leaves no config behind.
    config::save_pihole(config_path, addr, &pin, None).map_err(|e| ActionErr::new("io", e))?;
    ph.logout();
    Ok(json!({
        "ok": true,
        "address": addr.to_string(),
        "tlsSha256": format_fingerprint(&pin),
        "replacedExisting": !old_hash.is_empty() || in_keyring,
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
        fn password(&mut self, _p: &str) -> Result<String, String> {
            Ok(self.password.clone())
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
            } else if first.starts_with("GET /api/config/webserver/api") {
                Some(ok_json(&format!(
                    r#"{{"config":{{"webserver":{{"api":{{"app_pwhash":"{existing_hash}"}}}}}}}}"#
                )))
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

    fn script(confirms: Vec<bool>) -> Script {
        Script {
            said: vec![],
            confirms,
            questions: vec![],
            password: "web-secret".into(),
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
        let r = run(srv.addr, &mut p, &store, &cfgp).unwrap();
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
        let e = run(srv.addr, &mut p, &store, &cfgp).unwrap_err();
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
        let e = run(srv.addr, &mut p, &store, &cfgp).unwrap_err();
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
        let r = run(srv2.addr, &mut p, &store, &cfgp).unwrap();
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
        let e = run(srv.addr, &mut p, &store, &cfgp).unwrap_err();
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
        let e = run(srv.addr, &mut p, &store, &cfgp).unwrap_err();
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
        let e = run(addr, &mut p, &store, &dir.path().join("c.toml")).unwrap_err();
        assert_eq!(e.code, "unreachable");
    }
}

//! qnet: backend for the qqq.qnet Omarchy bar plugin.
//!
//!   qnet watch                     long-lived: JSON state lines on stdout
//!   qnet state                     one state snapshot, then exit (debugging)
//!   qnet dns pihole|auto [--force] DNS mode of the active connection
//!   qnet dns pin <uuid> [--force]  pin a saved profile to the Pi-hole
//!   qnet pihole pause [secs]|resume|setup <addr>
//!   qnet wifi connect <ap-path>    passphrase on stdin
//!   qnet wifi down|scan|radio on|off|forget <uuid>
//!   qnet portal                    captive-portal browser, throwaway profile
//!
//! One-shot verbs print one JSON line and exit 0 (`ok`) or 1.

mod actions;
mod config;
mod dnsmodel;
mod dnswire;
mod failover;
mod https;
mod icmp;
mod ledger;
mod neigh;
mod net;
mod nm;
mod pihole;
mod proc;
mod rstate;
mod setup;
mod state;
mod threads;
mod util;
mod watch;

use std::io::{BufRead, IsTerminal, Read, Write};
use std::process::ExitCode;

use serde_json::{json, Value};
use zeroize::Zeroizing;

use actions::{ActionErr, ActionResult, Ctx};

const USAGE: &str = "usage: qnet watch | state | dns pihole|auto [--force] | dns pin <uuid> [--force] | \
pihole pause [secs]|resume|setup <addr> | wifi connect <ap-path>|down|scan|forget <uuid>|radio on|off | portal";

fn usage() -> ActionErr {
    ActionErr::new("usage", USAGE)
}

fn backend() -> Result<nm::DbusBackend, ActionErr> {
    nm::DbusBackend::connect().map_err(|e| ActionErr::new("dbus", e.detail()))
}

fn backend_cancellable(term: &std::sync::Arc<std::sync::atomic::AtomicBool>) -> Result<nm::DbusBackend, ActionErr> {
    Ok(backend()?.with_cancel(term.clone()))
}

fn load_config() -> Result<config::Config, ActionErr> {
    config::load(&util::config_path()).map_err(|e| ActionErr::new("config", e))
}

// ---- Terminal helpers -----------------------------------------------------

/// Read a line without echo (when stdin is a terminal).
fn read_secret_line(prompt: &str) -> Result<Zeroizing<String>, String> {
    let tty = std::io::stdin().is_terminal();
    if tty {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
    }
    // SAFETY: plain termios calls on fd 0 with a zeroed, then filled, struct.
    let mut saved: Option<libc::termios> = None;
    if tty {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) == 0 {
                saved = Some(t);
                t.c_lflag &= !libc::ECHO;
                libc::tcsetattr(0, libc::TCSANOW, &t);
            }
        }
    }
    // Reserved up front (and the read is capped at 4096) so the buffer never
    // reallocates and leaves an unwiped copy behind.
    let mut line = Zeroizing::new(String::with_capacity(4200));
    let res = std::io::stdin().lock().take(4096).read_line(&mut line);
    if let Some(t) = saved {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &t);
        }
        eprintln!();
    }
    res.map_err(|e| e.to_string())?;
    let kept = line.trim_end_matches(['\n', '\r']).len();
    line.truncate(kept);
    Ok(line)
}

struct Terminal;

impl setup::Prompter for Terminal {
    fn say(&mut self, text: &str) {
        eprintln!("{text}");
    }
    fn confirm(&mut self, question: &str) -> bool {
        eprint!("{question} [y/N] ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().lock().take(256).read_line(&mut line).is_err() {
            return false;
        }
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }
    fn line(&mut self, prompt: &str) -> Result<String, String> {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        let n = std::io::stdin()
            .lock()
            .take(1024)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("end of input".into());
        }
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }
    fn password(&mut self, prompt: &str) -> Result<Zeroizing<String>, String> {
        read_secret_line(prompt)
    }
}

// ---- Command line ----------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Cmd {
    Watch,
    State,
    DnsPihole { force: bool },
    DnsAuto { force: bool },
    DnsPin { uuids: Vec<String>, force: bool },
    PiholePause { secs: u64 },
    PiholeResume,
    /// The address is optional: without it setup asks the user to type one.
    PiholeSetup { addr: Option<std::net::IpAddr> },
    WifiConnect { ap: String },
    WifiDown,
    WifiScan { if_stale: Option<u64> },
    WifiForget { uuid: String },
    WifiRadio { on: bool },
    Portal,
    Version,
}

/// Parse and validate the command line. Nothing here touches the system, so
/// bad input never gets as far as a D-Bus call.
fn parse(all: &[String]) -> Result<Cmd, ActionErr> {
    // `--if-stale <secs>` takes a value, so it is cut out before the rest is
    // matched by position.
    let mut args: Vec<String> = Vec::new();
    let mut if_stale: Option<u64> = None;
    let mut it = all.iter();
    while let Some(a) = it.next() {
        if a == "--if-stale" {
            let secs = it
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| (1..=86_400).contains(v))
                .ok_or_else(|| ActionErr::new("invalid", "--if-stale needs a number of seconds (1-86400)"))?;
            if_stale = Some(secs);
        } else {
            args.push(a.clone());
        }
    }
    let cmd = parse_positional(&args, if_stale)?;
    if if_stale.is_some() && !matches!(cmd, Cmd::WifiScan { .. }) {
        return Err(ActionErr::new("invalid", "--if-stale only applies to `wifi scan`"));
    }
    Ok(cmd)
}

fn parse_positional(args: &[String], if_stale: Option<u64>) -> Result<Cmd, ActionErr> {
    let force = args.iter().any(|a| a == "--force");
    let pos: Vec<&str> = args
        .iter()
        .filter(|a| !a.starts_with("--") || *a == "--version")
        .map(|s| s.as_str())
        .collect();
    let bad_uuid = || ActionErr::new("invalid", "not a connection uuid");
    match pos.as_slice() {
        ["watch"] => Ok(Cmd::Watch),
        ["state"] => Ok(Cmd::State),
        ["portal"] => Ok(Cmd::Portal),
        ["--version"] | ["-V"] => Ok(Cmd::Version),
        ["dns", "pihole"] => Ok(Cmd::DnsPihole { force }),
        ["dns", "auto"] => Ok(Cmd::DnsAuto { force }),
        ["dns", "pin", uuids @ ..] if !uuids.is_empty() => {
            if uuids.len() > 16 || uuids.iter().any(|u| !util::is_uuid(u)) {
                return Err(bad_uuid());
            }
            let mut list: Vec<String> = Vec::new();
            for u in uuids {
                if !list.iter().any(|x| x == u) {
                    list.push(u.to_string());
                }
            }
            Ok(Cmd::DnsPin { uuids: list, force })
        }
        ["pihole", "pause"] => Ok(Cmd::PiholePause { secs: 300 }),
        ["pihole", "pause", secs] => secs
            .parse::<u64>()
            .map(|secs| Cmd::PiholePause { secs })
            .map_err(|_| ActionErr::new("invalid", "seconds must be a number")),
        ["pihole", "resume"] => Ok(Cmd::PiholeResume),
        ["pihole", "setup"] => Ok(Cmd::PiholeSetup { addr: None }),
        ["pihole", "setup", addr] => addr
            .parse()
            .map(|addr| Cmd::PiholeSetup { addr: Some(addr) })
            .map_err(|_| ActionErr::new("invalid", "the Pi-hole address must be an IP address")),
        ["wifi", "connect", ap] => {
            if !util::is_ap_path(ap) {
                return Err(ActionErr::new("invalid", "not an access point path"));
            }
            Ok(Cmd::WifiConnect { ap: ap.to_string() })
        }
        ["wifi", "down"] => Ok(Cmd::WifiDown),
        ["wifi", "scan"] => Ok(Cmd::WifiScan { if_stale }),
        ["wifi", "forget", uuid] => {
            if !util::is_uuid(uuid) {
                return Err(bad_uuid());
            }
            Ok(Cmd::WifiForget { uuid: uuid.to_string() })
        }
        ["wifi", "radio", "on"] => Ok(Cmd::WifiRadio { on: true }),
        ["wifi", "radio", "off"] => Ok(Cmd::WifiRadio { on: false }),
        _ => Err(usage()),
    }
}

fn pihole_client(cfg: &config::Config) -> Result<pihole::Pihole, ActionErr> {
    let p = cfg
        .pihole
        .as_ref()
        .ok_or_else(|| ActionErr::new("unconfigured", "no Pi-hole configured; run `qnet pihole setup <address>`"))?;
    let addr = p.address;
    Ok(pihole::Pihole::new(
        addr,
        p.tls_sha256,
        Box::new(move || {
            config::lookup_password(addr).map_err(|e| match e {
                config::SecretError::Missing(m) => pihole::ApiError::Auth(m),
                config::SecretError::Failed(m) => pihole::ApiError::Other(m),
            })
        }),
    )?)
}

fn run_oneshot(cmd: Cmd) -> ActionResult {
    match cmd {
        Cmd::PiholeSetup { addr } => {
            // Interactive: Ctrl-C must keep working at the prompts, so no
            // signal flag here.
            if !std::io::stdin().is_terminal() {
                return Err(ActionErr::new("interactive", "pihole setup must be run from a terminal"));
            }
            util::harden_process();
            setup::run(addr, 443, &mut Terminal, &setup::Keyring, &util::config_path())
        }
        // From here on SIGTERM/SIGINT/SIGHUP only set a flag: the step in
        // progress finishes (or is undone) and sessions are logged out.
        Cmd::PiholePause { secs } => {
            let term = util::term_flag();
            util::harden_process();
            let cfg = load_config()?;
            let mut api = pihole_client(&cfg)?;
            let r = if term.load(std::sync::atomic::Ordering::SeqCst) {
                Err(ActionErr::new("interrupted", "stopped before anything was changed"))
            } else {
                actions::pihole_pause(&mut api, secs)
            };
            api.logout();
            r
        }
        Cmd::PiholeResume => {
            let term = util::term_flag();
            util::harden_process();
            let cfg = load_config()?;
            let mut api = pihole_client(&cfg)?;
            let r = if term.load(std::sync::atomic::Ordering::SeqCst) {
                Err(ActionErr::new("interrupted", "stopped before anything was changed"))
            } else {
                actions::pihole_resume(&mut api)
            };
            api.logout();
            r
        }
        Cmd::WifiConnect { ap } => {
            let term = util::term_flag();
            // One line on stdin: the passphrase (empty for open/known).
            // Read a line, never to EOF: the caller keeps the pipe open.
            util::harden_process();
            let pass = read_secret_line("Passphrase (empty for none): ").map_err(|e| ActionErr::new("io", e))?;
            let be = backend_cancellable(&term)?;
            let cfg = load_config()?;
            let mut ctx = Ctx::new(&be, &cfg);
            ctx.term = term;
            actions::wifi_connect(&ctx, &ap, Some(&pass))
        }
        other => {
            let term = util::term_flag();
            let be = backend_cancellable(&term)?;
            let cfg = load_config()?;
            let mut ctx = Ctx::new(&be, &cfg);
            ctx.term = term;
            match other {
                Cmd::DnsPihole { force } => actions::dns_pihole(&ctx, force),
                Cmd::DnsAuto { force } => actions::dns_auto(&ctx, force),
                Cmd::DnsPin { uuids, force } => actions::dns_pin_many(&ctx, &uuids, force),
                Cmd::WifiDown => actions::wifi_down(&ctx),
                Cmd::WifiScan { if_stale } => actions::wifi_scan(&ctx, if_stale),
                Cmd::WifiForget { uuid } => actions::wifi_forget(&ctx, &uuid),
                Cmd::WifiRadio { on } => actions::wifi_radio(&ctx, on),
                _ => Err(usage()),
            }
        }
    }
}

/// Opens the captive-portal page; stays alive until the browser exits so the
/// throwaway profile can be removed.
fn cmd_portal() -> ExitCode {
    let be = match backend() {
        Ok(b) => b,
        Err(e) => return print_result(Err(e)),
    };
    let url = match net::NetBackend::snapshot(&be, false) {
        Ok(s) => actions::portal_url(&s),
        Err(_) => actions::DEFAULT_PORTAL_URL.to_string(),
    };
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = match actions::private_temp_dir(&base) {
        Ok(d) => d,
        Err(e) => return print_result(Err(ActionErr::new("io", format!("temp dir: {e}")))),
    };
    let child = std::process::Command::new("chromium")
        .args(actions::portal_args(&url, &dir))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match child {
        Ok(mut c) => {
            print_json(&json!({"ok": true, "url": url}));
            let _ = c.wait();
            let _ = std::fs::remove_dir_all(&dir);
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            print_result(Err(ActionErr::new("spawn", format!("could not start chromium: {e}"))))
        }
    }
}

fn print_json(v: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn print_result(r: ActionResult) -> ExitCode {
    match r {
        Ok(v) => {
            print_json(&v);
            ExitCode::SUCCESS
        }
        Err(e) => {
            print_json(&e.to_json());
            ExitCode::from(if e.code == "usage" { 2 } else { 1 })
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Err(e) => print_result(Err(e)),
        Ok(Cmd::Watch) => match backend() {
            Ok(be) => ExitCode::from(watch::run_watch(Box::new(be)) as u8),
            Err(e) => print_result(Err(e)),
        },
        Ok(Cmd::State) => match backend() {
            Ok(be) => {
                let st = watch::state_once(Box::new(be));
                print_json(&serde_json::to_value(&st).unwrap_or(Value::Null));
                ExitCode::SUCCESS
            }
            Err(e) => print_result(Err(e)),
        },
        Ok(Cmd::Portal) => cmd_portal(),
        Ok(Cmd::Version) => {
            println!("qnet {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(cmd) => print_result(run_oneshot(cmd)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Cmd, ActionErr> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    const U: &str = "21307067-f47b-43ea-8c9c-2c746454b2bb";
    const AP: &str = "/org/freedesktop/NetworkManager/AccessPoint/12";

    #[test]
    fn verbs_parse() {
        assert_eq!(p(&["watch"]), Ok(Cmd::Watch));
        assert_eq!(p(&["state"]), Ok(Cmd::State));
        assert_eq!(p(&["portal"]), Ok(Cmd::Portal));
        assert_eq!(p(&["--version"]), Ok(Cmd::Version));
        assert_eq!(p(&["dns", "pihole"]), Ok(Cmd::DnsPihole { force: false }));
        assert_eq!(p(&["dns", "pihole", "--force"]), Ok(Cmd::DnsPihole { force: true }));
        assert_eq!(p(&["dns", "--force", "auto"]), Ok(Cmd::DnsAuto { force: true }));
        assert_eq!(p(&["dns", "pin", U]), Ok(Cmd::DnsPin { uuids: vec![U.into()], force: false }));
        let u2 = "f5520df2-a482-3ff6-a770-64b74a740967";
        assert_eq!(
            p(&["dns", "pin", U, "--force", u2, U]),
            Ok(Cmd::DnsPin { uuids: vec![U.into(), u2.into()], force: true }),
            "several uuids, duplicates dropped"
        );
        assert_eq!(p(&["pihole", "pause"]), Ok(Cmd::PiholePause { secs: 300 }));
        assert_eq!(p(&["pihole", "pause", "60"]), Ok(Cmd::PiholePause { secs: 60 }));
        assert_eq!(p(&["pihole", "resume"]), Ok(Cmd::PiholeResume));
        assert_eq!(
            p(&["pihole", "setup", "192.168.1.153"]),
            Ok(Cmd::PiholeSetup { addr: Some("192.168.1.153".parse().unwrap()) })
        );
        assert_eq!(p(&["pihole", "setup"]), Ok(Cmd::PiholeSetup { addr: None }));
        assert_eq!(p(&["wifi", "connect", AP]), Ok(Cmd::WifiConnect { ap: AP.into() }));
        assert_eq!(p(&["wifi", "down"]), Ok(Cmd::WifiDown));
        assert_eq!(p(&["wifi", "scan"]), Ok(Cmd::WifiScan { if_stale: None }));
        assert_eq!(p(&["wifi", "scan", "--if-stale", "60"]), Ok(Cmd::WifiScan { if_stale: Some(60) }));
        assert_eq!(p(&["wifi", "--if-stale", "5", "scan"]), Ok(Cmd::WifiScan { if_stale: Some(5) }));
        assert_eq!(p(&["wifi", "forget", U]), Ok(Cmd::WifiForget { uuid: U.into() }));
        assert_eq!(p(&["wifi", "radio", "on"]), Ok(Cmd::WifiRadio { on: true }));
        assert_eq!(p(&["wifi", "radio", "off"]), Ok(Cmd::WifiRadio { on: false }));
    }

    #[test]
    fn bad_input_is_rejected_before_anything_runs() {
        for bad in [
            &[][..],
            &["bogus"],
            &["dns"],
            &["dns", "wipe"],
            &["dns", "pin"],
            &["dns", "pin", "../etc"],
            &["dns", "pin", U, "not-a-uuid"],
            &["dns", "pihole", "extra"],
            &["pihole", "pause", "soon"],
            &["pihole", "pause", "-5"],
            &["pihole", "setup", "pi.hole"],
            &["wifi", "connect"],
            &["wifi", "connect", "Redwood"],
            &["wifi", "connect", "/org/freedesktop/NetworkManager/AccessPoint/1/../2"],
            &["wifi", "forget", "Redwood"],
            &["wifi", "scan", "--if-stale"],
            &["wifi", "scan", "--if-stale", "soon"],
            &["wifi", "scan", "--if-stale", "0"],
            &["wifi", "scan", "--if-stale", "-5"],
            &["wifi", "scan", "--if-stale", "999999"],
            &["wifi", "down", "--if-stale", "60"],
            &["dns", "auto", "--if-stale", "60"],
            &["wifi", "radio"],
            &["wifi", "radio", "maybe"],
            &["watch", "now"],
        ] {
            let e = p(bad).unwrap_err();
            assert!(e.code == "usage" || e.code == "invalid", "{bad:?} -> {e:?}");
        }
        assert_eq!(p(&["bogus"]).unwrap_err().code, "usage");
        assert_eq!(p(&["wifi", "forget", "x"]).unwrap_err().code, "invalid");
    }

    #[test]
    fn passphrase_reader_stops_at_the_first_line() {
        // The real reader locks process stdin; test the framing it relies on.
        use std::io::{BufRead, Read};
        let mut input = std::io::Cursor::new(b"hunter2 pass\nmore".to_vec()).take(4096);
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        assert_eq!(line.trim_end_matches(['\n', '\r']), "hunter2 pass");
    }
}

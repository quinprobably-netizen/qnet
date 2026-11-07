//! Small shared helpers: time, randomness, fingerprints, atomic file writes.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, fractional.
pub fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn unix_secs() -> u64 {
    unix_now() as u64
}

/// Fill `buf` from /dev/urandom.
pub fn urandom(buf: &mut [u8]) -> io::Result<()> {
    fs::File::open("/dev/urandom")?.read_exact(buf)
}

pub fn random_u16() -> u16 {
    let mut b = [0u8; 2];
    if urandom(&mut b).is_err() {
        // Extremely unlikely; fall back to the clock so probes still work.
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(7);
        return (n ^ (n >> 16)) as u16;
    }
    u16::from_be_bytes(b)
}

/// Round to one decimal place.
pub fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// `71:C7:1F:...` (uppercase, colon separated).
pub fn format_fingerprint(d: &[u8; 32]) -> String {
    let mut s = String::with_capacity(95);
    for (i, b) in d.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// Parse a SHA-256 fingerprint written with or without colons, any case.
pub fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let hex: Vec<u8> = s
        .bytes()
        .filter(|b| !matches!(b, b':' | b' ' | b'-'))
        .collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// NetworkManager connection UUID: 8-4-4-4-12 hex digits.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// NetworkManager access-point object path, digits only after the prefix.
pub fn is_ap_path(s: &str) -> bool {
    const PREFIX: &str = "/org/freedesktop/NetworkManager/AccessPoint/";
    match s.strip_prefix(PREFIX) {
        Some(rest) => !rest.is_empty() && rest.len() <= 10 && rest.bytes().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn config_dir() -> PathBuf {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v).join("qnet"),
        _ => home_dir().join(".config").join("qnet"),
    }
}

pub fn config_path() -> PathBuf {
    config_dir().join("config.toml")
}

pub fn state_dir() -> PathBuf {
    match std::env::var_os("XDG_STATE_HOME") {
        Some(v) if !v.is_empty() => PathBuf::from(v).join("qnet"),
        _ => home_dir().join(".local").join("state").join("qnet"),
    }
}

/// `$XDG_RUNTIME_DIR/qnet`, the home of the small cross-process files (the
/// session id, the DNS lock, the Wi-Fi throttles). Falls back to the state
/// directory so a missing runtime dir never disables a safety guard.
pub fn runtime_qnet_dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(rt) => PathBuf::from(rt).join("qnet"),
        None => state_dir(),
    }
}

/// An exclusive advisory lock on a file, released when dropped (or when the
/// process dies, however it dies).
#[derive(Debug)]
pub struct FileLock {
    _file: fs::File,
}

/// Try to take the lock without waiting. `Ok(None)` means someone else holds
/// it.
pub fn try_lock(path: &Path) -> io::Result<Option<FileLock>> {
    use std::os::fd::AsRawFd;
    if let Some(dir) = path.parent() {
        ensure_private_dir(dir)?;
    }
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)?;
    // SAFETY: flock on a descriptor we own; no memory is passed.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc == 0 {
        return Ok(Some(FileLock { _file: file }));
    }
    let err = io::Error::last_os_error();
    if err.kind() == io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(err)
    }
}

/// A flag that SIGTERM, SIGINT and SIGHUP set instead of killing the process,
/// so a verb can finish or undo its current step and log out. Not for
/// interactive prompts: a restarted `read` would swallow Ctrl-C.
pub fn term_flag() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for sig in [SIGTERM, SIGINT, SIGHUP] {
        let _ = signal_hook::flag::register(sig, flag.clone());
    }
    flag
}

/// Refuse core dumps and same-user memory reads of this process. Called by
/// the verbs that handle secrets.
pub fn harden_process() {
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes plain integers.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// `$XDG_RUNTIME_DIR/qnet/sid`, where the Pi-hole session id is kept so a
/// restart can reuse a session the previous process could not log out of.
pub fn sid_path() -> Option<PathBuf> {
    let rt = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(rt).join("qnet").join("sid"))
}

/// Create `dir` (and parents) and make sure the last component is mode 0700.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// True when `path` is a regular file owned by us that nobody else can read.
pub fn is_private_file(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        // SAFETY: geteuid has no preconditions.
        Ok(m) => m.file_type().is_file() && m.mode() & 0o077 == 0 && m.uid() == unsafe { libc::geteuid() },
        Err(_) => false,
    }
}

/// Write `bytes` to `path` via a temp file in the same directory and a rename.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    let mut tag = [0u8; 4];
    urandom(&mut tag)?;
    let tmp = dir.join(format!(
        ".{}.{:02x}{:02x}{:02x}{:02x}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        tag[0],
        tag[1],
        tag[2],
        tag[3]
    ));
    let res = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Hostname syntax check for the canary: letters, digits, `-`, `_`, dots.
pub fn valid_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_roundtrip() {
        let s = "71:C7:1F:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:01:23:45:67:89:AB:CD:EF:10:32:54:76:F4";
        let d = parse_fingerprint(s).unwrap();
        assert_eq!(d[0], 0x71);
        assert_eq!(d[31], 0xF4);
        assert_eq!(format_fingerprint(&d), s);
        assert_eq!(parse_fingerprint(&s.to_lowercase()), Some(d));
        assert_eq!(parse_fingerprint(&s.replace(':', "")), Some(d));
        assert!(parse_fingerprint("71:C7").is_none());
        assert!(parse_fingerprint(&s.replace("71", "ZZ")).is_none());
    }

    #[test]
    fn uuid_shape() {
        assert!(is_uuid("21307067-f47b-43ea-8c9c-2c746454b2bb"));
        assert!(!is_uuid("21307067-f47b-43ea-8c9c-2c746454b2b"));
        assert!(!is_uuid("21307067_f47b_43ea_8c9c_2c746454b2bb"));
        assert!(!is_uuid("2130706g-f47b-43ea-8c9c-2c746454b2bb"));
        assert!(!is_uuid("../../etc/passwd"));
    }

    #[test]
    fn ap_path_shape() {
        assert!(is_ap_path("/org/freedesktop/NetworkManager/AccessPoint/12"));
        assert!(!is_ap_path("/org/freedesktop/NetworkManager/AccessPoint/"));
        assert!(!is_ap_path("/org/freedesktop/NetworkManager/AccessPoint/1/../2"));
        assert!(!is_ap_path("/org/freedesktop/NetworkManager/Settings/1"));
        assert!(!is_ap_path("Redwood"));
    }

    #[test]
    fn dns_name_validation() {
        assert!(valid_dns_name("doubleclick.net"));
        assert!(valid_dns_name("doubleclick.net."));
        assert!(!valid_dns_name(""));
        assert!(!valid_dns_name("a..b"));
        assert!(!valid_dns_name("bad name.com"));
        assert!(!valid_dns_name(&"a".repeat(64)));
    }

    #[test]
    fn atomic_write_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("f.json");
        atomic_write(&p, b"one", 0o600).unwrap();
        atomic_write(&p, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let leftovers = fs::read_dir(p.parent().unwrap()).unwrap().count();
        assert_eq!(leftovers, 1);
    }

    #[test]
    fn try_lock_is_exclusive_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("dns.lock");
        let first = try_lock(&p).unwrap().expect("free lock");
        assert!(try_lock(&p).unwrap().is_none(), "busy while held");
        drop(first);
        assert!(try_lock(&p).unwrap().is_some(), "free again");
        let mode = fs::metadata(p.parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn runtime_dir_falls_back_to_state() {
        // Only the shape is checked; the environment is the test runner's.
        let d = runtime_qnet_dir();
        assert!(d.ends_with("qnet"));
    }
}

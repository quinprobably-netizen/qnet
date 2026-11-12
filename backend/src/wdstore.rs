//! The PC-side watchdog store (`~/.local/state/qnet/watchdog.json`, mode
//! 0600): which alerts were acknowledged here, the known-device list (with
//! labels) that is pushed to the Pi, the exempt-device list (the devices that
//! skip ad blocking; also with labels, also pushed to the Pi, at most
//! [`MAX_EXEMPT`] long) and which alert instances already got a desktop
//! notification. A file from before the exempt list has none: it loads with
//! an empty one.
//!
//! The watcher and the CLI both write it, so every change goes through
//! [`update`], a read-modify-write under an exclusive lock on
//! `watchdog.lock` next to the file. A file that cannot be read or parsed is
//! never overwritten: [`update`] moves it aside first. Every function takes
//! the path, so tests use temporary directories and never the real state
//! directory.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::watchdog::{normalize_mac, valid_key};

/// At most this many entries in each of the three lists (the exempt list has
/// its own, smaller bound: [`MAX_EXEMPT`]).
pub const MAX_ENTRIES: usize = 1024;
/// At most this many addresses on the exempt list: the Pi takes the whole
/// list in one body of at most this many.
pub const MAX_EXEMPT: usize = 64;
/// Longest label, in characters.
pub const LABEL_MAX: usize = 64;

/// How long [`update`] waits for the lock before giving up.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// An alert (by key) that was acknowledged, and when (unix seconds).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Acked {
    pub key: String,
    pub at: u64,
}

/// A device on the known list: MAC in lower-case colon form.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Known {
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub first_seen: u64,
}

/// A device on the exempt list: the same shape as a known one.
pub type Exempt = Known;

/// An alert instance that already got a notification: its key, the
/// `first_unix` of that instance (a fresh instance after a Pi reboot has a
/// later one), and when the notification went out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Notified {
    pub key: String,
    pub first_unix: u64,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Store {
    pub version: u32,
    pub acked: Vec<Acked>,
    pub known: Vec<Known>,
    /// Bumped by every edit of the known list.
    pub known_gen: u64,
    /// The `known_gen` that was last pushed to the Pi successfully.
    pub pushed_known_gen: u64,
    pub notified: Vec<Notified>,
    /// `"<address>|<pin hex>"` of the Pi-hole that turned out to have no
    /// watchdog (a real Pi-hole): while the configured one is that one, a
    /// closed qnet makes no watchdog request at all. Cleared when a watchdog
    /// is seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub absent_for: Option<String>,
    /// The devices that skip ad blocking, at most [`MAX_EXEMPT`]. Pushed to
    /// the Pi like the known list; the Pi holds it in memory only.
    pub exempt: Vec<Exempt>,
    /// Bumped by every edit of the exempt list.
    pub exempt_gen: u64,
    /// The `exempt_gen` that was last pushed to the Pi successfully.
    pub pushed_exempt_gen: u64,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            acked: Vec::new(),
            known: Vec::new(),
            known_gen: 0,
            pushed_known_gen: 0,
            notified: Vec::new(),
            absent_for: None,
            exempt: Vec::new(),
            exempt_gen: 0,
            pushed_exempt_gen: 0,
        }
    }
}

/// A label with control characters removed, trimmed and cut to
/// [`LABEL_MAX`] characters; `None` when nothing is left.
pub fn clean_label(s: &str) -> Option<String> {
    let kept: String = s.chars().filter(|c| !c.is_control()).collect();
    let label: String = kept.trim().chars().take(LABEL_MAX).collect();
    let label = label.trim_end().to_string();
    (!label.is_empty()).then_some(label)
}

/// Drop the entry with the smallest `at` (the first of equals) until at most
/// [`MAX_ENTRIES`] are left.
fn trim_oldest<T>(list: &mut Vec<T>, at: impl Fn(&T) -> u64) {
    while list.len() > MAX_ENTRIES {
        let oldest = list
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| at(e))
            .map(|(i, _)| i)
            .unwrap_or(0);
        list.remove(oldest);
    }
}

/// Put `mac` on `list` (at most `cap` entries) or update its label: the rule
/// of [`Store::know`] and [`Store::add_exempt`]. True when the list changed.
fn upsert(
    list: &mut Vec<Known>,
    cap: usize,
    mac: &str,
    label: Option<&str>,
    first_seen: u64,
) -> bool {
    let Some(mac) = normalize_mac(mac) else {
        return false;
    };
    let label = label.and_then(clean_label);
    if let Some(entry) = list.iter_mut().find(|k| k.mac == mac) {
        match label {
            Some(l) if entry.label.as_deref() != Some(l.as_str()) => entry.label = Some(l),
            _ => return false,
        }
    } else {
        if list.len() >= cap {
            return false;
        }
        list.push(Known {
            mac,
            label,
            first_seen,
        });
    }
    true
}

impl Store {
    /// The store at `path`, for reading only: a missing or unreadable file is
    /// the default (empty) store. Never write what this returns back; changes
    /// go through [`update`], which keeps an unreadable file instead of
    /// replacing it.
    pub fn load(path: &Path) -> Store {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Write the store to `path`: the directory is made 0700, the file is
    /// replaced atomically with mode 0600. Prefer [`update`], which holds the
    /// lock.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            crate::util::ensure_private_dir(dir)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        crate::util::atomic_write(path, &bytes, 0o600)
    }

    // -- acknowledged alerts ---------------------------------------------------

    /// Record that the alert with `key` was acknowledged at `at`. A key that
    /// is not 16 lower-case hex digits, or is there already, changes nothing
    /// (false). At most [`MAX_ENTRIES`] are kept: the oldest `at` goes first.
    pub fn add_acked(&mut self, key: &str, at: u64) -> bool {
        if !valid_key(key) || self.acked.iter().any(|a| a.key == key) {
            return false;
        }
        self.acked.push(Acked {
            key: key.to_string(),
            at,
        });
        trim_oldest(&mut self.acked, |a| a.at);
        true
    }

    /// The acknowledged keys, in the order they were recorded.
    pub fn acked_keys(&self) -> Vec<String> {
        self.acked.iter().map(|a| a.key.clone()).collect()
    }

    // -- the known list --------------------------------------------------------

    fn bump_gen(&mut self) {
        self.known_gen = self.known_gen.wrapping_add(1);
    }

    /// Whether `mac` (any accepted spelling) is on the list.
    pub fn is_known(&self, mac: &str) -> bool {
        normalize_mac(mac).is_some_and(|m| self.known.iter().any(|k| k.mac == m))
    }

    /// Put `mac` on the list or update its label; true when the list
    /// changed. `label` is cleaned by [`clean_label`]; a label that is
    /// absent or empty after cleaning leaves an existing label as it is, and
    /// `first_seen` only counts for a new entry. `known_gen` goes up only when
    /// something changed. False with no change for a MAC that does not parse,
    /// for an entry that is there with the same label, and for a new entry
    /// when [`MAX_ENTRIES`] are on the list already (see [`is_known`](Self::is_known)
    /// to tell these apart).
    pub fn know(&mut self, mac: &str, label: Option<&str>, first_seen: u64) -> bool {
        if !upsert(&mut self.known, MAX_ENTRIES, mac, label, first_seen) {
            return false;
        }
        self.bump_gen();
        true
    }

    /// Take `mac` off the list; true (and `known_gen` up) when it was there.
    pub fn forget(&mut self, mac: &str) -> bool {
        let Some(mac) = normalize_mac(mac) else {
            return false;
        };
        let before = self.known.len();
        self.known.retain(|k| k.mac != mac);
        if self.known.len() == before {
            return false;
        }
        self.bump_gen();
        true
    }

    /// The known MACs, in list order.
    pub fn known_macs(&self) -> Vec<String> {
        self.known.iter().map(|k| k.mac.clone()).collect()
    }

    /// Whether the list changed since it was last pushed to the Pi.
    pub fn push_due(&self) -> bool {
        self.known_gen != self.pushed_known_gen
    }

    /// Record a successful push of generation `generation` (the `known_gen`
    /// that was read before the push, not the current one: the list may have
    /// been edited while the push was on the wire).
    pub fn mark_pushed(&mut self, generation: u64) {
        self.pushed_known_gen = generation;
    }

    // -- the exempt list -------------------------------------------------------

    /// Whether `mac` (any accepted spelling) is on the exempt list.
    pub fn is_exempt(&self, mac: &str) -> bool {
        normalize_mac(mac).is_some_and(|m| self.exempt.iter().any(|e| e.mac == m))
    }

    /// Whether the exempt list holds [`MAX_EXEMPT`] entries already.
    pub fn exempt_is_full(&self) -> bool {
        self.exempt.len() >= MAX_EXEMPT
    }

    /// Put `mac` on the exempt list or update its label, exactly as
    /// [`know`](Self::know) does for the known list (same label cleaning, same
    /// `first_seen` rule); `exempt_gen` goes up only when something changed.
    /// False with no change for a MAC that does not parse, for an entry that
    /// is there with the same label, and for a new entry when
    /// [`MAX_EXEMPT`] are on the list already (see
    /// [`is_exempt`](Self::is_exempt) and [`exempt_is_full`](Self::exempt_is_full)
    /// to tell these apart). The device is not put on the known list: that is
    /// a separate edit.
    pub fn add_exempt(&mut self, mac: &str, label: Option<&str>, first_seen: u64) -> bool {
        if !upsert(&mut self.exempt, MAX_EXEMPT, mac, label, first_seen) {
            return false;
        }
        self.exempt_gen = self.exempt_gen.wrapping_add(1);
        true
    }

    /// Take `mac` off the exempt list; true (and `exempt_gen` up) when it was
    /// there. The device stays on the known list.
    pub fn remove_exempt(&mut self, mac: &str) -> bool {
        let Some(mac) = normalize_mac(mac) else {
            return false;
        };
        let before = self.exempt.len();
        self.exempt.retain(|e| e.mac != mac);
        if self.exempt.len() == before {
            return false;
        }
        self.exempt_gen = self.exempt_gen.wrapping_add(1);
        true
    }

    /// The exempt MACs, in list order.
    pub fn exempt_macs(&self) -> Vec<String> {
        self.exempt.iter().map(|e| e.mac.clone()).collect()
    }

    /// Whether the exempt list changed since it was last pushed to the Pi.
    pub fn exempt_push_due(&self) -> bool {
        self.exempt_gen != self.pushed_exempt_gen
    }

    /// Record a successful push of exempt generation `generation` (the
    /// `exempt_gen` that was read before the push, as for
    /// [`mark_pushed`](Self::mark_pushed)).
    pub fn mark_exempt_pushed(&mut self, generation: u64) {
        self.pushed_exempt_gen = generation;
    }

    // -- notifications ---------------------------------------------------------

    /// Whether the alert instance (`key`, `first_unix`) still needs its
    /// notification: its key is not recorded, or the recorded instance is an
    /// earlier one.
    pub fn should_notify(&self, key: &str, first_unix: u64) -> bool {
        match self.notified.iter().find(|n| n.key == key) {
            None => true,
            Some(n) => n.first_unix < first_unix,
        }
    }

    /// Record the notification of the instance (`key`, `first_unix`) sent at
    /// `at`. A key that is there is updated (the recorded `first_unix` never
    /// goes backwards); at most [`MAX_ENTRIES`] are kept, the oldest `at`
    /// going first.
    pub fn mark_notified(&mut self, key: &str, first_unix: u64, at: u64) {
        match self.notified.iter_mut().find(|n| n.key == key) {
            Some(n) => {
                n.first_unix = n.first_unix.max(first_unix);
                n.at = at;
            }
            None => {
                self.notified.push(Notified {
                    key: key.to_string(),
                    first_unix,
                    at,
                });
                trim_oldest(&mut self.notified, |n| n.at);
            }
        }
    }
}

/// Take the lock on `<dir of path>/watchdog.lock`, waiting up to two seconds
/// (a blocking, queued `flock`: see [`crate::util::lock_wait`]).
fn lock_for(path: &Path) -> io::Result<crate::util::FileLock> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    crate::util::lock_wait(&dir.join("watchdog.lock"), LOCK_WAIT)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "the watchdog store is locked by another qnet",
        )
    })
}

/// Move a file that cannot be used to `<name>.bad-<unix secs>` beside it (a
/// `-2`, `-3`, … is added rather than replace an earlier one), mode 0600, and
/// return where it went. Only the path is reported: never what is inside.
fn set_aside(path: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "watchdog.json".to_string());
    let secs = crate::util::unix_secs();
    let mut target = path.with_file_name(format!("{name}.bad-{secs}"));
    let mut n = 1;
    while target.symlink_metadata().is_ok() {
        n += 1;
        target = path.with_file_name(format!("{name}.bad-{secs}-{n}"));
    }
    std::fs::rename(path, &target)?;
    // Best effort: the file was private already, unless somebody edited it.
    let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600));
    eprintln!(
        "qnet: the watchdog store could not be read; kept as {}",
        target.display()
    );
    Ok(target)
}

/// The store for a read-modify-write. No file is the default store; a file
/// that cannot be read or parsed is moved aside (so the user's known list
/// and acks are not lost to the next save) and the default store starts
/// afresh. If it cannot be moved aside the error is returned and nothing is
/// overwritten.
fn load_for_update(path: &Path) -> io::Result<Store> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(store) => Ok(store),
            Err(_) => set_aside(path).map(|_| Store::default()),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Store::default()),
        Err(_) => set_aside(path).map(|_| Store::default()),
    }
}

/// Read-modify-write the store at `path` under its lock: load it, run `f`,
/// write it back only when `f` changed it, release the lock. Fails with
/// `TimedOut` when the lock stays taken for two seconds, or with whatever the
/// write fails with. A file that is there but cannot be read or parsed is
/// renamed to `<name>.bad-<unix secs>` first and `f` sees an empty store; it
/// is never silently replaced.
pub fn update<R>(path: &Path, f: impl FnOnce(&mut Store) -> R) -> io::Result<R> {
    let _lock = lock_for(path)?;
    let mut store = load_for_update(path)?;
    let before = serde_json::to_vec(&store).map_err(io::Error::other)?;
    let result = f(&mut store);
    let after = serde_json::to_vec(&store).map_err(io::Error::other)?;
    if after != before {
        store.save(path)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    fn key(i: usize) -> String {
        format!("{i:016x}")
    }
    fn mac(i: usize) -> String {
        format!("02:00:00:00:{:02x}:{:02x}", (i >> 8) & 0xff, i & 0xff)
    }
    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_store_survives_a_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        let mut s = Store::default();
        assert_eq!(s.version, 1);
        s.add_acked(&key(1), 100);
        s.know(&mac(1), Some("Printer"), 50);
        s.know(&mac(2), None, 60);
        s.mark_notified(&key(1), 90, 100);
        s.mark_pushed(1);
        s.save(&p).unwrap();
        let back = Store::load(&p);
        assert_eq!(back, s);
        assert_eq!(back.known[0].label.as_deref(), Some("Printer"));
        assert_eq!(back.known[1].label, None);
        assert_eq!((back.known_gen, back.pushed_known_gen), (2, 1));
    }

    #[test]
    fn the_file_is_camel_case_json() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("watchdog.json");
        let mut s = Store::default();
        s.know(&mac(1), Some("x"), 5);
        s.mark_notified(&key(2), 7, 8);
        s.save(&p).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["knownGen"], 1);
        assert_eq!(v["pushedKnownGen"], 0);
        assert_eq!(v["known"][0]["firstSeen"], 5);
        assert_eq!(v["known"][0]["mac"], mac(1));
        assert_eq!(v["notified"][0]["firstUnix"], 7);
        assert!(v["acked"].as_array().unwrap().is_empty());
    }

    #[test]
    fn missing_or_garbage_files_load_as_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("watchdog.json");
        assert_eq!(Store::load(&p), Store::default());
        std::fs::write(&p, "{broken").unwrap();
        assert_eq!(Store::load(&p), Store::default());
        std::fs::write(&p, "[1,2,3]").unwrap();
        assert_eq!(Store::load(&p), Store::default());
        std::fs::write(&p, "").unwrap();
        assert_eq!(Store::load(&p), Store::default());
        // Missing fields fall back to their defaults, the rest is kept.
        std::fs::write(&p, r#"{"knownGen": 4}"#).unwrap();
        let s = Store::load(&p);
        assert_eq!((s.version, s.known_gen, s.acked.len()), (1, 4, 0));
    }

    #[test]
    fn save_makes_the_directory_private_and_the_file_0600() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        Store::default().save(&p).unwrap();
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(p.parent().unwrap()), 0o700);
        // Saving over an existing file keeps the mode.
        let mut s = Store::default();
        s.add_acked(&key(1), 1);
        s.save(&p).unwrap();
        assert_eq!(mode(&p), 0o600);
    }

    #[test]
    fn acks_are_deduplicated_validated_and_bounded_to_1024_newest() {
        let mut s = Store::default();
        assert!(s.add_acked(&key(1), 10));
        assert!(!s.add_acked(&key(1), 99), "already there");
        assert_eq!(s.acked.len(), 1);
        assert_eq!(s.acked[0].at, 10, "the first time is kept");
        assert!(!s.add_acked("NOT-A-KEY", 5));
        assert!(!s.add_acked("ABCDEF0123456789", 5));
        assert_eq!(s.acked.len(), 1);

        let mut s = Store::default();
        for i in 1..=1025 {
            s.add_acked(&key(i), i as u64);
        }
        assert_eq!(s.acked.len(), 1024);
        assert!(!s.acked_keys().contains(&key(1)), "the oldest went");
        assert!(s.acked_keys().contains(&key(2)));
        assert!(s.acked_keys().contains(&key(1025)));
    }

    #[test]
    fn the_oldest_ack_goes_by_time_not_by_position() {
        let mut s = Store::default();
        for i in 1..=1024 {
            // Recorded out of order: key 500 has the oldest time.
            s.add_acked(&key(i), if i == 500 { 1 } else { 1000 + i as u64 });
        }
        s.add_acked(&key(2000), 5000);
        assert_eq!(s.acked.len(), 1024);
        let keys = s.acked_keys();
        assert!(!keys.contains(&key(500)));
        assert!(keys.contains(&key(1)) && keys.contains(&key(2000)));
    }

    #[test]
    fn know_inserts_updates_labels_and_bumps_the_generation_only_on_change() {
        let mut s = Store::default();
        assert!(!s.push_due());
        assert!(s.know("02:00:00:00:00:AA", Some("  Printer\n"), 100));
        assert_eq!(s.known_gen, 1);
        assert!(s.push_due());
        assert_eq!(s.known[0].mac, "02:00:00:00:00:aa", "normalised");
        assert_eq!(s.known[0].label.as_deref(), Some("Printer"), "cleaned");
        assert_eq!(s.known[0].first_seen, 100);

        // The same entry again: nothing changes.
        assert!(!s.know("02-00-00-00-00-aa", Some("Printer"), 999));
        assert!(!s.know("02:00:00:00:00:aa", None, 999));
        assert!(!s.know("02:00:00:00:00:aa", Some("  "), 999));
        assert_eq!(s.known_gen, 1);
        assert_eq!(s.known[0].label.as_deref(), Some("Printer"));

        // A new label changes it, first_seen stays.
        assert!(s.know("02:00:00:00:00:aa", Some("Office printer"), 999));
        assert_eq!(s.known_gen, 2);
        assert_eq!(s.known[0].label.as_deref(), Some("Office printer"));
        assert_eq!(s.known[0].first_seen, 100);
        assert_eq!(s.known.len(), 1);

        // Bad MACs are refused.
        assert!(!s.know("nonsense", Some("x"), 1));
        assert!(!s.know("", None, 1));
        assert_eq!(s.known_gen, 2);
        assert!(s.is_known("02:00:00:00:00:AA"));
        assert!(!s.is_known("02:00:00:00:00:bb"));
    }

    #[test]
    fn forget_bumps_the_generation_only_when_it_removes_something() {
        let mut s = Store::default();
        s.know(&mac(1), None, 1);
        s.know(&mac(2), None, 1);
        assert_eq!(s.known_gen, 2);
        assert!(!s.forget(&mac(3)));
        assert!(!s.forget("junk"));
        assert_eq!(s.known_gen, 2);
        assert!(s.forget(&mac(1).to_uppercase()));
        assert_eq!(s.known_gen, 3);
        assert_eq!(s.known_macs(), [mac(2)]);
        assert!(!s.forget(&mac(1)), "already gone");
        assert_eq!(s.known_gen, 3);
    }

    #[test]
    fn the_known_list_holds_at_most_1024() {
        let mut s = Store::default();
        for i in 0..1024 {
            assert!(s.know(&mac(i), None, 1), "{i}");
        }
        let gen = s.known_gen;
        assert!(!s.know(&mac(5000), None, 1), "refused beyond 1024");
        assert_eq!(s.known.len(), 1024);
        assert_eq!(s.known_gen, gen, "a refusal changes nothing");
        // An existing entry can still be relabelled when the list is full.
        assert!(s.know(&mac(0), Some("still editable"), 1));
        assert!(s.forget(&mac(1)));
        assert!(s.know(&mac(5000), None, 1), "room again");
    }

    #[test]
    fn labels_are_cleaned() {
        assert_eq!(clean_label("  hello \t"), Some("hello".into()));
        assert_eq!(
            clean_label("a\u{0}b\nc\u{7f}d\u{85}e"),
            Some("abcde".into())
        );
        assert_eq!(clean_label(""), None);
        assert_eq!(clean_label("  \n\t "), None);
        assert_eq!(clean_label("\u{1b}\u{0}"), None);
        let long = clean_label(&"x".repeat(100)).unwrap();
        assert_eq!(long.chars().count(), 64);
        let wide = clean_label(&"é€".repeat(50)).unwrap();
        assert_eq!(wide.chars().count(), 64);
        // A cut that lands on a space does not leave it trailing.
        let spaced = format!("{} {}", "a".repeat(63), "b".repeat(10));
        assert_eq!(clean_label(&spaced), Some("a".repeat(63)));
    }

    #[test]
    fn push_due_follows_the_generations() {
        let mut s = Store::default();
        assert!(!s.push_due());
        s.know(&mac(1), None, 1);
        assert!(s.push_due());
        let pushed = s.known_gen;
        // An edit while the push is on the wire stays due.
        s.know(&mac(2), None, 1);
        s.mark_pushed(pushed);
        assert!(s.push_due());
        s.mark_pushed(s.known_gen);
        assert!(!s.push_due());
    }

    #[test]
    fn notifications_are_recorded_per_instance() {
        let mut s = Store::default();
        assert!(s.should_notify(&key(1), 100), "never seen");
        s.mark_notified(&key(1), 100, 5);
        assert!(!s.should_notify(&key(1), 100), "same instance");
        assert!(!s.should_notify(&key(1), 50), "an earlier one");
        assert!(
            s.should_notify(&key(1), 101),
            "a fresh instance after a reboot"
        );
        s.mark_notified(&key(1), 101, 6);
        assert!(!s.should_notify(&key(1), 101));
        assert_eq!(s.notified.len(), 1, "updated in place");
        assert_eq!((s.notified[0].first_unix, s.notified[0].at), (101, 6));
        // The recorded instance never goes backwards.
        s.mark_notified(&key(1), 90, 7);
        assert_eq!(s.notified[0].first_unix, 101);
        assert!(s.should_notify(&key(2), 0));
    }

    #[test]
    fn notified_is_bounded_to_1024_newest() {
        let mut s = Store::default();
        for i in 1..=1025 {
            s.mark_notified(&key(i), 1, i as u64);
        }
        assert_eq!(s.notified.len(), 1024);
        assert!(s.should_notify(&key(1), 1), "the oldest was dropped");
        assert!(!s.should_notify(&key(2), 1));
        assert!(!s.should_notify(&key(1025), 1));
    }

    #[test]
    fn update_loads_changes_and_saves() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        let n = update(&p, |s| {
            s.add_acked(&key(1), 1);
            s.acked.len()
        })
        .unwrap();
        assert_eq!(n, 1);
        update(&p, |s| s.add_acked(&key(2), 2)).unwrap();
        assert_eq!(Store::load(&p).acked_keys(), [key(1), key(2)]);
        assert_eq!(mode(&p), 0o600);
        assert_eq!(mode(p.parent().unwrap()), 0o700);
        assert!(p.parent().unwrap().join("watchdog.lock").exists());
    }

    #[test]
    fn update_writes_only_when_something_changed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        // No change, no file.
        update(&p, |s| s.acked.len()).unwrap();
        assert!(!p.exists());
        update(&p, |s| s.add_acked(&key(1), 1)).unwrap();
        // A hand-edited (differently formatted) file is not rewritten by a
        // no-op update.
        let text = std::fs::read_to_string(&p).unwrap();
        let squashed: String = serde_json::to_string(&Store::load(&p)).unwrap();
        std::fs::write(&p, &squashed).unwrap();
        update(&p, |s| s.known.len()).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), squashed);
        assert_ne!(text, squashed);
        // A failed add (duplicate) is not a change either.
        update(&p, |s| s.add_acked(&key(1), 99)).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), squashed);
    }

    /// The `.bad-*` files beside `p`, with their contents.
    fn bad_files(p: &Path) -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| {
                let e = e.unwrap();
                let name = e.file_name().to_string_lossy().into_owned();
                name.contains(".bad-")
                    .then(|| (name, std::fs::read(e.path()).unwrap()))
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn update_keeps_a_corrupt_file_aside_instead_of_replacing_it() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        // The labelled list the user would lose, damaged by a bad edit.
        let original = br#"{"version":1,"known":[{"mac":"02:00:00:00:00:01","label":"Printer"#;
        std::fs::write(&p, original).unwrap();

        let seen_empty = update(&p, |s| {
            let empty = *s == Store::default();
            s.add_acked(&key(7), 7);
            empty
        })
        .unwrap();
        assert!(seen_empty, "the change starts from an empty store");
        let s = Store::load(&p);
        assert_eq!(s.acked_keys(), [key(7)], "only the change");
        assert!(s.known.is_empty());
        assert_eq!(mode(&p), 0o600);

        let bad = bad_files(&p);
        assert_eq!(bad.len(), 1, "{bad:?}");
        assert!(bad[0].0.starts_with("watchdog.json.bad-"), "{}", bad[0].0);
        assert_eq!(bad[0].1, original, "the original bytes");
        assert_eq!(
            mode(&p.parent().unwrap().join(&bad[0].0)),
            0o600,
            "still private"
        );

        // A healthy file is not touched again.
        update(&p, |s| s.add_acked(&key(8), 8)).unwrap();
        assert_eq!(bad_files(&p).len(), 1);
        assert_eq!(Store::load(&p).acked.len(), 2);
    }

    #[test]
    fn a_file_of_the_wrong_shape_or_not_text_is_kept_aside_too() {
        for junk in [&b"[1,2,3]"[..], b"null", b"", b"\xff\xfe\x00 not utf-8"] {
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("watchdog.json");
            std::fs::write(&p, junk).unwrap();
            update(&p, |s| s.know(&mac(1), None, 5)).unwrap();
            let bad = bad_files(&p);
            assert_eq!(bad.len(), 1, "{junk:?}");
            assert_eq!(bad[0].1, junk);
            assert_eq!(Store::load(&p).known_macs(), [mac(1)]);
        }
    }

    #[test]
    fn an_unreadable_path_is_kept_aside_and_a_missing_one_is_just_new() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        // Missing: the default store, and no `.bad-*`.
        update(&p, |s| s.add_acked(&key(1), 1)).unwrap();
        assert!(bad_files(&p).is_empty());
        // A directory where the file should be: reading it fails with
        // something other than "not found".
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("inside"), "x").unwrap();
        update(&p, |s| s.add_acked(&key(2), 2)).unwrap();
        assert_eq!(Store::load(&p).acked_keys(), [key(2)]);
        let moved: Vec<_> = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".bad-"))
            .collect();
        assert_eq!(moved.len(), 1, "{moved:?}");
    }

    #[test]
    fn two_corruptions_in_the_same_second_do_not_overwrite_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("watchdog.json");
        for i in 0..3u8 {
            std::fs::write(&p, [b'{', i]).unwrap();
            update(&p, |s| s.add_acked(&key(i as usize + 1), 1)).unwrap();
        }
        let bad = bad_files(&p);
        assert_eq!(bad.len(), 3, "{bad:?}");
        let mut bodies: Vec<_> = bad.into_iter().map(|b| b.1).collect();
        bodies.sort();
        assert_eq!(bodies, [vec![b'{', 0], vec![b'{', 1], vec![b'{', 2]]);
    }

    #[test]
    fn the_absent_verdict_is_saved_only_when_set() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("watchdog.json");
        let mut s = Store::default();
        s.save(&p).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(v.get("absentFor").is_none());
        s.absent_for = Some("192.0.2.9|ab".into());
        s.save(&p).unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["absentFor"], "192.0.2.9|ab");
        assert_eq!(Store::load(&p), s);
        // An older file without the field reads as no verdict.
        std::fs::write(&p, r#"{"version":1,"knownGen":2}"#).unwrap();
        assert_eq!(Store::load(&p).absent_for, None);
    }

    // -- the exempt list -------------------------------------------------------

    #[test]
    fn the_exempt_list_survives_a_save_and_load_in_camel_case() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        let mut s = Store::default();
        assert!(s.add_exempt("02:00:00:00:00:AA", Some(" Smart TV "), 70));
        assert!(s.add_exempt(&mac(2), None, 80));
        s.mark_exempt_pushed(1);
        s.save(&p).unwrap();
        let back = Store::load(&p);
        assert_eq!(back, s);
        assert_eq!(back.exempt[0].mac, "02:00:00:00:00:aa");
        assert_eq!(back.exempt[0].label.as_deref(), Some("Smart TV"));
        assert_eq!(back.exempt[1].label, None);
        assert_eq!((back.exempt_gen, back.pushed_exempt_gen), (2, 1));
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["exempt"][0]["mac"], "02:00:00:00:00:aa");
        assert_eq!(v["exempt"][0]["firstSeen"], 70);
        assert_eq!(v["exempt"][1].get("label"), None, "no label, no key");
        assert_eq!(v["exemptGen"], 2);
        assert_eq!(v["pushedExemptGen"], 1);
        assert_eq!(v["knownGen"], 0, "the known list is not touched");
        assert!(v["known"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_file_from_before_the_exempt_list_loads_with_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("watchdog.json");
        let old = r#"{"version":1,"acked":[{"key":"0000000000000001","at":5}],
            "known":[{"mac":"02:00:00:00:00:01","label":"Printer","firstSeen":9}],
            "knownGen":3,"pushedKnownGen":3,"notified":[],"absentFor":"192.0.2.9|ab"}"#;
        std::fs::write(&p, old).unwrap();
        let s = Store::load(&p);
        assert!(s.exempt.is_empty());
        assert_eq!((s.exempt_gen, s.pushed_exempt_gen), (0, 0));
        assert!(!s.exempt_push_due());
        // Everything else is as it was.
        assert_eq!(s.known_macs(), [mac(1)]);
        assert_eq!((s.known_gen, s.pushed_known_gen), (3, 3));
        assert_eq!(s.acked_keys(), [key(1)]);
        assert_eq!(s.absent_for.as_deref(), Some("192.0.2.9|ab"));

        // A no-op update neither rewrites the file nor loses anything.
        update(&p, |s| s.exempt.len()).unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), old);
        // A change adds the exempt keys and keeps the old data.
        update(&p, |s| s.add_exempt(&mac(1), None, 1)).unwrap();
        let s = Store::load(&p);
        assert_eq!(s.exempt_macs(), [mac(1)]);
        assert_eq!(s.known[0].label.as_deref(), Some("Printer"));
        assert_eq!(s.absent_for.as_deref(), Some("192.0.2.9|ab"));
        assert!(bad_files(&p).is_empty(), "an old file is not corrupt");
    }

    #[test]
    fn add_exempt_inserts_updates_labels_and_bumps_the_generation_only_on_change() {
        let mut s = Store::default();
        assert!(!s.exempt_push_due());
        assert!(s.add_exempt("02:00:00:00:00:AA", Some("  TV\n"), 100));
        assert_eq!(s.exempt_gen, 1);
        assert!(s.exempt_push_due());
        assert_eq!(s.exempt[0].mac, "02:00:00:00:00:aa", "normalised");
        assert_eq!(s.exempt[0].label.as_deref(), Some("TV"), "cleaned");
        assert_eq!(s.exempt[0].first_seen, 100);

        // The same entry again: nothing changes.
        assert!(!s.add_exempt("02-00-00-00-00-aa", Some("TV"), 999));
        assert!(!s.add_exempt("02:00:00:00:00:aa", None, 999));
        assert!(!s.add_exempt("02:00:00:00:00:aa", Some("  "), 999));
        assert_eq!(s.exempt_gen, 1);

        // A new label changes it, first_seen stays.
        assert!(s.add_exempt("02:00:00:00:00:aa", Some("Living room TV"), 999));
        assert_eq!(s.exempt_gen, 2);
        assert_eq!(s.exempt[0].label.as_deref(), Some("Living room TV"));
        assert_eq!(s.exempt[0].first_seen, 100);
        assert_eq!(s.exempt.len(), 1);

        // Bad MACs are refused.
        assert!(!s.add_exempt("nonsense", Some("x"), 1));
        assert!(!s.add_exempt("", None, 1));
        assert_eq!(s.exempt_gen, 2);
        assert!(s.is_exempt("02:00:00:00:00:AA"));
        assert!(!s.is_exempt("02:00:00:00:00:bb"));
        assert!(!s.is_exempt("junk"));
    }

    #[test]
    fn the_exempt_and_known_lists_do_not_touch_each_other() {
        let mut s = Store::default();
        s.know(&mac(1), None, 1);
        s.add_exempt(&mac(2), None, 1);
        assert_eq!((s.known_gen, s.exempt_gen), (1, 1));
        assert_eq!(s.known_macs(), [mac(1)]);
        assert_eq!(s.exempt_macs(), [mac(2)]);
        assert!(!s.is_known(&mac(2)) && !s.is_exempt(&mac(1)));
        // Forgetting a device leaves the exempt list alone, and removing it
        // from the exempt list leaves it known.
        s.add_exempt(&mac(1), None, 1);
        assert!(s.forget(&mac(1)));
        assert!(s.is_exempt(&mac(1)));
        s.know(&mac(2), None, 1);
        assert!(s.remove_exempt(&mac(2)));
        assert!(s.is_known(&mac(2)));
        // Each list has its own pushed generation.
        let (k, e) = (s.known_gen, s.exempt_gen);
        s.mark_pushed(k);
        assert!(!s.push_due() && s.exempt_push_due());
        s.mark_exempt_pushed(e);
        assert!(!s.exempt_push_due());
    }

    #[test]
    fn remove_exempt_bumps_the_generation_only_when_it_removes_something() {
        let mut s = Store::default();
        s.add_exempt(&mac(1), None, 1);
        s.add_exempt(&mac(2), None, 1);
        assert_eq!(s.exempt_gen, 2);
        assert!(!s.remove_exempt(&mac(3)));
        assert!(!s.remove_exempt("junk"));
        assert_eq!(s.exempt_gen, 2);
        assert!(s.remove_exempt(&mac(1).to_uppercase()));
        assert_eq!(s.exempt_gen, 3);
        assert_eq!(s.exempt_macs(), [mac(2)]);
        assert!(!s.remove_exempt(&mac(1)), "already gone");
        assert_eq!(s.exempt_gen, 3);
    }

    #[test]
    fn the_exempt_list_holds_at_most_64() {
        assert_eq!(MAX_EXEMPT, 64);
        let mut s = Store::default();
        for i in 0..MAX_EXEMPT {
            assert!(!s.exempt_is_full(), "{i}");
            assert!(s.add_exempt(&mac(i), None, 1), "{i}");
        }
        assert!(s.exempt_is_full());
        let gen = s.exempt_gen;
        assert!(!s.add_exempt(&mac(5000), None, 1), "refused beyond 64");
        assert_eq!(s.exempt.len(), 64);
        assert_eq!(s.exempt_gen, gen, "a refusal changes nothing");
        // An existing entry can still be relabelled when the list is full.
        assert!(s.add_exempt(&mac(0), Some("still editable"), 1));
        assert!(s.remove_exempt(&mac(1)));
        assert!(!s.exempt_is_full());
        assert!(s.add_exempt(&mac(5000), None, 1), "room again");
    }

    #[test]
    fn exempt_push_due_follows_the_generations() {
        let mut s = Store::default();
        assert!(!s.exempt_push_due());
        s.add_exempt(&mac(1), None, 1);
        assert!(s.exempt_push_due());
        let pushed = s.exempt_gen;
        // An edit while the push is on the wire stays due.
        s.add_exempt(&mac(2), None, 1);
        s.mark_exempt_pushed(pushed);
        assert!(s.exempt_push_due());
        s.mark_exempt_pushed(s.exempt_gen);
        assert!(!s.exempt_push_due());
    }

    #[test]
    fn update_serialises_concurrent_writers() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        std::thread::scope(|scope| {
            for t in 0..2usize {
                let p = p.clone();
                scope.spawn(move || {
                    for i in 0..50usize {
                        let k = key(t * 1000 + i + 1);
                        update(&p, |s| s.add_acked(&k, (t * 1000 + i) as u64)).unwrap();
                    }
                });
            }
        });
        let s = Store::load(&p);
        assert_eq!(s.acked.len(), 100, "no update was lost");
        let mut keys = s.acked_keys();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 100);
    }

    #[test]
    fn update_gives_up_when_the_lock_stays_taken() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        let lock_path = p.parent().unwrap().join("watchdog.lock");
        let held = crate::util::try_lock(&lock_path).unwrap().expect("free");
        let t0 = Instant::now();
        let err = update(&p, |s| s.add_acked(&key(1), 1)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let waited = t0.elapsed();
        assert!(
            waited >= Duration::from_millis(1800) && waited < Duration::from_secs(5),
            "{waited:?}"
        );
        assert!(!p.exists(), "nothing was written");
        // Released: it works again.
        drop(held);
        update(&p, |s| s.add_acked(&key(1), 1)).unwrap();
        assert_eq!(Store::load(&p).acked.len(), 1);
    }

    #[test]
    fn update_waits_for_a_lock_that_is_released_in_time() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("watchdog.json");
        let lock_path = p.parent().unwrap().join("watchdog.lock");
        let held = crate::util::try_lock(&lock_path).unwrap().expect("free");
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(held);
        });
        update(&p, |s| s.add_acked(&key(1), 1)).unwrap();
        releaser.join().unwrap();
        assert_eq!(Store::load(&p).acked.len(), 1);
    }
}

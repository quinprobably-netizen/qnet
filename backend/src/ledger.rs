//! A tally of the queries qnet itself sends to the Pi-hole (canary, upstream
//! check, retries), so they can be subtracted from "today's" numbers. The
//! Pi-hole keeps a rolling 24 hours; the tally keeps 10-minute buckets for
//! the same window and survives restarts.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub const BUCKET_S: i64 = 600;
pub const WINDOW_S: i64 = 24 * 3600;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Ledger {
    /// (bucket start, queries sent, of which blocked)
    buckets: Vec<(i64, u32, u32)>,
    #[serde(skip)]
    dirty: bool,
}

impl Ledger {
    pub fn add(&mut self, now_unix: f64, total: u32, blocked: u32) {
        if total == 0 {
            return;
        }
        let start = (now_unix as i64).div_euclid(BUCKET_S) * BUCKET_S;
        match self.buckets.last_mut() {
            Some(b) if b.0 == start => {
                b.1 += total;
                b.2 += blocked;
            }
            _ => self.buckets.push((start, total, blocked)),
        }
        self.dirty = true;
        self.prune(now_unix);
    }

    /// Drop buckets that have left the window.
    pub fn prune(&mut self, now_unix: f64) {
        let cutoff = now_unix as i64 - WINDOW_S - BUCKET_S;
        let before = self.buckets.len();
        self.buckets.retain(|b| b.0 >= cutoff);
        if self.buckets.len() != before {
            self.dirty = true;
        }
    }

    /// (total, blocked) sent within the last 24 hours.
    pub fn sums(&self, now_unix: f64) -> (u64, u64) {
        let cutoff = now_unix as i64 - WINDOW_S;
        self.buckets
            .iter()
            // A bucket counts while any of it is inside the window.
            .filter(|b| b.0 + BUCKET_S > cutoff)
            .fold((0, 0), |(t, bl), b| (t + u64::from(b.1), bl + u64::from(b.2)))
    }

    /// (total, blocked) sent in the bucket that starts at `bucket_start`.
    pub fn bucket(&self, bucket_start: i64) -> (u64, u64) {
        self.buckets
            .iter()
            .filter(|b| b.0 == bucket_start)
            .fold((0, 0), |(t, bl), b| (t + u64::from(b.1), bl + u64::from(b.2)))
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        crate::util::atomic_write(path, &bytes, 0o600)?;
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_in_ten_minute_buckets() {
        let mut l = Ledger::default();
        l.add(1_000_000.0, 2, 2);
        l.add(1_000_100.0, 1, 0);
        l.add(1_000_700.0, 3, 3);
        assert_eq!(l.buckets.len(), 2);
        assert_eq!(l.sums(1_000_800.0), (6, 5));
    }

    #[test]
    fn old_queries_age_out_of_the_window() {
        let mut l = Ledger::default();
        l.add(1_000_000.0, 10, 8);
        l.add(1_000_000.0 + 3600.0, 4, 1);
        assert_eq!(l.sums(1_000_000.0 + 3700.0), (14, 9));
        // 24 h and one bucket later the first batch is gone, the second stays.
        let later = 1_000_000.0 + 86_400.0 + 700.0;
        assert_eq!(l.sums(later), (4, 1));
        l.prune(later + 4000.0);
        assert_eq!(l.sums(later + 4000.0), (0, 0));
    }

    #[test]
    fn per_bucket_lookup() {
        let mut l = Ledger::default();
        l.add(1_000_100.0, 2, 1);
        l.add(1_000_700.0, 5, 5);
        let start = |t: i64| t.div_euclid(BUCKET_S) * BUCKET_S;
        assert_eq!(l.bucket(start(1_000_100)), (2, 1));
        assert_eq!(l.bucket(start(1_000_700)), (5, 5));
        assert_eq!(l.bucket(start(2_000_000)), (0, 0));
    }

    #[test]
    fn zero_adds_are_ignored_and_dirty_tracks_changes() {
        let mut l = Ledger::default();
        l.add(5.0, 0, 0);
        assert!(!l.is_dirty());
        l.add(5.0, 1, 1);
        assert!(l.is_dirty());
    }

    #[test]
    fn survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("qnet").join("self-queries.json");
        let mut l = Ledger::default();
        l.add(2_000_000.0, 7, 5);
        l.save(&p).unwrap();
        assert!(!l.is_dirty());
        let back = Ledger::load(&p);
        assert_eq!(back.sums(2_000_100.0), (7, 5));
        // Missing or corrupt files start empty rather than failing.
        assert_eq!(Ledger::load(&dir.path().join("nope")).sums(1.0), (0, 0));
        std::fs::write(&p, "{broken").unwrap();
        assert_eq!(Ledger::load(&p).sums(1.0), (0, 0));
    }
}

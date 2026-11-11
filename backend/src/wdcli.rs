//! The `qnet watchdog …` verbs: look at the Pi's alerts and devices, acknowledge
//! an alert, and edit the known-device list of this PC (which is then pushed
//! to the Pi).
//!
//! Each verb is a function of the API client, the path of the PC-side store
//! and the time (unix seconds), so tests run against the fake Pi and a
//! temporary store; `main` only parses, builds the client and prints the
//! result. An alert is told apart by its id, a device by its MAC address.
//!
//! The known list is edited on this PC first and pushed second: when the push
//! fails, or the Pi has no watchdog, the edit stays and the watcher pushes it
//! later (the store's `knownGen` says it is due).

use std::collections::HashSet;
use std::path::Path;

use serde_json::{json, Value};

use crate::actions::{ActionErr, ActionResult};
use crate::pihole::Pihole;
use crate::state::{WatchdogAlertOut, WatchdogDeviceOut};
use crate::watchdog::{self, normalize_mac, Inventory, Qbp};
use crate::wdstore::{self, clean_label, Store};

const USAGE: &str = "usage: qnet watchdog alerts | devices | know-all | ack <id> | \
know <mac> [label...] | forget <mac>";

/// One `qnet watchdog` verb, validated.
#[derive(Debug, PartialEq, Eq)]
pub enum WdCmd {
    Alerts,
    /// The id the Pi gave the alert (digits, fits a `u64`).
    Ack {
        id: u64,
    },
    Devices,
    /// `mac` in lower-case colon form, `label` already cleaned (at most 64
    /// characters; longer is cut, not refused).
    Know {
        mac: String,
        label: Option<String>,
    },
    Forget {
        mac: String,
    },
    KnowAll,
}

fn usage() -> ActionErr {
    ActionErr::new("usage", USAGE)
}

/// 1 to 20 ASCII digits that fit a `u64` (no sign, no spaces).
fn parse_id(s: &str) -> Option<u64> {
    if !(1..=20).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn parse_mac(s: &str) -> Result<String, ActionErr> {
    normalize_mac(s).ok_or_else(|| {
        ActionErr::new(
            "invalid",
            "not a hardware address (six hex pairs, like 02:00:00:00:00:01)",
        )
    })
}

/// Parse what follows `watchdog` on the command line. The words are taken as
/// typed (a label may hold anything, even words that look like flags); bad
/// shapes are `usage`, a bad id or MAC is `invalid`.
pub fn parse(args: &[String]) -> Result<WdCmd, ActionErr> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["alerts"] => Ok(WdCmd::Alerts),
        ["devices"] => Ok(WdCmd::Devices),
        ["know-all"] => Ok(WdCmd::KnowAll),
        ["ack", id] => parse_id(id).map(|id| WdCmd::Ack { id }).ok_or_else(|| {
            ActionErr::new(
                "invalid",
                "an alert id is a whole number (see `watchdog alerts`)",
            )
        }),
        ["forget", mac] => Ok(WdCmd::Forget {
            mac: parse_mac(mac)?,
        }),
        ["know", mac, label @ ..] => Ok(WdCmd::Know {
            mac: parse_mac(mac)?,
            label: clean_label(&label.join(" ")),
        }),
        _ => Err(usage()),
    }
}

/// Run one verb.
pub fn run(api: &mut Pihole, store_path: &Path, now: u64, cmd: &WdCmd) -> ActionResult {
    match cmd {
        WdCmd::Alerts => alerts(api),
        WdCmd::Ack { id } => ack(api, store_path, now, *id),
        WdCmd::Devices => devices(api, store_path),
        WdCmd::Know { mac, label } => know(api, store_path, now, mac, label.as_deref()),
        WdCmd::Forget { mac } => forget(api, store_path, mac),
        WdCmd::KnowAll => know_all(api, store_path, now),
    }
}

// -- helpers ------------------------------------------------------------------

fn absent() -> ActionErr {
    ActionErr::new("absent", "the Pi-hole has no watchdog")
}

fn store_err(e: std::io::Error) -> ActionErr {
    ActionErr::new("store", format!("could not save the known list: {e}"))
}

/// How pushing the PC list to the Pi ended.
enum Pushed {
    Sent,
    /// Not tried: nothing was due.
    Skipped,
    /// Tried; the Pi has no watchdog (`"absent"`) or the call failed (the
    /// message). The edit on this PC stays.
    Failed(String),
}

impl Pushed {
    fn add_to(self, out: &mut Value) {
        match self {
            Pushed::Sent => out["pushed"] = json!(true),
            Pushed::Skipped => out["pushed"] = json!(false),
            Pushed::Failed(why) => {
                out["pushed"] = json!(false);
                out["pushError"] = json!(why);
            }
        }
    }
}

/// The PC list as it was after an edit: what to push, and which generation
/// that was (the one to record when the push succeeds, even if the list is
/// edited again while it is on the wire).
struct Snapshot {
    generation: u64,
    macs: Vec<String>,
}

impl Snapshot {
    fn of(s: &Store) -> Self {
        Self {
            generation: s.known_gen,
            macs: s.known_macs(),
        }
    }
}

/// Push the PC list to the Pi and record the push. An empty list is pushed as
/// it is: these verbs are explicit edits (see the store's `push_due`).
fn push(api: &mut Pihole, store_path: &Path, snap: &Snapshot) -> Pushed {
    match watchdog::put_known(api, &snap.macs) {
        Ok(Qbp::Present(_)) => {
            // If this cannot be recorded the list stays due and the watcher
            // pushes it once more: harmless.
            let _ = wdstore::update(store_path, |s| s.mark_pushed(snap.generation));
            Pushed::Sent
        }
        Ok(Qbp::Absent) => Pushed::Failed("absent".to_string()),
        Err(e) => Pushed::Failed(e.message().to_string()),
    }
}

// -- alerts -------------------------------------------------------------------

/// `watchdog alerts`: every alert the Pi holds, newest change first, in the
/// shape of the state JSON's `watchdog.alerts`.
pub fn alerts(api: &mut Pihole) -> ActionResult {
    let page = match watchdog::get_alerts(api, 0)? {
        Qbp::Absent => return Err(absent()),
        Qbp::Present(p) => p,
    };
    let mut list = page.alerts;
    list.sort_by(|a, b| b.rev.cmp(&a.rev).then(b.id.cmp(&a.id)));
    let alerts: Vec<WatchdogAlertOut> = list.iter().map(WatchdogAlertOut::from_alert).collect();
    Ok(json!({
        "ok": true,
        "rev": page.rev,
        "suppressed": page.suppressed,
        "alerts": alerts,
    }))
}

/// `watchdog ack <id>`: find the alert for its key, acknowledge it on the Pi,
/// and remember the key here (so the Pi gets it again after a reboot). When
/// the Pi accepted it but this PC could not record it, the answer is still
/// `ok` with `"saved": false`.
pub fn ack(api: &mut Pihole, store_path: &Path, now: u64, id: u64) -> ActionResult {
    let not_found = || ActionErr::new("not-found", "the Pi has no alert with that id");
    let page = match watchdog::get_alerts(api, 0)? {
        Qbp::Absent => return Err(absent()),
        Qbp::Present(p) => p,
    };
    let key = page
        .alerts
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.key.clone())
        .ok_or_else(not_found)?;
    // The watchdog was there a moment ago, so a 404 now means the alert is
    // gone (the Pi restarted, or it was dropped).
    if watchdog::ack(api, id)? == Qbp::Absent {
        return Err(not_found());
    }
    let saved = wdstore::update(store_path, |s| s.add_acked(&key, now)).is_ok();
    Ok(json!({ "ok": true, "id": id, "key": key, "saved": saved }))
}

// -- devices ------------------------------------------------------------------

/// `watchdog devices`: the Pi's inventory, last seen first, with what this PC
/// knows about each device, and the PC's known devices the Pi did not report.
pub fn devices(api: &mut Pihole, store_path: &Path) -> ActionResult {
    let inv = match watchdog::get_devices(api)? {
        Qbp::Absent => return Err(absent()),
        Qbp::Present(i) => i,
    };
    let store = Store::load(store_path);
    let reported: HashSet<&str> = inv.devices.iter().map(|d| d.mac.as_str()).collect();
    let offline: Vec<Value> = store
        .known
        .iter()
        .filter(|k| !reported.contains(k.mac.as_str()))
        .map(|k| {
            json!({
                "mac": k.mac,
                "label": k.label.as_deref().unwrap_or(""),
                "firstSeen": k.first_seen,
            })
        })
        .collect();
    let mut list = inv.devices.clone();
    list.sort_by_key(|d| std::cmp::Reverse(d.last_unix));
    let devices: Vec<WatchdogDeviceOut> = watchdog::annotate(list, &store)
        .iter()
        .map(WatchdogDeviceOut::from_report_device)
        .collect();
    Ok(json!({
        "ok": true,
        "knownList": inv.known_list,
        "devices": devices,
        "knownOffline": offline,
    }))
}

// -- the known list -----------------------------------------------------------

/// Seed an empty PC list with what the Pi already treats as known, so the
/// first edit does not replace a list the Pi made itself: it raises a
/// `new_device` alert for every device it has seen that is not on the list it
/// is given. Only when this PC has no list (and no unpushed edit that
/// emptied it on purpose) and the Pi has one (`learned` on its own or
/// `received` from somewhere); a `waiting` Pi has none to lose. The entries
/// have no label and the time the Pi first saw the device. Returns how many
/// were added.
fn seed_from_pi(s: &mut Store, inv: &Inventory, now: u64) -> u64 {
    if !s.known.is_empty()
        || s.push_due()
        || !matches!(inv.known_list.as_str(), "learned" | "received")
    {
        return 0;
    }
    let mut seeded = 0;
    for d in inv.devices.iter().filter(|d| d.known) {
        let first_seen = if d.first_unix > 0 { d.first_unix } else { now };
        if s.know(&d.mac, None, first_seen) {
            seeded += 1;
        }
    }
    seeded
}

/// `watchdog know <mac> [label]`: put the device on this PC's list (or change
/// its label; without a label an existing one stays), then push the list.
/// `first_seen` of a new entry is when the Pi first saw the device, or `now`
/// when it does not say (or cannot be asked). If this PC has no list yet but
/// the Pi has one (see [`seed_from_pi`]), the Pi's known devices are put on
/// the list first, so the push adds one device to that list instead of
/// replacing it; `seeded` in the answer says how many.
pub fn know(
    api: &mut Pihole,
    store_path: &Path,
    now: u64,
    mac: &str,
    label: Option<&str>,
) -> ActionResult {
    let mac =
        normalize_mac(mac).ok_or_else(|| ActionErr::new("invalid", "not a hardware address"))?;
    let inv = match watchdog::get_devices(api) {
        Ok(Qbp::Present(inv)) => Some(inv),
        _ => None,
    };
    let first_seen = inv
        .as_ref()
        .and_then(|inv| inv.devices.iter().find(|d| d.mac == mac))
        .map(|d| d.first_unix)
        .filter(|&t| t > 0)
        .unwrap_or(now);
    let edit = wdstore::update(store_path, |s| {
        let seeded = inv.as_ref().map_or(0, |inv| seed_from_pi(s, inv, now));
        let was_known = s.is_known(&mac);
        let changed = s.know(&mac, label, first_seen);
        if !changed && !was_known {
            return None;
        }
        let label = s
            .known
            .iter()
            .find(|k| k.mac == mac)
            .and_then(|k| k.label.clone());
        Some((Snapshot::of(s), label, seeded))
    })
    .map_err(store_err)?;
    let Some((snap, label, seeded)) = edit else {
        return Err(ActionErr::new(
            "full",
            format!(
                "the known list holds {} devices already",
                wdstore::MAX_ENTRIES
            ),
        ));
    };
    let mut out = json!({ "ok": true, "mac": mac, "known": snap.macs.len() });
    if let Some(l) = label {
        out["label"] = json!(l);
    }
    if seeded > 0 {
        out["seeded"] = json!(seeded);
    }
    push(api, store_path, &snap).add_to(&mut out);
    Ok(out)
}

/// `watchdog forget <mac>`: take the device off this PC's list, then push the
/// list (an emptied list is pushed too: this is an explicit edit).
pub fn forget(api: &mut Pihole, store_path: &Path, mac: &str) -> ActionResult {
    let mac =
        normalize_mac(mac).ok_or_else(|| ActionErr::new("invalid", "not a hardware address"))?;
    let snap = wdstore::update(store_path, |s| s.forget(&mac).then(|| Snapshot::of(s)))
        .map_err(store_err)?
        .ok_or_else(|| ActionErr::new("not-found", "that device is not on the known list"))?;
    let mut out = json!({ "ok": true, "mac": mac, "known": snap.macs.len() });
    push(api, store_path, &snap).add_to(&mut out);
    Ok(out)
}

/// `watchdog know-all`: put every device the Pi reports on this PC's list in
/// one edit (existing entries and their labels are not touched), then push.
/// Nothing is pushed when nothing was added and no earlier edit is waiting to
/// go. Devices that do not fit on a full list are counted in `skipped`.
pub fn know_all(api: &mut Pihole, store_path: &Path, now: u64) -> ActionResult {
    let inv = match watchdog::get_devices(api)? {
        Qbp::Absent => return Err(absent()),
        Qbp::Present(i) => i,
    };
    let (added, skipped, due, snap) = wdstore::update(store_path, |s| {
        let (mut added, mut skipped) = (0u64, 0u64);
        for d in &inv.devices {
            if s.is_known(&d.mac) {
                continue;
            }
            let first_seen = if d.first_unix > 0 { d.first_unix } else { now };
            if s.know(&d.mac, None, first_seen) {
                added += 1;
            } else {
                skipped += 1;
            }
        }
        (added, skipped, s.push_due(), Snapshot::of(s))
    })
    .map_err(store_err)?;
    let mut out = json!({ "ok": true, "added": added, "known": snap.macs.len() });
    if skipped > 0 {
        out["skipped"] = json!(skipped);
    }
    let pushed = if added == 0 && !due {
        Pushed::Skipped
    } else {
        push(api, store_path, &snap)
    };
    pushed.add_to(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakeqbp::{key, mac, FakePi, T0};
    use crate::https::testutil::{ok_json, serve};
    use crate::pihole::ApiError;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    // Test data uses documentation addresses (192.0.2.x) and locally
    // administered MACs (02:00:00:…) only.

    /// A fake Pi, a client for it and a temporary store.
    struct Rig {
        pi: FakePi,
        api: Pihole,
        dir: tempfile::TempDir,
    }

    impl Rig {
        fn new() -> Self {
            Self::on(FakePi::start(20))
        }
        fn on(pi: FakePi) -> Self {
            let api = pi.client();
            Self {
                pi,
                api,
                dir: tempfile::tempdir().unwrap(),
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
        fn known_puts(&self) -> Vec<Value> {
            self.pi.with(|s| s.known_puts.clone())
        }
        fn pi_known(&self) -> Vec<String> {
            self.pi.with(|s| s.known.clone())
        }
        fn know(&mut self, mac: &str, label: Option<&str>) -> ActionResult {
            let path = self.path();
            know(&mut self.api, &path, T0 + 999, mac, label)
        }
        fn forget(&mut self, mac: &str) -> ActionResult {
            let path = self.path();
            forget(&mut self.api, &path, mac)
        }
        fn know_all(&mut self) -> ActionResult {
            let path = self.path();
            know_all(&mut self.api, &path, T0 + 999)
        }
        fn ack(&mut self, id: u64) -> ActionResult {
            let path = self.path();
            ack(&mut self.api, &path, T0 + 500, id)
        }
        fn devices(&mut self) -> ActionResult {
            let path = self.path();
            devices(&mut self.api, &path)
        }
    }

    /// A store path that cannot be written: its parent is a regular file.
    fn unwritable(dir: &Path) -> PathBuf {
        let blocker = dir.join("blocker");
        std::fs::write(&blocker, "x").unwrap();
        blocker.join("watchdog.json")
    }

    fn err(r: ActionResult) -> ActionErr {
        r.unwrap_err()
    }

    /// The Pi reports devices `1..=n`.
    fn pi_devices(rig: &Rig, n: usize) {
        rig.pi.with(|s| {
            s.devices = (1..=n)
                .map(|i| (mac(i), format!("192.0.2.{}", i % 250 + 1)))
                .collect()
        });
    }

    // -- alerts ---------------------------------------------------------------

    #[test]
    fn alerts_lists_every_alert_newest_change_first_in_the_state_shape() {
        let mut rig = Rig::new();
        rig.pi.raise("new_device", "02:00:00:00:00:07", None, 1);
        rig.pi.raise("arp_spoof", "192.0.2.1", Some("192.0.2.9"), 2);
        rig.pi.raise("dga", "x.example", Some("192.0.2.5"), 3);
        rig.pi.repeat(1);
        rig.pi.ack(2);
        let v = alerts(&mut rig.api).unwrap();
        assert_eq!(
            v,
            json!({
                "ok": true, "rev": 5, "suppressed": 0,
                "alerts": [
                    { "id": 2, "key": key(2), "kind": "arp_spoof", "severity": "warn",
                      "title": "Router impersonation (ARP spoofing)",
                      "client": "192.0.2.9", "subject": "192.0.2.1",
                      "firstUnix": T0 + 20, "lastUnix": T0 + 20, "count": 1, "acked": true },
                    { "id": 1, "key": key(1), "kind": "new_device", "severity": "warn",
                      "title": "New device on the network",
                      "client": null, "subject": "02:00:00:00:00:07",
                      "firstUnix": T0 + 10, "lastUnix": T0 + 40, "count": 2, "acked": false },
                    { "id": 3, "key": key(3), "kind": "dga", "severity": "warn",
                      "title": "Suspicious lookups (DGA)",
                      "client": "192.0.2.5", "subject": "x.example",
                      "firstUnix": T0 + 30, "lastUnix": T0 + 30, "count": 1, "acked": false },
                ]
            })
        );
        assert_eq!(rig.pi.with(|s| s.since.clone()), vec![0], "all of them");
    }

    #[test]
    fn alerts_of_a_quiet_pi_is_an_empty_list() {
        let mut rig = Rig::new();
        let v = alerts(&mut rig.api).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "rev": 0, "suppressed": 0, "alerts": []})
        );
    }

    #[test]
    fn a_real_pihole_has_no_watchdog_for_any_verb() {
        let mut rig = Rig::on(FakePi::pihole_only(20));
        let want = ActionErr::new("absent", "the Pi-hole has no watchdog");
        assert_eq!(err(alerts(&mut rig.api)), want);
        assert_eq!(err(rig.ack(1)), want);
        assert_eq!(err(rig.devices()), want);
        assert_eq!(err(rig.know_all()), want);
        assert_eq!(
            want.to_json(),
            json!({"ok": false, "error": "absent", "detail": "the Pi-hole has no watchdog"})
        );
        assert_eq!(rig.pi.count("POST /api/qbp"), 0);
        assert_eq!(rig.pi.count("PUT /api/qbp"), 0);
        assert!(!rig.path().exists(), "nothing was written");
    }

    // -- ack ------------------------------------------------------------------

    #[test]
    fn ack_acknowledges_on_the_pi_and_remembers_the_key() {
        let mut rig = Rig::new();
        rig.pi.raise("new_device", "02:00:00:00:00:07", None, 1);
        rig.pi.raise("dga", "x.example", Some("192.0.2.5"), 2);
        let v = rig.ack(2).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "id": 2, "key": key(2), "saved": true})
        );
        assert_eq!(rig.pi.count("POST /api/qbp/alerts/2/ack"), 1);
        assert_eq!(rig.pi.count("POST /api/qbp/alerts/1/ack"), 0);
        let acked = rig
            .pi
            .with(|s| s.alerts.iter().map(|a| (a.id, a.acked)).collect::<Vec<_>>());
        assert_eq!(acked, vec![(1, false), (2, true)]);
        let store = rig.store();
        assert_eq!(store.acked_keys(), vec![key(2)]);
        assert_eq!(store.acked[0].at, T0 + 500);
    }

    #[test]
    fn ack_of_an_unknown_id_is_not_found_and_posts_nothing() {
        let mut rig = Rig::new();
        rig.pi.raise("new_device", "02:00:00:00:00:07", None, 1);
        let e = err(rig.ack(99));
        assert_eq!(e.code, "not-found");
        assert_eq!(
            e.to_json(),
            json!({"ok": false, "error": "not-found", "detail": "the Pi has no alert with that id"})
        );
        assert_eq!(rig.pi.count("POST /api/qbp/alerts"), 0);
        assert!(!rig.path().exists());
        // The same on a Pi with no alerts at all.
        let mut quiet = Rig::new();
        assert_eq!(err(quiet.ack(1)).code, "not-found");
        assert_eq!(quiet.pi.count("POST /api/qbp/alerts"), 0);
    }

    #[test]
    fn ack_on_a_real_pihole_posts_nothing() {
        let mut rig = Rig::on(FakePi::pihole_only(20));
        assert_eq!(err(rig.ack(1)).code, "absent");
        assert_eq!(rig.pi.count("POST /api/qbp"), 0);
        assert_eq!(rig.pi.count("GET /api/qbp/alerts"), 1);
    }

    #[test]
    fn ack_of_an_alert_that_vanished_before_the_post_is_not_found() {
        // The Pi lists alert 5 and then answers 404 to its ack.
        let srv = serve(5, |_, req| {
            let first = req.lines().next().unwrap_or("");
            Some(if first.starts_with("POST /api/auth") {
                ok_json(r#"{"session":{"valid":true,"sid":"S","validity":300}}"#)
            } else if first.starts_with("GET /api/qbp/alerts") {
                ok_json(&format!(
                    r#"{{"rev":1,"alerts":[{{"id":5,"key":"{}","kind":"dga","rev":1}}]}}"#,
                    key(5)
                ))
            } else if first.starts_with("DELETE /api/auth") {
                b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}".to_vec()
            })
        });
        let mut api = Pihole::at(
            srv.addr,
            srv.fingerprint,
            Box::new(|| Ok(Zeroizing::new("pw".to_string()))),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watchdog.json");
        let e = ack(&mut api, &path, T0, 5).unwrap_err();
        assert_eq!(e.code, "not-found");
        assert!(!path.exists(), "nothing was recorded");
    }

    #[test]
    fn ack_says_saved_false_when_only_the_pi_took_it() {
        let mut rig = Rig::new();
        rig.pi.raise("dga", "x.example", None, 1);
        let bad = unwritable(rig.dir.path());
        let v = ack(&mut rig.api, &bad, T0, 1).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "id": 1, "key": key(1), "saved": false})
        );
        assert!(rig.pi.with(|s| s.alerts[0].acked), "the Pi has it");
    }

    // -- devices --------------------------------------------------------------

    #[test]
    fn devices_shows_the_pi_inventory_with_this_pcs_list_and_what_is_offline() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            s.know(&mac(1), Some("Printer"), 40);
            s.know(&mac(9), Some("Old NAS"), 50);
            s.know(&mac(10), None, 60);
        });
        rig.pi.with(|s| {
            s.known = vec![mac(2)];
            s.known_list = "learned";
        });
        let v = rig.devices().unwrap();
        // The fake lists oldest first; the answer is last seen first.
        assert_eq!(
            v,
            json!({
                "ok": true, "knownList": "learned",
                "devices": [
                    { "mac": mac(3), "ipv4": ["192.0.2.3"], "hostname": "",
                      "firstUnix": T0, "lastUnix": T0 + 102,
                      "knownOnPi": false, "known": false, "label": "" },
                    { "mac": mac(2), "ipv4": ["192.0.2.2"], "hostname": "",
                      "firstUnix": T0, "lastUnix": T0 + 101,
                      "knownOnPi": true, "known": false, "label": "" },
                    { "mac": mac(1), "ipv4": ["192.0.2.1"], "hostname": "",
                      "firstUnix": T0, "lastUnix": T0 + 100,
                      "knownOnPi": false, "known": true, "label": "Printer" },
                ],
                "knownOffline": [
                    { "mac": mac(9), "label": "Old NAS", "firstSeen": 50 },
                    { "mac": mac(10), "label": "", "firstSeen": 60 },
                ]
            })
        );
        assert_eq!(rig.store().known_gen, 3, "looking changes nothing");
    }

    #[test]
    fn devices_is_not_cut_at_the_panels_128() {
        let mut rig = Rig::new();
        pi_devices(&rig, 300);
        let v = rig.devices().unwrap();
        assert_eq!(v["devices"].as_array().unwrap().len(), 300);
        assert_eq!(v["knownOffline"], json!([]));
    }

    // -- know -----------------------------------------------------------------

    #[test]
    fn know_adds_the_device_and_pushes_the_list() {
        let mut rig = Rig::new();
        let v = rig.know(&mac(2), Some("Phone")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "label": "Phone", "known": 1, "pushed": true})
        );
        let store = rig.store();
        assert_eq!(store.known.len(), 1);
        assert_eq!(store.known[0].mac, mac(2));
        assert_eq!(store.known[0].label.as_deref(), Some("Phone"));
        assert_eq!(store.known[0].first_seen, T0, "when the Pi first saw it");
        assert!(!store.push_due(), "the push was recorded");
        assert_eq!((store.known_gen, store.pushed_known_gen), (1, 1));
        assert_eq!(
            rig.known_puts(),
            vec![json!({"known": [mac(2)], "append": false, "complete": true})]
        );
        assert_eq!(rig.pi_known(), vec![mac(2)]);
    }

    /// A Pi with `n` devices, the first `known` of them on a list of its own.
    fn pi_with_list(rig: &Rig, list: &'static str, n: usize, known: usize) {
        pi_devices(rig, n);
        rig.pi.with(|s| s.known = (1..=known).map(mac).collect());
        rig.pi.set_known_list(list);
    }

    #[test]
    fn the_first_know_on_an_empty_list_seeds_it_from_a_list_the_pi_learned() {
        // The Pi raises an alert for every device that is not on the list it
        // is given, so replacing its 30 with 1 would flood.
        let mut rig = Rig::new();
        pi_with_list(&rig, "learned", 31, 30);
        let v = rig.know(&mac(31), Some("Tablet")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(31), "label": "Tablet", "known": 31,
                   "seeded": 30, "pushed": true})
        );
        let sent: Vec<String> = (1..=31).map(mac).collect();
        assert_eq!(
            rig.known_puts(),
            vec![json!({"known": sent, "append": false, "complete": true})]
        );
        assert_eq!(rig.pi_known(), sent);
        let store = rig.store();
        assert_eq!(store.known_macs(), sent);
        assert!(!store.push_due());
        // Seeded entries: the Pi's first-seen time, no label. The new one
        // has its label.
        assert!(store.known[..30]
            .iter()
            .all(|k| k.label.is_none() && k.first_seen == T0));
        assert_eq!(store.known[30].label.as_deref(), Some("Tablet"));

        // The list is there now: the next edit seeds nothing.
        let v = rig.know(&mac(5), Some("Printer")).unwrap();
        assert_eq!(v["known"], 31);
        assert!(v.get("seeded").is_none(), "{v}");
    }

    #[test]
    fn a_list_the_pi_received_is_seeded_from_too_and_a_waiting_pi_has_nothing_to_lose() {
        let mut rig = Rig::new();
        pi_with_list(&rig, "received", 6, 4);
        let v = rig.know(&mac(6), None).unwrap();
        assert_eq!(
            (v["known"].clone(), v["seeded"].clone()),
            (json!(5), json!(4))
        );
        assert_eq!(
            rig.pi_known(),
            (1..=4).chain([6]).map(mac).collect::<Vec<_>>()
        );

        // `waiting`: it has no list, nothing is seeded (its devices say
        // `known: false` anyway, but the state alone settles it).
        let mut rig = Rig::new();
        pi_with_list(&rig, "waiting", 6, 4);
        let v = rig.know(&mac(6), None).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(6), "known": 1, "pushed": true})
        );
    }

    #[test]
    fn nothing_is_seeded_over_a_list_that_is_there_or_one_that_was_emptied_on_purpose() {
        // A list on this PC: it is the master.
        let mut rig = Rig::new();
        pi_with_list(&rig, "learned", 10, 8);
        rig.edit(|s| s.know(&mac(9), None, 1));
        let v = rig.know(&mac(10), None).unwrap();
        assert_eq!(v["known"], 2);
        assert!(v.get("seeded").is_none());
        assert_eq!(rig.pi_known(), [mac(9), mac(10)]);

        // An edit that emptied the list and is not pushed yet: the user
        // meant it, the Pi's old list is not brought back.
        let mut rig = Rig::new();
        pi_with_list(&rig, "received", 10, 8);
        rig.edit(|s| {
            s.know(&mac(1), None, 1);
            s.forget(&mac(1));
        });
        assert!(rig.store().push_due() && rig.store().known.is_empty());
        let v = rig.know(&mac(10), None).unwrap();
        assert_eq!(v["known"], 1);
        assert!(v.get("seeded").is_none());
    }

    #[test]
    fn without_an_answer_from_devices_know_behaves_as_before() {
        // A Pi that fails the devices read (and the push).
        let mut rig = Rig::new();
        pi_with_list(&rig, "learned", 10, 8);
        rig.pi.with(|s| s.fail_qbp = true);
        let v = rig.know(&mac(10), None).unwrap();
        assert_eq!(
            v["known"], 1,
            "just the one: it cannot know what to seed from"
        );
        assert!(v.get("seeded").is_none());
        assert_eq!(v["pushed"], false);
        // A real Pi-hole.
        let mut rig = Rig::on(FakePi::pihole_only(20));
        let v = rig.know(&mac(10), None).unwrap();
        assert_eq!(v["known"], 1);
        assert!(v.get("seeded").is_none());
    }

    #[test]
    fn know_of_a_device_the_pi_has_not_seen_starts_now_and_may_have_no_label() {
        let mut rig = Rig::new();
        let v = rig.know(&mac(50), None).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(50), "known": 1, "pushed": true}),
            "no label, no label key"
        );
        assert_eq!(rig.store().known[0].first_seen, T0 + 999);
    }

    #[test]
    fn know_without_a_label_keeps_the_one_there_and_a_new_label_replaces_it() {
        let mut rig = Rig::new();
        rig.know(&mac(2), Some("Phone")).unwrap();
        let v = rig.know(&mac(2), None).unwrap();
        assert_eq!(v["label"], "Phone");
        assert_eq!(rig.store().known_gen, 1, "nothing changed");
        let v = rig.know(&mac(2), Some("Work phone")).unwrap();
        assert_eq!(v["label"], "Work phone");
        assert_eq!(rig.store().known.len(), 1);
        assert_eq!(rig.store().known_gen, 2);
        assert_eq!(rig.known_puts().len(), 3, "each call pushes");
    }

    #[test]
    fn know_cuts_a_long_label_at_64_characters() {
        let mut rig = Rig::new();
        let v = rig.know(&mac(1), Some(&"é".repeat(100))).unwrap();
        assert_eq!(v["label"].as_str().unwrap().chars().count(), 64);
    }

    #[test]
    fn know_on_a_real_pihole_still_edits_this_pcs_list() {
        let mut rig = Rig::on(FakePi::pihole_only(20));
        let v = rig.know(&mac(2), Some("Phone")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "label": "Phone", "known": 1,
                   "pushed": false, "pushError": "absent"})
        );
        let store = rig.store();
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert!(store.push_due(), "the watcher pushes it when it can");
        assert_eq!(store.known[0].first_seen, T0 + 999);
    }

    #[test]
    fn a_failed_push_leaves_the_edit_and_stays_due_until_one_works() {
        let mut rig = Rig::new();
        rig.pi.with(|s| s.fail_puts = true);
        let v = rig.know(&mac(2), None).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["known"], 1);
        assert_eq!(v["pushed"], false);
        assert!(
            v["pushError"].as_str().unwrap().contains("500"),
            "{}",
            v["pushError"]
        );
        let store = rig.store();
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert!(store.push_due());
        assert!(rig.known_puts().is_empty());

        rig.pi.with(|s| s.fail_puts = false);
        let v = rig.know(&mac(3), None).unwrap();
        assert_eq!(v["pushed"], true);
        assert!(v.get("pushError").is_none());
        assert!(!rig.store().push_due(), "both edits went out together");
        assert_eq!(rig.pi_known(), vec![mac(2), mac(3)]);
    }

    #[test]
    fn know_when_the_list_is_full_is_refused_and_pushes_nothing() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            for i in 1..=wdstore::MAX_ENTRIES {
                s.know(&mac(i), None, T0);
            }
        });
        let e = err(rig.know(&mac(5000), Some("One too many")));
        assert_eq!(e.code, "full");
        assert_eq!(rig.store().known.len(), wdstore::MAX_ENTRIES);
        assert!(rig.known_puts().is_empty());
        // A device that is there can still get a label.
        let v = rig.know(&mac(7), Some("Seventh")).unwrap();
        assert_eq!(v["known"], wdstore::MAX_ENTRIES);
        assert_eq!(v["pushed"], true);
    }

    #[test]
    fn a_store_that_cannot_be_written_is_a_store_error_and_pushes_nothing() {
        let mut rig = Rig::new();
        let bad = unwritable(rig.dir.path());
        let e = know(&mut rig.api, &bad, T0, &mac(1), None).unwrap_err();
        assert_eq!(e.code, "store");
        assert!(e.detail.contains("known list"), "{}", e.detail);
        assert!(rig.known_puts().is_empty());
        let e = forget(&mut rig.api, &bad, &mac(1)).unwrap_err();
        assert_eq!(e.code, "store");
        let e = know_all(&mut rig.api, &bad, T0).unwrap_err();
        assert_eq!(e.code, "store");
        assert!(rig.known_puts().is_empty());
    }

    // -- forget ---------------------------------------------------------------

    #[test]
    fn know_then_forget_round_trips_with_the_lists_the_pi_saw() {
        let mut rig = Rig::new();
        rig.know(&mac(1), Some("A")).unwrap();
        rig.know(&mac(2), None).unwrap();
        let v = rig.forget(&mac(1)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(1), "known": 1, "pushed": true})
        );
        let v = rig.forget(&mac(2)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "known": 0, "pushed": true})
        );
        let bodies = |macs: &[String]| json!({"known": macs, "append": false, "complete": true});
        assert_eq!(
            rig.known_puts(),
            vec![
                bodies(&[mac(1)]),
                bodies(&[mac(1), mac(2)]),
                bodies(&[mac(2)]),
                bodies(&[]),
            ],
            "the emptied list is pushed too"
        );
        assert!(rig.pi_known().is_empty());
        let store = rig.store();
        assert!(store.known.is_empty() && !store.push_due());
        assert_eq!(store.known_gen, 4);
    }

    #[test]
    fn forget_of_a_device_that_is_not_listed_is_not_found_and_pushes_nothing() {
        let mut rig = Rig::new();
        rig.know(&mac(1), None).unwrap();
        let e = err(rig.forget(&mac(2)));
        assert_eq!(e.code, "not-found");
        assert_eq!(rig.known_puts().len(), 1, "only the first push");
        assert_eq!(rig.store().known_macs(), vec![mac(1)]);
    }

    #[test]
    fn forget_on_a_real_pihole_still_edits_this_pcs_list() {
        let mut rig = Rig::on(FakePi::pihole_only(20));
        rig.edit(|s| s.know(&mac(1), Some("A"), T0));
        rig.edit(|s| s.know(&mac(2), None, T0));
        let v = rig.forget(&mac(1)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(1), "known": 1, "pushed": false, "pushError": "absent"})
        );
        let store = rig.store();
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert!(store.push_due());
        // Nothing to forget: no request at all.
        let before = rig.pi.with(|s| s.log.len());
        assert_eq!(err(rig.forget(&mac(7))).code, "not-found");
        assert_eq!(rig.pi.with(|s| s.log.len()), before);
    }

    // -- know-all -------------------------------------------------------------

    #[test]
    fn know_all_adds_every_reported_device_and_keeps_existing_labels() {
        let mut rig = Rig::new();
        pi_devices(&rig, 5);
        rig.edit(|s| s.know(&mac(2), Some("Phone"), 77));
        let v = rig.know_all().unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "added": 4, "known": 5, "pushed": true})
        );
        let store = rig.store();
        let got: Vec<(&str, Option<&str>, u64)> = store
            .known
            .iter()
            .map(|k| (k.mac.as_str(), k.label.as_deref(), k.first_seen))
            .collect();
        let m: Vec<String> = (1..=5).map(mac).collect();
        assert_eq!(
            got,
            vec![
                (m[1].as_str(), Some("Phone"), 77),
                (m[0].as_str(), None, T0),
                (m[2].as_str(), None, T0),
                (m[3].as_str(), None, T0),
                (m[4].as_str(), None, T0),
            ]
        );
        assert!(!store.push_due());
        assert_eq!(rig.known_puts().len(), 1);
        assert_eq!(rig.pi_known().len(), 5);
    }

    #[test]
    fn know_all_with_nothing_new_and_nothing_due_pushes_nothing() {
        let mut rig = Rig::new();
        rig.know_all().unwrap();
        assert_eq!(rig.known_puts().len(), 1);
        let v = rig.know_all().unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "added": 0, "known": 3, "pushed": false})
        );
        assert_eq!(rig.known_puts().len(), 1, "no second push");
        // A Pi that reports nothing leaves an empty list alone.
        let mut empty = Rig::new();
        empty.pi.with(|s| s.devices.clear());
        let v = empty.know_all().unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "added": 0, "known": 0, "pushed": false})
        );
        assert!(empty.known_puts().is_empty());
    }

    #[test]
    fn know_all_pushes_an_earlier_edit_that_is_still_due() {
        let mut rig = Rig::new();
        rig.know_all().unwrap();
        rig.pi.with(|s| s.fail_puts = true);
        rig.forget(&mac(1)).unwrap();
        assert!(rig.store().push_due());
        rig.pi.with(|s| s.fail_puts = false);
        let v = rig.know_all().unwrap();
        // Device 1 is reported again, so it is added back; the edit goes out.
        assert_eq!(
            v,
            json!({"ok": true, "added": 1, "known": 3, "pushed": true})
        );
        assert!(!rig.store().push_due());

        // Nothing added, but a failed edit is waiting.
        rig.pi.with(|s| s.fail_puts = true);
        rig.know(&mac(60), None).unwrap();
        rig.pi.with(|s| s.fail_puts = false);
        let before = rig.known_puts().len();
        let v = rig.know_all().unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "added": 0, "known": 4, "pushed": true})
        );
        assert_eq!(rig.known_puts().len(), before + 1);
    }

    #[test]
    fn know_all_of_250_devices_goes_out_in_two_chunks() {
        let mut rig = Rig::new();
        pi_devices(&rig, 250);
        rig.edit(|s| s.know(&mac(10), Some("Printer"), 5));
        let v = rig.know_all().unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "added": 249, "known": 250, "pushed": true})
        );
        let puts = rig.known_puts();
        assert_eq!(puts.len(), 2, "250 MACs do not fit one 4000-byte body");
        assert_eq!(
            (puts[0]["append"].clone(), puts[0]["complete"].clone()),
            (json!(false), json!(false))
        );
        assert_eq!(
            (puts[1]["append"].clone(), puts[1]["complete"].clone()),
            (json!(true), json!(true))
        );
        let store = rig.store();
        let sent: Vec<String> = puts
            .iter()
            .flat_map(|b| b["known"].as_array().unwrap().iter())
            .map(|m| m.as_str().unwrap().to_string())
            .collect();
        assert_eq!(sent, store.known_macs(), "every MAC once, in list order");
        assert_eq!(sent.len(), 250);
        assert!(puts.iter().all(|b| b.to_string().len() <= 4000));
        assert_eq!(rig.pi_known(), sent, "the Pi took the whole list");
        assert_eq!(store.known[0].label.as_deref(), Some("Printer"));
        assert_eq!(
            store.known[0].first_seen, 5,
            "an existing entry is untouched"
        );
        assert!(!store.push_due());
    }

    #[test]
    fn know_all_counts_what_does_not_fit_on_a_full_list() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            for i in 1..=(wdstore::MAX_ENTRIES - 1) {
                s.know(&mac(1000 + i), None, T0);
            }
        });
        let v = rig.know_all().unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "added": 1, "known": 1024, "skipped": 2, "pushed": true})
        );
    }

    // -- errors and dispatch --------------------------------------------------

    #[test]
    fn api_errors_keep_their_codes() {
        let pi = FakePi::start(20);
        let wrong_pin = |pi: &FakePi| {
            Pihole::at(
                pi.srv.addr,
                [7u8; 32],
                Box::new(|| Ok(Zeroizing::new("pw".to_string()))),
            )
            .unwrap()
        };
        let mut api = wrong_pin(&pi);
        assert_eq!(err(alerts(&mut api)).code, "tls");

        let mut api = Pihole::at(
            pi.srv.addr,
            pi.srv.fingerprint,
            Box::new(|| Err(ApiError::Auth("no password stored".into()))),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("watchdog.json");
        assert_eq!(err(alerts(&mut api)).code, "auth");
        assert_eq!(err(ack(&mut api, &path, T0, 1)).code, "auth");
        assert_eq!(err(devices(&mut api, &path)).code, "auth");
        assert_eq!(err(know_all(&mut api, &path, T0)).code, "auth");
        // know and forget still edit the list; the push says why not.
        let v = know(&mut api, &path, T0, &mac(1), None).unwrap();
        assert_eq!(v["pushed"], false);
        assert_eq!(v["pushError"], "no password stored");
        assert!(Store::load(&path).push_due());

        // Nothing listens: unreachable.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let mut api = Pihole::at(
            closed,
            [7u8; 32],
            Box::new(|| Ok(Zeroizing::new("pw".to_string()))),
        )
        .unwrap();
        assert_eq!(err(alerts(&mut api)).code, "unreachable");
    }

    #[test]
    fn run_dispatches_each_verb() {
        let mut rig = Rig::new();
        rig.pi.raise("dga", "x.example", None, 1);
        let path = rig.path();
        let mut go = |cmd: WdCmd| run(&mut rig.api, &path, T0, &cmd).unwrap();
        assert_eq!(go(WdCmd::Alerts)["alerts"].as_array().unwrap().len(), 1);
        assert_eq!(go(WdCmd::Ack { id: 1 })["key"], key(1));
        assert_eq!(go(WdCmd::Devices)["devices"].as_array().unwrap().len(), 3);
        let know_cmd = WdCmd::Know {
            mac: mac(9),
            label: Some("Nine".into()),
        };
        assert_eq!(go(know_cmd)["label"], "Nine");
        assert_eq!(go(WdCmd::KnowAll)["added"], 3);
        assert_eq!(go(WdCmd::Forget { mac: mac(9) })["known"], 3);
    }
}

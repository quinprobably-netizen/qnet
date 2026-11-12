//! The `qnet watchdog …` verbs: look at the Pi's alerts and devices, acknowledge
//! an alert, and edit the known-device list, the ADS PASS list (`exempt`: the
//! devices that are exempt from ad blocking; threat blocking stays) and the
//! exempt-by-default policy (the mode in which every device has ADS PASS
//! except the ones on a block list) of this PC, which are then pushed to the
//! Pi, and set or clear the PIN of the Pi's front panel.
//!
//! Each verb is a function of the API client, the path of the PC-side store
//! and the time (unix seconds), so tests run against the fake Pi and a
//! temporary store; `main` only parses, builds the client and prints the
//! result. An alert is told apart by its id, a device by its MAC address.
//!
//! The known list is edited on this PC first and pushed second: when the push
//! fails, or the Pi has no watchdog, the edit stays and the watcher pushes it
//! later (the store's `knownGen` says it is due). The ADS PASS list works the
//! same way (its `generation`), with its own push and its own result keys
//! (`exemptPushed`, `exemptPushError`), so one failing never hides the other.
//! A Pi that answers 404 for the exempt route has no ADS PASS support: the
//! edit is saved here and reported as "not pushed: not supported yet". The
//! policy works the same way (the mode and the block list are one push, with
//! `policyPushed`/`policyPushError` in the result), and `block` pushes the
//! lists it changed in order: known list, ADS PASS list (a device that is
//! blocked is taken off it), policy. The names (labels) of the devices are
//! pushed after any edit that may change them (`labelsPushed`,
//! `labelsPushError`), and the PIN hash by `pin set` and `pin clear`
//! (`panelPushed`, `panelPushError`).
//!
//! The Pi's front panel edits the ADS PASS list and the block list as well. A
//! verb that edits one of them reads the Pi's inventory first: when the
//! panel changed the list since this PC pushed it (the Pi's revision is above 0
//! and its pushed list differs from this PC's, with no edit of this PC waiting
//! and no sign that the Pi started again) the panel's list is adopted before
//! the verb edits it, and the push carries the revision that was read as
//! `if_rev`. A push that the panel overtook in between is a 409: the Pi's
//! list is read again and the verb's edit (what it added and took off) is put
//! on top of it, so neither edit is lost.
//!
//! `block-this` finds this computer's own hardware address without running
//! anything: the interface of the default IPv4 route from `/proc/net/route`,
//! its address from `/sys/class/net/<interface>/address` and the hostname for
//! the label (see [`HostFiles`], which tests point at a fake tree).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::actions::{ActionErr, ActionResult};
use crate::pihole::Pihole;
use crate::pinhash::PinHash;
use crate::state::{WatchdogAlertOut, WatchdogDeviceOut};
use crate::watchdog::{self, normalize_mac, Inventory, ListPut, Qbp};
use crate::wdstore::{self, clean_label, Store};

pub const USAGE: &str = "usage: qnet watchdog alerts | devices | know-all | ack <id> | \
know <mac> [label...] | forget <mac> | exempt|ads-pass <mac> [label...] | \
unexempt|ads-block <mac> | exempt-default on|off | block <mac> [label...] | \
unblock <mac> | block-this | pin set|clear";

/// What an ADS PASS push says when the Pi answered 404 for the route (an older
/// Pi, or a Pi-hole that is not a qberrypi at all).
const UNSUPPORTED: &str = "the Pi's software does not support ADS PASS devices yet";

/// What a policy push says when the Pi answered 404 for the route (an older
/// Pi, or a Pi-hole that is not a qberrypi at all).
const UNSUPPORTED_POLICY: &str =
    "the Pi's software does not support exempt-by-default blocking yet";

/// What a labels push says when the Pi answered 404 for the route (a Pi from
/// before its front panel, or a Pi-hole that is not a qberrypi at all).
const UNSUPPORTED_LABELS: &str = "the Pi's software does not show device names yet";

/// What a PIN push says when the Pi answered 404 for the route.
const UNSUPPORTED_PANEL: &str = "the Pi's software does not take a panel PIN yet";

/// The warning that goes with turning the exempt-by-default mode on.
const EXEMPT_DEFAULT_NOTE: &str = "every device that is not on the block list now has ADS PASS \
(threat blocking stays); keep a device's ads blocked with `qnet watchdog block <mac>`";

/// The note that goes with taking the PIN off.
const PIN_CLEAR_NOTE: &str = "the PIN is off on the Pi for this boot; a PIN in the Pi's own \
configuration comes back when the Pi restarts";

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
    /// As `Know`, and the device is put on the ADS PASS list as well
    /// (`exempt`, or `ads-pass`).
    Exempt {
        mac: String,
        label: Option<String>,
    },
    /// Take the device off the ADS PASS list (`unexempt`, or `ads-block`).
    Unexempt {
        mac: String,
    },
    /// Turn the exempt-by-default mode on or off.
    ExemptDefault {
        on: bool,
    },
    /// As `Know`, and the device is put on the block list as well (and taken
    /// off the exempt list).
    Block {
        mac: String,
        label: Option<String>,
    },
    Unblock {
        mac: String,
    },
    /// `Block` for this computer (its address and hostname are found by
    /// [`block_this`]).
    BlockThis,
    /// Set the panel's PIN. The digits are read from stdin by `main`, never
    /// from the command line, and are not part of this value.
    PinSet,
    /// Take the panel's PIN off.
    PinClear,
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
        ["unexempt" | "ads-block", mac] => Ok(WdCmd::Unexempt {
            mac: parse_mac(mac)?,
        }),
        ["exempt" | "ads-pass", mac, label @ ..] => Ok(WdCmd::Exempt {
            mac: parse_mac(mac)?,
            label: clean_label(&label.join(" ")),
        }),
        ["exempt-default", "on"] => Ok(WdCmd::ExemptDefault { on: true }),
        ["exempt-default", "off"] => Ok(WdCmd::ExemptDefault { on: false }),
        ["unblock", mac] => Ok(WdCmd::Unblock {
            mac: parse_mac(mac)?,
        }),
        ["block", mac, label @ ..] => Ok(WdCmd::Block {
            mac: parse_mac(mac)?,
            label: clean_label(&label.join(" ")),
        }),
        ["block-this"] => Ok(WdCmd::BlockThis),
        ["pin", "set"] => Ok(WdCmd::PinSet),
        ["pin", "clear"] => Ok(WdCmd::PinClear),
        _ => Err(usage()),
    }
}

/// Run one verb.
pub fn run(api: &mut Pihole, store_path: &Path, now: u64, cmd: &WdCmd) -> ActionResult {
    run_with(api, store_path, now, cmd, &HostFiles::system())
}

/// Run one verb, with `host` as the files `block-this` reads.
pub fn run_with(
    api: &mut Pihole,
    store_path: &Path,
    now: u64,
    cmd: &WdCmd,
    host: &HostFiles,
) -> ActionResult {
    match cmd {
        WdCmd::Alerts => alerts(api),
        WdCmd::Ack { id } => ack(api, store_path, now, *id),
        WdCmd::Devices => devices(api, store_path),
        WdCmd::Know { mac, label } => know(api, store_path, now, mac, label.as_deref()),
        WdCmd::Forget { mac } => forget(api, store_path, mac),
        WdCmd::KnowAll => know_all(api, store_path, now),
        WdCmd::Exempt { mac, label } => exempt(api, store_path, now, mac, label.as_deref()),
        WdCmd::Unexempt { mac } => unexempt(api, store_path, now, mac),
        WdCmd::ExemptDefault { on } => exempt_default(api, store_path, now, *on),
        WdCmd::Block { mac, label } => block(api, store_path, now, mac, label.as_deref()),
        WdCmd::Unblock { mac } => unblock(api, store_path, now, mac),
        WdCmd::BlockThis => block_this(api, store_path, now, host),
        // The digits come from stdin, which only `main` reads: see
        // [`pin_set`].
        WdCmd::PinSet => Err(ActionErr::new(
            "usage",
            "the PIN is read from stdin: run `qnet watchdog pin set`",
        )),
        WdCmd::PinClear => pin_clear(api, store_path),
    }
}

// -- helpers ------------------------------------------------------------------

fn absent() -> ActionErr {
    ActionErr::new("absent", "the Pi-hole has no watchdog")
}

fn store_err(e: std::io::Error) -> ActionErr {
    ActionErr::new("store", format!("could not save the known list: {e}"))
}

fn exempt_store_err(e: std::io::Error) -> ActionErr {
    ActionErr::new("store", format!("could not save the ADS PASS list: {e}"))
}

fn pin_store_err(e: std::io::Error) -> ActionErr {
    ActionErr::new("store", format!("could not save the panel PIN: {e}"))
}

fn policy_store_err(e: std::io::Error) -> ActionErr {
    ActionErr::new(
        "store",
        format!("could not save the exempt-by-default policy: {e}"),
    )
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
        self.add_as(out, "pushed", "pushError");
    }

    /// The result under the keys `pushed` and `error` (the exempt list has
    /// its own).
    fn add_as(self, out: &mut Value, pushed: &str, error: &str) {
        match self {
            Pushed::Sent => out[pushed] = json!(true),
            Pushed::Skipped => out[pushed] = json!(false),
            Pushed::Failed(why) => {
                out[pushed] = json!(false);
                out[error] = json!(why);
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

/// How many times a push that the front panel overtook (a 409) is read again
/// and merged before the verb gives up and says so.
const PUSH_TRIES: usize = 3;

/// What a verb knows of the Pi's lists when it pushes: the revision it read
/// (the `if_rev` of the push) and each list as the verb found it, before its
/// edit, when that was the Pi's pushed list too: the common ground that a
/// panel edit that overtakes the push is merged on (see [`watchdog::rebase`]).
#[derive(Debug, Default, Clone)]
struct Base {
    rev: Option<u64>,
    exempt: Option<Vec<String>>,
    block: Option<Vec<String>>,
}

/// The Pi's inventory, if it can be read at all.
fn read_pi(api: &mut Pihole) -> Option<Inventory> {
    match watchdog::get_devices(api) {
        Ok(Qbp::Present(inv)) => Some(inv),
        _ => None,
    }
}

/// Whether two lists of addresses name the same devices, whatever their order.
fn same_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|m| b.contains(m))
}

/// The first step of a verb that edits the ADS PASS list or the block list,
/// inside its locked edit: when the Pi's front panel changed a list since this
/// PC pushed it, take the panel's over (the panel's edit is newer than this
/// PC's list), so that the verb edits what the Pi has. That is when the Pi
/// says its revision (above 0: something changed its lists since it started)
/// and a pushed list that differs from this PC's, with no edit of this PC
/// waiting to be pushed and no sign that the Pi started again (it still waits
/// for a known list that this PC has). Returns what the push needs: the
/// revision and the lists as they stand now, before the verb's edit.
fn adopt_panel(s: &mut Store, inv: Option<&Inventory>, now: u64) -> Base {
    let Some((inv, rev)) = inv.and_then(|inv| Some((inv, inv.rev?))) else {
        return Base::default();
    };
    let restarted = inv.known_list == "waiting" && !s.known.is_empty();
    let adoptable = rev > 0 && !restarted;
    let mut base = Base {
        rev: Some(rev),
        ..Base::default()
    };
    if let Some(on_pi) = &inv.exempt_pushed {
        if adoptable && !s.exempt_push_due() && !same_set(&s.exempt_macs(), on_pi) {
            s.adopt_exempt(on_pi, now);
        }
        base.exempt = same_set(&s.exempt_macs(), on_pi).then(|| s.exempt_macs());
    }
    if let Some(on_pi) = &inv.block_pushed {
        if adoptable && !s.policy_push_due() && !same_set(&s.block_macs(), on_pi) {
            s.adopt_block(on_pi, now);
        }
        base.block = same_set(&s.block_macs(), on_pi).then(|| s.block_macs());
    }
    base
}

/// The exempt list as it was after an edit, like [`Snapshot`] for the known one.
struct ExemptSnapshot {
    generation: u64,
    macs: Vec<String>,
}

impl ExemptSnapshot {
    fn of(s: &Store) -> Self {
        Self {
            generation: s.exempt_gen,
            macs: s.exempt_macs(),
        }
    }
}

/// Push the PC's ADS PASS list to the Pi and record the push. An empty list is
/// pushed as it is (it clears the Pi's list): these verbs are explicit edits.
/// The push is made on the revision that was read (`base`); when the panel
/// overtook it (a 409) the Pi's list is read again, this PC's edit is put on
/// top of it and the push is made again. A 404 is "not supported", whatever the
/// reason: the edit stays on this PC and the watcher asks again once per login
/// session.
fn push_exempt(
    api: &mut Pihole,
    store_path: &Path,
    now: u64,
    mut snap: ExemptSnapshot,
    base: &Base,
) -> Pushed {
    let (mut rev, mut from) = (base.rev, base.exempt.clone());
    for attempt in 1..=PUSH_TRIES {
        match watchdog::put_exempt(api, &snap.macs, rev) {
            Ok(ListPut::Done { .. }) => {
                // If this cannot be recorded the list stays due and the
                // watcher pushes it once more: harmless.
                let _ = wdstore::update(store_path, |s| s.mark_exempt_pushed(snap.generation));
                return Pushed::Sent;
            }
            Ok(ListPut::Absent) => return Pushed::Failed(UNSUPPORTED.to_string()),
            Err(e) => return Pushed::Failed(e.message().to_string()),
            Ok(ListPut::Stale { .. }) if attempt < PUSH_TRIES => {
                let Some(inv) = read_pi(api) else {
                    return Pushed::Failed(CHANGED_UNREAD.to_string());
                };
                let Some(current) = inv.exempt_pushed else {
                    break;
                };
                if let Some(from) = from.as_mut() {
                    let merged = watchdog::rebase(from, &snap.macs, &current);
                    if !same_set(&merged, &snap.macs) {
                        match wdstore::update(store_path, |s| {
                            s.replace_exempt(&merged, now);
                            ExemptSnapshot::of(s)
                        }) {
                            Ok(next) => snap = next,
                            Err(e) => {
                                return Pushed::Failed(format!("could not save the merge: {e}"))
                            }
                        }
                    }
                    // What the Pi has now is what the next merge starts from.
                    *from = current;
                }
                rev = inv.rev;
            }
            Ok(ListPut::Stale { .. }) => break,
        }
    }
    Pushed::Failed(CHANGING.to_string())
}

/// What a push says when the panel overtook it and the Pi's lists could not be
/// read again.
const CHANGED_UNREAD: &str = "the Pi's lists changed while this was sent (its front panel?) and \
could not be read again; run it again";

/// What a push says when the Pi's lists kept changing under it.
const CHANGING: &str = "the Pi's lists kept changing while this was sent (its front panel?); \
run it again";

/// The policy as it was after an edit: the mode and the block list to push,
/// and which generation that was (like [`Snapshot`]).
struct PolicySnapshot {
    generation: u64,
    exempt_default: bool,
    macs: Vec<String>,
}

impl PolicySnapshot {
    fn of(s: &Store) -> Self {
        Self {
            generation: s.policy_gen,
            exempt_default: s.exempt_default,
            macs: s.block_macs(),
        }
    }
}

/// Push the PC's policy to the Pi and record the push, as [`push_exempt`] does
/// for the ADS PASS list: the default policy is pushed as it is (it clears the
/// Pi's), and a push that the panel overtook is merged and made again. The mode
/// is this PC's to say and is never merged.
fn push_policy(
    api: &mut Pihole,
    store_path: &Path,
    now: u64,
    mut snap: PolicySnapshot,
    base: &Base,
) -> Pushed {
    let (mut rev, mut from) = (base.rev, base.block.clone());
    for attempt in 1..=PUSH_TRIES {
        match watchdog::put_policy(api, snap.exempt_default, &snap.macs, rev) {
            Ok(ListPut::Done { .. }) => {
                // If this cannot be recorded the policy stays due and the
                // watcher pushes it once more: harmless.
                let _ = wdstore::update(store_path, |s| s.mark_policy_pushed(snap.generation));
                return Pushed::Sent;
            }
            Ok(ListPut::Absent) => return Pushed::Failed(UNSUPPORTED_POLICY.to_string()),
            Err(e) => return Pushed::Failed(e.message().to_string()),
            Ok(ListPut::Stale { .. }) if attempt < PUSH_TRIES => {
                let Some(inv) = read_pi(api) else {
                    return Pushed::Failed(CHANGED_UNREAD.to_string());
                };
                let Some(current) = inv.block_pushed else {
                    break;
                };
                if let Some(from) = from.as_mut() {
                    let merged = watchdog::rebase(from, &snap.macs, &current);
                    if !same_set(&merged, &snap.macs) {
                        match wdstore::update(store_path, |s| {
                            s.replace_block(&merged, now);
                            PolicySnapshot::of(s)
                        }) {
                            Ok(next) => snap = next,
                            Err(e) => {
                                return Pushed::Failed(format!("could not save the merge: {e}"))
                            }
                        }
                    }
                    *from = current;
                }
                rev = inv.rev;
            }
            Ok(ListPut::Stale { .. }) => break,
        }
    }
    Pushed::Failed(CHANGING.to_string())
}

/// Push the names of this PC's devices (see [`watchdog::labels_for_pi`]) to the
/// Pi, as the lists are now. Pushed after every edit that may have changed
/// them, also when none did. A 404 is "not supported", as for the lists.
fn push_labels(api: &mut Pihole, store_path: &Path) -> Pushed {
    let store = Store::load(store_path);
    match watchdog::put_labels(api, &watchdog::labels_for_pi(&store)) {
        Ok(Qbp::Present(_)) => Pushed::Sent,
        Ok(Qbp::Absent) => Pushed::Failed(UNSUPPORTED_LABELS.to_string()),
        Err(e) => Pushed::Failed(e.message().to_string()),
    }
}

/// Push the PIN hash (or its absence) of generation `generation` to the Pi and
/// record the push. The hash is in no error and no result.
fn push_panel(
    api: &mut Pihole,
    store_path: &Path,
    generation: u64,
    hash: Option<&PinHash>,
) -> Pushed {
    match watchdog::put_panel(api, hash) {
        Ok(Qbp::Present(())) => {
            // If this cannot be recorded the PIN stays due and the watcher
            // pushes it once more: harmless.
            let _ = wdstore::update(store_path, |s| s.mark_pin_pushed(generation));
            Pushed::Sent
        }
        Ok(Qbp::Absent) => Pushed::Failed(UNSUPPORTED_PANEL.to_string()),
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
/// knows about each device (known, ADS PASS) and what the Pi says (known,
/// ADS PASS), the PC's known and ADS PASS devices the Pi did not report
/// (`knownOffline`, `exemptOffline`), and the addresses only the Pi passes
/// (`exemptOnPiOnly`: they come from its config file or from its front panel,
/// not from this PC's list). The front panel's fields are shown too: `rev`
/// on top (the revision of the Pi's device lists, `null` when it does not
/// say), and on each device `labelOnPi` (the name the Pi was given, `null`
/// for none; `label` is this PC's), `gateLeftSecs` (the seconds that the
/// panel's gate for the device stays open, `null` while shut), `fixed` (the Pi's
/// configuration decides the device, so no edit changes it) and `always` (the
/// router or the Pi itself: never ADS PASS). The exempt-by-default policy has the same two views: `exemptDefault`
/// (this PC's mode) and `exemptDefaultOnPi` (the Pi's), `blockOffline` (this
/// PC's block list minus the reported devices) and `blockOnPiOnly` (the Pi's
/// block list minus this PC's), and `blocked`/`blockedOnPi` on every device.
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
    let exempt_offline: Vec<Value> = store
        .exempt
        .iter()
        .filter(|e| !reported.contains(e.mac.as_str()))
        .map(|e| {
            json!({
                "mac": e.mac,
                "label": e.label.as_deref().unwrap_or(""),
                "firstSeen": e.first_seen,
            })
        })
        .collect();
    let mine: HashSet<&str> = store.exempt.iter().map(|e| e.mac.as_str()).collect();
    let exempt_on_pi_only: Vec<&String> = inv
        .exempt_macs
        .iter()
        .filter(|m| !mine.contains(m.as_str()))
        .collect();
    let block_offline: Vec<Value> = store
        .block
        .iter()
        .filter(|b| !reported.contains(b.mac.as_str()))
        .map(|b| {
            json!({
                "mac": b.mac,
                "label": b.label.as_deref().unwrap_or(""),
                "firstSeen": b.first_seen,
            })
        })
        .collect();
    let my_block: HashSet<&str> = store.block.iter().map(|b| b.mac.as_str()).collect();
    let block_on_pi_only: Vec<&String> = inv
        .block_macs
        .iter()
        .filter(|m| !my_block.contains(m.as_str()))
        .collect();
    let mut list = inv.devices.clone();
    list.sort_by_key(|d| std::cmp::Reverse(d.last_unix));
    let devices: Vec<Value> = watchdog::annotate(list, &store)
        .iter()
        .map(|d| {
            let mut out = json!(WatchdogDeviceOut::from_report_device(d));
            out["labelOnPi"] = json!(d.device.label);
            out["gateLeftSecs"] = json!(d.device.gate_left_secs);
            out["fixed"] = json!(d.device.fixed);
            out["always"] = json!(d.device.always);
            out
        })
        .collect();
    Ok(json!({
        "ok": true,
        "rev": inv.rev,
        "knownList": inv.known_list,
        "devices": devices,
        "knownOffline": offline,
        "exemptOffline": exempt_offline,
        "exemptOnPiOnly": exempt_on_pi_only,
        "exemptDefault": store.exempt_default,
        "exemptDefaultOnPi": inv.exempt_default,
        "blockOffline": block_offline,
        "blockOnPiOnly": block_on_pi_only,
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

/// The Pi's inventory, if it can be read, and when the Pi first saw `mac`
/// (`now` when it does not say, or cannot be asked).
fn look_up(api: &mut Pihole, mac: &str, now: u64) -> (Option<Inventory>, u64) {
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
    (inv, first_seen)
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
    let (inv, first_seen) = look_up(api, &mac, now);
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
    push_labels(api, store_path).add_as(&mut out, "labelsPushed", "labelsPushError");
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
    push_labels(api, store_path).add_as(&mut out, "labelsPushed", "labelsPushError");
    Ok(out)
}

// -- the ADS PASS list ----------------------------------------------------------

/// `watchdog exempt <mac> [label]` (or `ads-pass`): put the device on this PC's
/// ADS PASS list (or change its label; without a label an existing one stays)
/// and on the known list exactly as [`know`] does (the owner named it, so the
/// Pi must not raise a new-device alert for it; the first edit on an empty
/// known list seeds it from the Pi's, see [`seed_from_pi`]), in one locked
/// edit, then push the known list and then the ADS PASS list. Both are pushed
/// on every call, also when nothing changed. Before the edit the Pi's own list
/// is adopted if its front panel changed it (see [`adopt_panel`]), and the push
/// is made on the revision that was read, merged with the panel's edit when it
/// is overtaken (see [`push_exempt`]). Refused (`full`, nothing changed,
/// nothing pushed) when the list holds [`wdstore::MAX_EXEMPT`] devices already
/// and this is a new one, or when the known list is full and the device is not
/// on it. The result carries `known` and `pushed`/`pushError` for the known
/// list as `know` does, plus `exempt` (the size of the list after the edit)
/// and `exemptPushed`/`exemptPushError` for its push (a Pi that answers 404
/// for it has no ADS PASS support yet), and `labelsPushed`/`labelsPushError`.
pub fn exempt(
    api: &mut Pihole,
    store_path: &Path,
    now: u64,
    mac: &str,
    label: Option<&str>,
) -> ActionResult {
    let mac =
        normalize_mac(mac).ok_or_else(|| ActionErr::new("invalid", "not a hardware address"))?;
    let (inv, first_seen) = look_up(api, &mac, now);
    let edit = wdstore::update(store_path, |s| {
        let base = adopt_panel(s, inv.as_ref(), now);
        // Checked before anything is touched: a refusal changes nothing.
        if !s.is_exempt(&mac) && s.exempt_is_full() {
            return Err(ActionErr::new(
                "full",
                format!(
                    "the ADS PASS list holds {} devices already",
                    wdstore::MAX_EXEMPT
                ),
            ));
        }
        let seeded = inv.as_ref().map_or(0, |inv| seed_from_pi(s, inv, now));
        let was_known = s.is_known(&mac);
        if !s.know(&mac, label, first_seen) && !was_known {
            return Err(ActionErr::new(
                "full",
                format!(
                    "the known list holds {} devices already, so this one cannot be marked known",
                    wdstore::MAX_ENTRIES
                ),
            ));
        }
        s.add_exempt(&mac, label, first_seen);
        let label = s
            .known
            .iter()
            .find(|k| k.mac == mac)
            .and_then(|k| k.label.clone());
        Ok((Snapshot::of(s), ExemptSnapshot::of(s), label, seeded, base))
    })
    .map_err(exempt_store_err)??;
    let (known, exempt, label, seeded, base) = edit;
    let mut out = json!({
        "ok": true, "mac": mac, "known": known.macs.len(), "exempt": exempt.macs.len(),
    });
    if let Some(l) = label {
        out["label"] = json!(l);
    }
    if seeded > 0 {
        out["seeded"] = json!(seeded);
    }
    push(api, store_path, &known).add_to(&mut out);
    push_exempt(api, store_path, now, exempt, &base).add_as(
        &mut out,
        "exemptPushed",
        "exemptPushError",
    );
    push_labels(api, store_path).add_as(&mut out, "labelsPushed", "labelsPushError");
    Ok(out)
}

/// `watchdog unexempt <mac>` (or `ads-block`): take the device off this PC's
/// ADS PASS list, then push that list (an emptied list is pushed too: this is
/// an explicit edit). The device stays on the known list, which is not touched
/// or pushed. The Pi's own list is adopted first when its front panel changed
/// it, as for [`exempt`], so a device that the panel took off the list already
/// is `not-found`.
pub fn unexempt(api: &mut Pihole, store_path: &Path, now: u64, mac: &str) -> ActionResult {
    let mac =
        normalize_mac(mac).ok_or_else(|| ActionErr::new("invalid", "not a hardware address"))?;
    let inv = read_pi(api);
    let (snap, base) = wdstore::update(store_path, |s| {
        let base = adopt_panel(s, inv.as_ref(), now);
        s.remove_exempt(&mac).then(|| (ExemptSnapshot::of(s), base))
    })
    .map_err(exempt_store_err)?
    .ok_or_else(|| ActionErr::new("not-found", "that device is not on the ADS PASS list"))?;
    let mut out = json!({ "ok": true, "mac": mac, "exempt": snap.macs.len() });
    push_exempt(api, store_path, now, snap, &base).add_as(
        &mut out,
        "exemptPushed",
        "exemptPushError",
    );
    push_labels(api, store_path).add_as(&mut out, "labelsPushed", "labelsPushError");
    Ok(out)
}

// -- the exempt-by-default policy ---------------------------------------------

/// `watchdog exempt-default on|off`: set the mode on this PC, then push the
/// policy (the mode and the block list). It pushes on every call, also when
/// nothing changed (so a Pi that lost the policy gets it, and a PC that wants
/// the default policy on the Pi can say so). Turning it on warns, in `note`,
/// that every device that is not on the block list has ADS PASS from then on
/// (threat blocking stays). The block list is not touched: it is kept while the
/// mode is off, for the next time (but for what the Pi's front panel changed
/// of it, which is adopted first, as for [`exempt`]). The result is `{"ok":true,
/// "exemptDefault":bool,"block":n,"policyPushed":bool,"policyPushError"?,
/// "note"?}`; a 404 is reported as not supported (the edit stays and the
/// watcher asks again once per login session).
pub fn exempt_default(api: &mut Pihole, store_path: &Path, now: u64, on: bool) -> ActionResult {
    let inv = read_pi(api);
    let (snap, base) = wdstore::update(store_path, |s| {
        let base = adopt_panel(s, inv.as_ref(), now);
        s.set_exempt_default(on);
        (PolicySnapshot::of(s), base)
    })
    .map_err(policy_store_err)?;
    let mut out = json!({ "ok": true, "exemptDefault": on, "block": snap.macs.len() });
    if on {
        out["note"] = json!(EXEMPT_DEFAULT_NOTE);
    }
    push_policy(api, store_path, now, snap, &base).add_as(
        &mut out,
        "policyPushed",
        "policyPushError",
    );
    Ok(out)
}

/// `watchdog block <mac> [label]`: put the device on this PC's block list (or
/// change its label; without a label an existing one stays) and on the known
/// list exactly as [`know`] does (the owner named it, so the Pi must not raise
/// a new-device alert for it; the first edit on an empty known list seeds it
/// from the Pi's, see [`seed_from_pi`]), and take it off the ADS PASS list if it
/// is there (a device is not both), in one locked edit. Then push the known
/// list, the ADS PASS list (only when the device was taken off it) and the
/// policy. Pushes on every call, also when nothing changed. Refused (`full`,
/// nothing changed, nothing pushed) when the block list holds
/// [`wdstore::MAX_BLOCK`] devices already and this is a new one, or when the
/// known list is full and the device is not on it. The result carries `known`
/// and `pushed`/`pushError` as `know` does, `block` (the size of the block list
/// after the edit) and `policyPushed`/`policyPushError`, and when the device
/// was on the ADS PASS list `unexempted: true`, `exempt` and
/// `exemptPushed`/`exemptPushError`, and `labelsPushed`/`labelsPushError`.
/// Every push has its own keys, so one failing never hides another. The Pi's
/// own lists are adopted first, and the pushes merged, as for [`exempt`].
pub fn block(
    api: &mut Pihole,
    store_path: &Path,
    now: u64,
    mac: &str,
    label: Option<&str>,
) -> ActionResult {
    let mac =
        normalize_mac(mac).ok_or_else(|| ActionErr::new("invalid", "not a hardware address"))?;
    let (inv, first_seen) = look_up(api, &mac, now);
    let edit = wdstore::update(store_path, |s| {
        let base = adopt_panel(s, inv.as_ref(), now);
        // Checked before anything is touched: a refusal changes nothing.
        if !s.is_blocked(&mac) && s.block_is_full() {
            return Err(ActionErr::new(
                "full",
                format!(
                    "the block list holds {} devices already",
                    wdstore::MAX_BLOCK
                ),
            ));
        }
        let seeded = inv.as_ref().map_or(0, |inv| seed_from_pi(s, inv, now));
        let was_known = s.is_known(&mac);
        if !s.know(&mac, label, first_seen) && !was_known {
            return Err(ActionErr::new(
                "full",
                format!(
                    "the known list holds {} devices already, so this one cannot be marked known",
                    wdstore::MAX_ENTRIES
                ),
            ));
        }
        s.add_block(&mac, label, first_seen);
        let unexempted = s.remove_exempt(&mac);
        let label = s
            .known
            .iter()
            .find(|k| k.mac == mac)
            .and_then(|k| k.label.clone());
        Ok(BlockEdit {
            known: Snapshot::of(s),
            exempt: unexempted.then(|| ExemptSnapshot::of(s)),
            policy: PolicySnapshot::of(s),
            label,
            seeded,
            base,
        })
    })
    .map_err(policy_store_err)??;
    let mut out = json!({
        "ok": true, "mac": mac, "known": edit.known.macs.len(), "block": edit.policy.macs.len(),
    });
    if let Some(l) = edit.label {
        out["label"] = json!(l);
    }
    if edit.seeded > 0 {
        out["seeded"] = json!(edit.seeded);
    }
    if let Some(e) = &edit.exempt {
        out["unexempted"] = json!(true);
        out["exempt"] = json!(e.macs.len());
    }
    push(api, store_path, &edit.known).add_to(&mut out);
    if let Some(e) = edit.exempt {
        push_exempt(api, store_path, now, e, &edit.base).add_as(
            &mut out,
            "exemptPushed",
            "exemptPushError",
        );
    }
    push_policy(api, store_path, now, edit.policy, &edit.base).add_as(
        &mut out,
        "policyPushed",
        "policyPushError",
    );
    push_labels(api, store_path).add_as(&mut out, "labelsPushed", "labelsPushError");
    Ok(out)
}

/// What one locked edit of [`block`] leaves to push and to report.
struct BlockEdit {
    known: Snapshot,
    /// Set when the device was taken off the ADS PASS list.
    exempt: Option<ExemptSnapshot>,
    policy: PolicySnapshot,
    label: Option<String>,
    seeded: u64,
    base: Base,
}

/// `watchdog unblock <mac>`: take the device off this PC's block list, then
/// push the policy (an emptied list is pushed too: this is an explicit edit).
/// The device stays on the known list, which is neither changed nor pushed.
/// The Pi's own list is adopted first, as for [`exempt`].
pub fn unblock(api: &mut Pihole, store_path: &Path, now: u64, mac: &str) -> ActionResult {
    let mac =
        normalize_mac(mac).ok_or_else(|| ActionErr::new("invalid", "not a hardware address"))?;
    let inv = read_pi(api);
    let (snap, base) = wdstore::update(store_path, |s| {
        let base = adopt_panel(s, inv.as_ref(), now);
        s.remove_block(&mac).then(|| (PolicySnapshot::of(s), base))
    })
    .map_err(policy_store_err)?
    .ok_or_else(|| ActionErr::new("not-found", "that device is not on the block list"))?;
    let mut out = json!({ "ok": true, "mac": mac, "block": snap.macs.len() });
    push_policy(api, store_path, now, snap, &base).add_as(
        &mut out,
        "policyPushed",
        "policyPushError",
    );
    push_labels(api, store_path).add_as(&mut out, "labelsPushed", "labelsPushError");
    Ok(out)
}

// -- the panel's PIN ----------------------------------------------------------

/// `watchdog pin set`, once `main` has read the four digits from stdin and made
/// the hash (see [`crate::pinhash`]): keep the hash (nothing of the digits is
/// kept) and push it to the Pi with `PUT /api/qbp/panel`, for the running boot;
/// the watcher pushes it again after each start of the Pi, and when this push
/// fails. The result is `{"ok":true,"pin":"set","panelPushed":bool,
/// "panelPushError"?}`: no digit and no hash is in it, or in any error.
pub fn pin_set(api: &mut Pihole, store_path: &Path, hash: PinHash) -> ActionResult {
    let generation = wdstore::update(store_path, |s| {
        s.set_pin(hash.clone());
        s.pin_gen
    })
    .map_err(pin_store_err)?;
    let mut out = json!({ "ok": true, "pin": "set" });
    push_panel(api, store_path, generation, Some(&hash)).add_as(
        &mut out,
        "panelPushed",
        "panelPushError",
    );
    Ok(out)
}

/// `watchdog pin clear`: forget the hash on this PC and push `null`, which
/// takes the PIN off the Pi for the running boot (also one that was set at its
/// panel). It pushes on every call, also when this PC had none. The result is
/// `{"ok":true,"pin":"cleared","panelPushed":bool,"panelPushError"?,"note"}`;
/// the note says that a PIN in the Pi's own configuration comes back when it
/// restarts, which only the Pi's configuration changes.
pub fn pin_clear(api: &mut Pihole, store_path: &Path) -> ActionResult {
    let generation = wdstore::update(store_path, |s| {
        s.clear_pin();
        s.pin_gen
    })
    .map_err(pin_store_err)?;
    let mut out = json!({ "ok": true, "pin": "cleared", "note": PIN_CLEAR_NOTE });
    push_panel(api, store_path, generation, None).add_as(&mut out, "panelPushed", "panelPushError");
    Ok(out)
}

/// Where [`block_this`] looks for what it needs to know about this computer.
/// [`system`](Self::system) is the real thing; tests point the paths at a fake
/// tree.
pub struct HostFiles {
    /// The IPv4 routing table (`/proc/net/route`).
    pub route: PathBuf,
    /// The folder of the network interfaces (`/sys/class/net`), each with an
    /// `address` file.
    pub sys_class_net: PathBuf,
    /// The hostname (`/proc/sys/kernel/hostname`).
    pub hostname: PathBuf,
}

impl HostFiles {
    pub fn system() -> Self {
        Self {
            route: PathBuf::from("/proc/net/route"),
            sys_class_net: PathBuf::from("/sys/class/net"),
            hostname: PathBuf::from("/proc/sys/kernel/hostname"),
        }
    }
}

/// This computer as the Pi sees it.
struct ThisComputer {
    interface: String,
    mac: String,
    label: Option<String>,
}

/// The interface that carries the IPv4 default route in a `/proc/net/route`
/// table: of the routes that are up (not rejecting) with destination and mask
/// 0.0.0.0, the one with the lowest metric (the first listed among equals), as
/// the kernel would pick it.
fn default_route_interface(table: &str) -> Option<String> {
    const RTF_UP: u32 = 0x0001;
    const RTF_REJECT: u32 = 0x0200;
    table
        .lines()
        .filter(|l| !l.starts_with("Iface"))
        .filter_map(|line| {
            // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
            let f: Vec<&str> = line.split_whitespace().collect();
            let [iface, dest, _gateway, flags, _refs, _use, metric, mask, ..] = f.as_slice() else {
                return None;
            };
            if *dest != "00000000" || *mask != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(flags, 16).ok()?;
            if flags & RTF_UP == 0 || flags & RTF_REJECT != 0 {
                return None;
            }
            Some((metric.parse::<u32>().ok()?, iface.to_string()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, iface)| iface)
}

/// This computer's hardware address (of the interface that carries the
/// default IPv4 route) and hostname, read from `host`. Refused with
/// `no-route` when there is no such route (or the table cannot be read) and
/// `no-address` when the interface has no usable Ethernet address (a tunnel, a
/// VPN: the Pi never sees an address like that anyway).
fn this_computer(host: &HostFiles) -> Result<ThisComputer, ActionErr> {
    let table = std::fs::read_to_string(&host.route).map_err(|e| {
        ActionErr::new("no-route", format!("could not read the routing table: {e}"))
    })?;
    let interface = default_route_interface(&table).ok_or_else(|| {
        ActionErr::new(
            "no-route",
            "this computer has no default route for IPv4 (is it online?), so there is no \
             interface to block",
        )
    })?;
    // The name comes from the kernel, but it is joined to a path: keep it
    // inside the interfaces' folder.
    let mac = (!interface.contains('/'))
        .then(|| host.sys_class_net.join(&interface).join("address"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|a| normalize_mac(a.trim()))
        .filter(|m| m != "00:00:00:00:00:00")
        .ok_or_else(|| {
            ActionErr::new(
                "no-address",
                format!(
                    "the interface {interface} that carries the default route has no Ethernet \
                     address (a tunnel or VPN?); block this computer by its own address with \
                     `qnet watchdog block <mac>`"
                ),
            )
        })?;
    let label = std::fs::read_to_string(&host.hostname)
        .ok()
        .and_then(|h| clean_label(&h));
    Ok(ThisComputer {
        interface,
        mac,
        label,
    })
}

/// `watchdog block-this`: [`block`] for this computer: the address of the
/// interface that carries the default IPv4 route, labelled with the hostname.
/// The result is that of `block` plus `interface`. Refused (`no-route`,
/// `no-address`) before anything is asked of the Pi or changed.
pub fn block_this(api: &mut Pihole, store_path: &Path, now: u64, host: &HostFiles) -> ActionResult {
    let me = this_computer(host)?;
    let mut out = block(api, store_path, now, &me.mac, me.label.as_deref())?;
    out["interface"] = json!(me.interface);
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

    /// A verb's result without the names' push (`labelsPushed`,
    /// `labelsPushError`), which the tests of the lists leave to their own.
    fn bare(mut result: ActionResult) -> ActionResult {
        if let Ok(v) = &mut result {
            let out = v.as_object_mut().unwrap();
            out.remove("labelsPushed");
            out.remove("labelsPushError");
        }
        result
    }

    /// A push body without its `if_rev` (the Pi's revision when it was read).
    fn without_if_rev(mut body: Value) -> Value {
        body.as_object_mut().unwrap().remove("if_rev");
        body
    }

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
            bare(know(&mut self.api, &path, T0 + 999, mac, label))
        }
        fn forget(&mut self, mac: &str) -> ActionResult {
            let path = self.path();
            bare(forget(&mut self.api, &path, mac))
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
        let v = without_panel_fields(rig.devices().unwrap());
        // The fake lists oldest first; the answer is last seen first.
        assert_eq!(
            v,
            json!({
                "ok": true, "knownList": "learned",
                "devices": [
                    { "mac": mac(3), "ipv4": ["192.0.2.3"], "hostname": "",
                      "firstUnix": T0, "lastUnix": T0 + 102,
                      "knownOnPi": false, "known": false, "label": "",
                      "exemptOnPi": false, "exempt": false,
                      "blockedOnPi": false, "blocked": false },
                    { "mac": mac(2), "ipv4": ["192.0.2.2"], "hostname": "",
                      "firstUnix": T0, "lastUnix": T0 + 101,
                      "knownOnPi": true, "known": false, "label": "",
                      "exemptOnPi": false, "exempt": false,
                      "blockedOnPi": false, "blocked": false },
                    { "mac": mac(1), "ipv4": ["192.0.2.1"], "hostname": "",
                      "firstUnix": T0, "lastUnix": T0 + 100,
                      "knownOnPi": false, "known": true, "label": "Printer",
                      "exemptOnPi": false, "exempt": false,
                      "blockedOnPi": false, "blocked": false },
                ],
                "knownOffline": [
                    { "mac": mac(9), "label": "Old NAS", "firstSeen": 50 },
                    { "mac": mac(10), "label": "", "firstSeen": 60 },
                ],
                "exemptOffline": [],
                "exemptOnPiOnly": [],
                "exemptDefault": false,
                "exemptDefaultOnPi": false,
                "blockOffline": [],
                "blockOnPiOnly": [],
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
        assert_eq!(v["exemptOffline"], json!([]));
    }

    /// A `devices` result without the front panel's fields: `rev` on top, and
    /// `labelOnPi`, `gateLeftSecs`, `fixed` and `always` on every device.
    fn without_panel_fields(mut v: Value) -> Value {
        v.as_object_mut().unwrap().remove("rev");
        for d in v["devices"].as_array_mut().unwrap() {
            let d = d.as_object_mut().unwrap();
            for key in ["labelOnPi", "gateLeftSecs", "fixed", "always"] {
                d.remove(key);
            }
        }
        v
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

    // -- exempt and unexempt ---------------------------------------------------

    const UNSUPPORTED: &str = "the Pi's software does not support ADS PASS devices yet";

    impl Rig {
        fn exempt(&mut self, mac: &str, label: Option<&str>) -> ActionResult {
            let path = self.path();
            bare(exempt(&mut self.api, &path, T0 + 999, mac, label))
        }
        fn unexempt(&mut self, mac: &str) -> ActionResult {
            let path = self.path();
            bare(unexempt(&mut self.api, &path, T0, mac))
        }
        fn exempt_puts(&self) -> Vec<Value> {
            self.exempt_puts_raw()
                .into_iter()
                .map(without_if_rev)
                .collect()
        }
        fn exempt_puts_raw(&self) -> Vec<Value> {
            self.pi.with(|s| s.exempt_puts.clone())
        }
        fn pi_exempt(&self) -> Vec<String> {
            self.pi.with(|s| s.exempt.clone())
        }
    }

    #[test]
    fn exempt_adds_the_device_to_both_lists_and_pushes_the_known_list_then_the_exempt_list() {
        let mut rig = Rig::new();
        let v = rig.exempt(&mac(2), Some("Smart TV")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "label": "Smart TV", "known": 1,
                   "exempt": 1, "pushed": true, "exemptPushed": true})
        );
        let store = rig.store();
        // Named by the owner, so it is known and the Pi raises no alert.
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert_eq!(store.known[0].label.as_deref(), Some("Smart TV"));
        assert_eq!(store.known[0].first_seen, T0, "when the Pi first saw it");
        assert_eq!(store.exempt_macs(), vec![mac(2)]);
        assert_eq!(store.exempt[0].label.as_deref(), Some("Smart TV"));
        assert_eq!(store.exempt[0].first_seen, T0);
        assert!(!store.push_due() && !store.exempt_push_due());
        assert_eq!(
            rig.known_puts(),
            vec![json!({"known": [mac(2)], "append": false, "complete": true})]
        );
        assert_eq!(rig.exempt_puts(), vec![json!({"exempt": [mac(2)]})]);
        assert_eq!(rig.pi_known(), vec![mac(2)]);
        assert_eq!(rig.pi_exempt(), vec![mac(2)]);
        let at = |p: &str| rig.pi.with(|s| s.log.iter().position(|l| l.starts_with(p)));
        assert!(at("PUT /api/qbp/devices/known") < at("PUT /api/qbp/devices/exempt"));
        // The edit of the known list is the same as `know` makes.
        let mut plain = Rig::new();
        plain.know(&mac(2), Some("Smart TV")).unwrap();
        assert_eq!(plain.store().known, store.known);
    }

    #[test]
    fn exempt_of_a_device_the_pi_has_not_seen_starts_now_and_may_have_no_label() {
        let mut rig = Rig::new();
        let v = rig.exempt(&mac(50), None).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(50), "known": 1, "exempt": 1,
                   "pushed": true, "exemptPushed": true}),
            "no label, no label key"
        );
        let store = rig.store();
        assert_eq!(store.known[0].first_seen, T0 + 999);
        assert_eq!(store.exempt[0].first_seen, T0 + 999);
    }

    #[test]
    fn exempt_keeps_a_label_that_was_there_and_replaces_it_when_given_a_new_one() {
        let mut rig = Rig::new();
        rig.know(&mac(2), Some("Phone")).unwrap();
        let v = rig.exempt(&mac(2), None).unwrap();
        assert_eq!(v["label"], "Phone", "the known label stays");
        assert_eq!(rig.store().exempt[0].label, None);
        assert_eq!(rig.store().known_gen, 1, "no change of the known list");
        let v = rig.exempt(&mac(2), Some("Work phone")).unwrap();
        assert_eq!(v["label"], "Work phone");
        let store = rig.store();
        assert_eq!(store.known[0].label.as_deref(), Some("Work phone"));
        assert_eq!(store.exempt[0].label.as_deref(), Some("Work phone"));
        assert_eq!((store.known.len(), store.exempt.len()), (1, 1));
        assert_eq!(store.exempt_gen, 2);
        // Asking again changes nothing and still pushes (as `know` does).
        let before = rig.exempt_puts().len();
        rig.exempt(&mac(2), Some("Work phone")).unwrap();
        assert_eq!(rig.store().exempt_gen, 2);
        assert_eq!(rig.exempt_puts().len(), before + 1);
    }

    #[test]
    fn exempt_cuts_a_long_label_at_64_characters() {
        let mut rig = Rig::new();
        let v = rig.exempt(&mac(1), Some(&"é".repeat(100))).unwrap();
        assert_eq!(v["label"].as_str().unwrap().chars().count(), 64);
        assert_eq!(
            rig.store().exempt[0]
                .label
                .as_deref()
                .unwrap()
                .chars()
                .count(),
            64
        );
    }

    #[test]
    fn the_first_exempt_on_an_empty_known_list_seeds_it_from_a_list_the_pi_learned() {
        let mut rig = Rig::new();
        pi_with_list(&rig, "learned", 31, 30);
        let v = rig.exempt(&mac(31), Some("Tablet")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(31), "label": "Tablet", "known": 31,
                   "exempt": 1, "seeded": 30, "pushed": true, "exemptPushed": true})
        );
        let sent: Vec<String> = (1..=31).map(mac).collect();
        assert_eq!(rig.pi_known(), sent, "nothing the Pi learned is lost");
        assert_eq!(rig.pi_exempt(), vec![mac(31)]);
    }

    #[test]
    fn more_than_64_exempt_devices_are_refused_and_nothing_is_changed_or_pushed() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            for i in 1..=wdstore::MAX_EXEMPT {
                s.know(&mac(i), None, T0);
                s.add_exempt(&mac(i), None, T0);
            }
        });
        let before = rig.store();
        let e = err(rig.exempt(&mac(5000), Some("One too many")));
        assert_eq!(e.code, "full");
        assert!(
            e.detail.contains("ADS PASS") && e.detail.contains("64"),
            "{}",
            e.detail
        );
        assert_eq!(rig.store(), before, "not even the known list was touched");
        assert!(rig.known_puts().is_empty() && rig.exempt_puts().is_empty());
        // A device that is there can still get a label.
        let v = rig.exempt(&mac(7), Some("Seventh")).unwrap();
        assert_eq!(
            (v["exempt"].clone(), v["exemptPushed"].clone()),
            (json!(64), json!(true))
        );
        // And a place frees up when one is taken off.
        rig.unexempt(&mac(1)).unwrap();
        assert_eq!(rig.exempt(&mac(5000), None).unwrap()["exempt"], 64);
    }

    #[test]
    fn a_device_cannot_be_exempt_without_being_known() {
        // The known list is full and the device is not on it: it cannot be
        // marked known, so the exempt list is not changed either.
        let mut rig = Rig::new();
        rig.edit(|s| {
            for i in 1..=wdstore::MAX_ENTRIES {
                s.know(&mac(i), None, T0);
            }
        });
        let before = rig.store();
        let e = err(rig.exempt(&mac(5000), None));
        assert_eq!(e.code, "full");
        assert!(e.detail.contains("known"), "{}", e.detail);
        assert_eq!(rig.store(), before);
        assert!(rig.known_puts().is_empty() && rig.exempt_puts().is_empty());
        // One that is known already goes on the exempt list.
        let v = rig.exempt(&mac(7), None).unwrap();
        assert_eq!(
            (v["known"].clone(), v["exempt"].clone()),
            (json!(1024), json!(1))
        );
    }

    #[test]
    fn on_an_older_pi_exempt_is_saved_and_reported_as_not_supported() {
        let mut rig = Rig::on(FakePi::without_exempt(20));
        let v = rig.exempt(&mac(2), Some("Smart TV")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "label": "Smart TV", "known": 1, "exempt": 1,
                   "pushed": true, "exemptPushed": false, "exemptPushError": UNSUPPORTED})
        );
        let store = rig.store();
        assert_eq!(store.exempt_macs(), vec![mac(2)]);
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert!(!store.push_due(), "the known list went out");
        assert!(
            store.exempt_push_due(),
            "the watcher tries again in a session"
        );
        assert_eq!(rig.pi_known(), vec![mac(2)]);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 1);
        // The same for taking it off again.
        let v = rig.unexempt(&mac(2)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "exempt": 0,
                   "exemptPushed": false, "exemptPushError": UNSUPPORTED})
        );
        assert!(rig.store().exempt.is_empty());
    }

    #[test]
    fn on_a_real_pihole_exempt_still_edits_this_pcs_lists() {
        let mut rig = Rig::on(FakePi::pihole_only(20));
        let v = rig.exempt(&mac(2), Some("TV")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "label": "TV", "known": 1, "exempt": 1,
                   "pushed": false, "pushError": "absent",
                   "exemptPushed": false, "exemptPushError": UNSUPPORTED})
        );
        let store = rig.store();
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert_eq!(store.exempt_macs(), vec![mac(2)]);
        assert!(store.push_due() && store.exempt_push_due());
        let v = rig.unexempt(&mac(2)).unwrap();
        assert_eq!(
            (v["exemptPushed"].clone(), v["exempt"].clone()),
            (json!(false), json!(0))
        );
        assert!(rig.store().exempt.is_empty());
    }

    #[test]
    fn a_failed_exempt_push_leaves_the_edit_and_the_known_push_is_unaffected() {
        let mut rig = Rig::new();
        rig.pi.with(|s| s.fail_exempt = true);
        let v = rig.exempt(&mac(2), None).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["pushed"], true, "the known list went out");
        assert_eq!(v["exemptPushed"], false);
        assert!(
            v["exemptPushError"].as_str().unwrap().contains("500"),
            "{v}"
        );
        let store = rig.store();
        assert_eq!(store.exempt_macs(), vec![mac(2)]);
        assert!(!store.push_due() && store.exempt_push_due());

        rig.pi.with(|s| s.fail_exempt = false);
        let v = rig.exempt(&mac(3), None).unwrap();
        assert_eq!(v["exemptPushed"], true);
        assert!(v.get("exemptPushError").is_none());
        assert_eq!(
            rig.pi_exempt(),
            vec![mac(2), mac(3)],
            "both edits went out together"
        );
        assert!(!rig.store().exempt_push_due());
    }

    #[test]
    fn a_failed_known_push_does_not_keep_the_exempt_list_from_going_out() {
        let mut rig = Rig::new();
        rig.pi.with(|s| s.fail_known = true);
        let v = rig.exempt(&mac(2), None).unwrap();
        assert_eq!(v["pushed"], false);
        assert!(v["pushError"].as_str().unwrap().contains("500"));
        assert_eq!(v["exemptPushed"], true);
        assert_eq!(rig.pi_exempt(), vec![mac(2)]);
        let store = rig.store();
        assert!(store.push_due() && !store.exempt_push_due());
        rig.pi.with(|s| s.fail_known = false);
        let v = rig.exempt(&mac(2), None).unwrap();
        assert_eq!(
            (v["pushed"].clone(), v["exemptPushed"].clone()),
            (json!(true), json!(true))
        );
        assert!(!rig.store().push_due() && !rig.store().exempt_push_due());
    }

    #[test]
    fn unexempt_removes_the_device_pushes_the_list_and_leaves_it_known() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), Some("A")).unwrap();
        rig.exempt(&mac(2), None).unwrap();
        let known_pushes = rig.known_puts().len();
        let v = rig.unexempt(&mac(1)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(1), "exempt": 1, "exemptPushed": true})
        );
        assert_eq!(rig.pi_exempt(), vec![mac(2)]);
        let v = rig.unexempt(&mac(2)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "exempt": 0, "exemptPushed": true})
        );
        let body = |m: &[String]| json!({ "exempt": m });
        assert_eq!(
            rig.exempt_puts(),
            vec![
                body(&[mac(1)]),
                body(&[mac(1), mac(2)]),
                body(&[mac(2)]),
                body(&[]),
            ],
            "the emptied list is pushed too"
        );
        assert!(rig.pi_exempt().is_empty());
        let store = rig.store();
        assert!(store.exempt.is_empty() && !store.exempt_push_due());
        assert_eq!(store.known_macs(), vec![mac(1), mac(2)], "still known");
        assert_eq!(
            rig.known_puts().len(),
            known_pushes,
            "the known list is not pushed"
        );
        assert_eq!(rig.pi_known(), vec![mac(1), mac(2)]);
    }

    #[test]
    fn unexempt_of_a_device_that_is_not_listed_is_not_found_and_pushes_nothing() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), None).unwrap();
        let before = rig.pi.with(|s| s.log.len());
        let e = err(rig.unexempt(&mac(2)));
        assert_eq!(e.code, "not-found");
        assert!(e.detail.contains("ADS PASS"), "{}", e.detail);
        // It looked at the Pi's list first (the front panel may have put the
        // device on it), and that is all.
        assert_eq!(rig.pi.with(|s| s.log.len()), before + 1);
        assert_eq!(
            rig.pi.with(|s| s.log.last().cloned()).as_deref(),
            Some("GET /api/qbp/devices HTTP/1.1")
        );
        assert_eq!(rig.store().exempt_macs(), vec![mac(1)]);
        // Known but not exempt is just as not found.
        rig.know(&mac(3), None).unwrap();
        assert_eq!(err(rig.unexempt(&mac(3))).code, "not-found");
    }

    #[test]
    fn exempt_and_unexempt_need_a_writable_store_and_push_nothing_without_one() {
        let mut rig = Rig::new();
        let bad = unwritable(rig.dir.path());
        let e = exempt(&mut rig.api, &bad, T0, &mac(1), None).unwrap_err();
        assert_eq!(e.code, "store");
        assert!(e.detail.contains("ADS PASS list"), "{}", e.detail);
        let e = unexempt(&mut rig.api, &bad, T0, &mac(1)).unwrap_err();
        assert_eq!(e.code, "store");
        assert!(rig.known_puts().is_empty() && rig.exempt_puts().is_empty());
    }

    #[test]
    fn exempt_without_an_answer_from_devices_still_works_like_know() {
        let mut rig = Rig::new();
        pi_with_list(&rig, "learned", 10, 8);
        rig.pi.with(|s| s.fail_qbp = true);
        let v = rig.exempt(&mac(10), None).unwrap();
        assert_eq!(v["known"], 1, "it cannot know what to seed from");
        assert!(v.get("seeded").is_none());
        assert_eq!(
            (v["pushed"].clone(), v["exemptPushed"].clone()),
            (json!(false), json!(false))
        );
        assert_eq!(rig.store().exempt_macs(), vec![mac(10)]);
    }

    #[test]
    fn devices_marks_exempt_devices_on_both_sides_and_lists_the_rest() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            s.know(&mac(1), Some("TV"), 40);
            s.add_exempt(&mac(1), Some("TV"), 40);
            s.know(&mac(9), Some("Console"), 50);
            s.add_exempt(&mac(9), Some("Console"), 50);
            s.add_exempt(&mac(10), None, 60);
        });
        rig.pi.with(|s| {
            // What the Pi has: this PC's list as pushed earlier (mac 1 only)
            // and two addresses of its own config file.
            s.exempt = vec![mac(1)];
            s.exempt_config = vec![mac(3), mac(40)];
        });
        let v = rig.devices().unwrap();
        let by_mac = |m: String| {
            v["devices"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["mac"] == json!(m))
                .unwrap()
                .clone()
        };
        let flags = |m: String| {
            let d = by_mac(m);
            (d["exempt"].clone(), d["exemptOnPi"].clone())
        };
        assert_eq!(flags(mac(1)), (json!(true), json!(true)));
        assert_eq!(
            flags(mac(3)),
            (json!(false), json!(true)),
            "from the Pi's config"
        );
        assert_eq!(flags(mac(2)), (json!(false), json!(false)));
        assert_eq!(
            v["exemptOffline"],
            json!([
                { "mac": mac(9), "label": "Console", "firstSeen": 50 },
                { "mac": mac(10), "label": "", "firstSeen": 60 },
            ]),
            "on this PC's list, not among the Pi's devices"
        );
        assert_eq!(
            v["exemptOnPiOnly"],
            json!([mac(3), mac(40)]),
            "on the Pi's list, not on this PC's"
        );
        assert_eq!(rig.store().exempt_gen, 3, "looking changes nothing");
    }

    #[test]
    fn devices_from_an_older_pi_has_no_exempt_flags_and_nothing_only_on_the_pi() {
        let mut rig = Rig::on(FakePi::without_exempt(20));
        rig.edit(|s| {
            s.know(&mac(1), None, 40);
            s.add_exempt(&mac(1), None, 40);
            s.add_exempt(&mac(9), Some("Gone"), 50);
        });
        let v = rig.devices().unwrap();
        for d in v["devices"].as_array().unwrap() {
            assert_eq!(d["exemptOnPi"], false, "{d}");
            assert_eq!(d["exempt"], d["mac"] == json!(mac(1)), "{d}");
        }
        assert_eq!(v["exemptOnPiOnly"], json!([]));
        assert_eq!(
            v["exemptOffline"],
            json!([{ "mac": mac(9), "label": "Gone", "firstSeen": 50 }])
        );
    }

    // -- exempt by default, block, unblock and block-this -----------------------

    const UNSUPPORTED_POLICY: &str =
        "the Pi's software does not support exempt-by-default blocking yet";

    impl Rig {
        fn exempt_default(&mut self, on: bool) -> ActionResult {
            let path = self.path();
            bare(exempt_default(&mut self.api, &path, T0, on))
        }
        fn block(&mut self, mac: &str, label: Option<&str>) -> ActionResult {
            let path = self.path();
            bare(block(&mut self.api, &path, T0 + 999, mac, label))
        }
        fn unblock(&mut self, mac: &str) -> ActionResult {
            let path = self.path();
            bare(unblock(&mut self.api, &path, T0, mac))
        }
        fn policy_puts(&self) -> Vec<Value> {
            self.policy_puts_raw()
                .into_iter()
                .map(without_if_rev)
                .collect()
        }
        fn policy_puts_raw(&self) -> Vec<Value> {
            self.pi.with(|s| s.policy_puts.clone())
        }
        fn pi_block(&self) -> Vec<String> {
            self.pi.with(|s| s.policy_block.clone())
        }
        fn at(&self, prefix: &str) -> Option<usize> {
            self.pi
                .with(|s| s.log.iter().position(|l| l.starts_with(prefix)))
        }
    }

    fn policy_body(on: bool, macs: &[String]) -> Value {
        json!({ "exempt_default": on, "block": macs })
    }

    #[test]
    fn exempt_default_on_sets_the_mode_pushes_the_policy_and_warns() {
        let mut rig = Rig::new();
        let v = rig.exempt_default(true).unwrap();
        let note = v["note"].as_str().expect("a note").to_string();
        assert!(
            note.contains("block list") && note.contains("ADS PASS") && note.contains("threat"),
            "{note}"
        );
        assert_eq!(
            v,
            json!({"ok": true, "exemptDefault": true, "block": 0,
                   "policyPushed": true, "note": note})
        );
        assert_eq!(rig.policy_puts(), vec![policy_body(true, &[])]);
        assert!(rig.pi.with(|s| s.exempt_default));
        let store = rig.store();
        assert!(store.exempt_default && !store.policy_push_due());
        // Neither list was touched or pushed.
        assert!(rig.known_puts().is_empty() && rig.exempt_puts().is_empty());
    }

    #[test]
    fn exempt_default_off_turns_the_mode_off_keeps_the_block_list_and_has_no_note() {
        let mut rig = Rig::new();
        rig.block(&mac(1), Some("PC")).unwrap();
        rig.exempt_default(true).unwrap();
        let v = rig.exempt_default(false).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "exemptDefault": false, "block": 1, "policyPushed": true})
        );
        // The block list goes with it: it is part of the policy.
        assert_eq!(
            rig.policy_puts().last().unwrap(),
            &policy_body(false, &[mac(1)])
        );
        assert!(!rig.pi.with(|s| s.exempt_default));
        assert_eq!(rig.pi_block(), vec![mac(1)]);
        let store = rig.store();
        assert!(!store.exempt_default);
        assert_eq!(store.block_macs(), vec![mac(1)], "kept for later");
    }

    #[test]
    fn exempt_default_pushes_on_every_call_also_when_nothing_changed() {
        let mut rig = Rig::new();
        rig.exempt_default(true).unwrap();
        let gen = rig.store().policy_gen;
        let v = rig.exempt_default(true).unwrap();
        assert_eq!(v["policyPushed"], true);
        assert!(v["note"].is_string(), "the warning is not shown only once");
        assert_eq!(rig.policy_puts().len(), 2);
        assert_eq!(rig.store().policy_gen, gen, "nothing was edited");
        // Off when it is off already: the default policy goes too (it clears
        // what a Pi may still hold).
        let mut rig = Rig::new();
        let v = rig.exempt_default(false).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "exemptDefault": false, "block": 0, "policyPushed": true})
        );
        assert_eq!(rig.policy_puts(), vec![policy_body(false, &[])]);
    }

    #[test]
    fn on_a_pi_without_the_policy_exempt_default_is_saved_and_reported_as_not_supported() {
        let mut rig = Rig::on(FakePi::without_policy(20));
        let v = rig.exempt_default(true).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["exemptDefault"], true);
        assert_eq!(v["policyPushed"], false);
        assert_eq!(v["policyPushError"], UNSUPPORTED_POLICY);
        assert!(v["note"].is_string());
        let store = rig.store();
        assert!(store.exempt_default);
        assert!(
            store.policy_push_due(),
            "the watcher tries again in a session"
        );
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/policy"), 1);
        // The same for taking a device off the block list again.
        rig.edit(|s| s.add_block(&mac(1), None, T0));
        let v = rig.unblock(&mac(1)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(1), "block": 0,
                   "policyPushed": false, "policyPushError": UNSUPPORTED_POLICY})
        );
    }

    #[test]
    fn on_a_real_pihole_the_policy_verbs_still_edit_this_pcs_store() {
        let mut rig = Rig::on(FakePi::pihole_only(20));
        let v = rig.exempt_default(true).unwrap();
        assert_eq!(
            (v["policyPushed"].clone(), v["policyPushError"].clone()),
            (json!(false), json!(UNSUPPORTED_POLICY))
        );
        let v = rig.block(&mac(2), Some("PC")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "label": "PC", "known": 1, "block": 1,
                   "pushed": false, "pushError": "absent",
                   "policyPushed": false, "policyPushError": UNSUPPORTED_POLICY})
        );
        let store = rig.store();
        assert!(store.exempt_default);
        assert_eq!(store.block_macs(), vec![mac(2)]);
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert!(store.push_due() && store.policy_push_due());
        let v = rig.unblock(&mac(2)).unwrap();
        assert_eq!(v["block"], 0);
        assert!(rig.store().block.is_empty());
    }

    #[test]
    fn a_failed_policy_push_leaves_the_edit_and_the_other_pushes_are_unaffected() {
        let mut rig = Rig::new();
        rig.pi.with(|s| s.fail_policy = true);
        let v = rig.block(&mac(2), None).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["pushed"], true, "the known list went out");
        assert_eq!(v["policyPushed"], false);
        assert!(
            v["policyPushError"].as_str().unwrap().contains("500"),
            "{v}"
        );
        let store = rig.store();
        assert_eq!(store.block_macs(), vec![mac(2)]);
        assert!(!store.push_due() && store.policy_push_due());

        rig.pi.with(|s| s.fail_policy = false);
        let v = rig.block(&mac(3), None).unwrap();
        assert_eq!(v["policyPushed"], true);
        assert!(v.get("policyPushError").is_none());
        assert_eq!(
            rig.pi_block(),
            vec![mac(2), mac(3)],
            "both edits went out together"
        );
        assert!(!rig.store().policy_push_due());
    }

    #[test]
    fn a_failed_known_push_does_not_keep_the_policy_from_going_out() {
        let mut rig = Rig::new();
        rig.pi.with(|s| s.fail_known = true);
        let v = rig.block(&mac(2), None).unwrap();
        assert_eq!(v["pushed"], false);
        assert!(v["pushError"].as_str().unwrap().contains("500"));
        assert_eq!(v["policyPushed"], true);
        assert_eq!(rig.pi_block(), vec![mac(2)]);
        let store = rig.store();
        assert!(store.push_due() && !store.policy_push_due());
        // And a failed exempt push (the device was exempt) does not either.
        let mut rig = Rig::new();
        rig.exempt(&mac(2), None).unwrap();
        rig.pi.with(|s| s.fail_exempt = true);
        let v = rig.block(&mac(2), None).unwrap();
        assert_eq!(v["exemptPushed"], false);
        assert!(v["exemptPushError"].as_str().unwrap().contains("500"));
        assert_eq!(v["policyPushed"], true);
        assert_eq!(rig.pi_block(), vec![mac(2)]);
        assert!(rig.store().exempt_push_due() && !rig.store().policy_push_due());
    }

    #[test]
    fn block_adds_the_device_to_both_lists_and_pushes_the_known_list_then_the_policy() {
        let mut rig = Rig::new();
        let v = rig.block(&mac(2), Some("Work laptop")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "label": "Work laptop", "known": 1,
                   "block": 1, "pushed": true, "policyPushed": true})
        );
        let store = rig.store();
        // Named by the owner, so it is known and the Pi raises no alert.
        assert_eq!(store.known_macs(), vec![mac(2)]);
        assert_eq!(store.known[0].label.as_deref(), Some("Work laptop"));
        assert_eq!(store.known[0].first_seen, T0, "when the Pi first saw it");
        assert_eq!(store.block_macs(), vec![mac(2)]);
        assert_eq!(store.block[0].label.as_deref(), Some("Work laptop"));
        assert_eq!(store.block[0].first_seen, T0);
        assert!(!store.push_due() && !store.policy_push_due());
        assert!(!store.exempt_push_due(), "the exempt list was not touched");
        assert_eq!(
            rig.known_puts(),
            vec![json!({"known": [mac(2)], "append": false, "complete": true})]
        );
        // The mode is not changed by blocking a device.
        assert_eq!(rig.policy_puts(), vec![policy_body(false, &[mac(2)])]);
        assert_eq!(rig.pi_known(), vec![mac(2)]);
        assert_eq!(rig.pi_block(), vec![mac(2)]);
        assert_eq!(rig.pi.count("PUT /api/qbp/devices/exempt"), 0);
        assert!(rig.at("PUT /api/qbp/devices/known") < rig.at("PUT /api/qbp/devices/policy"));
        // The edit of the known list is the same as `know` makes.
        let mut plain = Rig::new();
        plain.know(&mac(2), Some("Work laptop")).unwrap();
        assert_eq!(plain.store().known, store.known);
        // It follows the mode that is set.
        rig.exempt_default(true).unwrap();
        rig.block(&mac(3), None).unwrap();
        assert_eq!(
            rig.policy_puts().last().unwrap(),
            &policy_body(true, &[mac(2), mac(3)])
        );
    }

    #[test]
    fn block_of_an_exempt_device_takes_it_off_the_exempt_list_and_pushes_that_list_too() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), Some("TV")).unwrap();
        rig.exempt(&mac(2), None).unwrap();
        let exempt_pushes = rig.exempt_puts().len();
        let v = rig.block(&mac(1), None).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(1), "label": "TV", "known": 2, "block": 1,
                   "unexempted": true, "exempt": 1,
                   "pushed": true, "exemptPushed": true, "policyPushed": true})
        );
        let store = rig.store();
        assert_eq!(store.exempt_macs(), vec![mac(2)]);
        assert_eq!(store.block_macs(), vec![mac(1)]);
        assert!(!store.exempt_push_due() && !store.policy_push_due());
        // The known list keeps the label it had; the block entry has none,
        // as none was given (the same rule as for an exempt entry).
        assert_eq!(store.block[0].label, None);
        assert_eq!(store.known[0].label.as_deref(), Some("TV"));
        assert_eq!(rig.exempt_puts().len(), exempt_pushes + 1);
        assert_eq!(rig.pi_exempt(), vec![mac(2)]);
        assert_eq!(rig.pi_block(), vec![mac(1)]);
        // Known list, then the exempt list, then the policy.
        let known = rig.pi.with(|s| {
            s.log
                .iter()
                .rposition(|l| l.starts_with("PUT /api/qbp/devices/known"))
        });
        let exempt = rig.pi.with(|s| {
            s.log
                .iter()
                .rposition(|l| l.starts_with("PUT /api/qbp/devices/exempt"))
        });
        let policy = rig.at("PUT /api/qbp/devices/policy");
        assert!(known < exempt && exempt < policy);

        // A device that is not exempt: nothing about the exempt list.
        let v = rig.block(&mac(5), None).unwrap();
        for key in ["unexempted", "exempt", "exemptPushed", "exemptPushError"] {
            assert!(v.get(key).is_none(), "{key} in {v}");
        }
        assert_eq!(rig.exempt_puts().len(), exempt_pushes + 1);
        // Blocking the same device again is no change of the exempt list.
        let v = rig.block(&mac(1), None).unwrap();
        assert!(v.get("unexempted").is_none());
    }

    #[test]
    fn block_keeps_a_label_that_was_there_and_replaces_it_when_given_a_new_one() {
        let mut rig = Rig::new();
        rig.block(&mac(1), Some("First")).unwrap();
        let v = rig.block(&mac(1), None).unwrap();
        assert_eq!(v["label"], "First");
        let v = rig.block(&mac(1), Some("Second")).unwrap();
        assert_eq!(v["label"], "Second");
        let store = rig.store();
        assert_eq!(store.block[0].label.as_deref(), Some("Second"));
        assert_eq!(store.known[0].label.as_deref(), Some("Second"));
        assert_eq!(store.block.len(), 1);
        // A long label is cut at 64 characters, as for the other lists.
        let v = rig.block(&mac(2), Some(&"x".repeat(100))).unwrap();
        assert_eq!(v["label"].as_str().unwrap().chars().count(), 64);
    }

    #[test]
    fn the_first_block_on_an_empty_known_list_seeds_it_from_a_list_the_pi_learned() {
        let mut rig = Rig::new();
        pi_with_list(&rig, "learned", 31, 30);
        let v = rig.block(&mac(31), Some("Tablet")).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(31), "label": "Tablet", "known": 31, "block": 1,
                   "seeded": 30, "pushed": true, "policyPushed": true})
        );
        let sent: Vec<String> = (1..=31).map(mac).collect();
        assert_eq!(rig.pi_known(), sent, "nothing the Pi learned is lost");
        assert_eq!(rig.pi_block(), vec![mac(31)]);
    }

    #[test]
    fn more_than_64_blocked_devices_are_refused_and_nothing_is_changed_or_pushed() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            for i in 1..=wdstore::MAX_BLOCK {
                s.know(&mac(i), None, T0);
                s.add_block(&mac(i), None, T0);
            }
        });
        let before = rig.store();
        let e = err(rig.block(&mac(5000), Some("One too many")));
        assert_eq!(e.code, "full");
        assert!(
            e.detail.contains("block") && e.detail.contains("64"),
            "{}",
            e.detail
        );
        assert_eq!(rig.store(), before, "not even the known list was touched");
        assert!(rig.known_puts().is_empty() && rig.policy_puts().is_empty());
        // A device that is there can still get a label.
        let v = rig.block(&mac(7), Some("Seventh")).unwrap();
        assert_eq!(
            (v["block"].clone(), v["policyPushed"].clone()),
            (json!(64), json!(true))
        );
        // And a place frees up when one is taken off.
        rig.unblock(&mac(1)).unwrap();
        assert_eq!(rig.block(&mac(5000), None).unwrap()["block"], 64);
    }

    #[test]
    fn a_device_cannot_be_blocked_without_being_known() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            for i in 1..=wdstore::MAX_ENTRIES {
                s.know(&mac(i), None, T0);
            }
        });
        let before = rig.store();
        let e = err(rig.block(&mac(5000), None));
        assert_eq!(e.code, "full");
        assert!(e.detail.contains("known"), "{}", e.detail);
        assert_eq!(rig.store(), before);
        assert!(rig.known_puts().is_empty() && rig.policy_puts().is_empty());
        // One that is known already goes on the block list.
        let v = rig.block(&mac(7), None).unwrap();
        assert_eq!(
            (v["known"].clone(), v["block"].clone()),
            (json!(1024), json!(1))
        );
    }

    #[test]
    fn unblock_removes_the_device_pushes_the_policy_and_leaves_it_known() {
        let mut rig = Rig::new();
        rig.block(&mac(1), Some("A")).unwrap();
        rig.block(&mac(2), None).unwrap();
        let known_pushes = rig.known_puts().len();
        let v = rig.unblock(&mac(1)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(1), "block": 1, "policyPushed": true})
        );
        assert_eq!(rig.pi_block(), vec![mac(2)]);
        let v = rig.unblock(&mac(2)).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": mac(2), "block": 0, "policyPushed": true})
        );
        assert_eq!(
            rig.policy_puts(),
            vec![
                policy_body(false, &[mac(1)]),
                policy_body(false, &[mac(1), mac(2)]),
                policy_body(false, &[mac(2)]),
                policy_body(false, &[]),
            ],
            "the emptied list is pushed too"
        );
        let store = rig.store();
        assert!(store.block.is_empty() && !store.policy_push_due());
        assert_eq!(store.known_macs(), vec![mac(1), mac(2)], "still known");
        assert_eq!(rig.known_puts().len(), known_pushes, "not pushed");
    }

    #[test]
    fn unblock_of_a_device_that_is_not_listed_is_not_found_and_pushes_nothing() {
        let mut rig = Rig::new();
        rig.block(&mac(1), None).unwrap();
        let before = rig.pi.with(|s| s.log.len());
        let e = err(rig.unblock(&mac(2)));
        assert_eq!(e.code, "not-found");
        assert!(e.detail.contains("block"), "{}", e.detail);
        assert_eq!(
            rig.pi.with(|s| s.log.len()),
            before + 1,
            "it read the Pi's list, as unexempt does"
        );
        assert_eq!(
            rig.pi.with(|s| s.log.last().cloned()).as_deref(),
            Some("GET /api/qbp/devices HTTP/1.1")
        );
        assert_eq!(rig.store().block_macs(), vec![mac(1)]);
        // Known (or exempt) but not blocked is just as not found.
        rig.exempt(&mac(3), None).unwrap();
        assert_eq!(err(rig.unblock(&mac(3))).code, "not-found");
    }

    #[test]
    fn the_policy_verbs_need_a_writable_store_and_push_nothing_without_one() {
        let mut rig = Rig::new();
        let bad = unwritable(rig.dir.path());
        let e = exempt_default(&mut rig.api, &bad, T0, true).unwrap_err();
        assert_eq!(e.code, "store");
        assert!(e.detail.contains("policy"), "{}", e.detail);
        let e = block(&mut rig.api, &bad, T0, &mac(1), None).unwrap_err();
        assert_eq!(e.code, "store");
        let e = unblock(&mut rig.api, &bad, T0, &mac(1)).unwrap_err();
        assert_eq!(e.code, "store");
        assert!(rig.known_puts().is_empty() && rig.policy_puts().is_empty());
    }

    #[test]
    fn block_without_an_answer_from_devices_still_works_like_know() {
        let mut rig = Rig::new();
        pi_with_list(&rig, "learned", 10, 8);
        rig.pi.with(|s| s.fail_qbp = true);
        let v = rig.block(&mac(10), None).unwrap();
        assert_eq!(v["known"], 1, "it cannot know what to seed from");
        assert!(v.get("seeded").is_none());
        assert_eq!(
            (v["pushed"].clone(), v["policyPushed"].clone()),
            (json!(false), json!(false))
        );
        assert_eq!(rig.store().block_macs(), vec![mac(10)]);
    }

    // block-this

    /// A fake `/proc/net/route` and `/sys/class/net`, in a temporary
    /// directory of its own.
    struct FakeHost {
        dir: tempfile::TempDir,
    }

    const ROUTE_HEADER: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT";

    impl FakeHost {
        fn new(route_lines: &[&str]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let h = Self { dir };
            h.set_route(route_lines);
            std::fs::create_dir_all(h.dir.path().join("net")).unwrap();
            h.set_hostname("testbox\n");
            h
        }
        fn set_route(&self, lines: &[&str]) {
            let mut t = format!("{ROUTE_HEADER}\n");
            for l in lines {
                t.push_str(l);
                t.push('\n');
            }
            std::fs::write(self.dir.path().join("route"), t).unwrap();
        }
        fn set_hostname(&self, h: &str) {
            std::fs::write(self.dir.path().join("hostname"), h).unwrap();
        }
        /// An interface with `address` in its sysfs folder (`None`: no file).
        fn iface(&self, name: &str, address: Option<&str>) {
            let d = self.dir.path().join("net").join(name);
            std::fs::create_dir_all(&d).unwrap();
            if let Some(a) = address {
                std::fs::write(d.join("address"), a).unwrap();
            }
        }
        fn files(&self) -> HostFiles {
            HostFiles {
                route: self.dir.path().join("route"),
                sys_class_net: self.dir.path().join("net"),
                hostname: self.dir.path().join("hostname"),
            }
        }
    }

    /// A route line as the kernel writes it: default (all zero) through
    /// `gw`, flags `flags` (3 = up and gateway), metric `metric`.
    fn default_via(iface: &str, flags: u32, metric: u32) -> String {
        format!("{iface}\t00000000\t0100A8C0\t{flags:04X}\t0\t0\t{metric}\t00000000\t0\t0\t0")
    }
    fn lan(iface: &str) -> String {
        format!("{iface}\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0")
    }

    impl Rig {
        fn block_this(&mut self, host: &FakeHost) -> ActionResult {
            let path = self.path();
            bare(block_this(&mut self.api, &path, T0 + 999, &host.files()))
        }
    }

    #[test]
    fn block_this_blocks_the_interface_of_the_default_route_labelled_with_the_hostname() {
        let host = FakeHost::new(&[&default_via("eth0", 3, 100), &lan("eth0")]);
        host.iface("eth0", Some("02:00:00:AA:BB:CC\n"));
        let mut rig = Rig::new();
        let v = rig.block_this(&host).unwrap();
        assert_eq!(
            v,
            json!({"ok": true, "mac": "02:00:00:aa:bb:cc", "label": "testbox",
                   "interface": "eth0", "known": 1, "block": 1,
                   "pushed": true, "policyPushed": true})
        );
        let store = rig.store();
        assert_eq!(store.block_macs(), vec!["02:00:00:aa:bb:cc".to_string()]);
        assert_eq!(store.block[0].label.as_deref(), Some("testbox"));
        assert!(store.is_known("02:00:00:aa:bb:cc"));
        assert_eq!(rig.pi_block(), vec!["02:00:00:aa:bb:cc".to_string()]);
    }

    #[test]
    fn block_this_takes_the_default_route_that_is_used_and_not_the_first_listed() {
        // Wi-Fi first in the table, but Ethernet has the lower metric.
        let host = FakeHost::new(&[
            &default_via("wlan0", 3, 600),
            &lan("wlan0"),
            &default_via("eth0", 3, 100),
        ]);
        host.iface("wlan0", Some("02:00:00:00:00:02\n"));
        host.iface("eth0", Some("02:00:00:00:00:01\n"));
        let mut rig = Rig::new();
        let v = rig.block_this(&host).unwrap();
        assert_eq!(
            (v["mac"].clone(), v["interface"].clone()),
            (json!(mac(1)), json!("eth0"))
        );
        // Equal metrics: the first one listed.
        host.set_route(&[&default_via("wlan0", 3, 100), &default_via("eth0", 3, 100)]);
        let v = rig.block_this(&host).unwrap();
        assert_eq!(v["interface"], "wlan0");
    }

    #[test]
    fn block_this_ignores_routes_that_are_not_up_or_not_default() {
        let host = FakeHost::new(&[
            // Not up (flags 2), a reject route (0x0203), a default route
            // with a destination that is not 0.0.0.0, and one with a mask.
            &default_via("down0", 2, 10),
            &default_via("rej0", 0x0203, 20),
            "net0\t0000A8C0\t0100A8C0\t0003\t0\t0\t30\t00000000\t0\t0\t0",
            "net1\t00000000\t0100A8C0\t0003\t0\t0\t40\t00FFFFFF\t0\t0\t0",
            // A point-to-point link: up, no gateway.
            &default_via("ppp0", 1, 700),
        ]);
        for n in ["down0", "rej0", "net0", "net1"] {
            host.iface(n, Some("02:00:00:00:00:09\n"));
        }
        host.iface("ppp0", Some("02:00:00:00:00:05\n"));
        let mut rig = Rig::new();
        let v = rig.block_this(&host).unwrap();
        assert_eq!(v["interface"], "ppp0");
        assert_eq!(v["mac"], mac(5));
    }

    #[test]
    fn block_this_without_a_default_route_is_refused_and_changes_nothing() {
        let mut rig = Rig::new();
        let before = rig.store();
        // Only the local network, and an empty table.
        for lines in [vec![lan("eth0")], vec![]] {
            let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
            let host = FakeHost::new(&lines);
            host.iface("eth0", Some("02:00:00:00:00:01\n"));
            let e = err(rig.block_this(&host));
            assert_eq!(e.code, "no-route");
            assert!(e.detail.contains("default route"), "{}", e.detail);
        }
        // A routing table that cannot be read says so.
        let host = FakeHost::new(&[]);
        std::fs::remove_file(host.dir.path().join("route")).unwrap();
        assert_eq!(err(rig.block_this(&host)).code, "no-route");
        assert_eq!(rig.store(), before);
        assert!(rig.known_puts().is_empty() && rig.policy_puts().is_empty());
        assert_eq!(rig.pi.qbp_requests(), 0, "the Pi was not even asked");
    }

    #[test]
    fn block_this_on_an_interface_without_an_ethernet_address_is_refused() {
        let mut rig = Rig::new();
        let before = rig.store();
        let host = FakeHost::new(&[&default_via("wg0", 3, 50)]);
        // No address file at all, an empty one (a tunnel), the all-zero
        // address some virtual links have, and something that is no address.
        host.iface("wg0", None);
        for content in [
            "",
            "\n",
            "00:00:00:00:00:00\n",
            "garbage\n",
            "02:00:00:00:00\n",
        ] {
            host.iface("wg0", Some(content));
            let e = err(rig.block_this(&host));
            assert_eq!(e.code, "no-address", "{content:?}");
            assert!(e.detail.contains("wg0"), "{}", e.detail);
            assert!(e.detail.contains("Ethernet"), "{}", e.detail);
        }
        let host = FakeHost::new(&[&default_via("tun0", 3, 50)]);
        host.iface("tun0", None);
        assert_eq!(err(rig.block_this(&host)).code, "no-address");
        // No such interface in sysfs either.
        let host = FakeHost::new(&[&default_via("gone0", 3, 50)]);
        assert_eq!(err(rig.block_this(&host)).code, "no-address");
        // A name that would leave the sysfs folder is not followed.
        let host = FakeHost::new(&[&default_via("../x", 3, 50)]);
        assert_eq!(err(rig.block_this(&host)).code, "no-address");
        assert_eq!(rig.store(), before);
        assert_eq!(rig.pi.qbp_requests(), 0);
    }

    #[test]
    fn block_this_without_a_hostname_has_no_label_and_cleans_the_one_it_has() {
        let host = FakeHost::new(&[&default_via("eth0", 3, 100)]);
        host.iface("eth0", Some("02-00-00-AA-BB-CC\n"));
        let mut rig = Rig::new();
        host.set_hostname("\n");
        let v = rig.block_this(&host).unwrap();
        assert_eq!(v["mac"], "02:00:00:aa:bb:cc", "normalised");
        assert!(v.get("label").is_none(), "{v}");
        assert_eq!(rig.store().block[0].label, None);
        // A missing file is no hostname either.
        std::fs::remove_file(host.dir.path().join("hostname")).unwrap();
        assert!(rig.block_this(&host).unwrap().get("label").is_none());
        // Control characters go, a long name is cut at 64 characters.
        host.set_hostname(&format!("  my\u{7}box{}\n", "x".repeat(100)));
        let v = rig.block_this(&host).unwrap();
        let label = v["label"].as_str().unwrap();
        assert!(
            label.starts_with("mybox") && label.chars().count() == 64,
            "{label}"
        );
    }

    #[test]
    fn block_this_can_be_repeated_and_unblocked_by_its_address() {
        let host = FakeHost::new(&[&default_via("eth0", 3, 100)]);
        host.iface("eth0", Some("02:00:00:00:00:07\n"));
        let mut rig = Rig::new();
        rig.block_this(&host).unwrap();
        let v = rig.block_this(&host).unwrap();
        assert_eq!(v["block"], 1, "the same device, not a second entry");
        let v = rig.unblock(&mac(7)).unwrap();
        assert_eq!(v["block"], 0);
    }

    // devices

    #[test]
    fn devices_reports_the_policy_on_both_sides() {
        let mut rig = Rig::new();
        rig.edit(|s| {
            s.set_exempt_default(true);
            s.know(&mac(1), Some("PC"), 40);
            s.add_block(&mac(1), Some("PC"), 40);
            s.add_block(&mac(9), Some("Gone"), 50);
            s.add_block(&mac(10), None, 60);
        });
        rig.pi.with(|s| {
            // What the Pi has: the mode, this PC's block list as pushed
            // earlier (mac 1 only) and one of its own (mac 3).
            s.exempt_default = true;
            s.policy_block = vec![mac(1), mac(3)];
        });
        let v = rig.devices().unwrap();
        let by_mac = |m: String| {
            v["devices"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["mac"] == json!(m))
                .unwrap()
                .clone()
        };
        let flags = |m: String| {
            let d = by_mac(m);
            (d["blocked"].clone(), d["blockedOnPi"].clone())
        };
        assert_eq!(flags(mac(1)), (json!(true), json!(true)));
        assert_eq!(flags(mac(3)), (json!(false), json!(true)), "only on the Pi");
        assert_eq!(flags(mac(2)), (json!(false), json!(false)));
        // `exemptOnPi` is the Pi's effective answer: everyone but the blocked.
        let exempt_on_pi = |m: String| by_mac(m)["exemptOnPi"].clone();
        assert_eq!(
            (
                exempt_on_pi(mac(1)),
                exempt_on_pi(mac(2)),
                exempt_on_pi(mac(3))
            ),
            (json!(false), json!(true), json!(false))
        );
        assert_eq!(by_mac(mac(2))["exempt"], false, "not on this PC's list");
        assert_eq!(v["exemptDefault"], true);
        assert_eq!(v["exemptDefaultOnPi"], true);
        assert_eq!(
            v["blockOffline"],
            json!([
                { "mac": mac(9), "label": "Gone", "firstSeen": 50 },
                { "mac": mac(10), "label": "", "firstSeen": 60 },
            ]),
            "on this PC's list, not among the Pi's devices"
        );
        assert_eq!(
            v["blockOnPiOnly"],
            json!([mac(3)]),
            "on the Pi's list, not on this PC's"
        );
        assert_eq!(rig.store().policy_gen, 4, "looking changes nothing");
        // The Pi's mode and this PC's can differ.
        rig.pi.with(|s| s.exempt_default = false);
        let v = rig.devices().unwrap();
        assert_eq!(
            (v["exemptDefault"].clone(), v["exemptDefaultOnPi"].clone()),
            (json!(true), json!(false))
        );
    }

    #[test]
    fn devices_from_a_pi_without_the_policy_has_no_policy_flags_and_nothing_only_on_the_pi() {
        let mut rig = Rig::on(FakePi::without_policy(20));
        rig.edit(|s| {
            s.set_exempt_default(true);
            s.know(&mac(1), None, 40);
            s.add_block(&mac(1), None, 40);
            s.add_block(&mac(9), Some("Gone"), 50);
        });
        let v = rig.devices().unwrap();
        for d in v["devices"].as_array().unwrap() {
            assert_eq!(d["blockedOnPi"], false, "{d}");
            assert_eq!(d["blocked"], d["mac"] == json!(mac(1)), "{d}");
        }
        assert_eq!(v["exemptDefault"], true);
        assert_eq!(v["exemptDefaultOnPi"], false);
        assert_eq!(v["blockOnPiOnly"], json!([]));
        assert_eq!(
            v["blockOffline"],
            json!([{ "mac": mac(9), "label": "Gone", "firstSeen": 50 }])
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
        let exempt_cmd = WdCmd::Exempt {
            mac: mac(8),
            label: Some("Eight".into()),
        };
        assert_eq!(go(exempt_cmd)["exempt"], 1);
        assert_eq!(go(WdCmd::Unexempt { mac: mac(8) })["exempt"], 0);
        assert_eq!(go(WdCmd::ExemptDefault { on: true })["exemptDefault"], true);
        let block_cmd = WdCmd::Block {
            mac: mac(7),
            label: Some("Seven".into()),
        };
        assert_eq!(go(block_cmd)["block"], 1);
        assert_eq!(go(WdCmd::Unblock { mac: mac(7) })["block"], 0);
        assert_eq!(
            go(WdCmd::ExemptDefault { on: false })["exemptDefault"],
            false
        );
        assert_eq!(go(WdCmd::PinClear)["pin"], "cleared");
    }

    #[test]
    fn run_with_dispatches_block_this_to_the_host_it_is_given() {
        let mut rig = Rig::new();
        let host = FakeHost::new(&[&default_via("eth0", 3, 100)]);
        host.iface("eth0", Some("02:00:00:00:00:07\n"));
        let path = rig.path();
        let v = run_with(&mut rig.api, &path, T0, &WdCmd::BlockThis, &host.files()).unwrap();
        assert_eq!(
            (v["mac"].clone(), v["interface"].clone()),
            (json!(mac(7)), json!("eth0"))
        );
        assert_eq!(rig.pi_block(), vec![mac(7)]);
    }

    // -- ADS PASS aliases, the front panel's fields, adoption, the PIN -----------

    #[test]
    fn ads_pass_and_ads_block_are_the_exempt_and_unexempt_verbs() {
        let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse(&words(&["ads-pass", &mac(1), "Smart", "TV"])),
            parse(&words(&["exempt", &mac(1), "Smart", "TV"]))
        );
        assert_eq!(
            parse(&words(&["ads-pass", &mac(1)])),
            Ok(WdCmd::Exempt {
                mac: mac(1),
                label: None
            })
        );
        assert_eq!(
            parse(&words(&["ads-block", &mac(1)])),
            parse(&words(&["unexempt", &mac(1)]))
        );
        assert_eq!(
            parse(&words(&["ads-block", "nonsense"])).unwrap_err().code,
            "invalid"
        );
        assert_eq!(parse(&words(&["ads-pass"])).unwrap_err().code, "usage");
        assert_eq!(
            parse(&words(&["ads-block", &mac(1), "extra"]))
                .unwrap_err()
                .code,
            "usage"
        );
    }

    #[test]
    fn the_pin_verbs_take_no_argument_so_the_digits_are_never_on_the_command_line() {
        let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse(&words(&["pin", "set"])), Ok(WdCmd::PinSet));
        assert_eq!(parse(&words(&["pin", "clear"])), Ok(WdCmd::PinClear));
        for bad in [
            &["pin"][..],
            &["pin", "set", "1234"],
            &["pin", "1234"],
            &["pin", "clear", "x"],
        ] {
            let e = parse(&words(bad)).unwrap_err();
            assert_eq!(e.code, "usage");
            assert!(!e.detail.contains("1234"), "{}", e.detail);
        }
        // `run` has no digits to hash: it says where they come from.
        let mut rig = Rig::new();
        let path = rig.path();
        let e = run(&mut rig.api, &path, T0, &WdCmd::PinSet).unwrap_err();
        assert_eq!(e.code, "usage");
        assert_eq!(rig.pi.qbp_requests(), 0);
    }

    #[test]
    fn the_usage_names_the_new_words_and_no_pin_argument() {
        assert!(USAGE.contains("ads-pass") && USAGE.contains("ads-block"));
        assert!(USAGE.contains("pin set|clear") && !USAGE.contains("pin set <"));
    }

    #[test]
    fn devices_shows_the_front_panels_fields_and_the_revision() {
        let mut rig = Rig::new();
        rig.pi.with(|s| {
            s.dev_rev = 7;
            s.labels = vec![(mac(2), "Desk PC".to_string())];
            s.gates = vec![(mac(3), 240)];
            s.exempt_config = vec![mac(1)];
        });
        let v = rig.devices().unwrap();
        assert_eq!(v["rev"], 7);
        let by_mac = |m: &str| {
            v["devices"]
                .as_array()
                .unwrap()
                .iter()
                .find(|d| d["mac"] == m)
                .unwrap()
                .clone()
        };
        let (a, b, c) = (by_mac(&mac(1)), by_mac(&mac(2)), by_mac(&mac(3)));
        assert_eq!(
            (
                &a["labelOnPi"],
                &a["gateLeftSecs"],
                &a["fixed"],
                &a["always"]
            ),
            (&json!(null), &json!(null), &json!(true), &json!(false))
        );
        assert_eq!(b["labelOnPi"], "Desk PC");
        assert_eq!(b["label"], "", "label is this PC's, labelOnPi the Pi's");
        assert_eq!(
            (&c["gateLeftSecs"], &c["exempt"], &c["exemptOnPi"]),
            (&json!(240), &json!(false), &json!(true))
        );
        // From a Pi from before the front panel: nothing, said as null and false.
        let mut old = Rig::on(FakePi::without_panel(20));
        let v = old.devices().unwrap();
        assert_eq!(v["rev"], json!(null));
        for d in v["devices"].as_array().unwrap() {
            assert_eq!(
                (
                    &d["labelOnPi"],
                    &d["gateLeftSecs"],
                    &d["fixed"],
                    &d["always"]
                ),
                (&json!(null), &json!(null), &json!(false), &json!(false))
            );
        }
    }

    #[test]
    fn exempt_starts_from_the_list_the_panel_changed_and_does_not_overwrite_it() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), None).unwrap();
        rig.exempt(&mac(2), None).unwrap();
        // The panel takes 1 off and puts 9 on.
        rig.pi.panel_ads_pass(&mac(1), false);
        rig.pi.panel_ads_pass(&mac(9), true);
        let v = rig.exempt(&mac(3), Some("Camera")).unwrap();
        assert_eq!(v["exempt"], 3);
        assert_eq!(
            rig.pi_exempt(),
            vec![mac(2), mac(3), mac(9)],
            "the panel's edits are in"
        );
        assert_eq!(rig.store().exempt_macs(), vec![mac(2), mac(9), mac(3)]);
        assert!(!rig.store().exempt_push_due());
        assert_eq!(rig.pi.with(|s| s.conflicts), 0);
        // The push was made on the revision that was read.
        let body = rig.exempt_puts_raw().pop().unwrap();
        assert!(body["if_rev"].is_u64());
    }

    #[test]
    fn unexempt_takes_a_device_off_the_panels_list_and_not_found_for_what_the_panel_took_off() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), None).unwrap();
        rig.pi.panel_ads_pass(&mac(9), true);
        // 9 is on the Pi's list only: adopted first, then taken off.
        let v = rig.unexempt(&mac(9)).unwrap();
        assert_eq!(v["exempt"], 1);
        assert_eq!(rig.pi_exempt(), vec![mac(1)]);
        // What the panel took off already is not on the list any more.
        rig.pi.panel_ads_pass(&mac(1), false);
        assert_eq!(err(rig.unexempt(&mac(1))).code, "not-found");
        assert!(rig.store().exempt.is_empty(), "adopted all the same");
        assert_eq!(rig.pi_exempt(), Vec::<String>::new());
    }

    #[test]
    fn a_push_that_the_panel_overtakes_is_read_again_and_merged_not_overwritten() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), None).unwrap();
        // After this command read the Pi's lists the panel puts 9 on: the push is
        // refused once, the list is read again and this command's 5 goes on top.
        rig.pi.with(|s| s.taps_after_next_get.push((mac(9), true)));
        let v = rig.exempt(&mac(5), None).unwrap();
        assert_eq!(rig.pi.with(|s| s.conflicts), 1);
        assert_eq!(v["exemptPushed"], true);
        assert!(v.get("exemptPushError").is_none());
        assert_eq!(
            rig.pi_exempt(),
            vec![mac(1), mac(5), mac(9)],
            "both edits stand"
        );
        assert_eq!(rig.store().exempt_macs(), vec![mac(1), mac(5), mac(9)]);
        assert!(
            !rig.store().exempt_push_due(),
            "and the merge is recorded as pushed"
        );
        // The same for taking one off.
        rig.pi.with(|s| s.taps_after_next_get.push((mac(1), false)));
        rig.unexempt(&mac(5)).unwrap();
        assert_eq!(rig.pi.with(|s| s.conflicts), 2);
        assert_eq!(
            rig.pi_exempt(),
            vec![mac(9)],
            "the panel's removal and this one both stand"
        );
        assert_eq!(rig.store().exempt_macs(), vec![mac(9)]);
    }

    #[test]
    fn a_push_that_the_panel_keeps_overtaking_is_given_up_and_reported() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), None).unwrap();
        rig.pi.with(|s| s.churn = true);
        let v = rig.exempt(&mac(5), None).unwrap();
        assert_eq!(rig.pi.with(|s| s.conflicts), 3);
        assert_eq!(v["exemptPushed"], false);
        let why = v["exemptPushError"].as_str().unwrap();
        assert!(
            why.contains("kept changing") && why.contains("run it again"),
            "{why}"
        );
        // The edit stays, due, for the watcher; the ok is still true.
        assert_eq!(v["ok"], true);
        assert!(rig.store().is_exempt(&mac(5)) && rig.store().exempt_push_due());
    }

    #[test]
    fn block_and_exempt_default_adopt_the_panels_block_list_and_merge_a_race() {
        let mut rig = Rig::new();
        rig.exempt_default(true).unwrap();
        rig.block(&mac(1), None).unwrap();
        // In that mode the panel's BLOCK ADS puts a device on the block list.
        rig.pi.panel_ads_pass(&mac(2), false);
        let v = rig.block(&mac(3), None).unwrap();
        assert_eq!(v["block"], 3);
        assert_eq!(rig.pi_block(), vec![mac(1), mac(2), mac(3)]);
        // A race: the panel takes 1 off after the read.
        rig.pi.with(|s| s.taps_after_next_get.push((mac(1), true)));
        let v = rig.block(&mac(4), None).unwrap();
        assert_eq!(v["policyPushed"], true);
        assert_eq!(rig.pi.with(|s| s.conflicts), 1);
        assert_eq!(rig.pi_block(), vec![mac(2), mac(3), mac(4)]);
        assert_eq!(rig.store().block_macs(), vec![mac(2), mac(3), mac(4)]);
        // The mode is this PC's: turned off here, the Pi follows.
        rig.exempt_default(false).unwrap();
        assert!(!rig.pi.with(|s| s.exempt_default));
        let body = rig.policy_puts_raw().pop().unwrap();
        assert!(body["if_rev"].is_u64());
    }

    #[test]
    fn a_pi_that_just_started_again_is_not_read_as_a_panel_that_emptied_the_lists() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), None).unwrap();
        rig.exempt(&mac(2), None).unwrap();
        rig.pi.reboot();
        // The Pi waits for the known list that this PC has: its empty list is
        // no edit of the panel, and this PC's list is the one to push.
        rig.pi.panel_ads_pass(&mac(9), true);
        let v = rig.exempt(&mac(3), None).unwrap();
        assert_eq!(v["exempt"], 3);
        assert_eq!(rig.store().exempt_macs(), vec![mac(1), mac(2), mac(3)]);
        assert_eq!(rig.pi_exempt(), vec![mac(1), mac(2), mac(3)]);
    }

    #[test]
    fn an_edit_that_is_waiting_is_not_given_up_for_the_panels_list() {
        let mut rig = Rig::new();
        rig.exempt(&mac(1), None).unwrap();
        // A command whose push failed left an edit due; the panel changed the list too.
        rig.pi.with(|s| s.fail_exempt = true);
        rig.exempt(&mac(2), None).unwrap();
        rig.pi.with(|s| s.fail_exempt = false);
        rig.pi.panel_ads_pass(&mac(9), true);
        assert!(rig.store().exempt_push_due());
        rig.exempt(&mac(3), None).unwrap();
        assert_eq!(rig.store().exempt_macs(), vec![mac(1), mac(2), mac(3)]);
        assert_eq!(rig.pi_exempt(), vec![mac(1), mac(2), mac(3)]);
    }

    #[test]
    fn a_pi_from_before_the_front_panel_gets_pushes_without_if_rev() {
        let mut rig = Rig::on(FakePi::without_panel(20));
        let v = rig.exempt(&mac(1), None).unwrap();
        assert_eq!(v["exemptPushed"], true);
        assert_eq!(rig.exempt_puts_raw(), vec![json!({"exempt": [mac(1)]})]);
        rig.block(&mac(2), None).unwrap();
        assert_eq!(rig.policy_puts_raw(), vec![policy_body(false, &[mac(2)])]);
    }

    #[test]
    fn the_verbs_push_the_labels_after_the_lists_and_say_so() {
        let mut rig = Rig::new();
        let path = rig.path();
        let v = exempt(&mut rig.api, &path, T0, &mac(2), Some("Smart TV")).unwrap();
        assert_eq!(v["labelsPushed"], true);
        assert!(v.get("labelsPushError").is_none());
        assert_eq!(
            rig.pi.with(|s| s.labels.clone()),
            vec![(mac(2), "Smart TV".to_string())]
        );
        let known = rig.pi.with(|s| {
            s.log
                .iter()
                .position(|l| l.starts_with("PUT /api/qbp/devices/known"))
        });
        let exempt_at = rig.pi.with(|s| {
            s.log
                .iter()
                .position(|l| l.starts_with("PUT /api/qbp/devices/exempt"))
        });
        let labels = rig.pi.with(|s| {
            s.log
                .iter()
                .position(|l| l.starts_with("PUT /api/qbp/devices/labels"))
        });
        assert!(known < exempt_at && exempt_at < labels);
        let v = know(&mut rig.api, &path, T0, &mac(5), Some("Printer")).unwrap();
        assert_eq!(v["labelsPushed"], true);
        assert_eq!(rig.pi.with(|s| s.labels.len()), 2);
        let v = forget(&mut rig.api, &path, &mac(5)).unwrap();
        assert_eq!(v["labelsPushed"], true);
        assert_eq!(
            rig.pi.with(|s| s.labels.clone()),
            vec![(mac(2), "Smart TV".to_string())]
        );
        let v = block(&mut rig.api, &path, T0, &mac(6), Some("Guest")).unwrap();
        assert_eq!(v["labelsPushed"], true);
        let v = unblock(&mut rig.api, &path, T0, &mac(6)).unwrap();
        assert_eq!(v["labelsPushed"], true);
        let v = unexempt(&mut rig.api, &path, T0, &mac(2)).unwrap();
        assert_eq!(v["labelsPushed"], true);
        assert_eq!(
            rig.pi.with(|s| s.labels.len()),
            2,
            "the names stay with the known list"
        );
    }

    #[test]
    fn a_failing_or_unsupported_labels_push_is_reported_on_its_own_and_stops_nothing() {
        let mut rig = Rig::new();
        rig.pi.with(|s| s.fail_labels = true);
        let path = rig.path();
        let v = exempt(&mut rig.api, &path, T0, &mac(2), Some("TV")).unwrap();
        assert_eq!(
            (
                v["ok"].clone(),
                v["pushed"].clone(),
                v["exemptPushed"].clone()
            ),
            (json!(true), json!(true), json!(true))
        );
        assert_eq!(v["labelsPushed"], false);
        assert!(v["labelsPushError"].as_str().unwrap().contains("500"));
        let mut old = Rig::on(FakePi::without_panel(20));
        let path = old.path();
        let v = know(&mut old.api, &path, T0, &mac(2), Some("TV")).unwrap();
        assert_eq!(v["pushed"], true);
        assert_eq!(v["labelsPushed"], false);
        assert_eq!(
            v["labelsPushError"],
            "the Pi's software does not show device names yet"
        );
    }

    fn hash_of(pin: &str) -> PinHash {
        crate::pinhash::hash_with_salt(pin, [4; 16]).unwrap()
    }

    #[test]
    fn pin_set_keeps_the_hash_pushes_it_and_says_nothing_of_either_it_or_the_digits() {
        let mut rig = Rig::new();
        let path = rig.path();
        let hash = hash_of("1234");
        let v = pin_set(&mut rig.api, &path, hash.clone()).unwrap();
        assert_eq!(v, json!({"ok": true, "pin": "set", "panelPushed": true}));
        assert_eq!(
            rig.pi.with(|s| s.pin_hash.clone()).as_deref(),
            Some(hash.as_str())
        );
        let store = rig.store();
        assert_eq!(store.pin_hash.as_ref(), Some(&hash));
        assert!(!store.pin_push_due(), "the push was recorded");
        let text = v.to_string();
        assert!(!text.contains("1234") && !text.contains(hash.as_str()));
        // The digits are nowhere on disk: only the hash, in the exempt file.
        let on_disk = std::fs::read_to_string(wdstore::exempt_path(&path)).unwrap();
        assert!(on_disk.contains(hash.as_str()) && !on_disk.contains("1234"));
        assert!(!std::fs::read_to_string(&path)
            .unwrap_or_default()
            .contains("pin"));
    }

    #[test]
    fn pin_clear_pushes_null_and_forgets_the_hash_and_says_what_a_config_pin_does() {
        let mut rig = Rig::new();
        let path = rig.path();
        pin_set(&mut rig.api, &path, hash_of("1234")).unwrap();
        let v = pin_clear(&mut rig.api, &path).unwrap();
        assert_eq!(v["pin"], "cleared");
        assert_eq!(v["panelPushed"], true);
        assert!(v["note"].as_str().unwrap().contains("restarts"));
        assert!(rig.pi.with(|s| s.pin_hash.is_none()));
        assert!(rig.store().pin_hash.is_none() && !rig.store().pin_push_due());
        // On every call, also when this PC had none (the Pi may have one set at its panel).
        let n = rig.pi.with(|s| s.panel_puts.len());
        pin_clear(&mut rig.api, &path).unwrap();
        assert_eq!(rig.pi.with(|s| s.panel_puts.len()), n + 1);
    }

    #[test]
    fn a_pin_that_could_not_be_pushed_stays_set_and_due_with_a_reason_that_names_nothing() {
        let mut rig = Rig::new();
        let path = rig.path();
        rig.pi.with(|s| s.fail_panel = true);
        let hash = hash_of("1234");
        let v = pin_set(&mut rig.api, &path, hash.clone()).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["panelPushed"], false);
        let why = v["panelPushError"].as_str().unwrap();
        assert!(
            why.contains("500") && !why.contains("1234") && !why.contains(hash.as_str()),
            "{why}"
        );
        assert!(
            rig.store().pin_push_due() && rig.store().pin_hash.is_some(),
            "the watcher pushes it"
        );
        // A Pi that does not take a PIN yet.
        let mut old = Rig::on(FakePi::without_panel(20));
        let path = old.path();
        let v = pin_set(&mut old.api, &path, hash_of("4321")).unwrap();
        assert_eq!(
            v["panelPushError"],
            "the Pi's software does not take a panel PIN yet"
        );
        assert!(old.store().pin_push_due());
    }

    #[test]
    fn a_pin_needs_a_writable_store_and_pushes_nothing_without_one() {
        let mut rig = Rig::new();
        let bad = unwritable(rig.dir.path());
        let e = pin_set(&mut rig.api, &bad, hash_of("1234")).unwrap_err();
        assert_eq!(e.code, "store");
        assert!(!e.detail.contains("1234"));
        let e = pin_clear(&mut rig.api, &bad).unwrap_err();
        assert_eq!(e.code, "store");
        assert_eq!(rig.pi.with(|s| s.panel_puts.len()), 0);
    }
}

# qnet: the watchdog tab as a patch bay (plan)

Date: 2026-11-17. Branch `watchdog-bay`, built in its own git worktree.
Binding reference: the approved mockup (watchdog round 2: its `index.html`,
its build sheet and its 2x stills). The build sheet says what each mark reads;
its sizes are at `Style.space(1)` = 1 px.

Owner decisions (approved, "build it"):
- The jack's word says **PASS**; the rail, the readout and the tickets say **ADS PASS**.
- **Keep the lamp row** (THREAT, NEW DEVICE, ARP SPOOF, REBIND, LOOKUPS). An alert
  that rings no jack (ARP spoof, or a client that is no device on the board)
  rings its lamp and queues as "LAN".
- **NORMAL → ADS PASS asks first** and says how many devices lose ad blocking;
  back to BLOCKED is immediate.
- **The tab is reached from the qbp node on the Route**, which carries the count
  of calls waiting. The DNS view moves to the **upstream node**.
- Order: alerting and new first, then labelled, then by address; held while the
  panel is open (set when it opens, kept across the views, dropped when it
  closes; a device that turns up goes in front of the offline ones). Offline
  known devices dimmed at the end. Gates 5/30/60 min.
  Dismiss and Dismiss all (both clear the Pi's screen). FIXED riveted. PIN in the
  footer (`pin set` semantics: the PIN goes on stdin, never on a command line).

Rules for every task: logic in Rust where it can be; QML is the host layer and
stays a thin view; `Model.js` keeps only view logic (navigation, cursor,
paging, held order, argv building), tested with `node --test tests/`. Public
repo: 192.0.2.x, 02:00:00:… MACs, example names only. Never read
`~/.config/qnet/`, the keyring, `~/.local/state/qnet/`; never contact the Pi or
the network; never write into `~/.config/omarchy/plugins/qqq.qnet`; never run
`install.sh` or restart the shell; no synthetic input. No new dependencies.
`export CARGO_TARGET_DIR=<this worktree>/backend/target`, run cargo from
`backend/`.

Gates before each commit: from `backend/` `cargo test`, `cargo clippy
--all-targets` (0 warnings), `cargo fmt --check`; from the root `node --test
tests/`; for QML tasks, offscreen shots (`tools/shot`).

## What the Pi can and cannot do (checked in the qberrypi source)

- `PUT /api/qbp/devices/gate` `{"mac","secs"}` → `{"gate_left_secs","rev"}`
  (secs 0 shuts it). Gates live in the Pi's memory only.
- `PUT /api/qbp/alerts/acked` `{"acked":[key…]}` acknowledges the alerts the Pi
  holds with those keys (and the same key raised later): Dismiss all is one call.
- `arp_spoof`: `client` is the gateway's IP, `subject` the second card's MAC.
  `new_device`: `subject` is the device's MAC. Others: `client` is the device's IP.
- **No per-device query log.** `/api/v1/queries` has no client field, so the
  mockup's "recent" lookups in the device ticket cannot be built; the ticket
  leaves that section out (reported to the owner as a difference).

## Tasks

### T1 Backend verbs (Rust)
Files: `backend/src/wdcli.rs`, `main.rs`, `watchdog.rs`, `fakeqbp.rs`,
`watch.rs`, `threads.rs`, `SPEC.md`, `README.md`.
- `qnet watchdog gate <mac> <secs>`: `secs` 0..=3600 (0 shuts); `PUT
  devices/gate`. Result `{"ok":true,"mac","gateLeftSecs":n|null}`. Errors
  `invalid`, `absent`, `unsupported` (404 on the route: "the Pi's software does
  not take gates yet"), and the Pi's refusals (fixed/always devices) as
  `refused` with its message.
- `qnet watchdog patch <mac> pass|blocked`: the panel's one verb for a cord.
  Mode off: `pass` = `exempt`, `blocked` = `unexempt` (not-found is fine: it is
  already blocked → ok). Mode on: `blocked` = `block`, `pass` = `unblock`
  (not-found → ok). Then, if the device's gate is open, shut it (`gate 0`).
  Result: the underlying verb's result plus `"patch"`, `"gateShut"?:bool`.
- `qnet watchdog label <mac> [label...]`: sets this PC's label on every list
  that holds the device (known, ADS PASS, block); no label clears it; a device
  on none of them goes on the known list as `know` does. Pushes the labels.
  Result `{"ok":true,"mac","label"?,"labelsPushed",…}`.
- `qnet watchdog ack-all`: `GET alerts`, `PUT alerts/acked` with every unacked
  key, record the keys in the store as `ack` does. Result
  `{"ok":true,"acked":n,"saved":bool}`.
- Watcher stdin command `devices`: like `refresh`, and the next poll re-reads
  the devices (`wd.last_devices = None`), so the panel sees an edit at once.
- Fake Pi (`fakeqbp.rs`) learns gate (and the existing routes as needed);
  tests for each verb against it, and parser tests in `main.rs`.
Acceptance: verbs documented in SPEC "Actions" and README's command list;
gates green.

### T2 The bay in the state stream (Rust)
Files: new `backend/src/bay.rs`, `state.rs`, `watchdog.rs` (report),
`threads.rs`/`watch.rs` as needed, `SPEC.md`, new golden fixtures
`tests/fixtures/watchdog-{rest,n30,arp,calm,mode}.json`.
The watcher already holds the Pi's devices (label on Pi, gate, fixed, always)
and this PC's store. Add to `watchdog` in the state JSON:
```
"exemptDefault": false, "exemptDefaultOnPi": false, "pinSet": true,
"devicesAt": 1794122640,          // unix time of the last device read, 0 = none
"bay": {
  "jacks": [{
    "mac", "ip": "192.0.2.40" | "", "tail": "·40" (last octet) | ":d8" (no IPv4: last MAC byte),
    "hostname", "name": label || labelOnPi || "", "strip": ["Living","room TV"] | ["Doorbell"] | [],
    "known": bool (this PC's list), "isNew": !(known || knownOnPi), "offline": bool,
    "firstUnix", "lastUnix",
    "patch": "blocked"|"pass"|"always"|"fixed",
    "row": "blocked"|"pass",      // the row the cord, the normal wire or the rivet bar runs to
    "cord": bool,                 // off the normal wiring (on the ADS PASS list with mode off, on the block list with mode on)
    "gateUntil": unix|null,       // devicesAt + gateLeftSecs while a gate is open
    "lamp": ""|"warn"|"high", "alertId": id|null,   // the newest unacked alert ringing this jack
    "rank": 0|1|2|3 }],           // 0 alerting or new, 1 labelled, 2 the rest, 3 offline
  "flipCount": n,                 // jacks that would get ADS PASS if NORMAL became ADS PASS (0 when it is already)
  "lamps": [{"kind":"threat|new_device|arp_spoof|rebind|lookups","count","tone":""|"warn"|"high","alertId"|null}],  // always these five, in that order
  "calls": [{"id","key","kind","lamp","severity","tone","mac"|null,"relatedMac"|null,"subject","count","firstUnix","lastUnix"}],  // unacked, newest lastUnix first
  "quietSince": unix              // the newest lastUnix of any alert held, 0 = none
}
```
Rules: jacks are the Pi's devices plus this PC's offline entries (known,
ADS PASS, block lists; `offline:true`, no IPv4), sorted by rank, then by IPv4
numerically (no IPv4: by MAC), at most 128 + offline. `patch`: `always` →
always/row blocked; `fixed` → fixed/row by `exemptOnPi`; mode off → pass if on
this PC's ADS PASS list (cord) else blocked (normal); mode on → blocked if on
the block list (cord) else pass (normal). Which jack an alert rings:
`new_device` → the jack whose MAC is the subject; `arp_spoof` → none,
`relatedMac` = the subject's MAC if a jack has it; others → the jack whose
IPv4 holds `client`, else none. Lamp kind: dga/tunnel/beacon/burst and any
unknown kind → `lookups`. Tone: severity high → `high`, else `warn`.
`strip`: the mockup's `strip2` (two lines of at most 8 chars, break at a space,
after `-_./`, at a lower→upper case change, at a letter→digit change, the most
even break that fits; else whole words then an ellipsis: "Streaming stick" →
["Streami…","stick"], "Thermostat" → ["Thermos…"]), counted in chars, with
unit tests for those cases and the mockup's names.
Golden fixtures: a Rust test builds five full State values at the JS tests'
clock (`NOW_S = 1794122700`) from the mockup's sample data (`index.html` RAW,
ALERTS, ARP: 8 devices with a threat on ·40 and a new ·216, a gate on ·23 with
872 s left, TV/Bedroom TV/Streaming stick on ADS PASS, router and qbp always,
Printer fixed pass; n30: all 30 with two offline; arp: rest + the ARP spoof;
calm: no alerts, ·216 known, no gate; mode: exemptDefault on with PC, laptop
and tablet on the block list) and compares them with
`tests/fixtures/watchdog-*.json`; `QNET_UPDATE_FIXTURES=1 cargo test` writes
them. Acceptance: SPEC "State JSON" documents every field; the existing state
tests still pass; a quiet poll is still a heartbeat (`gateUntil` is stable).

### T3 Model.js: watchdog data, route and navigation (JS)
Files: `Model.js`, new `tests/watchdog.test.js`, `tests/route.test.js`,
`tests/focus.test.js` as needed.
- `normalizeState` normalises `watchdog` (all of T2's fields; clean strings,
  caps, enums) so the panel never reads raw JSON.
- Route: `watchdogPresent(v)` = status `ok` or `polledAt > 0`. The `ph` node
  opens `"watchdog"` when present, else `"dns"`; every `up` node opens `"dns"`.
  The `ph` badge is the calls waiting (`{n, tone: high→"urgent" else
  "warning"}`) when present; the leak badge moves to the `up` node.
  `routeStops`/`routeTarget` follow.
- `navOpen` accepts `"watchdog"`; `escapeStep` gains `pin`, `flip` (the
  confirm), `ticket` before `back`.
- `holdOrder(prev, jacks)`: prev empty → the jacks' order; else keep prev's
  macs that still exist in prev's order, new online ones in front of the
  offline ones at the end, new offline ones last.
- `bayLayout(order, ui)`: bays of 8; slots shown = 1 with a ticket open (the
  ticket's bay), else min(2, bays); scroll clamp; pager text parts and the
  ring flags (an alerting jack above or below the shown bays).
- `gateLeft(jack, nowS)`, `formatGate(s)` → "14:32"; `needsClock` also while
  the watchdog view is up and a gate is open.
- argv builders: `argvWatchdog(bin, verb, args)` for `patch`, `gate`, `label`,
  `know`, `forget`, `ack`, `ack-all`, `exempt-default`, `pin set`, `pin clear`
  (validates MACs and numbers; never takes a PIN).
- `focusRows` for `view: "watchdog"`: back; lamps (lit ones); one row per shown
  bay (items = its jacks' macs); normal; flip confirm (flip, cancel); pager
  (up, down) when shown; queue (dismissall) and call:N; ticket rows (device:
  label, patch, gate, actions; alert: actions); pin (its buttons).
  `initialCursor` on `back`.
Acceptance: tests over T2's golden fixtures for each of the above; all
existing tests still pass (update the route tests that said the upstream is
not a door).

### T4 Offscreen harness (QML stubs; parallel with T1–T3)
Files: new `tools/shot`, `tools/harness/Shot.qml`, `tools/harness/imports/…`
(stubs of `qs.Ui`, `qs.Commons`, `Quickshell`, `Quickshell.Io`), a section in
`README.md`. Model: an earlier plugin's harness.
`tools/shot <fixture> <out.png> [ui.json]` renders the whole `Panel.qml`
offscreen (`QT_QPA_PLATFORM=offscreen`, software, 1x, `/usr/bin/qml6`), card
520 px wide (488 content), with the Omarchy Amethyst colours of the mockup
(fg `#dad6ec`, accent `#a08dff`, urgent `#f06a8a`, card `#151326`) and the
JetBrainsMono Nerd Font at the real `Style.font` sizes (10/11/12/13/14/16).
The fake `qnet watch` (the Process stub) emits the fixture as one state line;
the harness shifts every unix time in it by `now − 1794122700` so gates and
ages read as in the fixture. `ui.json` says what to do after load, through the
panel's own functions: `{"view":"dns|wifi|watchdog", "call": [["fnName", args…]…]}`.
Fails on any QML warning. Acceptance: shots of the existing main, Wi-Fi and
DNS views from `tests/fixtures/healthy.json` in `docs/shots/watchdog-bay/`
(`before-main.png`, `before-wifi.png`, `before-dns.png`).

### T5a The board (QML)
Files: new `components/WatchdogView.qml`, `components/LampRow.qml`,
`components/PatchBay.qml` (rail + bays, QtQuick.Shapes or Canvas),
`Panel.qml` (third view, `openView("watchdog")`, IPC `view watchdog`, key `3`,
held order on open), `components/HeroViz.qml` (the ph badge), `i18n/en.json`.
Draw exactly the mockup's header (Watchdog, "qbp ·2 · 8 devices · 2 offline",
the small route "route › qbp"), lamp row, rail with the NORMAL key, bays
(plate, screws, strip, tail, three jacks, normal dotted wire, cords with
plugs, amber gate cord and tag, rivet bars, drop lamps, spares, dimmed
offline columns, the word under each jack: BLOCKED / PASS / ALWAYS / FIXED /
countdown), readout line (state or the hovered jack's full name and state) and
pager. Pointer: hover a column → readout; scroll a bay at a time. Colours
from the panel's tokens (`fg`, `dim`, `accent`, `urgent`, `warning`,
`restFill`, `hoverFill`, `lineColor`); type `Style.font` sizes only, the bar
font only. Acceptance: shots `rest.png`, `n30.png` (scrolled to bays 3–4),
`calm.png`, plus `after-main.png`, `after-dns.png` (DNS opened from the
upstream node), `after-wifi.png`, compared by eye with the stills.

### T5b Queue, tickets, confirm, PIN, actions (QML)
Files: `components/WatchdogView.qml`, new `components/CallQueue.qml`,
`components/DeviceTicket.qml`, `components/AlertTicket.qml`,
`components/PinFooter.qml`, `Panel.qml` (actions through `runCli` with
`Model.argvWatchdog`, then `QnetService.send("devices")`; inline notes for
failures; the cursor rows), `i18n/en.json`, `README.md` (the tab, key 3, IPC).
Queue head with count and Dismiss all; calls newest first (LAN for no jack);
device ticket (line, word, label field 24 chars committed on Enter/blur,
address · MAC · host · first seen, patch BLOCKED/ADS PASS, gate 5/30/60 m or
"open, shuts in 14:32" + Shut now, Mark known / Forget device, Close; ALWAYS
and FIXED explain themselves; no "recent" section); alert ticket (lamp, title,
severity · ×n · times, subject, who, a sentence per kind, Dismiss, Mark known
for new_device, Open device / Open ·216 for the ARP spoof's related jack);
NORMAL flip confirm in the readout ("Flip normal to ADS PASS? 23 devices will
see ads. Threats stay blocked." Flip / Cancel); PIN footer (PIN set · Change ›
· Clear, or no PIN · Set ›; the field is a password field, its text goes to
`pin set` as the runner's stdin secret and is cleared at once). A ticket
shrinks the board to its bay. Acceptance: shots `device.png`, `mode.png`
(NORMAL ADS PASS) and `flip.png` (the confirm), `alert.png`, `arp.png`, all
under `docs/shots/watchdog-bay/`, compared by eye with the stills.

### Review
One Opus whole-branch review, then one fix wave for Critical/Important.

## Amendment (after T4): the width

The real `KeyboardPanel` makes qnet's card `Style.space(488)` wide, and its
padding (14) and border leave a content column of 456, not the 488 the mockup
assumed ("520 px card, 488 px content, as Panel.qml" was a misreading). The
board needs 70 + 418 = 488. Decision: while the watchdog view is up the card is
`Style.space(520)` wide (content 488, the mockup's geometry at 1:1); the other
views keep 488. The owner is told (a card that widens by 32 px on entering the
tab). `tools/shot` must draw the card at the panel's own `contentWidth` (the
real geometry), not a fixed 520.

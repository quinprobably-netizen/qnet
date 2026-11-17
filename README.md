# qnet (`qqq.qnet`)

Wi-Fi and network panel for the Omarchy bar. It replaces `omarchy.network` and
knows about the Pi-hole on the LAN. It is a thin QML panel over a Rust binary,
`~/.local/bin/qnet`.

- **Main view, "the Route":** PC → AP → Pi-hole → upstream, with live figures on
  each hop.
  - Blocked queries drain into the Pi-hole node.
  - Paused, failover, bypass, unreachable, degraded and offline each show on
    the route itself.
  - Below the route: Pause blocking 5 min (`p`), and the IP line.
- **Wi-Fi view** (click the AP node, or `2`): an active-connection card and the
  nearby list. Opening it scans only if the last scan is more than 60 s old.
- **DNS view** (click the Pi-hole node, or `1`):
  - the resolver chain, systemd-resolved → Pi-hole → upstreams;
  - the resolver choice (leaving the Pi-hole asks first);
  - leaks with Pin, failover, and Admin.
- **Failover:** when the Pi-hole stops answering (≥30 s, and its pinned API is
  also dead), the *runtime* DNS switches to the trusted router or Quad9. It
  switches back on recovery. The saved profile is never written.
- **Watchdog (qberrypi):** when the Pi-hole is a qberrypi, qnet reads its
  watchdog.
  - Alerts and devices are in the state JSON (`watchdog`), and new alerts raise
    desktop notifications (3 a minute, then "N more alerts").
  - The acknowledged alerts and the known devices are kept on this PC and
    pushed back after a Pi reboot.
  - A device can have **ADS PASS** (it is exempt from ad blocking; threat
    blocking stays): the list is kept on this PC (in a file of its own, so
    that an older qnet cannot rewrite it away) and pushed to the Pi like the
    known list. A Pi that does not support it yet is told so by the commands
    and left alone by the watcher until the next login session, and nothing
    else is affected.
  - **Exempt by default:** a mode in which every device has ADS PASS (threat
    blocking stays) except the ones on a short block list, new devices
    included. This PC owns the mode and the block list (in the same file as the
    ADS PASS list) and pushes them as one policy, with the same rules: on every
    session push, after an edit or a Pi restart, and a Pi that does not support
    it yet is told so by the commands and left alone by the watcher. Turning the
    mode on says so: every device not on the block list stops being ad-blocked.
  - **The Pi's front panel** can give a device ADS PASS or take it away (in the
    exempt-by-default mode: put it on the block list or take it off), and its
    edit is newer than the list this PC pushed. Before it pushes either list,
    and whenever it reads the devices, qnet looks at the Pi's lists and the
    Pi's revision: when the panel changed a list, qnet **adopts** it instead of
    pushing its older one over it. Every push carries the revision it was made
    on (`if_rev`), so a push that the panel overtook is refused by the Pi, read
    again and decided again. A list that was edited here and not pushed yet
    wins over the panel's, and so does this PC's list when the Pi has just
    restarted (its lists are empty then). The commands do the same: they edit
    the panel's list, not an older one.
  - **Names:** the labels given with `know`, `ads-pass` and `block` are pushed
    to the Pi (in this PC's order, at most 64, plain ASCII, 24 characters) for
    the panel to show, after each session push, a Pi restart and each edit.
  - **Cords and gates:** `patch <mac> pass|blocked` is the one verb for a
    device's cord: with the exempt-by-default mode off it is `exempt` or
    `unexempt`, with it on `unblock` or `block`, and a device that is where it
    was told to go already is fine. It then shuts the device's gate if the Pi
    says it is open. `gate <mac> <secs>` opens a gate (ads pass for that long,
    at most an hour, in either mode) or shuts it with 0; gates live on the Pi,
    in its memory, and this PC keeps nothing of them. `label <mac> [label...]`
    renames a device on every list that holds it, `ack-all` acknowledges every
    alert at once. The watcher takes the line `devices` on stdin as `refresh`
    that also has the Pi's devices read at the next poll, so the panel sees its
    own edit at once.
  - **Panel PIN:** `qnet watchdog pin set` asks for four digits (on stdin,
    never on the command line, no echo on a terminal) and keeps only their
    hash, which it pushes to the Pi after every login and restart so that the
    panel's lock holds. `pin clear` takes the PIN off the running Pi.
  - Against a real Pi-hole nothing changes. There is no panel for it yet.

Details: `SPEC.md`.

## Install / update

```
./install.sh                 # builds to ~/.cache/qnet/target, installs ~/.local/bin/qnet
omarchy restart shell        # QML hot-reload is unreliable; restart to load edits
qnet pihole setup [address]  # once, in a terminal: pins the cert, stores an app password in the keyring
qnet watchdog alerts         # qberrypi only: its alerts, one JSON line
qnet watchdog ack <id>       # acknowledge an alert
qnet watchdog ack-all        # acknowledge every alert that is not acknowledged yet, in one call
qnet watchdog devices        # its devices (also its labels, gates, fixed/always, revision), and what this PC knows of them
qnet watchdog know <mac> [label...]   # add to the known list; pushed to the Pi
qnet watchdog forget <mac>   # take a device off the list
qnet watchdog label <mac> [label...]  # this PC's name for a device, on every list that holds it; no words clear it
qnet watchdog exempt <mac> [label...]   # ADS PASS for it (also marks it known); pushed to the Pi. Alias: ads-pass
qnet watchdog unexempt <mac> # ads blocked again; the device stays known. Alias: ads-block
qnet watchdog exempt-default on|off   # every device has ADS PASS but the blocked ones (threats stay blocked)
qnet watchdog block <mac> [label...]  # keep it fully blocked in that mode (also marks it known, takes it off the ADS PASS list)
qnet watchdog unblock <mac>  # take it off the block list
qnet watchdog block-this     # block this computer: the interface of the default route, labelled with the hostname
qnet watchdog patch <mac> pass|blocked  # one device's cord, in either mode: ADS PASS or blocked; shuts its open gate
qnet watchdog gate <mac> <secs>         # ADS PASS for a while: 1 to 3600 seconds, 0 shuts the gate (the Pi keeps it in memory)
qnet watchdog know-all       # add every device the Pi has seen
qnet watchdog pin set        # the panel's PIN: four digits on stdin (no echo on a terminal); only the hash is kept
qnet watchdog pin clear      # take the PIN off the running Pi
```

`ads-pass` and `ads-block` are the panel's words for `exempt` and `unexempt`
(the JSON field names keep `exempt`). `ads-block` takes ADS PASS away from a
device; it is not `block`, which is the exempt-by-default mode's block list. In
that mode the block list decides, so use `block` and `unblock` there.

- IPC: `omarchy-shell qqq.qnet toggle | open | close | view <main|wifi|dns|watchdog>`.
- Keybinding: `SUPER + CTRL + N`, rebound in `~/.config/hypr/bindings.lua`.
- Run cargo from inside `backend/`, or `.cargo/config.toml` is skipped and
  `backend/target` lands in the watched plugin tree.

## Offscreen shots

```
tools/shot [--scale N] <fixture.json> <out.png> [ui.json]
tools/shot --scale 2 tests/fixtures/healthy.json docs/shots/x.png tools/harness/ui/wifi.json
```

Renders the whole panel to a PNG without the shell (`/usr/bin/qml6`, offscreen,
software). `Panel.qml`, `QnetService.qml` and `components/` are the real ones;
what the shell provides (`qs.Ui`, `qs.Commons`, `Quickshell`, `Quickshell.Io`)
is a stub in `tools/harness/imports/`: the Amethyst colours, JetBrainsMono Nerd
Font at the shell's `Style.font` sizes, `i18n/en.json` for the words, motion off
(so a shot repeats byte for byte). The card is drawn as the real KeyboardPanel
draws it, on the page colour with a 24 px margin: as wide as the panel asks for
(488 px; 520 px on the watchdog view), minus 2 x (14 px of padding + 2 px of
border) for its content column (456 px, and 488 px for the board). `--scale 2`
gives the 2x of the mockup stills.

- **Fixture:** a full state JSON. The fake `qnet watch` (the `Process` stub) says
  it as its one state line. Its unix times are moved by `now - 1794122700` (the
  tests' clock), so ages and countdowns read as when it was written. A time is a
  number over 1e9 named `*Unix`, `*At`, `*Until`, `*Since`, `since`, `until` or
  `t`; `seq`, `lastScanAgeS`, `pauseRemainingS` and the like are relative and stay.
  Any other command (an action) is logged and answers `{"ok":true}`.
- **ui.json:** `{"view": "main|dns|wifi|watchdog", "call": [["functionName", arg, …], …]}`.
  `view` runs `openView(view, false)` (as the IPC does, so the keyboard cursor
  shows); each `call` runs `functionName(args)` on the panel, in order. A view
  that does not open, or an unknown function, fails. `{"call": [["openView",
  "dns", true]]}` opens it as a click does, without the cursor.
- Exits 1 on any QML warning. Nothing of the live shell is touched, no input is
  sent, nothing leaves the machine.

## Review history

Blind council: Opus/Sonnet seats plus a Fable security seat, with an Opus chair.

| Round | Chair score | Owner |
|---|---|---|
| Stock `omarchy.network` | 4.5 | |
| R1, first build | 6.0 | |
| R2 | 6.5 | 4–5: "looks like an audio panel" |
| R3, the Route + drill-down rows | | 8.2: "still the dns and wifi menus" |
| R3b, node navigation, network-native views | seats 7 / 6.5 / 7 / 7.5 / 8 | |

## Next round: the chair's minimum for 8.5 (not started)

Mostly subtractions. Do not add identity elements before the owner rates 3b.

1. **Wi-Fi view tooltip:** "Scan (r)" shows on hover only and stays inside
   the gutter.
2. **Main view subtraction:**
   - drop the footer and the header signal %;
   - replace the blocked pool gauge with "51% blocked" text and demote the
     query count;
   - hide Pause when the Pi-hole isn't the resolver.
3. **No alarm while healthy:** no badge or warning for inactive profiles.
4. **DNS view, out of Sound Hub grammar:**
   - leaks become dashed branches off the chain ("inactive · Pin", one Pin all);
   - failover state goes into the Pi-hole row caption;
   - drop the Leaks and Failover sections and the IP on the resolver radio.
5. **Wi-Fi card:**
   - drop the Signal and DNS rows;
   - plasma-tint the connected network's bars;
   - move the list up.
6. **Navigable nodes:** a persistent brighter ring at rest. No `›`, which
   reads as a menu row.
7. **Truth:**
   - a line plus a cure for every non-profile leak;
   - Automatic lists the servers actually seen;
   - "ready" only when failover is eligible.
8. **Failover:**
   - Quad9 by default;
   - reachability from gateway ICMP plus the fallback query;
   - warning wording when router trust rests on the MAC.
9. **No silent passes:**
   - the downgrade check reports "unknown" on timeout (or reads the journal);
   - adopt only fallbacks qnet recognises;
   - gravity empty or stale counts as degraded.

## Known issues (open, from round 3)

**Truth.**
- Non-profile leaks are computed but not drawn. resolved's compiled
  FallbackDNS (Quad9) has been used on this machine, and global DNS= and
  VPN/unmanaged-link leaks are missed the same way. Fix them in
  `Model.js` leak routing. The cure for the FallbackDNS leak is an empty
  `FallbackDNS=` in a resolved.conf drop-in.
- The resolved downgrade check uses `resolvectl show-server-state` with a
  3 s cap, and that often takes 5–15 s. A timeout reads as healthy. Read the
  journal instead.
- Failover adoption labels any foreign runtime DNS as "Fallback · router".
- Failover requires the router to answer DNS. Once the router forwards to the
  Pi-hole, check reachability with ICMP plus the public fallback instead.
- The "Automatic → router" label omits the IPv6 RA servers (Google).
  `failoverInfo` says "ready · router" even when failover is ineligible.
- The canary proves the exact deny list, not gravity. Gravity health (count
  and age) is not checked.
- The own-query ledger covers only ~110 min of the 24 h window, and upstream
  shares include qnet's own probes.

**Engineering.**
- NM device PropertiesChanged signals (Rx/TxBytes etc.) trigger full re-reads
  while the panel is closed.
- Radio and scan guards are check, act, stamp with no lock. Wi-Fi verbs aren't
  serialised against each other.
- The ActionRunner timeout doesn't wait for the process or escalate to KILL.
  A heartbeat `seq` gap doesn't trigger a refresh.
- No Rust → JS fixture contract test.
- `Model.js` is 1,835 lines and wants splitting.
- While the Pi-hole is down, the suspect cadence probes every 5 s. Back it off.

**UX.**
- Clickable route nodes have no resting cue; add `›` on their captions.
- Inactive-profile leaks show a warning badge in the healthy state.
- The query count outranks "% blocked".
- Duplicate signal and IP figures.
- The Wi-Fi view card doesn't use the route language.
- "Scan (r)" tooltip overflow.

**Security** (no exploitable holes found; hygiene):
- A cloned router MAC passes the router-trust check. Document it as mis-network
  detection only, and consider Quad9 as the default fallback.
- Absolute paths for helper binaries.
- Portal profile in `$XDG_CACHE_HOME`.
- `neigh` should skip bad ARP lines.

# qnet: watchdog support (plan)

Date: 2026-11-11. Branch `watchdog`. Backend and CLI only: no QML or panel
changes (a UI comes later, after mockups). The data is exposed in the watcher's
state JSON for that later UI.

qberrypi (the Pi-hole replacement) adds a watchdog behind the same login as the
Pi-hole API. Its endpoints, all under `/api/qbp/` (exact JSON from qberrypi's
`api/qbp.rs`):

| Call | Answer |
|---|---|
| `GET alerts[?since=R]` | `{"rev", "suppressed", "alerts":[{id, key, rev, kind, severity, client, subject, first_unix, last_unix, count, acked}]}`, the alerts changed after `R`, oldest change first. `key` is 16 lower-case hex, stable across Pi reboots; `id` and `rev` restart at a reboot. `client` is an IP string or null. `severity` is `info`, `warn` or `high`. |
| `POST alerts/{id}/ack` | `{"acked":true}`, 404 for an unknown id |
| `PUT alerts/acked` | `{"acked":["<16 hex>",…]}` → `{"restored":n}`; additive; Pi keeps at most 1024 |
| `GET devices` | `{"known_list":"waiting|learned|received","devices":[{mac, ipv4[], hostname, first_unix, last_unix, known}]}` (mac lower-case `aa:bb:…`) |
| `PUT devices/known` | `{"known":[mac…],"append":bool,"complete":bool}` → `{"known":n}`; body cap 4096 bytes (≈200 MACs); a list takes effect on the `complete` chunk; Pi keeps at most 1024 |

Kinds raised today: `new_device`, `arp_spoof`, `dga`, `tunnel`, `beacon`,
`burst`, `threat`, `rebind`. A real Pi-hole answers 404 on all of these: qnet
then calls the watchdog **absent** and behaves exactly as before.

## Design

### Pieces

- `pihole.rs`: `Pihole::json_opt(method, path, body) -> Result<Option<Value>, ApiError>`
  (like `json`, but HTTP 404 is `Ok(None)`), and `Pihole::logins() -> u64`, a
  counter bumped on every successful login (a new session).
- `watchdog.rs` (new): the wire types and their parsers (invalid entries are
  dropped, strings cleaned of control characters and capped), the qbp calls
  (`Absent` on 404), titles by kind, notification escaping, burst folding,
  known-list chunking, and the one-cycle poll logic used by the API thread.
- `wdstore.rs` (new): the PC-side store `~/.local/state/qnet/watchdog.json`
  (0600, `util::atomic_write`, read-modify-write under a blocking-with-timeout
  `flock` on `watchdog.lock`, since the CLI and the watcher both write it):
  - `acked`: `[{key, at}]`, at most 1024, oldest dropped;
  - `known`: `[{mac, label?, firstSeen}]`, at most 1024, MAC normalised to
    lower-case colon form, label cleaned (no control chars, ≤ 64 chars);
  - `knownGen` / `pushedKnownGen`: bumped by every known-list edit / set to
    `knownGen` by whoever pushes it successfully;
  - `notified`: `{key: first_unix}`, at most 1024 (oldest dropped): which alert
    instances already got a desktop notification, so a shell restart does not
    repeat them.
- `threads.rs`: the API thread runs the watchdog cycle; `Event::Watchdog(WatchdogReport)`
  carries the result to the main thread. Injected deps (`WatchdogDeps`: store
  path, notifier) so tests never touch the real state dir or `notify-send`.
- `state.rs` / `watch.rs`: a top-level `watchdog` object in the state JSON.
- `main.rs`: `qnet watchdog …` verbs.
- `desktop_notify` passes `--` before the title so a body/title starting with
  `-` is never read as a `notify-send` option.

### Presence

`unknown` until the first qbp call is answered; `present` on any 2xx; `absent`
on 404. Once absent, no qbp request is made again until a new config or a new
login session (one extra request per session, never per poll). While the
panel is **closed**:
- one presence check `ApiTiming::wd_first_delay` (30 s) after start, which
  logs in; if absent, the thread logs out again at once (closed qnet holds no
  session, as today);
- an auth failure (missing secret, locked keyring) parks the closed poll until
  the next `Open`/`Config`, so a locked keyring is never asked every minute;
- other failures retry on the existing backoffs (tls 30 s, else 60 s).

### Cadence

- Open: every stats poll (10 s) is followed by the watchdog cycle;
  `GET devices` on open and then on the history cadence (60 s).
- Closed and present: the watchdog cycle alone every `wd_closed_every` (60 s):
  alerts only, no stats, no `Event::Api`. Its failures go to
  `watchdog.status`, never to `pihole.api`.
- Absent: nothing, open or closed (stats polling exactly as today).

### One watchdog cycle

1. **Push if due** (acks first, then the known list):
   - due when this client has never pushed, its `logins()` changed since the
     last push (a new session: the Pi may have rebooted), the alerts `rev`
     went backwards, `known_list` was seen as `waiting`, or
     `knownGen != pushedKnownGen`;
   - acks: `PUT alerts/acked` in bodies ≤ 4000 bytes (skip when none);
   - known: chunked `PUT devices/known` (first `append:false`, last
     `complete:true`, each body ≤ 4000 bytes) only when the PC list is
     non-empty, or when `knownGen != pushedKnownGen` (an explicit edit that
     emptied it). An empty list is otherwise never pushed: it would make the
     Pi raise every device; without a list the Pi learns silently.
   - a failed push stays due; success records `pushedKnownGen`.
2. `GET alerts?since=<cursor>` (0 at start). `rev < cursor` means the Pi
   restarted: reset cursor and the in-memory alert map, mark the push due, do
   it, and fetch again from 0 (at most once per cycle).
3. Merge into the in-memory map (by id, at most 256, newest kept). Alerts the
   Pi reports `acked` add their key to the store's `acked` (acks made on the
   Pi's own panel survive its reboot too).
4. Notify: an alert is new when `!acked` and its key is not in `notified` or
   its `first_unix` is later than the one recorded (a fresh instance after a
   reboot). Title by kind, body `subject · client` (client omitted when null),
   both escaped. **Folding:** at most 3 individual notifications per rolling
   60 s; the rest accumulate and go out as one `"N more alerts"` notification,
   itself at most once per 60 s (leftovers carry to the next allowed cycle).
5. Open and devices due: `GET devices`; `waiting` with a non-empty PC list
   marks the push due (done in the same cycle).
6. Send `Event::Watchdog`.

Titles: `new_device` "New device on the network", `arp_spoof` "Router
impersonation (ARP spoofing)", `dga` "Suspicious lookups (DGA)", `tunnel`
"Possible DNS tunnel", `beacon` "Regular beaconing", `burst` "Burst of
lookups", `threat` "Threat blocked", `rebind` "DNS rebinding blocked",
anything else "Watchdog alert". Escaping: `&`→`&amp;`, `<`→`&lt;`, `>`→`&gt;`,
control characters → space, at most 200 characters.

### State JSON

```json
"watchdog": {
  "status": "unknown|ok|absent|auth|tls|unreachable",
  "rev": 41, "suppressed": 0, "unacked": 2,
  "alerts": [{ "id": 7, "key": "…16 hex…", "kind": "new_device", "severity": "warn",
               "title": "New device on the network", "client": null,
               "subject": "02:00:00:00:00:07", "firstUnix": 0, "lastUnix": 0,
               "count": 1, "acked": false }],
  "knownList": "waiting|learned|received|",
  "devices": [{ "mac": "02:00:00:00:00:07", "ipv4": ["192.0.2.7"], "hostname": "",
                "firstUnix": 0, "lastUnix": 0, "knownOnPi": false,
                "known": false, "label": "" }],
  "knownCount": 12, "pushedAt": 0, "pushError": "", "polledAt": 0
}
```

`alerts`: newest change first, at most 50. `devices`: last seen first, at most
128, `[]` until fetched (open only). With no Pi-hole configured, or absent,
everything is empty and `status` says why.

### CLI (one JSON line, exit code as the other verbs)

| Verb | Result |
|---|---|
| `qnet watchdog alerts` | `{"ok":true,"rev","suppressed","alerts":[…]}` (all alerts, `since` 0) |
| `qnet watchdog ack <id>` | looks the id up for its key, `POST …/ack`, records the key: `{"ok":true,"id","key"}`; `not-found` |
| `qnet watchdog devices` | `{"ok":true,"knownList","devices":[{mac,ipv4,hostname,firstUnix,lastUnix,knownOnPi,known,label}],"knownOffline":[{mac,label,firstSeen}]}` |
| `qnet watchdog know <mac> [label]` | edits the PC list, then pushes it: `{"ok":true,"mac","known":n,"pushed":bool,"pushError"?}` |
| `qnet watchdog forget <mac>` | as `know`; `not-found` if not on the list |
| `qnet watchdog know-all` | adds every device the Pi has seen: `{"ok":true,"added":n,"known":n,"pushed":bool}` |

Errors: `absent` (the Pi-hole has no watchdog), `not-found`, `invalid`, plus
the existing `unconfigured`, `auth`, `interrupted`. `know`/`forget` still edit
the PC list when the push fails or the watchdog is absent (`pushed:false`):
the watcher pushes it later (`knownGen`).

## Tasks (one fresh Sonnet implementer each, in order)

1. **Core:** `pihole.rs` additions, `watchdog.rs` (types, parsers, qbp calls,
   titles, escaping, folding, chunking), `wdstore.rs`, `desktop_notify --`.
   Tests: parsing and dropping bad entries; 404 → absent against a fake
   server; chunks each ≤ 4000 bytes with the right flags (1, 2 and 6 chunks,
   order kept); escaping; folding windows; store round-trip, bounds, lock.
2. **Watcher:** the cycle in the API thread, cadence, presence,
   `Event::Watchdog`, the `watchdog` state object. Tests with the fake HTTPS
   server: a real Pi-hole (404) is absent, makes no further qbp requests and
   closed qnet logs out; closed + present polls alerts only; a new session /
   rev going backwards / `waiting` re-pushes acks and the chunked list;
   notification count and folding through the injected notifier; existing
   API-thread tests unchanged in meaning.
3. **CLI:** the verbs in `main.rs`, actions against the fake server, parse
   tests.
4. **Docs:** SPEC.md (process model error codes, data sources table, state
   JSON, field rules, actions, state files) and README.

Gates before every commit, from `backend/` with
`TMPDIR=$PWD/target/tmp CARGO_TARGET_DIR=$PWD/target`: `cargo test`,
`cargo clippy --all-targets` (0 warnings), `cargo fmt --check`; and
`node --test tests/` from the repo root. Test data uses 192.0.2.x and
02:00:00:… only.

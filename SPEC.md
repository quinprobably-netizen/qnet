# qnet (`qqq.qnet`): spec (v1)

A bar widget that replaces `omarchy.network` (the Wi-Fi and connection panel)
and knows about the owner's Pi-hole. A thin QML panel sits over a Rust binary,
`qnet` (`~/.local/bin/qnet`), the same split as `qqq.soundhub`. The baseline
council rated the stock panel. Its biggest failure was lying about DNS: it showed
"DHCP" while every query went to the Pi-hole, and one click on that lit pill
wiped the Pi-hole pin from every profile.

## Goals, in priority order

1. **Tell the truth about DNS.**
   - Show the resolver that actually answers, read per link from
     systemd-resolved.
   - Never light a wrong tile.
   - Tapping the current mode does nothing.
   - If anything bypasses the Pi-hole, say which link or profile and which
     server.
2. **Pi-hole support.**
   - Health: reachable, latency, and a canary query proving it blocks.
   - Today's numbers, and a live query-flow hero.
   - Pause blocking for 5 minutes, and resume.
   - Safe automatic failover, and recovery.
   - Watchdog: when the Pi-hole is a qberrypi, qnet also fronts its watchdog
     (alerts, devices, desktop notifications, and the acknowledged and known
     lists kept on this PC, and the exempt list). Against a real Pi-hole
     nothing changes.
3. **Passive Wi-Fi.** NetworkManager over D-Bus, event-driven, using NM's
   cached access-point list. Scan only on an explicit request (`qnet wifi
   scan`, at most once per 15 s); opening the panel never scans. The AX210 is
   fragile. With the panel closed, cost should be close to zero.
4. **Identity beside Sound Hub and Overclock.**
   - A live graph header.
   - Accent for every "on" state; grey only for the keyboard cursor.
   - One bar font and one sentence-case label style.

## Process model

- `qnet watch` is one long-lived child of the panel.
  - **stdout:** one JSON object per line. A full `state` snapshot on start,
    then a fresh snapshot on every change (coalesced, at most 4 per second).
    After 10 s with nothing to say, a bare heartbeat `{"type":"hb","seq":N}`
    (`seq` is the seq of the last `state` line; it does not advance). A
    heartbeat is never a snapshot. Time-driven changes (an expiring reading)
    are sent as a `state`, not hidden behind a heartbeat.
  - **stdin:** one command per line: `open`, `closed`, `refresh`. `open` and
    `closed` set the cadence. It never waits for EOF to act on a line.
  - The panel spawns no other periodic processes.
  - On exit (stdin EOF, SIGTERM, SIGINT, SIGHUP, or the parent dying:
    `PR_SET_PDEATHSIG`) it ends the Pi-hole API session (`DELETE /api/auth`)
    and returns a runtime failover to the saved profile **only if the last
    probe passed**; if the Pi-hole is still down the fallback stays and the
    next start adopts it. A closed stdout also ends it.
  - Because SIGKILL cannot be handled, the Pi-hole session id is kept in
    `$XDG_RUNTIME_DIR/qnet/sid` (file 0600, directory 0700, bound to the
    Pi-hole address) and reused on the next start if the Pi-hole still calls
    it valid, so a killed `watch` never leaks a session slot. A process removes
    the file on logout only if it still holds *its own* session id.
  - **Pi-hole API thread:** it polls the stats only while the panel is open.
    It also runs while the panel is closed, for the watchdog only: one alerts
    request a minute, no stats and no change to `pihole.api`, and only while
    the Pi-hole turns out to be a qberrypi (see "Watchdog (qberrypi)"). A real
    Pi-hole is asked once while closed, ever: 30 s after start it is one
    login, one request and one logout, and the verdict ("no watchdog here",
    for this address and pin) is saved in the watchdog store. From then on a
    closed qnet makes no watchdog request at all, not even after a restart:
    no client is built and the keyring is not read. An open panel still looks
    once per session, which is how a Pi-hole that was replaced by a qberrypi
    is noticed (the verdict is cleared when a watchdog is seen). Until the
    Pi-hole has answered at all (away from home, the Pi-hole down, never
    asked) a failing closed poll backs off instead of repeating every minute:
    60 s, 120 s, 240 s and so on up to 30 min (a TLS failure starts at 30 s),
    starting again after a success, on `open` or on a new config.
- One-shot actions are `qnet <verb> ...`.
  - Each prints one JSON line, `{"ok":true,...}` or
    `{"ok":false,"error":"..."}`, and the exit code matches.
  - Every DNS-changing verb ends by sending one DNS query through the system
    resolver (resolved D-Bus `ResolveHostname`) and reports the server now in
    use as `{"verifiedVia":"192.168.1.153"}`. For `qnet dns pihole` (and the
    pin of the active profile) `verifiedVia` appears **only if the canary
    came back 0.0.0.0**, together with `"blocked":true`; otherwise there is
    `"blocked":false` and a `"verifyError"` and no `verifiedVia`.
- Cross-process state lives in `$XDG_RUNTIME_DIR/qnet/` (dir 0700; falls back
  to `~/.local/state/qnet/`): `sid` (see above), `dns.lock`, `scan`, `radio`.
  - **DNS lock:** every DNS-changing verb (`dns pihole|auto|pin`) and the
    watcher's failover engage/recover take a non-blocking `flock` on
    `dns.lock` for the whole operation. If it is held the verb answers
    `{"ok":false,"error":"busy"}` and changes nothing; the watcher skips that
    attempt and retries after its cool-down.
  - **Error codes the panel should know:** `too-soon` (with `retryInS`, from
    `wifi scan` and `wifi radio`), `busy`, `confirm`, `interrupted`,
    `partial`, `unconfigured`, `enterprise`, `badpass`, `auth`, `nolink`,
    `radio`, `rfkill`. The `watchdog` verbs add `absent` (the Pi-hole has no
    watchdog), `not-found` (no such alert, or the device is not on the known
    or exempt list), `full` (the known list already holds 1024 devices, or the
    exempt list 64) and `store` (the PC-side watchdog store could not be
    written).
  - **One-shot verbs and signals:** except the interactive `pihole setup`,
    they catch SIGTERM/SIGINT/SIGHUP. The step in progress finishes (a
    profile that was written is applied, a half-made Wi-Fi profile is
    deleted), the next step is not started, the Pi-hole session is logged
    out, and the verb ends with `"interrupted"` (error, or `"interrupted":
    true` on a result that was applied but not checked).
- The watchdog keeps its own state in `~/.local/state/qnet/watchdog.json`
  (file 0600, directory 0700), with `watchdog.lock` beside it.
  - **Holds:** `acked` (the keys of the alerts acknowledged, and when),
    `known` (the known-device list: MAC, optional label, when it was first
    seen), `knownGen` and `pushedKnownGen` (which edit of that list the Pi
    has), `notified` (the alert instances that already got a desktop
    notification, so a restart repeats none), `absentFor` (only while set:
    `"<address>|<pin>"` of the Pi-hole that was found to have no watchdog, see
    the API thread above) and `version`. Each list keeps at most 1024 entries.
  - **The exempt list has a file of its own,** `watchdog-exempt.json` in the
    same directory (mode 0600): `exempt` (the devices that skip ad blocking,
    entries as in `known`, at most 64: the Pi takes the list in one body of
    that size), `generation` and `pushedGeneration` (which edit of it the Pi
    has) and `version`. Why: a qnet from before the exempt list ignores
    fields it does not know and writes `watchdog.json` back without them, so
    an older watcher that is still running after an upgrade would erase a
    list kept there; it never touches a file it does not know. The two files
    are one store: read together, written together under the one lock, and
    only the file that changed is written. A `watchdog.json` from before the
    split may hold the list (`exempt`, `exemptGen`, `pushedExemptGen`): while
    the new file is absent it is read from there, and the next update moves it
    and writes `watchdog.json` without it; from then on the new file wins. A
    store without any exempt list loads with an empty one and no new file is
    made until it is edited.
  - **Writers:** the watcher (keys the Pi reports as acknowledged,
    `notified`, `pushedKnownGen` after a push, `pushedGeneration` of the
    exempt list) and the one-shot verbs
    `watchdog ack|know|forget|know-all|exempt|unexempt`. Two processes can write it, so every
    change is a read-modify-write under an exclusive `flock` on
    `watchdog.lock` and replaces the file atomically. Unlike the DNS lock this
    one waits, up to 2 s: a blocking `flock` queued in the kernel (on a helper
    thread, so the 2 s bound holds), so a process that takes the lock again at
    once after releasing it cannot starve one that is waiting. If it stays
    taken, a verb answers `store` and the watcher tries again on its next
    cycle.
  - **A damaged file is kept.** A missing file is an empty store. A file that
    cannot be read or parsed is renamed to `watchdog.json.bad-<unix seconds>`
    (mode 0600; a `-2`, `-3`, … is added rather than replace an earlier one)
    before the first change is written, and that change starts from an empty
    store: the labelled known list and the acks are never silently
    overwritten. If it cannot be moved aside the change fails (`store`).
    Reading (the state JSON, `watchdog devices`) treats such a file as empty
    and writes nothing. The exempt list's file is kept the same way, as
    `watchdog-exempt.json.bad-<unix seconds>`, and independently: a damaged
    `watchdog.json` does not take the exempt list with it, nor the other way
    round.
- Secrets never go on argv: Wi-Fi passphrases and the Pi-hole web password
  arrive on stdin (one line; the reader never waits for EOF). Untrusted
  strings reach processes only as argv elements. There is no shell anywhere
  (`sh -c` / `bash -c` are forbidden). Secrets are held in zeroizing buffers
  and the verbs that handle them (and `watch`) set `PR_SET_DUMPABLE=0`.
  - **Yama:** `PR_SET_DUMPABLE=0` is what stops a same-user process from
    reading qnet's memory when `kernel.yama.ptrace_scope` is 0 (classic
    ptrace permissions). With ptrace_scope ≥ 1 that is already blocked for
    non-descendants. It is not a defence against root, and a process that
    runs as you can still read the keyring if it is unlocked.
  - **The app password is a full Pi-hole admin credential** (it can change
    any setting, add or delete lists and clients, and log in to the web UI).
    Anyone who can read the Secret Service entry `service qnet pihole <addr>`
    has the Pi-hole. qnet only ever uses it for the read calls and for
    pause/resume, but it is not scoped down; treat the keyring accordingly.

## Data sources (watch)

| What | Source | Cadence |
|---|---|---|
| Devices, primary connection, connectivity, Wi-Fi AP (ssid bytes, strength, freq, bitrate), IP4 address and gateway | NetworkManager D-Bus PropertiesChanged signals | event-driven; re-read on `open` |
| Access points | NM `Device.Wireless.AccessPoints`, `LastScan` | event-driven; read on `open`, ignored while closed. `RequestScan` only via `qnet wifi scan [--if-stale <secs>]` (never on `open`; at least 15 s after both NM's `LastScan` and qnet's own last request) |
| Saved profiles and their DNS settings | NM Settings `ListConnections` / `GetSettings` | on start, and on NewConnection, ConnectionRemoved, Updated |
| Resolver truth | resolved D-Bus `org.freedesktop.resolve1` Manager `DNSEx`, `CurrentDNSServerEx` (a server with ifindex 0 is resolved's global pick, only possible from the compiled `FallbackDNS`), `FallbackDNSEx`; per-link `DefaultRoute` | on NM change, plus every 30 s |
| resolved's rating of the Pi-hole | `resolvectl show-server-state` (argv-only child, 3 s limit): a link server dropped to "UDP" or "TCP" (from "UDP+EDNS0") is a downgrade, shown as `health: degraded`. Only a health note; it never feeds the failover. The journal shows this happens here every few minutes ("Using degraded feature set UDP instead of UDP+EDNS0 for DNS server …"), so the probes also carry an EDNS0 OPT record like resolved's | only while open: on open, then every 30 s |
| Pi-hole health | Raw UDP DNS sent straight to the Pi-hole. An A query for the canary must return `0.0.0.0` (blocking) or a real address (paused). Timeout 1.5 s, a timed-out probe is retried once at once; the RTT is the latency. The canary is the dedicated `qnet-canary.invalid` when the Pi-hole blocks it (it is on the exact deny list, added at setup; looked for again every 10 min while absent), otherwise the configured `canary`. | every 15 s closed, 5 s open; after any failed cycle every 5 s until 6 good cycles in a row (keeps failover ≈ 35 s and recovery ≈ 15 s) |
| Upstream check | A random label under `example.com` (`<16 hex>.example.com`) sent to the Pi-hole. NOERROR or NXDOMAIN is healthy; SERVFAIL, REFUSED or a timeout means "degraded". Only run when the canary answered. | every 60 s closed, 15 s open |
| Gateway gate | The canary probe sent to the gateway on port 53 (the router answers DNS). Also records whether the router itself answered `0.0.0.0` (it forwards to the Pi-hole, so it is no fallback) | while the Pi-hole probe is failing **or its upstream check is** |
| Web API liveness | One pinned HTTPS `GET /api/dns/blocking` (3 s cap, 1.5 s here); a completed pinned handshake counts as "alive" whatever the HTTP status | only when the canary went unanswered (to decide whether it is an outage) and once when a router is to be recorded |
| Gateway latency | In-process unprivileged ICMP echo (`SOCK_DGRAM`, `IPPROTO_ICMP`; needs `net.ipv4.ping_group_range`) to the gateway; no child process | only while open, every 5 s |
| Pi-hole stats | HTTPS API on 443 with the **pinned cert SHA-256**: `/api/stats/summary`, `/api/dns/blocking` | only while open, every 10 s; `/api/history` and `/api/stats/upstreams` every 60 s and on open |
| Watchdog alerts (qberrypi only) | `GET /api/qbp/alerts?since=<rev>` on the same pinned HTTPS session | open: after every good stats poll (10 s). Closed: 30 s after start, then every 60 s, while the watchdog is present; while the Pi-hole has not answered yet, a failing poll waits 60 s, 120 s, … up to 30 min. Never again once it is absent, until a new login session or a new config, and not at all while closed once the store says this Pi-hole is absent (`absentFor`) |
| Watchdog devices (qberrypi only) | `GET /api/qbp/devices` | open only: on open, then every 60 s. Never while closed |
| Watchdog pushes | `PUT /api/qbp/alerts/acked`, `PUT /api/qbp/devices/known` and `PUT /api/qbp/devices/exempt` | only when due (see "Watchdog (qberrypi)"): the first cycle of a session, a new login (in the same cycle), a Pi restart, a Pi that is `waiting` for its list, an edit of the known list (of the exempt list for its own call). Each body is at most 4000 bytes (the Pi's cap is 4096), so the known list goes in chunks; the exempt list is one body of at most 64 addresses. An empty known list is pushed only when an edit emptied it; the exempt list is pushed empty too, see "Watchdog (qberrypi)" |

### Pi-hole API sessions

- Log in once (`POST /api/auth` with the app password from the keyring) and
  keep the SID in memory and in `$XDG_RUNTIME_DIR/qnet/sid` (see above). The
  SID is checked to be visible ASCII before it is used or saved.
- Reuse it until a 401, then log in once more.
- `DELETE /api/auth` on a clean exit. Never log in per request: a Pi 3B+ has
  few session slots.
- Backoff after a failure: 60 s for auth problems (including a keyring that
  is locked or does not answer), 30 s for TLS problems.
- Response bodies are capped at 256 KiB; requests time out after 3 s. The
  pinned-certificate verdict is reset for every request.
- The watchdog uses the same session. A closed qnet whose Pi-hole has a
  watchdog keeps its session between the minute polls (only the idle
  connection is closed). If the closed poll finds there is none, it logs out
  again at once, so a qnet that was never opened holds no session, as before.

### Our own queries

The canary, its retries and the upstream check are queries the Pi-hole logs.
`watch` keeps a tally in 10-minute buckets for the Pi-hole's rolling 24 hours
(`~/.local/state/qnet/self-queries.json`, saved every 5 min and on exit) and
subtracts it from `today` and from each `history` bucket.

## State JSON (the contract between watch and QML)

```json
{
  "type": "state",
  "seq": 42,
  "link": {
    "kind": "wifi|ethernet|none",
    "device": "wlp7s0",
    "connection": "Redwood",
    "uuid": "…",
    "ssid": "Redwood",
    "signal": 72,
    "band": "5 GHz",
    "bitrateMbps": 866,
    "frequencyMhz": 5180,
    "prefix": 24,
    "signalDbm": null,
    "ip4": "192.168.1.242",
    "gateway": "192.168.1.1",
    "gatewayMs": 4.1,
    "connectivity": "full|limited|portal|none|unknown",
    "portalUrl": ""
  },
  "radio": { "wifiEnabled": true, "hwEnabled": true },
  "networks": [
    {
      "id": "/org/freedesktop/NetworkManager/AccessPoint/12",
      "ssid": "Redwood",
      "hidden": false,
      "signal": 72,
      "security": "open|psk|sae|owe|enterprise",
      "known": true,
      "uuid": "…",
      "active": true,
      "band": "5 GHz",
      "frequencyMhz": 5180
    }
  ],
  "scan": { "running": false, "lastScanAgeS": 12 },
  "dns": {
    "mode": "pihole|fallback|auto|custom|none|unknown",
    "modeSource": "profile|runtime-failover",
    "servers": [
      { "addr": "192.168.1.153", "link": "wlp7s0", "current": true, "role": "pihole|router|public|other" }
    ],
    "leaks": [
      { "kind": "link|profile|ipv6-ra", "where": "Wired connection 1", "uuid": "…", "detail": "uses router DNS (automatic)" }
    ],
    "failover": { "enabled": true, "fallback": "router|quad9|cloudflare", "active": false, "since": 0, "reason": "" },
    "manualOverride": false,
    "bypassed": false,
    "resolvedFallback": ""
  },
  "pihole": {
    "configured": true,
    "address": "192.168.1.153",
    "adminUrl": "https://192.168.1.153/admin/",
    "reachable": true,
    "latencyMs": 3.1,
    "blocking": "enabled|disabled|unknown",
    "pauseRemainingS": 0,
    "api": "ok|auth|tls|unreachable|unconfigured",
    "health": "ok|degraded|unreachable|unknown",
    "healthReason": "",
    "canaryBlocked": true,
    "today": { "total": 1204, "blocked": 164, "percent": 13.6, "selfQueries": 14 },
    "history": [{ "t": 1794034800, "total": 40, "blocked": 6 }],
    "historySpanS": 21600,
    "upstreams": [{ "name": "dns9.quad9.net", "ip": "9.9.9.9", "port": 53, "count": 287, "responseMs": 159.2 }],
    "answeredBy": { "blocklist": 1734, "cache": 1075, "forwarded": 430 },
    "detected": "",
    "probes": [{ "t": 1794035000.1, "ok": true, "ms": 3.1, "blocked": true }]
  },
  "watchdog": {
    "status": "unknown|ok|absent|auth|tls|unreachable|unconfigured",
    "rev": 41,
    "suppressed": 0,
    "unacked": 1,
    "alerts": [
      { "id": 7, "key": "a1b2c3d400000007", "kind": "new_device", "severity": "info|warn|high",
        "title": "New device on the network", "client": null, "subject": "02:00:00:00:00:07",
        "firstUnix": 1794000000, "lastUnix": 1794000050, "count": 1, "acked": false }
    ],
    "knownList": "waiting|learned|received|",
    "devices": [
      { "mac": "02:00:00:00:00:07", "ipv4": ["192.0.2.7"], "hostname": "", "firstUnix": 1794000000,
        "lastUnix": 1794000050, "knownOnPi": false, "known": true, "label": "Printer",
        "exemptOnPi": false, "exempt": true }
    ],
    "knownCount": 12,
    "pushedAt": 1794000001,
    "pushError": "",
    "polledAt": 1794000005
  },
  "error": ""
}
```

Field rules:

- **`networks`:**
  - `id` is the NM access-point object path. Actions use it, never the SSID
    string.
  - The SSID is decoded lossily for display only, with control characters
    stripped. Hidden networks (empty SSID) have `hidden: true` and cannot be
    connected from the list.
  - Grouped by SSID with the strongest AP shown. At most 40.
- **When a `state` line is sent.** Whenever the state differs from the last
  line sent, at most 4 per second. While the panel is closed `pihole.probes`,
  `pihole.latencyMs` and `link.bitrateMbps` do not count, so a healthy closed
  probe produces only a heartbeat. `watchdog.polledAt` never counts, open or
  closed, so a quiet watchdog poll is a heartbeat too. `open` always sends the
  full state.
- **`link.frequencyMhz`, `link.prefix`:** the active access point's channel
  frequency in MHz (`null` off Wi-Fi), and the IPv4 prefix length of `ip4`
  (`null` without an address); both straight from NetworkManager's D-Bus
  (`AccessPoint.Frequency`, `IP4Config.AddressData` `prefix`). Each
  `networks[]` entry has its own `frequencyMhz`.
- **`link.signalDbm`:** always `null`. NetworkManager's D-Bus API gives only
  the percentage (`link.signal`); qnet does not poll `iw` or the supplicant.
- **`pihole.upstreams`:** from `GET /api/stats/upstreams`, refreshed on open
  and every 60 s while open: at most four real resolvers, busiest first,
  `{name, ip, port, count, responseMs}` (`name` is `""` when Pi-hole has none,
  `responseMs` is `null` without a figure; Pi-hole reports seconds). Entries
  whose address, port or count do not validate are dropped. The counts are
  Pi-hole's own.
- **`pihole.answeredBy`:** `{blocklist, cache, forwarded}` from the same
  answer: the pseudo-entries `blocklist` and `cache`, and the queries that went
  to an upstream. qnet's own probes are taken out (the blocked ones from
  `blocklist`, the rest from `forwarded`), like for `today`.
- **`failover.fallback`:** the fallback actually in use while `failover.active`
  (it may differ from the configured one: quad9 stands in for an untrusted
  router), the configured one otherwise. `failover.reason` says why.
- **`dns.mode` `fallback`:** only for the link that actually failed over. If
  another link has become primary, that link's own mode is shown while
  `failover.active` stays true.
- **`scan`:** `running` is always `false` (the watcher never scans);
  `lastScanAgeS` is NM's last-scan age, kept counting between reads, `null` if
  there has never been a scan.
- **`link.gatewayMs`:** round trip of an ICMP echo to the gateway, `null` when
  the panel is closed, the gateway is unknown or it did not answer (or the
  last answer is older than 20 s).
- **`dns.mode`:** what resolved is actually using on the primary link.
  - `pihole`: the Pi-hole is among the servers (see `bypassed`);
  - `auto`: servers come from DHCP/RA and the profile has no manual DNS;
  - `custom`: other servers, the Pi-hole not among them;
  - `fallback`: a runtime failover is active (`modeSource` is then
    `runtime-failover`);
  - `none`: no link, or the link is up with no DNS servers (resolved would use
    its compiled fallback list);
  - `unknown`: no Pi-hole is configured and a LAN candidate is still being
    checked. `custom` is never reported while that is pending.
- **`dns.bypassed`:** true only with a configured Pi-hole and mode `pihole`,
  `custom` or `auto`: other servers are in use next to (or instead of) the
  Pi-hole, the primary profile is not pinned (DHCP or router advertisements
  may add servers), or the link is on Automatic DNS that nobody chose.
  Automatic counts as chosen only if `qnet dns auto` recorded it for this very
  profile (`~/.local/state/qnet/auto-dns.json`; `dns pihole` and `dns pin`
  clear it). So plugging in a cable whose new profile is automatic warns,
  with a Pin action. A `fallback`, `none` and `unknown` are never a bypass.
- **`dns.resolvedFallback`:** the first of resolved's compiled `FallbackDNS`
  servers, only while the mode is `none` with a link up; otherwise `""`.
- **`dns.leaks[].kind`:** `link`, `profile`, `ipv6-ra`, or `resolved-fallback`
  (`where: "systemd-resolved"`): resolved's compiled-in `FallbackDNS` has been
  picked as its global server while links have servers of their own, so
  queries may leave for 9.9.9.9 & co. The detail names the servers; the cure
  is an empty `FallbackDNS=` in `resolved.conf`. Never raised when no link has
  servers (that is mode `none`) or when the global server comes from
  `resolved.conf`'s `DNS=` (reported as a `link` leak).
- **`dns.leaks`:** unchanged shape; the panel groups them. Inactive saved
  profiles with automatic or foreign DNS are always listed; the active link
  is listed when its servers include anything but the Pi-hole (except in a
  deliberate `auto`/`fallback`).
- **`pihole.address`, `adminUrl`:** only ever from the config file; `""` when
  unconfigured. `pihole.detected` holds a LAN Pi-hole seen blocking the canary
  when none is configured (display only: it is never used as the address, and
  `qnet pihole setup` does not take it from there).
- **`pihole.health`:** `unreachable` after two unanswered canary probes in a
  row; `degraded` when the canary is answered but the latest upstream check
  failed (SERVFAIL, REFUSED, timeout) or systemd-resolved has dropped the
  Pi-hole to plain UDP/TCP; `ok`; `unknown` before any probe or without a
  Pi-hole. `healthReason` is a short sentence for it ("" when `ok` or
  `unknown`); for `unreachable` it says whether the web API still answers.
- **`pihole.canaryBlocked`:** whether the last answered canary was `0.0.0.0`
  (`true`), a real address (`false`, e.g. paused), or `null` if none yet.
- **`pihole.today`:** the Pi-hole's 24-hour totals with qnet's own probe
  queries already subtracted; `selfQueries` is how many were taken out.
  `history` buckets have theirs subtracted too.
- **`pihole.historySpanS`:** seconds from the first non-empty history bucket
  to the end of the last one (at most 86400); 0 if there is none.
- **`history`:** at most 144 buckets (24 h × 10 min).
- **`probes`:** a ring buffer of the last 60 health probes. It drives the
  live edge of the hero.
- **`manualOverride`:** true when the active profile has DNS servers set that
  qnet did not write. qnet must confirm before overwriting them.
- **`watchdog.status`:**
  - `unconfigured`: no Pi-hole is configured; everything else is empty or 0;
  - `unknown`: configured, but no cycle has answered yet (also right after the
    Pi-hole's address or pin changed);
  - `ok`: the last cycle was answered;
  - `absent`: the Pi-hole has no watchdog (a real Pi-hole); the lists are empty;
  - `auth`, `tls`, `unreachable`: the last cycle failed. The data from earlier
    cycles stays. A watchdog failure shows here and never in `pihole.api`.
- **`watchdog.rev`, `suppressed`:** the Pi's alert revision and its own count
  of suppressed alerts, as of the last answer.
- **`watchdog.unacked`:** alerts not acknowledged among those qnet holds (at
  most 256), so it can be more than the 50 listed.
- **`watchdog.alerts`:**
  - Newest change first, at most 50.
  - `id` (and the top-level `rev`) start again at a Pi reboot; `key` (16
    lower-case hex) does not, so it is what tells an alert apart over time.
    `qnet watchdog ack` takes the `id`.
  - `title` is the notification title for `kind` (unescaped; an unknown kind
    reads "Watchdog alert"). `client` is an IP address or `null`. `severity`
    is `info`, `warn` or `high` (anything else reads `info`).
  - `subject` is text from the network, shown with control characters removed
    and cut to 255 bytes. Show it as plain text.
  - Entries without a usable id, key or kind are dropped.
- **`watchdog.devices`:**
  - Last seen first, at most 128.
  - `[]` until the first read, which happens only while the panel is open;
    after that the last read stays while it is closed. Read again on open and
    every 60 s.
  - `knownOnPi`: the Pi counts the device as known. `known`: it is on this
    PC's known list, the one pushed to the Pi. The two can differ: the Pi may
    have learned a device on its own, or a list edit may not have been pushed
    yet.
  - `label`: this PC's label for the device, `""` when there is none.
  - `exemptOnPi`: the Pi skips ad blocking for the device (threat blocking
    stays); `false` when the Pi does not say, as an older Pi does not.
    `exempt`: it is on this PC's exempt list, the one pushed to the Pi. As
    with the known flags the two can differ: the Pi's own config file can
    exempt a device, an edit may not have been pushed yet, or the Pi's
    software may not support exempt devices.
  - `ipv4` holds at most 4 addresses; `hostname` is cut to 64 bytes.
- **`watchdog.knownList`:** the Pi's list state: `waiting` (it has no list and
  wants one; qnet pushes the PC's list if it has one), `learned` (it built its
  own), `received` (a list was pushed to it), `""` (not read yet, or not a
  value qnet knows).
- **`watchdog.knownCount`:** the entries on this PC's known list at the last
  report, so it is also set while the status is `absent` or a failure; it is 0
  while `unconfigured` or `unknown`.
- **`watchdog.pushedAt`, `pushError`:** the time of the last push that sent
  something (0 = none yet in this run), and why the last push failed
  (`""` once one has worked). A failed push stays due.
- **`watchdog.polledAt`:** the time of the last cycle the Pi answered (0 =
  none). It moves with every poll, so it is not a change (see above).

## Actions

| Verb | Effect |
|---|---|
| `qnet dns pihole` | **Active connection's saved profile only.**<br>• Sets `ipv4.dns=<pihole>`, `ipv4.ignore-auto-dns=yes`, `ipv6.ignore-auto-dns=yes`, `ipv6.dns=` (blocks the IPv6 RA leak), then `Device.Reapply`.<br>• First saves the previous ipv4/ipv6 DNS settings to `~/.local/state/qnet/prev-dns/<uuid>.json` for undo.<br>• Refuses with `{"ok":false,"error":"confirm","detail":…}` when `manualOverride` is set and `--force` is absent.<br>• No-op only when already pinned **and** resolved shows nothing but the Pi-hole; an unpinned profile that merely happens to resolve through it is pinned.<br>• Records the network's gateway in the undo file `prev-dns/<uuid>.json` (`gateway`), which the failover uses to decide whether the router is trustworthy.<br>• Succeeds with `verifiedVia` only if the canary comes back blocked (see above). |
| `qnet dns auto` | Clears the active profile to automatic (the saved previous settings are restored only when they were automatic). Active profile only. Same confirm and no-op rules. Records Automatic as the user's choice for this profile (also on a no-op tap), before touching the profile. |
| `qnet dns pin <uuid> [<uuid>...]` | Applies the Pi-hole settings to inactive saved profiles, e.g. Wired connection 1. Saves undo state. No Reapply. With one uuid the result is as for `dns pihole` (the active profile is pinned the same way as `dns pihole`); with several each is pinned independently and the result is `{"ok":true,"results":[{uuid,…}],"verifiedVia":…}`, or `{"ok":false,"error":"partial","results":[…]}` if any refused. |
| `qnet pihole pause [secs=300]` / `resume` | `POST /api/dns/blocking {"blocking":false,"timer":secs}` / `{"blocking":true,"timer":null}` |
| `qnet pihole setup [addr]` | Interactive only (run from a terminal). With no address it asks "Pi-hole address:"; an address is never taken from network detection. Takes the web password at a no-echo prompt.<br>• Fetches the TLS cert and prints its SHA-256 for the user to accept (TOFU). On a re-setup it loads the pinned certificate for that address; if the new one differs it prints a loud `CERTIFICATE CHANGED (was …, now …)` and requires the word `yes` to be typed before the password is sent.<br>• Reads the existing `app_pwhash` first; if that cannot be read (or is not understood) setup stops before changing anything, so a later rollback can never write an empty hash over a real one.<br>• Warns if an app password already exists, because `app_pwhash` replaces it.<br>• Creates the app password (`GET /api/auth/app`, then `PATCH /api/config` with `{"config":{"webserver":{"api":{"app_pwhash":…}}}}`) and stores it with `secret-tool store` (secret on stdin; attributes `service qnet`, `pihole <addr>`). Creating it ends the setup session, so setup logs in again.<br>• Adds `qnet-canary.invalid` to the exact deny list (`POST /api/domains/deny/exact`, comment "qnet canary"), best effort.<br>• Writes the config. |
| `qnet wifi connect <ap-path>` | Passphrase on stdin; empty means an open or known network. Known: `ActivateConnection` of the matching profile. Unknown: `AddAndActivateConnection` with the secret in the settings dict. **Enterprise (802.1X) is refused** with `"error":"enterprise"`; the panel then opens `nmtui` in a terminal. qnet never creates an EAP profile. |
| `qnet wifi down`, `qnet wifi forget <uuid>` | NM D-Bus |
| `qnet wifi scan [--if-stale <secs>]` | `RequestScan`, but never closer than 15 s to **either** NM's `LastScan` or qnet's own last request (`$XDG_RUNTIME_DIR/qnet/scan`). Too soon: `{"ok":false,"error":"too-soon","retryInS":N}`. With `--if-stale`, a scan is requested only if both clocks are older than `<secs>`; otherwise `{"ok":true,"skipped":true,"lastScanAgeS":N}` (N = the younger of the two) and nothing is done. The 15 s rule still applies after that check. The panel calls `qnet wifi scan --if-stale 60` when the Wi-Fi view opens. |
| `qnet wifi radio on\|off` | NM `WirelessEnabled`. A request for the state it is already in is a no-op. A second *change* within 10 s of the last one (`$XDG_RUNTIME_DIR/qnet/radio`) is refused: `{"ok":false,"error":"too-soon","retryInS":N}`. |
| `qnet portal` | Opens `link.portalUrl`, or `http://neverssl.com`, in a normal **incognito window with a throwaway profile**: `chromium --user-data-dir=<new 0700 temp dir> --incognito <url>` (not `--app`: a portal page is untrusted web content). The temp dir is removed when the browser exits. |
| `qnet watchdog alerts` | Every alert the Pi holds, newest change first, in the shape of `watchdog.alerts` (not cut at 50): `{"ok":true,"rev","suppressed","alerts":[…]}`. Error: `absent`. |
| `qnet watchdog ack <id>` | Looks the alert up by `id` (`GET alerts`), `POST alerts/<id>/ack`, then records its key in the store so the Pi gets it again after a reboot. Result `{"ok":true,"id","key","saved":bool}`; `saved:false` means the Pi took it but this PC could not record it.<br>• Errors: `invalid` (not a whole number), `not-found` (no alert with that id, also when it vanished before the POST; nothing is written), `absent`. |
| `qnet watchdog devices` | Result `{"ok":true,"knownList","devices":[…],"knownOffline":[{mac,label,firstSeen}],"exemptOffline":[{mac,label,firstSeen}],"exemptOnPiOnly":[mac,…]}`.<br>• `devices`: everything the Pi reports (not cut at 128), last seen first, each as in `watchdog.devices`.<br>• `knownOffline`: devices on this PC's known list that the Pi did not report (`label` is `""` without one). `exemptOffline`: the same for this PC's exempt list.<br>• `exemptOnPiOnly`: the addresses on the Pi's effective exempt list (`exempt_macs`) that are not on this PC's: they come from the Pi's own config file. `[]` for a Pi that does not say.<br>• Error: `absent`. |
| `qnet watchdog know <mac> [label...]` | Puts the device on this PC's known list, or changes its label, then pushes the whole list. Without a label an existing one stays. A new entry's `firstSeen` is when the Pi first saw the device, or now if the Pi does not list it or cannot be asked. It pushes on every call, also when nothing changed.<br>• **Seeding:** the Pi raises a `new_device` alert for every device it has seen that is not on the list it is given, so replacing a list it made itself with one device would flood. When this PC's list is empty (and no edit that emptied it is still unpushed) and the Pi's `knownList` is `learned` or `received`, the Pi's devices that are `known` are put on this PC's list first (no label, `firstSeen` from the Pi), in the same locked edit, then the device is added and the whole list pushed. If the devices cannot be read, nothing is seeded. `forget` cannot reach that state: an empty list has nothing to forget.<br>• Result `{"ok":true,"mac","label"?,"known":n,"seeded"?:n,"pushed":bool,"pushError"?}`; `known` is the size of the list after the edit, `seeded` (only when more than 0) how many entries were taken over from the Pi.<br>• A failed push, or a Pi-hole with no watchdog (`"pushError":"absent"`), still leaves the edit: `pushed:false`, and the watcher pushes it later.<br>• Errors: `invalid`, `full` (a new device, the list holds 1024; nothing is pushed), `store`. |
| `qnet watchdog forget <mac>` | Takes the device off this PC's known list, then pushes the list; an emptied list is pushed too. Result as for `know`, without `label`. Errors: `invalid`, `not-found` (not on this PC's list; the Pi's own `known` flag does not count; no request is made), `store`. |
| `qnet watchdog exempt <mac> [label...]` | Puts the device on this PC's exempt list (or changes its label; without a label an existing one stays, a label is handled as for `know`) **and** on the known list exactly as `know` does (the owner named the device, so the Pi must not raise a new-device alert for it; the seeding of an empty known list applies too), in one locked edit. Then it pushes the known list, then the exempt list (`PUT /api/qbp/devices/exempt`, body `{"exempt":[…]}`, the whole list, at most 64 addresses; an emptied list is pushed too). It pushes on every call, also when nothing changed.<br>• Result `{"ok":true,"mac","label"?,"known":n,"exempt":n,"seeded"?:n,"pushed":bool,"pushError"?,"exemptPushed":bool,"exemptPushError"?}`: `known`, `seeded`, `pushed` and `pushError` are as for `know`; `exempt` is the size of the exempt list after the edit; `exemptPushed` and `exemptPushError` are the exempt push alone, so one failing never hides the other.<br>• A Pi (or a real Pi-hole) that answers 404 for the route has no exempt support: the edit stays and is saved, `exemptPushed:false` and `exemptPushError` says "the Pi's software does not support exempt devices yet". The watcher asks again once per login session. Any other failure leaves the edit too, and the watcher retries it on its next cycle.<br>• Errors: `invalid`, `full` (the exempt list holds 64 and this is a new device, or the known list holds 1024 and the device is not on it; nothing is changed or pushed), `store`. |
| `qnet watchdog unexempt <mac>` | Takes the device off this PC's exempt list, then pushes that list (an emptied list is pushed too). The device stays on the known list, which is neither changed nor pushed. Result `{"ok":true,"mac","exempt":n,"exemptPushed":bool,"exemptPushError"?}`; a 404 is reported as for `exempt`. Errors: `invalid`, `not-found` (not on this PC's exempt list; the Pi's own config list does not count; no request is made), `store`. |
| `qnet watchdog know-all` | Adds every device the Pi reports that is not on the list, in one edit (existing entries and labels are untouched; `firstSeen` comes from the Pi), then pushes. It pushes only if something was added or an earlier edit is still waiting to go.<br>• Result `{"ok":true,"added":n,"known":n,"pushed":bool,"skipped"?:n,"pushError"?}`; `skipped` counts devices that did not fit on a full list.<br>• Errors: `absent`, `store`. |

The `watchdog` verbs share these rules:

- A `<mac>` is six hex pairs with `:` or `-` between them, in either case; it is stored in lower-case colon form. Anything else is `invalid`, as is an `<id>` that is not a whole number.
- A `label` is the rest of the line, words joined by single spaces and taken as typed (even words that look like flags). Control characters are removed, the ends trimmed and it is cut at 64 characters (cut, not refused); nothing left means no label.
- A wrong shape of command is `usage`. Besides the errors above they can fail with `unconfigured`, `auth`, `tls`, `unreachable`, `api` (an answer qnet cannot use) and `interrupted`. The exit code matches `ok`, as for every verb.
- `know`, `forget`, `exempt` and `unexempt` need no watchdog to edit the lists; `alerts`, `ack`, `devices` and `know-all` answer `absent` without one.

## Failover (in `qnet watch`)

- **Eligible** only when the active profile's mode is `pihole` and
  `failover.enabled` is set.
- **Trigger** (all must hold):
  - the Pi-hole has been failing continuously for at least 30 s, over at
    least two probes (a probe is "failing" if the canary is unanswered, or the
    canary is answered but the upstream check keeps failing; a timed-out probe
    is retried once at once before it counts);
  - the link is up (NM device state ACTIVATED) and has been the same
    connection for 10 s;
  - the gateway answers the same DNS probe;
  - the Pi-hole's pinned web API does **not** answer (when the canary is
    unanswered). A completed pinned handshake means the host is alive, so the
    DNS silence is packet loss or spoofing, not an outage, and qnet does not
    fail over; a different certificate does not count as the Pi-hole being
    dead either. (This check is not made when the canary is answered but
    upstream resolution fails: then the web API being up is expected.)
  - the hold-down after the last recovery has passed (see below).

  A dead Wi-Fi card is not a Pi-hole outage, so in that case qnet does
  nothing.
- **Action:**
  - Runtime only: `Device.GetAppliedConnection`, change the DNS settings,
    then `Device.Reapply` with them. The saved profile is never written, so a
    crash can never leave you stranded on the fallback.
  - Keep `ipv6.ignore-auto-dns=yes`.
  - The fallback server is `router` (the gateway), `quad9` or `cloudflare`.
    `router` is used only if the router is verifiably the one the profile was
    pinned on: the gateway's **IP and MAC** (from `/proc/net/arp`) both match
    what `prev-dns/<uuid>.json` holds, **and** the router does not itself
    answer the canary with `0.0.0.0` (that means it forwards to the Pi-hole).
    Otherwise quad9 is used and `failover.reason` says why. The record is made
    by `dns pihole`, or learned once from a healthy pinned profile, but only
    after the Pi-hole's pinned web API has answered on that link; a record for
    a different router is never overwritten by the learning.
  - A DNS change is made under the DNS lock (see above); if it is held the
    attempt is retried after the cool-down.
  - The engaged interface and connection are remembered; recovery and exit
    restore **that** link even if the primary link has since changed. If the
    engaged link itself goes away the failover state is simply dropped (a new
    activation loads the saved profile).
  - Set `failover.active`, and send `notify-send "Pi-hole unreachable" "Using <fallback> DNS"`.
- **Recovery:** 3 consecutive good probes (canary answered and upstream
  working) sent straight to the Pi-hole, then Reapply the saved profile and
  notify.
- **Hold-down:** after a recovery, no new failover for 60 s, doubling for each
  recovery within the following hour, capped at 15 min; reset after an hour
  without trouble.
- **Never** fail over or touch DNS while the link is down or flapping, and
  never touch the radio.

## Watchdog (qberrypi)

qberrypi, the owner's Pi-hole replacement, has a watchdog behind the same login
as the Pi-hole API. It raises alerts (a new device, ARP spoofing, DGA lookups,
DNS tunnels, beaconing, bursts, blocked threats, DNS rebinding) and keeps an
inventory of the devices it has heard. qnet reads both over the pinned HTTPS
API, puts them in the `watchdog` object of the state JSON and raises desktop
notifications for new alerts. It keeps three lists on this PC and pushes them
back to the Pi, so they survive its reboots: the acknowledged alerts, the
known devices and the exempt devices (the ones that skip ad blocking; threat
blocking stays). A real Pi-hole answers 404 on all of it, and then qnet
behaves exactly as it did before. There is no panel for it yet.

Every call is under `/api/qbp/`, on the same session as the stats:

| Call | Answer, and what qnet does with it |
|---|---|
| `GET alerts?since=R` | `{rev, suppressed, alerts:[…]}`: the alerts that changed after revision `R`, oldest change first. The query is always sent (0 at the start). |
| `POST alerts/{id}/ack` | Acknowledges one alert; 404 for an unknown id. |
| `PUT alerts/acked` | `{"acked":[<key>…]}`. Additive; the Pi keeps at most 1024. |
| `GET devices` | `{known_list, devices:[{mac, ipv4[], hostname, first_unix, last_unix, known, exempt?}], exempt_macs?}`. `exempt` and `exempt_macs` (the Pi's effective exempt list: its config file's plus the pushed one, lower-case colon form) are absent on an older Pi: they read as `false` and an empty list. |
| `PUT devices/known` | `{"known":[<mac>…],"append":bool,"complete":bool}`. A list takes effect on the `complete` body; the Pi keeps at most 1024. |
| `PUT devices/exempt` | `{"exempt":[<mac>…]}`: replaces the Pi's pushed list, `[]` clears it, at most 64 addresses in one body (no chunking). Answers `{"exempt":n}`; 400 means the body was refused. The Pi holds the list in memory only. A 404 means this Pi has no exempt support (see below). |

Answers are parsed leniently. An alert without a usable `id`, `key` or `kind`
and a device without a valid MAC are dropped; other fields fall back to
harmless defaults; strings lose their control characters and are capped; at
most 256 alerts (the newest) and 512 devices are kept from one answer. A 2xx
answer that does not parse is an error, never "absent".

- **Presence:**
  - `unknown` until the first qbp call is answered; `present` on any 2xx;
    `absent` on HTTP 404 from the alerts, devices or push calls.
  - Once absent, no qbp request is made again until a new config or a new
    login session by this client: one extra request per session, never per
    poll. The Pi's alerts, devices and `rev` are forgotten and stats polling
    goes on exactly as before.
  - **The saved verdict:** when the poller goes absent it writes `absentFor`
    (`"<address>|<pin>"` of the configured Pi-hole) to the store; when it
    sees a watchdog it clears it (retried on every cycle until the store
    took it). While the store says absent for the configured address and pin
    (and this run has not seen a watchdog) a closed qnet schedules no poll at
    all: after the first ever probe, a real Pi-hole gets no request from a
    closed qnet, however often it is restarted. An open panel is not
    affected: it asks once per session, as above. A different address or pin
    is a different Pi-hole and is asked.
  - While closed, a first presence check runs 30 s after start (it logs in);
    if the watchdog is absent the thread logs out again at once. An auth
    failure (no secret, a locked keyring) parks the closed poll until the next
    `open` or new config, so a locked keyring is never asked every minute.
    Other failures retry after the closed period (60 s; 30 s after a TLS
    failure) **once the Pi-hole has answered**. Before that (not asked yet,
    away from home, the Pi-hole down) each failure in a row doubles the wait:
    60 s, 120 s, 240 s and so on, at most 30 min (a TLS failure starts at
    30 s). A success, `open` or a new config start it again.
  - Failures of the watchdog go to `watchdog.status` and never to
    `pihole.api`. While open, a failed stats poll skips the watchdog cycle for
    that round: it only follows a good one. An auth failure of the watchdog
    drops the client and waits 60 s, like one of the stats.
- **The cycle** (the API thread; open after every good stats poll, closed on its
  own, where it asks for alerts only):
  1. Push what is due (below): the acknowledged keys first, then the known
     list, then the exempt list.
  2. `GET alerts?since=<cursor>`. The Pi may have restarted, and then the
     cursor and the alerts held cannot be trusted, so the cursor, the alerts
     and the device list are reset, the lists are pushed and the alerts are
     fetched again from 0 (once per cycle at most). That is the case when:
     - this client logged in again since the last page (a new session: a Pi
       that rebooted has lost it; the stats poll may have been the one to log
       in). A reboot that has already made as many changes as the cursor
       shows in no `rev`, and the alerts up to the cursor would never be
       fetched, so the session is what tells;
     - the `rev` is below the cursor;
     - an alert has an `id` that is held under another `key` (ids restart at
       a reboot, so it is not the same alert).

     A new client (the thread made one) counts as a new session: the next page
     is taken from 0.
  3. Record the page in the store, in one locked update: an alert the Pi
     reports as acknowledged adds its key to `acked` (so an ack made on the
     Pi's own panel survives its reboot too), and an alert that needs a
     notification is marked in `notified`. If the store cannot be written
     the cursor does not move and nothing is notified: the next cycle gets the
     same alerts again, so a notification is late and never lost.
  4. Merge the page into the alerts held in memory, by `id`, at most 256 (the
     lowest `rev` goes first).
  5. Fold and show the notifications (below).
  6. Open and devices due: `GET devices`. A `waiting` Pi with a non-empty PC
     list is pushed at once (the exempt list with it). A failing devices read
     or push does not fail the cycle.
  7. Send the report to the main thread. The status is `ok` and `polledAt` is
     now.

  A failure that means no contact (auth, tls, unreachable) or an alerts
  answer that cannot be used ends the cycle with that status, and nothing is
  recorded.
- **Pushes and reboots:**
  - A push is due when this client has never pushed, when its login counter
    changed (a new session, and the Pi may have rebooted: the push is made in
    the same cycle, before the alerts are fetched again from 0), when the
    cycle restarted for another reason (see above), when the Pi's
    `knownList` was seen as `waiting` while the PC list is not empty, or when
    `knownGen` differs from `pushedKnownGen` (the list was edited and the Pi
    does not have it yet). A restart never pushes twice in one cycle.
  - Acks: `PUT alerts/acked` with every stored key, in bodies of at most 4000
    bytes; nothing is sent when there are none.
  - Known list: `PUT devices/known` in chunks of at most 4000 bytes (197 MACs
    each, so 250 MACs are 2 bodies and 1024 are 6), the first with
    `append:false`, the last with `complete:true`, the MACs in list order and
    never split. The Pi switches to the new list on the last chunk; if one
    fails midway it keeps its old list and the next push starts over.
  - **Empty list:** the list is pushed when it is not empty, or when an edit
    emptied it (`knownGen` differs). An empty list that nobody edited is never
    pushed: it would make the Pi raise every device, and without a list the Pi
    learns silently.
  - A failed push stays due and its message is `watchdog.pushError`. A
    successful one records `pushedKnownGen` as the generation read before the
    push, so an edit made while it was on the wire stays due.
  - **The exempt list** is pushed wherever the known list is pushed again (the
    first cycle of a client, a new login session, a restart, a `waiting` Pi),
    and after an edit of its own (`generation` differs from `pushedGeneration`),
    right after the known list: `PUT devices/exempt` with the whole list in one
    body of at most 64 addresses. Unlike the known list it is pushed when it
    is empty as well, on every such push and not only after an edit: this PC's
    list is the master, so a Pi that still holds exemptions from a store that
    was lost or reset hears that there are none. It is not sent before the
    watchdog has been seen (the first cycle of a client with an empty list
    waits for the next one), so a real Pi-hole is never asked for it, and it
    is left out when the lists answered 404 or the Pi cannot be reached. Its
    push is kept apart from the known list's:
    - a known list or acks that keep failing (the Pi answers, with an
      error) do not hold it back: it is sent in the same cycle, after them;
    - a failure of it (any status but 404, or no answer) never stops or
      delays the known list's push or the alerts; the list stays due, is tried
      again on the next cycle as a failed known push would be, and its message
      shows in `watchdog.pushError` as `exempt list: <why>` unless the known
      list's own failure is there;
    - a 404 means this Pi has no exempt support (an older qberrypi): it is not
      an error and not an absence of the watchdog. The answer stands for the
      login session: the list is not sent again while the session lasts (the
      store keeps it due), and a new session, a restart that resets the
      cursor, or a new client gives it one more look, so a Pi that was
      upgraded gets the list. Nothing of this is kept in the store (a closed
      qnet whose Pi has a watchdog polls alerts either way);
    - success records `pushedGeneration` as the generation read before the
      push.
- **Notifications:**
  - An alert is new when it is not acknowledged and its key is not in
    `notified`, or its `first_unix` is later than the one recorded there (a
    fresh instance after a Pi reboot). The first cycle fetches from 0, so
    unacknowledged alerts the Pi still holds notify then (folded, if there
    are many), unless `notified` already has them. `notified` is
    persisted, so restarting qnet repeats none. Alerts the Pi reports as
    acknowledged never notify.
  - Title by kind, body `<subject> · <client>` (just the subject when the
    client is `null`):

    | Kind | Title |
    |---|---|
    | `new_device` | New device on the network |
    | `arp_spoof` | Router impersonation (ARP spoofing) |
    | `dga` | Suspicious lookups (DGA) |
    | `tunnel` | Possible DNS tunnel |
    | `beacon` | Regular beaconing |
    | `burst` | Burst of lookups |
    | `threat` | Threat blocked |
    | `rebind` | DNS rebinding blocked |
    | anything else | Watchdog alert |

  - **Escaping:** the notification daemon may read its text as markup and the
    subject comes from the network. In title and body `&` becomes `&amp;`, `<`
    becomes `&lt;`, `>` becomes `&gt;` and every control character (newline and
    tab too) becomes one space. Each is at most 200 characters; a longer text
    ends in `…` and an entity is never cut in half.
  - The process is `notify-send -a qnet -- <title> <body>`, argv only, with
    `--` before the title so text that starts with `-` is never read as an
    option. The failover notification gets the `--` as well.
  - **Folding:** at most 3 individual notifications per rolling 60 s. The
    rest are held and go out as one `Watchdog` / "N more alerts" ("1 more
    alert" for one), itself at most once per 60 s; what is held carries to
    the next cycle that may send it. Alerts that were only folded still count
    as notified. A restart drops a fold that was still waiting.
  - They are shown open or closed: that is what the closed poll is for.
- **The PC store** (`~/.local/state/qnet/watchdog.json`, see the Process
  model):
  - `acked`: at most 1024 keys; when full the oldest goes first. They are
    pushed to the Pi, and a key the Pi reports acknowledged is added.
  - `known`: at most 1024 entries `{mac, label?, firstSeen}`. A MAC is stored
    in lower-case colon form and a label has no control characters and at most
    64 characters. A new device is refused when the list is full (`full`); it
    is never dropped to make room.
  - `knownGen` goes up on every edit of the list, `pushedKnownGen` is set to
    the generation that was pushed by whoever pushes it successfully, the
    watcher or a verb. `push due` means they differ.
  - `exempt` (in `watchdog-exempt.json`, see the Process model): at most 64
    entries of the same shape as `known`, edited by
    `watchdog exempt|unexempt` (a new device is refused when the list is full,
    `full`). `generation` and `pushedGeneration` work as the known list's
    `knownGen` and `pushedKnownGen`.
    `exempt` puts the device on `known` as well; `unexempt` leaves it
    known, and `forget` leaves it on the exempt list.
  - `notified`: at most 1024 `{key, firstUnix, at}`; when full the oldest `at`
    goes first.

## Config: `~/.config/qnet/config.toml`

```toml
[pihole]
address = "192.168.1.153"
tls_sha256 = "71:C7:…"        # pinned at setup
canary = "doubleclick.net"    # a real blocklisted name; used when qnet-canary.invalid is not on the deny list
[failover]
enabled = true
fallback = "router"           # router | quad9 | cloudflare
```

With no config file, the Pi-hole features are off and the hero shows
"Set up Pi-hole ›", which runs `qnet pihole setup` in a floating terminal.

## Panel layout (top to bottom)

1. **Header.**
   - Wi-Fi glyph and the SSID ("Ethernet" or "Offline" otherwise).
   - Status line: `Connected · 5 GHz · 72% · 866 Mb/s`. When the state isn't
     full it reads `Limited` / `Sign in required ›` / `No internet` in the
     urgent colour, which tells you you're on Wi-Fi but limited.
   - Right side: the QR share and speed-test icon buttons, both with
     tooltips. After a clear gap, the radio switch.
2. **DNS hero, the identity.** It is a wide graph block.
   - **Background:** the 24 h query flow as an area graph. Total queries are
     a plasma-accent gradient fill; the blocked share is a brighter band along
     the bottom.
   - **Live edge:** the rightmost segment comes from `probes`. A thin pulse
     line of probe latency ticks in every 5 s while the panel is open. A
     failed probe draws a gap.
   - **Overlay, top-left:** the state word at title size:
     - `Pi-hole` in accent;
     - `Paused 4:32` in dim;
     - `Fallback · router` in the warning colour;
     - `Bypassed` / `Unreachable` in urgent;
     - `Router DNS` in dim.
   - **Under the state word:** one line, `via 192.168.1.153 · 3 ms`. Latency
     shows in urgent only when it is over 100 ms or probes are failing
     (quiet until bad).
   - **Top right:** `1,204 queries` with `13.6% blocked` dim beneath it.
   - **When unreachable or the API fails:** keep the graph, frozen and
     desaturated, with the state word. Never collapse it to one line.
   - **Not configured:** the graph area is empty with "Set up Pi-hole ›".
3. **Leaks.** Shown only when there are any. One urgent line each with a fix
   action, e.g. `Wired connection 1 would bypass Pi-hole · Pin`. resolved's
   compiled FallbackDNS is not a leak while the links have servers.
4. **DNS row.**
   - Segmented tiles `Pi-hole | Automatic`. The live mode gets the accent
     tile. A runtime failover shows as the `Pi-hole` tile in the warning
     colour, labelled `Pi-hole (fallback)`. Custom DNS lights no tile and
     shows a `Custom: 9.9.9.9` caption.
   - Then one chip: `Pause 5m`, which becomes `Resume 4:32`.
   - Then an `Admin ›` link.
5. **Networks.**
   - One list: the active network first, then known, then others.
   - The active row has an accent glyph and a `Connected` caption.
   - Only open networks are marked ("Open"). Enterprise rows say "802.1X".
   - The section label "Networks" has a scan action that shows its progress.
   - An inline password row appears for a secure unknown network.
   - The active row offers Disconnect; known rows offer Forget (on secondary
     click or the `Delete` key).
6. **IP footer.** `192.168.1.242 · gw 192.168.1.1`, dim, small, click to
   copy, with stable `--` placeholders.

Keyboard: up and down move through focusable items in order; left and right move
inside a row of tiles; Enter activates; `p` pauses or resumes; `r` scans; Esc
closes. Focus starts on the Networks list.

## Visual rules

- Tokens come from `lib/tokens.js`, copied from `qqq.soundhub`.
- The bar font only, at `Style.font` sizes. Sentence-case dim labels.
- Accent for "on"; grey only for the cursor.
- `Text.PlainText` everywhere.
- Motion follows the Omarchy rules: `Style.duration`, ease-out, under 300 ms.
  Nothing animates on open.

## Cut from v1

- Scanning when the panel opens (cut in round 2; only `qnet wifi scan`).
- "Recently blocked" with Allow (v2).
- A failover switch in the UI (it stays in config).
- A 1 h pause.
- rx/tx throughput.
- Band pinning, hotspot, VPN.
- Creating 802.1X profiles.
- The watchdog panel (alert and device lists, acknowledge and known-device
  buttons). Only the backend, the `qnet watchdog` verbs and the `watchdog`
  state object exist; the panel needs mockups first.

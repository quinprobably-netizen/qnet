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
    `radio`, `rfkill`.
  - **One-shot verbs and signals:** except the interactive `pihole setup`,
    they catch SIGTERM/SIGINT/SIGHUP. The step in progress finishes (a
    profile that was written is applied, a half-made Wi-Fi profile is
    deleted), the next step is not started, the Pi-hole session is logged
    out, and the verb ends with `"interrupted"` (error, or `"interrupted":
    true` on a result that was applied but not checked).
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
      "band": "5 GHz"
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
  probe produces only a heartbeat. `open` always sends the full state.
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

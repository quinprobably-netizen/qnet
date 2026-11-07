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
   cached access-point list. Scan only on request, or on open when the last
   scan is older than 30 s. The AX210 is fragile. With the panel closed, cost
   should be close to zero.
4. **Identity beside Sound Hub and Overclock.**
   - A live graph header.
   - Accent for every "on" state; grey only for the keyboard cursor.
   - One bar font and one sentence-case label style.

## Process model

- `qnet watch` is one long-lived child of the panel.
  - **stdout:** one JSON object per line. A full `state` snapshot on start,
    then a fresh snapshot on every change (coalesced, at most 4 per second),
    plus a heartbeat every 10 s.
  - **stdin:** one command per line: `open`, `closed`, `refresh`. `open` and
    `closed` set the cadence.
  - The panel spawns no other periodic processes.
  - On exit (stdin EOF or SIGTERM) it ends the Pi-hole API session
    (`DELETE /api/auth`) and returns any runtime failover to the saved profile.
- One-shot actions are `qnet <verb> ...`.
  - Each prints one JSON line, `{"ok":true,...}` or
    `{"ok":false,"error":"..."}`, and the exit code matches.
  - Every DNS-changing verb ends by sending one DNS query through the system
    resolver (resolved D-Bus `ResolveHostname`), and reports the server that
    answered as `{"verifiedVia":"192.168.1.153"}`.
- Secrets never go on argv: Wi-Fi passphrases and the Pi-hole web password
  arrive on stdin. Untrusted strings reach processes only as argv elements.
  There is no shell anywhere (`sh -c` / `bash -c` are forbidden).

## Data sources (watch)

| What | Source | Cadence |
|---|---|---|
| Devices, primary connection, connectivity, Wi-Fi AP (ssid bytes, strength, freq, bitrate), IP4 address and gateway | NetworkManager D-Bus PropertiesChanged signals | event-driven; re-read on `open` |
| Access points | NM `Device.Wireless.AccessPoints`, `LastScan` | event-driven. `RequestScan` only via `qnet wifi scan` (≥ 15 s apart), or on `open` when `LastScan` is older than 30 s |
| Saved profiles and their DNS settings | NM Settings `ListConnections` / `GetSettings` | on start, and on NewConnection, ConnectionRemoved, Updated |
| Resolver truth | resolved D-Bus `org.freedesktop.resolve1` Manager `DNSEx`, `CurrentDNSServerEx`, `FallbackDNSEx`; per-link `DefaultRoute` | on NM change, plus every 30 s |
| Pi-hole health | Raw UDP DNS sent straight to the Pi-hole. An A query for the canary (default `doubleclick.net`) must return `0.0.0.0` (blocking) or a real address (paused). Timeout 1.5 s; the RTT is the latency. | every 15 s closed, 5 s open |
| Gateway gate | The same probe sent to the gateway on port 53 (the router answers DNS) | only while the Pi-hole probe is failing |
| Pi-hole stats | HTTPS API on 443 with the **pinned cert SHA-256**: `/api/stats/summary`, `/api/dns/blocking` | only while open, every 10 s; `/api/history` every 60 s |

### Pi-hole API sessions

- Log in once (`POST /api/auth` with the app password from the keyring) and
  keep the SID in memory only.
- Reuse it until a 401, then log in once more.
- `DELETE /api/auth` on exit. Never log in per request: a Pi 3B+ has few
  session slots.
- Response bodies are capped at 256 KiB; requests time out after 3 s.

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
    "ip4": "192.168.1.242",
    "gateway": "192.168.1.1",
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
    "mode": "pihole|fallback|auto|custom",
    "modeSource": "profile|runtime-failover",
    "servers": [
      { "addr": "192.168.1.153", "link": "wlp7s0", "current": true, "role": "pihole|router|public|other" }
    ],
    "leaks": [
      { "kind": "link|profile|ipv6-ra", "where": "Wired connection 1", "uuid": "…", "detail": "uses router DNS (automatic)" }
    ],
    "failover": { "enabled": true, "fallback": "router", "active": false, "since": 0, "reason": "" },
    "manualOverride": false
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
    "today": { "total": 1204, "blocked": 164, "percent": 13.6 },
    "history": [{ "t": 1794034800, "total": 40, "blocked": 6 }],
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
- **`history`:** at most 144 buckets (24 h × 10 min).
- **`probes`:** a ring buffer of the last 60 health probes. It drives the
  live edge of the hero.
- **`manualOverride`:** true when the active profile has DNS servers set that
  qnet did not write. qnet must confirm before overwriting them.

## Actions

| Verb | Effect |
|---|---|
| `qnet dns pihole` | **Active connection's saved profile only.**<br>• Sets `ipv4.dns=<pihole>`, `ipv4.ignore-auto-dns=yes`, `ipv6.ignore-auto-dns=yes`, `ipv6.dns=` (blocks the IPv6 RA leak), then `Device.Reapply`.<br>• First saves the previous ipv4/ipv6 DNS settings to `~/.local/state/qnet/prev-dns/<uuid>.json` for undo.<br>• Refuses with `{"ok":false,"error":"confirm","detail":…}` when `manualOverride` is set and `--force` is absent.<br>• No-op when already in this mode. |
| `qnet dns auto` | Restores the saved previous settings, or clears to automatic. Active profile only. Same confirm and no-op rules. |
| `qnet dns pin <uuid>` | Applies the Pi-hole settings to an inactive saved profile, e.g. Wired connection 1. Saves undo state. No Reapply. |
| `qnet pihole pause [secs=300]` / `resume` | `POST /api/dns/blocking {"blocking":false,"timer":secs}` / `{"blocking":true,"timer":null}` |
| `qnet pihole setup <addr>` | Interactive only (run from a terminal). Takes the web password on stdin.<br>• Fetches the TLS cert and prints its SHA-256 for the user to accept (TOFU).<br>• Warns if an app password already exists, because `app_pwhash` replaces it.<br>• Creates the app password (`GET /api/auth/app`, then `PATCH /api/config/webserver/api/app_pwhash`) and stores it with `secret-tool store` (secret on stdin; attributes `service qnet`, `pihole <addr>`).<br>• Writes the config. |
| `qnet wifi connect <ap-path>` | Passphrase on stdin; empty means an open or known network. Known: `ActivateConnection` of the matching profile. Unknown: `AddAndActivateConnection` with the secret in the settings dict. **Enterprise (802.1X) is refused** with `"error":"enterprise"`; the panel then opens `nmtui` in a terminal. qnet never creates an EAP profile. |
| `qnet wifi down`, `qnet wifi forget <uuid>`, `qnet wifi scan`, `qnet wifi radio on\|off` | NM D-Bus |
| `qnet portal` | Opens `link.portalUrl`, or `http://neverssl.com`, in a **throwaway browser profile**: `chromium --user-data-dir=<new 0700 temp dir> --app=<url>`. The temp dir is removed when the browser exits. |

## Failover (in `qnet watch`)

- **Eligible** only when the active profile's mode is `pihole` and
  `failover.enabled` is set.
- **Trigger** (all must hold):
  - 3 consecutive failed Pi-hole probes (about 45 s closed, 15 s open);
  - the link is up (NM device state ACTIVATED);
  - the gateway answers the same DNS probe.

  A dead Wi-Fi card is not a Pi-hole outage, so in that case qnet does
  nothing.
- **Action:**
  - Runtime only: `Device.GetAppliedConnection`, change the DNS settings,
    then `Device.Reapply` with them. The saved profile is never written, so a
    crash can never leave you stranded on the fallback.
  - Keep `ipv6.ignore-auto-dns=yes`.
  - The fallback server is `router` (the gateway), `quad9` or `cloudflare`.
  - Set `failover.active`, and send `notify-send "Pi-hole unreachable" "Using <fallback> DNS"`.
- **Recovery:** 3 consecutive good probes sent straight to the Pi-hole, then
  Reapply the saved profile and notify.
- **Never** fail over or touch DNS while the link is down or flapping, and
  never touch the radio.

## Config: `~/.config/qnet/config.toml`

```toml
[pihole]
address = "192.168.1.153"
tls_sha256 = "71:C7:…"        # pinned at setup
canary = "doubleclick.net"    # must be on a blocklist
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

- "Recently blocked" with Allow (v2).
- A failover switch in the UI (it stays in config).
- A 1 h pause.
- rx/tx throughput.
- Band pinning, hotspot, VPN.
- Creating 802.1X profiles.

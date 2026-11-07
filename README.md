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

Details: `SPEC.md`.

## Install / update

```
./install.sh                 # builds to ~/.cache/qnet/target, installs ~/.local/bin/qnet
omarchy restart shell        # QML hot-reload is unreliable; restart to load edits
qnet pihole setup [address]  # once, in a terminal: pins the cert, stores an app password in the keyring
```

- IPC: `omarchy-shell qqq.qnet toggle | open | close | view <main|wifi|dns>`.
- Keybinding: `SUPER + CTRL + N`, rebound in `~/.config/hypr/bindings.lua`.
- Run cargo from inside `backend/`, or `.cargo/config.toml` is skipped and
  `backend/target` lands in the watched plugin tree.

## Review history

Blind council: Opus/Sonnet seats plus a Fable security seat, with an Opus chair.

| Round | Chair score | Owner |
|---|---|---|
| Stock `omarchy.network` | 4.5 | |
| R1, first build | 6.0 | |
| R2 | 6.5 | 4–5: "looks like an audio panel" |
| R3, the Route + drill-down rows | | 8.2: "still the dns and wifi menus" |
| R3b, node navigation, network-native views | seats 7 / 6.5 / 7 / 7.5 / 8 | |

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

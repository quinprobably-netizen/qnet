// qnet (qqq.qnet): everything the panel decides, as pure functions. No QML
// types and no imports, so node loads it (tests/*.test.js) and QML imports
// it as a library. Panel.qml and components/ only draw what these return.
//
//   state       SPEC.md "State JSON"; normalizeState() bounds and validates a
//               snapshot, parseStateLine() turns a stdout line into one
//   view        the state with the panel's optimistic overlays on it
//               (effective()); every component reads the view, never `pending`.
//               view.backendDown: the watch process is not running
//   pending     { dns, pause, pauseUntilMs, radio, scanUntilMs, connectId,
//                 disconnecting, forgetUuid, pinUuid }: what the user asked
//                 for and the backend has not confirmed yet
//   argv        every process is an argv array built here; null for an input
//               that does not validate, so nothing untrusted reaches a shell
//
// Text that came from the network or the backend (SSIDs, domains, errors) is
// display-only: clean() strips control and bidi characters and caps length,
// and every Text in the panel is Text.PlainText.

// ---------------------------------------------------------------- limits

var MAX_LINE = 262144          // one stdout line, bytes of text
var MAX_NETWORKS = 40
var MAX_HISTORY = 144          // 24 h x 10 min
var MAX_PROBES = 60
var MAX_SERVERS = 8
var MAX_LEAKS = 8
var HISTORY_BUCKET_S = 600
var HISTORY_SPAN_S = 86400
var MIN_AXIS_S = 10800         // the graph's x-axis is never shorter than 3 h
var STABLE_UPTIME_MS = 30000   // a watch child must live this long to reset the backoff
var PAUSE_SECONDS = 300
var LATENCY_BAD_MS = 100
var PENDING_TTL_MS = 12000     // an unconfirmed request is given up after this
var SCAN_SPIN_MS = 4000

var BACKOFF_MS = [1000, 2000, 5000, 10000, 30000]
var AP_PATH_RE = /^\/org\/freedesktop\/NetworkManager\/AccessPoint\/\d+$/
var UUID_RE = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/
var ADDR_RE = /^[0-9A-Za-z.:\-]{1,64}$/
var IP_RE = /^[0-9A-Fa-f:.]{1,64}$/

// -------------------------------------------------------------- glyphs
// Nerd Font (Material Design) code points, written as escapes: private-use
// characters pasted into a source file do not survive every editor.

var GLYPH = {
  wifi: ["\u{f092f}", "\u{f091f}", "\u{f0922}", "\u{f0925}", "\u{f0928}"],
  wifiRestricted: "\u{f0929}",
  wifiOff: "\u{f092e}",
  ethernet: "\u{f0200}",
  ethernetOff: "\u{f0202}",
  qr: "\u{f0432}",
  speed: "\u{f04c5}",
  refresh: "\u{f0450}",
  check: "\u{f012c}"
}

// ----------------------------------------------------------- sanitising

function isObj(v) { return v !== null && typeof v === "object" && !Array.isArray(v) }

// Control characters (C0, DEL, C1) and the bidi overrides that can make one
// string read as another are dropped; length is capped. Markup characters
// stay as they are: they are only ever drawn as plain text.
function clean(v, max) {
  var s = v === null || v === undefined ? "" : String(v)
  s = s.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u200e\u200f]/g, "")
  var cap = max > 0 ? max : 120
  return s.length > cap ? s.substring(0, cap) : s
}

function num(v, fallback) {
  var n = typeof v === "number" ? v : parseFloat(v)
  return isFinite(n) ? n : (fallback === undefined ? 0 : fallback)
}

function toInt(v, fallback) { return Math.round(num(v, fallback)) }

function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v) }

function oneOf(v, list, fallback) { return list.indexOf(v) >= 0 ? v : fallback }

function toBool(v, fallback) { return typeof v === "boolean" ? v : fallback }

function ip(v) {
  var s = v === null || v === undefined ? "" : String(v)
  return IP_RE.test(s) ? s : ""
}

function addr(v) {
  var s = v === null || v === undefined ? "" : String(v)
  return ADDR_RE.test(s) ? s : ""
}

// An https/http URL of host[:port][/path]. Opened with the default browser,
// so nothing else (no credentials, query or fragment) passes.
function safeUrl(v) {
  var s = v === null || v === undefined ? "" : String(v)
  return /^https?:\/\/[0-9A-Za-z.\-]+(:\d{1,5})?(\/[0-9A-Za-z._~\-\/]*)?$/.test(s) && s.length <= 200 ? s : ""
}

// ------------------------------------------------------------ the state

function emptyState() { return normalizeState({}) }

function normalizeState(raw) {
  var r = isObj(raw) ? raw : {}
  var l = isObj(r.link) ? r.link : {}
  var rad = isObj(r.radio) ? r.radio : {}
  var sc = isObj(r.scan) ? r.scan : {}
  var d = isObj(r.dns) ? r.dns : {}
  var f = isObj(d.failover) ? d.failover : {}
  var p = isObj(r.pihole) ? r.pihole : {}
  var t = isObj(p.today) ? p.today : {}

  var servers = []
  var sv = Array.isArray(d.servers) ? d.servers : []
  for (var i = 0; i < sv.length && servers.length < MAX_SERVERS; i++) {
    if (!isObj(sv[i])) continue
    var a = addr(sv[i].addr)
    if (a === "") continue
    servers.push({
      addr: a, link: clean(sv[i].link, 32), current: sv[i].current === true,
      role: oneOf(sv[i].role, ["pihole", "router", "public", "other"], "other")
    })
  }

  var leaks = []
  var lk = Array.isArray(d.leaks) ? d.leaks : []
  for (var j = 0; j < lk.length && leaks.length < MAX_LEAKS; j++) {
    if (!isObj(lk[j])) continue
    var uuid = String(lk[j].uuid || "")
    leaks.push({
      kind: oneOf(lk[j].kind, ["link", "profile", "ipv6-ra"], "link"),
      where: clean(lk[j].where, 80), uuid: UUID_RE.test(uuid) ? uuid : "",
      detail: clean(lk[j].detail, 120)
    })
  }

  var networks = []
  var nw = Array.isArray(r.networks) ? r.networks : []
  for (var k = 0; k < nw.length && networks.length < MAX_NETWORKS; k++) {
    if (!isObj(nw[k]) || !AP_PATH_RE.test(String(nw[k].id || ""))) continue
    var ssid = clean(nw[k].ssid, 64)
    var nuuid = String(nw[k].uuid || "")
    networks.push({
      id: String(nw[k].id), ssid: ssid, hidden: nw[k].hidden === true || ssid === "",
      signal: clamp(toInt(nw[k].signal, 0), 0, 100),
      security: oneOf(nw[k].security, ["open", "psk", "sae", "owe", "enterprise"], "psk"),
      known: nw[k].known === true, uuid: UUID_RE.test(nuuid) ? nuuid : "",
      active: nw[k].active === true, band: clean(nw[k].band, 12)
    })
  }

  var history = []
  var hs = Array.isArray(p.history) ? p.history : []
  for (var m = Math.max(0, hs.length - MAX_HISTORY); m < hs.length; m++) {
    if (!isObj(hs[m])) continue
    var ht = num(hs[m].t, NaN)
    if (!isFinite(ht)) continue
    var tot = Math.max(0, toInt(hs[m].total, 0))
    history.push({ t: ht, total: tot, blocked: clamp(toInt(hs[m].blocked, 0), 0, tot) })
  }

  var probes = []
  var pr = Array.isArray(p.probes) ? p.probes : []
  for (var n = Math.max(0, pr.length - MAX_PROBES); n < pr.length; n++) {
    if (!isObj(pr[n])) continue
    var pt = num(pr[n].t, NaN)
    if (!isFinite(pt)) continue
    var ok = pr[n].ok === true
    var ms = pr[n].ms === null || pr[n].ms === undefined ? NaN : num(pr[n].ms, NaN)
    probes.push({ t: pt, ok: ok, ms: ok && isFinite(ms) && ms >= 0 ? ms : null, blocked: pr[n].blocked === true })
  }

  var pms = p.latencyMs === null || p.latencyMs === undefined ? NaN : num(p.latencyMs, NaN)
  var gms = l.gatewayMs === null || l.gatewayMs === undefined ? NaN : num(l.gatewayMs, NaN)
  // health is the Pi-hole's state; reachable follows it when it is given.
  var healthRaw = oneOf(p.health, ["ok", "degraded", "unreachable", "unknown"], "")
  var reachable = healthRaw !== "" ? (healthRaw === "ok" || healthRaw === "degraded") : p.reachable === true
  var health = healthRaw !== "" ? healthRaw : (reachable ? "ok" : (p.configured === true ? "unreachable" : "unknown"))
  return {
    seq: toInt(r.seq, -1),
    link: {
      kind: oneOf(l.kind, ["wifi", "ethernet", "none"], "none"),
      device: clean(l.device, 32), connection: clean(l.connection, 64),
      uuid: UUID_RE.test(String(l.uuid || "")) ? String(l.uuid) : "",
      ssid: clean(l.ssid, 64), signal: clamp(toInt(l.signal, 0), 0, 100), band: clean(l.band, 12),
      bitrateMbps: Math.max(0, toInt(l.bitrateMbps, 0)), ip4: ip(l.ip4), gateway: ip(l.gateway),
      gatewayMs: isFinite(gms) && gms >= 0 ? gms : null,
      connectivity: oneOf(l.connectivity, ["full", "limited", "portal", "none", "unknown"], "unknown"),
      portalUrl: safeUrl(l.portalUrl)
    },
    radio: { wifiEnabled: toBool(rad.wifiEnabled, true), hwEnabled: toBool(rad.hwEnabled, true) },
    networks: networks,
    scan: { running: sc.running === true, lastScanAgeS: num(sc.lastScanAgeS, -1) },
    dns: {
      mode: oneOf(d.mode, ["pihole", "fallback", "auto", "custom", "none", "unknown"], "unknown"),
      modeSource: oneOf(d.modeSource, ["profile", "runtime-failover"], "profile"),
      servers: servers, leaks: leaks,
      failover: {
        enabled: f.enabled === true, fallback: oneOf(f.fallback, ["router", "quad9", "cloudflare"], "router"),
        active: f.active === true, since: Math.max(0, num(f.since, 0)), reason: clean(f.reason, 80)
      },
      manualOverride: d.manualOverride === true,
      bypassed: d.bypassed === true,
      resolvedFallback: addr(d.resolvedFallback)
    },
    pihole: {
      configured: p.configured === true, address: addr(p.address), adminUrl: safeUrl(p.adminUrl),
      detected: addr(p.detected), reachable: reachable, health: health,
      canaryBlocked: typeof p.canaryBlocked === "boolean" ? p.canaryBlocked : null,
      historySpanS: clamp(num(p.historySpanS, 0), 0, HISTORY_SPAN_S),
      latencyMs: isFinite(pms) && pms >= 0 ? pms : null,
      blocking: oneOf(p.blocking, ["enabled", "disabled", "unknown"], "unknown"),
      pauseRemainingS: Math.max(0, toInt(p.pauseRemainingS, 0)),
      api: oneOf(p.api, ["ok", "auth", "tls", "unreachable", "unconfigured"], "unconfigured"),
      today: {
        total: Math.max(0, toInt(t.total, 0)), blocked: Math.max(0, toInt(t.blocked, 0)),
        percent: clamp(num(t.percent, 0), 0, 100), selfQueries: Math.max(0, toInt(t.selfQueries, 0))
      },
      history: history, probes: probes
    },
    error: clean(r.error, 160)
  }
}

// One stdout line of `qnet watch`. lastSeq is the newest seq applied by this
// child process (-1 for a fresh one).
//   { kind: "state", state, seq }  a snapshot newer than lastSeq
//   { kind: "stale" }              a snapshot that is not newer: ignored
//   { kind: "hb" }                 a heartbeat ({"type":"hb","seq":N}): proof of
//                                  life for the watchdog, nothing to apply
//   { kind: "other" }              valid JSON of another type: ignored
//   { kind: "bad" }                not JSON, too long, or no usable seq
function parseStateLine(line, lastSeq) {
  var text = line === null || line === undefined ? "" : String(line)
  if (text.length > MAX_LINE) return { kind: "bad" }
  text = text.trim()
  if (text === "") return { kind: "bad" }
  var obj
  try { obj = JSON.parse(text) } catch (e) { return { kind: "bad" } }
  if (!isObj(obj)) return { kind: "bad" }
  if (obj.type === "hb") return { kind: "hb" }
  if (obj.type !== "state") return { kind: "other" }
  if (typeof obj.seq !== "number" || !isFinite(obj.seq)) return { kind: "bad" }
  var last = typeof lastSeq === "number" ? lastSeq : -1
  if (obj.seq <= last) return { kind: "stale" }
  var state = normalizeState(obj)
  return { kind: "state", state: state, seq: state.seq }
}

// Delay before restart number `attempt` (0-based) of the watch process:
// 1 s, 2 s, 5 s, 10 s, then 30 s for good.
function backoffMs(attempt) {
  var a = Math.max(0, toInt(attempt, 0))
  return BACKOFF_MS[Math.min(a, BACKOFF_MS.length - 1)]
}

// The restart counter after the child said something: it starts over only
// when the child had been up for STABLE_UPTIME_MS, so a child that starts,
// speaks and dies keeps climbing the backoff.
function restartAttempt(attempt, uptimeMs) {
  return num(uptimeMs, 0) >= STABLE_UPTIME_MS ? 0 : Math.max(0, toInt(attempt, 0))
}

// ----------------------------------------------------------- formatting

// 272 -> "4:32", 3725 -> "1:02:05". Never negative.
function formatCountdown(sec) {
  var s = Math.max(0, Math.floor(num(sec, 0)))
  var h = Math.floor(s / 3600)
  var m = Math.floor((s % 3600) / 60)
  var r = s % 60
  var rr = r < 10 ? "0" + r : String(r)
  if (h > 0) return h + ":" + (m < 10 ? "0" + m : m) + ":" + rr
  return m + ":" + rr
}

function groupDigits(n) {
  var s = String(Math.round(num(n, 0)))
  var neg = s.charAt(0) === "-"
  if (neg) s = s.substring(1)
  var out = ""
  while (s.length > 3) { out = "," + s.substring(s.length - 3) + out; s = s.substring(0, s.length - 3) }
  return (neg ? "-" : "") + s + out
}

// 1204 -> "1,204". fmt(n) is the shell's locale formatter when QML passes one.
function formatCount(n, fmt) {
  return typeof fmt === "function" ? fmt(Math.round(num(n, 0))) : groupDigits(n)
}

// A decimal with the language's separator when fmt is I18n.formatNumber.
function formatDecimal(v, decimals, fmt) {
  if (typeof fmt === "function") return fmt(v, decimals)
  return num(v, 0).toFixed(decimals)
}

// 13.64 -> "13.6%"
function formatPercent(v, fmt) { return formatDecimal(v, 1, fmt) + "%" }

// 3.1 -> "3 ms", 0.4 -> "<1 ms", 142.7 -> "143 ms"
function formatLatency(ms, fmt) {
  var v = num(ms, NaN)
  if (!isFinite(v) || v < 0) return ""
  if (v < 1) return "<1 ms"
  return formatDecimal(Math.round(v), 0, fmt) + " ms"
}

// 5400 -> "1.5 h", 7200 -> "2 h", 2400 -> "40 min", 50000 -> "14 h"
function formatSpan(sec, fmt) {
  var s = Math.max(0, num(sec, 0))
  if (s < 3600) return formatDecimal(Math.max(1, Math.round(s / 60)), 0, fmt) + " min"
  var h = s / 3600
  if (h < 10) {
    var tenth = Math.round(h * 10) / 10
    return formatDecimal(tenth, tenth === Math.round(tenth) ? 0 : 1, fmt) + " h"
  }
  return formatDecimal(Math.round(h), 0, fmt) + " h"
}

// 866 -> "866 Mb/s", 1000 -> "1 Gb/s", 2500 -> "2.5 Gb/s"
function formatRate(mbps, fmt) {
  var v = num(mbps, 0)
  if (v <= 0) return ""
  if (v >= 1000) {
    var g = v / 1000
    return formatDecimal(g, g === Math.round(g) ? 0 : 1, fmt) + " Gb/s"
  }
  return formatDecimal(Math.round(v), 0, fmt) + " Mb/s"
}

// ------------------------------------------------------------ the view

function copyState(s) {
  return {
    backendDown: false,
    seq: s.seq, link: s.link, radio: s.radio, networks: s.networks, scan: s.scan,
    dns: s.dns, pihole: s.pihole, error: s.error
  }
}

// Seconds of pause left now. The snapshot says how many it had when it was
// applied at appliedMs; this counts down from there. A pending request
// overrides: a pause just asked for shows its full 5:00, a resume shows 0.
function pauseRemaining(state, pending, appliedMs, nowMs) {
  var p = pending || {}
  if (p.pause === "pause") return Math.max(0, Math.ceil((num(p.pauseUntilMs, 0) - nowMs) / 1000))
  if (p.pause === "resume") return 0
  var base = state.pihole.pauseRemainingS
  if (base <= 0) return 0
  return Math.max(0, Math.ceil(base - Math.max(0, nowMs - appliedMs) / 1000))
}

// The state with the panel's pending requests laid over it, so the UI
// answers at once. reconcilePending() drops a request when the backend
// confirms it or it times out.
function effective(state, pending, appliedMs, nowMs, down) {
  var p = pending || {}
  var v = copyState(state)
  v.backendDown = down === true
  var mode = state.dns.mode
  if (p.dns === "pihole" || p.dns === "auto") mode = p.dns
  if (mode !== state.dns.mode) {
    // Asked for the Pi-hole: pinned, so nothing bypasses it. Asked for
    // Automatic: unpinned, which is what "bypassed" means with a Pi-hole set up.
    v.dns = Object.assign({}, state.dns, {
      mode: mode, modeSource: "profile", bypassed: mode === "auto" && state.pihole.configured
    })
    v.dns.failover = Object.assign({}, state.dns.failover, { active: false })
  }
  var blocking = state.pihole.blocking
  if (p.pause === "pause") blocking = "disabled"
  else if (p.pause === "resume") blocking = "enabled"
  var remaining = pauseRemaining(state, p, appliedMs, nowMs)
  if (blocking !== state.pihole.blocking || remaining !== state.pihole.pauseRemainingS) {
    v.pihole = Object.assign({}, state.pihole, { blocking: blocking, pauseRemainingS: remaining })
  }
  if (p.radio === "on" || p.radio === "off") {
    v.radio = Object.assign({}, state.radio, { wifiEnabled: p.radio === "on" })
  }
  var scanning = state.scan.running || num(p.scanUntilMs, 0) > nowMs
  if (scanning !== state.scan.running) v.scan = Object.assign({}, state.scan, { running: scanning })
  return v
}

// What each pending key rests at once it is settled.
var PENDING_REST = {
  dns: "", pause: "", pauseUntilMs: 0, radio: "", connectId: "", disconnecting: false,
  forgetUuid: "", pinUuid: "", scanUntilMs: 0, since: 0
}

function emptyPending() { return Object.assign({}, PENDING_REST) }

// Pending requests the new snapshot has settled, or that ran out of time
// (`since` is when the newest was made). Returns a new object, or the same
// one when nothing changed.
function reconcilePending(pending, state, nowMs) {
  var p = pending || emptyPending()
  var out = Object.assign({}, p)
  var changed = false
  function drop() {
    for (var i = 0; i < arguments.length; i++) {
      if (out[arguments[i]] !== PENDING_REST[arguments[i]]) { out[arguments[i]] = PENDING_REST[arguments[i]]; changed = true }
    }
  }
  var expired = num(p.since, 0) > 0 && nowMs - p.since > PENDING_TTL_MS
  var i

  if (p.dns && (state.dns.mode === p.dns || expired)) drop("dns")
  if (p.pause === "pause" && (state.pihole.blocking === "disabled" || nowMs > num(p.pauseUntilMs, 0) || expired)) drop("pause", "pauseUntilMs")
  if (p.pause === "resume" && (state.pihole.blocking !== "disabled" || expired)) drop("pause")
  if (p.radio && (state.radio.wifiEnabled === (p.radio === "on") || expired)) drop("radio")
  if (p.connectId) {
    var active = false
    for (i = 0; i < state.networks.length; i++) if (state.networks[i].active && state.networks[i].id === p.connectId) active = true
    // A connect can take a long while (NetworkManager waits out 25 s for a
    // wrong passphrase): it does not age out. The action's own callback
    // clears it, or a snapshot that shows the network active.
    var want = connectSsid(state, p.connectId)
    if (active || (want !== "" && state.link.ssid === want)) drop("connectId")
  }
  if (p.disconnecting && (state.link.kind === "none" || expired)) drop("disconnecting")
  if (p.forgetUuid) {
    var present = false
    for (i = 0; i < state.networks.length; i++) if (state.networks[i].known && state.networks[i].uuid === p.forgetUuid) present = true
    if (!present || expired) drop("forgetUuid")
  }
  if (p.pinUuid) {
    var ids = String(p.pinUuid).split(" ")
    var leaking = false
    for (i = 0; i < state.dns.leaks.length; i++) if (ids.indexOf(state.dns.leaks[i].uuid) >= 0) leaking = true
    if (!leaking || expired) drop("pinUuid")
  }
  if (num(p.scanUntilMs, 0) > 0 && p.scanUntilMs <= nowMs) drop("scanUntilMs")
  return changed ? out : p
}

// The SSID of the access point a connect was asked for ("" when it is gone).
function connectSsid(state, id) {
  for (var i = 0; i < state.networks.length; i++) if (state.networks[i].id === id) return state.networks[i].ssid
  return ""
}

// Whether anything is still waiting for the backend (keeps the panel's clock ticking).
function hasPending(p) {
  if (!p) return false
  return p.dns !== "" || p.pause !== "" || p.radio !== "" || p.connectId !== "" || p.disconnecting === true ||
    p.forgetUuid !== "" || p.pinUuid !== "" || num(p.scanUntilMs, 0) > 0
}

// A request to add to `pending`: stamps the time reconcilePending() ages it by.
function withPending(pending, patch, nowMs) {
  var out = Object.assign(emptyPending(), pending || {})
  var pk = Object.keys(patch)
  for (var j = 0; j < pk.length; j++) out[pk[j]] = patch[pk[j]]
  out.since = nowMs
  return out
}

// ------------------------------------------------------------- the hero

function currentServer(v) {
  var s = v.dns.servers
  for (var i = 0; i < s.length; i++) if (s[i].current) return s[i]
  return s.length ? s[0] : null
}

function isPaused(v) { return v.pihole.blocking === "disabled" }

// The last word of the line under the state word: the canary says whether
// the Pi-hole is really blocking. "" when it is not known or blocking is off.
function blockingWord(v) {
  var p = v.pihole
  if (p.blocking !== "enabled") return ""
  if (p.canaryBlocked === true) return "blocking"
  if (p.canaryBlocked === false) return "notBlocking"
  return ""
}

// What the hero says. kind picks the state word (Panel maps it to a
// translated string), tone its colour, `frozen` greys the graph.
//
//   pihole       accent   queries are answered by the Pi-hole and it blocks
//   paused       dim      the Pi-hole answers but blocking is off (countdown)
//   degraded     warning  the Pi-hole answers its canary but upstream fails
//   fallback     warning  a runtime failover moved DNS off the Pi-hole
//   bypassed     urgent   a Pi-hole is set up and this link's queries can skip
//                         it (dns.bypassed: an unpinned profile, or extra servers)
//   unreachable  urgent   the Pi-hole does not answer and nothing took over
//   none         urgent   the link has no DNS servers at all
//   router       dim      automatic (the router's DNS)
//   custom       dim      someone else's DNS servers
//   checking     dim      the first probe has not come back
//   offline      dim      no link
//   nobackend    urgent   `qnet watch` is not running
//
// setup: no Pi-hole is configured, so the hero offers to set one up
// (`detected` is a candidate on the LAN, shown as such, never used).
// empty: nothing to draw. frozen: unreachable or the API fails, so the graph
// is old. blocking: "blocking" | "notBlocking" | "" (see blockingWord).
function heroState(v) {
  var p = v.pihole
  var d = v.dns
  var cur = currentServer(v)
  var apiBad = p.api !== "ok"
  var out = {
    kind: "router", tone: "dim", frozen: false, setup: !p.configured, empty: !p.configured,
    via: cur ? cur.addr : "", latencyMs: null, latencyBad: false, apiIssue: "",
    fallback: "", pauseS: 0, noAnswer: false, sinceS: 0, blocking: "",
    resolvedFallback: "", detected: p.configured ? "" : p.detected
  }
  if (v.backendDown) {
    out.kind = "nobackend"; out.tone = "urgent"; out.frozen = true; out.setup = false; out.empty = true
    out.via = ""; out.detected = ""
    return out
  }
  if (!p.configured) {
    if (v.link.kind === "none") out.kind = "offline"
    else if (d.mode === "custom") out.kind = "custom"
    else if (d.mode === "pihole") { out.kind = "pihole"; out.tone = "accent" }
    else if (d.mode === "none") { out.kind = "none"; out.tone = "urgent"; out.resolvedFallback = d.resolvedFallback; out.via = "" }
    else if (d.mode === "unknown") { out.kind = "checking"; out.via = "" }
    else out.kind = "router"
    out.frozen = true
    return out
  }

  var lastProbe = p.probes.length ? p.probes[p.probes.length - 1] : null
  var probesFailing = !!lastProbe && !lastProbe.ok
  out.latencyMs = p.reachable ? p.latencyMs : null
  out.latencyBad = out.latencyMs !== null && out.latencyMs > LATENCY_BAD_MS || (p.reachable && probesFailing)
  out.apiIssue = p.reachable && apiBad && p.api !== "unconfigured" ? p.api : ""
  out.frozen = !p.reachable || apiBad

  if (v.link.kind === "none") {
    out.kind = "offline"; out.tone = "dim"; out.frozen = true; out.via = ""; out.latencyMs = null
    out.latencyBad = false; out.apiIssue = ""
    return out
  }
  if (d.mode === "unknown" || (p.health === "unknown" && d.mode !== "none")) {
    out.kind = "checking"; out.tone = "dim"; out.via = ""; out.latencyMs = null; out.latencyBad = false; out.apiIssue = ""
    return out
  }
  if (d.mode === "none") {
    out.kind = "none"; out.tone = "urgent"; out.resolvedFallback = d.resolvedFallback; out.via = ""
    out.latencyMs = null; out.latencyBad = false; out.apiIssue = ""
    return out
  }
  if (d.mode === "fallback" || d.failover.active) {
    out.kind = "fallback"; out.tone = "warning"; out.fallback = d.failover.fallback
    out.sinceS = d.failover.since; out.latencyMs = null; out.latencyBad = false; out.apiIssue = ""
    out.frozen = true
    return out
  }
  if (d.mode === "pihole") {
    if (!p.reachable) {
      out.kind = "unreachable"; out.tone = "urgent"; out.noAnswer = true; out.via = p.address || out.via
      out.latencyBad = false; out.apiIssue = ""
      return out
    }
    out.blocking = blockingWord(v)
    if (d.bypassed) { out.kind = "bypassed"; out.tone = "urgent"; return out }
    if (isPaused(v)) { out.kind = "paused"; out.tone = "dim"; out.pauseS = p.pauseRemainingS; out.blocking = ""; return out }
    if (p.health === "degraded") { out.kind = "degraded"; out.tone = "warning"; return out }
    out.kind = "pihole"; out.tone = "accent"
    return out
  }
  // automatic or custom DNS: bypassed when a reachable Pi-hole is set up
  // and this link is not pinned to it
  out.latencyMs = null; out.latencyBad = false
  if (d.bypassed && p.reachable) { out.kind = "bypassed"; out.tone = "urgent"; return out }
  out.kind = d.mode === "custom" ? "custom" : "router"
  out.tone = "dim"
  return out
}

// ------------------------------------------------------------- the graph

// The x-axis: three hours at least, as long as the history there is, a day
// at most; right-anchored on now.
function axisSpan(spanS) {
  return clamp(Math.max(MIN_AXIS_S, num(spanS, 0)), MIN_AXIS_S, HISTORY_SPAN_S)
}

// Seconds of history from its first non-empty bucket to nowS: the span the
// backend reports as historySpanS, for when it does not.
function dataSpan(history, nowS) {
  var h = Array.isArray(history) ? history : []
  for (var i = 0; i < h.length; i++) if (h[i].total > 0) return Math.max(0, nowS - h[i].t)
  return 0
}

// Whether the panel says how much history the graph holds: only while it is
// under a day.
function showSpanLabel(spanS) {
  var s = num(spanS, 0)
  return s > 0 && s < HISTORY_SPAN_S - HISTORY_BUCKET_S
}

// The history as columns of 10 minutes ending at nowS, as many as the axis
// holds, scaled to 0..1 against the busiest column (plus headroom) and
// lightly smoothed. Missing buckets are empty columns.
//   { total, blocked, peak, n, axisS, start } or null without data; start is
//   the first column that holds anything (the columns before it are empty).
function historySeries(history, nowS, spanS) {
  var h = Array.isArray(history) ? history : []
  if (h.length === 0) return null
  var axis = axisSpan(spanS)
  var colS = HISTORY_BUCKET_S
  var cols = Math.max(2, Math.round(axis / colS))
  // Columns sit on the bucket grid, the last one being the bucket now is in.
  var t0 = Math.floor(nowS / colS) * colS - (cols - 1) * colS
  var total = []
  var blocked = []
  var i
  for (i = 0; i < cols; i++) { total.push(0); blocked.push(0) }
  for (i = 0; i < h.length; i++) {
    var idx = Math.floor((h[i].t - t0) / colS)
    if (idx < 0 || idx >= cols) continue
    total[idx] += h[i].total
    blocked[idx] += h[i].blocked
  }
  // The newest column is still filling: scale what it holds to a full
  // bucket so the graph does not end in a dip, or repeat the column before
  // it while there is too little to scale.
  var lastIdx = cols - 1
  var elapsed = nowS - (t0 + lastIdx * colS)
  if (elapsed > 0 && elapsed < colS) {
    if (elapsed < 120) { total[lastIdx] = total[lastIdx - 1]; blocked[lastIdx] = blocked[lastIdx - 1] }
    else { var k = Math.min(4, colS / elapsed); total[lastIdx] *= k; blocked[lastIdx] *= k }
  }
  var start = cols
  for (i = 0; i < cols; i++) if (total[i] > 0) { start = i; break }
  function smooth(a) {
    var out = []
    for (var j = 0; j < a.length; j++) {
      var l = a[j > 0 ? j - 1 : 0], r = a[j < a.length - 1 ? j + 1 : a.length - 1]
      out.push((l + 2 * a[j] + r) / 4)
    }
    return out
  }
  var st = smooth(total)
  var sb = smooth(blocked)
  var peak = 0
  for (i = 0; i < st.length; i++) if (st[i] > peak) peak = st[i]
  if (peak <= 0) return { total: st, blocked: sb, peak: 0, n: cols, axisS: axis, start: start }
  var top = peak * 1.08
  var t = [], b = []
  for (i = 0; i < st.length; i++) {
    t.push(st[i] / top)
    b.push(Math.min(sb[i], st[i]) / top)
  }
  return { total: t, blocked: b, peak: peak, n: cols, axisS: axis, start: start }
}

// Values (0..1) as points left to right over [x0, x0 + width], 0 on the
// floor line yFloor and 1 at yFloor - h.
function edgePoints(values, x0, width, yFloor, h) {
  var pts = []
  var n = values.length
  if (n < 2) return pts
  for (var i = 0; i < n; i++) {
    pts.push({ x: x0 + width * i / (n - 1), y: yFloor - clamp(values[i], 0, 1) * h })
  }
  return pts
}

// The same as a smooth curve (Catmull-Rom through each value, `steps` points
// between neighbours, never below the floor or above the top).
function smoothEdge(values, x0, width, yFloor, h, steps) {
  var pts = []
  var n = values.length
  if (n < 2) return pts
  var dx = width / (n - 1)
  var st = Math.max(1, toInt(steps, 6))
  function y(v) { return yFloor - clamp(v, 0, 1) * h }
  for (var i = 0; i < n - 1; i++) {
    var p0 = values[i > 0 ? i - 1 : 0], p1 = values[i], p2 = values[i + 1], p3 = values[i + 2 < n ? i + 2 : n - 1]
    for (var k = 0; k < st; k++) {
      var t = k / st
      var v = 0.5 * ((2 * p1) + (p2 - p0) * t + (2 * p0 - 5 * p1 + 4 * p2 - p3) * t * t + (3 * p1 - p0 - 3 * p2 + p3) * t * t * t)
      pts.push({ x: x0 + (i + t) * dx, y: y(v) })
    }
  }
  pts.push({ x: x0 + width, y: y(values[n - 1]) })
  return pts
}

// The runs of an edge that stand more than `rise` px above the floor, for
// the stroke: a span of nothing gets no line. Each run takes the point on
// either side, so it ends down on the floor.
function strokeRuns(pts, yFloor, rise) {
  var runs = []
  var run = null
  for (var i = 0; i < pts.length; i++) {
    var up = pts[i].y < yFloor - rise
    if (up && !run) {
      run = i > 0 ? [pts[i - 1]] : []
      runs.push(run)
    }
    if (run) {
      run.push(pts[i])
      if (!up) run = null
    }
  }
  for (var j = runs.length - 1; j >= 0; j--) if (runs[j].length < 2) runs.splice(j, 1)
  return runs
}

// The graph's head dot: the newest probe's verdict. ok null: no probe yet.
function headState(probes) {
  var list = Array.isArray(probes) ? probes : []
  if (list.length === 0) return { ok: null, ms: null }
  var last = list[list.length - 1]
  return { ok: last.ok === true, ms: last.ms }
}

// A short signature of the history/probe arrays, so the panel redraws the
// graph when they change and not on every snapshot.
function seriesSignature(arr) {
  var a = Array.isArray(arr) ? arr : []
  if (a.length === 0) return "0"
  var last = a[a.length - 1]
  var sum = 0
  for (var i = 0; i < a.length; i++) sum += (a[i].total !== undefined ? a[i].total + a[i].blocked : (a[i].ok ? 1 : 0) + (a[i].ms || 0))
  return a.length + ":" + last.t + ":" + sum
}

// ---------------------------------------------------------------- leaks

// What bypasses the Pi-hole, as at most two lines:
//   bypass    urgent: this link's queries can skip it (dns.bypassed). Pin
//             applies the Pi-hole to the link in use (`qnet dns pihole`).
//             `where` and `details` say how (the active link's leaks).
//   profiles  warning: saved profiles that are not in use and would bypass
//             it when they are. One line however many; Pin all pins them in
//             one `qnet dns pin u1 u2`. lines are for the tooltip.
// pending.pinUuid (space-separated) hides the profiles just pinned.
function leakGroups(v, pending) {
  var pinned = {}
  var ids = pending && pending.pinUuid ? String(pending.pinUuid).split(" ") : []
  for (var i = 0; i < ids.length; i++) if (ids[i] !== "") pinned[ids[i]] = true
  var inactive = []
  var active = []
  var ls = v.dns.leaks
  for (var j = 0; j < ls.length; j++) {
    var lk = ls[j]
    if (lk.kind === "profile" && !(lk.uuid !== "" && lk.uuid === v.link.uuid)) {
      if (lk.uuid !== "" && pinned[lk.uuid]) continue
      inactive.push(lk)
    } else active.push(lk)
  }
  var bypass = null
  if (v.dns.bypassed && !v.backendDown) {
    var details = []
    for (var a = 0; a < active.length; a++) details.push((active[a].where ? active[a].where + ": " : "") + active[a].detail)
    bypass = { where: active.length ? active[0].where : "", details: details, action: { verb: "pihole" } }
  }
  var profiles = null
  if (inactive.length) {
    var uuids = []
    var lines = []
    for (var k = 0; k < inactive.length; k++) {
      if (inactive[k].uuid !== "" && uuids.indexOf(inactive[k].uuid) < 0) uuids.push(inactive[k].uuid)
      lines.push(inactive[k].where + (inactive[k].detail ? ": " + inactive[k].detail : ""))
    }
    profiles = { count: inactive.length, uuids: uuids, lines: lines, pinnable: uuids.length > 0 }
  }
  return { bypass: bypass, profiles: profiles }
}

// ------------------------------------------------------------- DNS row

// Which segmented tile is lit, and in what colour. Never lights a wrong
// tile: a custom resolver lights neither, a runtime failover lights Pi-hole
// in the warning colour with its own label, and while the mode is unknown
// (no probe yet) or there are no servers, nothing is lit.
//   pihole: "on" | "warn" | "off"; auto: "on" | "off"
//   custom: the servers for the "Custom: 9.9.9.9" caption, or null
function dnsTiles(v) {
  // Without the backend nothing is known, so nothing is lit.
  if (v.backendDown) return { live: "unknown", pihole: "off", fallbackLabel: false, auto: "off", custom: null }
  var mode = v.dns.mode
  return {
    live: mode,
    pihole: mode === "pihole" ? "on" : (mode === "fallback" ? "warn" : "off"),
    fallbackLabel: mode === "fallback",
    auto: mode === "auto" ? "on" : "off",
    custom: mode === "custom" ? customServers(v) : null
  }
}

// The addresses a custom resolver uses (current ones first, at most two).
function customServers(v) {
  var seen = {}
  var list = []
  var s = v.dns.servers
  var i
  for (i = 0; i < s.length; i++) if (s[i].current && !seen[s[i].addr]) { seen[s[i].addr] = true; list.push(s[i].addr) }
  for (i = 0; i < s.length; i++) if (!seen[s[i].addr]) { seen[s[i].addr] = true; list.push(s[i].addr) }
  return list.slice(0, 2)
}

// A tap on a tile: the verb to run, or null when the tile is already lit.
function tapDns(tile, v) {
  var t = dnsTiles(v)
  if (tile === "pihole") return t.pihole === "off" ? { verb: "pihole" } : null
  if (tile === "auto") return t.auto === "off" ? { verb: "auto" } : null
  return null
}

// What "Replace custom DNS ...?" names: the servers the backend reported in
// its confirm answer (a string or a list), else the ones the resolver uses.
function confirmServers(detail, v) {
  var list = []
  if (Array.isArray(detail)) {
    for (var i = 0; i < detail.length; i++) { var a = addr(detail[i]); if (a !== "") list.push(a) }
  } else if (isObj(detail) && Array.isArray(detail.servers)) {
    return confirmServers(detail.servers, v)
  } else if (typeof detail === "string") {
    var parts = detail.split(/[\s,;]+/)
    for (var j = 0; j < parts.length; j++) { var b = addr(parts[j]); if (b !== "" && /[0-9a-fA-F]/.test(b) && (b.indexOf(".") >= 0 || b.indexOf(":") >= 0)) list.push(b) }
  }
  if (list.length === 0) list = customServers(v)
  return list.slice(0, 2).join(", ")
}

// The pause chip: "Pause 5m", or "Resume 4:32" while paused.
function pauseChip(v) {
  var paused = isPaused(v)
  return {
    mode: paused ? "resume" : "pause",
    remainingS: paused ? v.pihole.pauseRemainingS : 0,
    enabled: !v.backendDown && v.pihole.configured && v.pihole.reachable && v.pihole.api === "ok" && v.link.kind !== "none"
  }
}

// ------------------------------------------------------------- the header

function wifiGlyph(signal) {
  var s = clamp(num(signal, 0), 0, 100)
  var idx = Math.max(0, Math.min(4, Math.ceil(s / 20) - 1))
  return GLYPH.wifi[idx]
}

function isRestricted(v) { return v.link.kind !== "none" && (v.link.connectivity === "portal" || v.link.connectivity === "limited") }

// The glyph for the connection, in the bar and in the header.
function linkGlyph(v) {
  var l = v.link
  var restricted = isRestricted(v)
  if (l.kind === "wifi") return restricted ? GLYPH.wifiRestricted : wifiGlyph(l.signal)
  if (l.kind === "ethernet") return restricted ? GLYPH.ethernetOff : GLYPH.ethernet
  return GLYPH.wifiOff
}

// The header's two lines. title: the SSID, or "" when the panel names it
// itself ("Ethernet", "Offline", "Wi-Fi off"). status: [{ k, ... }] parts the
// panel joins with " · ": k "state" (key connected | limited | portal |
// nointernet | offline | off) or k "text" (band, signal, rate, "gw 4 ms" while
// the panel is open and the backend measures it). urgent: the state part
// reads in the urgent colour. disconnectable: a Wi-Fi link, which the header
// can drop (a secondary click or Delete on it).
function headerInfo(v, fmt) {
  var l = v.link
  var out = {
    kind: "offline", title: "", glyph: linkGlyph(v), status: [], urgent: false, portal: false,
    restricted: isRestricted(v), disconnectable: false
  }
  if (v.backendDown) {
    out.kind = "nobackend"; out.urgent = true; out.restricted = false
    out.status.push({ k: "state", key: "nobackend" })
    return out
  }
  if (l.kind === "none") {
    if (!v.radio.wifiEnabled) { out.kind = "off"; out.status.push({ k: "state", key: "off" }) }
    else { out.status.push({ k: "state", key: "offline" }) }
    return out
  }
  out.kind = l.kind
  out.disconnectable = l.kind === "wifi"
  out.title = l.kind === "wifi" ? (l.ssid || l.connection) : ""
  var rate = formatRate(l.bitrateMbps, fmt)
  if (l.connectivity === "portal") {
    out.urgent = true; out.portal = true
    out.status.push({ k: "state", key: "portal" })
    return out
  }
  if (l.connectivity === "limited") {
    out.urgent = true
    out.status.push({ k: "state", key: "limited" })
  } else if (l.connectivity === "none") {
    out.urgent = true
    out.status.push({ k: "state", key: "nointernet" })
  } else {
    out.status.push({ k: "state", key: "connected" })
  }
  if (l.kind === "wifi") {
    if (l.band) out.status.push({ k: "text", text: l.band })
    if (l.signal > 0) out.status.push({ k: "text", text: formatDecimal(l.signal, 0, fmt) + "%" })
  }
  if (rate !== "") out.status.push({ k: "text", text: rate })
  if (l.gatewayMs !== null) out.status.push({ k: "text", text: "gw " + formatLatency(l.gatewayMs, fmt) })
  return out
}

// The bar icon's tooltip: only when something deserves one.
function barTip(v) {
  if (v.link.connectivity === "portal" && v.link.kind !== "none") return "portal"
  if (v.link.connectivity === "limited" && v.link.kind !== "none") return "limited"
  var h = heroState(v)
  if (h.kind === "fallback" || h.kind === "unreachable" || h.kind === "bypassed") return h.kind
  return ""
}

// The bar icon takes the urgent colour for a restricted link and for DNS
// that bypasses or lost the Pi-hole.
function barActive(v) {
  var tip = barTip(v)
  return tip === "portal" || tip === "limited" || tip === "unreachable" || tip === "bypassed"
}

// Whether the QR share button is offered: a connected, non-802.1X Wi-Fi.
function canShareWifi(v) {
  if (v.link.kind !== "wifi") return false
  for (var i = 0; i < v.networks.length; i++) if (v.networks[i].active) return v.networks[i].security !== "enterprise"
  return true
}

// The IP footer, with a stable placeholder so it never reflows. (The
// gateway's latency is on the header's status line.)
function ipFooter(v) {
  return { ip: v.link.ip4, text: v.link.ip4 !== "" ? v.link.ip4 : "--", copyable: v.link.ip4 !== "" }
}

// ------------------------------------------------------------- networks

// The list under the header: saved networks first, then the rest;
// strongest first within each group, ties by name. The network in use is not
// in it (the header is that row, and carries its Disconnect). Hidden
// networks (no SSID) are left out unless asked for; a duplicate SSID keeps
// its strongest entry (the backend groups, this is a guard).
function orderNetworks(networks, showHidden) {
  var best = {}
  var order = []
  var list = Array.isArray(networks) ? networks : []
  var inUse = {}
  var i
  for (i = 0; i < list.length; i++) if (list[i].active && !list[i].hidden) inUse[list[i].ssid] = true
  for (i = 0; i < list.length; i++) {
    var n = list[i]
    if (n.active || (!n.hidden && inUse[n.ssid])) continue
    if (n.hidden && !showHidden) continue
    var key = n.hidden ? "\u0000" + n.id : n.ssid
    if (best[key] === undefined) { best[key] = n; order.push(key) }
    else if (n.signal > best[key].signal) best[key] = n
  }
  var out = []
  for (i = 0; i < order.length; i++) out.push(best[order[i]])
  function rank(n) { return n.known ? 0 : 1 }
  out.sort(function(a, b) {
    var ra = rank(a), rb = rank(b)
    if (ra !== rb) return ra - rb
    if (a.signal !== b.signal) return b.signal - a.signal
    return a.ssid < b.ssid ? -1 : (a.ssid > b.ssid ? 1 : 0)
  })
  return out
}

// What a tap on a network row does.
//   disconnect  the active network
//   connect     a known network, or an open/OWE one: no secret
//   password    a secured unknown network: ask for the passphrase
//   nmtui       802.1X that is not saved: the terminal tool
//   none        a hidden network
function connectPlan(net) {
  if (!net || net.hidden) return "none"
  if (net.active) return "disconnect"
  if (net.known) return "connect"
  if (net.security === "open" || net.security === "owe") return "connect"
  if (net.security === "enterprise") return "nmtui"
  return "password"
}

// The caption under a network's name, and its colour.
//   ctx: { connectId, disconnecting, forgetUuid, failId, failText, armedUuid, connectivity }
// Returns { key, tone, text }: key is a translated caption or "text" (use
// `text` as given), tone dim | urgent | accent | none.
function rowCaption(net, ctx) {
  var c = ctx || {}
  if (c.failId && c.failId === net.id) return { key: "text", tone: "urgent", text: c.failText || "" }
  if (c.armedUuid && net.uuid && c.armedUuid === net.uuid) return { key: "forget", tone: "urgent", text: "" }
  if (c.connectId && c.connectId === net.id) return { key: "connecting", tone: "dim", text: "" }
  if (c.disconnecting && net.active) return { key: "disconnecting", tone: "dim", text: "" }
  if (c.forgetUuid && net.uuid && c.forgetUuid === net.uuid) return { key: "forgetting", tone: "dim", text: "" }
  if (net.active) {
    if (c.connectivity === "portal") return { key: "portal", tone: "urgent", text: "" }
    if (c.connectivity === "limited") return { key: "limited", tone: "urgent", text: "" }
    return { key: "connected", tone: "accent", text: "" }
  }
  if (net.hidden) return { key: "hidden", tone: "dim", text: "" }
  if (net.known) return { key: "saved", tone: "dim", text: "" }
  if (net.security === "open") return { key: "open", tone: "dim", text: "" }
  if (net.security === "enterprise") return { key: "enterprise", tone: "dim", text: "" }
  return { key: "", tone: "none", text: "" }
}

// ----------------------------------------------------------- processes

function okBin(bin) { return typeof bin === "string" && bin.length > 0 && bin.charAt(0) === "/" }

function argvDns(bin, verb, force) {
  if (!okBin(bin) || (verb !== "pihole" && verb !== "auto")) return null
  var a = [bin, "dns", verb]
  if (force === true) a.push("--force")
  return a
}

// `qnet dns pin <uuid> [<uuid>...]`: one uuid or a list, each validated.
function argvPin(bin, uuids) {
  var list = Array.isArray(uuids) ? uuids : [uuids]
  if (!okBin(bin) || list.length === 0 || list.length > MAX_LEAKS) return null
  for (var i = 0; i < list.length; i++) if (!UUID_RE.test(String(list[i] || ""))) return null
  return [bin, "dns", "pin"].concat(list.map(String))
}

function argvPause(bin, secs) {
  var s = Math.round(num(secs, PAUSE_SECONDS))
  if (!okBin(bin) || s < 1 || s > 86400) return null
  return [bin, "pihole", "pause", String(s)]
}

function argvResume(bin) { return okBin(bin) ? [bin, "pihole", "resume"] : null }

function argvConnect(bin, apPath) {
  if (!okBin(bin) || !AP_PATH_RE.test(String(apPath || ""))) return null
  return [bin, "wifi", "connect", String(apPath)]
}

function argvDown(bin) { return okBin(bin) ? [bin, "wifi", "down"] : null }

function argvForget(bin, uuid) {
  if (!okBin(bin) || !UUID_RE.test(String(uuid || ""))) return null
  return [bin, "wifi", "forget", String(uuid)]
}

function argvScan(bin) { return okBin(bin) ? [bin, "wifi", "scan"] : null }

function argvRadio(bin, on) { return okBin(bin) ? [bin, "wifi", "radio", on ? "on" : "off"] : null }

function argvPortal(bin) { return okBin(bin) ? [bin, "portal"] : null }

// The floating-terminal launcher joins its arguments with spaces and hands
// them to bash, so every token must be a plain word. A token that is not
// (a path with a space, a quote) makes the whole command null. Setup takes no
// address: it asks the user to type the Pi-hole's, so a guess from the
// network can never become the pinned one.
function argvTerminal(kind, bin) {
  var plain = /^[A-Za-z0-9_.\/:@%+=,\-]+$/
  var cmd
  if (kind === "nmtui") cmd = ["nmtui"]
  else if (kind === "setup") cmd = [okBin(bin) && plain.test(bin) ? bin : "qnet", "pihole", "setup"]
  else return null
  for (var i = 0; i < cmd.length; i++) if (!plain.test(cmd[i])) return null
  return ["omarchy-launch-floating-terminal-with-presentation"].concat(cmd)
}

function argvOpenUrl(url) {
  var u = safeUrl(url)
  return u === "" ? null : ["omarchy-launch-browser", u]
}

function argvCopy(text) {
  var t = String(text === null || text === undefined ? "" : text)
  return IP_RE.test(t) ? ["wl-copy", "--", t] : null
}

// The last JSON object line of an action's stdout, as
// { ok, error, detail, verifiedVia, blocked, verifyError }. Anything
// unreadable is a failure with error "noanswer". `qnet dns pihole` reports
// verifiedVia only when its canary came back blocked (blocked: true), else
// verifyError.
function parseResult(text, exitCode) {
  var s = text === null || text === undefined ? "" : String(text)
  if (s.length > MAX_LINE) s = s.substring(0, MAX_LINE)
  var lines = s.split("\n")
  for (var i = lines.length - 1; i >= 0; i--) {
    var ln = lines[i].trim()
    if (ln === "") continue
    var obj
    try { obj = JSON.parse(ln) } catch (e) { break }
    if (!isObj(obj) || typeof obj.ok !== "boolean") break
    return {
      ok: obj.ok === true, error: clean(obj.error, 80), detail: obj.detail === undefined ? null : obj.detail,
      verifiedVia: addr(obj.verifiedVia), blocked: obj.blocked === true, verifyError: clean(obj.verifyError, 80)
    }
  }
  return {
    ok: false, error: exitCode === 0 || exitCode === undefined ? "noanswer" : "exit", detail: null,
    verifiedVia: "", blocked: false, verifyError: ""
  }
}

// A failed result as { code, text }: code is a translated message key
// (confirm and enterprise are handled by the panel before this), text a
// cleaned backend message to show when the code is "generic".
function failure(result) {
  var e = String(result && result.error || "").toLowerCase()
  if (e === "confirm" || e === "enterprise") return { code: e, text: "" }
  if (e === "wrongpassword" || e === "wrong-password" || e === "auth" || e === "secrets" || e === "badpassword")
    return { code: "wrongPassword", text: "" }
  if (e === "noanswer" || e === "exit" || e === "") return { code: "noAnswer", text: "" }
  if (e === "timeout") return { code: "timeout", text: "" }
  if (e === "toosoon" || e === "too-soon" || e === "ratelimit") return { code: "tooSoon", text: "" }
  return { code: "generic", text: clean(e, 60) }
}

// After `qnet dns pihole` succeeded: "" when its canary came back blocked,
// else the reason it did not (verifyError), to show as a warning. Nothing for
// other verbs, or when the backend says neither.
function verifyNote(verb, result) {
  if (verb !== "pihole" || !result || !result.ok || result.blocked === true) return ""
  return result.verifyError
}

// ------------------------------------------------------------ keyboard

// The focusable rows in order, top to bottom, each with the items that
// left/right walk. ctx: { confirm } -- an inline confirm line adds its two
// buttons as a row above the DNS row.
//   header   conn? (the Wi-Fi link: Delete or Enter drops it), portal?, qr?,
//            speed?, radio
//   hero     setup (no Pi-hole configured), else pause, admin?
//   bypass   Pin, when this link's queries can skip the Pi-hole
//   profiles Pin all, for saved profiles that would bypass it
//   confirm  replace, cancel
//   dns      tile:pihole, tile:auto
//   scan     the Networks label's scan action
//   net:N    one row per listed network
//   ip       the footer
function focusRows(v, ctx, pending, nets) {
  var c = ctx || {}
  var rows = []
  var items = []
  if (v.link.kind === "wifi") items.push("conn")
  if (v.link.kind !== "none" && v.link.connectivity === "portal") items.push("portal")
  if (canShareWifi(v)) items.push("qr")
  if (v.link.device !== "" && v.link.kind !== "none") items.push("speed")
  items.push("radio")
  rows.push({ id: "header", items: items })
  if (!v.pihole.configured) rows.push({ id: "hero", items: ["setup"] })
  else rows.push({ id: "hero", items: v.pihole.adminUrl !== "" ? ["pause", "admin"] : ["pause"] })
  var g = leakGroups(v, pending)
  if (g.bypass) rows.push({ id: "bypass", items: ["fix"] })
  if (g.profiles && g.profiles.pinnable) rows.push({ id: "profiles", items: ["pinall"] })
  if (c.confirm) rows.push({ id: "confirm", items: ["replace", "cancel"] })
  rows.push({ id: "dns", items: ["tile:pihole", "tile:auto"] })
  rows.push({ id: "scan", items: ["scan"] })
  var list = nets || orderNetworks(v.networks)
  for (var n = 0; n < list.length; n++) rows.push({ id: "net:" + n, items: ["row"] })
  rows.push({ id: "ip", items: ["ip"] })
  return rows
}

function rowIndex(rows, id) {
  for (var i = 0; i < rows.length; i++) if (rows[i].id === id) return i
  return -1
}

// Where the cursor starts: the Networks list ("net:0"), else the scan
// action, else the DNS row.
function initialCursor(rows) {
  var i = rowIndex(rows, "net:0")
  if (i < 0) i = rowIndex(rows, "scan")
  if (i < 0) i = rowIndex(rows, "dns")
  return { row: rows[Math.max(0, i)].id, item: 0 }
}

// One key. cursor { row, item }; memory { rowId: itemIndex } remembers where
// each row's cursor last was, so down-and-up comes back to the same tile.
// Up/down stop at the ends; left/right stop at a row's ends.
function moveFocus(rows, cursor, dx, dy, memory) {
  var mem = {}
  var mk = Object.keys(memory || {})
  for (var m = 0; m < mk.length; m++) mem[mk[m]] = memory[mk[m]]
  var at = rowIndex(rows, cursor.row)
  if (at < 0) return { cursor: initialCursor(rows), memory: mem }
  var row = rows[at]
  var item = clamp(cursor.item, 0, row.items.length - 1)
  mem[row.id] = item
  if (dy !== 0) {
    var to = clamp(at + (dy > 0 ? 1 : -1), 0, rows.length - 1)
    var target = rows[to]
    var remembered = mem[target.id] === undefined ? 0 : mem[target.id]
    return { cursor: { row: target.id, item: clamp(remembered, 0, target.items.length - 1) }, memory: mem }
  }
  if (dx !== 0) {
    item = clamp(item + (dx > 0 ? 1 : -1), 0, row.items.length - 1)
    mem[row.id] = item
  }
  return { cursor: { row: row.id, item: item }, memory: mem }
}

// A cursor that still points somewhere after the rows changed under it.
function settleCursor(rows, cursor, lastIndex) {
  if (rowIndex(rows, cursor.row) >= 0) {
    var r = rows[rowIndex(rows, cursor.row)]
    return { row: r.id, item: clamp(cursor.item, 0, r.items.length - 1) }
  }
  var fallback = rows[clamp(lastIndex, 0, rows.length - 1)]
  return { row: fallback.id, item: 0 }
}

// ------------------------------------------------------- key auto-repeat

// A press that counts: not within gapMs of the last one for this action.
function freshGate(times, name, nowMs, gapMs) {
  var last = times[name]
  times[name] = nowMs
  return last === undefined || nowMs - last >= gapMs
}

if (typeof module !== "undefined") {
  module.exports = {
    MAX_LINE: MAX_LINE, MAX_NETWORKS: MAX_NETWORKS, MAX_HISTORY: MAX_HISTORY, MAX_PROBES: MAX_PROBES,
    HISTORY_SPAN_S: HISTORY_SPAN_S, HISTORY_BUCKET_S: HISTORY_BUCKET_S, MIN_AXIS_S: MIN_AXIS_S,
    STABLE_UPTIME_MS: STABLE_UPTIME_MS, PAUSE_SECONDS: PAUSE_SECONDS, LATENCY_BAD_MS: LATENCY_BAD_MS,
    PENDING_TTL_MS: PENDING_TTL_MS, SCAN_SPIN_MS: SCAN_SPIN_MS, GLYPH: GLYPH,
    clean: clean, safeUrl: safeUrl, emptyState: emptyState, normalizeState: normalizeState,
    parseStateLine: parseStateLine, backoffMs: backoffMs, restartAttempt: restartAttempt,
    formatCountdown: formatCountdown, groupDigits: groupDigits, formatCount: formatCount,
    formatPercent: formatPercent, formatLatency: formatLatency, formatRate: formatRate, formatSpan: formatSpan,
    pauseRemaining: pauseRemaining, effective: effective, reconcilePending: reconcilePending,
    emptyPending: emptyPending, hasPending: hasPending, withPending: withPending,
    currentServer: currentServer, heroState: heroState, blockingWord: blockingWord,
    axisSpan: axisSpan, dataSpan: dataSpan, showSpanLabel: showSpanLabel, historySeries: historySeries,
    edgePoints: edgePoints, smoothEdge: smoothEdge, strokeRuns: strokeRuns, headState: headState,
    seriesSignature: seriesSignature, leakGroups: leakGroups, dnsTiles: dnsTiles,
    customServers: customServers, tapDns: tapDns, confirmServers: confirmServers, pauseChip: pauseChip,
    wifiGlyph: wifiGlyph, isRestricted: isRestricted, linkGlyph: linkGlyph, headerInfo: headerInfo,
    barTip: barTip, barActive: barActive, canShareWifi: canShareWifi, ipFooter: ipFooter,
    orderNetworks: orderNetworks, connectPlan: connectPlan, rowCaption: rowCaption,
    argvDns: argvDns, argvPin: argvPin, argvPause: argvPause, argvResume: argvResume,
    argvConnect: argvConnect, argvDown: argvDown, argvForget: argvForget, argvScan: argvScan,
    argvRadio: argvRadio, argvPortal: argvPortal, argvTerminal: argvTerminal, argvOpenUrl: argvOpenUrl,
    argvCopy: argvCopy, parseResult: parseResult, failure: failure, verifyNote: verifyNote,
    focusRows: focusRows, rowIndex: rowIndex, initialCursor: initialCursor, moveFocus: moveFocus,
    settleCursor: settleCursor, freshGate: freshGate
  }
}

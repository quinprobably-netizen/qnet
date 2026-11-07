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
var MAX_UPSTREAMS = 4
var STABLE_UPTIME_MS = 30000   // a watch child must live this long to reset the backoff
var PAUSE_SECONDS = 300
var LATENCY_BAD_MS = 100
var PENDING_TTL_MS = 12000     // an unconfirmed request is given up after this
var SCAN_SPIN_MS = 4000
var SCAN_IF_STALE_S = 60         // entering the Wi-Fi view scans only if the last scan is older
var FAILOVER_AFTER_S = 30        // the backend fails over after this long of failed probes
var ACTION_DEADLINE_MS = 25000   // an action that has not answered by now is given up
var GW_SLOW_MS = 50              // the gateway's latency is worth a word above this

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
  pc: "\u{f0322}",
  ap: "\u{f05a9}",
  shield: "\u{f0498}",
  shieldOutline: "\u{f0499}",
  shieldOff: "\u{f099c}",
  earth: "\u{f01e7}",
  plus: "\u{f0415}",
  lock: "\u{f033e}",
  resolver: "\u{f048d}",
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
      kind: oneOf(lk[j].kind, ["link", "profile", "ipv6-ra", "resolved-fallback"], "link"),
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
      active: nw[k].active === true, band: clean(nw[k].band, 12),
      frequencyMhz: clamp(toInt(nw[k].frequencyMhz, 0), 0, 8000)
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
  var dbm = l.signalDbm === null || l.signalDbm === undefined ? NaN : num(l.signalDbm, NaN)

  // The resolvers the Pi-hole forwards to, busiest first, at most four.
  var upstreams = []
  var up = Array.isArray(p.upstreams) ? p.upstreams : []
  for (var u = 0; u < up.length; u++) {
    if (!isObj(up[u])) continue
    var uip = addr(up[u].ip)
    var rms = up[u].responseMs === null || up[u].responseMs === undefined ? NaN : num(up[u].responseMs, NaN)
    if (uip === "" && clean(up[u].name, 80) === "") continue
    upstreams.push({
      name: clean(up[u].name, 80), ip: uip, port: clamp(toInt(up[u].port, 53), 0, 65535),
      count: Math.max(0, toInt(up[u].count, 0)), responseMs: isFinite(rms) && rms >= 0 ? rms : null
    })
  }
  upstreams.sort(function(a, b) { return b.count - a.count })
  upstreams = upstreams.slice(0, MAX_UPSTREAMS)
  var ab = isObj(p.answeredBy) ? p.answeredBy : {}
  var answeredBy = {
    blocklist: Math.max(0, toInt(ab.blocklist, 0)), cache: Math.max(0, toInt(ab.cache, 0)),
    forwarded: Math.max(0, toInt(ab.forwarded, 0))
  }
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
      frequencyMhz: clamp(toInt(l.frequencyMhz, 0), 0, 8000),
      prefix: toInt(l.prefix, 0) >= 1 && toInt(l.prefix, 0) <= 32 ? toInt(l.prefix, 0) : 0,
      gatewayMs: isFinite(gms) && gms >= 0 ? gms : null,
      gatewayOk: typeof l.gatewayOk === "boolean" ? l.gatewayOk : null,
      signalDbm: isFinite(dbm) && dbm < 0 && dbm >= -130 ? Math.round(dbm) : null,
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
      healthReason: clean(p.healthReason, 80),
      upstreams: upstreams, answeredBy: answeredBy,
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
    // Automatic through qnet: a choice, not a bypass.
    v.dns = Object.assign({}, state.dns, { mode: mode, modeSource: "profile", bypassed: false })
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

// How long until the backend fails over, in seconds, while the Pi-hole's
// probes are failing and a failover is armed (enabled and not yet active);
// null otherwise. The failing run is counted from the probes themselves, to
// nowS (or to the newest probe when nowS is not given).
function failoverIn(v, nowS) {
  var f = v.dns.failover
  if (!f.enabled || f.active) return null
  var pr = v.pihole.probes
  var i = pr.length - 1
  while (i >= 0 && !pr[i].ok) i--
  if (i === pr.length - 1) return null
  var first = pr[i + 1].t
  var now = typeof nowS === "number" ? nowS : pr[pr.length - 1].t
  return Math.min(FAILOVER_AFTER_S, Math.max(0, Math.ceil(FAILOVER_AFTER_S - (now - first))))
}

// Who the extra resolver is when the Pi-hole is one of several: the first
// server that is not the Pi-hole, as { who, viaRa } ("router" or an address;
// viaRa when it arrives by IPv6 router advertisement), or null.
function extraResolver(v) {
  if (v.dns.mode !== "pihole") return null
  var s = v.dns.servers
  var who = ""
  for (var i = 0; i < s.length; i++) if (s[i].role !== "pihole") { who = s[i].role === "router" ? "router" : s[i].addr; break }
  var ra = false
  for (var j = 0; j < v.dns.leaks.length; j++) if (v.dns.leaks[j].kind === "ipv6-ra") ra = true
  if (who === "" && ra) who = "router"
  return who === "" ? null : { who: who, viaRa: ra }
}

// What the hero says. kind picks the state word (Panel maps it to a
// translated string), tone its colour, `frozen` greys the graph.
//
//   pihole       accent   queries are answered by the Pi-hole and it blocks
//   paused       warning  the Pi-hole answers but blocking is off (countdown)
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
// is old. desaturated: frozen, or DNS is not going through the Pi-hole at
// all (the picture greys either way). blocking: "blocking" | "notBlocking" |
// "" (see blockingWord). action: the one corrective step this state offers,
// "setup" | "signin" | "usepihole" | "pin" | "" (it sits on the hero's line;
// nothing gets a row of its own). failoverIn: seconds until the backend
// fails over, while that is armed and the probes fail. extra: see
// extraResolver, set when the Pi-hole is one of several resolvers.
function heroState(v, nowS) {
  var p = v.pihole
  var d = v.dns
  var cur = currentServer(v)
  var apiBad = p.api !== "ok"
  var out = {
    kind: "router", tone: "dim", frozen: false, desaturated: true, setup: !p.configured, empty: !p.configured,
    via: cur ? cur.addr : "", latencyMs: null, latencyBad: false, apiIssue: "",
    fallback: "", pauseS: 0, noAnswer: false, sinceS: 0, blocking: "",
    resolvedFallback: "", detected: p.configured ? "" : p.detected,
    action: "", failoverIn: null, extra: null, healthReason: p.healthReason
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
    out.action = v.link.kind === "none" ? "" : "setup"
    return out
  }

  var lastProbe = p.probes.length ? p.probes[p.probes.length - 1] : null
  var probesFailing = !!lastProbe && !lastProbe.ok
  out.latencyMs = p.reachable ? p.latencyMs : null
  out.latencyBad = out.latencyMs !== null && out.latencyMs > LATENCY_BAD_MS || (p.reachable && probesFailing)
  out.apiIssue = p.reachable && apiBad && p.api !== "unconfigured" ? p.api : ""
  out.frozen = !p.reachable || apiBad
  out.desaturated = out.frozen || d.mode !== "pihole"
  if (p.reachable && p.api === "auth") out.action = "signin"

  if (v.link.kind === "none") {
    out.kind = "offline"; out.tone = "dim"; out.frozen = true; out.desaturated = true; out.via = ""; out.latencyMs = null
    out.latencyBad = false; out.apiIssue = ""; out.action = ""
    return out
  }
  if (d.mode === "unknown" || (p.health === "unknown" && d.mode !== "none")) {
    out.kind = "checking"; out.tone = "dim"; out.via = ""; out.latencyMs = null; out.latencyBad = false; out.apiIssue = ""
    out.desaturated = true; out.action = ""
    return out
  }
  if (d.mode === "none") {
    out.kind = "none"; out.tone = "urgent"; out.resolvedFallback = d.resolvedFallback; out.via = ""
    out.latencyMs = null; out.latencyBad = false; out.apiIssue = ""; out.desaturated = true
    out.action = "usepihole"
    return out
  }
  if (d.mode === "fallback" || d.failover.active) {
    out.kind = "fallback"; out.tone = "warning"; out.fallback = d.failover.fallback
    out.sinceS = d.failover.since; out.latencyMs = null; out.latencyBad = false; out.apiIssue = ""
    out.frozen = true; out.desaturated = true; out.action = ""
    return out
  }
  if (d.mode === "pihole") {
    if (!p.reachable) {
      out.kind = "unreachable"; out.tone = "urgent"; out.noAnswer = true; out.via = p.address || out.via
      out.latencyBad = false; out.apiIssue = ""; out.failoverIn = failoverIn(v, nowS); out.action = ""
      return out
    }
    out.blocking = blockingWord(v)
    if (d.bypassed) {
      out.kind = "bypassed"; out.tone = "urgent"; out.extra = extraResolver(v); out.blocking = ""
      out.action = "pin"
      return out
    }
    if (isPaused(v)) { out.kind = "paused"; out.tone = "warning"; out.pauseS = p.pauseRemainingS; out.blocking = ""; return out }
    if (p.health === "degraded") { out.kind = "degraded"; out.tone = "warning"; return out }
    out.kind = "pihole"; out.tone = "accent"
    return out
  }
  // automatic or custom DNS: bypassed when a reachable Pi-hole is set up
  // and this link is not pinned to it
  out.latencyMs = null; out.latencyBad = false
  if (d.bypassed && p.reachable) { out.kind = "bypassed"; out.tone = "urgent"; out.action = "pin"; return out }
  out.kind = d.mode === "custom" ? "custom" : "router"
  out.tone = "dim"
  return out
}

// Whether the panel's clock must tick while it is open: a pause counting
// down, a failover countdown, or a request waiting for the backend.
function needsClock(v, pending, nowS) {
  if (hasPending(pending)) return true
  if (v.pihole.blocking === "disabled") return true
  return failoverIn(v, nowS) !== null && !v.pihole.reachable && v.dns.mode === "pihole"
}

// ------------------------------------------------------------- the route

// How busy DNS is right now, 0..1: the last three history buckets' average
// against the busiest bucket of the day, never under 0.15 while there is any
// traffic. It sets how thick the flow on the route is.
function queryDensity(v) {
  var h = v.pihole.history
  var peak = 0
  var i
  for (i = 0; i < h.length; i++) if (h[i].total > peak) peak = h[i].total
  if (peak <= 0) return v.pihole.today.total > 0 ? 0.3 : 0
  var recent = 0
  var n = 0
  for (i = Math.max(0, h.length - 3); i < h.length; i++) { recent += h[i].total; n++ }
  return clamp((recent / Math.max(1, n)) / peak, 0.15, 1)
}

// Today's blocked share, 0..1.
function blockedShare(v) {
  var t = v.pihole.today
  if (t.total <= 0) return 0
  return clamp(t.blocked / t.total, 0, 1)
}

// "192.168.1.242" -> ".242"; anything else, "" (an IPv6 address is not
// shortened this way).
function lastOctet(address) {
  var m = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.(\d{1,3})$/.exec(String(address || ""))
  return m ? "." + m[1] : ""
}

// How the Pi-hole's answers divide, in whole percent: { blocklist, cache,
// forwarded } (they add up to 100 unless there is nothing yet).
function answeredShares(a) {
  var total = a.blocklist + a.cache + a.forwarded
  if (total <= 0) return { blocklist: 0, cache: 0, forwarded: 0 }
  var b = Math.round(a.blocklist * 100 / total)
  var c = Math.round(a.cache * 100 / total)
  return { blocklist: b, cache: c, forwarded: Math.max(0, 100 - b - c) }
}

function part(text, tone) { return { text: String(text), tone: tone || "" } }
function word(key, args, tone) { return { key: key, args: args || [], tone: tone || "" } }

// The address as it goes under a node: a LAN address as its last octet
// (".153"), anything else whole ("9.9.9.9").
function shortAddr(a) {
  var o = lastOctet(a)
  return o !== "" && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a) ? o : a
}

// How the Pi-hole looks in the hero and in the DNS view's chain, by state:
// { tone, glyph, mark, text, stat, statTone } -- text is its address with the
// mark (".153 ✓"), stat the word under it (latency, "paused 4:30", the
// failover countdown).
function piholeLook(v, h) {
  var p = v.pihole
  var short = shortAddr(p.address)
  if (h.kind === "paused") {
    return { tone: "dim", glyph: "shieldOutline", mark: "", text: short,
      stat: word("route.paused", [h.pauseS > 0 ? formatCountdown(h.pauseS) : ""], "warning"), statTone: "warning" }
  }
  if (h.kind === "fallback") return { tone: "dim", glyph: "shieldOff", mark: "\u2715", text: short + " \u2715", stat: null, statTone: "" }
  if (h.kind === "unreachable") {
    var fi = h.failoverIn
    return { tone: "urgent", glyph: "shieldOff", mark: "\u2715", text: short + " \u2715",
      stat: fi !== null ? (fi > 0 ? word("hero.failoverIn", [formatCountdown(fi)], "warning") : word("hero.failingOver", [], "warning")) : word("hero.noAnswer", [], "urgent"),
      statTone: fi !== null ? "warning" : "urgent" }
  }
  var ms = p.latencyMs !== null ? formatLatency(p.latencyMs) : ""
  return { tone: "accent", glyph: "shield", mark: "\u2713", text: short + " \u2713", stat: ms !== "" ? part(ms) : null,
    statTone: h.latencyBad ? "urgent" : "" }
}

// How many things bypass the Pi-hole, for the count on its node: the saved
// profiles that would, and this link itself when it does.
function leakCount(v, pending) {
  var g = leakGroups(v, pending)
  return (g.profiles ? g.profiles.count : 0) + (g.bypass ? 1 : 0)
}

// The hero's picture, as data: the route a DNS query takes from this machine
// out to the internet, hop by hop, and what state each hop is in. HeroViz
// only draws it. Slots, left to right: pc, ap, ph (the Pi-hole's place), up
// (the resolver beyond), then the arrow into the internet.
//
//   kind     route | direct | none | checking | offline | nobackend
//            route    the Pi-hole is the resolver: pc, ap, ph, up
//            direct   no Pi-hole in the path (not set up, or Automatic, or
//                     custom): pc, ap, [ph slot: a ghost to set up, or idle],
//                     up is the resolver
//            none     the link has no DNS servers: pc, ap, then a note
//            offline  pc alone
//   nodes    [{ id, glyph, tone, label, stat, statTone, mark, tip, open, badge }]
//            label and stat are parts: { text } or { key, args } to be worded
//            by the panel; tone accent | dim | warning | urgent
//            open  "wifi" | "dns" | "": the view the node opens (the route is
//                  the navigation: the AP opens Wi-Fi, the Pi-hole's place
//                  opens DNS)
//            badge null or { n, tone }: the count of things that bypass the
//                  Pi-hole, on its node
//   links    [{ a, b, state, tone, thin }] state flow | stalled | dim |
//            dashed; thin: after the Pi-hole, where the blocked share has
//            peeled off
//   branch   null or { tone, label, flow }: a dashed branch from the AP under
//            the Pi-hole to the internet (failover, or a bypass)
//   sink     null or { pct, empty, label }: the drain under the Pi-hole into
//            the pool of what was blocked
//   note     the words for the none kind, under the DNS node
//   ghost    true when the ph slot offers setup
//   flow     { live, density, share }: live is whether traffic is moving
function routeModel(v, nowS, pending) {
  var h = heroState(v, nowS)
  var l = v.link
  var p = v.pihole
  var d = v.dns
  var share = blockedShare(v)
  var out = {
    kind: "route", nodes: [], links: [], branch: null, sink: null, note: null, ghost: false,
    flow: { live: false, density: queryDensity(v), share: share }
  }
  if (h.kind === "nobackend") { out.kind = "nobackend"; out.flow.density = 0; return out }

  function node(id, glyph, tone, label, stat, extra) {
    var n = { id: id, glyph: glyph, tone: tone, label: label, stat: stat || null, statTone: "", mark: "", tip: "", open: "", badge: null }
    if (extra) for (var k in extra) n[k] = extra[k]
    out.nodes.push(n)
    return n
  }

  var online = l.kind !== "none"
  var pcLabel = part(l.ip4 !== "" ? (lastOctet(l.ip4) || l.ip4) : "—")
  node("pc", "pc", online ? "accent" : "dim", pcLabel, null, { tip: l.ip4 })

  if (!online) {
    out.kind = "offline"
    // the access point stands dim at the end of a dashed link, and still
    // opens the Wi-Fi view (to join something)
    node("ap", "ap", "dim", word(v.radio.wifiEnabled ? "route.offline" : "route.wifiOff", [], "dim"), null, { open: "wifi" })
    out.links.push({ a: "pc", b: "ap", state: "dashed", tone: "dim", thin: false })
    out.flow.density = 0
    return out
  }

  // the access point (or the wire)
  var wired = l.kind === "ethernet"
  var apLabel = l.signalDbm !== null ? part(l.signalDbm + " dBm") : (wired ? part(formatRate(l.bitrateMbps)) : part(l.signal > 0 ? l.signal + "%" : "—"))
  var apStat = null
  var apStatTone = ""
  if (l.gatewayOk === false) { apStat = part("gw ✗"); apStatTone = "urgent" }
  else if (l.gatewayMs !== null) { apStat = part(formatLatency(l.gatewayMs)); apStatTone = l.gatewayMs > GW_SLOW_MS ? "urgent" : "" }
  var ap = node("ap", wired ? "wire" : "ap", isRestricted(v) ? "urgent" : "accent", apLabel, apStat, { tip: wired ? "" : l.ssid, open: "wifi" })
  ap.statTone = apStatTone

  var live = p.configured && h.kind !== "unreachable" && h.kind !== "fallback" && out.flow.density > 0

  if (h.kind === "none") {
    out.kind = "none"
    node("ph", "shieldOff", "urgent", part(""), null, { mark: "\u2715", open: "dns" })
    out.links.push({ a: "pc", b: "ap", state: "flow", tone: "accent", thin: false, flow: false })
    out.links.push({ a: "ap", b: "ph", state: "dashed", tone: "urgent", thin: false, flow: false })
    out.note = word("route.none", [d.resolvedFallback], "urgent")
    out.flow.density = 0
    return out
  }

  // the resolver in use, for the routes that go straight to it
  var cur = currentServer(v)
  function resolverNode(tone) {
    var a = cur ? cur.addr : ""
    var role = cur ? cur.role : "other"
    var n = node("up", "earth", tone, part(a !== "" ? shortAddr(a) : "—"), role !== "other" && role !== "pihole" ? word("route.role." + role) : null, { tip: a })
    return n
  }

  if (h.kind === "checking") {
    out.kind = "route"
    node("ph", "shield", "dim", part(p.address !== "" ? shortAddr(p.address) : "…"), null, { open: "dns" })
    node("up", "earth", "dim", part("…"), null, {})
    out.links.push({ a: "pc", b: "ap", state: "dim", tone: "dim", thin: false }, { a: "ap", b: "ph", state: "dim", tone: "dim", thin: false },
      { a: "ph", b: "up", state: "dim", tone: "dim", thin: false }, { a: "up", b: "end", state: "dim", tone: "dim", thin: false })
    out.flow.density = 0
    return out
  }

  var throughPihole = p.configured && d.mode !== "auto" && d.mode !== "custom"
  if (!throughPihole) {
    // no Pi-hole in the path: not set up, Automatic, or somebody else's DNS
    out.kind = "direct"
    var bypassed = h.kind === "bypassed"
    if (!p.configured) {
      out.ghost = true
      node("ph", "ghost", "dim", part(p.detected !== "" ? shortAddr(p.detected) + "?" : ""), null, { tip: p.detected, open: "dns" })
    } else {
      node("ph", "shield", "dim", part(shortAddr(p.address)), word("route.idle", [], ""), { tip: p.address, open: "dns" })
    }
    resolverNode(bypassed ? "urgent" : "accent")
    var liveDirect = out.flow.density > 0 || p.today.total > 0
    out.links.push({ a: "pc", b: "ap", state: "flow", tone: "accent", thin: false, flow: liveDirect })
    out.links.push({ a: "ap", b: "up", state: "flow", tone: bypassed ? "urgent" : "accent", thin: false, flow: liveDirect })
    out.links.push({ a: "up", b: "end", state: "flow", tone: bypassed ? "urgent" : "accent", thin: false, flow: liveDirect })
    out.flow.live = liveDirect
    if (!p.configured && out.flow.density === 0) out.flow.density = 0.3
    return out
  }

  // the Pi-hole is the resolver
  var look = piholeLook(v, h)
  var ph = node("ph", look.glyph, look.tone, part(look.text), look.stat, { mark: look.mark, tip: p.address, open: "dns" })
  ph.statTone = look.statTone
  var nLeaks = leakCount(v, pending)
  if (nLeaks > 0) ph.badge = { n: nLeaks, tone: h.kind === "bypassed" ? "urgent" : "warning" }

  // the resolver beyond: the Pi-hole's busiest upstream
  var upstream = p.upstreams.length ? p.upstreams[0] : null
  var tips = []
  for (var i = 0; i < p.upstreams.length; i++) {
    var u = p.upstreams[i]
    tips.push((u.name !== "" ? u.name + "  " : "") + u.ip + (u.responseMs !== null ? "  " + formatLatency(u.responseMs) : ""))
  }
  var upTone = "accent"
  var upStat = upstream && upstream.responseMs !== null ? part(formatLatency(upstream.responseMs)) : null
  var upStatTone = ""
  if (h.kind === "degraded") {
    upTone = "warning"
    upStat = p.healthReason !== "" ? part(p.healthReason) : word("route.servfail", [], "warning")
    upStatTone = "warning"
  }
  var up = node("up", "earth", h.kind === "fallback" || h.kind === "unreachable" ? "dim" : upTone,
    upstream ? part(upstream.ip !== "" ? upstream.ip : upstream.name) : word("route.upstream", []), upStat,
    { tip: tips.join("\n") })
  up.statTone = upStatTone

  var thin = h.kind === "paused" || h.kind === "fallback" || h.kind === "unreachable" ? false : share > 0
  var flowing = live
  out.links.push({ a: "pc", b: "ap", state: "flow", tone: "accent", thin: false, flow: flowing || h.kind === "unreachable" ? true : false })
  if (h.kind === "unreachable") {
    out.links.push({ a: "ap", b: "ph", state: "stalled", tone: "accent", thin: false, flow: false })
    out.links.push({ a: "ph", b: "up", state: "dashed", tone: "dim", thin: false, flow: false })
    out.links.push({ a: "up", b: "end", state: "dashed", tone: "dim", thin: false, flow: false })
    out.links[0].flow = false
  } else if (h.kind === "fallback") {
    out.links.push({ a: "ap", b: "ph", state: "dim", tone: "dim", thin: false, flow: false })
    out.links.push({ a: "ph", b: "up", state: "dim", tone: "dim", thin: false, flow: false })
    out.links.push({ a: "up", b: "end", state: "dim", tone: "dim", thin: false, flow: false })
    var fb = d.failover.fallback
    out.branch = { tone: "warning", label: word("fallback." + fb, [], "warning"), flow: out.flow.density > 0 }
    out.links[0].flow = out.flow.density > 0
    // the fallback resolver is where the branch comes out
    if (cur) { up.label = part(shortAddr(cur.addr)); up.tone = "warning"; up.tip = cur.addr; up.stat = null }
  } else {
    out.links.push({ a: "ap", b: "ph", state: "flow", tone: "accent", thin: false, flow: flowing })
    out.links.push({ a: "ph", b: "up", state: "flow", tone: "accent", thin: thin, flow: flowing })
    out.links.push({ a: "up", b: "end", state: "flow", tone: "accent", thin: thin, flow: flowing })
  }

  if (h.kind === "bypassed") {
    var ex = h.extra
    var who = ex ? ex.who : (cur ? shortAddr(cur.addr) : "")
    out.branch = {
      tone: "urgent", flow: flowing,
      label: ex && ex.viaRa ? word("hero.extraRa", [who], "urgent") : word("hero.extra", [who], "urgent")
    }
  }

  if (h.kind === "paused") out.sink = { pct: 0, empty: true, label: null }
  else if ((h.kind === "pihole" || h.kind === "degraded" || h.kind === "bypassed") && p.today.total > 0)
    out.sink = { pct: Math.round(share * 1000) / 10, empty: share <= 0, label: word("hero.blocked", [formatPercent(p.today.percent)], "legend") }
  var anyFlow = !!(out.branch && out.branch.flow)
  for (var q = 0; q < out.links.length; q++) if (out.links[q].flow) anyFlow = true
  out.flow.live = anyFlow
  return out
}

// The route's stops for the keyboard, left to right: the nodes that open a
// view ("ap" opens Wi-Fi, "ph" opens DNS; offline only the AP). Nothing when
// there is no route to draw.
function routeStops(v) {
  var nodes = routeModel(v, 0).nodes
  var ids = []
  for (var i = 0; i < nodes.length; i++) if (nodes[i].open !== "") ids.push(nodes[i].id)
  return ids
}

// The view a route node opens: "wifi" | "dns" | "".
function routeTarget(v, id) {
  var nodes = routeModel(v, 0).nodes
  for (var i = 0; i < nodes.length; i++) if (nodes[i].id === id) return nodes[i].open
  return ""
}

// ------------------------------------------------------ the resolver chain

// The DNS view's picture: the same route as the hero, drawn top to bottom and
// compact, one row a node: this PC, systemd-resolved, the Pi-hole, and the
// resolvers the Pi-hole forwards to, one node each with its share of the
// queries and its response time. What is wrong is on the chain: a bypass or a
// failover is a side node off the trunk (dashed, urgent or warning), a paused
// Pi-hole is an outline, an unreachable one a cross with its countdown.
//
//   kind     as heroState: pihole | paused | degraded | fallback | bypassed |
//            unreachable | none | router | custom | checking | offline |
//            nobackend
//   nodes    top to bottom: [{ id, glyph, tone, label, sub, stat, statTone,
//            mark, tip, depth, via, viaTone, counts }]
//            label, sub, stat: parts ({ text } or { key, args })
//            depth 0 is the trunk, 1 a node hanging off it (the upstreams
//            under the Pi-hole; a bypass or the fallback beside it)
//            via the tube into the node: flow | stalled | dim | dashed, and
//            viaTone: accent | dim | warning | urgent
//            counts (the Pi-hole's) how its answers divide, today:
//            [{ key: blocklist | cache | forwarded, n }], as labelled counts
//            on its branch (not a meter)
//   flow     { density, share }
function chainModel(v, nowS) {
  var h = heroState(v, nowS)
  var l = v.link
  var p = v.pihole
  var d = v.dns
  var out = { kind: h.kind, nodes: [], flow: { density: queryDensity(v), share: blockedShare(v) } }
  if (h.kind === "nobackend") { out.flow.density = 0; return out }

  function add(id, glyph, tone, label, sub, stat, extra) {
    var n = {
      id: id, glyph: glyph, tone: tone, label: label, sub: sub || null, stat: stat || null, statTone: "",
      mark: "", tip: "", depth: 0, via: "flow", viaTone: "accent", counts: null
    }
    if (extra) for (var k in extra) n[k] = extra[k]
    out.nodes.push(n)
    return n
  }

  var online = l.kind !== "none"
  var pc = add("pc", "pc", online ? "accent" : "dim", word("chain.pc"), part(l.ip4 !== "" ? l.ip4 : "\u2014"))
  if (!online) {
    out.kind = "offline"
    pc.stat = word(v.radio.wifiEnabled ? "route.offline" : "route.wifiOff", [], "dim")
    pc.statTone = "dim"
    out.flow.density = 0
    return out
  }
  var res = add("res", "resolver", "accent", word("chain.resolved"), null, null, {})

  if (h.kind === "none") {
    res.tone = "urgent"
    res.sub = word("route.none", [d.resolvedFallback], "urgent")
    out.flow.density = 0
    return out
  }

  var cur = currentServer(v)
  if (h.kind === "checking") {
    add("ph", "shield", "dim", word("chain.pihole"), part(p.address !== "" ? shortAddr(p.address) : "\u2026"), null, { via: "dim", viaTone: "dim" })
    out.flow.density = 0
    return out
  }

  var through = p.configured && d.mode !== "auto" && d.mode !== "custom"
  if (!through) {
    // no Pi-hole in the path: the resolver in use is the end of the chain
    var bypassed = h.kind === "bypassed"
    var role = cur ? cur.role : "other"
    add("dest", "earth", bypassed ? "urgent" : "accent", part(cur ? cur.addr : "\u2014"),
      role !== "other" && role !== "pihole" ? word("route.role." + role) : null,
      bypassed ? word("hero.bypassed", [], "urgent") : null,
      { tip: cur ? cur.addr : "", statTone: bypassed ? "urgent" : "", viaTone: bypassed ? "urgent" : "accent" })
    return out
  }

  var dead = h.kind === "unreachable"
  var moved = h.kind === "fallback"

  // beside the trunk, above the Pi-hole: where the queries go when they do
  // not go through it
  if (h.kind === "fallback") {
    var fr = cur ? cur.role : "other"
    add("side", "earth", "warning", part(cur ? cur.addr : "\u2014"),
      fr !== "other" && fr !== "pihole" ? word("route.role." + fr) : null, word("chain.inUse", [], "warning"),
      { depth: 1, via: "flow", viaTone: "warning", statTone: "warning", tip: cur ? cur.addr : "" })
  } else if (h.kind === "bypassed") {
    var ex = h.extra
    var who = ex ? ex.who : (cur ? shortAddr(cur.addr) : "")
    add("side", "earth", "urgent", part(who), ex && ex.viaRa ? word("chain.viaRa") : null, word("chain.bypass", [], "urgent"),
      { depth: 1, via: "dashed", viaTone: "urgent", statTone: "urgent", tip: cur ? cur.addr : "" })
  }

  var look = piholeLook(v, h)
  var ph = add("ph", look.glyph, look.tone, word("chain.pihole"), part(look.text), look.stat, {
    mark: look.mark, tip: p.address, via: dead ? "stalled" : (moved ? "dim" : "flow"), viaTone: moved ? "dim" : "accent"
  })
  ph.statTone = look.statTone

  if (moved) return out

  // what its answers were, today, as labelled counts
  var ab = p.answeredBy
  if (!dead && ab.blocklist + ab.cache + ab.forwarded > 0) {
    ph.counts = [{ key: "blocklist", n: ab.blocklist }, { key: "cache", n: ab.cache }, { key: "forwarded", n: ab.forwarded }]
  }

  // the resolvers it forwards to
  var ups = p.upstreams
  var total = 0
  var i
  for (i = 0; i < ups.length; i++) total += ups[i].count
  for (i = 0; i < ups.length; i++) {
    var u = ups[i]
    var pct = total > 0 ? Math.round(u.count * 100 / total) : 0
    var text = (total > 0 ? pct + "%" : "") + (u.responseMs !== null ? (total > 0 ? " \u00b7 " : "") + formatLatency(u.responseMs) : "")
    var stat = text !== "" ? part(text) : null
    var tone = dead ? "dim" : (h.kind === "degraded" ? "warning" : "accent")
    var node = add("up:" + i, "earth", tone, part(u.ip !== "" ? u.ip : u.name), u.ip !== "" && u.name !== "" ? part(u.name) : null, stat, {
      depth: 1, via: dead ? "dashed" : "flow", viaTone: dead ? "dim" : "accent", tip: u.name + (u.count > 0 ? "  " + u.count : "")
    })
    if (h.kind === "degraded" && i === 0) {
      node.stat = p.healthReason !== "" ? part(p.healthReason) : word("route.servfail", [], "warning")
      node.statTone = "warning"
    }
  }
  return out
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
    var items = []
    for (var m = 0; m < inactive.length; m++) items.push({
      where: inactive[m].where, detail: inactive[m].detail, uuid: inactive[m].uuid, key: inactive[m].where + ":" + inactive[m].uuid
    })
    profiles = { count: inactive.length, uuids: uuids, lines: lines, items: items, pinnable: uuids.length > 0 }
  }
  return { bypass: bypass, profiles: profiles }
}

// -------------------------------------------------------- DNS choices

// Which resolver choice is lit, and in what colour. Never lights a wrong
// row: a custom resolver lights neither, a runtime failover lights Pi-hole
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

// The resolver choices of the DNS view, a selectable list (radio rows): the
// Pi-hole and Automatic. Lit by what systemd-resolved reports, never by what
// was last asked for (see dnsTiles).
//   [{ id, lit: "on" | "warn" | "off", warn, configured, detail }]
// detail is the address a row names (the Pi-hole's); Automatic's is worded by
// the panel ("router").
function dnsChoices(v) {
  var t = dnsTiles(v)
  var p = v.pihole
  return [
    { id: "pihole", lit: t.pihole, warn: t.fallbackLabel, configured: p.configured, detail: p.configured ? p.address : "" },
    { id: "auto", lit: t.auto, warn: false, configured: true, detail: "" }
  ]
}

// A tap on a choice ("pihole" | "auto"): the verb to run, or null when that
// choice is already lit.
// `leaves` is set when the verb moves DNS off the Pi-hole (Automatic while
// the Pi-hole, or its failover, is in use): the risky direction.
function tapDns(tile, v) {
  var t = dnsTiles(v)
  if (tile === "pihole") return t.pihole === "off" ? { verb: "pihole", leaves: false } : null
  if (tile === "auto") return t.auto === "off" ? { verb: "auto", leaves: v.dns.mode === "pihole" || v.dns.mode === "fallback" } : null
  return null
}

// What a tap on a choice does:
//   none      it is already lit (or unknown): nothing
//   setup     the Pi-hole choice without a Pi-hole: run setup
//   confirm   leaving the Pi-hole: ask first, inline (two steps: the tap, then
//             "Use automatic DNS"); nothing runs yet
//   run       anything else: run the verb now (towards the Pi-hole, or from a
//             resolver that is not the Pi-hole)
function tapPlan(tile, v) {
  var t = tapDns(tile, v)
  if (!t) return { action: "none", verb: "" }
  if (tile === "pihole" && !v.pihole.configured) return { action: "setup", verb: t.verb }
  if (t.leaves) return { action: "confirm", verb: t.verb, kind: "leave" }
  return { action: "run", verb: t.verb }
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

// The Pause tile: "Pause blocking · 5 min", or "Paused · 4:32 · Resume" in the
// warning colour while paused. Disabled (and dim) when DNS is not going
// through a Pi-hole that can be told to pause: not set up, not answering, its
// API failing, the link down, or the resolver pointed somewhere else. A
// paused one can always be resumed while the Pi-hole answers.
function pauseChip(v) {
  var paused = isPaused(v)
  var p = v.pihole
  return {
    mode: paused ? "resume" : "pause",
    tone: paused ? "warning" : "dim",
    remainingS: paused ? p.pauseRemainingS : 0,
    enabled: !v.backendDown && p.configured && p.reachable && p.api === "ok" && v.link.kind !== "none" &&
      (paused || v.dns.mode === "pihole")
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
// panel joins with " · ": k "state" (key limited | portal | nointernet |
// offline | off | connected) or k "text" (band, signal, rate, "gw 120 ms").
//   - "Connected" is left out when the connection is fine and there is
//     something else to say (Wi-Fi: "5 GHz · 58%"); a wire with no rate
//     keeps it so the line is never empty.
//   - the gateway's latency appears only when it is slow (over GW_SLOW_MS)
//     or the probe fails (gatewayOk false), never as routine noise.
// urgent: the state part reads in the urgent colour.
function headerInfo(v, fmt) {
  var l = v.link
  var out = {
    kind: "offline", title: "", glyph: linkGlyph(v), status: [], urgent: false, portal: false,
    restricted: isRestricted(v)
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
  out.title = l.kind === "wifi" ? (l.ssid || l.connection) : ""
  if (l.connectivity === "portal") {
    out.urgent = true; out.portal = true
    out.status.push({ k: "state", key: "portal" })
    return out
  }
  var parts = []
  if (l.kind === "wifi") {
    if (l.band) parts.push({ k: "text", text: l.band })
    if (l.signal > 0) parts.push({ k: "text", text: formatDecimal(l.signal, 0, fmt) + "%" })
  } else {
    var rate = formatRate(l.bitrateMbps, fmt)
    if (rate !== "") parts.push({ k: "text", text: rate })
  }
  if (l.gatewayOk === false) parts.push({ k: "text", text: "gw \u2717" })
  else if (l.gatewayMs !== null && l.gatewayMs > GW_SLOW_MS) parts.push({ k: "text", text: "gw " + formatLatency(l.gatewayMs, fmt) })
  if (l.connectivity === "limited") {
    out.urgent = true
    out.status.push({ k: "state", key: "limited" })
  } else if (l.connectivity === "none") {
    out.urgent = true
    out.status.push({ k: "state", key: "nointernet" })
  } else if (parts.length === 0) {
    out.status.push({ k: "state", key: "connected" })
  }
  return { kind: out.kind, title: out.title, glyph: out.glyph, status: out.status.concat(parts), urgent: out.urgent, portal: false, restricted: out.restricted }
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

// The footer: "192.168.1.242 · gw 192.168.1.1", with stable placeholders so
// it never reflows.
function ipFooter(v) {
  var ipText = v.link.ip4 !== "" ? v.link.ip4 : "--"
  var gw = v.link.gateway !== "" ? v.link.gateway : "--"
  return { ip: v.link.ip4, gateway: v.link.gateway, text: ipText + " · gw " + gw, copyable: v.link.ip4 !== "" }
}

// ------------------------------------------------------------- networks

// The channel for a frequency in MHz, 0 when it is none: 2.4 GHz 1..14,
// 5 GHz 32..177 (5180 -> 36), 6 GHz 1..233 (5955 -> 1).
function channelOf(mhz) {
  var f = num(mhz, 0)
  if (f === 2484) return 14
  if (f >= 2412 && f <= 2472) return Math.round((f - 2407) / 5)
  if (f >= 5160 && f <= 5885) return Math.round((f - 5000) / 5)
  if (f >= 5955 && f <= 7115) return Math.round((f - 5950) / 5)
  return 0
}

// "2.4 GHz" | "5 GHz" | "6 GHz" for a frequency in MHz, "" when it is none.
function bandOfMhz(mhz) {
  var f = num(mhz, 0)
  if (f >= 2400 && f <= 2500) return "2.4 GHz"
  if (f >= 5150 && f <= 5895) return "5 GHz"
  if (f >= 5925 && f <= 7125) return "6 GHz"
  return ""
}

// The chip on a network row: "2.4G" | "5G" | "6G" from the band the backend
// names (or from the frequency when it does not), "" when neither is known.
function bandChip(band, mhz) {
  var b = String(band || "") !== "" ? String(band) : bandOfMhz(mhz)
  var m = /^(2\.4|5|6)\s*GHz$/i.exec(b)
  return m ? m[1] + "G" : ""
}

// How many of the four bars of the signal glyph are filled: 0..4.
function signalBars(signal) {
  var s = clamp(num(signal, 0), 0, 100)
  if (s <= 0) return 0
  return s >= 75 ? 4 : (s >= 50 ? 3 : (s >= 25 ? 2 : 1))
}

// The Wi-Fi view's card for the connection in use, in monospace key/value
// lines:
//   { kind, title, glyph, urgent, rows: [{ k, v, key }], canDisconnect, uuid }
//   kind   wifi | ethernet | none | off | nobackend
//   title  the SSID ("" for a wire: the panel names it)
//   rows   k link | signal | ip | gateway | dns. v is the text; key (when set)
//          is a translated word to show in v's place ("no DNS")
//   link   "5 GHz . ch 149 . 866 Mb/s"; signal "72% . -58 dBm"; ip with its
//          prefix when it is known ("192.168.1.242/24"); gateway with its
//          latency; dns the resolvers in use ("192.168.1.153")
//   canDisconnect  a Wi-Fi link can be dropped from the card
function connectionCard(v, fmt) {
  var l = v.link
  var out = { kind: "none", title: "", glyph: linkGlyph(v), urgent: isRestricted(v), rows: [], canDisconnect: false, uuid: l.uuid }
  if (v.backendDown) { out.kind = "nobackend"; out.urgent = false; return out }
  if (l.kind === "none") { out.kind = v.radio.wifiEnabled ? "none" : "off"; out.urgent = false; return out }
  out.kind = l.kind
  out.title = l.kind === "wifi" ? (l.ssid || l.connection) : ""
  out.canDisconnect = l.kind === "wifi"
  var parts = []
  if (l.kind === "wifi") {
    var band = l.band !== "" ? l.band : bandOfMhz(l.frequencyMhz)
    if (band !== "") parts.push(band)
    var ch = channelOf(l.frequencyMhz)
    if (ch > 0) parts.push("ch " + ch)
  }
  var rate = formatRate(l.bitrateMbps, fmt)
  if (rate !== "") parts.push(rate)
  if (parts.length) out.rows.push({ k: "link", v: parts.join(" \u00b7 "), key: "" })
  if (l.kind === "wifi" && l.signal > 0) {
    out.rows.push({ k: "signal", v: formatDecimal(l.signal, 0, fmt) + "%" + (l.signalDbm !== null ? " \u00b7 " + l.signalDbm + " dBm" : ""), key: "" })
  }
  if (l.ip4 !== "") out.rows.push({ k: "ip", v: l.ip4 + (l.prefix > 0 ? "/" + l.prefix : ""), key: "" })
  if (l.gateway !== "") {
    out.rows.push({ k: "gateway", v: l.gateway + (l.gatewayMs !== null ? " \u00b7 " + formatLatency(l.gatewayMs, fmt) : ""), key: "" })
  }
  var servers = []
  var sv = v.dns.servers
  var i
  for (i = 0; i < sv.length; i++) if (sv[i].current && servers.indexOf(sv[i].addr) < 0) servers.push(sv[i].addr)
  if (servers.length === 0) for (i = 0; i < sv.length; i++) if (servers.indexOf(sv[i].addr) < 0) servers.push(sv[i].addr)
  if (servers.length) out.rows.push({ k: "dns", v: servers.slice(0, 2).join(", "), key: "" })
  else if (v.dns.mode === "none") out.rows.push({ k: "dns", v: "", key: "card.noDns" })
  return out
}

// The Wi-Fi view's "Nearby" list: every visible network but the one in use
// (the card has that), strongest first, ties by name. Hidden networks (no
// SSID) are left out unless they are asked for; a duplicate SSID keeps its
// best entry (the backend groups, this is a guard).
function orderNetworks(networks, showHidden) {
  var best = {}
  var order = []
  var list = Array.isArray(networks) ? networks : []
  var i
  for (i = 0; i < list.length; i++) {
    var n = list[i]
    if (n.active) continue
    if (n.hidden && !showHidden) continue
    var key = n.hidden ? "\u0000" + n.id : n.ssid
    if (best[key] === undefined) { best[key] = n; order.push(key) }
    else if (n.signal > best[key].signal) best[key] = n
  }
  var out = []
  for (i = 0; i < order.length; i++) out.push(best[order[i]])
  out.sort(function(a, b) {
    if (a.signal !== b.signal) return b.signal - a.signal
    return a.ssid < b.ssid ? -1 : (a.ssid > b.ssid ? 1 : 0)
  })
  return out
}

// Whether a nearby network wears a lock: secured and not saved. (A saved one
// says "Saved"; an open one has nothing.)
function showLock(net) {
  return !net.known && !net.hidden && net.security !== "open" && net.security !== "owe" ? true : false
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
  if (net.hidden) return { key: "hidden", tone: "dim", text: "" }
  if (net.known) return { key: "saved", tone: "dim", text: "" }
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

// `qnet wifi scan`, or with ifStaleS `qnet wifi scan --if-stale <s>`: the
// backend scans only when the last scan is older than that (entering the
// Wi-Fi view); the scan button forces one (it is throttled there).
function argvScan(bin, ifStaleS) {
  if (!okBin(bin)) return null
  var a = [bin, "wifi", "scan"]
  if (ifStaleS !== undefined && ifStaleS !== null) {
    if (typeof ifStaleS !== "number" && !/^\d{1,6}$/.test(String(ifStaleS))) return null
    var n = Math.round(num(ifStaleS, -1))
    if (n < 0 || n > 86400) return null
    a.push("--if-stale", String(n))
  }
  return a
}

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
      verifiedVia: addr(obj.verifiedVia), blocked: obj.blocked === true, verifyError: clean(obj.verifyError, 80),
      retryInS: Math.max(0, Math.min(3600, toInt(obj.retryInS, 0)))
    }
  }
  return {
    ok: false, error: exitCode === 0 || exitCode === undefined ? "noanswer" : "exit", detail: null,
    verifiedVia: "", blocked: false, verifyError: "", retryInS: 0
  }
}

// A failed result as { code, text, retryInS }: code is a message key
// (confirm and enterprise are handled by the panel before this), text a
// cleaned backend message to show when the code is "generic". "too-soon"
// carries retryInS; "busy" is another action in flight; "skipped" is the
// backend deciding there was nothing to do, which is not an error.
function failure(result) {
  var e = String(result && result.error || "").toLowerCase()
  var retry = result && result.retryInS ? result.retryInS : 0
  if (e === "confirm" || e === "enterprise") return { code: e, text: "", retryInS: 0 }
  if (e === "wrongpassword" || e === "wrong-password" || e === "auth" || e === "secrets" || e === "badpassword")
    return { code: "wrongPassword", text: "", retryInS: 0 }
  if (e === "noanswer" || e === "exit" || e === "") return { code: "noAnswer", text: "", retryInS: 0 }
  if (e === "timeout") return { code: "timeout", text: "", retryInS: 0 }
  if (e === "toosoon" || e === "too-soon" || e === "ratelimit") return { code: "tooSoon", text: "", retryInS: retry }
  if (e === "busy") return { code: "busy", text: "", retryInS: 0 }
  if (e === "skipped") return { code: "skipped", text: "", retryInS: 0 }
  return { code: "generic", text: clean(e, 60), retryInS: 0 }
}

// After `qnet dns pihole` succeeded: "" when its canary came back blocked,
// else the reason it did not (verifyError), to show as a warning. Nothing for
// other verbs, or when the backend says neither.
function verifyNote(verb, result) {
  if (verb !== "pihole" || !result || !result.ok || result.blocked === true) return ""
  return result.verifyError
}

// ------------------------------------------------------------ ages

// Seconds as { unit, n }: "now" under a minute, then minutes, then hours.
function ageParts(sec) {
  var s = num(sec, -1)
  if (s < 0) return null
  if (s < 60) return { unit: "now", n: 0 }
  if (s < 3600) return { unit: "min", n: Math.floor(s / 60) }
  return { unit: "hour", n: Math.floor(s / 3600) }
}

// The DNS view's failover line: { state, fallback, reason, sinceS }
//   off     failover is not enabled
//   armed   enabled, not engaged
//   active  DNS is on the fallback right now
// fallback is the one in effect (the backend names the effective fallback);
// reason is the backend's own words, shown as they are.
function failoverInfo(v) {
  var f = v.dns.failover
  return {
    state: f.active ? "active" : (f.enabled ? "armed" : "off"),
    fallback: f.fallback, reason: f.reason, sinceS: f.since
  }
}

// ----------------------------------------------------------- the views

// Which view is up: the main one, or a drill-down the main one pushed (DNS,
// Wi-Fi) from a node of the route. returnCursor is where the cursor was on
// the main view, put back when the drill-down is left.
function navInit() { return { view: "main", returnCursor: null } }

// Open a drill-down. effects says what entering it does: the Wi-Fi view runs
// `qnet wifi scan --if-stale 60` (never on opening the panel itself).
function navOpen(nav, name, cursor) {
  if ((name !== "dns" && name !== "wifi") || nav.view === name) return { nav: nav, effects: [] }
  var ret = nav.view === "main" ? (cursor || null) : nav.returnCursor
  return {
    nav: { view: name, returnCursor: ret },
    effects: name === "wifi" ? [{ run: "scan", ifStaleS: SCAN_IF_STALE_S }] : []
  }
}

// Back to the main view; cursor is the stop to put the cursor on (null when
// already there).
function navBack(nav) {
  if (nav.view === "main") return { nav: nav, cursor: null, left: false }
  return { nav: navInit(), cursor: nav.returnCursor, left: true }
}

// What Esc does, one level at a time: an armed Forget, the DNS confirm, the
// passphrase row, a drill-down (back), then the panel (close).
function escapeStep(ctx) {
  var c = ctx || {}
  if (c.armed) return "disarm"
  if (c.confirm) return "confirm"
  if (c.password) return "password"
  if (c.view && c.view !== "main") return "back"
  return "close"
}

// ------------------------------------------------------------ keyboard

// The focusable rows in order, top to bottom, each with the items that
// left/right walk, for the view that is up. ctx: { view, confirm }.
//   main     header: portal?, qr?, speed?, radio
//            hero: the one corrective action, when the state has one
//            route: the nodes that open a view, left to right (ap -> Wi-Fi,
//            ph -> DNS)
//            pause: the Pause tile
//            ip: the footer
//   dns      back, choice:pihole, choice:auto (the resolver choices),
//            confirm? (replace, cancel), bypass? (fix), leak:N (pin) one per
//            profile, pinall? (two or more), admin?
//   wifi     back, card? (disconnect), scan, net:N one per nearby network
function focusRows(v, ctx, pending, nets) {
  var c = ctx || {}
  var rows = []
  if (c.view === "dns") {
    rows.push({ id: "back", items: ["back"] })
    rows.push({ id: "choice:pihole", items: ["pick"] })
    rows.push({ id: "choice:auto", items: ["pick"] })
    if (c.confirm) rows.push({ id: "confirm", items: ["replace", "cancel"] })
    var g = leakGroups(v, pending)
    if (g.bypass) rows.push({ id: "bypass", items: ["fix"] })
    if (g.profiles) {
      for (var k = 0; k < g.profiles.items.length; k++) if (g.profiles.items[k].uuid !== "") rows.push({ id: "leak:" + k, items: ["pin"] })
      if (g.profiles.uuids.length > 1) rows.push({ id: "pinall", items: ["pinall"] })
    }
    if (v.pihole.configured && v.pihole.adminUrl !== "") rows.push({ id: "admin", items: ["admin"] })
    return rows
  }
  if (c.view === "wifi") {
    rows.push({ id: "back", items: ["back"] })
    if (connectionCard(v).canDisconnect) rows.push({ id: "card", items: ["disconnect"] })
    rows.push({ id: "scan", items: ["scan"] })
    var list = nets || orderNetworks(v.networks)
    for (var n = 0; n < list.length; n++) rows.push({ id: "net:" + n, items: ["row"] })
    return rows
  }
  var items = []
  if (v.link.kind !== "none" && v.link.connectivity === "portal") items.push("portal")
  if (canShareWifi(v)) items.push("qr")
  if (v.link.device !== "" && v.link.kind !== "none") items.push("speed")
  items.push("radio")
  rows.push({ id: "header", items: items })
  if (heroState(v).action !== "") rows.push({ id: "hero", items: ["action"] })
  var stops = routeStops(v)
  if (stops.length) rows.push({ id: "route", items: stops })
  rows.push({ id: "pause", items: ["pause"] })
  rows.push({ id: "ip", items: ["ip"] })
  return rows
}

function rowIndex(rows, id) {
  for (var i = 0; i < rows.length; i++) if (rows[i].id === id) return i
  return -1
}

// Where the cursor starts: on the route of the main view (the first node
// only opens the Wi-Fi view), the way back on the DNS view (never on a
// resolver choice: a stray Enter or Space as the view opens must not change
// DNS) and the scan button on the Wi-Fi view (never on a network, the card's
// Disconnect or anything else that changes the connection).
function initialCursor(rows, view) {
  var order = view === "dns" ? ["back"] : (view === "wifi" ? ["scan", "back"] : ["route", "pause", "header"])
  for (var i = 0; i < order.length; i++) {
    var at = rowIndex(rows, order[i])
    if (at >= 0) return { row: rows[at].id, item: 0 }
  }
  return { row: rows[0].id, item: 0 }
}

// One key. cursor { row, item }; memory { rowId: itemIndex } remembers where
// each row's cursor last was, so down-and-up comes back to the same tile.
// Up/down stop at the ends; left/right stop at a row's ends.
function moveFocus(rows, cursor, dx, dy, memory) {
  var mem = {}
  var mk = Object.keys(memory || {})
  for (var m = 0; m < mk.length; m++) mem[mk[m]] = memory[mk[m]]
  var at = rowIndex(rows, cursor.row)
  if (at < 0) return { cursor: initialCursor(rows, null), memory: mem }
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
    HISTORY_SPAN_S: HISTORY_SPAN_S, HISTORY_BUCKET_S: HISTORY_BUCKET_S, MAX_UPSTREAMS: MAX_UPSTREAMS,
    STABLE_UPTIME_MS: STABLE_UPTIME_MS, PAUSE_SECONDS: PAUSE_SECONDS, SCAN_IF_STALE_S: SCAN_IF_STALE_S,
    FAILOVER_AFTER_S: FAILOVER_AFTER_S, ACTION_DEADLINE_MS: ACTION_DEADLINE_MS, GW_SLOW_MS: GW_SLOW_MS,
    LATENCY_BAD_MS: LATENCY_BAD_MS, PENDING_TTL_MS: PENDING_TTL_MS, SCAN_SPIN_MS: SCAN_SPIN_MS, GLYPH: GLYPH,
    clean: clean, safeUrl: safeUrl, emptyState: emptyState, normalizeState: normalizeState,
    parseStateLine: parseStateLine, backoffMs: backoffMs, restartAttempt: restartAttempt,
    formatCountdown: formatCountdown, groupDigits: groupDigits, formatCount: formatCount,
    formatPercent: formatPercent, formatLatency: formatLatency, formatRate: formatRate,
    pauseRemaining: pauseRemaining, effective: effective, reconcilePending: reconcilePending,
    emptyPending: emptyPending, hasPending: hasPending, withPending: withPending,
    currentServer: currentServer, heroState: heroState, blockingWord: blockingWord,
    failoverIn: failoverIn, extraResolver: extraResolver, needsClock: needsClock,
    ageParts: ageParts, failoverInfo: failoverInfo,
    navInit: navInit, navOpen: navOpen, navBack: navBack, escapeStep: escapeStep,
    queryDensity: queryDensity, blockedShare: blockedShare, lastOctet: lastOctet, answeredShares: answeredShares,
    routeModel: routeModel, routeStops: routeStops, routeTarget: routeTarget, chainModel: chainModel,
    piholeLook: piholeLook, leakCount: leakCount, leakGroups: leakGroups, dnsTiles: dnsTiles, dnsChoices: dnsChoices, tapPlan: tapPlan,
    customServers: customServers, tapDns: tapDns, confirmServers: confirmServers, pauseChip: pauseChip,
    wifiGlyph: wifiGlyph, isRestricted: isRestricted, linkGlyph: linkGlyph, headerInfo: headerInfo,
    barTip: barTip, barActive: barActive, canShareWifi: canShareWifi, ipFooter: ipFooter,
    orderNetworks: orderNetworks, showLock: showLock, channelOf: channelOf, bandOfMhz: bandOfMhz, bandChip: bandChip,
    signalBars: signalBars, connectionCard: connectionCard, connectPlan: connectPlan, rowCaption: rowCaption,
    argvDns: argvDns, argvPin: argvPin, argvPause: argvPause, argvResume: argvResume,
    argvConnect: argvConnect, argvDown: argvDown, argvForget: argvForget, argvScan: argvScan,
    argvRadio: argvRadio, argvPortal: argvPortal, argvTerminal: argvTerminal, argvOpenUrl: argvOpenUrl,
    argvCopy: argvCopy, parseResult: parseResult, failure: failure, verifyNote: verifyNote,
    focusRows: focusRows, rowIndex: rowIndex, initialCursor: initialCursor, moveFocus: moveFocus,
    settleCursor: settleCursor, freshGate: freshGate
  }
}

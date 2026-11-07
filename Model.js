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
var PROBE_WINDOW_S = 300       // the live edge shows the last five minutes
var PAUSE_SECONDS = 300
var DEFAULT_PIHOLE_ADDR = "192.168.1.153"
var LATENCY_BAD_MS = 100
var PENDING_TTL_MS = 12000     // an unconfirmed request is given up after this
var SCAN_SPIN_MS = 4000
var LEAKS_SHOWN = 3

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
  s = s.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩‎‏]/g, "")
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
  return {
    seq: toInt(r.seq, -1),
    link: {
      kind: oneOf(l.kind, ["wifi", "ethernet", "none"], "none"),
      device: clean(l.device, 32), connection: clean(l.connection, 64),
      uuid: UUID_RE.test(String(l.uuid || "")) ? String(l.uuid) : "",
      ssid: clean(l.ssid, 64), signal: clamp(toInt(l.signal, 0), 0, 100), band: clean(l.band, 12),
      bitrateMbps: Math.max(0, toInt(l.bitrateMbps, 0)), ip4: ip(l.ip4), gateway: ip(l.gateway),
      connectivity: oneOf(l.connectivity, ["full", "limited", "portal", "none", "unknown"], "unknown"),
      portalUrl: safeUrl(l.portalUrl)
    },
    radio: { wifiEnabled: toBool(rad.wifiEnabled, true), hwEnabled: toBool(rad.hwEnabled, true) },
    networks: networks,
    scan: { running: sc.running === true, lastScanAgeS: num(sc.lastScanAgeS, -1) },
    dns: {
      mode: oneOf(d.mode, ["pihole", "fallback", "auto", "custom"], "auto"),
      modeSource: oneOf(d.modeSource, ["profile", "runtime-failover"], "profile"),
      servers: servers, leaks: leaks,
      failover: {
        enabled: f.enabled === true, fallback: oneOf(f.fallback, ["router", "quad9", "cloudflare"], "router"),
        active: f.active === true, since: Math.max(0, num(f.since, 0)), reason: clean(f.reason, 80)
      },
      manualOverride: d.manualOverride === true
    },
    pihole: {
      configured: p.configured === true, address: addr(p.address), adminUrl: safeUrl(p.adminUrl),
      reachable: p.reachable === true, latencyMs: isFinite(pms) && pms >= 0 ? pms : null,
      blocking: oneOf(p.blocking, ["enabled", "disabled", "unknown"], "unknown"),
      pauseRemainingS: Math.max(0, toInt(p.pauseRemainingS, 0)),
      api: oneOf(p.api, ["ok", "auth", "tls", "unreachable", "unconfigured"], "unconfigured"),
      today: {
        total: Math.max(0, toInt(t.total, 0)), blocked: Math.max(0, toInt(t.blocked, 0)),
        percent: clamp(num(t.percent, 0), 0, 100)
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
//   { kind: "other" }              valid JSON of another type (a heartbeat)
//   { kind: "bad" }                not JSON, too long, or no usable seq
function parseStateLine(line, lastSeq) {
  var text = line === null || line === undefined ? "" : String(line)
  if (text.length > MAX_LINE) return { kind: "bad" }
  text = text.trim()
  if (text === "") return { kind: "bad" }
  var obj
  try { obj = JSON.parse(text) } catch (e) { return { kind: "bad" } }
  if (!isObj(obj)) return { kind: "bad" }
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
    v.dns = Object.assign({}, state.dns, { mode: mode, modeSource: "profile" })
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
    if (active || expired) drop("connectId")
  }
  if (p.disconnecting && (state.link.kind === "none" || expired)) drop("disconnecting")
  if (p.forgetUuid) {
    var present = false
    for (i = 0; i < state.networks.length; i++) if (state.networks[i].known && state.networks[i].uuid === p.forgetUuid) present = true
    if (!present || expired) drop("forgetUuid")
  }
  if (p.pinUuid) {
    var leaking = false
    for (i = 0; i < state.dns.leaks.length; i++) if (state.dns.leaks[i].uuid === p.pinUuid) leaking = true
    if (!leaking || expired) drop("pinUuid")
  }
  if (num(p.scanUntilMs, 0) > 0 && p.scanUntilMs <= nowMs) drop("scanUntilMs")
  return changed ? out : p
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

// A leak on the link in use: DNS servers of that link (or its IPv6 router
// advertisements) other than the Pi-hole, so queries may skip it. A leak on
// another profile only "would" bypass it and shows as a line, not in the hero.
function activeLinkLeak(v) {
  var ls = v.dns.leaks
  for (var i = 0; i < ls.length; i++) {
    if (ls[i].kind === "profile") continue
    if (ls[i].where !== "" && (ls[i].where === v.link.device || ls[i].where === v.link.connection)) return true
  }
  return false
}

// What the hero says. kind picks the state word (Panel maps it to a
// translated string), tone its colour, `frozen` greys the graph.
//
//   pihole       accent   queries are answered by the Pi-hole and it blocks
//   paused       dim      the Pi-hole answers but blocking is off (countdown)
//   fallback     warning  a runtime failover moved DNS off the Pi-hole
//   bypassed     urgent   the profile says Pi-hole, but the resolver uses another
//                         server, or the link in use also has a non-Pi-hole one
//   unreachable  urgent   the Pi-hole does not answer and nothing took over
//   router       dim      automatic (the router's DNS)
//   custom       dim      someone else's DNS servers
//   offline      dim      no link
//   nobackend    urgent   `qnet watch` is not running
//
// setup: no Pi-hole is configured, so the hero offers "Set up Pi-hole".
// empty: nothing to draw (no config). frozen: unreachable or the API fails,
// so the graph is old.
function heroState(v) {
  var p = v.pihole
  var d = v.dns
  var cur = currentServer(v)
  var apiBad = p.api !== "ok"
  if (v.backendDown) {
    return {
      kind: "nobackend", tone: "urgent", frozen: true, setup: false, empty: true, via: "", latencyMs: null,
      latencyBad: false, apiIssue: "", fallback: "", pauseS: 0, noAnswer: false, sinceS: 0
    }
  }
  var out = {
    kind: "router", tone: "dim", frozen: false, setup: !p.configured, empty: !p.configured,
    via: cur ? cur.addr : "", latencyMs: null, latencyBad: false, apiIssue: "",
    fallback: "", pauseS: 0, noAnswer: false, sinceS: 0
  }
  if (!p.configured) {
    if (v.link.kind === "none") out.kind = "offline"
    else if (d.mode === "custom") out.kind = "custom"
    else if (d.mode === "pihole") { out.kind = "pihole"; out.tone = "accent" }
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
    if (isPaused(v)) {
      out.kind = "paused"; out.tone = "dim"; out.pauseS = p.pauseRemainingS
      return out
    }
    if ((cur && cur.role !== "pihole") || activeLinkLeak(v)) {
      out.kind = "bypassed"; out.tone = "urgent"
      return out
    }
    out.kind = "pihole"; out.tone = "accent"
    return out
  }
  out.kind = d.mode === "custom" ? "custom" : "router"
  out.tone = "dim"
  out.latencyMs = null; out.latencyBad = false
  out.via = cur ? cur.addr : ""
  return out
}

// ------------------------------------------------------------- the graph

// The 24 h history as `n` columns of 10 minutes ending at nowS, scaled to
// 0..1 against the busiest column (plus headroom), lightly smoothed. Missing
// buckets are empty columns. { total, blocked, peak, n } or null without data.
function historySeries(history, nowS, n) {
  var h = Array.isArray(history) ? history : []
  var cols = Math.max(2, toInt(n, MAX_HISTORY))
  if (h.length === 0) return null
  var colS = HISTORY_SPAN_S / cols
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
  function smooth(a) {
    var out = []
    for (var k = 0; k < a.length; k++) {
      var l = a[k > 0 ? k - 1 : 0], r = a[k < a.length - 1 ? k + 1 : a.length - 1]
      out.push((l + 2 * a[k] + r) / 4)
    }
    return out
  }
  var st = smooth(smooth(total))
  var sb = smooth(smooth(blocked))
  var peak = 0
  for (i = 0; i < st.length; i++) if (st[i] > peak) peak = st[i]
  if (peak <= 0) return { total: st, blocked: sb, peak: 0, n: cols }
  var top = peak * 1.12
  var t = [], b = []
  for (i = 0; i < st.length; i++) {
    t.push(st[i] / top)
    b.push(Math.min(sb[i], st[i]) / top)
  }
  return { total: t, blocked: b, peak: peak, n: cols }
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

// The live edge: the last five minutes of probes as runs of {x, v} (x 0..1
// from five minutes ago to nowS, v 0..1 latency against a floor of 25 ms). A
// failed probe ends the run, which draws as a gap. head is the newest probe.
function pulseRuns(probes, nowS) {
  var list = Array.isArray(probes) ? probes : []
  var runs = []
  var run = null
  var maxMs = 25
  var i
  for (i = 0; i < list.length; i++) if (list[i].ok && list[i].ms !== null && list[i].ms > maxMs) maxMs = list[i].ms
  maxMs *= 1.15
  var head = null
  for (i = 0; i < list.length; i++) {
    var x = 1 - (nowS - list[i].t) / PROBE_WINDOW_S
    if (x < 0 || x > 1.0001) continue
    if (!list[i].ok || list[i].ms === null) { run = null; head = { x: clamp(x, 0, 1), v: 0, ok: false }; continue }
    var pt = { x: clamp(x, 0, 1), v: clamp(list[i].ms / maxMs, 0, 1) }
    if (!run) { run = []; runs.push(run) }
    run.push(pt)
    head = { x: pt.x, v: pt.v, ok: true }
  }
  for (i = runs.length - 1; i >= 0; i--) if (runs[i].length < 2) runs.splice(i, 1)
  return { runs: runs, head: head }
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

// One urgent line per leak, with its fix. action: null when there is none
// that is safe to offer (an unknown profile).
//   kind profile   "<where> would bypass Pi-hole"   Pin  (qnet dns pin <uuid>)
//   kind link      "<where> bypasses Pi-hole"       Fix  (qnet dns pihole, the active profile)
//   kind ipv6-ra   "<where> bypasses Pi-hole"       Fix
// pending.pinUuid hides the leak just pinned.
function leakLines(v, pending) {
  var out = []
  var pinned = pending && pending.pinUuid ? pending.pinUuid : ""
  var ls = v.dns.leaks
  for (var i = 0; i < ls.length; i++) {
    var lk = ls[i]
    if (pinned !== "" && lk.uuid === pinned) continue
    var activeProfile = lk.uuid !== "" && lk.uuid === v.link.uuid
    var action = null
    if (lk.kind === "profile" && lk.uuid !== "" && !activeProfile) action = { verb: "pin", uuid: lk.uuid }
    else if (lk.kind === "profile" && activeProfile) action = { verb: "pihole", uuid: "" }
    else if ((lk.kind === "link" || lk.kind === "ipv6-ra") && (lk.uuid === "" || activeProfile)) action = { verb: "pihole", uuid: "" }
    else if (lk.uuid !== "") action = { verb: "pin", uuid: lk.uuid }
    out.push({
      key: lk.kind + ":" + lk.where + ":" + lk.uuid, kind: lk.kind, where: lk.where || "?",
      would: lk.kind === "profile", detail: lk.detail, action: action
    })
  }
  return out
}

// ------------------------------------------------------------- DNS row

// Which segmented tile is lit, and in what colour. Never lights a wrong
// tile: a custom resolver lights neither, and a runtime failover lights
// Pi-hole in the warning colour with its own label.
//   pihole: "on" | "warn" | "off"; auto: "on" | "off"
//   caption: "Custom: <servers>" data, or null
function dnsTiles(v) {
  // Without the backend nothing is known, so nothing is lit.
  if (v.backendDown) return { live: "unknown", pihole: "off", fallbackLabel: false, auto: "off", custom: null }
  var mode = v.dns.mode
  var out = {
    live: mode,
    pihole: mode === "pihole" ? "on" : (mode === "fallback" ? "warn" : "off"),
    fallbackLabel: mode === "fallback",
    auto: mode === "auto" ? "on" : "off",
    custom: mode === "custom" ? customServers(v) : null
  }
  return out
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
// nointernet | offline | off) or k "text" (band, signal, rate). urgent: the
// state part reads in the urgent colour.
function headerInfo(v, fmt) {
  var l = v.link
  var out = { kind: "offline", title: "", glyph: linkGlyph(v), status: [], urgent: false, portal: false, restricted: isRestricted(v) }
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

// The IP footer, with stable placeholders so it never reflows.
function ipFooter(v) {
  var ipText = v.link.ip4 !== "" ? v.link.ip4 : "--"
  var gw = v.link.gateway !== "" ? v.link.gateway : "--"
  return { ip: v.link.ip4, gateway: v.link.gateway, text: ipText + " · gw " + gw, copyable: v.link.ip4 !== "" }
}

// ------------------------------------------------------------- networks

// The list: the active network first, then known, then the rest; strongest
// first within each group, ties by name. Hidden networks (no SSID) are left
// out unless one is the active network; a duplicate SSID keeps its best
// entry (the backend groups, this is a guard).
function orderNetworks(networks, showHidden) {
  var best = {}
  var order = []
  var list = Array.isArray(networks) ? networks : []
  var i
  for (i = 0; i < list.length; i++) {
    var n = list[i]
    if (n.hidden && !n.active && !showHidden) continue
    var key = n.hidden ? "\u0000" + n.id : n.ssid
    if (best[key] === undefined) { best[key] = n; order.push(key) }
    else {
      var b = best[key]
      if ((n.active && !b.active) || (n.active === b.active && n.signal > b.signal)) best[key] = n
    }
  }
  var out = []
  for (i = 0; i < order.length; i++) out.push(best[order[i]])
  function rank(n) { return n.active ? 0 : (n.known ? 1 : 2) }
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

function argvPin(bin, uuid) {
  if (!okBin(bin) || !UUID_RE.test(String(uuid || ""))) return null
  return [bin, "dns", "pin", String(uuid)]
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
// (a path with a space, a quote) makes the whole command null.
function argvTerminal(kind, bin, address) {
  var plain = /^[A-Za-z0-9_.\/:@%+=,\-]+$/
  var cmd
  if (kind === "nmtui") cmd = ["nmtui"]
  else if (kind === "setup") {
    var a = addr(address) !== "" ? addr(address) : DEFAULT_PIHOLE_ADDR
    cmd = [okBin(bin) && plain.test(bin) ? bin : "qnet", "pihole", "setup", a]
  } else return null
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
// { ok, error, detail, verifiedVia }. Anything unreadable is a failure
// with error "noanswer".
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
      verifiedVia: addr(obj.verifiedVia)
    }
  }
  return { ok: false, error: exitCode === 0 || exitCode === undefined ? "noanswer" : "exit", detail: null, verifiedVia: "" }
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

// After a DNS verb: the server that answered the verification query is not
// the Pi-hole, though that is what was asked for.
function verifyMismatch(verb, result, v) {
  if (verb !== "pihole" || !result || !result.verifiedVia || !v.pihole.address) return ""
  return result.verifiedVia === v.pihole.address ? "" : result.verifiedVia
}

// ------------------------------------------------------------ keyboard

// The focusable rows in order, top to bottom, each with the items that
// left/right walk. ctx: { confirm, password } -- an inline confirm line adds
// its two buttons as a row above the DNS row.
//   header   portal?, qr?, speed?, radio
//   setup    the hero's "Set up Pi-hole" link (unconfigured only)
//   leak:N   one row per leak with a fix action
//   confirm  replace, cancel
//   dns      tile:pihole, tile:auto, pause?, admin?
//   scan     the Networks label's scan action
//   net:N    one row per listed network
//   ip       the footer
function focusRows(v, ctx, pending, nets) {
  var c = ctx || {}
  var rows = []
  var items = []
  if (v.link.kind !== "none" && v.link.connectivity === "portal") items.push("portal")
  if (canShareWifi(v)) items.push("qr")
  if (v.link.device !== "" && v.link.kind !== "none") items.push("speed")
  items.push("radio")
  rows.push({ id: "header", items: items })
  if (!v.pihole.configured) rows.push({ id: "setup", items: ["setup"] })
  var leaks = leakLines(v, pending).slice(0, LEAKS_SHOWN)
  for (var i = 0; i < leaks.length; i++) if (leaks[i].action) rows.push({ id: "leak:" + i, items: ["fix"] })
  if (c.confirm) rows.push({ id: "confirm", items: ["replace", "cancel"] })
  var dns = ["tile:pihole", "tile:auto"]
  if (v.pihole.configured) dns.push("pause")
  if (v.pihole.configured && v.pihole.adminUrl !== "") dns.push("admin")
  rows.push({ id: "dns", items: dns })
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
    HISTORY_SPAN_S: HISTORY_SPAN_S, PROBE_WINDOW_S: PROBE_WINDOW_S, PAUSE_SECONDS: PAUSE_SECONDS,
    DEFAULT_PIHOLE_ADDR: DEFAULT_PIHOLE_ADDR, LATENCY_BAD_MS: LATENCY_BAD_MS, PENDING_TTL_MS: PENDING_TTL_MS,
    SCAN_SPIN_MS: SCAN_SPIN_MS, LEAKS_SHOWN: LEAKS_SHOWN, GLYPH: GLYPH,
    clean: clean, safeUrl: safeUrl, emptyState: emptyState, normalizeState: normalizeState,
    parseStateLine: parseStateLine, backoffMs: backoffMs,
    formatCountdown: formatCountdown, groupDigits: groupDigits, formatCount: formatCount,
    formatPercent: formatPercent, formatLatency: formatLatency, formatRate: formatRate,
    pauseRemaining: pauseRemaining, effective: effective, reconcilePending: reconcilePending,
    emptyPending: emptyPending, hasPending: hasPending, withPending: withPending, activeLinkLeak: activeLinkLeak, currentServer: currentServer, heroState: heroState,
    historySeries: historySeries, edgePoints: edgePoints, pulseRuns: pulseRuns,
    seriesSignature: seriesSignature, leakLines: leakLines, dnsTiles: dnsTiles,
    customServers: customServers, tapDns: tapDns, confirmServers: confirmServers, pauseChip: pauseChip,
    wifiGlyph: wifiGlyph, isRestricted: isRestricted, linkGlyph: linkGlyph, headerInfo: headerInfo,
    barTip: barTip, barActive: barActive, canShareWifi: canShareWifi, ipFooter: ipFooter,
    orderNetworks: orderNetworks, connectPlan: connectPlan, rowCaption: rowCaption,
    argvDns: argvDns, argvPin: argvPin, argvPause: argvPause, argvResume: argvResume,
    argvConnect: argvConnect, argvDown: argvDown, argvForget: argvForget, argvScan: argvScan,
    argvRadio: argvRadio, argvPortal: argvPortal, argvTerminal: argvTerminal, argvOpenUrl: argvOpenUrl,
    argvCopy: argvCopy, parseResult: parseResult, failure: failure, verifyMismatch: verifyMismatch,
    focusRows: focusRows, rowIndex: rowIndex, initialCursor: initialCursor, moveFocus: moveFocus,
    settleCursor: settleCursor, freshGate: freshGate
  }
}

"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, raw, state, NOW_S } = require("./helpers.js")

const FIXTURES = ["healthy", "paused", "fallback", "unreachable", "unconfigured", "leaks", "bypassed",
  "portal", "offline", "radio-off", "custom", "api-auth", "ethernet", "markup", "partial", "ethernet-bypassed",
  "degraded", "not-blocking", "none", "unknown"]

test("every fixture normalises and keeps SPEC's shape", () => {
  for (const name of FIXTURES) {
    const s = state(name)
    assert.ok(["wifi", "ethernet", "none"].includes(s.link.kind), name)
    assert.ok(["pihole", "fallback", "auto", "custom", "none", "unknown"].includes(s.dns.mode), name)
    assert.ok(Array.isArray(s.networks) && s.networks.length <= Model.MAX_NETWORKS, name)
    assert.ok(s.pihole.history.length <= Model.MAX_HISTORY, name)
    assert.ok(s.pihole.probes.length <= Model.MAX_PROBES, name)
    assert.equal(typeof s.pihole.today.total, "number", name)
  }
})

test("normalising twice changes nothing", () => {
  for (const name of FIXTURES) {
    const once = state(name)
    assert.deepEqual(Model.normalizeState(once), once, name)
  }
})

test("garbage in, a usable empty state out", () => {
  for (const bad of [null, undefined, 7, "x", [], { link: 5, dns: [], pihole: "no", networks: "no" }]) {
    const s = Model.normalizeState(bad)
    assert.equal(s.link.kind, "none")
    assert.equal(s.dns.mode, "unknown", "nothing is known, so nothing is claimed")
    assert.equal(s.dns.bypassed, false)
    assert.deepEqual(s.networks, [])
    assert.equal(s.pihole.configured, false)
    assert.equal(s.pihole.api, "unconfigured")
    assert.equal(s.pihole.health, "unknown")
    assert.equal(s.pihole.canaryBlocked, null)
    assert.equal(s.link.gatewayMs, null)
  }
})

test("collections are capped", () => {
  const r = raw("healthy")
  r.networks = []
  for (let i = 0; i < 100; i++) r.networks.push({ id: "/org/freedesktop/NetworkManager/AccessPoint/" + i, ssid: "n" + i, signal: 50, security: "psk" })
  r.pihole.history = []
  for (let i = 0; i < 500; i++) r.pihole.history.push({ t: i, total: 5, blocked: 1 })
  r.pihole.probes = []
  for (let i = 0; i < 500; i++) r.pihole.probes.push({ t: i, ok: true, ms: 3 })
  r.dns.servers = []
  for (let i = 0; i < 50; i++) r.dns.servers.push({ addr: "10.0.0." + i, current: false, role: "other" })
  r.dns.leaks = []
  for (let i = 0; i < 50; i++) r.dns.leaks.push({ kind: "link", where: "x" + i })
  const s = Model.normalizeState(r)
  assert.equal(s.networks.length, 40)
  assert.equal(s.pihole.history.length, 144)
  assert.equal(s.pihole.history[143].t, 499, "the newest buckets are kept")
  assert.equal(s.pihole.probes.length, 60)
  assert.equal(s.dns.servers.length, 8)
  assert.equal(s.dns.leaks.length, 8)
})

test("strings are bounded and stripped of control characters; markup stays literal", () => {
  const s = state("markup")
  assert.equal(s.link.ssid, '<img src="https://example.invalid/tracker">', "markup is data, not removed")
  const evil = s.networks.find((n) => n.ssid.startsWith("Evil"))
  assert.equal(evil.ssid, "EvilNet<b>x</b>", "BEL and the bidi override are gone")
  assert.equal(s.dns.leaks[0].where, '<a href="http://example.invalid">Wired</a>')
  assert.ok(Model.clean("x".repeat(500), 60).length === 60)
  assert.equal(Model.clean("a\u0000b\u001fc\u007fd\u0085e‮f⁦g"), "abcdefg")
})

test("invalid ids, addresses and urls are dropped", () => {
  const r = raw("healthy")
  r.networks.push({ id: "javascript:alert(1)", ssid: "bad", signal: 10, security: "psk" })
  r.pihole.adminUrl = "javascript:alert(1)"
  r.link.ip4 = "1.2.3.4; rm -rf /"
  r.dns.servers.push({ addr: "$(reboot)", current: false, role: "other" })
  const s = Model.normalizeState(r)
  assert.equal(s.networks.find((n) => n.ssid === "bad"), undefined)
  assert.equal(s.pihole.adminUrl, "")
  assert.equal(s.link.ip4, "")
  assert.equal(s.dns.servers.length, 1)
  assert.equal(Model.safeUrl("https://192.168.1.153/admin/"), "https://192.168.1.153/admin/")
  assert.equal(Model.safeUrl("https://user:pw@host/"), "")
  assert.equal(Model.safeUrl("https://host/a?b=c"), "")
  assert.equal(Model.safeUrl("file:///etc/passwd"), "")
})

test("probes: a failed one keeps no latency; blocked share is capped at total", () => {
  const r = raw("healthy")
  r.pihole.probes = [{ t: 1, ok: false, ms: 5 }, { t: 2, ok: true, ms: -3 }]
  r.pihole.history = [{ t: 1, total: 4, blocked: 9 }]
  const s = Model.normalizeState(r)
  assert.equal(s.pihole.probes[0].ms, null)
  assert.equal(s.pihole.probes[1].ms, null)
  assert.equal(s.pihole.history[0].blocked, 4)
})

// ---- the watch stream -------------------------------------------------

test("a snapshot line newer than the last applied one is a state", () => {
  const line = JSON.stringify(raw("healthy"))
  const r = Model.parseStateLine(line, 41)
  assert.equal(r.kind, "state")
  assert.equal(r.seq, 42)
  assert.equal(r.state.link.ssid, "Redwood")
})

test("a line whose seq is not newer is ignored", () => {
  const line = JSON.stringify(raw("healthy"))
  assert.equal(Model.parseStateLine(line, 42).kind, "stale")
  assert.equal(Model.parseStateLine(line, 99).kind, "stale")
})

test("a fresh child starts again at -1, so its seq 1 is applied", () => {
  const r = raw("healthy")
  r.seq = 1
  assert.equal(Model.parseStateLine(JSON.stringify(r), -1).kind, "state")
  assert.equal(Model.parseStateLine(JSON.stringify(r), 42).kind, "stale", "the old child's counter must be reset by the caller")
})

test("seq 0 is a valid first snapshot", () => {
  const r = raw("healthy")
  r.seq = 0
  assert.equal(Model.parseStateLine(JSON.stringify(r), -1).kind, "state")
})

test("the heartbeat is an hb line: proof of life, never applied", () => {
  assert.equal(Model.parseStateLine('{"type":"hb","seq":500}', 1).kind, "hb")
  assert.equal(Model.parseStateLine('{"type":"hb","seq":0}', 99).kind, "hb", "not subject to the seq check")
  assert.equal(Model.parseStateLine('{"type":"hb"}', -1).kind, "hb")
})

test("heartbeats and other types are not states; junk is bad", () => {
  assert.equal(Model.parseStateLine('{"type":"heartbeat","seq":500}', 1).kind, "other")
  assert.equal(Model.parseStateLine("not json", 1).kind, "bad")
  assert.equal(Model.parseStateLine("", 1).kind, "bad")
  assert.equal(Model.parseStateLine("[1,2]", 1).kind, "bad")
  assert.equal(Model.parseStateLine('{"type":"state"}', 1).kind, "bad", "no seq")
  assert.equal(Model.parseStateLine('{"type":"state","seq":"7"}', 1).kind, "bad", "seq must be a number")
  assert.equal(Model.parseStateLine("x".repeat(Model.MAX_LINE + 1), 1).kind, "bad")
})

test("restart delays: 1 s, 2 s, 5 s, then up to 30 s", () => {
  assert.deepEqual([0, 1, 2].map(Model.backoffMs), [1000, 2000, 5000])
  assert.equal(Model.backoffMs(3), 10000)
  assert.equal(Model.backoffMs(4), 30000)
  assert.equal(Model.backoffMs(50), 30000)
  assert.equal(Model.backoffMs(-3), 1000)
})

test("fixture clock matches the newest history bucket", () => {
  const s = state("healthy")
  const last = s.pihole.history[s.pihole.history.length - 1]
  assert.ok(NOW_S - last.t >= 0 && NOW_S - last.t < 600)
})

// ---- the round-2 contract ------------------------------------------------

test("dns.mode takes none and unknown; anything else it does not know is unknown", () => {
  const r = raw("healthy")
  for (const m of ["pihole", "fallback", "auto", "custom", "none", "unknown"]) {
    r.dns.mode = m
    assert.equal(Model.normalizeState(r).dns.mode, m)
  }
  r.dns.mode = "dhcp"
  assert.equal(Model.normalizeState(r).dns.mode, "unknown")
})

test("bypassed, resolvedFallback, health, canaryBlocked, selfQueries, historySpanS, gatewayMs and detected", () => {
  const s = state("partial")
  assert.equal(s.pihole.health, "ok")
  assert.equal(s.pihole.canaryBlocked, true)
  assert.equal(s.pihole.historySpanS, 5400)
  assert.equal(s.pihole.today.selfQueries, 31)
  assert.equal(s.link.gatewayMs, 4.2)
  assert.equal(state("ethernet-bypassed").dns.bypassed, true)
  assert.equal(state("none").dns.resolvedFallback, "9.9.9.9")
  assert.equal(state("healthy").dns.resolvedFallback, "")
  assert.equal(state("unconfigured").pihole.detected, "192.168.1.153")
  assert.equal(state("unconfigured").pihole.address, "", "the address comes only from config")
  assert.equal(state("degraded").pihole.health, "degraded")
  assert.equal(state("degraded").pihole.reachable, true, "degraded still answers")
  assert.equal(state("unknown").pihole.health, "unknown")
  assert.equal(state("unreachable").pihole.reachable, false)
})

test("health and reachable agree: health wins when given, reachable stands in when not", () => {
  const r = raw("healthy")
  r.pihole.health = "unreachable"
  r.pihole.reachable = true
  assert.equal(Model.normalizeState(r).pihole.reachable, false)
  delete r.pihole.health
  r.pihole.reachable = false
  const s = Model.normalizeState(r)
  assert.equal(s.pihole.health, "unreachable")
  r.pihole.reachable = true
  assert.equal(Model.normalizeState(r).pihole.health, "ok")
})

test("the new fields are bounded", () => {
  const r = raw("healthy")
  r.link.gatewayMs = -5
  r.pihole.canaryBlocked = "yes"
  r.pihole.historySpanS = 99999999
  r.pihole.detected = "$(reboot)"
  r.dns.resolvedFallback = "9.9.9.9; reboot"
  r.pihole.today.selfQueries = -3
  const s = Model.normalizeState(r)
  assert.equal(s.link.gatewayMs, null)
  assert.equal(s.pihole.canaryBlocked, null)
  assert.equal(s.pihole.historySpanS, 86400)
  assert.equal(s.pihole.detected, "")
  assert.equal(s.dns.resolvedFallback, "")
  assert.equal(s.pihole.today.selfQueries, 0)
})

test("the restart counter starts over only after 30 s of uptime", () => {
  assert.equal(Model.restartAttempt(3, 29999), 3, "a child that spoke and died quickly keeps climbing")
  assert.equal(Model.restartAttempt(3, 30000), 0)
  assert.equal(Model.restartAttempt(3, 120000), 0)
  assert.equal(Model.restartAttempt(0, 10), 0)
  assert.equal(Model.restartAttempt(-2, 10), 0)
})

test("Model.js carries no raw bidi or control characters", () => {
  const src = require("fs").readFileSync(require("path").join(__dirname, "..", "Model.js"), "utf8")
  assert.doesNotMatch(src, /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u0000-\u0008\u000b\u000c\u000e-\u001f]/)
})

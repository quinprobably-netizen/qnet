"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, hero, state, BIN, NOW_MS } = require("./helpers.js")

const eff = (s, pend) => Model.effective(s, pend || Model.emptyPending(), NOW_MS, NOW_MS)

// ---- the state word ----------------------------------------------------

test("healthy Pi-hole: accent word, via address, quiet latency, blocking", () => {
  const h = hero("healthy")
  assert.equal(h.kind, "pihole")
  assert.equal(h.tone, "accent")
  assert.equal(h.frozen, false)
  assert.equal(h.setup, false)
  assert.equal(h.via, "192.168.1.153")
  assert.equal(h.latencyMs, 3.1)
  assert.equal(h.latencyBad, false)
  assert.equal(h.blocking, "blocking")
  assert.equal(Model.formatLatency(h.latencyMs), "3 ms")
})

test("a blocked canary reads blocking; a real address while blocking is on reads not blocking", () => {
  assert.equal(hero("not-blocking").blocking, "notBlocking")
  assert.equal(hero("not-blocking").kind, "pihole", "the word stays; the last word of the line carries it")
  const s = state("healthy")
  s.pihole.canaryBlocked = null
  assert.equal(Model.heroState(eff(s)).blocking, "", "unknown says nothing")
  const t = state("healthy")
  t.pihole.canaryBlocked = false
  t.pihole.blocking = "disabled"
  assert.equal(Model.heroState(eff(t)).blocking, "", "a paused Pi-hole is not 'not blocking'")
})

test("paused: dim word with the countdown", () => {
  const h = hero("paused")
  assert.equal(h.kind, "paused")
  assert.equal(h.tone, "dim")
  assert.equal(h.pauseS, 272)
  assert.equal(h.blocking, "")
  assert.equal(Model.formatCountdown(h.pauseS), "4:32")
})

test("degraded: warning word, still reachable, graph not frozen", () => {
  const h = hero("degraded")
  assert.equal(h.kind, "degraded")
  assert.equal(h.tone, "warning")
  assert.equal(h.frozen, false)
  assert.equal(h.via, "192.168.1.153")
  assert.equal(h.latencyMs, 6.4)
})

test("fallback: warning word naming the fallback, graph frozen", () => {
  const h = hero("fallback")
  assert.equal(h.kind, "fallback")
  assert.equal(h.tone, "warning")
  assert.equal(h.fallback, "router")
  assert.equal(h.via, "192.168.1.1")
  assert.equal(h.frozen, true)
  assert.ok(h.sinceS > 0)
})

test("unreachable with no failover: urgent, frozen, no latency", () => {
  const h = hero("unreachable")
  assert.equal(h.kind, "unreachable")
  assert.equal(h.tone, "urgent")
  assert.equal(h.frozen, true)
  assert.equal(h.noAnswer, true)
  assert.equal(h.latencyMs, null)
  assert.equal(h.via, "192.168.1.153")
})

test("unconfigured: the mode word, setup, an empty graph, and the detected candidate named", () => {
  const h = hero("unconfigured")
  assert.equal(h.kind, "router")
  assert.equal(h.tone, "dim")
  assert.equal(h.setup, true)
  assert.equal(h.empty, true)
  assert.equal(h.detected, "192.168.1.153", "shown as detected, never as the address")
  assert.equal(hero("healthy").detected, "")
})

test("bypassed is the backend's dns.bypassed, urgent, with the Pi-hole's own sub-line", () => {
  const h = hero("bypassed")
  assert.equal(h.kind, "bypassed")
  assert.equal(h.tone, "urgent")
  assert.equal(h.via, "192.168.1.153")
  assert.equal(h.blocking, "blocking")
  assert.equal(hero("leaks").kind, "pihole", "profiles that are not in use do not make the hero say Bypassed")
})

test("Ethernet on automatic DNS with a Pi-hole set up: Bypassed, via the router", () => {
  const h = hero("ethernet-bypassed")
  assert.equal(h.kind, "bypassed")
  assert.equal(h.tone, "urgent")
  assert.equal(h.via, "192.168.1.1")
  assert.equal(h.latencyMs, null, "the Pi-hole's latency is not this link's")
  assert.equal(h.blocking, "")
})

test("a Pi-hole that is down is not pinned to: unpinned and unreachable is just Router DNS", () => {
  const s = state("ethernet-bypassed")
  s.pihole.health = "unreachable"
  s.pihole.reachable = false
  assert.equal(Model.heroState(eff(s)).kind, "router")
})

test("no DNS servers: urgent, and the resolved fallback named", () => {
  const h = hero("none")
  assert.equal(h.kind, "none")
  assert.equal(h.tone, "urgent")
  assert.equal(h.resolvedFallback, "9.9.9.9")
  assert.equal(h.via, "")
})

test("mode unknown (before the first probe): dim Checking, never Custom", () => {
  const h = hero("unknown")
  assert.equal(h.kind, "checking")
  assert.equal(h.tone, "dim")
  const s = state("unknown")
  s.pihole = Object.assign({}, s.pihole, { configured: false })
  assert.equal(Model.heroState(eff(s)).kind, "checking")
})

test("custom DNS and router DNS are dim; offline is dim and frozen", () => {
  assert.equal(hero("custom").kind, "custom")
  assert.equal(hero("custom").tone, "dim")
  const offline = hero("offline")
  assert.equal(offline.kind, "offline")
  assert.equal(offline.frozen, true)
  const s = state("healthy")
  s.dns.mode = "auto"
  assert.equal(Model.heroState(eff(s)).kind, "router")
})

test("latency is urgent only past 100 ms or with failing probes", () => {
  const s = state("healthy")
  s.pihole.latencyMs = 140
  assert.equal(Model.heroState(eff(s)).latencyBad, true)
  const t = state("healthy")
  t.pihole.probes[t.pihole.probes.length - 1].ok = false
  t.pihole.probes[t.pihole.probes.length - 1].ms = null
  assert.equal(Model.heroState(eff(t)).latencyBad, true)
  assert.equal(hero("healthy").latencyBad, false)
})

test("API trouble keeps the word but freezes the graph and names the issue", () => {
  const h = hero("api-auth")
  assert.equal(h.kind, "pihole")
  assert.equal(h.frozen, true)
  assert.equal(h.apiIssue, "auth")
  assert.equal(hero("healthy").apiIssue, "")
})

test("every fixture yields a hero", () => {
  for (const n of ["healthy", "paused", "fallback", "unreachable", "unconfigured", "leaks", "bypassed", "portal",
    "offline", "radio-off", "custom", "api-auth", "ethernet", "markup", "partial", "ethernet-bypassed", "degraded",
    "not-blocking", "none", "unknown"]) {
    const h = hero(n)
    assert.ok(["pihole", "paused", "degraded", "fallback", "bypassed", "unreachable", "none", "checking", "router", "custom", "offline"].includes(h.kind), n)
    assert.ok(["accent", "dim", "warning", "urgent"].includes(h.tone), n)
  }
})

// ---- tiles --------------------------------------------------------------

test("only the live mode's tile is lit", () => {
  let t = Model.dnsTiles(view("healthy"))
  assert.deepEqual([t.pihole, t.auto, t.custom], ["on", "off", null])
  t = Model.dnsTiles(view("unconfigured"))
  assert.deepEqual([t.pihole, t.auto], ["off", "on"])
})

test("a runtime failover lights Pi-hole in the warning colour with its own label", () => {
  const t = Model.dnsTiles(view("fallback"))
  assert.equal(t.pihole, "warn")
  assert.equal(t.fallbackLabel, true)
  assert.equal(t.auto, "off")
})

test("custom DNS lights no tile and names its servers", () => {
  const t = Model.dnsTiles(view("custom"))
  assert.deepEqual([t.pihole, t.auto], ["off", "off"])
  assert.deepEqual(t.custom, ["9.9.9.9"])
})

test("no DNS and unknown light no tile", () => {
  for (const n of ["none", "unknown"]) {
    const t = Model.dnsTiles(view(n))
    assert.deepEqual([t.pihole, t.auto, t.custom], ["off", "off", null], n)
  }
})

test("tapping the lit tile does nothing; any other tile runs its verb", () => {
  assert.equal(Model.tapDns("pihole", view("healthy")), null)
  assert.deepEqual(Model.tapDns("auto", view("healthy")), { verb: "auto" })
  assert.equal(Model.tapDns("auto", view("unconfigured")), null)
  assert.deepEqual(Model.tapDns("pihole", view("unconfigured")), { verb: "pihole" })
  assert.equal(Model.tapDns("pihole", view("fallback")), null, "the warning tile is lit too")
  assert.deepEqual(Model.tapDns("pihole", view("custom")), { verb: "pihole" })
  assert.deepEqual(Model.tapDns("auto", view("custom")), { verb: "auto" })
  assert.deepEqual(Model.tapDns("pihole", view("none")), { verb: "pihole" })
  assert.equal(Model.tapDns("bogus", view("custom")), null)
})

test("a pending request lights the tile it asked for at once, and the other goes out", () => {
  const pend = Model.withPending(Model.emptyPending(), { dns: "auto" }, NOW_MS)
  const t = Model.dnsTiles(view("healthy", pend))
  assert.deepEqual([t.pihole, t.auto], ["off", "on"])
  assert.equal(Model.tapDns("auto", view("healthy", pend)), null, "a second tap on the pending tile is a no-op")
})

test("asking for the Pi-hole clears 'bypassed' at once; asking for Automatic sets it", () => {
  const pin = Model.withPending(Model.emptyPending(), { dns: "pihole" }, NOW_MS)
  assert.equal(view("ethernet-bypassed", pin).dns.bypassed, false)
  assert.equal(Model.heroState(view("ethernet-bypassed", pin)).kind, "pihole")
  const auto = Model.withPending(Model.emptyPending(), { dns: "auto" }, NOW_MS)
  assert.equal(view("healthy", auto).dns.bypassed, true)
  assert.equal(view("unconfigured", auto).dns.bypassed, false, "nothing to bypass without a Pi-hole")
})

test("the confirm line names the servers the backend gave, else the resolver's", () => {
  const v = view("custom")
  assert.equal(Model.confirmServers("9.9.9.9", v), "9.9.9.9")
  assert.equal(Model.confirmServers(["1.1.1.1", "1.0.0.1", "8.8.8.8"], v), "1.1.1.1, 1.0.0.1")
  assert.equal(Model.confirmServers({ servers: ["4.4.4.4"] }, v), "4.4.4.4")
  assert.equal(Model.confirmServers("custom dns", v), "9.9.9.9")
  assert.equal(Model.confirmServers(null, v), "9.9.9.9")
  assert.equal(Model.confirmServers("$(reboot)", v), "9.9.9.9")
})

// ---- pause chip ---------------------------------------------------------

test("the pause chip is Pause until blocking is off, then Resume with the countdown", () => {
  assert.deepEqual(Model.pauseChip(view("healthy")), { mode: "pause", remainingS: 0, enabled: true })
  const c = Model.pauseChip(view("paused"))
  assert.equal(c.mode, "resume")
  assert.equal(c.remainingS, 272)
  assert.equal(Model.pauseChip(view("unreachable")).enabled, false)
  assert.equal(Model.pauseChip(view("api-auth")).enabled, false)
  assert.equal(Model.pauseChip(view("unconfigured")).enabled, false)
})

// ---- leaks --------------------------------------------------------------

test("saved profiles that are not in use collapse into ONE line, pinned together", () => {
  const g = Model.leakGroups(view("leaks"))
  assert.equal(g.bypass, null)
  assert.equal(g.profiles.count, 2)
  assert.deepEqual(g.profiles.uuids, ["b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66", "0c3d9f12-88aa-4e77-b5d1-72f6e0a1c9d3"])
  assert.equal(g.profiles.pinnable, true)
  assert.deepEqual(g.profiles.lines, ["Wired connection 1: uses router DNS (automatic)", "Home-Guest: uses 1.1.1.1"])
})

test("the partial-history fixture has two wired profiles to pin", () => {
  const g = Model.leakGroups(view("partial"))
  assert.equal(g.profiles.count, 2)
  assert.deepEqual(Model.argvPin(BIN, g.profiles.uuids).slice(0, 3), [BIN, "dns", "pin"])
  assert.equal(Model.argvPin(BIN, g.profiles.uuids).length, 5, "one command, both uuids")
})

test("the urgent line is for dns.bypassed only, and its fix is the Pi-hole on the link in use", () => {
  const g = Model.leakGroups(view("bypassed"))
  assert.deepEqual(g.bypass.action, { verb: "pihole" })
  assert.equal(g.bypass.where, "wlp7s0")
  assert.deepEqual(g.bypass.details, ["wlp7s0: router advertises fe80::1"])
  assert.equal(g.profiles, null, "the active link's leak is not one of the unused profiles")
})

test("Ethernet bypassed: the active profile's leak is the detail of the urgent line", () => {
  const g = Model.leakGroups(view("ethernet-bypassed"))
  assert.notEqual(g.bypass, null)
  assert.equal(g.profiles, null)
  assert.match(g.bypass.details[0], /Wired connection 1/)
})

test("a leak on the active link with bypassed false is not an alarm", () => {
  const s = state("bypassed")
  s.dns.bypassed = false
  assert.equal(Model.leakGroups(eff(s)).bypass, null)
})

test("profiles just pinned drop out of the line at once, all of them or one", () => {
  const both = Model.withPending(Model.emptyPending(), { pinUuid: "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66 0c3d9f12-88aa-4e77-b5d1-72f6e0a1c9d3" }, NOW_MS)
  assert.equal(Model.leakGroups(view("leaks", both), both).profiles, null)
  const one = Model.withPending(Model.emptyPending(), { pinUuid: "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66" }, NOW_MS)
  const g = Model.leakGroups(view("leaks", one), one)
  assert.equal(g.profiles.count, 1)
  assert.equal(g.profiles.lines[0].startsWith("Home-Guest"), true)
})

test("no leaks, no lines; the compiled FallbackDNS is never a leak", () => {
  const g = Model.leakGroups(view("healthy"))
  assert.deepEqual([g.bypass, g.profiles], [null, null])
})

// ---- the backend is down -------------------------------------------------

test("with qnet not running the hero and header say so and the graph freezes", () => {
  const down = Model.effective(state("healthy"), Model.emptyPending(), NOW_MS, NOW_MS, true)
  const h = Model.heroState(down)
  assert.equal(h.kind, "nobackend")
  assert.equal(h.tone, "urgent")
  assert.equal(h.frozen, true)
  assert.equal(h.empty, true)
  const hd = Model.headerInfo(down)
  assert.equal(hd.kind, "nobackend")
  assert.deepEqual(hd.status, [{ k: "state", key: "nobackend" }])
  assert.equal(hd.urgent, true)
  assert.equal(Model.barActive(down), false, "the last known state is not an alarm")
  assert.equal(view("healthy").backendDown, false)
  const t = Model.dnsTiles(down)
  assert.deepEqual([t.pihole, t.auto, t.custom], ["off", "off", null], "no tile is lit while nothing is known")
  assert.equal(Model.pauseChip(down).enabled, false)
  assert.equal(Model.leakGroups(down).bypass, null)
})

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

test("paused: warning word with the countdown", () => {
  const h = hero("paused")
  assert.equal(h.kind, "paused")
  assert.equal(h.tone, "warning")
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

test("bypassed is the backend's dns.bypassed, urgent; it names the extra resolver and drops 'blocking'", () => {
  const h = hero("bypassed")
  assert.equal(h.kind, "bypassed")
  assert.equal(h.tone, "urgent")
  assert.equal(h.via, "192.168.1.153")
  assert.equal(h.blocking, "", "no '. blocking' while queries can skip the Pi-hole")
  assert.deepEqual(h.extra, { who: "router", viaRa: true }, "+ router via IPv6 RA")
  assert.equal(h.action, "pin")
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
    "not-blocking", "none", "unknown", "unreachable-armed", "slow-gateway"]) {
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

test("tapping the lit tile does nothing; any other tile has its verb", () => {
  assert.equal(Model.tapDns("pihole", view("healthy")), null)
  assert.deepEqual(Model.tapDns("auto", view("healthy")), { verb: "auto", leaves: true })
  assert.equal(Model.tapDns("auto", view("unconfigured")), null)
  assert.deepEqual(Model.tapDns("pihole", view("unconfigured")), { verb: "pihole", leaves: false })
  assert.equal(Model.tapDns("pihole", view("fallback")), null, "the warning tile is lit too")
  assert.deepEqual(Model.tapDns("auto", view("fallback")), { verb: "auto", leaves: true })
  assert.deepEqual(Model.tapDns("pihole", view("custom")), { verb: "pihole", leaves: false })
  assert.deepEqual(Model.tapDns("auto", view("custom")), { verb: "auto", leaves: false })
  assert.deepEqual(Model.tapDns("pihole", view("none")), { verb: "pihole", leaves: false })
  assert.equal(Model.tapDns("bogus", view("custom")), null)
})

// ---- leaving the Pi-hole is asked first -----------------------------------------

test("a tap that would leave the Pi-hole only asks: nothing runs until the second step", () => {
  for (const n of ["healthy", "paused", "degraded", "bypassed", "leaks", "partial", "fallback", "not-blocking"]) {
    const plan = Model.tapPlan("auto", view(n))
    assert.deepEqual(plan, { action: "confirm", verb: "auto", kind: "leave" }, n)
  }
})

test("towards the Pi-hole, or between other resolvers, a tap runs at once", () => {
  assert.deepEqual(Model.tapPlan("pihole", view("custom")), { action: "run", verb: "pihole" })
  assert.deepEqual(Model.tapPlan("pihole", view("ethernet-bypassed")), { action: "run", verb: "pihole" })
  assert.deepEqual(Model.tapPlan("pihole", view("none")), { action: "run", verb: "pihole" })
  assert.deepEqual(Model.tapPlan("auto", view("custom")), { action: "run", verb: "auto" })
  assert.deepEqual(Model.tapPlan("auto", view("none")), { action: "run", verb: "auto" })
})

test("a lit tile, an unknown one and the Pi-hole tile without a Pi-hole do nothing or set up", () => {
  assert.equal(Model.tapPlan("pihole", view("healthy")).action, "none")
  assert.equal(Model.tapPlan("auto", view("unconfigured")).action, "none")
  assert.equal(Model.tapPlan("pihole", view("unconfigured")).action, "setup")
  assert.equal(Model.tapPlan("auto", view("ethernet-bypassed")).action, "none", "Automatic is already what is lit")
})

test("a switch to Automatic that is already pending asks nothing and does nothing", () => {
  const pend = Model.withPending(Model.emptyPending(), { dns: "auto" }, NOW_MS)
  assert.equal(Model.tapPlan("auto", view("healthy", pend)).action, "none")
})

test("the panel wires it: the tap opens the confirm, only the confirm's yes runs the switch", () => {
  const panel = require("fs").readFileSync(require("path").join(__dirname, "..", "Panel.qml"), "utf8")
  const tap = panel.slice(panel.indexOf("function tapTile(name)"), panel.indexOf("function confirmReplace()"))
  assert.match(tap, /Model\.tapPlan\(name, view\)/)
  assert.match(tap, /plan\.action === "confirm"[\s\S]*?kind: plan\.kind[\s\S]*?return/, "the confirm branch returns before anything runs")
  const confirmAt = tap.indexOf('plan.action === "confirm"')
  const runAt = tap.indexOf("runDns(plan.verb, false)")
  assert.ok(confirmAt > 0 && runAt > confirmAt, "runDns comes after the confirm branch has returned")
  const yes = panel.slice(panel.indexOf("function confirmReplace()"), panel.indexOf("function confirmCancel()"))
  assert.match(yes, /runDns\(verb, force\)/)
  assert.match(yes, /force = confirm\.kind !== "leave"/, "leaving is not a --force")
  const tiles = require("fs").readFileSync(require("path").join(__dirname, "..", "components", "DnsTiles.qml"), "utf8")
  assert.match(tiles, /dns\.leaveQ/)
  assert.match(tiles, /dns\.leaveYes/)
})

test("a pending request lights the tile it asked for at once, and the other goes out", () => {
  const pend = Model.withPending(Model.emptyPending(), { dns: "auto" }, NOW_MS)
  const t = Model.dnsTiles(view("healthy", pend))
  assert.deepEqual([t.pihole, t.auto], ["off", "on"])
  assert.equal(Model.tapDns("auto", view("healthy", pend)), null, "a second tap on the pending tile is a no-op")
})

test("asking for the Pi-hole clears 'bypassed' at once; Automatic chosen through qnet is a choice, not a bypass", () => {
  const pin = Model.withPending(Model.emptyPending(), { dns: "pihole" }, NOW_MS)
  assert.equal(view("ethernet-bypassed", pin).dns.bypassed, false)
  assert.equal(Model.heroState(view("ethernet-bypassed", pin)).kind, "pihole")
  const auto = Model.withPending(Model.emptyPending(), { dns: "auto" }, NOW_MS)
  assert.equal(view("healthy", auto).dns.bypassed, false)
  assert.equal(Model.heroState(view("healthy", auto)).kind, "router")
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

test("the Pause tile is Pause until blocking is off, then Resume with the countdown in warning", () => {
  assert.deepEqual(Model.pauseChip(view("healthy")), { mode: "pause", tone: "dim", remainingS: 0, enabled: true })
  const c = Model.pauseChip(view("paused"))
  assert.equal(c.mode, "resume")
  assert.equal(c.tone, "warning")
  assert.equal(c.remainingS, 272)
  assert.equal(c.enabled, true)
})

test("the Pause tile is disabled whenever DNS is not going through the Pi-hole", () => {
  for (const n of ["unreachable", "api-auth", "unconfigured", "fallback", "none", "unknown", "custom", "offline", "radio-off", "ethernet-bypassed"])
    assert.equal(Model.pauseChip(view(n)).enabled, false, n)
  for (const n of ["healthy", "paused", "degraded", "bypassed", "leaks", "partial"])
    assert.equal(Model.pauseChip(view(n)).enabled, true, n)
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

test("each profile is named, with its own uuid, for the DNS view", () => {
  const items = Model.leakGroups(view("leaks")).profiles.items
  assert.deepEqual(items.map((i) => i.where), ["Wired connection 1", "Home-Guest"])
  assert.equal(items[0].uuid, "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66")
  assert.equal(items[0].detail, "uses router DNS (automatic)")
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

// ---- round 3: fault states, one corrective action each ------------------

test("every fault state offers exactly one corrective action, and none gets a row", () => {
  const want = { unconfigured: "setup", "api-auth": "signin", none: "usepihole", bypassed: "pin", "ethernet-bypassed": "pin" }
  for (const n of Object.keys(want)) assert.equal(hero(n).action, want[n], n)
  for (const n of ["healthy", "paused", "degraded", "fallback", "unreachable", "unreachable-armed", "offline", "unknown", "custom"])
    assert.equal(hero(n).action, "", n)
})

test("a Pi-hole that was never set up and a link that is down offer nothing to do", () => {
  const s = state("unconfigured")
  s.link = Object.assign({}, s.link, { kind: "none" })
  assert.equal(Model.heroState(eff(s)).action, "")
})

test("unreachable with a failover armed counts down to it; with none armed, says nothing", () => {
  assert.equal(hero("unreachable").failoverIn, null, "failover is off in that fixture")
  const h = hero("unreachable-armed")
  assert.equal(h.kind, "unreachable")
  assert.ok(h.failoverIn > 10 && h.failoverIn <= 15, "failing for 15 s of the 30: " + h.failoverIn)
  const later = Model.heroState(view("unreachable-armed"), 1794122700 + 20)
  assert.equal(later.failoverIn, 0, "it is due")
  assert.equal(Model.heroState(view("unreachable-armed"), 1794122700 + 5).failoverIn, 10)
  assert.equal(hero("healthy").failoverIn, null)
  assert.equal(hero("fallback").failoverIn, null, "already failed over")
})

test("the panel's clock ticks for a pause, a failover countdown or a pending request", () => {
  assert.equal(Model.needsClock(view("healthy"), Model.emptyPending(), 0), false)
  assert.equal(Model.needsClock(view("paused"), Model.emptyPending(), 0), true)
  assert.equal(Model.needsClock(view("unreachable-armed"), Model.emptyPending(), 0), true)
  assert.equal(Model.needsClock(view("unreachable"), Model.emptyPending(), 0), false)
  assert.equal(Model.needsClock(view("healthy"), Model.withPending(Model.emptyPending(), { radio: "off" }, 0), 0), true)
})

test("the hero desaturates whenever DNS is not via the Pi-hole", () => {
  for (const n of ["healthy", "partial", "degraded", "paused", "bypassed"]) assert.equal(hero(n).desaturated, false, n)
  for (const n of ["fallback", "none", "unknown", "custom", "ethernet-bypassed", "offline", "unreachable", "api-auth", "unconfigured"])
    assert.equal(hero(n).desaturated, true, n)
  const s = state("healthy")
  s.dns.mode = "auto"
  assert.equal(Model.heroState(eff(s)).desaturated, true)
})

test("bypassed in Automatic names no extra resolver: the link simply is not on the Pi-hole", () => {
  const h = hero("ethernet-bypassed")
  assert.equal(h.extra, null)
  assert.equal(h.blocking, "")
})

test("the extra resolver: a router by IPv6 RA, or an address", () => {
  assert.deepEqual(Model.extraResolver(view("bypassed")), { who: "router", viaRa: true })
  const s = state("bypassed")
  s.dns.servers[1] = { addr: "1.1.1.1", link: "wlp7s0", current: false, role: "public" }
  s.dns.leaks = [{ kind: "link", where: "wlp7s0", uuid: "", detail: "also uses 1.1.1.1" }]
  assert.deepEqual(Model.extraResolver(eff(s)), { who: "1.1.1.1", viaRa: false })
  assert.equal(Model.extraResolver(view("healthy")), null)
})

test("a resolved-fallback leak is the link's, never an unused profile", () => {
  const s = state("bypassed")
  s.dns.leaks = [{ kind: "resolved-fallback", where: "resolved", uuid: "", detail: "FallbackDNS 9.9.9.9 in use" }]
  const g = Model.leakGroups(eff(s))
  assert.equal(g.profiles, null)
  assert.deepEqual(g.bypass.details, ["resolved: FallbackDNS 9.9.9.9 in use"])
  assert.equal(Model.normalizeState({ dns: { leaks: [{ kind: "resolved-fallback", where: "x" }] } }).dns.leaks[0].kind, "resolved-fallback")
})

// ---- the DNS row's value ------------------------------------------------------

test("the DNS row says what the resolver is, and colours what is wrong", () => {
  const sum = (n) => Model.dnsSummary(view(n))
  assert.deepEqual(sum("healthy"), { mode: "pihole", arg: "", suffix: [], tone: "dim", leaks: 0 })
  assert.deepEqual(sum("leaks"), { mode: "pihole", arg: "", suffix: ["leaks"], tone: "warning", leaks: 2 })
  assert.deepEqual(sum("bypassed").suffix, ["bypassed"])
  assert.equal(sum("bypassed").tone, "urgent")
  assert.deepEqual(sum("fallback"), { mode: "fallback", arg: "router", suffix: [], tone: "warning", leaks: 0 })
  assert.equal(sum("none").tone, "urgent")
  assert.deepEqual(sum("custom"), { mode: "custom", arg: "9.9.9.9", suffix: [], tone: "dim", leaks: 0 })
  assert.deepEqual(sum("ethernet-bypassed").suffix, ["bypassed"])
  assert.equal(sum("ethernet-bypassed").mode, "auto")
  assert.equal(Model.dnsSummary(Model.effective(state("healthy"), Model.emptyPending(), 0, 0, true)).mode, "unknown")
})

test("failover on the DNS view: off, armed or active, with the effective fallback and the reason", () => {
  assert.deepEqual(Model.failoverInfo(view("healthy")), { state: "armed", fallback: "router", reason: "", sinceS: 0 })
  const f = Model.failoverInfo(view("fallback"))
  assert.equal(f.state, "active")
  assert.equal(f.reason, "3 failed probes")
  assert.ok(f.sinceS > 0)
  assert.equal(Model.failoverInfo(view("unreachable")).state, "off")
})

test("the Pi-hole's health reason is carried, bounded", () => {
  assert.equal(state("degraded").pihole.healthReason, "upstream SERVFAIL")
  assert.equal(hero("degraded").healthReason, "upstream SERVFAIL")
  assert.equal(Model.normalizeState({ pihole: { healthReason: "x".repeat(500) } }).pihole.healthReason.length, 80)
})

"use strict"
// The hero's picture as data: the route a query takes, hop by hop, and what
// state each hop is in (Model.routeModel). HeroViz only draws it.
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, state, raw, NOW_MS, NOW_S } = require("./helpers.js")

const route = (name, nowS) => Model.routeModel(view(name), nowS)
const node = (r, id) => r.nodes.find((n) => n.id === id)
const link = (r, a, b) => r.links.find((l) => l.a === a && l.b === b)
const text = (p) => (p ? (p.text !== undefined ? p.text : p.key + "|" + p.args.join(",")) : null)

// ---- the contract's new fields -----------------------------------------

test("upstreams: busiest first, at most four, addresses validated, latency null when unknown", () => {
  const r = raw("healthy")
  r.pihole.upstreams = [
    { name: "a", ip: "1.1.1.1", port: 53, count: 5, responseMs: 3 },
    { name: "b", ip: "9.9.9.9", port: 53, count: 50, responseMs: null },
    { name: "c", ip: "8.8.8.8; reboot", port: 53, count: 20, responseMs: -2 },
    { name: "d", ip: "4.4.4.4", port: 53, count: 1 },
    { name: "e", ip: "5.5.5.5", port: 53, count: 99 },
    { name: "f", ip: "6.6.6.6", port: 53, count: 7 }
  ]
  const u = Model.normalizeState(r).pihole.upstreams
  assert.equal(u.length, 4)
  assert.deepEqual(u.map((x) => x.name), ["e", "b", "c", "f"], "sorted by count, the weakest dropped")
  assert.equal(u[1].responseMs, null)
  assert.equal(u[2].ip, "", "an invalid address is not kept")
  assert.equal(u[2].responseMs, null)
  assert.equal(Model.normalizeState({}).pihole.upstreams.length, 0)
  assert.equal(Model.normalizeState({ pihole: { upstreams: "no" } }).pihole.upstreams.length, 0)
})

test("answeredBy and signalDbm", () => {
  const s = state("healthy")
  assert.deepEqual(s.pihole.answeredBy, { blocklist: 164, cache: 470, forwarded: 570 })
  assert.deepEqual(Model.normalizeState({}).pihole.answeredBy, { blocklist: 0, cache: 0, forwarded: 0 })
  assert.deepEqual(Model.answeredShares(s.pihole.answeredBy), { blocklist: 14, cache: 39, forwarded: 47 })
  assert.deepEqual(Model.answeredShares({ blocklist: 0, cache: 0, forwarded: 0 }), { blocklist: 0, cache: 0, forwarded: 0 })
  assert.equal(state("dbm").link.signalDbm, -58)
  assert.equal(state("healthy").link.signalDbm, null)
  for (const bad of [5, 0, -500, "x", null]) assert.equal(Model.normalizeState({ link: { signalDbm: bad } }).link.signalDbm, null, String(bad))
})

// ---- the small functions ----------------------------------------------------

test("last octet, blocked share and query density", () => {
  assert.equal(Model.lastOctet("192.168.1.242"), ".242")
  assert.equal(Model.lastOctet("10.0.0.7"), ".7")
  assert.equal(Model.lastOctet("fe80::1"), "")
  assert.equal(Model.lastOctet(""), "")
  assert.equal(Model.lastOctet("1.2.3.4; reboot"), "")
  assert.ok(Math.abs(Model.blockedShare(view("partial")) - 0.507) < 0.001)
  assert.equal(Model.blockedShare(view("unconfigured")), 0)
  const d = Model.queryDensity(view("healthy"))
  assert.ok(d >= 0.15 && d <= 1, "density " + d)
  assert.equal(Model.queryDensity(view("unconfigured")), 0)
  const s = state("healthy")
  s.pihole.history = []
  assert.equal(Model.queryDensity(Model.effective(s, Model.emptyPending(), 0, 0)), 0.3, "traffic today but no history: a gentle flow")
  s.pihole.today = { total: 0, blocked: 0, percent: 0, selfQueries: 0 }
  assert.equal(Model.queryDensity(Model.effective(s, Model.emptyPending(), 0, 0)), 0)
})

// ---- healthy -------------------------------------------------------------------

test("healthy: PC, AP, Pi-hole, upstream, with the numbers under them", () => {
  const r = route("healthy")
  assert.equal(r.kind, "route")
  assert.deepEqual(r.nodes.map((n) => n.id), ["pc", "ap", "ph", "up"])
  assert.equal(text(node(r, "pc").label), ".242")
  assert.equal(node(r, "pc").glyph, "pc")
  assert.equal(text(node(r, "ap").label), "72%")
  assert.equal(text(node(r, "ap").stat), "4 ms")
  assert.equal(node(r, "ap").glyph, "ap")
  assert.equal(node(r, "ph").glyph, "shield")
  assert.equal(text(node(r, "ph").label), ".153 ✓")
  assert.equal(text(node(r, "ph").stat), "3 ms")
  assert.equal(node(r, "ph").tone, "accent")
  assert.equal(text(node(r, "up").label), "9.9.9.9")
  assert.equal(text(node(r, "up").stat), "12 ms")
  assert.equal(node(r, "up").tip, "dns.quad9.net  9.9.9.9  12 ms\none.one.one.one  1.1.1.1  10 ms", "the names are in the tooltip")
  assert.equal(r.branch, null)
})

test("healthy: every link flows, and the ones after the Pi-hole are thinner", () => {
  const r = route("healthy")
  assert.deepEqual(r.links.map((l) => l.a + ">" + l.b), ["pc>ap", "ap>ph", "ph>up", "up>end"])
  for (const l of r.links) { assert.equal(l.state, "flow"); assert.equal(l.tone, "accent"); assert.equal(l.flow, true) }
  assert.deepEqual(r.links.map((l) => l.thin), [false, false, true, true])
  assert.equal(r.flow.live, true)
  assert.ok(Math.abs(r.flow.share - 0.136) < 0.002)
})

test("healthy: the sink drains the blocked share, labelled", () => {
  const r = route("partial")
  assert.equal(r.sink.pct, 50.7)
  assert.equal(r.sink.empty, false)
  assert.equal(text(r.sink.label), "hero.blocked|50.7%")
  assert.equal(route("healthy").sink.pct, 13.6)
})

test("the AP: dBm when the radio reports it, the rate on a wire, a gateway latency when measured", () => {
  assert.equal(text(node(route("dbm"), "ap").label), "-58 dBm")
  const wire = route("ethernet")
  assert.equal(node(wire, "ap").glyph, "wire")
  assert.equal(text(node(wire, "ap").label), "1 Gb/s")
  assert.equal(text(node(wire, "ap").stat), "<1 ms")
  const s = state("healthy")
  s.link.gatewayMs = null
  assert.equal(node(Model.routeModel(Model.effective(s, Model.emptyPending(), 0, 0), 0), "ap").stat, null, "not measured while closed")
  s.link.gatewayMs = 120
  assert.equal(node(Model.routeModel(Model.effective(s, Model.emptyPending(), 0, 0), 0), "ap").statTone, "urgent")
  s.link.gatewayOk = false
  const bad = node(Model.routeModel(Model.effective(s, Model.emptyPending(), 0, 0), 0), "ap")
  assert.equal(text(bad.stat), "gw ✗")
  assert.equal(bad.statTone, "urgent")
})

test("a Pi-hole latency over 100 ms is urgent on its node, and only then", () => {
  assert.equal(node(route("healthy"), "ph").statTone, "")
  const s = state("healthy")
  s.pihole.latencyMs = 180
  assert.equal(node(Model.routeModel(Model.effective(s, Model.emptyPending(), 0, 0), 0), "ph").statTone, "urgent")
})

test("without upstream data the beyond node says so rather than inventing a resolver", () => {
  const s = state("healthy")
  s.pihole.upstreams = []
  const up = node(Model.routeModel(Model.effective(s, Model.emptyPending(), 0, 0), 0), "up")
  assert.equal(text(up.label), "route.upstream|")
  assert.equal(up.stat, null)
  assert.equal(up.tip, "")
})

// ---- states, each on the route -----------------------------------------------------

test("paused: the Pi-hole is an open gate with 'paused 4:30' in warning; the sink is empty; the flow passes at full width", () => {
  const r = route("paused")
  const ph = node(r, "ph")
  assert.equal(ph.glyph, "shieldOutline")
  assert.equal(ph.tone, "dim")
  assert.equal(text(ph.label), ".153")
  assert.equal(text(ph.stat), "route.paused|4:32")
  assert.equal(ph.statTone, "warning")
  assert.equal(r.sink.empty, true)
  assert.equal(r.sink.pct, 0)
  assert.equal(r.sink.label, null)
  assert.deepEqual(r.links.map((l) => l.thin), [false, false, false, false])
  assert.equal(link(r, "ph", "up").flow, true)
})

test("fallback: the Pi-hole greyed with a cross; a warning branch carries the flow, named for the fallback", () => {
  const r = route("fallback")
  const ph = node(r, "ph")
  assert.equal(ph.glyph, "shieldOff")
  assert.equal(ph.tone, "dim")
  assert.equal(text(ph.label), ".153 ✕")
  assert.equal(r.branch.tone, "warning")
  assert.equal(r.branch.label.key, "fallback.router")
  assert.equal(r.branch.flow, true)
  assert.equal(link(r, "ap", "ph").state, "dim")
  assert.equal(link(r, "ap", "ph").flow, false)
  assert.equal(link(r, "pc", "ap").flow, true, "the way to the AP still carries traffic")
  assert.equal(node(r, "up").tone, "warning", "the fallback resolver is where it comes out")
  assert.equal(text(node(r, "up").label), ".1")
  assert.equal(r.sink, null)
})

test("unreachable, no failover yet: urgent Pi-hole with a cross, the flow stalls at it", () => {
  const r = route("unreachable")
  const ph = node(r, "ph")
  assert.equal(ph.tone, "urgent")
  assert.equal(ph.glyph, "shieldOff")
  assert.equal(text(ph.stat), "hero.noAnswer|")
  assert.equal(link(r, "ap", "ph").state, "stalled")
  assert.equal(link(r, "ap", "ph").flow, false)
  assert.equal(link(r, "ph", "up").state, "dashed")
  assert.equal(r.flow.live, false)
  assert.equal(r.branch, null)
  assert.equal(r.sink, null)
})

test("unreachable with a failover armed: the countdown sits under the Pi-hole", () => {
  const r = route("unreachable-armed", NOW_S)
  assert.equal(text(node(r, "ph").stat), "hero.failoverIn|0:15")
  assert.equal(node(r, "ph").statTone, "warning")
  const due = route("unreachable-armed", NOW_S + 30)
  assert.equal(text(node(due, "ph").stat), "hero.failingOver|")
})

test("degraded: the upstream node is warning, with the reason (or SERVFAIL)", () => {
  const r = route("degraded")
  assert.equal(node(r, "up").tone, "warning")
  assert.equal(text(node(r, "up").stat), "upstream SERVFAIL")
  assert.equal(node(r, "up").statTone, "warning")
  assert.equal(node(r, "ph").tone, "accent", "the Pi-hole itself answers")
  const s = state("degraded")
  s.pihole.healthReason = ""
  assert.equal(text(node(Model.routeModel(Model.effective(s, Model.emptyPending(), 0, 0), 0), "up").stat), "route.servfail|")
})

test("bypassed: an urgent branch skips the Pi-hole to the leaking resolver, part of the flow takes it", () => {
  const r = route("bypassed")
  assert.equal(r.kind, "route")
  assert.equal(r.branch.tone, "urgent")
  assert.equal(text(r.branch.label), "hero.extraRa|router")
  assert.equal(r.branch.flow, true)
  assert.equal(link(r, "ph", "up").flow, true, "and the rest still goes through")
  assert.notEqual(r.sink, null)
})

test("Ethernet on automatic DNS: the Pi-hole is idle, the way to the resolver is urgent", () => {
  const r = route("ethernet-bypassed")
  assert.equal(r.kind, "direct")
  assert.equal(node(r, "ph").glyph, "shield")
  assert.equal(node(r, "ph").tone, "dim")
  assert.equal(text(node(r, "ph").stat), "route.idle|")
  assert.equal(link(r, "ap", "up").tone, "urgent")
  assert.equal(text(node(r, "up").label), ".1")
  assert.equal(text(node(r, "up").stat), "route.role.router|")
  assert.equal(node(r, "ap").glyph, "wire")
  assert.equal(r.sink, null)
})

test("no DNS: the route ends at an urgent DNS node past the AP, with the note under it", () => {
  const r = route("none")
  assert.equal(r.kind, "none")
  assert.deepEqual(r.nodes.map((n) => n.id), ["pc", "ap", "ph"])
  assert.equal(node(r, "ph").tone, "urgent")
  assert.equal(node(r, "ph").open, "dns", "the DNS node opens the DNS view")
  assert.deepEqual(link(r, "ap", "ph"), { a: "ap", b: "ph", state: "dashed", tone: "urgent", thin: false, flow: false })
  assert.equal(r.note.key, "route.none")
  assert.deepEqual(r.note.args, ["9.9.9.9"])
  assert.equal(r.note.tone, "urgent")
})

test("not set up: PC to AP to the DNS server, with a ghost where the Pi-hole would be", () => {
  const r = route("unconfigured")
  assert.equal(r.kind, "direct")
  assert.equal(r.ghost, true)
  assert.deepEqual(r.nodes.map((n) => n.id), ["pc", "ap", "ph", "up"])
  assert.equal(node(r, "ph").glyph, "ghost")
  assert.equal(text(node(r, "ph").label), ".153?", "a Pi-hole found on the LAN is a candidate, marked as one")
  assert.equal(text(node(r, "up").label), ".1")
  assert.deepEqual(r.links.map((l) => l.a + ">" + l.b), ["pc>ap", "ap>up", "up>end"], "the way passes behind the ghost")
  assert.equal(route("healthy").ghost, false)
})

test("custom DNS: direct to the servers, the Pi-hole idle", () => {
  const r = route("custom")
  assert.equal(r.kind, "direct")
  assert.equal(r.ghost, false)
  assert.equal(text(node(r, "up").label), "9.9.9.9", "a public address is shown whole")
  assert.equal(text(node(r, "ph").stat), "route.idle|")
})

test("offline and radio off: the PC and a dim AP at the end of a dashed link, saying why", () => {
  for (const [n, key] of [["offline", "route.offline"], ["radio-off", "route.wifiOff"]]) {
    const r = route(n)
    assert.equal(r.kind, "offline", n)
    assert.deepEqual(r.nodes.map((x) => x.id), ["pc", "ap"], n)
    assert.equal(r.nodes[0].tone, "dim")
    assert.equal(r.nodes[1].tone, "dim")
    assert.equal(r.nodes[1].label.key, key, n)
    assert.equal(r.nodes[1].open, "wifi", n + ": the dim AP still opens Wi-Fi, to join something")
    assert.deepEqual(r.links, [{ a: "pc", b: "ap", state: "dashed", tone: "dim", thin: false }], n)
    assert.equal(r.note, null, n)
    assert.equal(r.flow.density, 0)
  }
})

// ---- the route is the navigation -----------------------------------------

test("the AP opens Wi-Fi and the Pi-hole's place opens DNS, in every state that has them", () => {
  for (const n of ["healthy", "paused", "fallback", "bypassed", "unreachable", "degraded", "custom", "unconfigured", "none", "unknown", "ethernet"]) {
    const r = route(n)
    assert.equal(node(r, "ap").open, "wifi", n)
    assert.equal(node(r, "ph").open, "dns", n)
    assert.equal(node(r, "pc").open, "", n)
    if (node(r, "up")) assert.equal(node(r, "up").open, "", n + ": the upstream is a tooltip, not a door")
  }
})

test("leaks are a count on the Pi-hole's node: warning for profiles, urgent for a bypass", () => {
  assert.equal(node(route("healthy"), "ph").badge, null)
  assert.deepEqual(node(route("leaks"), "ph").badge, { n: 2, tone: "warning" })
  assert.deepEqual(node(route("bypassed"), "ph").badge, { n: 1, tone: "urgent" })
  const pend = Model.withPending(Model.emptyPending(), { pinUuid: Model.leakGroups(view("leaks")).profiles.uuids.join(" ") }, NOW_MS)
  assert.equal(node(Model.routeModel(view("leaks", pend), NOW_S, pend), "ph").badge, null, "pinned: gone at once")
  assert.equal(node(route("custom"), "ph").badge, null, "no Pi-hole in the path, no count")
})

test("before the first probe: the same route, dim, nothing flowing", () => {
  const r = route("unknown")
  assert.deepEqual(r.nodes.map((n) => n.id), ["pc", "ap", "ph", "up"])
  assert.equal(node(r, "ph").tone, "dim")
  assert.ok(r.links.every((l) => l.state === "dim" && !l.flow))
  assert.equal(r.flow.live, false)
})

test("with qnet down there is no route to draw", () => {
  const down = Model.effective(state("healthy"), Model.emptyPending(), NOW_MS, NOW_MS, true)
  const r = Model.routeModel(down, 0)
  assert.equal(r.kind, "nobackend")
  assert.deepEqual(r.nodes, [])
})

test("every fixture has a route, and nothing in it is invented or empty-handed", () => {
  for (const n of ["healthy", "paused", "fallback", "unreachable", "unconfigured", "leaks", "bypassed", "portal", "offline",
    "radio-off", "custom", "api-auth", "ethernet", "markup", "partial", "ethernet-bypassed", "degraded", "not-blocking",
    "none", "unknown", "unreachable-armed", "slow-gateway", "dbm"]) {
    const r = route(n)
    assert.ok(["route", "direct", "none", "offline", "checking"].includes(r.kind), n + " " + r.kind)
    assert.ok(r.nodes.length >= 1 && r.nodes[0].id === "pc", n)
    for (const nd of r.nodes) {
      assert.ok(["accent", "dim", "warning", "urgent"].includes(nd.tone), n + " " + nd.id)
      assert.ok(nd.label && (nd.label.text !== undefined || nd.label.key), n + " " + nd.id)
    }
    for (const l of r.links) assert.ok(["flow", "stalled", "dim", "dashed"].includes(l.state), n)
  }
})

test("untrusted text on the route is data: it reaches the picture as parts, never as markup", () => {
  const r = route("markup")
  assert.equal(node(r, "ap").tip, '<img src="https://example.invalid/tracker">', "the SSID is only a tooltip, drawn as plain text")
  const s = state("healthy")
  s.pihole.upstreams = [{ name: "<b>x</b>\u0007", ip: "9.9.9.9", port: 53, count: 1, responseMs: 1 }]
  assert.equal(Model.normalizeState(raw("healthy")).pihole.upstreams[0].name.indexOf("\u0007"), -1)
  const n = Model.normalizeState({ pihole: { upstreams: [{ name: "<b>x</b>\u0007", ip: "9.9.9.9", count: 1 }] } })
  assert.equal(n.pihole.upstreams[0].name, "<b>x</b>")
})

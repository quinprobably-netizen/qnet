"use strict"
// The DNS view's resolver chain as data (Model.chainModel): this PC,
// systemd-resolved, the Pi-hole, and one node per upstream the Pi-hole
// forwards to. ResolverChain only draws it.
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, state, raw, NOW_MS, NOW_S } = require("./helpers.js")

const chain = (name, pend) => Model.chainModel(view(name, pend), NOW_S)
const ids = (c) => c.nodes.map((n) => n.id)
const node = (c, id) => c.nodes.find((n) => n.id === id)
const text = (p) => (p ? (p.text !== undefined ? p.text : p.key + "|" + p.args.join(",")) : null)

test("healthy: this PC, systemd-resolved, the Pi-hole, then one node per upstream", () => {
  const c = chain("healthy")
  assert.equal(c.kind, "pihole")
  assert.deepEqual(ids(c), ["pc", "res", "ph", "up:0", "up:1"])
  assert.deepEqual(c.nodes.map((n) => n.depth), [0, 0, 0, 1, 1], "the upstreams hang off the trunk")
  assert.equal(text(node(c, "pc").label), "chain.pc|")
  assert.equal(text(node(c, "pc").sub), "192.168.1.242")
  assert.equal(text(node(c, "res").label), "chain.resolved|")
  assert.equal(text(node(c, "ph").label), "chain.pihole|")
  assert.equal(text(node(c, "ph").sub), ".153 ✓", "the address with its check")
  assert.equal(text(node(c, "ph").stat), "3 ms")
  assert.ok(c.nodes.every((n) => n.via === "flow" && n.viaTone === "accent"))
})

test("each upstream: its IP, its name, its share of the queries and its response time", () => {
  const c = chain("healthy")
  const u = node(c, "up:0")
  assert.equal(text(u.label), "9.9.9.9")
  assert.equal(text(u.sub), "dns.quad9.net")
  assert.equal(text(u.stat), "81% · 12 ms")
  assert.equal(text(node(c, "up:1").stat), "19% · 10 ms")
  const r = raw("healthy")
  r.pihole.upstreams = [{ name: "", ip: "9.9.9.9", port: 53, count: 10, responseMs: null }, { name: "x", ip: "", port: 53, count: 0, responseMs: 7 }]
  const odd = Model.chainModel(Model.effective(Model.normalizeState(r), Model.emptyPending(), NOW_MS, NOW_MS), NOW_S)
  assert.equal(node(odd, "up:0").sub, null, "no name, no second line")
  assert.equal(text(node(odd, "up:0").stat), "100%", "no response time known")
  assert.equal(text(node(odd, "up:1").label), "x", "a name stands in for a missing address")
  assert.equal(text(node(odd, "up:1").stat), "0% · 7 ms")
})

test("how the Pi-hole's answers divided is three labelled counts on its node, not a meter", () => {
  const ph = node(chain("healthy"), "ph")
  assert.deepEqual(ph.counts, [{ key: "blocklist", n: 164 }, { key: "cache", n: 470 }, { key: "forwarded", n: 570 }])
  for (const n of chain("healthy").nodes) if (n.id !== "ph") assert.equal(n.counts, null, n.id)
  const none = raw("healthy")
  none.pihole.answeredBy = { blocklist: 0, cache: 0, forwarded: 0 }
  const c = Model.chainModel(Model.effective(Model.normalizeState(none), Model.emptyPending(), NOW_MS, NOW_MS), NOW_S)
  assert.equal(node(c, "ph").counts, null, "nothing answered yet: nothing to count")
  assert.equal(JSON.stringify(ph).indexOf("percent"), -1, "no meter fields on the node")
})

test("paused: an outline with the countdown, the rest as it was", () => {
  const c = chain("paused")
  const ph = node(c, "ph")
  assert.equal(ph.glyph, "shieldOutline")
  assert.equal(ph.tone, "dim")
  assert.deepEqual([ph.stat.key, ph.stat.args[0], ph.statTone], ["route.paused", "4:32", "warning"])
  assert.deepEqual(ids(c), ["pc", "res", "ph", "up:0", "up:1"])
})

test("fallback: the resolver in use is a warning node beside the trunk, the Pi-hole greyed and crossed", () => {
  const c = chain("fallback")
  assert.deepEqual(ids(c), ["pc", "res", "side", "ph"], "no upstreams: the Pi-hole is not forwarding")
  const side = node(c, "side")
  assert.equal(side.depth, 1)
  assert.equal(side.tone, "warning")
  assert.equal(text(side.label), "192.168.1.1")
  assert.equal(text(side.stat), "chain.inUse|")
  assert.deepEqual([side.via, side.viaTone], ["flow", "warning"])
  const ph = node(c, "ph")
  assert.deepEqual([ph.tone, ph.glyph, ph.via], ["dim", "shieldOff", "dim"])
  assert.equal(text(ph.sub), ".153 ✕")
})

test("bypassed: the extra resolver is an urgent dashed side node, and names who", () => {
  const c = chain("bypassed")
  assert.deepEqual(ids(c), ["pc", "res", "side", "ph", "up:0", "up:1"], "the side node sits above the Pi-hole")
  const side = node(c, "side")
  assert.deepEqual([side.depth, side.tone, side.via, side.viaTone], [1, "urgent", "dashed", "urgent"])
  assert.equal(text(side.label), "router")
  assert.equal(text(side.sub), "chain.viaRa|", "arrives by IPv6 router advertisement")
  assert.equal(text(side.stat), "chain.bypass|")
  assert.equal(node(c, "ph").tone, "accent", "the Pi-hole itself is fine")
})

test("unreachable: a crossed urgent Pi-hole with its countdown, a stalled tube, upstreams dim and dashed, no counts", () => {
  const c = chain("unreachable")
  const ph = node(c, "ph")
  assert.deepEqual([ph.tone, ph.via, ph.glyph], ["urgent", "stalled", "shieldOff"])
  assert.equal(text(ph.stat), "hero.noAnswer|")
  assert.equal(ph.counts, null)
  for (const id of ["up:0", "up:1"]) assert.deepEqual([node(c, id).tone, node(c, id).via, node(c, id).viaTone], ["dim", "dashed", "dim"], id)
  const armed = chain("unreachable-armed")
  assert.equal(node(armed, "ph").stat.key, "hero.failoverIn")
  assert.equal(node(armed, "ph").statTone, "warning")
})

test("degraded: the upstreams turn warning, the first says why", () => {
  const c = chain("degraded")
  assert.equal(node(c, "up:0").tone, "warning")
  assert.equal(text(node(c, "up:0").stat), "upstream SERVFAIL")
  assert.equal(node(c, "up:0").statTone, "warning")
  assert.equal(text(node(c, "up:1").stat), "19% · 10 ms")
})

test("no Pi-hole in the path: the resolver in use ends the chain", () => {
  for (const [n, who, role] of [["unconfigured", "192.168.1.1", "route.role.router|"], ["custom", "9.9.9.9", "route.role.public|"]]) {
    const c = chain(n)
    assert.deepEqual(ids(c), ["pc", "res", "dest"], n)
    assert.equal(text(node(c, "dest").label), who, n)
    assert.equal(text(node(c, "dest").sub), role, n)
  }
  const eb = chain("ethernet-bypassed")
  assert.deepEqual([node(eb, "dest").tone, node(eb, "dest").viaTone, node(eb, "dest").statTone], ["urgent", "urgent", "urgent"])
})

test("no DNS, offline, checking and no backend", () => {
  const none = chain("none")
  assert.deepEqual(ids(none), ["pc", "res"])
  assert.equal(node(none, "res").tone, "urgent")
  assert.deepEqual([text(node(none, "res").sub)], ["route.none|9.9.9.9"])
  for (const [n, key] of [["offline", "route.offline"], ["radio-off", "route.wifiOff"]]) {
    const c = chain(n)
    assert.deepEqual(ids(c), ["pc"], n)
    assert.equal(node(c, "pc").tone, "dim")
    assert.equal(node(c, "pc").stat.key, key, n)
    assert.equal(c.flow.density, 0)
  }
  const unknown = chain("unknown")
  assert.deepEqual(ids(unknown), ["pc", "res", "ph"])
  assert.equal(node(unknown, "ph").via, "dim")
  const down = Model.effective(state("healthy"), Model.emptyPending(), NOW_MS, NOW_MS, true)
  assert.deepEqual(Model.chainModel(down, NOW_S).nodes, [])
})

test("the chain and the route agree on how the Pi-hole looks", () => {
  for (const n of ["healthy", "paused", "fallback", "unreachable", "degraded", "bypassed"]) {
    const r = Model.routeModel(view(n), NOW_S)
    const c = chain(n)
    const rp = r.nodes.find((x) => x.id === "ph")
    const cp = node(c, "ph")
    assert.equal(cp.tone, rp.tone, n)
    assert.equal(cp.glyph, rp.glyph, n)
    assert.equal(text(cp.sub), text(rp.label), n)
    assert.equal(text(cp.stat), text(rp.stat), n)
  }
})

test("every state the route knows has a chain", () => {
  for (const n of ["healthy", "partial", "paused", "fallback", "bypassed", "ethernet-bypassed", "unreachable", "unreachable-armed", "degraded",
    "none", "unconfigured", "offline", "radio-off", "custom", "unknown", "api-auth", "dbm", "ethernet", "markup", "portal", "leaks"]) {
    const c = chain(n)
    assert.ok(c.nodes.length >= 1, n)
    assert.equal(c.nodes[0].id, "pc", n)
    assert.equal(c.nodes.filter((x) => x.depth === 0).length >= 1, true, n)
    for (const x of c.nodes) assert.ok(["flow", "stalled", "dim", "dashed"].indexOf(x.via) >= 0, n + " " + x.id)
  }
})

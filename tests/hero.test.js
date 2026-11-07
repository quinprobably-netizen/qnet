"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, hero, state, BIN, NOW_MS } = require("./helpers.js")

// ---- the state word ----------------------------------------------------

test("healthy Pi-hole: accent word, via address and a quiet latency", () => {
  const h = hero("healthy")
  assert.equal(h.kind, "pihole")
  assert.equal(h.tone, "accent")
  assert.equal(h.frozen, false)
  assert.equal(h.setup, false)
  assert.equal(h.via, "192.168.1.153")
  assert.equal(h.latencyMs, 3.1)
  assert.equal(h.latencyBad, false)
  assert.equal(Model.formatLatency(h.latencyMs), "3 ms")
})

test("paused: dim word with the countdown", () => {
  const h = hero("paused")
  assert.equal(h.kind, "paused")
  assert.equal(h.tone, "dim")
  assert.equal(h.pauseS, 272)
  assert.equal(Model.formatCountdown(h.pauseS), "4:32")
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

test("unconfigured: the mode word, the setup link and an empty graph", () => {
  const h = hero("unconfigured")
  assert.equal(h.kind, "router")
  assert.equal(h.tone, "dim")
  assert.equal(h.setup, true)
  assert.equal(h.empty, true)
})

test("an active-link leak makes the hero say Bypassed; an inactive profile does not", () => {
  assert.equal(hero("bypassed").kind, "bypassed")
  assert.equal(hero("bypassed").tone, "urgent")
  assert.equal(hero("leaks").kind, "pihole", "a profile that would bypass is a line, not the hero")
})

test("Pi-hole answering from a non-Pi-hole server is Bypassed", () => {
  const s = state("healthy")
  s.dns.servers[0].role = "router"
  assert.equal(Model.heroState(Model.effective(s, Model.emptyPending(), NOW_MS, NOW_MS)).kind, "bypassed")
})

test("custom DNS and router DNS are dim; offline is dim and frozen", () => {
  assert.equal(hero("custom").kind, "custom")
  assert.equal(hero("custom").tone, "dim")
  const offline = hero("offline")
  assert.equal(offline.kind, "offline")
  assert.equal(offline.frozen, true)
  const s = state("healthy")
  s.dns.mode = "auto"
  assert.equal(Model.heroState(Model.effective(s, Model.emptyPending(), NOW_MS, NOW_MS)).kind, "router")
})

test("latency is urgent only past 100 ms or with failing probes", () => {
  const s = state("healthy")
  s.pihole.latencyMs = 140
  assert.equal(Model.heroState(Model.effective(s, Model.emptyPending(), NOW_MS, NOW_MS)).latencyBad, true)
  const t = state("healthy")
  t.pihole.probes[t.pihole.probes.length - 1].ok = false
  t.pihole.probes[t.pihole.probes.length - 1].ms = null
  assert.equal(Model.heroState(Model.effective(t, Model.emptyPending(), NOW_MS, NOW_MS)).latencyBad, true)
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
    "offline", "radio-off", "custom", "api-auth", "ethernet", "markup"]) {
    const h = hero(n)
    assert.ok(["pihole", "paused", "fallback", "bypassed", "unreachable", "router", "custom", "offline"].includes(h.kind), n)
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

test("tapping the lit tile does nothing; any other tile runs its verb", () => {
  assert.equal(Model.tapDns("pihole", view("healthy")), null)
  assert.deepEqual(Model.tapDns("auto", view("healthy")), { verb: "auto" })
  assert.equal(Model.tapDns("auto", view("unconfigured")), null)
  assert.deepEqual(Model.tapDns("pihole", view("unconfigured")), { verb: "pihole" })
  assert.equal(Model.tapDns("pihole", view("fallback")), null, "the warning tile is lit too")
  assert.deepEqual(Model.tapDns("pihole", view("custom")), { verb: "pihole" })
  assert.deepEqual(Model.tapDns("auto", view("custom")), { verb: "auto" })
  assert.equal(Model.tapDns("bogus", view("custom")), null)
})

test("a pending request lights the tile it asked for at once, and the other goes out", () => {
  const pend = Model.withPending(Model.emptyPending(), { dns: "auto" }, NOW_MS)
  const t = Model.dnsTiles(view("healthy", pend))
  assert.deepEqual([t.pihole, t.auto], ["off", "on"])
  assert.equal(Model.tapDns("auto", view("healthy", pend)), null, "a second tap on the pending tile is a no-op")
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

test("leaks: one line each, a Pin for an inactive profile", () => {
  const lines = Model.leakLines(view("leaks"))
  assert.equal(lines.length, 2)
  assert.equal(lines[0].where, "Wired connection 1")
  assert.equal(lines[0].would, true)
  assert.deepEqual(lines[0].action, { verb: "pin", uuid: "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66" })
  assert.equal(lines[0].detail, "uses router DNS (automatic)")
})

test("a leak on the active link is fixed by applying the Pi-hole to it", () => {
  const lines = Model.leakLines(view("bypassed"))
  assert.equal(lines.length, 1)
  assert.equal(lines[0].would, false)
  assert.deepEqual(lines[0].action, { verb: "pihole", uuid: "" })
})

test("a profile just pinned drops out of the list at once", () => {
  const pend = Model.withPending(Model.emptyPending(), { pinUuid: "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66" }, NOW_MS)
  const lines = Model.leakLines(view("leaks"), pend)
  assert.equal(lines.length, 1)
  assert.equal(lines[0].where, "Home-Guest")
})

test("no leaks, no lines; the compiled FallbackDNS is never a leak", () => {
  assert.deepEqual(Model.leakLines(view("healthy")), [])
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
})

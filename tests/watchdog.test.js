"use strict"
// The watchdog tab's data and navigation (Model.normalizeWatchdog, the route's
// doors, holdOrder, bayLayout, the gate clock, argvWatchdog, focusRows, Esc),
// over the golden fixtures tests/fixtures/watchdog-{rest,n30,arp,calm,mode}.json
// that `qnet watch` would stream (backend/src/bayfix.rs writes them).
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("fs")
const path = require("path")
const { Model, view, state, raw, NOW_MS, NOW_S, BIN } = require("./helpers.js")

const FIXTURES = ["rest", "n30", "arp", "calm", "mode"]
const wd = (n) => state("watchdog-" + n).watchdog
const mac = (n) => "02:00:00:00:" + ((n >> 8) & 255).toString(16).padStart(2, "0") + ":" + (n & 255).toString(16).padStart(2, "0")
const ids = (rows) => rows.map((r) => r.id)
const row = (rows, id) => rows.find((r) => r.id === id)
const jackOf = (n, tail) => wd(n).bay.jacks.find((j) => j.tail === tail)
const node = (r, id) => r.nodes.find((x) => x.id === id)

// A fixture's raw JSON changed by `edit`, as the view the panel draws.
function edited(name, edit) {
  const r = raw("watchdog-" + name)
  edit(r)
  return Model.effective(Model.normalizeState(r), Model.emptyPending(), NOW_MS, NOW_MS)
}
function layoutOf(v, ui) {
  const jacks = v.watchdog.bay.jacks
  return Model.bayLayout(Model.holdOrder([], jacks), ui || { ticketMac: "", scroll: 0 }, jacks)
}
// The rows the watchdog view has for a fixture with a ticket, flip, pin, scroll.
function rowsOf(v, ctx, scroll) {
  const c = Object.assign({ view: "watchdog", flip: false, ticket: null, pinOpen: false }, ctx || {})
  const jacks = v.watchdog.bay.jacks
  const order = Model.holdOrder([], jacks)
  c.order = order
  c.layout = Model.bayLayout(order, { ticketMac: c.ticket && c.ticket.kind === "device" ? c.ticket.mac : "", scroll: scroll || 0, ticket: !!c.ticket }, jacks)
  return Model.focusRows(v, c)
}

// ---- the fixtures are what the public repo may hold ------------------------

test("the golden fixtures use only the documentation range, 02:00:00:… MACs and the Quad9 upstream", () => {
  for (const n of FIXTURES) {
    const text = fs.readFileSync(path.join(__dirname, "fixtures", "watchdog-" + n + ".json"), "utf8")
    for (const a of text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)) {
      assert.ok(a.indexOf("192.0.2.") === 0 || a === "9.9.9.9", n + ": " + a)
    }
    for (const m of text.match(/\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b/g) || []) assert.ok(m.indexOf("02:00:00:") === 0, n + ": " + m)
  }
  const r = raw("watchdog-rest")
  assert.equal(r.link.ip4, "192.0.2.10", "this PC is the board's ·10")
  assert.equal(r.link.gateway, "192.0.2.1")
  assert.equal(r.pihole.address, "192.0.2.2", "qbp is the board's ·2")
  assert.equal(r.pihole.adminUrl, "https://192.0.2.2/admin/")
})

test("mode: only This PC and the Work laptop are cords to blocked; nothing is a ninth, offline jack", () => {
  const jacks = wd("mode").bay.jacks
  assert.equal(jacks.length, 8)
  assert.deepEqual(jacks.filter((j) => j.cord).map((j) => j.tail), ["·10", "·12"])
  assert.equal(jacks.some((j) => j.offline), false)
})

// ---- normalisation ---------------------------------------------------------

test("an empty state has an empty watchdog: status unknown, no jacks, no calls, five dark lamps", () => {
  const w = Model.emptyState().watchdog
  assert.equal(w.status, "unknown")
  assert.deepEqual(w.alerts, [])
  assert.deepEqual(w.devices, [])
  assert.deepEqual(w.bay.jacks, [])
  assert.deepEqual(w.bay.calls, [])
  assert.deepEqual(w.bay.lamps.map((l) => l.kind), ["threat", "new_device", "arp_spoof", "rebind", "lookups"])
  assert.ok(w.bay.lamps.every((l) => l.count === 0 && l.tone === "" && l.alertId === null))
  assert.deepEqual([w.rev, w.polledAt, w.devicesAt, w.knownCount, w.bay.flipCount, w.bay.quietSince], [0, 0, 0, 0, 0, 0])
  assert.equal(w.exemptDefault, false)
  assert.equal(w.pinSet, false)
  assert.equal(Model.normalizeState({ watchdog: "no" }).watchdog.status, "unknown")
  assert.equal(Model.normalizeState({ watchdog: [] }).watchdog.bay.jacks.length, 0)
  assert.equal(state("healthy").watchdog.status, "unknown", "a state with no watchdog key")
})

test("every golden fixture normalises with its jacks, lamps and calls intact", () => {
  for (const n of FIXTURES) {
    const w = wd(n)
    const r = raw("watchdog-" + n).watchdog
    assert.equal(w.status, "ok", n)
    assert.equal(w.bay.jacks.length, r.bay.jacks.length, n)
    assert.deepEqual(w.bay.jacks, r.bay.jacks, n + ": a valid jack is kept as it is")
    assert.deepEqual(w.bay.lamps, r.bay.lamps, n)
    assert.deepEqual(w.bay.calls, r.bay.calls, n)
    assert.deepEqual(w.alerts, r.alerts, n)
    assert.deepEqual(w.devices, r.devices, n)
    assert.equal(w.bay.flipCount, r.bay.flipCount, n)
    assert.equal(w.bay.quietSince, r.bay.quietSince, n)
    for (const k of ["rev", "suppressed", "unacked", "knownList", "knownCount", "pushedAt", "pushError", "polledAt", "exemptDefault", "exemptDefaultOnPi", "pinSet", "devicesAt"]) {
      assert.deepEqual(w[k], r[k], n + " " + k)
    }
  }
  assert.equal(wd("rest").bay.jacks.length, 8)
  assert.equal(wd("n30").bay.jacks.length, 30)
  assert.equal(wd("n30").devices.length, 28, "the devices the Pi reports; two jacks are offline")
  assert.equal(wd("mode").exemptDefault, true)
  assert.equal(wd("calm").bay.calls.length, 0)
})

test("a jack's gate, lamp and wiring come through as the backend worked them out", () => {
  const phone = jackOf("rest", "·23")
  assert.equal(phone.gateUntil, NOW_S + 872)
  assert.deepEqual([phone.patch, phone.row, phone.cord], ["blocked", "blocked", false])
  const tv = jackOf("rest", "·40")
  assert.deepEqual([tv.patch, tv.row, tv.cord, tv.lamp, tv.alertId, tv.rank], ["pass", "pass", true, "high", 1, 0])
  assert.deepEqual(tv.strip, ["Living", "room TV"])
  const fresh = jackOf("rest", "·216")
  assert.deepEqual([fresh.isNew, fresh.known, fresh.lamp, fresh.alertId, fresh.name, fresh.strip], [true, false, "warn", 2, "", []])
  assert.equal(jackOf("n30", ":0f").offline, true)
  assert.equal(jackOf("n30", ":0f").ip, "")
  assert.equal(jackOf("n30", "·31").patch, "fixed")
})

test("hostile input: enums, numbers, strings, ids and MACs are checked, and nothing unknown is kept", () => {
  const evil = {
    watchdog: {
      status: "owned", rev: -5, suppressed: "7", unacked: 1e99, knownList: "everything",
      alerts: [
        { id: 1, key: "a1b2c3d400000001", kind: "bea\u0007con", severity: "catastrophic", title: "T\u202eitle", client: "192.0.2.5; reboot", subject: "x".repeat(900), count: -3, acked: "yes", extra: "<b>" },
        { id: "2", key: "a1b2c3d400000002", kind: "threat" },
        { id: 3, key: "NOT-HEX-KEY-0000", kind: "threat" },
        { id: 4, key: "a1b2c3d400000004", kind: "" },
        { id: 5, key: "a1b2c3d400000005", kind: "dga", client: "192.0.2.9" },
        { id: 5, key: "a1b2c3d400000006", kind: "dga" },
        7, null, "x"
      ],
      devices: [{ mac: "02:00:00:00:00:01", ipv4: ["192.0.2.1", "999.1.1.1", "x", "1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"], hostname: "h\u0000" + "n".repeat(200), label: "l".repeat(200) },
        { mac: "02:00:00:00:00:ZZ" }, { mac: "02-00-00-00-00-01" }, { mac: "02:00:00:00:00:01" }],
      bay: {
        jacks: [
          { mac: "02:00:00:00:00:0a", ip: "192.0.2.10", tail: "<script>", hostname: "ho\u001bst", name: "N".repeat(200), strip: ["abc", "def", "ghi", 7, "x".repeat(40)],
            known: 1, isNew: "true", offline: "no", patch: "root", row: "sideways", cord: "yes", gateUntil: "soon", lamp: "red", alertId: "1", rank: 9, firstUnix: -1, lastUnix: 1e30, evil: true },
          { mac: "02:00:00:00:00:0A" }, { mac: "nope" }, { mac: 5 }, null, "str",
          { mac: "02:00:00:00:00:0b", ip: "not-an-ip", strip: "abc", gateUntil: 0, offline: true },
          { mac: "02:00:00:00:00:0a", name: "duplicate" }
        ],
        lamps: [
          { kind: "rebind", count: 3, tone: "high", alertId: 4 },
          { kind: "bogus", count: 9, tone: "high", alertId: 1 },
          { kind: "threat", count: "x", tone: "red", alertId: -2 },
          { kind: "rebind", count: 1, tone: "", alertId: null }
        ],
        calls: [
          { id: 1, key: "a1b2c3d400000001", kind: "threat", lamp: "weird", severity: "high", tone: "loud", mac: "02:00:00:00:00:ZZ", relatedMac: "Q", subject: "s\u0000" + "x".repeat(400), count: 2, lastUnix: 10 },
          { id: 2, key: "bad", kind: "threat" },
          { id: 3, key: "a1b2c3d400000003", kind: "dga", severity: "warn", lastUnix: 20 },
          { id: 3, key: "a1b2c3d400000009", kind: "dga", lastUnix: 99 },
          { id: 4, key: "a1b2c3d400000004", kind: "mystery", severity: "info", lastUnix: 20 }
        ],
        flipCount: -1, quietSince: "x"
      }
    }
  }
  const w = Model.normalizeState(evil).watchdog
  assert.deepEqual([w.status, w.rev, w.suppressed, w.unacked, w.knownList], ["unknown", 0, 7, 999999, ""])
  assert.deepEqual(w.alerts.map((a) => a.id), [1, 5], "no usable id, key or kind: dropped; a repeated id: the first")
  const a = w.alerts[0]
  assert.deepEqual([a.kind, a.severity, a.title, a.client, a.count, a.acked], ["beacon", "info", "Title", null, 0, false])
  assert.equal(a.subject.length, 255)
  assert.equal(w.alerts[1].client, "192.0.2.9")
  assert.equal(Object.keys(a).includes("extra"), false, "unknown fields are not carried")
  assert.equal(w.devices.length, 1, "bad and repeated MACs are dropped")
  assert.deepEqual(w.devices[0].ipv4, ["192.0.2.1", "1.2.3.4", "1.2.3.5", "1.2.3.6"], "at most four addresses, each a dotted quad")
  assert.equal(w.devices[0].hostname.length, 64)
  assert.equal(w.devices[0].label.length, 64)
  assert.equal(w.devices[0].hostname.indexOf("\u0000"), -1)
  assert.deepEqual(w.bay.jacks.map((j) => j.mac), ["02:00:00:00:00:0a", "02:00:00:00:00:0b"])
  const j = w.bay.jacks[0]
  assert.equal(j.tail, "·10", "a bad tail is worked out from the address")
  assert.equal(j.hostname, "host")
  assert.equal(j.name.length, 64)
  assert.deepEqual(j.strip, ["abc", "def"], "at most two lines")
  assert.deepEqual([j.known, j.isNew, j.offline, j.cord], [false, false, false, false])
  assert.deepEqual([j.patch, j.row, j.gateUntil, j.lamp, j.alertId, j.rank], ["blocked", "blocked", null, "", null, 2])
  assert.deepEqual([j.firstUnix, j.lastUnix], [0, 4102444800])
  assert.equal(Object.keys(j).includes("evil"), false)
  const off = w.bay.jacks[1]
  assert.deepEqual([off.ip, off.tail, off.strip, off.gateUntil, off.rank], ["", ":0b", [], null, 3], "offline without a rank reads as offline; a MAC tail without an address")
  assert.deepEqual(w.bay.lamps.map((l) => l.kind), ["threat", "new_device", "arp_spoof", "rebind", "lookups"], "always the five, in order")
  assert.deepEqual(w.bay.lamps[3], { kind: "rebind", count: 3, tone: "high", alertId: 4 }, "the first one of a kind")
  assert.deepEqual(w.bay.lamps[0], { kind: "threat", count: 0, tone: "", alertId: null }, "bad numbers and tones read as nothing")
  assert.deepEqual(w.bay.lamps[1], { kind: "new_device", count: 0, tone: "", alertId: null }, "a missing lamp is dark")
  assert.deepEqual(w.bay.calls.map((c) => c.id), [3, 4, 1], "newest first; a repeated id and a bad key are dropped; ties keep their order")
  const c1 = w.bay.calls[2]
  assert.deepEqual([c1.lamp, c1.tone, c1.mac, c1.relatedMac, c1.severity], ["threat", "high", null, null, "high"], "lamp and tone are worked out when the backend's are not valid")
  assert.equal(c1.subject.length, 255)
  assert.equal(w.bay.calls[1].lamp, "lookups", "an unknown kind rings the lookups lamp")
  assert.equal(w.bay.calls[1].tone, "warn")
  assert.deepEqual([w.bay.flipCount, w.bay.quietSince], [0, 0])
})

test("the arrays are capped: 256 jacks, 50 calls and alerts, 128 devices", () => {
  const jacks = []
  const calls = []
  const alerts = []
  const devices = []
  for (let i = 0; i < 400; i++) {
    jacks.push({ mac: mac(i), ip: "192.0.2.1" })
    calls.push({ id: i, key: "a1b2c3d4" + i.toString(16).padStart(8, "0"), kind: "threat", lastUnix: i })
    alerts.push({ id: i, key: "a1b2c3d4" + i.toString(16).padStart(8, "0"), kind: "threat" })
    devices.push({ mac: mac(i) })
  }
  const w = Model.normalizeState({ watchdog: { alerts, devices, bay: { jacks, calls } } }).watchdog
  assert.equal(w.bay.jacks.length, 256)
  assert.equal(w.bay.calls.length, 50)
  assert.equal(w.alerts.length, 50)
  assert.equal(w.devices.length, 128)
  assert.equal(w.bay.jacks[255].mac, mac(255), "the first ones are kept, in order")
})

test("a bad strip, tail or unix time never reaches the panel", () => {
  const w = Model.normalizeState({ watchdog: { bay: { jacks: [
    { mac: mac(1), tail: "·999999", strip: [{}, "a\u0007b", "", "ok"] },
    { mac: mac(2), ip: "192.0.2.77", tail: ":zz", gateUntil: -9 },
    { mac: mac(3), gateUntil: 1794123572.9 }
  ] } } }).watchdog
  assert.deepEqual(w.bay.jacks.map((j) => j.tail), [":01", "·77", ":03"])
  assert.deepEqual(w.bay.jacks[0].strip, ["ab", "ok"])
  assert.equal(w.bay.jacks[1].gateUntil, null)
  assert.equal(w.bay.jacks[2].gateUntil, 1794123572, "whole seconds")
})

test("the view carries the watchdog", () => {
  assert.equal(view("watchdog-rest").watchdog.bay.jacks.length, 8)
  assert.equal(view("healthy").watchdog.status, "unknown")
})

// ---- the route -------------------------------------------------------------

test("watchdogPresent: answered ok, or answered once and failing since; never absent, unconfigured or unknown", () => {
  const p = (status, polledAt) => Model.watchdogPresent({ watchdog: Model.normalizeState({ watchdog: { status, polledAt } }).watchdog })
  assert.equal(p("ok", 0), true)
  assert.equal(p("ok", 5), true)
  assert.equal(p("auth", 5), true)
  assert.equal(p("tls", 5), true)
  assert.equal(p("unreachable", 5), true)
  assert.equal(p("auth", 0), false)
  assert.equal(p("unreachable", 0), false)
  assert.equal(p("absent", 5), false, "a real Pi-hole answers too, and there is nothing to open")
  assert.equal(p("unconfigured", 5), false)
  assert.equal(p("unknown", 5), false)
  assert.equal(Model.watchdogPresent({}), false)
  assert.equal(Model.watchdogPresent(null), false)
  assert.equal(Model.watchdogPresent(view("healthy")), false)
  for (const n of FIXTURES) assert.equal(Model.watchdogPresent(view("watchdog-" + n)), true, n)
})

test("with a watchdog the Pi-hole's place opens it, carrying the calls waiting; the resolver beyond opens DNS", () => {
  for (const n of FIXTURES) {
    const r = Model.routeModel(view("watchdog-" + n), NOW_S)
    assert.equal(r.kind, "route", n)
    assert.deepEqual(r.nodes.map((x) => x.id), ["pc", "ap", "ph", "up"], n)
    assert.equal(node(r, "ph").open, "watchdog", n)
    assert.equal(node(r, "up").open, "dns", n)
    assert.equal(node(r, "ap").open, "wifi", n)
  }
  const badge = (n) => node(Model.routeModel(view("watchdog-" + n), NOW_S), "ph").badge
  assert.deepEqual(badge("rest"), { n: 2, tone: "urgent" }, "a high call makes it urgent")
  assert.deepEqual(badge("n30"), { n: 2, tone: "urgent" })
  assert.deepEqual(badge("arp"), { n: 3, tone: "urgent" })
  assert.deepEqual(badge("mode"), { n: 2, tone: "urgent" })
  assert.equal(badge("calm"), null, "no calls waiting, no count")
})

test("calls that are all warnings are a warning badge", () => {
  const v = edited("rest", (r) => {
    r.watchdog.bay.calls = r.watchdog.bay.calls.filter((c) => c.kind === "new_device")
  })
  assert.deepEqual(node(Model.routeModel(v, NOW_S), "ph").badge, { n: 1, tone: "warning" })
})

test("the leak badge is on the resolver's node, and the Pi-hole's carries the calls", () => {
  const r = Model.routeModel(view("watchdog-rest"), NOW_S)
  assert.deepEqual(node(r, "up").badge, { n: 2, tone: "warning" }, "the fixture's machine has two profiles that bypass the Pi-hole")
  assert.deepEqual(node(r, "ph").badge, { n: 2, tone: "urgent" })
})

test("a failing watchdog that answered once keeps its door; one that never answered, or is absent, opens DNS", () => {
  const door = (edit) => {
    const v = edited("rest", edit)
    const r = Model.routeModel(v, NOW_S)
    return [node(r, "ph").open, node(r, "ph").badge, Model.routeTarget(v, "ph")]
  }
  assert.deepEqual(door((r) => { r.watchdog.status = "unreachable" }), ["watchdog", { n: 2, tone: "urgent" }, "watchdog"])
  assert.deepEqual(door((r) => { r.watchdog.status = "auth"; r.watchdog.polledAt = 0 }), ["dns", null, "dns"])
  assert.deepEqual(door((r) => { r.watchdog.status = "absent" }), ["dns", null, "dns"], "absent keeps polledAt on the Pi's side; still no tab")
  assert.deepEqual(door((r) => { r.watchdog.status = "unconfigured" }), ["dns", null, "dns"])
  assert.deepEqual(door((r) => { delete r.watchdog }), ["dns", null, "dns"])
})

test("routeStops and routeTarget follow the doors", () => {
  assert.deepEqual(Model.routeStops(view("watchdog-rest")), ["ap", "ph", "up"])
  assert.equal(Model.routeTarget(view("watchdog-rest"), "ph"), "watchdog")
  assert.equal(Model.routeTarget(view("watchdog-rest"), "up"), "dns")
  assert.equal(Model.routeTarget(view("watchdog-rest"), "ap"), "wifi")
  assert.equal(Model.routeTarget(view("watchdog-rest"), "pc"), "")
  assert.equal(Model.routeTarget(view("healthy"), "ph"), "dns")
})

test("the no-DNS node stays the way to the DNS view even with a watchdog: nothing is beyond it", () => {
  const v = Model.effective(Model.normalizeState(Object.assign({}, raw("none"), { watchdog: raw("watchdog-rest").watchdog })), Model.emptyPending(), NOW_MS, NOW_MS)
  const r = Model.routeModel(v, NOW_S)
  assert.equal(r.kind, "none")
  assert.equal(node(r, "ph").open, "dns")
  assert.equal(node(r, "ph").badge, null)
})

test("the Pi-hole in the way but idle, and the first-probe route, take the same doors", () => {
  const wdOf = raw("watchdog-rest").watchdog
  for (const n of ["custom", "unknown"]) {
    const v = Model.effective(Model.normalizeState(Object.assign({}, raw(n), { watchdog: wdOf })), Model.emptyPending(), NOW_MS, NOW_MS)
    const r = Model.routeModel(v, NOW_S)
    assert.equal(node(r, "ph").open, "watchdog", n)
    assert.deepEqual(node(r, "ph").badge, { n: 2, tone: "urgent" }, n)
    assert.equal(node(r, "up").open, "dns", n)
  }
})

test("main view's route row has the resolver as a stop, and the cursor still starts on the route", () => {
  const rows = Model.focusRows(view("watchdog-rest"), { view: "main" })
  assert.deepEqual(row(rows, "route").items, ["ap", "ph", "up"])
  assert.deepEqual(Model.initialCursor(rows, "main"), { row: "route", item: 0 })
})

// ---- navigation ------------------------------------------------------------

test("navOpen takes the watchdog view with no effects; back returns to where the cursor was", () => {
  const o = Model.navOpen(Model.navInit(), "watchdog", { row: "route", item: 1 })
  assert.equal(o.nav.view, "watchdog")
  assert.deepEqual(o.effects, [])
  assert.deepEqual(o.nav.returnCursor, { row: "route", item: 1 })
  assert.equal(Model.navOpen(o.nav, "watchdog", null).nav, o.nav, "already there")
  const b = Model.navBack(o.nav)
  assert.deepEqual([b.nav.view, b.left, b.cursor], ["main", true, { row: "route", item: 1 }])
  const from = Model.navOpen(Model.navOpen(Model.navInit(), "dns", { row: "route", item: 2 }).nav, "watchdog", null)
  assert.equal(from.nav.view, "watchdog")
  assert.deepEqual(from.nav.returnCursor, { row: "route", item: 2 }, "one back to the main view")
})

test("Esc: pin, flip, ticket, in that order, after the older steps and before back", () => {
  const e = Model.escapeStep
  const all = { armed: true, confirm: true, password: true, pin: true, flip: true, ticket: true, view: "watchdog" }
  assert.equal(e(all), "disarm")
  delete all.armed
  assert.equal(e(all), "confirm")
  delete all.confirm
  assert.equal(e(all), "password")
  delete all.password
  assert.equal(e(all), "pin")
  delete all.pin
  assert.equal(e(all), "flip")
  delete all.flip
  assert.equal(e(all), "ticket")
  delete all.ticket
  assert.equal(e(all), "back")
  assert.equal(e({ view: "main" }), "close")
  assert.equal(e({ ticket: { kind: "device", mac: mac(1) }, view: "watchdog" }), "ticket", "a ticket object counts")
  assert.equal(e({ pinOpen: true, view: "watchdog" }), "pin")
  assert.equal(e({ ticket: null, flip: false, pin: false, view: "watchdog" }), "back")
})

// ---- the held order --------------------------------------------------------

test("holdOrder: the jacks' order at first; then the held ones that still exist, new ones at the end", () => {
  const jacks = wd("rest").bay.jacks
  const first = Model.holdOrder([], jacks)
  assert.deepEqual(first, jacks.map((j) => j.mac))
  assert.deepEqual(Model.holdOrder(undefined, jacks), first)
  assert.deepEqual(Model.holdOrder(null, jacks), first)
  assert.deepEqual(Model.holdOrder([], []), [])
  // the alert on ·40 goes away and a label changes: the jacks arrive in another order, the board stays
  const shuffled = [jacks[2], jacks[7], jacks[0], jacks[5], jacks[1], jacks[3], jacks[4], jacks[6]]
  assert.deepEqual(Model.holdOrder(first, shuffled), first)
  // a device that left drops out, a new one goes last, whatever its rank
  const fresh = { mac: mac(99) }
  const next = Model.holdOrder(first, [fresh].concat(jacks.filter((j) => j.tail !== "·12")))
  assert.deepEqual(next, first.filter((m) => m !== mac(12)).concat([mac(99)]))
  // the held order wins over a bigger list
  assert.deepEqual(Model.holdOrder([mac(51), mac(40)], [{ mac: mac(40) }, { mac: mac(51) }, { mac: mac(2) }]), [mac(51), mac(40), mac(2)])
  // junk and repeats are ignored
  assert.deepEqual(Model.holdOrder([mac(1), mac(1), 5, null], [{ mac: mac(1) }, { mac: mac(1) }, null, {}, { mac: 3 }]), [mac(1)])
  assert.deepEqual(Model.holdOrder("x", [{ mac: mac(1) }]), [mac(1)])
  assert.deepEqual(Model.holdOrder([mac(1)], "x"), [])
  const prev = [mac(1), mac(2)]
  Model.holdOrder(prev, [{ mac: mac(3) }])
  assert.deepEqual(prev, [mac(1), mac(2)], "the held order is not changed in place")
})

// ---- the bays --------------------------------------------------------------

test("bayLayout, 8 devices: one bay, everything shown, no pager", () => {
  const l = layoutOf(view("watchdog-rest"))
  assert.equal(l.bays.length, 1)
  assert.equal(l.bays[0].length, 8)
  assert.deepEqual(l.shown, [0, 1])
  assert.equal(l.scroll, 0)
  assert.equal(l.pager, null)
  assert.deepEqual(l.bays[0], wd("rest").bay.jacks.map((j) => j.mac))
})

test("bayLayout, up to 16 devices: both bays shown, no pager; 17 gets one", () => {
  const order = Array.from({ length: 16 }, (_, i) => mac(i + 1))
  const l = Model.bayLayout(order, { ticketMac: "", scroll: 0 })
  assert.deepEqual([l.bays.length, l.shown, l.pager], [2, [0, 2], null])
  const l17 = Model.bayLayout(order.concat([mac(17)]), { ticketMac: "", scroll: 0 })
  assert.deepEqual(l17.bays.map((b) => b.length), [8, 8, 1])
  assert.deepEqual(l17.pager, { from: 1, to: 2, total: 3, upRing: false, downRing: false, canUp: false, canDown: true })
  assert.deepEqual(Model.bayLayout(order.slice(0, 3), { ticketMac: "", scroll: 5 }).bays, [order.slice(0, 3)])
  const empty = Model.bayLayout([], { ticketMac: "", scroll: 3 })
  assert.deepEqual(empty, { bays: [], shown: [0, 0], scroll: 0, pager: null })
  assert.deepEqual(Model.bayLayout(undefined, undefined), empty)
})

test("bayLayout, 30 devices: four bays of 8, 8, 8 and 6, two in view, the pager says which", () => {
  const v = view("watchdog-n30")
  const l = layoutOf(v)
  assert.deepEqual(l.bays.map((b) => b.length), [8, 8, 8, 6])
  assert.deepEqual(l.shown, [0, 2])
  assert.deepEqual(l.pager, { from: 1, to: 2, total: 4, upRing: false, downRing: false, canUp: false, canDown: true })
  const mid = layoutOf(v, { ticketMac: "", scroll: 1 })
  assert.deepEqual([mid.shown, mid.scroll], [[1, 2], 1])
  assert.deepEqual(mid.pager, { from: 2, to: 3, total: 4, upRing: true, downRing: false, canUp: true, canDown: true }, "the alerting jacks are in bay 1, above")
  const end = layoutOf(v, { ticketMac: "", scroll: 2 })
  assert.deepEqual(end.pager, { from: 3, to: 4, total: 4, upRing: true, downRing: false, canUp: true, canDown: false })
  assert.deepEqual(end.bays[3].length, 6)
})

test("bayLayout clamps the scroll to what exists, and a bad one is 0", () => {
  const v = view("watchdog-n30")
  assert.equal(layoutOf(v, { ticketMac: "", scroll: 99 }).scroll, 2)
  assert.deepEqual(layoutOf(v, { ticketMac: "", scroll: 99 }).shown, [2, 2])
  assert.equal(layoutOf(v, { ticketMac: "", scroll: -4 }).scroll, 0)
  assert.equal(layoutOf(v, { ticketMac: "", scroll: NaN }).scroll, 0)
  assert.equal(layoutOf(v, { ticketMac: "", scroll: "x" }).scroll, 0)
  assert.equal(layoutOf(v, { ticketMac: "", scroll: 1.7 }).scroll, 1)
  assert.equal(layoutOf(v, {}).scroll, 0)
  assert.equal(layoutOf(v, null).scroll, 0)
})

test("bayLayout with a ticket open shows that jack's bay alone and scrolls to it", () => {
  const v = view("watchdog-n30")
  const jacks = v.watchdog.bay.jacks
  const old = jacks.find((j) => j.tail === ":0f")
  const l = layoutOf(v, { ticketMac: old.mac, scroll: 0 })
  assert.deepEqual(l.shown, [3, 1], "the offline laptop is in the last bay")
  assert.equal(l.scroll, 3)
  assert.deepEqual(l.pager, { from: 4, to: 4, total: 4, upRing: true, downRing: false, canUp: true, canDown: false })
  const near = layoutOf(v, { ticketMac: jacks[9].mac, scroll: 3 })
  assert.deepEqual(near.shown, [1, 1], "the ticket's bay wins over the scroll")
  assert.deepEqual(near.pager, { from: 2, to: 2, total: 4, upRing: true, downRing: false, canUp: true, canDown: true })
  const top = layoutOf(v, { ticketMac: jacks[0].mac, scroll: 2 })
  assert.deepEqual(top.shown, [0, 1])
  assert.deepEqual(top.pager.upRing, false)
  // with two bays a ticket still shrinks the board, and then a pager appears
  const two = Array.from({ length: 16 }, (_, i) => mac(i + 1))
  const t = Model.bayLayout(two, { ticketMac: mac(12), scroll: 0 })
  assert.deepEqual([t.shown, t.pager.total, t.pager.canUp, t.pager.canDown], [[1, 1], 2, true, false])
  // a ticket with no jack (the ARP spoof's) shrinks it at the scroll it had
  const arp = Model.bayLayout(two, { ticketMac: "", scroll: 1, ticket: true })
  assert.deepEqual([arp.shown, arp.scroll], [[1, 1], 1])
  // a ticket for a jack that is gone shows nothing special
  assert.deepEqual(Model.bayLayout(two, { ticketMac: mac(500), scroll: 0 }).shown, [0, 1])
  // one bay: nothing to page, ticket or not
  assert.equal(layoutOf(view("watchdog-rest"), { ticketMac: wd("rest").bay.jacks[3].mac, scroll: 0 }).pager, null)
})

test("the rings: an alerting jack in a bay above or below the ones in view", () => {
  const v = view("watchdog-n30")
  const jacks = v.watchdog.bay.jacks
  // the order reversed: the alerting ·40 and ·216 sit in the last bay, the offline pair first
  const rev = Model.holdOrder([], jacks.slice().reverse())
  const top = Model.bayLayout(rev, { ticketMac: "", scroll: 0 }, jacks)
  assert.deepEqual([top.pager.upRing, top.pager.downRing], [false, true], "below")
  const mid = Model.bayLayout(rev, { ticketMac: "", scroll: 1 }, jacks)
  assert.deepEqual([mid.pager.upRing, mid.pager.downRing], [false, true], "bays 1 and 2 are in view, bay 3 is still below")
  const bottom = Model.bayLayout(rev, { ticketMac: "", scroll: 2 }, jacks)
  assert.deepEqual([bottom.pager.upRing, bottom.pager.downRing], [false, false], "bay 3 is in view")
  // and with the alert in the first bay, scrolled past it
  const first = Model.bayLayout(Model.holdOrder([], jacks), { ticketMac: "", scroll: 2 }, jacks)
  assert.deepEqual([first.pager.upRing, first.pager.downRing], [true, false], "above")
  // no jacks given, no rings
  assert.deepEqual([Model.bayLayout(rev, { scroll: 0 }).pager.upRing, Model.bayLayout(rev, { scroll: 0 }).pager.downRing], [false, false])
  // a lamp "" is no alert
  const calm = view("watchdog-calm").watchdog.bay.jacks
  const mixed = Model.bayLayout(Array.from({ length: 30 }, (_, i) => mac(i + 1)), { scroll: 0 }, calm.concat([{ mac: mac(30), lamp: "" }]))
  assert.deepEqual([mixed.pager.upRing, mixed.pager.downRing], [false, false])
  const lit = Model.bayLayout(Array.from({ length: 30 }, (_, i) => mac(i + 1)), { scroll: 0 }, [{ mac: mac(30), lamp: "warn" }])
  assert.deepEqual([lit.pager.upRing, lit.pager.downRing], [false, true])
})

// ---- the gate clock --------------------------------------------------------

test("gateLeft counts down to gateUntil, and is 0 with no gate or past it", () => {
  const phone = jackOf("rest", "·23")
  assert.equal(Model.gateLeft(phone, NOW_S), 872)
  assert.equal(Model.gateLeft(phone, NOW_S + 100), 772)
  assert.equal(Model.gateLeft(phone, NOW_S + 871.2), 1, "a part of a second still counts")
  assert.equal(Model.gateLeft(phone, NOW_S + 872), 0)
  assert.equal(Model.gateLeft(phone, NOW_S + 5000), 0)
  assert.equal(Model.gateLeft(jackOf("rest", "·51"), NOW_S), 0, "no gate")
  assert.equal(Model.gateLeft({ gateUntil: null }, NOW_S), 0)
  assert.equal(Model.gateLeft({}, NOW_S), 0)
  assert.equal(Model.gateLeft(null, NOW_S), 0)
  assert.equal(Model.gateLeft({ gateUntil: "soon" }, NOW_S), 0)
})

test("formatGate: m:ss with unpadded minutes", () => {
  assert.equal(Model.formatGate(872), "14:32")
  assert.equal(Model.formatGate(300), "5:00")
  assert.equal(Model.formatGate(59), "0:59")
  assert.equal(Model.formatGate(60), "1:00")
  assert.equal(Model.formatGate(61), "1:01")
  assert.equal(Model.formatGate(1800), "30:00")
  assert.equal(Model.formatGate(3600), "60:00")
  assert.equal(Model.formatGate(0), "0:00")
  assert.equal(Model.formatGate(-5), "0:00")
  assert.equal(Model.formatGate(NaN), "0:00")
  assert.equal(Model.formatGate(871.9), "14:31")
  assert.equal(Model.formatGate(Model.gateLeft(jackOf("rest", "·23"), NOW_S)), "14:32", "the mockup's 14:32 at the fixture's clock")
})

test("needsClock: the watchdog view ticks while a gate is open, and stops when it has run out", () => {
  const rest = view("watchdog-rest")
  const p = Model.emptyPending()
  assert.equal(Model.needsClock(rest, p, NOW_S), false, "a quiet view needs no clock")
  assert.equal(Model.needsClock(rest, p, NOW_S, { view: "main" }), false, "a gate counts down only on its own view")
  assert.equal(Model.needsClock(rest, p, NOW_S, { view: "watchdog" }), true)
  assert.equal(Model.needsClock(rest, p, NOW_S + 871, { view: "watchdog" }), true)
  assert.equal(Model.needsClock(rest, p, NOW_S + 872, { view: "watchdog" }), false)
  assert.equal(Model.needsClock(view("watchdog-calm"), p, NOW_S, { view: "watchdog" }), false, "no gate open")
  assert.equal(Model.needsClock(rest, p, NOW_S, {}), false)
  assert.equal(Model.needsClock(rest, p, NOW_S, null), false)
  // the old reasons still hold, with or without the context
  const paused = view("paused")
  assert.equal(Model.needsClock(paused, p, NOW_S), true)
  assert.equal(Model.needsClock(paused, p, NOW_S, { view: "watchdog" }), true)
  assert.equal(Model.needsClock(view("healthy"), Model.withPending(p, { pause: "pause" }, NOW_MS), NOW_S, { view: "watchdog" }), true)
  assert.equal(Model.needsClock(view("healthy"), p, NOW_S, { view: "watchdog" }), false, "no watchdog at all")
})

// ---- argv ------------------------------------------------------------------

const M1 = "02:00:00:00:00:17"

test("argvWatchdog: each verb builds its argv through the absolute binary", () => {
  const a = (verb, args) => Model.argvWatchdog(BIN, verb, args)
  assert.deepEqual(a("patch", [M1, "pass"]), [BIN, "watchdog", "patch", M1, "pass"])
  assert.deepEqual(a("patch", [M1, "blocked"]), [BIN, "watchdog", "patch", M1, "blocked"])
  for (const s of [0, 300, 1800, 3600]) assert.deepEqual(a("gate", [M1, s]), [BIN, "watchdog", "gate", M1, String(s)])
  assert.deepEqual(a("gate", [M1, "1800"]), [BIN, "watchdog", "gate", M1, "1800"], "a number as text")
  assert.deepEqual(a("label", [M1, "Living room TV"]), [BIN, "watchdog", "label", M1, "Living room TV"])
  assert.deepEqual(a("label", [M1]), [BIN, "watchdog", "label", M1], "no text: clear")
  assert.deepEqual(a("know", [M1]), [BIN, "watchdog", "know", M1])
  assert.deepEqual(a("forget", [M1]), [BIN, "watchdog", "forget", M1])
  assert.deepEqual(a("ack", [7]), [BIN, "watchdog", "ack", "7"])
  assert.deepEqual(a("ack", ["12"]), [BIN, "watchdog", "ack", "12"])
  assert.deepEqual(a("ack", [0]), [BIN, "watchdog", "ack", "0"])
  assert.deepEqual(a("ack-all", []), [BIN, "watchdog", "ack-all"])
  assert.deepEqual(a("ack-all"), [BIN, "watchdog", "ack-all"])
  assert.deepEqual(a("exempt-default", ["on"]), [BIN, "watchdog", "exempt-default", "on"])
  assert.deepEqual(a("exempt-default", ["off"]), [BIN, "watchdog", "exempt-default", "off"])
  assert.deepEqual(a("pin", ["set"]), [BIN, "watchdog", "pin", "set"])
  assert.deepEqual(a("pin", ["clear"]), [BIN, "watchdog", "pin", "clear"])
})

test("argvWatchdog: a label is cleaned of control characters, trimmed and cut at 24; nothing left clears it", () => {
  const lab = (t) => Model.argvWatchdog(BIN, "label", [M1, t])
  assert.deepEqual(lab("  Hall\u0007way\tcam \n"), [BIN, "watchdog", "label", M1, "Hallwaycam"])
  assert.deepEqual(lab("x".repeat(60)), [BIN, "watchdog", "label", M1, "x".repeat(24)])
  assert.deepEqual(lab("a".repeat(23) + " bbbb"), [BIN, "watchdog", "label", M1, "a".repeat(23)], "the cut leaves no trailing space")
  assert.deepEqual(lab("\u202eevil\u202c"), [BIN, "watchdog", "label", M1, "evil"], "bidi overrides go")
  assert.deepEqual(lab(""), [BIN, "watchdog", "label", M1])
  assert.deepEqual(lab("   "), [BIN, "watchdog", "label", M1])
  assert.deepEqual(lab("\u0000\u0007"), [BIN, "watchdog", "label", M1])
  assert.deepEqual(lab("--force"), [BIN, "watchdog", "label", M1, "--force"], "a label is one argument; the backend reads it as text")
  assert.equal(Model.argvWatchdog(BIN, "label", [M1, 5]), null)
  assert.equal(Model.argvWatchdog(BIN, "label", [M1, "a", "b"]), null, "one text argument")
  assert.equal(Model.argvWatchdog(BIN, "label", []), null)
})

test("argvWatchdog rejects a bad binary, verb, MAC, number or extra argument", () => {
  const a = (verb, args, bin) => Model.argvWatchdog(bin === undefined ? BIN : bin, verb, args)
  for (const bin of ["", "qnet", "./qnet", null, undefined, 5]) assert.equal(Model.argvWatchdog(bin, "ack-all", []), null, String(bin))
  for (const verb of ["", "rm", "alerts", "devices", "exempt", "unexempt", "block", "unblock", "block-this", "know-all", "ack ", "PATCH", "constructor", "__proto__", "pin set", "pin-set", null, undefined, 7]) {
    assert.equal(a(verb, [M1]), null, String(verb))
  }
  // MACs: lower-case colon form only
  for (const bad of ["02:00:00:00:00:ZZ", "02:00:00:00:00:17;reboot", "02-00-00-00-00-17", "02:00:00:00:00:1", "02:00:00:00:00:17:aa", "", "--force", "02:00:00:00:00:17 ", "02:00:00:00:00:AB", null, 5, undefined]) {
    assert.equal(a("patch", [bad, "pass"]), null, "patch " + bad)
    assert.equal(a("gate", [bad, 300]), null, "gate " + bad)
    assert.equal(a("label", [bad, "x"]), null, "label " + bad)
    assert.equal(a("know", [bad]), null, "know " + bad)
    assert.equal(a("forget", [bad]), null, "forget " + bad)
  }
  // patch
  for (const bad of ["", "exempt", "PASS", "ads-pass", "pass ", null, 1, undefined]) assert.equal(a("patch", [M1, bad]), null, "patch " + bad)
  assert.equal(a("patch", [M1]), null)
  assert.equal(a("patch", [M1, "pass", "x"]), null)
  assert.equal(a("patch", []), null)
  assert.equal(a("patch"), null)
  // gate: only the lengths the panel offers, and 0
  for (const bad of [1, 299, 301, 3601, 7200, -1, 1.5, NaN, Infinity, "5", "03600", "300 ", "0x12c", "", "abc", null, undefined, true, [], {}]) assert.equal(a("gate", [M1, bad]), null, "gate " + String(bad))
  assert.equal(a("gate", [M1]), null)
  assert.equal(a("gate", [M1, 300, 1]), null)
  // ack: a whole number
  for (const bad of [-1, 1.5, NaN, Infinity, "-1", "1.5", "7x", "", " 7", "1e3", null, undefined, true, [], 2 ** 60, "9".repeat(20)]) assert.equal(a("ack", [bad]), null, "ack " + String(bad))
  assert.equal(a("ack", []), null)
  assert.equal(a("ack", [1, 2]), null)
  // no arguments where there should be none
  assert.equal(a("ack-all", ["x"]), null)
  assert.equal(a("ack-all", [1]), null)
  assert.equal(a("know", []), null)
  assert.equal(a("know", [M1, "label"]), null)
  assert.equal(a("forget", [M1, "x"]), null)
  // exempt-default
  for (const bad of ["", "ON", "true", "1", "yes", true, false, null, undefined]) assert.equal(a("exempt-default", [bad]), null, "exempt-default " + String(bad))
  assert.equal(a("exempt-default", []), null)
  assert.equal(a("exempt-default", ["on", "off"]), null)
  // args must be a list
  assert.equal(a("know", M1), null)
  assert.equal(a("know", { 0: M1 }), null)
})

test("argvWatchdog never takes a PIN: pin has set and clear and nothing else", () => {
  const a = (args) => Model.argvWatchdog(BIN, "pin", args)
  for (const bad of [["1234"], ["set", "1234"], ["1234", "set"], ["clear", "1234"], [1234], ["set1234"], ["SET"], ["Set"], [""], [], ["change"], ["set", "clear"], undefined, null, "set", "1234", 1234]) {
    assert.equal(a(bad), null, JSON.stringify(bad))
  }
  assert.equal(Model.argvWatchdog(BIN, "pin"), null)
  assert.equal(Model.argvWatchdog(BIN, "pin 1234", []), null)
  // and no verb takes a four-digit argument by accident
  for (const out of [Model.argvWatchdog(BIN, "pin", ["set"]), Model.argvWatchdog(BIN, "pin", ["clear"])]) {
    assert.equal(out.some((x) => /\d{4}/.test(x)), false)
  }
})

// ---- the keyboard rows -----------------------------------------------------

test("watchdog rows at rest: back, the lit lamps, the bay, normal, the queue and its calls, pin", () => {
  const rows = rowsOf(view("watchdog-rest"))
  assert.deepEqual(ids(rows), ["back", "lamps", "bay:0", "normal", "queue", "call:1", "call:2", "pin"])
  assert.deepEqual(row(rows, "back").items, ["back"])
  assert.deepEqual(row(rows, "lamps").items, ["threat", "new_device"], "the lit ones, in the lamp row's order")
  assert.deepEqual(row(rows, "bay:0").items, wd("rest").bay.jacks.map((j) => j.mac), "a bay's items are its macs, in the held order")
  assert.deepEqual(row(rows, "normal").items, ["key"])
  assert.deepEqual(row(rows, "queue").items, ["dismissall"])
  assert.deepEqual(row(rows, "call:1").items, ["open"])
  assert.deepEqual(row(rows, "pin").items, ["change", "clear"], "a PIN is set")
})

test("watchdog rows when calm: no lamps row, no queue", () => {
  const rows = rowsOf(view("watchdog-calm"))
  assert.deepEqual(ids(rows), ["back", "bay:0", "normal", "pin"])
  assert.deepEqual(ids(rowsOf(edited("calm", (r) => { r.watchdog.pinSet = false }))), ["back", "bay:0", "normal", "pin"])
  assert.deepEqual(row(rowsOf(edited("calm", (r) => { r.watchdog.pinSet = false })), "pin").items, ["set"], "no PIN: Set")
})

test("watchdog rows: calls newest first, the ARP spoof among them, lamps by kind", () => {
  const rows = rowsOf(view("watchdog-arp"))
  assert.deepEqual(ids(rows), ["back", "lamps", "bay:0", "normal", "queue", "call:3", "call:1", "call:2", "pin"])
  assert.deepEqual(row(rows, "lamps").items, ["threat", "new_device", "arp_spoof"])
  assert.deepEqual(ids(rowsOf(view("watchdog-mode"))), ["back", "lamps", "bay:0", "normal", "queue", "call:1", "call:2", "pin"])
})

test("watchdog rows, 30 devices: two bays and the pager, scrolled", () => {
  const v = view("watchdog-n30")
  const rows = rowsOf(v)
  assert.deepEqual(ids(rows), ["back", "lamps", "bay:0", "bay:1", "normal", "pager", "queue", "call:1", "call:2", "pin"])
  assert.equal(row(rows, "bay:0").items.length, 8)
  assert.deepEqual(row(rows, "pager").items, ["up", "down"])
  const jacks = v.watchdog.bay.jacks
  assert.deepEqual(row(rows, "bay:1").items, jacks.slice(8, 16).map((j) => j.mac))
  const scrolled = rowsOf(v, null, 2)
  assert.deepEqual(ids(scrolled).slice(0, 5), ["back", "lamps", "bay:2", "bay:3", "normal"], "bays are counted from the first")
  assert.equal(row(scrolled, "bay:3").items.length, 6)
  assert.deepEqual(ids(rowsOf(v, null, 99)).slice(2, 4), ["bay:2", "bay:3"], "scroll clamped")
})

test("watchdog rows: the NORMAL confirm sits under the key, before the pager", () => {
  const rows = rowsOf(view("watchdog-n30"), { flip: true })
  assert.deepEqual(ids(rows).slice(0, 7), ["back", "lamps", "bay:0", "bay:1", "normal", "flip", "pager"])
  assert.deepEqual(row(rows, "flip").items, ["flip", "cancel"])
  assert.equal(ids(rowsOf(view("watchdog-rest"))).includes("flip"), false)
})

test("watchdog rows: the PIN row while its field is open", () => {
  const rows = rowsOf(view("watchdog-rest"), { pinOpen: true })
  assert.equal(ids(rows)[ids(rows).length - 1], "pin")
  assert.deepEqual(row(rows, "pin").items, ["set", "cancel"])
  assert.deepEqual(row(rowsOf(view("watchdog-calm"), { pinOpen: true }), "pin").items, ["set", "cancel"])
})

test("device ticket: a blocked jack has label, patch, gate, actions; the board shrinks to its bay", () => {
  const v = view("watchdog-n30")
  const m = jackOf("n30", "·216").mac
  const rows = rowsOf(v, { ticket: { kind: "device", mac: m, alertId: null } })
  assert.deepEqual(ids(rows), ["back", "lamps", "bay:0", "normal", "pager", "queue", "call:1", "call:2", "label", "patch", "gate", "tactions", "pin"])
  assert.deepEqual(row(rows, "label").items, ["edit"])
  assert.deepEqual(row(rows, "patch").items, ["blocked", "pass"])
  assert.deepEqual(row(rows, "gate").items, ["300", "1800", "3600"])
  assert.deepEqual(row(rows, "tactions").items, ["know", "close"], "a new device is marked known")
  const old = rowsOf(v, { ticket: { kind: "device", mac: jackOf("n30", ":0f").mac, alertId: null } })
  assert.deepEqual(ids(old).slice(0, 4), ["back", "lamps", "bay:3", "normal"], "the ticket's bay")
})

test("device ticket: an open gate offers Shut now alone; a known one can be forgotten", () => {
  const rows = rowsOf(view("watchdog-rest"), { ticket: { kind: "device", mac: jackOf("rest", "·23").mac, alertId: null } })
  assert.deepEqual(row(rows, "gate").items, ["shut"])
  assert.deepEqual(row(rows, "patch").items, ["blocked", "pass"])
  assert.deepEqual(row(rows, "tactions").items, ["forget", "close"])
  // a gate that has run out reads as shut, when the clock is given
  const ctx = { view: "watchdog", ticket: { kind: "device", mac: jackOf("rest", "·23").mac, alertId: null }, order: Model.holdOrder([], wd("rest").bay.jacks) }
  assert.deepEqual(row(Model.focusRows(view("watchdog-rest"), Object.assign({ nowS: NOW_S + 900 }, ctx)), "gate").items, ["300", "1800", "3600"])
  assert.deepEqual(row(Model.focusRows(view("watchdog-rest"), Object.assign({ nowS: NOW_S }, ctx)), "gate").items, ["shut"])
})

test("device ticket: a jack that passes has no gate row; ALWAYS and FIXED have no cord and no gate", () => {
  const pass = rowsOf(view("watchdog-rest"), { ticket: { kind: "device", mac: jackOf("rest", "·40").mac, alertId: null } })
  assert.deepEqual(ids(pass).slice(-4), ["label", "patch", "tactions", "pin"], "already ADS PASS: no gate")
  assert.deepEqual(row(pass, "tactions").items, ["forget", "close"])
  const router = rowsOf(view("watchdog-rest"), { ticket: { kind: "device", mac: jackOf("rest", "·1").mac, alertId: null } })
  assert.deepEqual(ids(router).slice(-3), ["label", "tactions", "pin"])
  assert.deepEqual(row(router, "tactions").items, ["close"], "the router is never forgotten")
  const printer = rowsOf(view("watchdog-n30"), { ticket: { kind: "device", mac: jackOf("n30", "·31").mac, alertId: null } })
  assert.deepEqual(ids(printer).slice(-3), ["label", "tactions", "pin"], "fixed: only the label")
  assert.deepEqual(row(printer, "tactions").items, ["forget", "close"])
})

test("device ticket in the exempt-by-default mode: a cord and a passing jack read from the same patch", () => {
  const pc = rowsOf(view("watchdog-mode"), { ticket: { kind: "device", mac: jackOf("mode", "·10").mac, alertId: null } })
  assert.deepEqual(ids(pc).slice(-5), ["label", "patch", "gate", "tactions", "pin"], "a cord to blocked is blocked: it can have a gate")
  const free = rowsOf(view("watchdog-mode"), { ticket: { kind: "device", mac: jackOf("mode", "·51").mac, alertId: null } })
  assert.deepEqual(ids(free).slice(-4), ["label", "patch", "tactions", "pin"], "·51 passes by the normal wiring: no gate")
})

test("device ticket: an offline jack has no gate (the Pi has none for it); an unknown or gone jack has Close alone", () => {
  const old = rowsOf(view("watchdog-n30"), { ticket: { kind: "device", mac: jackOf("n30", ":0f").mac, alertId: null } })
  assert.deepEqual(ids(old).slice(-4), ["label", "patch", "tactions", "pin"])
  assert.deepEqual(row(old, "tactions").items, ["forget", "close"])
  const gone = rowsOf(view("watchdog-rest"), { ticket: { kind: "device", mac: mac(777), alertId: null } })
  assert.deepEqual(ids(gone).slice(-2), ["tactions", "pin"])
  assert.deepEqual(row(gone, "tactions").items, ["close"])
  assert.deepEqual(ids(gone).slice(0, 3), ["back", "lamps", "bay:0"])
})

test("alert ticket: dismiss, Mark known for a new device, Open for a jack, close", () => {
  const v = view("watchdog-rest")
  const newDev = rowsOf(v, { ticket: { kind: "alert", mac: null, alertId: 2 } })
  assert.deepEqual(ids(newDev).slice(-2), ["tactions", "pin"])
  assert.deepEqual(row(newDev, "tactions").items, ["dismiss", "know", "open", "close"])
  const threat = rowsOf(v, { ticket: { kind: "alert", mac: null, alertId: 1 } })
  assert.deepEqual(row(threat, "tactions").items, ["dismiss", "open", "close"])
  const arp = rowsOf(view("watchdog-arp"), { ticket: { kind: "alert", mac: null, alertId: 3 } })
  assert.deepEqual(row(arp, "tactions").items, ["dismiss", "open", "close"], "open the second card's jack")
  assert.equal(ids(arp).includes("label"), false)
  // a device already known is not offered again
  const known = edited("rest", (r) => { for (const j of r.watchdog.bay.jacks) if (j.mac === mac(216)) j.known = true })
  assert.deepEqual(row(rowsOf(known, { ticket: { kind: "alert", mac: null, alertId: 2 } }), "tactions").items, ["dismiss", "open", "close"])
  // an alert that rings no jack and names none: dismiss and close
  const lan = edited("rest", (r) => { r.watchdog.bay.calls[0].mac = null })
  assert.deepEqual(row(rowsOf(lan, { ticket: { kind: "alert", mac: null, alertId: 1 } }), "tactions").items, ["dismiss", "close"])
  const lanNew = edited("rest", (r) => { r.watchdog.bay.calls[1].mac = null })
  assert.deepEqual(row(rowsOf(lanNew, { ticket: { kind: "alert", mac: null, alertId: 2 } }), "tactions").items, ["dismiss", "close"])
  // an alert that is gone: Close alone
  assert.deepEqual(row(rowsOf(v, { ticket: { kind: "alert", mac: null, alertId: 99 } }), "tactions").items, ["close"])
  assert.deepEqual(row(rowsOf(v, { ticket: { kind: "alert", mac: null, alertId: null } }), "tactions").items, ["close"])
})

test("rows with no layout in the ctx work it out from the order, or from the jacks", () => {
  const v = view("watchdog-n30")
  assert.deepEqual(ids(Model.focusRows(v, { view: "watchdog" })).slice(0, 6), ["back", "lamps", "bay:0", "bay:1", "normal", "pager"])
  const reversed = Model.holdOrder([], v.watchdog.bay.jacks.slice().reverse())
  const r = Model.focusRows(v, { view: "watchdog", order: reversed })
  assert.equal(row(r, "bay:0").items[0], v.watchdog.bay.jacks[29].mac)
  const t = Model.focusRows(v, { view: "watchdog", ticket: { kind: "device", mac: v.watchdog.bay.jacks[29].mac, alertId: null }, order: reversed })
  assert.equal(ids(t).includes("bay:3"), false, "the last jack is first in the reversed order: bay 0")
  assert.equal(ids(t).includes("bay:0"), true)
  assert.equal(ids(Model.focusRows(v, { view: "watchdog", ticket: { kind: "other" } })).includes("label"), false, "an unknown ticket kind is no ticket")
})

test("the watchdog view's cursor starts on the way back, with or without a ticket, and walks the rows", () => {
  for (const n of FIXTURES) {
    for (const ticket of [null, { kind: "device", mac: wd(n).bay.jacks[0].mac, alertId: null }, { kind: "alert", mac: null, alertId: 1 }]) {
      const rows = rowsOf(view("watchdog-" + n), { ticket })
      assert.deepEqual(Model.initialCursor(rows, "watchdog"), { row: "back", item: 0 }, n)
      for (const r of rows) assert.ok(r.items.length >= 1, n + " " + r.id)
      assert.equal(new Set(ids(rows)).size, rows.length, n + ": row ids are unique")
    }
  }
  const rows = rowsOf(view("watchdog-rest"))
  let r = Model.moveFocus(rows, Model.initialCursor(rows, "watchdog"), 0, 1, {})
  assert.equal(r.cursor.row, "lamps")
  r = Model.moveFocus(rows, r.cursor, 0, 1, r.memory)
  assert.deepEqual(r.cursor, { row: "bay:0", item: 0 })
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  assert.deepEqual(r.cursor, { row: "bay:0", item: 2 }, "left and right walk the jacks of a bay")
  r = Model.moveFocus(rows, r.cursor, 0, 1, r.memory)
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.deepEqual(r.cursor, { row: "bay:0", item: 2 }, "and a bay remembers the jack")
  assert.deepEqual(Model.settleCursor(rowsOf(view("watchdog-calm")), { row: "queue", item: 0 }, 2), { row: "normal", item: 0 }, "a cursor on a vanished row lands nearby")
})

test("the dns and wifi views' rows are as they were", () => {
  assert.deepEqual(ids(Model.focusRows(view("watchdog-rest"), { view: "dns" })).slice(0, 3), ["back", "choice:pihole", "choice:auto"])
  assert.deepEqual(ids(Model.focusRows(view("watchdog-rest"), { view: "main" })).slice(0, 2), ["header", "route"])
})

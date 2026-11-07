"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, state, NOW_MS } = require("./helpers.js")

const ids = (rows) => rows.map((r) => r.id)
const main = (name, ctx, pend) => Model.focusRows(view(name, pend), Object.assign({ view: "main" }, ctx || {}), pend)
const dns = (name, ctx, pend) => Model.focusRows(view(name, pend), Object.assign({ view: "dns" }, ctx || {}), pend)
const wifi = (name) => Model.focusRows(view(name), { view: "wifi" })

// ---- the main view -------------------------------------------------------

test("main view, top to bottom: header, the route, pause, the footer; no drill-down rows", () => {
  const rows = main("healthy")
  assert.deepEqual(ids(rows), ["header", "route", "pause", "ip"])
  assert.deepEqual(rows[0].items, ["qr", "speed", "radio"], "the header no longer carries a Disconnect")
  assert.deepEqual(rows[1].items, ["ap", "ph"], "the route's nodes are the navigation, left to right")
  assert.deepEqual(rows[2].items, ["pause"])
  for (const n of ["healthy", "paused", "bypassed", "fallback", "none", "unconfigured", "offline", "radio-off", "ethernet", "api-auth"]) {
    assert.equal(ids(main(n)).some((id) => id.indexOf("goto:") === 0), false, n + ": the DNS and Wi-Fi rows are gone")
  }
})

test("the route's stops are the nodes that open a view: the AP, the Pi-hole's place", () => {
  assert.deepEqual(main("healthy")[1].items, ["ap", "ph"])
  assert.deepEqual(main("unconfigured").filter((r) => r.id === "route")[0].items, ["ap", "ph"], "the ghost node opens DNS")
  assert.deepEqual(main("none").filter((r) => r.id === "route")[0].items, ["ap", "ph"], "so does the DNS node of no-DNS")
  assert.deepEqual(main("offline").filter((r) => r.id === "route")[0].items, ["ap"], "offline: the dim AP still opens Wi-Fi")
  assert.deepEqual(main("radio-off").filter((r) => r.id === "route")[0].items, ["ap"])
  assert.deepEqual(main("ethernet").filter((r) => r.id === "route")[0].items, ["ap", "ph"])
  const down = Model.effective(state("healthy"), Model.emptyPending(), 0, NOW_MS, true)
  assert.equal(ids(Model.focusRows(down, { view: "main" })).includes("route"), false, "no route without the backend")
  assert.equal(Model.routeTarget(view("healthy"), "ap"), "wifi")
  assert.equal(Model.routeTarget(view("healthy"), "ph"), "dns")
  assert.equal(Model.routeTarget(view("healthy"), "pc"), "")
  assert.equal(Model.routeTarget(view("healthy"), "up"), "")
})

test("a portal puts its sign-in link first among the header's stops", () => {
  assert.deepEqual(main("portal")[0].items, ["portal", "qr", "speed", "radio"])
})

test("the hero is a stop only when its state has a corrective action", () => {
  assert.equal(ids(main("healthy")).includes("hero"), false)
  for (const n of ["unconfigured", "api-auth", "none", "bypassed", "ethernet-bypassed"]) {
    assert.equal(ids(main(n))[1], "hero", n)
    assert.deepEqual(main(n)[1].items, ["action"], n)
  }
  assert.equal(ids(main("unreachable")).includes("hero"), false, "unreachable only counts down")
  assert.equal(ids(main("fallback")).includes("hero"), false)
})

test("offline: no QR and no speed test; the radio switch stays", () => {
  assert.deepEqual(main("offline")[0].items, ["radio"])
  assert.deepEqual(main("ethernet")[0].items, ["speed", "radio"])
})

test("the cursor starts on the route of the main view, at the AP", () => {
  assert.deepEqual(Model.initialCursor(main("healthy"), "main"), { row: "route", item: 0 })
  const down = Model.effective(state("healthy"), Model.emptyPending(), 0, NOW_MS, true)
  assert.equal(Model.initialCursor(Model.focusRows(down, { view: "main" }), "main").row, "pause", "no route: the Pause tile")
})

test("up and down walk the main view's rows and stop at the ends", () => {
  const rows = main("healthy")
  let r = Model.moveFocus(rows, { row: "ip", item: 0 }, 0, -1, {})
  assert.equal(r.cursor.row, "pause")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(r.cursor.row, "route")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(r.cursor.row, "header")
  assert.equal(Model.moveFocus(rows, r.cursor, 0, -1, r.memory).cursor.row, "header", "stops at the top")
  assert.equal(Model.moveFocus(rows, { row: "ip", item: 0 }, 0, 1, {}).cursor.row, "ip", "stops at the bottom")
})

test("left and right move inside the header and stop at its ends", () => {
  const rows = main("healthy")
  let r = Model.moveFocus(rows, { row: "header", item: 0 }, 1, 0, {})
  assert.equal(r.cursor.item, 1)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  assert.equal(r.cursor.item, 2)
  assert.equal(Model.moveFocus(rows, r.cursor, 1, 0, r.memory).cursor.item, 2, "no wrap")
  assert.equal(Model.moveFocus(rows, { row: "header", item: 0 }, -1, 0, {}).cursor.item, 0)
  assert.equal(Model.moveFocus(rows, { row: "pause", item: 0 }, 1, 0, {}).cursor.item, 0, "a single-item row ignores left/right")
})

test("left and right walk along the route's nodes and stop at its ends", () => {
  const rows = main("healthy")
  let r = Model.moveFocus(rows, { row: "route", item: 0 }, 1, 0, {})
  assert.deepEqual(r.cursor, { row: "route", item: 1 })
  assert.equal(Model.moveFocus(rows, r.cursor, 1, 0, r.memory).cursor.item, 1, "no wrap at the Pi-hole")
  assert.equal(Model.moveFocus(rows, { row: "route", item: 0 }, -1, 0, {}).cursor.item, 0)
  r = Model.moveFocus(rows, r.cursor, 0, 1, r.memory)
  assert.equal(r.cursor.row, "pause")
  assert.deepEqual(Model.moveFocus(rows, r.cursor, 0, -1, r.memory).cursor, { row: "route", item: 1 }, "it remembers the node")
})

test("a row remembers which of its items the cursor was on", () => {
  const rows = main("healthy")
  let r = Model.moveFocus(rows, { row: "header", item: 2 }, 0, 1, {})
  assert.equal(r.cursor.row, "route")
  r = Model.moveFocus(rows, r.cursor, 0, 1, r.memory)
  assert.equal(r.cursor.row, "pause")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.deepEqual(r.cursor, { row: "header", item: 2 })
})

test("a cursor on a row that went away lands nearby", () => {
  const rows = main("healthy")
  assert.equal(Model.settleCursor(rows, { row: "net:9", item: 0 }, 3).row, rows[3].id)
  assert.deepEqual(Model.settleCursor(rows, { row: "header", item: 99 }, 0), { row: "header", item: 2 })
})

// ---- the DNS view --------------------------------------------------------

test("DNS view: back, the two resolver choices, then bypass, one stop per profile, Pin all, Admin", () => {
  assert.deepEqual(ids(dns("healthy")), ["back", "choice:pihole", "choice:auto", "admin"])
  assert.deepEqual(dns("healthy")[1].items, ["pick"])
  assert.deepEqual(ids(dns("leaks")), ["back", "choice:pihole", "choice:auto", "leak:0", "leak:1", "pinall", "admin"])
  assert.deepEqual(ids(dns("bypassed")), ["back", "choice:pihole", "choice:auto", "bypass", "admin"])
  assert.deepEqual(ids(dns("partial")).slice(0, 6), ["back", "choice:pihole", "choice:auto", "leak:0", "leak:1", "pinall"])
})

test("DNS view: Pin all only for two or more, no Admin without a Pi-hole, confirm sits under the choices", () => {
  const s = Model.leakGroups(view("markup")).profiles
  assert.equal(s.count, 1)
  assert.equal(ids(dns("markup")).includes("pinall"), false)
  assert.equal(ids(dns("unconfigured")).includes("admin"), false)
  const rows = dns("custom", { confirm: true })
  assert.deepEqual(ids(rows).slice(0, 5), ["back", "choice:pihole", "choice:auto", "confirm", "admin"])
  assert.deepEqual(rows[3].items, ["replace", "cancel"])
})

test("focus never starts on a resolver choice, a connection change or a forget: a stray Enter or Space does nothing", () => {
  const names = ["healthy", "paused", "degraded", "bypassed", "ethernet-bypassed", "leaks", "partial", "fallback", "custom",
    "none", "unconfigured", "unknown", "offline", "radio-off", "api-auth", "unreachable", "markup", "ethernet"]
  for (const n of names) {
    for (const page of ["main", "dns", "wifi"]) {
      const rows = Model.focusRows(view(n), { view: page })
      const c = Model.initialCursor(rows, page)
      assert.equal(c.row.indexOf("choice:"), -1, n + " " + page + ": starts on " + c.row)
      assert.notEqual(c.row, "card", n + " " + page + ": never on Disconnect")
      assert.equal(c.row.indexOf("net:"), -1, n + " " + page + ": never on a network")
      assert.equal(Model.rowIndex(rows, c.row) >= 0, true, n + " " + page)
    }
    assert.equal(Model.initialCursor(Model.focusRows(view(n), { view: "dns" }), "dns").row, "back", n)
    assert.equal(Model.initialCursor(Model.focusRows(view(n), { view: "wifi" }), "wifi").row, "scan", n)
    // and with the confirm up, or the cursor first revealed by a move
    const withConfirm = Model.focusRows(view(n), { view: "dns", confirm: true })
    assert.equal(Model.initialCursor(withConfirm, "dns").row, "back", n)
    assert.equal(Model.initialCursor(withConfirm, null).row.indexOf("choice:"), -1, n)
  }
})

test("the choices are reached only by walking down to them, and Enter there asks first", () => {
  const rows = dns("healthy")
  const r = Model.moveFocus(rows, Model.initialCursor(rows, "dns"), 0, 1, {})
  assert.equal(r.cursor.row, "choice:pihole", "one move down from the back button")
  const r2 = Model.moveFocus(rows, r.cursor, 0, 1, r.memory)
  assert.equal(r2.cursor.row, "choice:auto")
  assert.equal(Model.tapPlan("auto", view("healthy")).action, "confirm")
})

test("the panel starts every opening with the cursor hidden and every view with a safe stop", () => {
  const panel = require("fs").readFileSync(require("path").join(__dirname, "..", "Panel.qml"), "utf8")
  assert.match(panel, /cursorActive = false\s*\n\s*cursor = Model\.initialCursor\(rows, "main"\)/)
  assert.match(panel, /cursor = Model\.initialCursor\(rows, page\)/)
})

// ---- the Wi-Fi view ------------------------------------------------------

test("Wi-Fi view: back, the card's Disconnect, scan, then one stop per nearby network", () => {
  const rows = wifi("healthy")
  assert.deepEqual(ids(rows), ["back", "card", "scan", "net:0", "net:1", "net:2", "net:3", "net:4"], "the one in use is the card, not a row")
  assert.deepEqual(rows[1].items, ["disconnect"])
  assert.deepEqual(Model.initialCursor(rows, "wifi"), { row: "scan", item: 0 })
  assert.deepEqual(ids(wifi("radio-off")), ["back", "scan"], "no card row without a connection")
  assert.deepEqual(ids(wifi("ethernet")).slice(0, 3), ["back", "scan", "net:0"], "a wire has no Disconnect")
  assert.deepEqual(Model.initialCursor(wifi("radio-off"), "wifi"), { row: "scan", item: 0 })
})

test("a held key counts once", () => {
  const t = {}
  assert.equal(Model.freshGate(t, "esc", 1000, 80), true)
  assert.equal(Model.freshGate(t, "esc", 1030, 80), false)
  assert.equal(Model.freshGate(t, "esc", 1060, 80), false, "each press, fresh or not, restarts the gap")
  assert.equal(Model.freshGate(t, "esc", 1500, 80), true)
  assert.equal(Model.freshGate(t, "enter", 1500, 80), true)
})

// ---- pushing and popping the views ----------------------------------------

test("opening a drill-down remembers where the cursor was on the main view; back puts it there", () => {
  const nav0 = Model.navInit()
  assert.deepEqual(nav0, { view: "main", returnCursor: null })
  const o = Model.navOpen(nav0, "dns", { row: "route", item: 1 })
  assert.equal(o.nav.view, "dns")
  assert.deepEqual(o.nav.returnCursor, { row: "route", item: 1 })
  assert.deepEqual(o.effects, [], "the DNS view runs nothing on entry")
  const b = Model.navBack(o.nav)
  assert.equal(b.nav.view, "main")
  assert.deepEqual(b.cursor, { row: "route", item: 1 })
  assert.equal(b.left, true)
})

test("entering the Wi-Fi view scans if stale: qnet wifi scan --if-stale 60", () => {
  const o = Model.navOpen(Model.navInit(), "wifi", { row: "route", item: 0 })
  assert.equal(o.nav.view, "wifi")
  assert.deepEqual(o.effects, [{ run: "scan", ifStaleS: 60 }])
  const argv = Model.argvScan("/home/user/.local/bin/qnet", o.effects[0].ifStaleS)
  assert.deepEqual(argv, ["/home/user/.local/bin/qnet", "wifi", "scan", "--if-stale", "60"])
})

test("opening the panel, or the main or DNS view, never scans", () => {
  assert.deepEqual(Model.navOpen(Model.navInit(), "dns", null).effects, [])
  assert.deepEqual(Model.navOpen(Model.navInit(), "main", null).effects, [])
  const again = Model.navOpen(Model.navOpen(Model.navInit(), "wifi", null).nav, "wifi", null)
  assert.deepEqual(again.effects, [], "already there: no second scan")
  const panel = require("fs").readFileSync(require("path").join(__dirname, "..", "Panel.qml"), "utf8")
  const at = panel.indexOf("onOpenedChanged:")
  const opened = panel.slice(at, panel.indexOf("Component.onDestruction", at))
  assert.doesNotMatch(opened, /scan/i, "the panel's open handler does not scan")
})

test("going from one drill-down straight to the other keeps the way back to the main view", () => {
  const a = Model.navOpen(Model.navInit(), "dns", { row: "route", item: 1 })
  const b = Model.navOpen(a.nav, "wifi", { row: "x", item: 0 })
  assert.equal(b.nav.view, "wifi")
  assert.deepEqual(b.nav.returnCursor, { row: "route", item: 1 })
  assert.deepEqual(b.effects, [{ run: "scan", ifStaleS: 60 }])
  assert.equal(Model.navBack(b.nav).nav.view, "main")
})

test("back from the main view does nothing; unknown views are not opened", () => {
  const b = Model.navBack(Model.navInit())
  assert.equal(b.left, false)
  assert.equal(b.cursor, null)
  assert.equal(Model.navOpen(Model.navInit(), "eq", null).nav.view, "main")
})

test("Esc steps back one level: armed Forget, confirm, passphrase, the drill-down, then close", () => {
  assert.equal(Model.escapeStep({ armed: true, confirm: true, password: true, view: "wifi" }), "disarm")
  assert.equal(Model.escapeStep({ confirm: true, password: true, view: "dns" }), "confirm")
  assert.equal(Model.escapeStep({ password: true, view: "wifi" }), "password")
  assert.equal(Model.escapeStep({ view: "wifi" }), "back")
  assert.equal(Model.escapeStep({ view: "dns" }), "back")
  assert.equal(Model.escapeStep({ view: "main" }), "close")
  assert.equal(Model.escapeStep({}), "close")
})

"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view } = require("./helpers.js")

const ids = (rows) => rows.map((r) => r.id)

test("healthy panel, top to bottom", () => {
  const rows = Model.focusRows(view("healthy"), {})
  assert.deepEqual(ids(rows), ["header", "dns", "scan", "net:0", "net:1", "net:2", "net:3", "net:4", "net:5", "ip"])
  assert.deepEqual(rows[0].items, ["qr", "speed", "radio"])
  assert.deepEqual(Model.focusRows(view("portal"), {})[0].items, ["portal", "qr", "speed", "radio"], "the sign-in link is the first stop")
  assert.deepEqual(rows[1].items, ["tile:pihole", "tile:auto", "pause", "admin"])
})

test("unconfigured: the setup link is a stop and there is no pause or admin", () => {
  const rows = Model.focusRows(view("unconfigured"), {})
  assert.deepEqual(ids(rows).slice(0, 3), ["header", "setup", "dns"])
  assert.deepEqual(rows.find((r) => r.id === "dns").items, ["tile:pihole", "tile:auto"])
})

test("leaks with a fix are stops between the header and the DNS row", () => {
  const rows = Model.focusRows(view("leaks"), {})
  assert.deepEqual(ids(rows).slice(0, 4), ["header", "leak:0", "leak:1", "dns"])
})

test("an inline confirm line adds its two buttons right above the DNS row", () => {
  const rows = Model.focusRows(view("custom"), { confirm: true })
  const at = ids(rows).indexOf("confirm")
  assert.ok(at > 0 && ids(rows)[at + 1] === "dns")
  assert.deepEqual(rows[at].items, ["replace", "cancel"])
})

test("offline: no QR and no speed test, the radio switch stays", () => {
  assert.deepEqual(Model.focusRows(view("offline"), {})[0].items, ["radio"])
  assert.deepEqual(Model.focusRows(view("ethernet"), {})[0].items, ["speed", "radio"])
})

test("focus starts on the Networks list", () => {
  const rows = Model.focusRows(view("healthy"), {})
  assert.deepEqual(Model.initialCursor(rows), { row: "net:0", item: 0 })
  const none = Model.focusRows(view("radio-off"), {})
  assert.deepEqual(Model.initialCursor(none), { row: "scan", item: 0 })
})

test("up and down walk the rows and stop at the ends", () => {
  const rows = Model.focusRows(view("healthy"), {})
  let c = { row: "net:0", item: 0 }
  let m = {}
  let r = Model.moveFocus(rows, c, 0, -1, m)
  assert.equal(r.cursor.row, "scan")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(r.cursor.row, "dns")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(r.cursor.row, "header", "stops at the top")
  const top = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(top.cursor.row, "header")
  let end = { row: "net:5", item: 0 }
  end = Model.moveFocus(rows, end, 0, 1, {}).cursor
  assert.equal(end.row, "ip")
  assert.equal(Model.moveFocus(rows, end, 0, 1, {}).cursor.row, "ip", "stops at the bottom")
})

test("left and right move inside a row of tiles and stop at its ends", () => {
  const rows = Model.focusRows(view("healthy"), {})
  let c = { row: "dns", item: 0 }
  let m = {}
  let r = Model.moveFocus(rows, c, 1, 0, m)
  assert.equal(r.cursor.item, 1)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  assert.equal(r.cursor.item, 3)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  assert.equal(r.cursor.item, 3, "no wrap")
  r = Model.moveFocus(rows, { row: "dns", item: 0 }, -1, 0, {})
  assert.equal(r.cursor.item, 0)
  const single = Model.moveFocus(rows, { row: "net:0", item: 0 }, 1, 0, {})
  assert.equal(single.cursor.item, 0, "a single-item row ignores left/right")
})

test("a row remembers which of its tiles the cursor was on", () => {
  const rows = Model.focusRows(view("healthy"), {})
  let r = Model.moveFocus(rows, { row: "dns", item: 2 }, 0, 1, {})
  assert.equal(r.cursor.row, "scan")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.deepEqual(r.cursor, { row: "dns", item: 2 })
})

test("a cursor on a row that went away lands nearby", () => {
  const rows = Model.focusRows(view("healthy"), {})
  const c = Model.settleCursor(rows, { row: "net:9", item: 0 }, 6)
  assert.equal(c.row, rows[6].id)
  assert.deepEqual(Model.settleCursor(rows, { row: "dns", item: 99 }, 0), { row: "dns", item: 3 })
})

test("a held key counts once", () => {
  const t = {}
  assert.equal(Model.freshGate(t, "esc", 1000, 80), true)
  assert.equal(Model.freshGate(t, "esc", 1030, 80), false)
  assert.equal(Model.freshGate(t, "esc", 1060, 80), false, "each press, fresh or not, restarts the gap")
  assert.equal(Model.freshGate(t, "esc", 1500, 80), true)
  assert.equal(Model.freshGate(t, "enter", 1500, 80), true)
})

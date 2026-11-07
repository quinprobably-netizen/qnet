"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view } = require("./helpers.js")

const ids = (rows) => rows.map((r) => r.id)

test("healthy panel, top to bottom: the connected network is the header's, not a row", () => {
  const rows = Model.focusRows(view("healthy"), {})
  assert.deepEqual(ids(rows), ["header", "hero", "dns", "scan", "net:0", "net:1", "net:2", "net:3", "net:4", "ip"])
  assert.deepEqual(rows[0].items, ["conn", "qr", "speed", "radio"])
  assert.deepEqual(rows[1].items, ["pause", "admin"], "Pause and Admin live in the hero now")
  assert.deepEqual(rows[2].items, ["tile:pihole", "tile:auto"], "the tiles are alone in their row")
})

test("a portal puts its sign-in link after the connection, before the buttons", () => {
  assert.deepEqual(Model.focusRows(view("portal"), {})[0].items, ["conn", "portal", "qr", "speed", "radio"])
})

test("unconfigured: the hero's one stop is setup, with no pause or admin", () => {
  const rows = Model.focusRows(view("unconfigured"), {})
  assert.deepEqual(ids(rows).slice(0, 3), ["header", "hero", "dns"])
  assert.deepEqual(rows[1].items, ["setup"])
})

test("saved profiles that would bypass are one stop, Pin all", () => {
  const rows = Model.focusRows(view("leaks"), {})
  assert.deepEqual(ids(rows).slice(0, 4), ["header", "hero", "profiles", "dns"])
  assert.deepEqual(rows[2].items, ["pinall"])
})

test("a bypassed link is a stop of its own, above the profiles line", () => {
  const rows = Model.focusRows(view("bypassed"), {})
  assert.deepEqual(ids(rows).slice(0, 4), ["header", "hero", "bypass", "dns"])
  const eth = Model.focusRows(view("ethernet-bypassed"), {})
  assert.deepEqual(ids(eth).slice(0, 4), ["header", "hero", "bypass", "dns"])
})

test("an inline confirm line adds its two buttons right above the DNS row", () => {
  const rows = Model.focusRows(view("custom"), { confirm: true })
  const at = ids(rows).indexOf("confirm")
  assert.ok(at > 0 && ids(rows)[at + 1] === "dns")
  assert.deepEqual(rows[at].items, ["replace", "cancel"])
})

test("offline: no connection to drop, no QR, no speed test; the radio switch stays", () => {
  assert.deepEqual(Model.focusRows(view("offline"), {})[0].items, ["radio"])
  assert.deepEqual(Model.focusRows(view("ethernet"), {})[0].items, ["speed", "radio"], "Ethernet cannot be dropped from here")
})

test("focus starts on the Networks list", () => {
  const rows = Model.focusRows(view("healthy"), {})
  assert.deepEqual(Model.initialCursor(rows), { row: "net:0", item: 0 })
  const none = Model.focusRows(view("radio-off"), {})
  assert.deepEqual(Model.initialCursor(none), { row: "scan", item: 0 })
})

test("up and down walk the rows and stop at the ends", () => {
  const rows = Model.focusRows(view("healthy"), {})
  let r = Model.moveFocus(rows, { row: "net:0", item: 0 }, 0, -1, {})
  assert.equal(r.cursor.row, "scan")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(r.cursor.row, "dns")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(r.cursor.row, "hero")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(r.cursor.row, "header")
  const top = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.equal(top.cursor.row, "header", "stops at the top")
  let end = { row: "net:4", item: 0 }
  end = Model.moveFocus(rows, end, 0, 1, {}).cursor
  assert.equal(end.row, "ip")
  assert.equal(Model.moveFocus(rows, end, 0, 1, {}).cursor.row, "ip", "stops at the bottom")
})

test("left and right move inside a row and stop at its ends", () => {
  const rows = Model.focusRows(view("healthy"), {})
  let r = Model.moveFocus(rows, { row: "header", item: 0 }, 1, 0, {})
  assert.equal(r.cursor.item, 1)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  assert.equal(r.cursor.item, 3)
  r = Model.moveFocus(rows, r.cursor, 1, 0, r.memory)
  assert.equal(r.cursor.item, 3, "no wrap")
  r = Model.moveFocus(rows, { row: "header", item: 0 }, -1, 0, {})
  assert.equal(r.cursor.item, 0)
  const single = Model.moveFocus(rows, { row: "net:0", item: 0 }, 1, 0, {})
  assert.equal(single.cursor.item, 0, "a single-item row ignores left/right")
  const tiles = Model.moveFocus(rows, { row: "dns", item: 0 }, 1, 0, {})
  assert.equal(tiles.cursor.item, 1)
  assert.equal(Model.moveFocus(rows, tiles.cursor, 1, 0, tiles.memory).cursor.item, 1)
})

test("a row remembers which of its items the cursor was on", () => {
  const rows = Model.focusRows(view("healthy"), {})
  let r = Model.moveFocus(rows, { row: "hero", item: 1 }, 0, 1, {})
  assert.equal(r.cursor.row, "dns")
  r = Model.moveFocus(rows, r.cursor, 0, -1, r.memory)
  assert.deepEqual(r.cursor, { row: "hero", item: 1 })
})

test("a cursor on a row that went away lands nearby", () => {
  const rows = Model.focusRows(view("healthy"), {})
  const c = Model.settleCursor(rows, { row: "net:9", item: 0 }, 6)
  assert.equal(c.row, rows[6].id)
  assert.deepEqual(Model.settleCursor(rows, { row: "hero", item: 99 }, 0), { row: "hero", item: 1 })
})

test("a held key counts once", () => {
  const t = {}
  assert.equal(Model.freshGate(t, "esc", 1000, 80), true)
  assert.equal(Model.freshGate(t, "esc", 1030, 80), false)
  assert.equal(Model.freshGate(t, "esc", 1060, 80), false, "each press, fresh or not, restarts the gap")
  assert.equal(Model.freshGate(t, "esc", 1500, 80), true)
  assert.equal(Model.freshGate(t, "enter", 1500, 80), true)
})

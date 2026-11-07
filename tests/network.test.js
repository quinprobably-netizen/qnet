"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, state } = require("./helpers.js")

// ---- header --------------------------------------------------------------

test("connected Wi-Fi: SSID, then Connected, band, signal and rate", () => {
  const h = Model.headerInfo(view("healthy"))
  assert.equal(h.kind, "wifi")
  assert.equal(h.title, "Redwood")
  assert.equal(h.urgent, false)
  assert.deepEqual(h.status, [
    { k: "state", key: "connected" }, { k: "text", text: "5 GHz" }, { k: "text", text: "72%" }, { k: "text", text: "866 Mb/s" }
  ])
})

test("a captive portal reads Sign in required, urgent, and offers the portal", () => {
  const h = Model.headerInfo(view("portal"))
  assert.deepEqual(h.status, [{ k: "state", key: "portal" }])
  assert.equal(h.urgent, true)
  assert.equal(h.portal, true)
  assert.equal(h.restricted, true)
})

test("limited and no-internet read urgent; unknown connectivity reads Connected", () => {
  const s = state("healthy")
  s.link.connectivity = "limited"
  assert.equal(Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0)).status[0].key, "limited")
  s.link.connectivity = "none"
  const n = Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0))
  assert.equal(n.status[0].key, "nointernet")
  assert.equal(n.urgent, true)
  s.link.connectivity = "unknown"
  assert.equal(Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0)).status[0].key, "connected")
})

test("Ethernet has no title of its own and shows its rate", () => {
  const h = Model.headerInfo(view("ethernet"))
  assert.equal(h.kind, "ethernet")
  assert.equal(h.title, "")
  assert.deepEqual(h.status, [{ k: "state", key: "connected" }, { k: "text", text: "1 Gb/s" }])
})

test("offline and radio off", () => {
  assert.deepEqual(Model.headerInfo(view("offline")).status, [{ k: "state", key: "offline" }])
  assert.equal(Model.headerInfo(view("offline")).kind, "offline")
  assert.equal(Model.headerInfo(view("radio-off")).kind, "off")
})

test("the radio switch follows a pending request", () => {
  const pend = Model.withPending(Model.emptyPending(), { radio: "off" }, 0)
  assert.equal(Model.effective(state("healthy"), pend, 0, 0).radio.wifiEnabled, false)
})

test("QR share is offered on a connected, non-802.1X Wi-Fi only", () => {
  assert.equal(Model.canShareWifi(view("healthy")), true)
  assert.equal(Model.canShareWifi(view("ethernet")), false)
  assert.equal(Model.canShareWifi(view("offline")), false)
  const s = state("healthy")
  s.networks[0].security = "enterprise"
  assert.equal(Model.canShareWifi(Model.effective(s, Model.emptyPending(), 0, 0)), false)
})

test("glyphs: signal buckets, restricted and off", () => {
  assert.equal(Model.wifiGlyph(100), Model.GLYPH.wifi[4])
  assert.equal(Model.wifiGlyph(72), Model.GLYPH.wifi[3])
  assert.equal(Model.wifiGlyph(1), Model.GLYPH.wifi[0])
  assert.equal(Model.linkGlyph(view("portal")), Model.GLYPH.wifiRestricted)
  assert.equal(Model.linkGlyph(view("offline")), Model.GLYPH.wifiOff)
  assert.equal(Model.linkGlyph(view("ethernet")), Model.GLYPH.ethernet)
})

test("the bar icon turns urgent for a restricted link and for DNS that went wrong", () => {
  assert.equal(Model.barActive(view("healthy")), false)
  assert.equal(Model.barActive(view("portal")), true)
  assert.equal(Model.barActive(view("unreachable")), true)
  assert.equal(Model.barActive(view("bypassed")), true)
  assert.equal(Model.barActive(view("fallback")), false, "a working fallback is a tooltip, not an alarm")
  assert.equal(Model.barTip(view("fallback")), "fallback")
  assert.equal(Model.barTip(view("healthy")), "")
  assert.equal(Model.barTip(view("offline")), "")
})

// ---- footer --------------------------------------------------------------

test("the IP footer keeps stable placeholders", () => {
  assert.equal(Model.ipFooter(view("healthy")).text, "192.168.1.242 · gw 192.168.1.1")
  assert.equal(Model.ipFooter(view("offline")).text, "-- · gw --")
  assert.equal(Model.ipFooter(view("offline")).copyable, false)
  assert.equal(Model.ipFooter(view("healthy")).copyable, true)
})

// ---- networks ------------------------------------------------------------

test("order: the active network, then known, then the rest, strongest first", () => {
  const ordered = Model.orderNetworks(view("healthy").networks)
  assert.deepEqual(ordered.map((n) => n.ssid), ["Redwood", "Home-Guest", "Neighbor-5G", "CoffeeShop", "Uni-8021X", "Cafe-OWE"])
  assert.equal(ordered[0].active, true)
})

test("hidden networks are left out unless one is active or asked for", () => {
  const nets = view("healthy").networks
  assert.equal(Model.orderNetworks(nets).some((n) => n.hidden), false)
  assert.equal(Model.orderNetworks(nets, true).some((n) => n.hidden), true)
  const s = state("healthy")
  s.networks[3].hidden = true
  s.networks[3].active = true
  s.networks[0].active = false
  assert.equal(Model.orderNetworks(s.networks)[0].hidden, true)
})

test("a repeated SSID keeps the active or the strongest entry", () => {
  const a = { id: "/org/freedesktop/NetworkManager/AccessPoint/1", ssid: "X", hidden: false, signal: 30, security: "psk", known: false, active: false, uuid: "" }
  const b = Object.assign({}, a, { id: "/org/freedesktop/NetworkManager/AccessPoint/2", signal: 80 })
  const c = Object.assign({}, a, { id: "/org/freedesktop/NetworkManager/AccessPoint/3", signal: 10, active: true })
  assert.equal(Model.orderNetworks([a, b]).length, 1)
  assert.equal(Model.orderNetworks([a, b])[0].signal, 80)
  assert.equal(Model.orderNetworks([a, b, c])[0].id, c.id)
})

test("what a tap on a row does", () => {
  const by = (ssid) => view("healthy").networks.find((n) => n.ssid === ssid)
  assert.equal(Model.connectPlan(by("Redwood")), "disconnect")
  assert.equal(Model.connectPlan(by("Home-Guest")), "connect")
  assert.equal(Model.connectPlan(by("CoffeeShop")), "connect", "open: no secret")
  assert.equal(Model.connectPlan(by("Cafe-OWE")), "connect", "OWE has no passphrase")
  assert.equal(Model.connectPlan(by("Neighbor-5G")), "password")
  assert.equal(Model.connectPlan(by("Uni-8021X")), "nmtui")
  assert.equal(Model.connectPlan(view("healthy").networks.find((n) => n.hidden)), "none")
  assert.equal(Model.connectPlan(null), "none")
})

test("captions: only open and 802.1X networks are marked; no lock anywhere", () => {
  const by = (ssid) => view("healthy").networks.find((n) => n.ssid === ssid)
  const cap = (ssid, ctx) => Model.rowCaption(by(ssid), ctx)
  assert.equal(cap("Redwood", {}).key, "connected")
  assert.equal(cap("Redwood", {}).tone, "accent")
  assert.equal(cap("CoffeeShop", {}).key, "open")
  assert.equal(cap("Uni-8021X", {}).key, "enterprise")
  assert.equal(cap("Neighbor-5G", {}).key, "")
  assert.equal(cap("Home-Guest", {}).key, "")
  assert.equal(cap("Cafe-OWE", {}).key, "", "OWE is encrypted and passwordless: nothing to mark")
})

test("captions: transient states win, a failure is urgent text", () => {
  const rust = view("healthy").networks[0]
  const guest = view("healthy").networks.find((n) => n.ssid === "Home-Guest")
  assert.equal(Model.rowCaption(guest, { connectId: guest.id }).key, "connecting")
  assert.equal(Model.rowCaption(rust, { disconnecting: true }).key, "disconnecting")
  assert.equal(Model.rowCaption(guest, { forgetUuid: guest.uuid }).key, "forgetting")
  assert.equal(Model.rowCaption(guest, { armedUuid: guest.uuid }).key, "forget")
  const f = Model.rowCaption(guest, { failId: guest.id, failText: "Wrong password" })
  assert.deepEqual([f.key, f.tone, f.text], ["text", "urgent", "Wrong password"])
  assert.equal(Model.rowCaption(rust, { connectivity: "portal" }).key, "portal")
  assert.equal(Model.rowCaption(rust, { connectivity: "limited" }).key, "limited")
  assert.equal(Model.rowCaption(rust, { connectivity: "portal" }).tone, "urgent")
})

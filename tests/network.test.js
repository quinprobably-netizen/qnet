"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, state } = require("./helpers.js")

// ---- header --------------------------------------------------------------

test("connected Wi-Fi: SSID, then just band and signal; 'Connected' is left out when all is well", () => {
  const h = Model.headerInfo(view("healthy"))
  assert.equal(h.kind, "wifi")
  assert.equal(h.title, "Redwood")
  assert.equal(h.urgent, false)
  assert.deepEqual(h.status, [{ k: "text", text: "5 GHz" }, { k: "text", text: "72%" }])
})

test("gw appears only when the gateway is slow (over 50 ms) or its probe fails", () => {
  const texts = (s) => Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0)).status.map((p) => p.text)
  const s = state("healthy")
  assert.deepEqual(texts(s), ["5 GHz", "72%"], "4 ms is routine noise")
  s.link.gatewayMs = 50
  assert.deepEqual(texts(s), ["5 GHz", "72%"], "50 is the edge")
  s.link.gatewayMs = 61.7
  assert.deepEqual(texts(s), ["5 GHz", "72%", "gw 62 ms"])
  s.link.gatewayMs = null
  assert.deepEqual(texts(s), ["5 GHz", "72%"], "not measured while the panel is closed")
  s.link.gatewayOk = false
  assert.equal(texts(s).pop().startsWith("gw"), true, "a failing probe is worth a word")
  assert.deepEqual(texts(state("slow-gateway")).pop(), "gw 120 ms")
})

test("the real panel's status line", () => {
  assert.deepEqual(Model.headerInfo(view("partial")).status.map((p) => p.text), ["5 GHz", "61%"])
})

test("a captive portal reads Sign in required, urgent, and offers the portal", () => {
  const h = Model.headerInfo(view("portal"))
  assert.deepEqual(h.status, [{ k: "state", key: "portal" }])
  assert.equal(h.urgent, true)
  assert.equal(h.portal, true)
  assert.equal(h.restricted, true)
})

test("limited and no-internet read urgent; unknown connectivity is as good as full", () => {
  const s = state("healthy")
  s.link.connectivity = "limited"
  assert.equal(Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0)).status[0].key, "limited")
  assert.equal(Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0)).status[1].text, "5 GHz", "the state word first, then the rest")
  s.link.connectivity = "none"
  const n = Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0))
  assert.equal(n.status[0].key, "nointernet")
  assert.equal(n.urgent, true)
  s.link.connectivity = "unknown"
  assert.deepEqual(Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0)).status.map((p) => p.text), ["5 GHz", "72%"])
})

test("Ethernet has no title of its own and shows its rate; a wire with no rate says Connected", () => {
  const h = Model.headerInfo(view("ethernet"))
  assert.equal(h.kind, "ethernet")
  assert.equal(h.title, "")
  assert.deepEqual(h.status, [{ k: "text", text: "1 Gb/s" }])
  const s = state("ethernet")
  s.link.bitrateMbps = 0
  assert.deepEqual(Model.headerInfo(Model.effective(s, Model.emptyPending(), 0, 0)).status, [{ k: "state", key: "connected" }])
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

test("the footer is the address and the gateway, with stable placeholders", () => {
  assert.equal(Model.ipFooter(view("healthy")).text, "192.168.1.242 · gw 192.168.1.1")
  assert.equal(Model.ipFooter(view("offline")).text, "-- · gw --")
  assert.equal(Model.ipFooter(view("offline")).copyable, false)
  assert.equal(Model.ipFooter(view("healthy")).copyable, true)
})

// ---- networks ------------------------------------------------------------

test("order: the one in use first, then saved, then the rest, strongest first", () => {
  const ordered = Model.orderNetworks(view("healthy").networks)
  assert.deepEqual(ordered.map((n) => n.ssid), ["Redwood", "Home-Guest", "Neighbor-5G", "CoffeeShop", "Uni-8021X", "Cafe-OWE"])
  assert.equal(ordered[0].active, true)
})

test("hidden networks are left out unless one is in use or they are asked for", () => {
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

test("captions: Saved, Open and 802.1X; no lock anywhere", () => {
  const by = (ssid) => view("healthy").networks.find((n) => n.ssid === ssid)
  const cap = (ssid, ctx) => Model.rowCaption(by(ssid), ctx)
  assert.equal(cap("Home-Guest", {}).key, "saved")
  assert.equal(cap("Home-Guest", {}).tone, "dim")
  assert.equal(cap("CoffeeShop", {}).key, "open")
  assert.equal(cap("Uni-8021X", {}).key, "enterprise")
  assert.equal(cap("Neighbor-5G", {}).key, "")
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

// ---- the Wi-Fi row -----------------------------------------------------------

test("scan ages read as just now, minutes, hours", () => {
  assert.deepEqual(Model.ageParts(12), { unit: "now", n: 0 })
  assert.deepEqual(Model.ageParts(59), { unit: "now", n: 0 })
  assert.deepEqual(Model.ageParts(240), { unit: "min", n: 4 })
  assert.deepEqual(Model.ageParts(3599), { unit: "min", n: 59 })
  assert.deepEqual(Model.ageParts(7300), { unit: "hour", n: 2 })
  assert.equal(Model.ageParts(-1), null)
  assert.equal(Model.ageParts(NaN), null)
})

test("the Wi-Fi row: the network, and when the list was last scanned", () => {
  const s = state("healthy")
  s.scan.lastScanAgeS = 240
  assert.deepEqual(Model.wifiSummary(Model.effective(s, Model.emptyPending(), 0, 0)), { state: "connected", name: "Redwood", age: { unit: "min", n: 4 }, wired: false })
  assert.equal(Model.wifiSummary(view("offline")).state, "offline")
  assert.equal(Model.wifiSummary(view("radio-off")).state, "off")
  assert.equal(Model.wifiSummary(view("radio-off")).age, null, "no age with the radio off")
  assert.equal(Model.wifiSummary(view("ethernet")).wired, true)
  const never = state("healthy")
  never.scan.lastScanAgeS = null
  assert.equal(Model.wifiSummary(Model.effective(never, Model.emptyPending(), 0, 0)).age, null)
})

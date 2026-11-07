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

test("nearby: every network but the one in use, strongest first, ties by name", () => {
  const ordered = Model.orderNetworks(view("healthy").networks)
  assert.deepEqual(ordered.map((n) => n.ssid), ["Neighbor-5G", "CoffeeShop", "Home-Guest", "Uni-8021X", "Cafe-OWE"])
  assert.equal(ordered.some((n) => n.active), false, "the card has the one in use")
  const tie = [
    { id: "/org/freedesktop/NetworkManager/AccessPoint/1", ssid: "B", hidden: false, signal: 50, security: "psk", known: false, active: false, uuid: "" },
    { id: "/org/freedesktop/NetworkManager/AccessPoint/2", ssid: "A", hidden: false, signal: 50, security: "psk", known: true, active: false, uuid: "" }
  ]
  assert.deepEqual(Model.orderNetworks(tie).map((n) => n.ssid), ["A", "B"])
})

test("saved is not ranked above stronger: it is a mark, not a sort key", () => {
  const ordered = Model.orderNetworks(view("healthy").networks)
  assert.equal(ordered[2].known, true)
  assert.equal(ordered[0].known, false)
})

test("hidden networks are left out unless they are asked for", () => {
  const nets = view("healthy").networks
  assert.equal(Model.orderNetworks(nets).some((n) => n.hidden), false)
  assert.equal(Model.orderNetworks(nets, true).some((n) => n.hidden), true)
})

test("a repeated SSID keeps the strongest entry", () => {
  const a = { id: "/org/freedesktop/NetworkManager/AccessPoint/1", ssid: "X", hidden: false, signal: 30, security: "psk", known: false, active: false, uuid: "" }
  const b = Object.assign({}, a, { id: "/org/freedesktop/NetworkManager/AccessPoint/2", signal: 80 })
  assert.equal(Model.orderNetworks([a, b]).length, 1)
  assert.equal(Model.orderNetworks([a, b])[0].signal, 80)
  assert.equal(Model.orderNetworks([b, a])[0].signal, 80)
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

test("captions: Saved and 802.1X; an open network says nothing", () => {
  const by = (ssid) => view("healthy").networks.find((n) => n.ssid === ssid)
  const cap = (ssid, ctx) => Model.rowCaption(by(ssid), ctx)
  assert.equal(cap("Home-Guest", {}).key, "saved")
  assert.equal(cap("Home-Guest", {}).tone, "dim")
  assert.equal(cap("CoffeeShop", {}).key, "", "no lock is the sign of an open one")
  assert.equal(cap("Uni-8021X", {}).key, "enterprise")
  assert.equal(cap("Neighbor-5G", {}).key, "")
  assert.equal(cap("Cafe-OWE", {}).key, "", "OWE is encrypted and passwordless: nothing to mark")
})

test("the lock is only on secured networks that are not saved", () => {
  const by = (ssid) => view("healthy").networks.find((n) => n.ssid === ssid)
  assert.equal(Model.showLock(by("Neighbor-5G")), true, "sae, unknown")
  assert.equal(Model.showLock(by("Uni-8021X")), true, "802.1X, unknown")
  assert.equal(Model.showLock(by("Home-Guest")), false, "saved: it says Saved")
  assert.equal(Model.showLock(by("CoffeeShop")), false, "open")
  assert.equal(Model.showLock(by("Cafe-OWE")), false, "OWE")
  assert.equal(Model.showLock(view("healthy").networks.find((n) => n.hidden)), false, "hidden")
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
})

// ---- the signal, the band, the channel -------------------------------------------

test("four bars: the signal in steps", () => {
  assert.deepEqual([0, 1, 24, 25, 49, 50, 74, 75, 100].map(Model.signalBars), [0, 1, 1, 2, 2, 3, 3, 4, 4])
  assert.equal(Model.signalBars(NaN), 0)
  assert.equal(Model.signalBars(250), 4)
})

test("the channel comes from the frequency", () => {
  assert.equal(Model.channelOf(2412), 1)
  assert.equal(Model.channelOf(2437), 6)
  assert.equal(Model.channelOf(2472), 13)
  assert.equal(Model.channelOf(2484), 14)
  assert.equal(Model.channelOf(5180), 36)
  assert.equal(Model.channelOf(5745), 149)
  assert.equal(Model.channelOf(5885), 177)
  assert.equal(Model.channelOf(5955), 1, "6 GHz channel 1")
  assert.equal(Model.channelOf(6175), 45)
  assert.equal(Model.channelOf(0), 0)
  assert.equal(Model.channelOf(900), 0)
  assert.equal(Model.channelOf("nonsense"), 0)
})

test("band chips: 2.4G, 5G, 6G, from the band or, failing that, the frequency", () => {
  assert.equal(Model.bandChip("2.4 GHz", 0), "2.4G")
  assert.equal(Model.bandChip("5 GHz", 0), "5G")
  assert.equal(Model.bandChip("6 GHz", 0), "6G")
  assert.equal(Model.bandChip("", 5180), "5G")
  assert.equal(Model.bandChip("", 2437), "2.4G")
  assert.equal(Model.bandChip("", 6175), "6G")
  assert.equal(Model.bandChip("", 0), "")
  assert.equal(Model.bandChip("60 GHz", 0), "", "not a Wi-Fi band the chip knows")
  assert.equal(Model.bandOfMhz(5180), "5 GHz")
  assert.equal(Model.bandOfMhz(100), "")
})

// ---- the connection card -----------------------------------------------------

test("the active connection card: link, signal, IP, gateway, DNS", () => {
  const raw = JSON.parse(JSON.stringify(require("./helpers.js").raw("healthy")))
  raw.link.signalDbm = -58
  const v = Model.effective(Model.normalizeState(raw), Model.emptyPending(), 0, 0)
  const card = Model.connectionCard(v)
  assert.equal(card.kind, "wifi")
  assert.equal(card.title, "Redwood")
  assert.equal(card.canDisconnect, true)
  const rows = Object.fromEntries(card.rows.map((r) => [r.k, r.v]))
  assert.equal(rows.link, "5 GHz \u00b7 ch 149 \u00b7 866 Mb/s")
  assert.equal(rows.signal, "72% \u00b7 -58 dBm")
  assert.equal(rows.ip, "192.168.1.242/24")
  assert.equal(rows.gateway, "192.168.1.1 \u00b7 4 ms")
  assert.equal(rows.dns, "192.168.1.153")
  assert.deepEqual(card.rows.map((r) => r.k), ["link", "signal", "ip", "gateway", "dns"])
})

test("the card leaves out what the backend has not said, and never makes a channel up", () => {
  const bare = JSON.parse(JSON.stringify(require("./helpers.js").raw("healthy")))
  delete bare.link.frequencyMhz
  delete bare.link.prefix
  const card = Model.connectionCard(Model.effective(Model.normalizeState(bare), Model.emptyPending(), 0, 0))
  const rows = Object.fromEntries(card.rows.map((r) => [r.k, r.v]))
  assert.equal(rows.link, "5 GHz \u00b7 866 Mb/s", "no frequency, no channel")
  assert.equal(rows.signal, "72%")
  assert.equal(rows.ip, "192.168.1.242", "no prefix")
  bare.link.band = ""
  bare.link.frequencyMhz = 2437
  assert.equal(Model.connectionCard(Model.effective(Model.normalizeState(bare), Model.emptyPending(), 0, 0)).rows[0].v, "2.4 GHz \u00b7 ch 6 \u00b7 866 Mb/s")
})

test("frequency and prefix are bounded: nonsense is none", () => {
  for (const bad of [-5, 99999, "x", null]) {
    const l = Model.normalizeState({ link: { frequencyMhz: bad } }).link
    assert.ok(l.frequencyMhz >= 0 && l.frequencyMhz <= 8000, String(bad))
  }
  for (const bad of [0, 33, 128, -1, "x", null]) assert.equal(Model.normalizeState({ link: { prefix: bad } }).link.prefix, 0, String(bad))
  assert.equal(Model.normalizeState({ link: { prefix: 24 } }).link.prefix, 24)
  assert.equal(Model.normalizeState({ networks: [{ id: "/org/freedesktop/NetworkManager/AccessPoint/1", ssid: "a", frequencyMhz: 5180 }] }).networks[0].frequencyMhz, 5180)
})

test("the card for a wire, with no link, with the radio off and without the backend", () => {
  const wire = Model.connectionCard(view("ethernet"))
  assert.equal(wire.kind, "ethernet")
  assert.equal(wire.canDisconnect, false, "only a Wi-Fi link is dropped from here")
  assert.equal(wire.rows.some((r) => r.k === "signal"), false)
  assert.equal(wire.title, "")
  assert.equal(Model.connectionCard(view("offline")).kind, "none")
  assert.deepEqual(Model.connectionCard(view("offline")).rows, [])
  assert.equal(Model.connectionCard(view("radio-off")).kind, "off")
  const down = Model.effective(state("healthy"), Model.emptyPending(), 0, 0, true)
  assert.equal(Model.connectionCard(down).kind, "nobackend")
})

test("the card says so when the link has no DNS servers", () => {
  const rows = Model.connectionCard(view("none")).rows
  const dns = rows.find((r) => r.k === "dns")
  assert.deepEqual([dns.v, dns.key], ["", "card.noDns"])
})

test("the card names the resolver in use, and a custom pair by its first two", () => {
  assert.equal(Model.connectionCard(view("custom")).rows.find((r) => r.k === "dns").v.indexOf("9.9.9.9") >= 0, true)
  assert.equal(Model.connectionCard(view("fallback")).rows.find((r) => r.k === "dns").v, "192.168.1.1")
})

// ---- scan ages -------------------------------------------------------------

test("scan ages read as just now, minutes, hours", () => {
  assert.deepEqual(Model.ageParts(12), { unit: "now", n: 0 })
  assert.deepEqual(Model.ageParts(59), { unit: "now", n: 0 })
  assert.deepEqual(Model.ageParts(240), { unit: "min", n: 4 })
  assert.deepEqual(Model.ageParts(3599), { unit: "min", n: 59 })
  assert.deepEqual(Model.ageParts(7300), { unit: "hour", n: 2 })
  assert.equal(Model.ageParts(-1), null)
  assert.equal(Model.ageParts(NaN), null)
})


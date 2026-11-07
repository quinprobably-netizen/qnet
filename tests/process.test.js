"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, view, BIN } = require("./helpers.js")

const AP = "/org/freedesktop/NetworkManager/AccessPoint/12"
const UUID = "4a0f7e58-2d3c-4b8e-9c61-0d5a1f7e9b21"

test("every action is an argv array under the absolute qnet path", () => {
  assert.deepEqual(Model.argvDns(BIN, "pihole", false), [BIN, "dns", "pihole"])
  assert.deepEqual(Model.argvDns(BIN, "auto", true), [BIN, "dns", "auto", "--force"])
  assert.deepEqual(Model.argvPin(BIN, UUID), [BIN, "dns", "pin", UUID])
  assert.deepEqual(Model.argvPause(BIN, 300), [BIN, "pihole", "pause", "300"])
  assert.deepEqual(Model.argvResume(BIN), [BIN, "pihole", "resume"])
  assert.deepEqual(Model.argvConnect(BIN, AP), [BIN, "wifi", "connect", AP])
  assert.deepEqual(Model.argvDown(BIN), [BIN, "wifi", "down"])
  assert.deepEqual(Model.argvForget(BIN, UUID), [BIN, "wifi", "forget", UUID])
  assert.deepEqual(Model.argvScan(BIN), [BIN, "wifi", "scan"])
  assert.deepEqual(Model.argvRadio(BIN, true), [BIN, "wifi", "radio", "on"])
  assert.deepEqual(Model.argvRadio(BIN, false), [BIN, "wifi", "radio", "off"])
  assert.deepEqual(Model.argvPortal(BIN), [BIN, "portal"])
})

test("input that does not validate yields no command at all", () => {
  assert.equal(Model.argvDns(BIN, "dhcp", false), null)
  assert.equal(Model.argvDns("qnet", "pihole", false), null, "a relative binary is refused")
  assert.equal(Model.argvDns("", "pihole", false), null)
  assert.equal(Model.argvPin(BIN, "not-a-uuid"), null)
  assert.equal(Model.argvPin(BIN, UUID + "; reboot"), null)
  assert.equal(Model.argvConnect(BIN, "Redwood"), null, "actions use the AP path, never the SSID")
  assert.equal(Model.argvConnect(BIN, AP + "/../../x"), null)
  assert.equal(Model.argvForget(BIN, ""), null)
  assert.equal(Model.argvPause(BIN, 0), null)
  assert.equal(Model.argvPause(BIN, 10 * 86400), null)
})

test("the passphrase and SSIDs never appear in any argv builder's output", () => {
  const all = [
    Model.argvDns(BIN, "pihole"), Model.argvPin(BIN, UUID), Model.argvPause(BIN, 300), Model.argvResume(BIN),
    Model.argvConnect(BIN, AP), Model.argvDown(BIN), Model.argvForget(BIN, UUID), Model.argvScan(BIN),
    Model.argvRadio(BIN, true), Model.argvPortal(BIN), Model.argvTerminal("nmtui", BIN), Model.argvTerminal("setup", BIN, "192.168.1.153")
  ]
  for (const a of all) {
    assert.ok(Array.isArray(a))
    for (const el of a) assert.equal(typeof el, "string")
    assert.ok(!a.includes("bash") && !a.includes("sh") && !a.includes("-c"), JSON.stringify(a))
  }
})

test("terminal launches: nmtui and Pi-hole setup, as plain words", () => {
  assert.deepEqual(Model.argvTerminal("nmtui", BIN), ["omarchy-launch-floating-terminal-with-presentation", "nmtui"])
  assert.deepEqual(Model.argvTerminal("setup", BIN, "192.168.1.153"),
    ["omarchy-launch-floating-terminal-with-presentation", BIN, "pihole", "setup", "192.168.1.153"])
  assert.deepEqual(Model.argvTerminal("setup", BIN, ""),
    ["omarchy-launch-floating-terminal-with-presentation", BIN, "pihole", "setup", Model.DEFAULT_PIHOLE_ADDR])
  assert.equal(Model.argvTerminal("setup", BIN, "1.2.3.4; reboot")[4], Model.DEFAULT_PIHOLE_ADDR, "a bad address falls back to the default")
  assert.equal(Model.argvTerminal("setup", "/home/a b/.local/bin/qnet", "1.2.3.4")[1], "qnet", "a path with a space is not handed to the launcher's bash")
  assert.equal(Model.argvTerminal("evil", BIN), null)
})

test("admin links and copying", () => {
  assert.deepEqual(Model.argvOpenUrl("https://192.168.1.153/admin/"), ["omarchy-launch-browser", "https://192.168.1.153/admin/"])
  assert.equal(Model.argvOpenUrl("javascript:alert(1)"), null)
  assert.equal(Model.argvOpenUrl(""), null)
  assert.deepEqual(Model.argvCopy("192.168.1.242"), ["wl-copy", "--", "192.168.1.242"])
  assert.equal(Model.argvCopy("--help"), null)
  assert.equal(Model.argvCopy("$(id)"), null)
  assert.equal(Model.argvCopy(""), null)
})

// ---- results --------------------------------------------------------------

test("a result is the last JSON line of stdout", () => {
  const r = Model.parseResult('log noise\n{"ok":true,"verifiedVia":"192.168.1.153"}\n', 0)
  assert.equal(r.ok, true)
  assert.equal(r.verifiedVia, "192.168.1.153")
  const f = Model.parseResult('{"ok":false,"error":"confirm","detail":"9.9.9.9"}', 1)
  assert.deepEqual([f.ok, f.error, f.detail], [false, "confirm", "9.9.9.9"])
})

test("no answer, junk and a non-boolean ok are failures", () => {
  assert.equal(Model.parseResult("", 0).ok, false)
  assert.equal(Model.parseResult("", 0).error, "noanswer")
  assert.equal(Model.parseResult("", 1).error, "exit")
  assert.equal(Model.parseResult("not json", 0).ok, false)
  assert.equal(Model.parseResult('{"ok":"yes"}', 0).ok, false)
  assert.equal(Model.parseResult(null, 0).ok, false)
})

test("failures map to a message code; backend text is cleaned and bounded", () => {
  assert.equal(Model.failure({ error: "confirm" }).code, "confirm")
  assert.equal(Model.failure({ error: "enterprise" }).code, "enterprise")
  assert.equal(Model.failure({ error: "wrong-password" }).code, "wrongPassword")
  assert.equal(Model.failure({ error: "noanswer" }).code, "noAnswer")
  assert.equal(Model.failure({ error: "timeout" }).code, "timeout")
  const g = Model.failure({ error: "something <b>odd</b>\u0007" + "x".repeat(200) })
  assert.equal(g.code, "generic")
  assert.ok(g.text.length <= 60)
  assert.ok(!g.text.includes("\u0007"))
})

test("a Pi-hole switch that was answered by another server is called out", () => {
  const v = view("healthy")
  assert.equal(Model.verifyMismatch("pihole", { verifiedVia: "192.168.1.153" }, v), "")
  assert.equal(Model.verifyMismatch("pihole", { verifiedVia: "1.1.1.1" }, v), "1.1.1.1")
  assert.equal(Model.verifyMismatch("auto", { verifiedVia: "1.1.1.1" }, v), "")
  assert.equal(Model.verifyMismatch("pihole", { verifiedVia: "" }, v), "")
})

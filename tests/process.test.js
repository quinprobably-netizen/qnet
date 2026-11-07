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
  assert.deepEqual(Model.argvPin(BIN, [UUID, "0c3d9f12-88aa-4e77-b5d1-72f6e0a1c9d3"]),
    [BIN, "dns", "pin", UUID, "0c3d9f12-88aa-4e77-b5d1-72f6e0a1c9d3"], "several profiles, one command")
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
  assert.equal(Model.argvPin(BIN, [UUID, "nope"]), null, "one bad uuid refuses the lot")
  assert.equal(Model.argvPin(BIN, []), null)
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
    Model.argvRadio(BIN, true), Model.argvPortal(BIN), Model.argvTerminal("nmtui", BIN), Model.argvTerminal("setup", BIN)
  ]
  for (const a of all) {
    assert.ok(Array.isArray(a))
    for (const el of a) assert.equal(typeof el, "string")
    assert.ok(!a.includes("bash") && !a.includes("sh") && !a.includes("-c"), JSON.stringify(a))
  }
})

test("terminal launches: nmtui and Pi-hole setup, as plain words", () => {
  assert.deepEqual(Model.argvTerminal("nmtui", BIN), ["omarchy-launch-floating-terminal-with-presentation", "nmtui"])
  assert.equal(Model.argvTerminal("evil", BIN), null)
})

test("setup is launched with no address: it asks the user to type it", () => {
  assert.deepEqual(Model.argvTerminal("setup", BIN),
    ["omarchy-launch-floating-terminal-with-presentation", BIN, "pihole", "setup"])
  assert.deepEqual(Model.argvTerminal("setup", BIN, "192.168.1.153"),
    ["omarchy-launch-floating-terminal-with-presentation", BIN, "pihole", "setup"], "a detected address is never passed on")
  assert.equal(Model.argvTerminal("setup", "/home/a b/.local/bin/qnet")[1], "qnet", "a path with a space is not handed to the launcher's bash")
  assert.equal(Model.DEFAULT_PIHOLE_ADDR, undefined, "there is no built-in address to fall back on")
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

test("dns pihole results: blocked with verifiedVia, or a verifyError", () => {
  const good = Model.parseResult('{"ok":true,"verifiedVia":"192.168.1.153","blocked":true}', 0)
  assert.equal(good.blocked, true)
  assert.equal(good.verifiedVia, "192.168.1.153")
  assert.equal(good.verifyError, "")
  const bad = Model.parseResult('{"ok":true,"verifyError":"canary answered 3.4.5.6"}', 0)
  assert.equal(bad.blocked, false)
  assert.equal(bad.verifiedVia, "")
  assert.equal(bad.verifyError, "canary answered 3.4.5.6")
  assert.equal(Model.parseResult('{"ok":true,"noop":true,"verifiedVia":"192.168.1.153","blocked":true}', 0).ok, true)
})

test("a Pi-hole switch that its canary did not confirm is called out, nothing else is", () => {
  const good = Model.parseResult('{"ok":true,"verifiedVia":"192.168.1.153","blocked":true}', 0)
  const bad = Model.parseResult('{"ok":true,"verifyError":"canary answered 3.4.5.6"}', 0)
  const old = Model.parseResult('{"ok":true}', 0)
  assert.equal(Model.verifyNote("pihole", good), "")
  assert.equal(Model.verifyNote("pihole", bad), "canary answered 3.4.5.6")
  assert.equal(Model.verifyNote("pihole", old), "", "a backend that says neither is not accused")
  assert.equal(Model.verifyNote("auto", bad), "")
  assert.equal(Model.verifyNote("pihole", Model.parseResult('{"ok":false,"error":"x","verifyError":"y"}', 1)), "", "a failure has its own message")
  assert.equal(Model.verifyNote("pihole", null), "")
})

// ---- round 3: scans, deadlines and the new error codes -------------------------

test("scan: forced, or only when stale", () => {
  assert.deepEqual(Model.argvScan(BIN), [BIN, "wifi", "scan"])
  assert.deepEqual(Model.argvScan(BIN, 60), [BIN, "wifi", "scan", "--if-stale", "60"])
  assert.deepEqual(Model.argvScan(BIN, 0), [BIN, "wifi", "scan", "--if-stale", "0"])
  assert.equal(Model.argvScan(BIN, -1), null)
  assert.equal(Model.argvScan(BIN, "60; reboot"), null)
  assert.equal(Model.argvScan("qnet", 60), null)
  assert.equal(Model.SCAN_IF_STALE_S, 60)
})

test("an action has about 25 s to answer", () => {
  assert.equal(Model.ACTION_DEADLINE_MS, 25000)
  const runner = require("fs").readFileSync(require("path").join(__dirname, "..", "components", "ActionRunner.qml"), "utf8")
  assert.match(runner, /property int timeoutMs: 25000/)
})

test("too-soon carries how long to wait; busy and skipped are told apart", () => {
  const soon = Model.parseResult('{"ok":false,"error":"too-soon","retryInS":12}', 1)
  assert.equal(soon.retryInS, 12)
  assert.deepEqual(Model.failure(soon), { code: "tooSoon", text: "", retryInS: 12 })
  assert.equal(Model.failure({ error: "too-soon" }).retryInS, 0)
  assert.deepEqual(Model.failure(Model.parseResult('{"ok":false,"error":"busy"}', 1)), { code: "busy", text: "", retryInS: 0 })
  assert.deepEqual(Model.failure(Model.parseResult('{"ok":false,"error":"skipped"}', 0)), { code: "skipped", text: "", retryInS: 0 })
  assert.equal(Model.parseResult('{"ok":false,"error":"too-soon","retryInS":999999}', 1).retryInS, 3600, "bounded")
  assert.equal(Model.parseResult('{"ok":false,"error":"too-soon","retryInS":"x"}', 1).retryInS, 0)
})

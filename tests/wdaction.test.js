"use strict"
// The watchdog tab's own JavaScript, run as it is in Panel.qml: each function
// is cut out of the file and evaluated in a sandbox whose globals stand in for
// the panel's properties and the few things it calls (runCli, the service, the
// catalog). It checks what the shell cannot be started here to check: that an
// action that comes while another runs waits its turn instead of being lost,
// that a refusal says busy, that the PIN is cleared from every object the
// callback keeps, that leaving the tab sends the label field's edit once, and
// that the order of the jacks is the panel's and not the visit's.
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("fs")
const path = require("path")
const vm = require("node:vm")
const { Model, BIN } = require("./helpers.js")

const PANEL = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8")
const M1 = "02:00:00:00:00:17"
const M2 = "02:00:00:00:00:28"

// The source of `function name(...) { ... }` as Panel.qml has it, found by
// matching braces and skipping strings and comments.
function fnSource(name) {
  const at = PANEL.indexOf("  function " + name + "(")
  assert.ok(at >= 0, "Panel.qml has no function " + name)
  let i = PANEL.indexOf("{", PANEL.indexOf(")", at))
  const start = at
  let depth = 0
  for (; i < PANEL.length; i++) {
    const c = PANEL[i]
    if (c === '"' || c === "'") {
      i++
      while (i < PANEL.length && PANEL[i] !== c) { if (PANEL[i] === "\\") i++; i++ }
    } else if (c === "/" && PANEL[i + 1] === "/") {
      while (i < PANEL.length && PANEL[i] !== "\n") i++
    } else if (c === "{") depth++
    else if (c === "}" && --depth === 0) return PANEL.slice(start, i + 1)
  }
  throw new Error("unbalanced " + name)
}

// The body of the settle timer's handler.
function settleSource() {
  const m = /id: wdSettleTimer[\s\S]*?onTriggered: \{([\s\S]*?)\n    \}/.exec(PANEL)
  assert.ok(m, "the settle timer")
  return m[1]
}

function sandbox(extra) {
  const log = { runs: [], sent: [], failed: [], commits: [], timers: 0 }
  const ctx = {
    Model: Model,
    bin: BIN,
    root: null,
    opened: true,
    page: "watchdog",
    rawState: { watchdog: { bay: { jacks: [] } } },
    wdRunning: 0,
    wdSettling: false,
    wdQueue: [],
    wdCurrent: "",
    wdNote: "",
    wdOrder: [],
    wdScroll: 3,
    wdTicket: null,
    wdFlip: false,
    wdPinOpen: false,
    wdPinNote: "",
    wdLabelFocus: false,
    wdPinFocus: false,
    strings: { t: (k) => k },
    failureText: (f) => (f.text === "" ? "" : "failed: " + f.text),
    QnetService: { send: (c) => log.sent.push(c) },
    wdSettleTimer: { restart: () => { log.timers++ } },
    runCli: (argv, opts, cb) => { log.runs.push({ argv: argv, secret: opts.secret, opts: opts, cb: cb }); return true },
    setWdNote: (t) => { ctx.wdNote = t },
    wdLabelFailed: (mac) => log.failed.push(mac),
    wdCommitRequested: () => log.commits.push({ ticket: ctx.wdTicket, scroll: ctx.wdScroll, order: ctx.wdOrder.slice() }),
    wdSetTicket: (t) => { ctx.wdTicket = t },
    wdReturnFocus: () => {}
  }
  Object.assign(ctx, extra || {})
  ctx.root = ctx
  vm.createContext(ctx)
  for (const f of ["wdAction", "wdStart", "wdDrain", "wdLabel", "wdReset", "wdHold", "wdOpen", "wdSync"]) vm.runInContext(fnSource(f), ctx)
  const settle = () => vm.runInContext("(function() {" + settleSource() + "})()", ctx)
  return { ctx, log, settle }
}

const ok = { ok: true }
const fail = { ok: false, error: "refused", detail: "", code: 1 }
// a run as `qnet watchdog …` was asked, without the binary and the noun
const sayOf = (run) => run.argv.slice(2).join(" ")

test("an action with nothing running starts at once, and its success tells the watcher and starts the settle", () => {
  const { ctx, log } = sandbox()
  assert.equal(ctx.wdAction("gate", [M1, 300]), true)
  assert.equal(log.runs.length, 1)
  assert.equal(ctx.wdRunning, 1)
  assert.equal(ctx.wdCurrent, Model.actionKey("gate", [M1, 300]))
  log.runs[0].cb(ok)
  assert.deepEqual(log.sent, ["devices"])
  assert.equal(ctx.wdRunning, 0)
  assert.equal(ctx.wdSettling, true)
  assert.equal(log.timers, 1)
})

test("a label that loses the keys while a patch runs (or settles) is queued, and sent after both", () => {
  const { ctx, log, settle } = sandbox()
  assert.equal(ctx.wdAction("patch", [M1, "pass"]), true)
  // the click on ADS PASS does not take the focus; the field's commit comes in the middle of the patch ...
  assert.equal(ctx.wdLabel(M1, "Sam's phone"), true, "taken, not refused")
  assert.equal(log.runs.length, 1, "it waits")
  assert.equal(ctx.wdQueue.length, 1)
  assert.equal(ctx.wdNote, "", "and says nothing: it is not lost")
  // ... the patch answers: the settle begins and the label still waits
  log.runs[0].cb(ok)
  assert.equal(ctx.wdSettling, true)
  assert.equal(log.runs.length, 1)
  assert.equal(ctx.wdLabel(M1, "Sam's phone 2"), true, "an edit in the settle window waits too, and replaces the one waiting")
  assert.equal(ctx.wdQueue.length, 1)
  // the state has had its turn: the label goes
  settle()
  assert.equal(ctx.wdSettling, false)
  assert.equal(log.runs.length, 2)
  assert.deepEqual(log.runs[1].argv.slice(-3), ["label", M1, "Sam's phone 2"])
  assert.equal(ctx.wdQueue.length, 0)
  log.runs[1].cb(ok)
  assert.deepEqual(log.failed, [])
  assert.equal(ctx.wdSettling, true)
})

test("key presses in the busy window wait their turn in order: patch, gate, NORMAL, in the order pressed", () => {
  const { ctx, log, settle } = sandbox()
  ctx.wdAction("gate", [M1, 300])
  assert.equal(ctx.wdAction("patch", [M1, "pass"]), true)
  assert.equal(ctx.wdAction("exempt-default", ["on"]), true)
  assert.equal(ctx.wdAction("gate", [M2, 0]), true)
  assert.equal(log.runs.length, 1)
  for (let n = 1; n <= 3; n++) {
    log.runs[n - 1].cb(ok)
    assert.equal(log.runs.length, n, "no one starts inside the settle")
    settle()
    assert.equal(log.runs.length, n + 1, "one after each settle")
  }
  assert.deepEqual(log.runs.map(sayOf), [
    "gate " + M1 + " 300",
    "patch " + M1 + " pass",
    "exempt-default on",
    "gate " + M2 + " 0"
  ])
})

test("a failed action starts the next one at once (no settle) and the note is the failure's", () => {
  const { ctx, log } = sandbox()
  ctx.wdAction("forget", [M1])
  ctx.wdAction("gate", [M2, 300])
  log.runs[0].cb({ ok: false, error: "absent", detail: "", code: 1 })
  assert.equal(ctx.wdSettling, false)
  assert.equal(ctx.wdCurrent, Model.actionKey("gate", [M2, 300]))
  assert.equal(log.runs.length, 2, "no settle after a failure")
  assert.deepEqual(log.sent, [], "the watcher is told nothing")
})

test("a label that fails says so for the field, and the same press twice is one", () => {
  const { ctx, log, settle } = sandbox()
  ctx.wdLabel(M1, "x")
  log.runs[0].cb(fail)
  assert.deepEqual(log.failed, [M1])
  // the same key pressed again while it runs is already being served
  ctx.wdAction("forget", [M2])
  assert.equal(ctx.wdAction("forget", [M2]), true)
  assert.equal(ctx.wdQueue.length, 0)
  assert.equal(log.runs.length, 2)
  log.runs[1].cb(ok)
  assert.equal(ctx.wdAction("forget", [M2]), true, "also in the settle window")
  assert.equal(ctx.wdQueue.length, 0)
  settle()
  assert.equal(log.runs.length, 2)
})

test("an action that is truly refused says busy (the full queue); an invalid one is no busy", () => {
  const { ctx, log } = sandbox()
  ctx.wdAction("gate", [M1, 300])
  for (let i = 0; i < Model.WD_QUEUE_MAX; i++) assert.equal(ctx.wdAction("gate", ["02:00:00:00:01:" + (16 + i).toString(16), 300]), true)
  assert.equal(ctx.wdNote, "")
  assert.equal(ctx.wdLabel(M2, "one too many"), false)
  assert.equal(ctx.wdNote, "err.busy", "the note is the catalog's busy wording")
  assert.equal(ctx.wdQueue.length, Model.WD_QUEUE_MAX)
  ctx.wdNote = ""
  assert.equal(ctx.wdAction("gate", ["not a mac", 300]), false)
  assert.equal(ctx.wdNote, "", "an invalid action is not busy")
  assert.equal(log.runs.length, 1)
})

test("the PIN never waits, says nothing itself (the caller says busy) and is cleared from every object it was in", () => {
  // idle: it runs, the runner got it, and the opts object the callback's closure keeps does not hold it
  let { ctx, log } = sandbox()
  const opts = { secret: "4821", silent: true }
  assert.equal(ctx.wdAction("pin", ["set"], () => {}, opts), true)
  assert.equal(log.runs[0].secret, "4821", "the runner was given it")
  assert.equal(opts.secret, "", "and nothing the panel keeps holds it")
  assert.equal(log.runs[0].opts.secret, "")
  assert.deepEqual(log.runs[0].argv.slice(-2), ["pin", "set"], "never on the command line")
  assert.doesNotMatch(JSON.stringify(log.runs[0].argv), /4821/)
  // busy: refused, no note of its own (silent), not queued, and cleared as well
  ;({ ctx, log } = sandbox())
  ctx.wdAction("gate", [M1, 300])
  const busy = { secret: "4821", silent: true }
  assert.equal(ctx.wdAction("pin", ["set"], () => {}, busy), false)
  assert.equal(busy.secret, "")
  assert.equal(ctx.wdQueue.length, 0)
  assert.equal(ctx.wdNote, "")
  assert.doesNotMatch(JSON.stringify(ctx.wdQueue), /4821/)
  // the flags the callback needs survive the clearing: a silent failure sets no note
  ;({ ctx, log } = sandbox())
  ctx.wdAction("pin", ["set"], () => {}, { secret: "4821", silent: true })
  log.runs[0].cb(fail)
  assert.equal(ctx.wdNote, "")
  ;({ ctx, log } = sandbox())
  ctx.wdAction("gate", [M1, 300])
  log.runs[0].cb({ ok: false, error: "refused", detail: "x", code: 1 })
  assert.notEqual(ctx.wdNote, "", "and a loud one does")
  // the source clears it once the runner has it, and keeps wipeSecrets
  const start = fnSource("wdStart")
  assert.ok(start.indexOf('if (o.secret !== undefined) o.secret = ""') > start.indexOf("runCli(argv, o, function(res)"), "cleared right after runCli has started")
  assert.match(PANEL, /function wipeSecrets\(\) \{\s*if \(secretRun\) secretRun\.wipe\(\)\s*secretRun = null/)
})

test("leaving the tab or closing the panel sends what the label field holds first, once; the order stays", () => {
  const { ctx, log } = sandbox()
  ctx.wdTicket = { kind: "device", mac: M1 }
  ctx.wdOrder = [M2, M1]
  ctx.wdFlip = true
  ctx.wdNote = "x"
  ctx.wdReset()
  assert.equal(log.commits.length, 1, "exactly one commit request")
  assert.deepEqual(JSON.parse(JSON.stringify(log.commits[0].ticket)), { kind: "device", mac: M1 }, "asked while the ticket (and its field) is still up")
  assert.equal(log.commits[0].scroll, 3)
  assert.equal(ctx.wdTicket, null)
  assert.equal(ctx.wdScroll, 0)
  assert.equal(ctx.wdFlip, false)
  assert.equal(ctx.wdNote, "")
  assert.deepEqual(ctx.wdOrder.slice(), [M2, M1], "the held order is not the visit's")
})

test("the order of the jacks is held while the panel is open: set on opening or with the first jacks, kept across the views, new ones in front of the offline", () => {
  const jack = (m, off) => ({ mac: m, offline: off === true })
  const state = (...jacks) => ({ watchdog: { bay: { jacks: jacks, calls: [], lamps: [] } } })
  const A = "02:00:00:00:00:0a", B = "02:00:00:00:00:0b", C = "02:00:00:00:00:0c", D = "02:00:00:00:00:0d"
  const { ctx } = sandbox({ opened: true, page: "main" })
  // the panel is open on the main view and the first jacks come in: the order is set (not only on the tab)
  ctx.rawState = state(jack(A), jack(B), jack(C, true))
  ctx.wdSync()
  assert.deepEqual(ctx.wdOrder.slice(), [A, B, C])
  // another state ranks them otherwise and brings D: the held order stands, D goes in front of the offline one
  ctx.rawState = state(jack(C, true), jack(B), jack(D), jack(A))
  ctx.wdSync()
  assert.deepEqual(ctx.wdOrder.slice(), [A, B, D, C])
  // entering and leaving the tab does not sort again
  ctx.wdOpen()
  assert.deepEqual(ctx.wdOrder.slice(), [A, B, D, C], "entering the tab")
  ctx.wdReset()
  assert.deepEqual(ctx.wdOrder.slice(), [A, B, D, C], "leaving it")
  // a closed panel keeps no order up
  ctx.opened = false
  ctx.rawState = state(jack(D), jack(A))
  ctx.wdSync()
  assert.deepEqual(ctx.wdOrder.slice(), [A, B, D, C])
  // the panel's open and close clear it (resetUi) and its opening sets it from what is known
  assert.match(fnSource("resetUi"), /closeTransients\(\)\s*\n\s*wdOrder = \[\]/)
  assert.match(PANEL, /onOpenedChanged: \{[\s\S]*?if \(opened\) \{\s*resetUi\(\)[\s\S]*?wdHold\(\)[\s\S]*?\} else \{[\s\S]*?resetUi\(\)/)
  assert.doesNotMatch(fnSource("wdReset"), /wdOrder/, "wdReset is the visit's")
  assert.doesNotMatch(fnSource("wdOpen"), /wdOrder\s*=/)
})

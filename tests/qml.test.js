"use strict"
// Static checks on the QML, since the shell cannot be started here: every
// rule the plugin guide makes checkable by reading the source.
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("fs")
const path = require("path")

const ROOT = path.join(__dirname, "..")
const FILES = ["Panel.qml", "QnetService.qml"].concat(
  fs.readdirSync(path.join(ROOT, "components")).filter((f) => f.endsWith(".qml")).map((f) => "components/" + f))

function read(f) { return fs.readFileSync(path.join(ROOT, f), "utf8") }

// The body of every `Text { ... }` (the type exactly, not TextField or
// TextButton), found by matching braces and skipping strings and comments.
function textBlocks(src) {
  const blocks = []
  const re = /(^|[^A-Za-z0-9_.])Text\s*\{/g
  let m
  while ((m = re.exec(src))) {
    let i = m.index + m[0].length
    let depth = 1
    const start = i
    while (i < src.length && depth > 0) {
      const c = src[i]
      if (c === '"' || c === "'") {
        const q = c
        i++
        while (i < src.length && src[i] !== q) { if (src[i] === "\\") i++; i++ }
      } else if (c === "/" && src[i + 1] === "/") {
        while (i < src.length && src[i] !== "\n") i++
      } else if (c === "{") depth++
      else if (c === "}") depth--
      i++
    }
    blocks.push({ line: src.slice(0, m.index).split("\n").length + (m[1] === "\n" ? 1 : 0), body: src.slice(start, i - 1) })
  }
  return blocks
}

// A block's own properties: nested { } removed.
function ownBody(body) {
  let out = ""
  let depth = 0
  for (const c of body) {
    if (c === "{") depth++
    else if (c === "}") depth--
    else if (depth === 0) out += c
  }
  return out
}

test("every Text is plain text", () => {
  let count = 0
  for (const f of FILES) {
    for (const b of textBlocks(read(f))) {
      count++
      assert.match(ownBody(b.body), /textFormat:\s*Text\.PlainText/, f + ":" + b.line + " has a Text without textFormat: Text.PlainText")
    }
  }
  assert.ok(count > 25, "found the Text elements (" + count + ")")
})

test("no shell anywhere: no bash or sh, no -c, no bar.run", () => {
  for (const f of FILES.concat(["Model.js"])) {
    const src = read(f)
    assert.doesNotMatch(src, /["']bash["']/, f)
    assert.doesNotMatch(src, /["']sh["']/, f)
    assert.doesNotMatch(src, /["']-c["']/, f)
    assert.doesNotMatch(src, /\bbar\.run\(/, f)
    assert.doesNotMatch(src, /openUrlExternally/, f)
  }
})

test("durations go through Style.duration, and nothing is eased in or bounced", () => {
  for (const f of FILES) {
    const src = read(f)
    for (const [i, line] of src.split("\n").entries()) {
      if (/^\s*\/\//.test(line)) continue
      if (/\bduration:/.test(line)) assert.match(line, /duration:\s*Style\.duration\(\d+\)/, f + ":" + (i + 1) + " " + line.trim())
      assert.doesNotMatch(line, /Easing\.(In|InOut|OutIn)(Quad|Cubic|Quart|Quint|Sine|Expo|Circ|Back|Bounce|Elastic)/, f + ":" + (i + 1))
      assert.doesNotMatch(line, /Easing\.OutBounce|Easing\.OutBack|Easing\.OutElastic/, f + ":" + (i + 1))
    }
  }
})

test("durations stay under 300 ms (the spinner turns, it is not an entrance)", () => {
  for (const f of FILES) {
    for (const m of read(f).matchAll(/Style\.duration\((\d+)\)/g)) {
      const ms = Number(m[1])
      if (f === "components/NetworkList.qml" && ms === 900) continue
      assert.ok(ms <= 300, f + " " + ms)
    }
  }
})

test("one font: no family but the bar's", () => {
  for (const f of FILES) {
    for (const [i, line] of read(f).split("\n").entries()) {
      for (const m of line.matchAll(/font\.family:\s*(.+)$/g)) {
        assert.match(m[1], /fontFamily|Style\.font\.family/, f + ":" + (i + 1) + " " + line.trim())
      }
      assert.doesNotMatch(line, /["'](Adwaita|Inter|Noto Sans|sans-serif|DejaVu)/, f + ":" + (i + 1))
    }
  }
})

test("sizes come from Style.font or the three panel sizes", () => {
  for (const f of FILES) {
    for (const [i, line] of read(f).split("\n").entries()) {
      for (const m of line.matchAll(/font\.pixelSize:\s*(.+)$/g)) {
        const v = m[1].trim()
        assert.ok(/(type(Title|Body|Small)|Style\.font\.|Style\.space|fontSize|size\b)/.test(v), f + ":" + (i + 1) + " " + line.trim())
      }
    }
  }
})

test("Model.js has no QML imports and loads in node", () => {
  const src = read("Model.js")
  assert.doesNotMatch(src, /^\s*import\s/m)
  assert.doesNotMatch(src, /\bQt\./)
  assert.doesNotMatch(src, /\.pragma/)
})

// ---- i18n -----------------------------------------------------------------

function usedKeys() {
  const exact = new Set()
  const prefixes = new Set()
  for (const f of FILES) {
    const src = read(f)
    for (const m of src.matchAll(/(?<![A-Za-z0-9_])tn?\(\s*"([A-Za-z][A-Za-z0-9.]*)"(\s*\+)?/g)) {
      if (m[2]) prefixes.add(m[1])
      else exact.add(m[1])
    }
  }
  return { exact, prefixes }
}

test("every string the QML asks for is in en.json", () => {
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "i18n", "en.json"), "utf8"))
  const { exact, prefixes } = usedKeys()
  assert.ok(exact.size > 50)
  for (const k of exact) assert.ok(k in cat, "missing from en.json: " + k)
  for (const p of prefixes) assert.ok(Object.keys(cat).some((k) => k.startsWith(p)), "no keys for the family " + p)
})

test("every string in en.json is used, and plurals carry one and other", () => {
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "i18n", "en.json"), "utf8"))
  const { exact, prefixes } = usedKeys()
  for (const k of Object.keys(cat)) {
    const used = exact.has(k) || Array.from(prefixes).some((p) => k.startsWith(p))
    assert.ok(used, "unused in en.json: " + k)
    if (typeof cat[k] === "object") assert.ok("one" in cat[k] && "other" in cat[k], k)
  }
})

test("the keys Model.js hands back for captions, states and tips all have text", () => {
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "i18n", "en.json"), "utf8"))
  const Model = require("../Model.js")
  for (const k of ["connected", "connecting", "disconnecting", "forgetting", "forget", "portal", "limited", "open", "enterprise", "hidden"])
    assert.ok("net.caption." + k in cat, k)
  for (const k of ["connected", "limited", "portal", "nointernet", "offline", "off", "nobackend"]) assert.ok("header.state." + k in cat, k)
  for (const k of ["portal", "limited", "fallback", "unreachable", "bypassed"]) assert.ok("bar." + k in cat, k)
  for (const k of ["router", "quad9", "cloudflare"]) assert.ok("fallback." + k in cat, k)
  for (const k of ["auth", "tls", "unreachable"]) assert.ok("hero.api." + k in cat, k)
  assert.ok(Model.GLYPH.wifi.length === 5)
})

test("the manifest is the one SPEC asks for", () => {
  const m = JSON.parse(read("manifest.json"))
  assert.equal(m.id, "qqq.qnet")
  assert.equal(m.name, "qnet")
  assert.deepEqual(m.kinds, ["bar-widget"])
  assert.equal(m.entryPoints.barWidget, "Panel.qml")
  assert.equal(m.barWidget.category, "Network")
  assert.equal(m.barWidget.defaultSection, "right")
})

test("one watch process: the service is a singleton and Panel never starts a poller", () => {
  assert.match(read("qmldir"), /^singleton QnetService 1\.0 QnetService\.qml$/m)
  assert.match(read("QnetService.qml"), /^pragma Singleton/m)
  assert.doesNotMatch(read("Panel.qml"), /"watch"/)
  assert.equal((read("QnetService.qml").match(/command = \[bin, "watch"\]/g) || []).length, 1)
})

test("the Text scanner itself: it finds a Text without PlainText and skips TextField", () => {
  const bad = 'Item {\n  Text {\n    text: "a { b }"\n    Rectangle { textFormat: Text.PlainText }\n  }\n  TextField { text: "x" }\n  Text { textFormat: Text.PlainText; text: "ok" }\n}'
  const blocks = textBlocks(bad)
  assert.equal(blocks.length, 2)
  assert.doesNotMatch(ownBody(blocks[0].body), /textFormat:\s*Text\.PlainText/, "a nested child's format does not count")
  assert.match(ownBody(blocks[1].body), /textFormat:\s*Text\.PlainText/)
})

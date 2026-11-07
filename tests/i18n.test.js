"use strict"
// The strings the panel asks for, checked against i18n/en.json: every key
// that is referenced exists (a missing key shows as the raw key on screen and
// logs "QString::arg: Argument missing"), and every .arg() on a string matches
// the number of %N placeholders it has. Dynamic keys ("fallback." + name) are
// checked as families.
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("fs")
const path = require("path")

const ROOT = path.join(__dirname, "..")
const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, "i18n", "en.json"), "utf8"))

function sources() {
  const out = ["Panel.qml", "QnetService.qml", "Model.js"]
  for (const f of fs.readdirSync(path.join(ROOT, "components"))) if (f.endsWith(".qml")) out.push("components/" + f)
  const lib = path.join(ROOT, "lib")
  if (fs.existsSync(lib)) for (const f of fs.readdirSync(lib)) if (f.endsWith(".js")) out.push("lib/" + f)
  return out
}

// The text of a balanced (...) group starting at src[open] === "(", skipping
// strings; returns the index of its closing paren.
function closeParen(src, open, openCh, closeCh) {
  let depth = 0
  for (let i = open; i < src.length; i++) {
    const c = src[i]
    if (c === '"' || c === "'") {
      const q = c
      i++
      while (i < src.length && src[i] !== q) { if (src[i] === "\\") i++; i++ }
    } else if (c === openCh) depth++
    else if (c === closeCh) { depth--; if (depth === 0) return i }
  }
  return -1
}

// How many .arg(...) or .replace("%N", ...) calls follow a call whose closing
// paren is at `end`.
function chainedArgs(src, end) {
  let n = 0
  let i = end + 1
  for (;;) {
    const rest = src.slice(i)
    const m = /^\s*\.(arg|replace)\(/.exec(rest)
    if (!m) break
    const open = i + m[0].length - 1
    const close = closeParen(src, open, "(", ")")
    if (close < 0) break
    if (m[1] === "replace" && !/^\(\s*"%\d"/.test(src.slice(open, open + 8))) break
    n++
    i = close + 1
  }
  return n
}

// Top-level elements of the array literal whose "[" is at src[open].
function arrayLength(src, open) {
  const close = closeParen(src, open, "[", "]")
  const body = src.slice(open + 1, close).trim()
  if (body === "") return 0
  let depth = 0
  let n = 1
  for (let i = 0; i < body.length; i++) {
    const c = body[i]
    if (c === '"' || c === "'") { const q = c; i++; while (i < body.length && body[i] !== q) { if (body[i] === "\\") i++; i++ } }
    else if (c === "(" || c === "[" || c === "{") depth++
    else if (c === ")" || c === "]" || c === "}") depth--
    else if (c === "," && depth === 0) n++
  }
  return n
}

// %1..%N as a count (and they must run 1..N without gaps).
function placeholders(str) {
  const seen = new Set()
  for (const m of str.matchAll(/%(\d)/g)) seen.add(Number(m[1]))
  const max = seen.size ? Math.max.apply(null, Array.from(seen)) : 0
  for (let k = 1; k <= max; k++) assert.ok(seen.has(k), "placeholders skip %" + k + " in " + JSON.stringify(str))
  return max
}

function forms(key) {
  const v = catalog[key]
  return typeof v === "string" ? [v] : Object.values(v)
}

// Every static use: { file, line, key, args } with args null when it is not
// known (the string is passed on and filled elsewhere).
function uses() {
  const found = []
  for (const f of sources()) {
    const src = fs.readFileSync(path.join(ROOT, f), "utf8")
    const lineOf = (i) => src.slice(0, i).split("\n").length
    // strings.t("k") / strings.tn("k", n) / hub.strings.t / hero.t / t("k") / viz.tr("k")
    for (const m of src.matchAll(/(?<![A-Za-z0-9_])(tn?|tr)\(\s*"([A-Za-z][A-Za-z0-9.]*)"(\s*\+)?/g)) {
      if (m[3]) { found.push({ file: f, line: lineOf(m.index), prefix: m[2] }); continue }
      const open = src.indexOf("(", m.index)
      const close = closeParen(src, open, "(", ")")
      found.push({ file: f, line: lineOf(m.index), key: m[2], args: close < 0 ? null : chainedArgs(src, close) })
    }
    // the model's words: word("k", [args], tone), also with a ternary of keys
    for (const m of src.matchAll(/\bword\(/g)) {
      const open = m.index + m[0].length - 1
      const close = closeParen(src, open, "(", ")")
      const inner = src.slice(open + 1, close)
      // the first argument, up to the first top-level comma
      let depth = 0
      let cut = inner.length
      for (let i = 0; i < inner.length; i++) {
        const c = inner[i]
        if (c === '"') { i++; while (i < inner.length && inner[i] !== '"') { if (inner[i] === "\\") i++; i++ } }
        else if (c === "(" || c === "[") depth++
        else if (c === ")" || c === "]") depth--
        else if (c === "," && depth === 0) { cut = i; break }
      }
      const first = inner.slice(0, cut)
      if (/function\s+word/.test(src.slice(Math.max(0, m.index - 10), m.index + 10))) continue
      const rest = inner.slice(cut + 1)
      const at = rest.search(/\S/)
      const args = at >= 0 && rest[at] === "[" ? arrayLength(inner, cut + 1 + at) : 0
      const prefixed = /"\s*\+/.test(first)
      for (const k of first.matchAll(/"([A-Za-z][A-Za-z0-9.]*)"/g)) {
        if (prefixed) found.push({ file: f, line: lineOf(m.index), prefix: k[1] })
        else found.push({ file: f, line: lineOf(m.index), key: k[1], args: args })
      }
    }
  }
  return found
}

test("the catalog is flat, whole strings, and plurals carry one and other", () => {
  assert.ok(Object.keys(catalog).length > 100)
  for (const [k, v] of Object.entries(catalog)) {
    assert.match(k, /^[a-z][A-Za-z0-9]*(\.[A-Za-z0-9]+)+$/, "key " + k)
    if (typeof v === "object") {
      assert.ok("one" in v && "other" in v, k)
      assert.equal(new Set(forms(k).map(placeholders)).size, 1, k + ": every plural form has the same placeholders")
    } else assert.equal(typeof v, "string", k)
  }
})

test("every key the code asks for is in en.json", () => {
  const all = uses()
  assert.ok(all.length > 80, "found the uses (" + all.length + ")")
  for (const u of all) {
    if (u.key) assert.ok(u.key in catalog, u.file + ":" + u.line + " asks for a key that is not in en.json: " + u.key)
    else assert.ok(Object.keys(catalog).some((k) => k.startsWith(u.prefix)), u.file + ":" + u.line + " no keys for the family " + u.prefix)
  }
})

test("every .arg() count matches the placeholders of the string it fills", () => {
  let checked = 0
  for (const u of uses()) {
    if (!u.key || u.args === null) continue
    const want = placeholders(forms(u.key)[0])
    assert.equal(u.args, want, u.file + ":" + u.line + " " + u.key + " is filled with " + u.args + " argument(s), the string has " + want + " placeholder(s)")
    checked++
  }
  assert.ok(checked > 60, "checked the fills (" + checked + ")")
})

test("the keys the live panel logged as missing are here, with their placeholders", () => {
  // QString::arg: Argument missing: "leak.profiles", 2  /  "hero.queries", "2,700"
  assert.ok("leak.profiles" in catalog || !uses().some((u) => u.key === "leak.profiles"), "leak.profiles is either present or no longer asked for")
  assert.ok("hero.queries" in catalog || !uses().some((u) => u.key === "hero.queries"), "hero.queries is either present or no longer asked for")
  for (const u of uses()) if (u.key === "leak.profiles" || u.key === "hero.queries") assert.equal(placeholders(forms(u.key)[0]), 1)
})

test("a string that takes arguments is never shown raw: no key is used with fewer args than it has %N", () => {
  for (const u of uses()) {
    if (!u.key || u.args === null) continue
    for (const f of forms(u.key)) assert.ok(u.args >= placeholders(f), u.file + ":" + u.line + " " + u.key)
  }
})

test("the checker itself: it finds a missing key and a wrong argument count", () => {
  const src = 'x = strings.t("a.b").arg(1).arg(2)\ny = hero.t("c.d")\nz = strings.tn("e.f", n).arg(n)'
  const hits = Array.from(src.matchAll(/(?<![A-Za-z0-9_])(tn?|tr)\(\s*"([A-Za-z][A-Za-z0-9.]*)"/g))
  assert.equal(hits.length, 3)
  const open = src.indexOf("(", hits[0].index)
  assert.equal(chainedArgs(src, closeParen(src, open, "(", ")")), 2)
  const open2 = src.indexOf("(", hits[1].index)
  assert.equal(chainedArgs(src, closeParen(src, open2, "(", ")")), 0)
  const open3 = src.indexOf("(", hits[2].index)
  assert.equal(chainedArgs(src, closeParen(src, open3, "(", ")")), 1)
  assert.equal(arrayLength("[a, f(b, c), [d, e], \"x,y\"]", 0), 4)
  assert.equal(arrayLength("[]", 0), 0)
  assert.equal(placeholders("%1 of %2"), 2)
  assert.throws(() => placeholders("%2 only"))
})

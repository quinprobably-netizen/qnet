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
      if (/\bduration:/.test(line)) assert.match(line, /duration:\s*Style\.duration\([^)]/, f + ":" + (i + 1) + " " + line.trim())
      assert.doesNotMatch(line, /Easing\.(In|InOut|OutIn)(Quad|Cubic|Quart|Quint|Sine|Expo|Circ|Back|Bounce|Elastic)/, f + ":" + (i + 1))
      assert.doesNotMatch(line, /Easing\.OutBounce|Easing\.OutBack|Easing\.OutElastic/, f + ":" + (i + 1))
    }
  }
})

test("durations stay under 300 ms; only the scan spinner and the route's and chain's flow are longer", () => {
  for (const f of FILES) {
    for (const m of read(f).matchAll(/Style\.duration\((\d+)\)/g)) {
      const ms = Number(m[1])
      if (f === "components/NearbyList.qml" && ms === 900) continue
      if ((f === "components/HeroViz.qml" || f === "components/ResolverChain.qml") && ms === 5000) continue
      assert.ok(ms <= 300, f + " " + ms)
    }
  }
})

test("the flow of the route and of the chain is the only ambient motion, besides the scan spinner while it scans", () => {
  const looping = FILES.filter((f) => /Animation\.Infinite/.test(read(f)))
  assert.deepEqual(looping.sort(), ["components/HeroViz.qml", "components/NearbyList.qml", "components/ResolverChain.qml"])
  const viz = read("components/HeroViz.qml")
  assert.match(viz, /readonly property bool flowing: animate && !Style\.reduceMotion/, "still when animations are off")
  // every animation in the picture runs only while it is flowing
  for (const m of viz.matchAll(/running:\s*([^\n]+)/g)) assert.match(m[1], /live|visible/, "running: " + m[1])
  assert.match(viz, /live: viz\.flowing && index < count/)
  const chain = read("components/ResolverChain.qml")
  assert.match(chain, /readonly property bool flowing: animate && !Style\.reduceMotion/)
  for (const m of chain.matchAll(/running:\s*([^\n]+)/g)) assert.match(m[1], /visible/, "running: " + m[1])
  assert.match(chain, /visible: chain\.flowing && /)
  assert.match(read("components/NearbyList.qml"), /running:[^\n]*scan\.running[^\n]*!Style\.reduceMotion/)
  assert.doesNotMatch(read("components/Hero.qml"), /NumberAnimation|PropertyAnimation|Animation\.Infinite/, "the words do not move")
})

test("the hero's picture is its own piece: it takes the view and the host's words, not the hub", () => {
  const viz = read("components/HeroViz.qml")
  const hero = read("components/Hero.qml")
  assert.match(viz, /required property var view/)
  assert.match(viz, /property var tr: function/)
  assert.doesNotMatch(viz, /\bhub\b/, "the picture does not reach into the panel")
  assert.doesNotMatch(viz, /strings\.|\bt\("/, "and has no words of its own")
  assert.match(viz, /implicitHeight:/)
  assert.match(viz, /readonly property real overlap/)
  assert.match(viz, /readonly property color legendColor/)
  assert.match(viz, /Model\.routeModel\(view, nowS, pending\)/, "what it draws is decided in Model.js")
  assert.doesNotMatch(hero, /Shape|ShapePath|PathPolyline|Gradient/, "the words draw nothing")
  assert.match(hero, /HeroViz \{/)
  assert.match(hero, /view: hero\.hub\.view/)
  assert.match(hero, /tr: hero\.hub\.strings\.t/)
})

// ---- the route is the navigation ----------------------------------------------

test("the main view is the header, the hero with its route, Pause and the address: no drill-down rows", () => {
  const main = read("components/MainView.qml")
  for (const piece of ["Header {", "Hero {", "PauseTile {", "IpFooter {"]) assert.ok(main.indexOf(piece) >= 0, piece)
  assert.doesNotMatch(main, /DrillRow|goto:|openView/, "the rows are gone")
  assert.equal(fs.existsSync(path.join(ROOT, "components", "DrillRow.qml")), false)
  assert.equal(fs.existsSync(path.join(ROOT, "components", "DnsTiles.qml")), false, "the tiles are a list now")
  assert.equal(fs.existsSync(path.join(ROOT, "components", "NetworkList.qml")), false)
  // what is drawn, top to bottom
  const order = ["Header {", "Hero {", "PauseTile {", "Hairline {", "IpFooter {"].map((p) => main.indexOf(p))
  assert.deepEqual(order.slice().sort((a, b) => a - b), order)
})

test("the route's nodes are doors: pointer cursor, a ring under the cursor, a tooltip that says where", () => {
  const viz = read("components/HeroViz.qml")
  assert.match(viz, /cursorShape: nd\.opens \? Qt\.PointingHandCursor : Qt\.ArrowCursor/)
  assert.match(viz, /acceptedButtons: nd\.opens \? Qt\.LeftButton : Qt\.NoButton/, "pc and the upstream are not clickable")
  assert.match(viz, /onClicked: viz\.nodeClicked\(nd\.modelData\)/)
  assert.match(viz, /onPositionChanged: function\(mouse\) \{ if \(nd\.opens\) viz\.nodeMoved\(nd\.modelData, hit, mouse\) \}/)
  assert.match(viz, /ringColor: nd\.hasCursor \? \(viz\.cursorPointer \? viz\.accent : Util\.alpha\(viz\.fg, 0\.7\)\) : "transparent"/, "the accent for the pointer, grey for the keyboard")
  assert.match(viz, /tr\("route\.tip\.wifi"\)/)
  assert.match(viz, /tr\("route\.tip\.dns"\)/)
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "i18n", "en.json"), "utf8"))
  assert.equal(cat["route.tip.wifi"], "Wi-Fi networks")
  assert.equal(cat["route.tip.dns"], "DNS & Pi-hole")
  const hero = read("components/Hero.qml")
  assert.match(hero, /onNodeClicked: function\(id\) \{ hero\.hub\.openRouteNode\(id\) \}/)
  assert.match(hero, /hoverCursor\(area, mouse, "route", hero\.hub\.routeStops\.indexOf\(id\)\)/, "the pointer moves the one cursor")
  const panel = read("Panel.qml")
  assert.match(panel, /id === "route"\) openView\(Model\.routeTarget\(view, item\), false\)/, "Enter on a node opens its view")
  assert.match(panel, /function openRouteNode\(id\)/)
})

test("a view opened or left with the pointer shows no keyboard cursor until a key asks", () => {
  const panel = read("Panel.qml")
  assert.match(panel, /function openView\(name, viaPointer\)/)
  assert.match(panel, /cursorActive = viaPointer !== true/)
  assert.match(panel, /function goBack\(viaPointer\)/)
  assert.match(panel, /if \(viaPointer === true\) cursorActive = false/)
  assert.match(read("components/ViewHeader.qml"), /goBack\(true\)/)
  assert.match(panel, /cursorPointer = false\s*\n\s*var r = Model\.moveFocus/, "a key makes the cursor the keyboard's")
})

test("Forget works on the card too: Delete or a secondary click asks, a second press confirms", () => {
  const panel = read("Panel.qml")
  const del = panel.slice(panel.indexOf("function deleteKey()"), panel.indexOf("// ----------------------------------------------------------- actions"))
  assert.match(del, /cursor\.row === "card"\) uuid = view\.link\.uuid/)
  assert.match(del, /armedUuid !== "" && armedUuid === uuid/)
  assert.match(del, /!keyAutoRepeat && Date\.now\(\) - armedAt > 400/, "the confirming press is a new one, not the repeat")
  assert.match(panel, /function armForgetUuid\(uuid\)/)
  const card = read("components/ConnectionCard.qml")
  assert.match(card, /acceptedButtons: Qt\.RightButton/)
  assert.match(card, /card\.hub\.armForgetUuid\(card\.info\.uuid\)/)
  assert.match(card, /card\.hub\.confirmForget\(\)/)
})

test("the route's nodes and the chain's share one badge and one palette", () => {
  for (const f of ["components/HeroViz.qml", "components/ResolverChain.qml"]) {
    assert.match(read(f), /RouteBadge \{/, f)
    assert.match(read(f), /PlasmaPalette \{/, f)
  }
  assert.doesNotMatch(read("components/HeroViz.qml"), /function shifted|function mix/, "the colours live in the palette")
})

test("the leak count is a badge on the Pi-hole's node, not a row", () => {
  const viz = read("components/HeroViz.qml")
  assert.match(viz, /badgeText: nd\.n && nd\.n\.badge \? String\(nd\.n\.badge\.n\) : ""/)
  assert.doesNotMatch(read("Panel.qml"), /leaksWord|dnsRowValue/)
})

test("the Wi-Fi view is a card and a list: signal bars, a band chip, a lock only where it means something", () => {
  const wifi = read("components/WifiView.qml")
  assert.match(wifi, /ConnectionCard \{/)
  assert.match(wifi, /NearbyList \{/)
  const row = read("components/NearbyRow.qml")
  assert.match(row, /SignalBars \{/)
  assert.match(row, /Model\.signalBars\(row\.net\.signal\)/)
  assert.doesNotMatch(row, /wifiGlyph|linkGlyph/, "the list uses bars, not the fan")
  assert.match(row, /Model\.bandChip\(net\.band, net\.frequencyMhz\)/)
  assert.match(row, /readonly property bool lock: Model\.showLock\(net\)/)
  const card = read("components/ConnectionCard.qml")
  assert.match(card, /Model\.connectionCard\(hub\.view, hub\.formatNumber\)/)
  assert.match(card, /cursorRow: "card"/)
  assert.match(card, /hub\.disconnectNet\(\)/)
  assert.match(read("components/NearbyList.qml"), /text: list\.hub\.nearbyTitle/, "the scan age is in the list's head")
})

test("the DNS view is a chain and a list: no tiles, no segmented control", () => {
  const dns = read("components/DnsView.qml")
  assert.match(dns, /ResolverChain \{/)
  assert.match(dns, /ResolverChoices \{/)
  assert.match(dns, /LeakList \{/)
  assert.doesNotMatch(dns, /DnsTiles|tile:/)
  const choices = read("components/ResolverChoices.qml")
  assert.match(choices, /cursorRow|hasCursor: pick\.hub\.has\("choice:" \+ name\)/)
  assert.match(choices, /model: pick\.choices/)
  const chain = read("components/ResolverChain.qml")
  assert.match(chain, /Model\.chainModel\(view, nowS\)/)
  assert.doesNotMatch(chain, /\bhub\b/, "the chain takes the view and the host's words, like the route")
})

test("the section heads and the views no longer wear Sound Hub's layout", () => {
  const head = read("components/SectionHead.qml")
  assert.doesNotMatch(head, /Sound Hub/)
  assert.match(head, /anchors\.right: trailingSlot\.left/, "the label's rule runs on to the right edge")
  for (const f of ["components/WifiView.qml", "components/DnsView.qml", "components/ResolverChoices.qml", "components/NearbyList.qml"]) {
    assert.doesNotMatch(read(f), /Sound Hub|Equalizer|Bluetooth/, f)
  }
})

test("the area graph is gone: no history series, no crest, no head dot, no axis", () => {
  const all = FILES.map(read).join("\n") + read("Model.js")
  assert.doesNotMatch(all, /historySeries|smoothEdge|strokeRuns|edgePoints|headState|axisSpan|showSpanLabel|seriesSignature|formatSpan|PathPolyline/)
  assert.doesNotMatch(read("Panel.qml"), /syncSeries|historySig|probeHead/)
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
  // the model names the words of the route by key
  for (const m of read("Model.js").matchAll(/"((?:route|hero|fallback|chain|card)\.[A-Za-z0-9.]+)"(\s*\+)?/g)) {
    if (m[2]) prefixes.add(m[1])
    else exact.add(m[1])
  }
  for (const f of FILES) {
    const src = read(f)
    for (const m of src.matchAll(/(?<![A-Za-z0-9_])(?:tn?|tr)\(\s*"([A-Za-z][A-Za-z0-9.]*)"(\s*\+)?/g)) {
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
  for (const k of ["connecting", "disconnecting", "forgetting", "forget", "enterprise", "hidden", "saved"])
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

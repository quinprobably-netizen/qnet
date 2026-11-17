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

// ---- the watchdog view -----------------------------------------------------------

test("the watchdog view is the third pushed view: Panel opens it (key 3, IPC, the route's Pi-hole node), Esc steps back through it", () => {
  const panel = read("Panel.qml")
  assert.match(panel, /WatchdogView \{ id: watchdogView; hub: root; visible: root\.page === "watchdog" \}/)
  assert.match(panel, /root\.page === "watchdog" \? watchdogView : mainView/)
  assert.match(panel, /if \(name !== "dns" && name !== "wifi" && name !== "watchdog"\) return/)
  assert.match(panel, /name === "watchdog" && !Model\.watchdogPresent\(view\)\) return/, "no tab on a Pi-hole without a watchdog")
  assert.match(panel, /else if \(k === "3"\) \{ if \(root\.fresh\("key:3"\)\) root\.openView\("watchdog"\) \}/)
  assert.match(panel, /name === "dns" \|\| name === "wifi" \|\| name === "watchdog"\) root\.openView\(name, false\)/, "IPC view watchdog")
  assert.match(panel, /pin: wdPinOpen, flip: wdFlip, ticket: wdTicket !== null, view: page/, "Esc goes through Model.escapeStep with the tab's steps")
  assert.match(panel, /else if \(step === "pin"\) wdClosePin\(\)/)
  assert.match(panel, /else if \(step === "flip"\) wdFlip = false/)
  assert.match(panel, /else if \(step === "ticket"\) wdSetTicket\(null\)/)
  // the tab's own state, reset when it is left or the panel closes
  for (const p of ["wdOrder", "wdScroll", "wdTicket", "wdFlip", "wdPinOpen", "wdNote"]) assert.match(panel, new RegExp("property \\w+ " + p + ":"), p)
  assert.match(panel, /function closeTransients\(\) \{[\s\S]*?wdReset\(\)/)
  assert.match(panel, /Model\.holdOrder\(\[\], view\.watchdog\.bay\.jacks\)/, "the order is set on entering")
  assert.match(panel, /Model\.holdOrder\(wdOrder, rawState\.watchdog\.bay\.jacks\)/, "and held as jacks come and go")
  assert.match(panel, /Model\.needsClock\(root\.view, root\.pending, root\.nowMs \/ 1000, \{ view: root\.page \}\)/, "gates count down")
  assert.match(panel, /Model\.focusRows\(view, page === "watchdog" \? wdRowsCtx/)
  assert.match(panel, /else if \(page === "watchdog"\) wdActivate\(id, item\)/)
  // an action runs through argvWatchdog and tells the watcher to read the devices again
  assert.match(panel, /Model\.argvWatchdog\(bin, verb, args\)/)
  assert.match(panel, /QnetService\.send\("devices"\)/)
  assert.match(panel, /wdAction\("exempt-default", \["on"\]\)/, "the confirm turns the mode on")
  assert.match(panel, /wdAction\("exempt-default", \["off"\]\)/, "and back is at once")
  const views = fs.readFileSync(path.join(ROOT, "components", "WatchdogView.qml"), "utf8")
  for (const piece of ["ViewHeader {", "LampRow {", "PatchBay {"]) assert.ok(views.indexOf(piece) >= 0, piece)
  const order = ["ViewHeader {", "LampRow {", "PatchBay {"].map((p) => views.indexOf(p))
  assert.deepEqual(order.slice().sort((a, b) => a - b), order, "head, lamp row, board")
})

test("the card is 520 wide on the watchdog view (the board is 488), 488 elsewhere", () => {
  assert.match(read("Panel.qml"), /contentWidth: panel\.fittedContentWidth\(Style\.space\(root\.page === "watchdog" \? 520 : 488\)\)/)
  const board = read("components/PatchBay.qml")
  assert.match(board, /readonly property real railW: px\(70\)/)
  assert.match(board, /readonly property real bayW: px\(418\)/)
  assert.match(board, /implicitWidth: railW \+ bayW/, "70 + 418 = 488, the content column of a 520 card")
  const stub = fs.readFileSync(path.join(ROOT, "tools", "harness", "imports", "qs", "Ui", "KeyboardPanel.qml"), "utf8")
  assert.match(stub, /property int contentWidth: 488/)
  assert.doesNotMatch(stub, /realWidth|2 \* padding\)/, "the harness draws the real card at the width the panel asks for")
  assert.match(stub, /readonly property real inset: padding \+ borderWidth/, "content = card - 2 x (padding + border)")
  assert.doesNotMatch(read("tools/harness/Shot.qml"), /realWidth/)
})

test("the board is drawn at the mockup's sizes, in the panel's colours and the bar's font", () => {
  const board = read("components/PatchBay.qml")
  for (const [name, px] of [["bayH", 192], ["gap", 6], ["colW", 51], ["pad", 5], ["yT", 84], ["yD", 120], ["yB", 156]])
    assert.match(board, new RegExp("readonly property real " + name + ": px\\(" + px + "\\)"), name)
  assert.match(board, /function px\(n\) \{ return Style\.spaceReal\(n\) \}/, "every size goes through Style")
  for (const f of ["components/PatchBay.qml", "components/LampRow.qml", "components/WatchdogView.qml"]) {
    const src = read(f)
    assert.doesNotMatch(src, /#[0-9a-fA-F]{3,8}\b/, f + " has no colour of its own")
    assert.doesNotMatch(src, /Qt\.rgba\(\s*[0-9]/, f + " has no literal colour")
    assert.doesNotMatch(src, /font\.family:\s*"/, f + " has no font of its own")
    for (const m of src.matchAll(/font\.family:\s*([^\n]+)/g)) assert.match(m[1], /hub\.fontFamily/, f)
    for (const m of src.matchAll(/font\.pixelSize:\s*([^\n]+)/g)) assert.match(m[1], /Style\.font\.(caption|bodySmall|body|subtitle|heading)\b/, f + " " + m[1])
    assert.doesNotMatch(src, /PathPolyline/, f)
  }
  // the board's surfaces come from the theme, in the panel
  const panel = read("Panel.qml")
  for (const t of ["cardColor", "well", "raise", "sel", "hole", "ring", "muted", "bright"]) assert.match(panel, new RegExp("readonly property color " + t + ":"), t)
  assert.match(panel, /readonly property color well: Qt\.darker\(cardColor/)
  // the word under a jack is the model's, in the colours of the mockup's .w-* classes
  assert.match(board, /Model\.jackWord\(jack, board\.nowS\)/)
  assert.match(board, /if \(kind === "blocked"\) return board\.hub\.accent/)
  assert.match(board, /if \(kind === "pass"\) return board\.hub\.bright/)
  assert.match(board, /if \(kind === "gate"\) return board\.hub\.warning/)
  assert.match(board, /Model\.jackWord\(jack, board\.nowS\)[\s\S]*return board\.hub\.muted/, "ALWAYS and FIXED are muted")
})

test("a click on a column opens its ticket, on its lit drop lamp the alert's; the wheel moves a bay; the pointer moves the one cursor", () => {
  const board = read("components/PatchBay.qml")
  assert.match(board, /onClicked: board\.hub\.wdToggleDevice\(col\.mac\)/)
  assert.match(board, /onClicked: board\.hub\.wdOpenAlert\(col\.jack\.alertId\)/)
  assert.match(board, /onPositionChanged: function\(mouse\) \{ board\.hub\.hoverCursor\(hit, mouse, "bay:" \+ col\.bayIndex, col\.pos\) \}/)
  assert.match(board, /board\.hub\.has\("bay:" \+ bayIndex, pos\)/, "the keyboard's ring")
  assert.match(board, /hub\.wdPressKey\(\)/, "the NORMAL key")
  assert.match(board, /WheelHandler \{/)
  assert.match(board, /board\.hub\.wdPage\(acc < 0 \? 1 : -1\)/)
  assert.match(board, /active: index >= board\.firstBay && index < board\.firstBay \+ board\.shownCount/, "only the bays in view are built")
  const lamps = read("components/LampRow.qml")
  assert.match(lamps, /row\.hub\.wdOpenLamp\(win\.modelData\.kind\)/)
  assert.match(lamps, /row\.hub\.hoverCursor\(area, mouse, "lamps", win\.litIndex\)/)
  const view = read("components/WatchdogView.qml")
  assert.match(view, /page\.hub\.wdPage\(pb\.modelData\)/)
  assert.match(view, /hoverCursor\(pbArea, mouse, "pager", pb\.index\)/)
  assert.match(view, /page\.hub\.wdConfirmFlip\(\)/)
  assert.match(view, /page\.hub\.wdCancelFlip\(\)/)
  assert.match(view, /page\.hub\.wdPressKey\(\)/, "Flip ›")
  assert.match(view, /h\.strings\.tn\("wd\.flipQ", n\)\.arg\(n\)/, "the confirm counts the devices")
  assert.match(view, /readonly property string readoutMac: board\.hoverMac !== "" \? board\.hoverMac : Model\.bayCursorMac/, "hover first, then the keyboard cursor")
})

test("the watchdog view is head, lamps, board, readout, calls, ticket (a device's or a call's, one at a time), PIN footer", () => {
  const view = read("components/WatchdogView.qml")
  const order = ["ViewHeader {", "LampRow {", "PatchBay {", "id: line", "CallQueue {", "DeviceTicket {", "AlertTicket {", "PinFooter {"].map((p) => view.indexOf(p))
  for (const [i, p] of ["ViewHeader", "LampRow", "PatchBay", "readout line", "CallQueue", "DeviceTicket", "AlertTicket", "PinFooter"].entries()) assert.ok(order[i] >= 0, p)
  assert.deepEqual(order.slice().sort((a, b) => a - b), order)
  assert.match(view, /active: page\.ticketJack !== null/)
  assert.match(view, /active: page\.ticketCall !== null/)
  assert.match(view, /hub\.wdTicket\.kind === "device" \? Model\.jackOf/)
  assert.match(view, /hub\.wdTicket\.kind === "alert" \? Model\.callOf/)
  for (const [f, piece] of [["CallQueue", "TextButton {"], ["DeviceTicket", "TicketFrame {"], ["AlertTicket", "TicketFrame {"], ["PinFooter", "TicketButton {"]])
    assert.ok(read("components/" + f + ".qml").indexOf(piece) >= 0, f)
  // the confirm's two buttons are words of the readout's own line, so they wrap with it
  assert.doesNotMatch(view, /Row \{\s*visible: page\.readout\.kind === "confirm"/)
  assert.match(view, /tn\("wd\.flipQ", n\)\.arg\(n\) \+ " "/, "a space between the sentence and Flip")
})

test("the queue, the tickets and the PIN footer are Model's words in the panel's colours and the bar's font", () => {
  for (const f of ["CallQueue", "DeviceTicket", "AlertTicket", "PinFooter", "TicketFrame", "TicketButton"]) {
    const src = read("components/" + f + ".qml")
    assert.doesNotMatch(src, /#[0-9a-fA-F]{3,8}\b/, f + " has no colour of its own")
    assert.doesNotMatch(src, /Qt\.rgba\(\s*[0-9]/, f)
    assert.doesNotMatch(src, /font\.family:\s*"/, f)
    for (const m of src.matchAll(/font\.family:\s*([^\n]+)/g)) assert.match(m[1], /hub\.fontFamily/, f)
    for (const m of src.matchAll(/font\.pixelSize:\s*([^\n]+)/g)) assert.match(m[1], /Style\.font\.(caption|bodySmall|body|subtitle)\b/, f + " " + m[1])
  }
  const queue = read("components/CallQueue.qml")
  for (const w of ["callTitle", "callJackName", "callBrief", "quietLine"]) assert.match(queue, new RegExp("Model\\." + w + "\\("), w)
  assert.match(queue, /cursorRow: "queue"/)
  assert.match(queue, /hub\.has\("call:" \+ call\.id\)/)
  assert.match(queue, /onClicked: queue\.hub\.wdOpenAlert\(row\.call\.id\)/)
  assert.match(queue, /onClicked: queue\.hub\.wdDismissAll\(\)/)
  const dev = read("components/DeviceTicket.qml")
  for (const w of ["ticketWord", "gateRow", "jackNote", "deviceMeta", "patchCaption", "deviceActions", "labelEdit"]) assert.match(dev, new RegExp("Model\\." + w + "\\("), w)
  for (const row of ["label", "patch", "gate", "tactions"]) assert.match(dev, new RegExp('(cursorRow: |hub\\.has\\()"' + row + '"'), row)
  assert.match(dev, /hub\.wdPatch\(tk\.mac, sb\.modelData\)/)
  assert.match(dev, /hub\.wdGate\(tk\.mac, 0\)/)
  assert.match(dev, /hub\.wdGate\(tk\.mac, modelData\)/)
  assert.match(dev, /model: tk\.gate\.state === "shut" \? \[300, 1800, 3600\] : \[\]/, "5, 30 and 60 minutes")
  assert.match(dev, /maximumLength: Model\.LABEL_MAX/)
  assert.equal(Object.keys(JSON.parse(fs.readFileSync(path.join(ROOT, "i18n", "en.json"), "utf8"))).some((k) => /recent/i.test(k)), false, "the Pi keeps no per-device query log")
  const alert = read("components/AlertTicket.qml")
  for (const w of ["callTitle", "callMeta", "callSubject", "callWho", "callWhy", "alertActions", "alertOpenTarget"]) assert.match(alert, new RegExp("Model\\." + w + "\\("), w)
  assert.match(alert, /cursorRow: "tactions"/)
})

test("a ticket's buttons are dead while an action runs, and one action runs at a time", () => {
  assert.match(read("components/TicketButton.qml"), /enabled: !hub\.wdBusy/)
  const dev = read("components/DeviceTicket.qml")
  assert.match(dev, /readonly property bool idle: !hub\.wdBusy/)
  assert.match(dev, /enabled: tk\.idle/, "the cords")
  const panel = read("Panel.qml")
  assert.match(panel, /readonly property bool wdBusy: wdRunning > 0 \|\| wdSettling/)
  assert.match(panel, /if \(wdRunning > 0 \|\| \(wdSettling && o\.chain !== true\)\) return false/)
  assert.match(panel, /QnetService\.send\("devices"\)/)
  // every call goes through argvWatchdog, so nothing is built by hand
  const wd = panel.slice(panel.indexOf("function wdDismissAll()"), panel.indexOf("// -- Wi-Fi"))
  assert.doesNotMatch(wd, /runCli\(/, "the tab's actions all go through wdAction")
  for (const call of ['wdAction("ack-all"', 'wdAction("ack", [alertId]', 'wdAction("know", [mac]', 'wdAction("patch", [mac, want])', 'wdAction("gate", [mac, secs])', 'wdAction("label", [mac, text]', 'wdAction("forget", [wdTicket.mac])', 'wdAction("pin", ["clear"])'])
    assert.ok(wd.indexOf(call) >= 0, call)
})

test("every row of the watchdog view's keyboard does something on Enter", () => {
  const panel = read("Panel.qml")
  const act = panel.slice(panel.indexOf("function wdActivate(id, item)"), panel.indexOf("function wdPinAction(item)"))
  for (const id of ['"lamps"', '"bay:"', '"normal"', '"flip"', '"pager"', '"queue"', '"call:"', '"label"', '"patch"', '"gate"', '"tactions"', '"pin"']) assert.ok(act.indexOf(id) >= 0, id)
  assert.doesNotMatch(panel, /TODO\(T5b\)/)
  // the items of the ticket and PIN rows
  for (const item of ['"close"', '"know"', '"forget"', '"dismiss"', '"open"']) assert.ok(act.indexOf(item) >= 0, item)
  for (const item of ['"clear"', '"cancel"', '"set"']) assert.ok(panel.slice(panel.indexOf("function wdPinAction(item)")).indexOf(item) >= 0, item)
  assert.match(act, /item === "shut" \? 0 : parseInt\(item, 10\)/)
})

test("a text field of the tab owns the keys while it has the focus, and gives them back", () => {
  const panel = read("Panel.qml")
  assert.match(panel, /blocked: root\.passwordFor !== "" \|\| root\.wdEditing/)
  assert.match(panel, /root\.passwordFor === "" && !root\.wdEditing && keyGate\.Window\.active/, "the key gate leaves the field its focus")
  assert.match(panel, /function wdFieldFocus\(which, on\)/)
  assert.match(panel, /readonly property bool wdEditing: wdLabelFocus \|\| wdPinFocus/)
  assert.match(read("components/DeviceTicket.qml"), /hub\.wdFieldFocus\("label", activeFocus\)/)
  assert.match(read("components/PinFooter.qml"), /hub\.wdFieldFocus\("pin", activeFocus\)/)
  assert.match(panel, /ticket === null \|\| ticket\.kind !== "device"\) \{\s*wdLabelFocus = false/, "a label field that goes away with its ticket gives the keys back")
  const dev = read("components/DeviceTicket.qml")
  assert.match(dev, /onAccepted: \{\s*commit\(\)\s*focus = false/, "Enter sends the label and lets go")
  assert.match(dev, /onActiveFocusChanged: \{[^}]*if \(!activeFocus\) commit\(\)/, "so does losing the focus")
  assert.match(dev, /function onWdCommitRequested\(\) \{ if \(field\.activeFocus\) field\.commit\(\) \}/, "and a ticket that is closing")
  assert.match(panel, /function wdSetTicket\(ticket\) \{\s*wdCommitRequested\(\)/)
  assert.equal((panel.match(/\bwdTicket = /g) || []).length, 2, "a ticket opens and closes through wdSetTicket (wdReset and wdSetTicket alone assign it)")
})

test("the PIN is read, the field cleared in the same breath, and it goes to `pin set` on stdin and nowhere else", () => {
  const panel = read("Panel.qml")
  const fn = panel.slice(panel.indexOf("function wdSubmitPin(field)"), panel.indexOf("// A text field of the tab (\"label\""))
  assert.match(fn, /var pin = field\.text\s*\n\s*field\.text = ""/, "read and cleared together")
  assert.match(fn, /Model\.validPin\(pin\)/, "four digits, or refused inline")
  assert.match(fn, /wdAction\("pin", \["set"\], function\(res\) \{[\s\S]*\}, \{ secret: pin, silent: true \}\)/, "stdin, through the runner's secret")
  assert.match(fn, /secretRun = null/)
  assert.match(fn, /pin = ""/)
  assert.doesNotMatch(fn, /console\.|print\(|Quickshell\.execDetached|property /, "no log, no property")
  assert.doesNotMatch(panel, /argvWatchdog\(bin, "pin", \[[^\]]*pin/, "never on a command line")
  const model = read("Model.js")
  assert.match(model, /case "pin":\s*\n\s*return a\.length === 1 && \(a\[0\] === "set" \|\| a\[0\] === "clear"\)/)
  const foot = read("components/PinFooter.qml")
  assert.match(foot, /echoMode: TextInput\.Password/)
  assert.match(foot, /Qt\.ImhDigitsOnly/)
  assert.match(foot, /maximumLength: 4/)
  assert.match(foot, /Keys\.onEscapePressed: foot\.hub\.wdClosePin\(\)/)
  assert.match(foot, /onAccepted: foot\.hub\.wdSubmitPin\(field\)/)
  assert.match(foot, /field\.text = ""\s*\n\s*if \(foot\.editing\)/, "empty each time it opens or closes")
})

test("the route's Pi-hole node says where it goes", () => {
  assert.match(read("components/HeroViz.qml"), /if \(n\.open === "watchdog"\) return tr\("route\.tip\.watchdog"\)/)
  const cat = JSON.parse(fs.readFileSync(path.join(ROOT, "i18n", "en.json"), "utf8"))
  assert.equal(cat["route.tip.watchdog"], "Watchdog")
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
  for (const m of read("Model.js").matchAll(/"((?:route|hero|fallback|chain|card|wd)\.[A-Za-z0-9.]+)"(\s*\+)?/g)) {
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

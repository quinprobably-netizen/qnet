import QtQuick
import Quickshell
import qs.Ui
import qs.Commons
import qs.Commons as Commons
import "Model.js" as Model
import "lib/tokens.js" as Tokens
import "components"

// qnet: the network panel for the bar. It replaces omarchy.network and tells
// the truth about DNS: the resolver that answers is read per link from
// systemd-resolved, and a Pi-hole's health, blocking and day of queries come
// from the `qnet` backend (backend/, installed as ~/.local/bin/qnet).
//
// This file is presentation plus the glue: it holds the UI state (cursor,
// pending requests, inline errors) and runs the actions. What to show and
// what to run is decided in Model.js (pure, tested under tests/). The state
// itself comes from QnetService, the single `qnet watch` child the whole
// shell shares; the bar makes one widget per monitor, and each of them reads
// that one service and tells it when its panel opens and closes.
//
// Four views: the main one (components/MainView.qml: connection, the hero
// with its route, Pause, the address) and three it pushes, DNS (DnsView.qml),
// Wi-Fi (WifiView.qml) and the watchdog (WatchdogView.qml: a qberrypi's patch
// bay). The route is the navigation: its AP node opens the Wi-Fi view, its
// Pi-hole node the watchdog (the DNS view when there is no watchdog) and the
// resolver beyond it the DNS view. Which view is up, and what entering it
// does, is Model.navOpen/navBack. One keyboard cursor runs through the rows of
// the view that is up (Model.focusRows), and the pointer moves the same cursor.
Panel {
  id: root
  moduleName: "qqq.qnet"
  ipcTarget: "qqq.qnet"
  // Own the IpcHandler (below), as the other plugin panels do.
  manageIpc: false

  readonly property string bin: QnetService.bin

  Commons.Translations { id: tr; directory: Qt.resolvedUrl("i18n") }
  readonly property var strings: tr
  readonly property var glyphs: Model.GLYPH

  // ------------------------------------------------------------- tokens
  // One font, the bar's, at the shell's Style.font sizes; the hierarchy is
  // size, weight and the dim colour. Surfaces follow lib/tokens.js, shared
  // with Sound Hub and the overclock panel.
  readonly property color fg: bar ? bar.foreground : Commons.Color.foreground
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property int typeTitle: Style.font.heading
  // The hero's state word: a step under the connection's name above it.
  readonly property int typeHero: Style.font.title
  readonly property int typeBody: Style.font.subtitle
  readonly property int typeSmall: Style.font.bodySmall
  readonly property color accent: Commons.Color.accent
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  // Amber, leaning toward the theme's urgent colour: a failover is a warning,
  // not a fault.
  readonly property color warning: Qt.rgba(urgent.r * 0.35 + 0.93 * 0.65, urgent.g * 0.35 + 0.69 * 0.65, urgent.b * 0.35 + 0.25 * 0.65, 1)
  readonly property color dim: Qt.darker(fg, 1.4)
  readonly property color restFill: Qt.rgba(fg.r, fg.g, fg.b, Tokens.REST_FILL)
  readonly property color hoverFill: Qt.rgba(fg.r, fg.g, fg.b, Tokens.HOVER_FILL)
  readonly property color lineColor: Qt.rgba(fg.r, fg.g, fg.b, Tokens.LINE_ALPHA)
  // The patch bay's surfaces and marks (WatchdogView, PatchBay), all
  // derived from the theme: the card's own colour, a well darker than it, a
  // raised ring a shade toward the accent, a deep hole, and two tints of the
  // foreground for what is fixed and what is lit white.
  readonly property color cardColor: Commons.Color.popups.background
  readonly property color well: Qt.darker(cardColor, 1.25)
  readonly property color raise: Qt.tint(cardColor, Qt.rgba(accent.r, accent.g, accent.b, 0.08))
  readonly property color sel: Qt.tint(cardColor, Qt.rgba(accent.r, accent.g, accent.b, 0.19))
  readonly property color hole: Qt.darker(cardColor, 3)
  readonly property color ring: Qt.hsva(accent.hsvHue, Math.min(1, accent.hsvSaturation * 1.2), accent.hsvValue * 0.7, 1)
  readonly property color muted: Qt.tint(Qt.darker(dim, 1.7), Qt.rgba(accent.r, accent.g, accent.b, 0.3))
  readonly property color bright: Qt.lighter(fg, 1.1)
  readonly property real pressScale: Tokens.PRESS_SCALE
  readonly property real disabledOpacity: Tokens.DISABLED_OPACITY
  readonly property int gutter: Style.space(8)

  function formatNumber(value, decimals) { return Commons.I18n.formatNumber(value, decimals) }
  function formatInt(n) { return Qt.locale(Commons.I18n.formatLocale).toString(n, "f", 0) }

  // A word the model names by key ({ key, args }, as Model.jackReadout's
  // `how`), in the catalog's words.
  function say(w) { return Model.sayWord(w, function(key) { return strings.t(key) }) }

  // -------------------------------------------------------------- state
  // rawState is the newest snapshot from the service; the view is that with
  // this panel's pending requests laid on it, which is what everything draws.
  readonly property var rawState: QnetService.snapshot
  property var pending: Model.emptyPending()
  property double nowMs: Date.now()
  readonly property var view: Model.effective(rawState, pending, QnetService.appliedMs, nowMs, QnetService.down)
  readonly property var hero: Model.heroState(view, nowMs / 1000)
  readonly property var header: Model.headerInfo(view, formatNumber)
  readonly property var tiles: Model.dnsTiles(view)
  readonly property var choices: Model.dnsChoices(view)
  readonly property var chip: Model.pauseChip(view)
  readonly property var footer: Model.ipFooter(view)
  readonly property var netList: Model.orderNetworks(view.networks)
  readonly property var leaks: Model.leakGroups(view, pending)
  readonly property var leakExtra: Model.extraResolver(view)

  // When the Pi-hole's numbers were last known to be good: with the link
  // down they are old, and the hero says how old.
  property double statsGoodAt: 0

  onRawStateChanged: {
    nowMs = Date.now()
    pending = Model.reconcilePending(pending, rawState, nowMs)
    var p = rawState.pihole
    if (p.api === "ok" && p.reachable && rawState.link.kind !== "none") statsGoodAt = nowMs
    wdSync()
  }

  // Counts a pause or a failover down and lets pending requests expire, only
  // while the panel is open and there is something to count.
  Timer {
    interval: 1000
    repeat: true
    running: root.opened && Model.needsClock(root.view, root.pending, root.nowMs / 1000, { view: root.page })
    onTriggered: {
      root.nowMs = Date.now()
      root.pending = Model.reconcilePending(root.pending, root.rawState, root.nowMs)
    }
  }

  // Nothing animates while the panel opens: the behaviours that would (a
  // colour following a state that just arrived) wait for `settled`.
  property bool settled: false
  Timer { id: settleTimer; interval: 320; onTriggered: root.settled = root.opened }

  // ------------------------------------------------------------- views
  // "main" | "dns" | "wifi" | "watchdog"; a view is pushed from the main one
  // (by a click or Enter on a node of the route) and popped by Esc, Backspace
  // or the back button, which puts the main view's cursor back where it was.
  property var nav: Model.navInit()
  readonly property string page: nav.view
  readonly property int headerBackSize: Style.space(30)

  // viaPointer: the route's node was clicked, so the new view shows no
  // keyboard cursor until a key asks for one.
  function openView(name, viaPointer) {
    if (name !== "dns" && name !== "wifi" && name !== "watchdog") return
    // Nothing to open on a Pi-hole that has no watchdog.
    if (name === "watchdog" && !Model.watchdogPresent(view)) return
    var r = Model.navOpen(nav, name, cursor)
    if (r.nav === nav) return
    if (nav.view === "watchdog") wdReset()
    nav = r.nav
    if (name === "watchdog") wdOpen()
    cursorActive = viaPointer !== true
    cursorPointer = false
    cursorMemory = ({})
    cursor = Model.initialCursor(rows, page)
    pointerGate.reset()
    for (var i = 0; i < r.effects.length; i++) if (r.effects[i].run === "scan") scanIfStale(r.effects[i].ifStaleS)
    Qt.callLater(function() { wifiView.networks.flick.contentY = 0 })
  }

  function goBack(viaPointer) {
    var r = Model.navBack(nav)
    if (!r.left) return
    closeTransients()
    nav = r.nav
    cursorMemory = ({})
    cursor = r.cursor !== null && Model.rowIndex(rows, r.cursor.row) >= 0 ? r.cursor : Model.initialCursor(rows, "main")
    cursorPointer = false
    if (viaPointer === true) cursorActive = false
    pointerGate.reset()
  }

  // A node of the route was clicked: its cursor stop, then its view.
  function openRouteNode(id) {
    var target = Model.routeTarget(view, id)
    if (target === "") return
    var at = routeStops.indexOf(id)
    if (at >= 0) setCursor("route", at)
    openView(target, true)
  }

  function ageText(a) {
    if (a === null) return ""
    if (a.unit === "now") return strings.t("age.now")
    return strings.t("age." + a.unit).arg(a.n)
  }

  // The head of the Wi-Fi view's list: how long ago it was scanned.
  readonly property string nearbyTitle: {
    if (view.scan.running) return strings.t("net.titleScanning")
    var a = ageText(Model.ageParts(view.scan.lastScanAgeS))
    return a === "" || !view.radio.wifiEnabled ? strings.t("net.title") : strings.t("net.titleAge").arg(a)
  }

  // The age of the Pi-hole's numbers while the link is down, once it is a
  // minute or more.
  readonly property string statsAgeText: {
    if (statsGoodAt <= 0 || view.link.kind !== "none") return ""
    var a = Model.ageParts((nowMs - statsGoodAt) / 1000)
    return a === null || a.unit === "now" ? "" : ageText(a)
  }

  function formatClock(sec) {
    return Qt.locale(Commons.I18n.formatLocale).toString(new Date(sec * 1000), "HH:mm")
  }

  // The watchdog tab's clock for Model's words: "14:02", "2 Nov", "Mon 09:14".
  readonly property var timeFmt: ({
    clock: function(sec) { return root.formatClock(sec) },
    date: function(sec) { return Qt.locale(Commons.I18n.formatLocale).toString(new Date(sec * 1000), "d MMM") },
    stamp: function(sec) { return Qt.locale(Commons.I18n.formatLocale).toString(new Date(sec * 1000), "ddd HH:mm") }
  })

  // The DNS view's failover line.
  readonly property var failoverData: Model.failoverInfo(view)
  readonly property bool failoverActive: failoverData.state === "active"
  readonly property string failoverText: {
    var f = failoverData
    var name = strings.t("fallback." + f.fallback)
    if (f.state === "off") return strings.t("failover.off")
    if (f.state === "armed") return strings.t("failover.armed").arg(name)
    return f.sinceS > 0 ? strings.t("failover.activeSince").arg(name).arg(formatClock(f.sinceS)) : strings.t("failover.active").arg(name)
  }

  // ------------------------------------------------------ transient UI
  property string passwordFor: ""
  property string passwordError: ""
  property string armedUuid: ""
  property double armedAt: 0
  // kind: "replace" (DNS the user set by hand is about to be replaced) or
  // "leave" (switching from the Pi-hole to Automatic: asked first, inline)
  property var confirm: ({ open: false, verb: "", servers: "", kind: "" })
  property var dnsNote: ({ tone: "", text: "" })
  property string netNote: ""
  property var netFail: ({ id: "", text: "" })
  property bool copied: false
  property var secretRun: null

  readonly property var captionContext: ({
    connectId: pending.connectId, disconnecting: pending.disconnecting, forgetUuid: pending.forgetUuid,
    failId: netFail.id, failText: netFail.text, armedUuid: armedUuid, connectivity: view.link.connectivity
  })

  // How many network rows show before the list scrolls: eight, fewer on a
  // short screen.
  readonly property int listRows: Math.max(3, Math.min(8, Math.floor((panel.availableCardHeight - Style.space(360)) / Style.space(36))))

  Timer { id: noteTimer; interval: 7000; onTriggered: { root.dnsNote = ({ tone: "", text: "" }); root.netNote = ""; root.netFail = ({ id: "", text: "" }); root.wdNote = ""; root.wdPinNote = "" } }
  Timer { id: armTimer; interval: 4000; onTriggered: root.armedUuid = "" }
  Timer { id: copiedTimer; interval: 1300; onTriggered: root.copied = false }

  function setDnsNote(tone, text) {
    dnsNote = ({ tone: tone, text: text })
    noteTimer.restart()
  }

  function setNetNote(text) {
    netNote = text
    noteTimer.restart()
  }

  // The words for a failed action. "skipped" is the backend finding nothing
  // to do: no words.
  function failureText(f) {
    switch (f.code) {
    case "wrongPassword": return strings.t("err.wrongPassword")
    case "noAnswer": return strings.t("err.noAnswer")
    case "timeout": return strings.t("err.timeout")
    case "tooSoon": return f.retryInS > 0 ? strings.t("err.tooSoonIn").arg(f.retryInS) : strings.t("err.tooSoon")
    case "busy": return strings.t("err.busy")
    case "skipped": return ""
    default: return f.text !== "" ? strings.t("err.failed").arg(f.text) : strings.t("err.generic")
    }
  }

  // Everything that belongs to one opening of the panel. The passphrase is
  // not kept anywhere but in its field, which clears itself when its row
  // closes. The watchdog board's held order is one of them: it lasts from the
  // panel opening to its closing, across the views.
  function resetUi() {
    nav = Model.navInit()
    closeTransients()
    wdOrder = []
    dnsNote = ({ tone: "", text: "" })
    netNote = ""
    netFail = ({ id: "", text: "" })
    copied = false
    wipeSecrets()
  }

  // What belongs to the view being left: a passphrase row, an armed Forget,
  // the DNS confirm, the watchdog's board state.
  function closeTransients() {
    passwordFor = ""
    passwordError = ""
    armedUuid = ""
    confirm = ({ open: false, verb: "", servers: "", kind: "" })
    wdReset()
  }

  function wipeSecrets() {
    if (secretRun) secretRun.wipe()
    secretRun = null
  }

  onOpenedChanged: {
    QnetService.setOpen(root, opened)
    if (opened) {
      resetUi()
      settled = false
      settleTimer.restart()
      nowMs = Date.now()
      pending = Model.reconcilePending(pending, rawState, nowMs)
      wdHold()
      cursorActive = false
      cursor = Model.initialCursor(rows, "main")
      cursorMemory = ({})
      pointerGate.reset()
    } else {
      settleTimer.stop()
      settled = false
      resetUi()
    }
  }

  Component.onDestruction: QnetService.setOpen(root, false)

  // ------------------------------------------------------------- cursor
  // One cursor: a row of Model.focusRows and an item in it. The keyboard
  // moves it and so does the pointer (hoverCursor), so the screen never has
  // two highlights. It starts hidden; the first key shows it.
  property bool cursorActive: false
  // Whether the pointer put the cursor where it is (its ring is the accent;
  // the keyboard's is grey).
  property bool cursorPointer: false
  property var cursor: ({ row: "net:0", item: 0 })
  property var cursorMemory: ({})
  property int lastRowIndex: 0

  // The route's nodes that open a view, left to right, and the one the
  // cursor is on.
  readonly property var routeStops: Model.routeStops(view)
  readonly property string routeCursorNode: has("route") && routeStops.length > 0 ? routeStops[Math.min(cursor.item, routeStops.length - 1)] : ""

  readonly property var rows: Model.focusRows(view, page === "watchdog" ? wdRowsCtx : { view: page, confirm: confirm.open }, pending, netList)
  readonly property string rowsSig: page + ":" + rows.map(function(r) { return r.id }).join(",")
  // The header's own stops, whichever view is up (the header is on the main
  // view's face).
  readonly property var headerItems: Model.focusRows(view, { view: "main" }, pending, netList)[0].items

  onRowsChanged: {
    var c = Model.settleCursor(rows, cursor, lastRowIndex)
    if (c.row !== cursor.row || c.item !== cursor.item) cursor = c
    var i = Model.rowIndex(rows, cursor.row)
    if (i >= 0) lastRowIndex = i
  }
  onRowsSigChanged: pointerGate.reset()

  function has(row, item) {
    return cursorActive && cursor.row === row && (item === undefined || cursor.item === item)
  }

  function setCursor(row, item) {
    cursorActive = true
    cursorPointer = true
    cursor = ({ row: row, item: item === undefined ? 0 : item })
  }

  // Hover moves the cursor only when the pointer itself moved: rows that
  // scroll or appear under a parked pointer get hover events too, and must
  // not take the cursor from the keyboard (PointerMoveGate compares the
  // pointer's place in the key catcher, which never moves).
  function hoverCursor(item, mouse, row, itemIndex) {
    var at = mouse && mouse.position !== undefined ? mouse.position : mouse
    if (!pointerGate.moved(item, at)) return false
    setCursor(row, itemIndex)
    return true
  }

  PointerMoveGate {
    id: pointerGate
    referenceItem: keyCatcher
  }

  function moveCursor(dx, dy) {
    cursorPointer = false
    var r = Model.moveFocus(rows, cursor, dx, dy, cursorMemory)
    cursor = r.cursor
    cursorMemory = r.memory
  }

  // The network list scrolls inside its own box; keep the cursor in view.
  function ensureCursorVisible(item) {
    for (var p = item ? item.parent : null; p; p = p.parent) {
      if (p.cursorScroll === true) {
        var maxY = Math.max(0, p.contentHeight - p.height)
        if (maxY <= 0) return
        var margin = 4
        var top = item.mapToItem(p.contentItem, 0, 0).y
        var was = p.contentY
        if (top < p.contentY + margin) p.contentY = Math.max(0, top - margin)
        else if (top + item.height > p.contentY + p.height - margin) p.contentY = Math.min(maxY, top + item.height + margin - p.height)
        if (p.contentY !== was) pointerGate.reset()
        return
      }
    }
  }

  // --------------------------------------------------------------- keys
  // A held key acts once: Esc, Enter, p, r and Delete fire on the press and
  // ignore the key's auto-repeat (and a second press within 80 ms). Movement
  // repeats.
  readonly property int repeatGap: 80
  property var keyTimes: ({})
  property bool keyAutoRepeat: false

  function fresh(name) {
    var ok = Model.freshGate(keyTimes, name, Date.now(), repeatGap)
    return ok && !keyAutoRepeat
  }

  function noteKey(event) {
    keyAutoRepeat = event.isAutoRepeat
    if (keyAutoRepeat) Qt.callLater(function() { root.keyAutoRepeat = false })
  }

  // Esc steps back one level (Model.escapeStep): an armed Forget, the DNS
  // confirm, the passphrase row, the watchdog's PIN field, its NORMAL confirm
  // and its open ticket, a drill-down, then the panel.
  function handleEscape() {
    var step = Model.escapeStep({
      armed: armedUuid !== "", confirm: confirm.open, password: passwordFor !== "",
      pin: wdPinOpen, flip: wdFlip, ticket: wdTicket !== null, view: page
    })
    if (step === "disarm") disarmForget()
    else if (step === "confirm") confirmCancel()
    else if (step === "password") cancelPassword()
    else if (step === "pin") wdClosePin()
    else if (step === "flip") wdFlip = false
    else if (step === "ticket") wdSetTicket(null)
    else if (step === "back") goBack()
    else close()
  }

  function activateCursor() {
    var i = Model.rowIndex(rows, cursor.row)
    if (i < 0) return
    var row = rows[i]
    var item = row.items[Math.min(cursor.item, row.items.length - 1)]
    var id = row.id
    if (id === "back") goBack()
    else if (id === "header") {
      if (item === "portal") openPortal()
      else if (item === "qr") summonQr()
      else if (item === "speed") summonSpeed()
      else if (item === "radio") toggleRadio()
    } else if (id === "hero") heroAction()
    else if (id === "pause") togglePause()
    else if (id === "route") openView(Model.routeTarget(view, item), false)
    else if (id === "bypass") fixBypass()
    else if (id.indexOf("leak:") === 0) pinOne(parseInt(id.substring(5), 10))
    else if (id === "pinall") pinAll()
    else if (id === "admin") openAdmin()
    else if (id === "confirm") { if (item === "replace") confirmReplace(); else confirmCancel() }
    else if (id.indexOf("choice:") === 0) tapTile(id.substring(7))
    else if (id === "card") { if (item === "disconnect") disconnectNet() }
    else if (id === "scan") scan()
    else if (id.indexOf("net:") === 0) activateNet(parseInt(id.substring(4), 10))
    else if (id === "ip") copyIp()
    else if (page === "watchdog") wdActivate(id, item)
  }

  // Delete asks to forget the saved network under the cursor (the one in
  // use, on the card, included), and a second press confirms.
  function deleteKey() {
    if (!cursorActive) return
    var uuid = ""
    if (cursor.row === "card") uuid = view.link.uuid
    else if (cursor.row.indexOf("net:") === 0) {
      var net = netList[parseInt(cursor.row.substring(4), 10)]
      if (net) uuid = net.uuid
    }
    if (uuid === "") return
    if (armedUuid !== "" && armedUuid === uuid) {
      // Asked, and answered by a new press, not by the repeat of the first.
      if (!keyAutoRepeat && Date.now() - armedAt > 400) confirmForget()
    } else armForgetUuid(uuid)
  }

  // ----------------------------------------------------------- actions
  Component { id: runnerComp; ActionRunner {} }

  // Run `argv` (an array, never a shell) and call cb(result) when it is done.
  // opts.secret: written to its stdin as one line, then forgotten.
  function runCli(argv, opts, cb) {
    if (!argv) return false
    var o = opts || {}
    var hasSecret = o.secret !== undefined
    var r = runnerComp.createObject(root, {
      command: argv, hasSecret: hasSecret, secret: hasSecret ? o.secret : "",
      timeoutMs: o.timeoutMs ? o.timeoutMs : Model.ACTION_DEADLINE_MS, done: cb
    })
    if (!r) return false
    if (hasSecret) secretRun = r
    r.running = true
    return true
  }

  function setPending(patch) { pending = Model.withPending(pending, patch, Date.now()) }

  // -- DNS
  // One DNS change at a time: while one is pending, no new one starts.
  function runDns(verb, force) {
    if (pending.dns !== "") return
    var argv = Model.argvDns(bin, verb, force)
    if (!argv) return
    dnsNote = ({ tone: "", text: "" })
    setPending({ dns: verb })
    runCli(argv, {}, function(res) {
      if (res.ok) {
        // `qnet dns pihole` checks with a canary that must come back blocked;
        // if it did not, say why.
        var unverified = Model.verifyNote(verb, res)
        if (unverified !== "") setDnsNote("warning", strings.t("dns.unverified").arg(unverified))
        return
      }
      setPending({ dns: "" })
      var f = Model.failure(res)
      if (f.code === "confirm") {
        confirm = ({ open: true, verb: verb, servers: Model.confirmServers(res.detail, view), kind: "replace" })
        return
      }
      var words = failureText(f)
      if (words !== "") setDnsNote("urgent", words)
    })
  }

  // A tap on a mode tile (Model.tapPlan). Leaving the Pi-hole is two steps:
  // the tap only asks ("Stop using Pi-hole? Use automatic DNS · Cancel"),
  // and nothing runs until that is answered.
  function tapTile(name) {
    var plan = Model.tapPlan(name, view)
    if (plan.action === "none") return
    if (plan.action === "setup") { setup(); return }
    if (pending.dns !== "") return
    if (plan.action === "confirm") {
      confirm = ({ open: true, verb: plan.verb, servers: "", kind: plan.kind })
      return
    }
    confirm = ({ open: false, verb: "", servers: "", kind: "" })
    runDns(plan.verb, false)
  }

  // The yes of the inline confirm: switch away from the Pi-hole (a "leave"),
  // or replace the DNS that was set by hand (--force).
  function confirmReplace() {
    if (!confirm.open) return
    var verb = confirm.verb
    var force = confirm.kind !== "leave"
    confirm = ({ open: false, verb: "", servers: "", kind: "" })
    runDns(verb, force)
  }

  function confirmCancel() {
    confirm = ({ open: false, verb: "", servers: "", kind: "" })
  }

  function togglePause() {
    if (!chip.enabled) return
    var now = Date.now()
    var done = function(patch) {
      return function(res) {
        if (res.ok) { QnetService.refresh(); return }
        setPending(patch)
        var words = failureText(Model.failure(res))
        if (words !== "") setDnsNote("urgent", words)
      }
    }
    if (chip.mode === "pause") {
      setPending({ pause: "pause", pauseUntilMs: now + Model.PAUSE_SECONDS * 1000 })
      runCli(Model.argvPause(bin, Model.PAUSE_SECONDS), {}, done({ pause: "", pauseUntilMs: 0 }))
    } else {
      setPending({ pause: "resume" })
      runCli(Model.argvResume(bin), {}, done({ pause: "" }))
    }
  }

  // This link's queries can skip the Pi-hole: apply it to the link in use.
  function fixBypass() { runDns("pihole", false) }

  // The one corrective step the hero offers (Model.heroState's `action`).
  function heroAction() {
    switch (hero.action) {
    case "setup":
    case "signin": setup(); break
    case "usepihole": tapTile("pihole"); break
    case "pin": fixBypass(); break
    }
  }

  // Pin saved profiles that are not in use: a list of uuids, one command.
  function pinUuids(uuids) {
    if (uuids.length === 0 || pending.dns !== "" || pending.pinUuid !== "") return
    var argv = Model.argvPin(bin, uuids)
    if (!argv) return
    setPending({ pinUuid: uuids.join(" ") })
    runCli(argv, {}, function(res) {
      if (res.ok) return
      setPending({ pinUuid: "" })
      var words = failureText(Model.failure(res))
      if (words !== "") setDnsNote("urgent", words)
    })
  }

  function pinAll() {
    var g = leaks.profiles
    if (g && g.pinnable) pinUuids(g.uuids)
  }

  function pinOne(i) {
    var g = leaks.profiles
    if (g && g.items[i] && g.items[i].uuid !== "") pinUuids([g.items[i].uuid])
  }

  function openAdmin() {
    var argv = Model.argvOpenUrl(view.pihole.adminUrl)
    if (!argv) return
    Quickshell.execDetached(argv)
    close()
  }

  function setup() {
    // No address: setup asks for it, so a guess never becomes the pinned one.
    var argv = Model.argvTerminal("setup", bin)
    if (!argv) return
    Quickshell.execDetached(argv)
    close()
  }

  // -- Watchdog (a qberrypi's patch bay: WatchdogView, PatchBay, LampRow)
  // The tab's state lives here, as the other views' does: reset when the tab
  // is left or the panel closes, and nothing but the held order survives a
  // state update. The held order lives longer than a visit: it is the panel's.
  //   wdOrder     the macs in the order the board keeps while the panel is
  //               open (Model.holdOrder); set when the panel opens (or when
  //               the first jacks arrive), updated as jacks come and go, kept
  //               across the views, cleared when the panel closes (resetUi)
  //   wdScroll    the first bay in view (Model.bayLayout clamps it)
  //   wdTicket    null, { kind: "device", mac } or { kind: "alert", alertId }:
  //               the open ticket; the board shrinks to its bay
  //   wdFlip      the NORMAL confirm is open
  //   wdPinOpen   the PIN field is open
  //   wdNote      an inline note (a failed action), cleared by noteTimer
  //   wdPinNote   the same, in the PIN footer
  //   wdRunning   actions of the tab that have not answered yet; wdSettling is
  //               the moment after one succeeded, until the next state shows
  //               what it did: wdBusy (either) keeps a ticket's buttons from
  //               running twice. An action that comes in that time is not lost:
  //               it waits in wdQueue (Model.queueAction) and runs after the
  //               one before it and its settle; wdCurrent names the one running
  //               or just done
  //   wdEditing   a text field of the tab (the label, the PIN) has the keys
  property var wdOrder: []
  property int wdScroll: 0
  property var wdTicket: null
  property bool wdFlip: false
  property bool wdPinOpen: false
  property string wdNote: ""
  property string wdPinNote: ""
  property int wdRunning: 0
  property bool wdSettling: false
  property var wdQueue: []
  property string wdCurrent: ""
  property bool wdLabelFocus: false
  property bool wdPinFocus: false
  readonly property bool wdEditing: wdLabelFocus || wdPinFocus
  readonly property bool wdBusy: wdRunning > 0 || wdSettling

  // A ticket is closing or changing: the label field, if it holds an edit,
  // sends it now. The PIN footer's Set was pressed from the keyboard: the PIN
  // field submits. The label row got Enter: the label field takes the keys.
  signal wdCommitRequested()
  signal wdPinSubmitRequested()
  signal wdLabelFocusRequested()
  // A label did not get to the Pi: a field of that device shows its name again.
  signal wdLabelFailed(string mac)

  Timer {
    id: wdSettleTimer
    interval: 1500
    onTriggered: {
      root.wdSettling = false
      root.wdCurrent = ""
      root.wdDrain()
    }
  }

  // The jack the open ticket belongs to ("" for none, or for a call that
  // rings no jack: the ARP spoof's).
  readonly property string wdTicketMac: {
    if (wdTicket === null) return ""
    if (wdTicket.kind === "device") return wdTicket.mac
    var call = Model.callOf(view, wdTicket.alertId)
    return call !== null && call.mac !== null ? call.mac : ""
  }
  // The lamp whose window is lit "on": the open alert ticket's kind.
  readonly property string wdTicketLamp: {
    if (wdTicket === null || wdTicket.kind !== "alert") return ""
    var call = Model.callOf(view, wdTicket.alertId)
    return call !== null ? call.lamp : ""
  }
  readonly property var wdLayout: Model.bayLayout(wdOrder, { ticketMac: wdTicketMac, ticket: wdTicket !== null, scroll: wdScroll }, view.watchdog.bay.jacks)
  readonly property var wdRowsCtx: ({
    view: "watchdog", flip: wdFlip, ticket: wdTicket, pinOpen: wdPinOpen, layout: wdLayout, order: wdOrder, nowS: nowMs / 1000
  })

  // The tab is left or the panel closes: what the label field holds is sent
  // first (the field commits once: it knows what was sent), then the visit's
  // state goes. The held order stays (see wdOrder).
  function wdReset() {
    wdCommitRequested()
    wdScroll = 0
    wdTicket = null
    wdFlip = false
    wdPinOpen = false
    wdNote = ""
    wdPinNote = ""
    wdLabelFocus = false
    wdPinFocus = false
  }

  // The held order: the jacks' own (alerting and new first, labelled, then by
  // address, offline last) when there is none yet, which is when the panel
  // opens or the first jacks arrive; after that the same places, with the jacks
  // that came put in front of the offline ones and those that went dropped.
  function wdHold() {
    var next = Model.holdOrder(wdOrder, rawState.watchdog.bay.jacks)
    if (next.join(",") !== wdOrder.join(",")) wdOrder = next
  }

  // Entering the tab: a fresh visit (the order is the panel's and is kept).
  function wdOpen() {
    wdReset()
    wdHold()
  }

  // A new snapshot while the panel is open: the order is kept up, and on the
  // tab an alert or device ticket whose subject is gone closes.
  function wdSync() {
    if (!opened) return
    wdHold()
    if (page !== "watchdog") return
    if (wdTicket !== null && wdTicket.kind === "alert" && Model.callOf(rawState, wdTicket.alertId) === null) wdSetTicket(null)
    if (wdTicket !== null && wdTicket.kind === "device" && Model.jackOf(rawState, wdTicket.mac) === null) wdSetTicket(null)
  }

  // Open, switch or close the ticket. An edit in the label field is sent
  // first (a ticket going away ends the field's focus).
  function wdSetTicket(ticket) {
    wdCommitRequested()
    wdTicket = ticket
    // a label field that goes away with its ticket takes its focus with it
    if (ticket === null || ticket.kind !== "device") {
      wdLabelFocus = false
      wdReturnFocus()
    }
  }

  // Which bay is in view after a ticket for `mac` opens: its own, which stays
  // when the ticket closes.
  function wdSeat(mac) {
    wdScroll = Model.bayLayout(wdOrder, { ticketMac: mac, scroll: wdScroll }, view.watchdog.bay.jacks).scroll
  }

  // A click or Enter on a jack's column: its ticket opens, or closes.
  function wdToggleDevice(mac) {
    if (typeof mac !== "string" || mac === "") return
    wdFlip = false
    if (wdTicket !== null && wdTicket.kind === "device" && wdTicket.mac === mac) { wdSetTicket(null); return }
    wdSeat(mac)
    wdSetTicket({ kind: "device", mac: mac })
  }

  // "Open device ›" on an alert's ticket: that jack's ticket, whatever is open.
  function wdOpenDevice(mac) {
    if (typeof mac !== "string" || mac === "" || Model.jackOf(view, mac) === null) return
    wdFlip = false
    wdSeat(mac)
    wdSetTicket({ kind: "device", mac: mac })
  }

  // A click or Enter on a lit drop lamp, a lit window of the lamp row or a
  // call: that alert's ticket opens, or closes.
  function wdOpenAlert(alertId) {
    if (typeof alertId !== "number") return
    wdFlip = false
    if (wdTicket !== null && wdTicket.kind === "alert" && wdTicket.alertId === alertId) { wdSetTicket(null); return }
    var call = Model.callOf(view, alertId)
    if (call === null) return
    if (call.mac !== null) wdSeat(call.mac)
    wdSetTicket({ kind: "alert", alertId: alertId })
  }

  // A lit window of the lamp row opens its kind's newest call.
  function wdOpenLamp(kind) {
    var lamps = view.watchdog.bay.lamps
    for (var i = 0; i < lamps.length; i++) if (lamps[i].kind === kind) { wdOpenAlert(lamps[i].alertId); return }
  }

  // Put bay `bay` first in view (the shots use it; the pager and the wheel
  // step with wdPage). Model.bayLayout clamps it to what exists, and an open
  // ticket's bay wins.
  function wdScrollTo(bay) {
    if (wdTicketMac === "") wdScroll = Math.max(0, Math.floor(Number(bay) || 0))
  }

  function wdPage(dir) {
    if (wdTicketMac !== "") return
    wdScroll = Math.max(0, wdLayout.scroll + (dir < 0 ? -1 : 1))
  }

  // The NORMAL key and "Flip ›": to ADS PASS asks first (the confirm in the
  // readout); back to BLOCKED is at once.
  function wdPressKey() {
    if (view.watchdog.exemptDefault) {
      wdFlip = false
      wdAction("exempt-default", ["off"])
    } else wdFlip = !wdFlip
  }

  function wdConfirmFlip() {
    if (!wdFlip) return
    wdFlip = false
    wdAction("exempt-default", ["on"])
  }

  function wdCancelFlip() { wdFlip = false }

  function setWdNote(text) {
    wdNote = text
    noteTimer.restart()
  }

  // One `qnet watchdog <verb>` (Model.argvWatchdog builds it). When it
  // succeeds the watcher is told to read the devices again so the board shows
  // the edit at once; when it fails the board says why, inline. One at a time:
  // while one runs, and for a moment after it succeeded (until the state has
  // had its turn), a ticket's buttons are dead so none runs twice, and an
  // action that still comes (the label's commit when the field loses the keys,
  // a key press) is not dropped: it waits in wdQueue and runs when the ones
  // before it are done (wdDrain). Only a full queue, or a PIN (which never
  // waits), is refused: the note says busy, and the caller learns it from the
  // return value (true: it runs now or later).
  // opts: { secret } goes to the child's stdin (the PIN), { chain } lets an
  // action that follows another one start inside that moment, { silent }
  // leaves the notes to `done` and the caller.
  function wdAction(verb, args, done, opts) {
    var o = opts || {}
    if (wdRunning === 0 && (!wdSettling || o.chain === true)) return wdStart(verb, args, done, o)
    if (!Model.argvWatchdog(bin, verb, args)) return false
    var q = Model.queueAction(wdQueue, { verb: verb, args: args, done: done, opts: o }, wdCurrent)
    if (!q.took) {
      if (o.secret !== undefined) o.secret = ""
      if (o.silent !== true) setWdNote(strings.t("err.busy"))
      return false
    }
    wdQueue = q.queue
    return true
  }

  // Runs one now: the caller has made sure none is running.
  function wdStart(verb, args, done, o) {
    var argv = Model.argvWatchdog(bin, verb, args)
    if (!argv) return false
    var silent = o.silent === true
    wdNote = ""
    wdRunning++
    wdCurrent = Model.actionKey(verb, args)
    var started = runCli(argv, o, function(res) {
      wdRunning = Math.max(0, wdRunning - 1)
      if (res.ok) {
        QnetService.send("devices")
        wdSettling = true
        wdSettleTimer.restart()
      } else {
        wdCurrent = ""
        if (!silent) {
          var words = failureText(Model.failure(res))
          if (words !== "") setWdNote(words)
        }
      }
      if (typeof done === "function") done(res)
      wdDrain()
    })
    // The PIN: the runner has its own copy, written to the child's stdin and
    // cleared there; this object (which the callback's closure keeps alive)
    // must not hold it until the child exits.
    if (o.secret !== undefined) o.secret = ""
    if (!started) {
      wdRunning = Math.max(0, wdRunning - 1)
      wdCurrent = ""
    }
    return started
  }

  // The next waiting action, once nothing runs and the last one has settled.
  // One that cannot start is skipped for the one after it.
  function wdDrain() {
    while (wdQueue.length > 0 && wdRunning === 0 && !wdSettling) {
      var next = wdQueue[0]
      wdQueue = wdQueue.slice(1)
      wdStart(next.verb, next.args, next.done, next.opts)
    }
  }

  // The queue's Dismiss all, a ticket's Dismiss (both clear the Pi's screen).
  function wdDismissAll() {
    if (view.watchdog.bay.calls.length === 0) return
    wdAction("ack-all", [], function(res) {
      if (res.ok && wdTicket !== null && wdTicket.kind === "alert") wdSetTicket(null)
    })
  }

  function wdDismiss(alertId) {
    wdAction("ack", [alertId], function(res) {
      if (res.ok && wdTicket !== null && wdTicket.kind === "alert" && wdTicket.alertId === alertId) wdSetTicket(null)
    })
  }

  // Mark known puts the jack on this PC's list and settles the calls that
  // said it was new (the Pi would otherwise keep ringing them).
  function wdKnow(mac) {
    var calls = Model.newDeviceCalls(view, mac)
    wdAction("know", [mac], function(res) { if (res.ok) wdAckEach(calls) })
  }

  function wdAckEach(ids) {
    if (ids.length === 0) return
    wdAction("ack", [ids[0]], function(res) { if (res.ok) wdAckEach(ids.slice(1)) }, { chain: true })
  }

  // The patch row: the cord of the open ticket's jack (patch is blocked or pass).
  function wdPatch(mac, want) {
    var jack = Model.jackOf(view, mac)
    if (!jack || !Model.patchWanted(jack, want, nowMs / 1000)) return
    wdAction("patch", [mac, want])
  }

  // The gate row: secs 0 shuts it, 300, 1800 or 3600 opens it.
  function wdGate(mac, secs) { wdAction("gate", [mac, secs]) }

  // The label field's edit, as typed. True: it was sent or waits its turn (a
  // failure shows as wdLabelFailed, which the field answers by showing the
  // jack's name again); false: it was refused (busy, said inline) and the
  // field must not look as if it were saved.
  function wdLabel(mac, text) {
    return wdAction("label", [mac, text], function(res) { if (!res.ok) wdLabelFailed(mac) })
  }

  // The PIN footer. Set and Change open the field (it takes the keys); the
  // field's text goes to `pin set` as the runner's stdin and nowhere else.
  function wdOpenPin() {
    wdPinNote = ""
    wdPinOpen = true
  }

  function wdClosePin() {
    wdPinOpen = false
    wdPinNote = ""
    wdPinFocus = false
    wdReturnFocus()
  }

  // Called with the PIN field: the digits are read, the field cleared in the
  // same breath, and they are not kept (the passphrase's way: submitPassword).
  function wdSubmitPin(field) {
    var pin = field.text
    field.text = ""
    if (!Model.validPin(pin)) {
      pin = ""
      wdPinNote = strings.t("wd.pin.four")
      noteTimer.restart()
      return
    }
    var started = wdAction("pin", ["set"], function(res) {
      secretRun = null
      if (res.ok) wdClosePin()
      else {
        wdPinNote = failureText(Model.failure(res))
        noteTimer.restart()
      }
    }, { secret: pin, silent: true })
    pin = ""
    if (!started) {
      wdPinNote = strings.t("err.busy")
      noteTimer.restart()
    }
  }

  // A text field of the tab ("label" or "pin") took the keys, or let them go.
  function wdFieldFocus(which, on) {
    if (which === "pin") wdPinFocus = on
    else wdLabelFocus = on
    if (!on) wdReturnFocus()
  }

  // The keys go back to the key gate (a field is done with them).
  function wdReturnFocus() {
    Qt.callLater(function() { if (root.opened && root.passwordFor === "" && !root.wdEditing) keyGate.forceActiveFocus() })
  }

  // Enter on a stop of the watchdog view (the back button is handled above).
  // Each row's items are named in Model.focusRows.
  function wdActivate(id, item) {
    var mac = wdTicketMac
    if (id === "lamps") wdOpenLamp(item)
    else if (id.indexOf("bay:") === 0) wdToggleDevice(item)
    else if (id === "normal") wdPressKey()
    else if (id === "flip") { if (item === "flip") wdConfirmFlip(); else wdCancelFlip() }
    else if (id === "pager") wdPage(item === "up" ? -1 : 1)
    else if (id === "queue") wdDismissAll()
    else if (id.indexOf("call:") === 0) wdOpenAlert(parseInt(id.substring(5), 10))
    else if (id === "label") wdLabelFocusRequested()
    else if (id === "patch") wdPatch(mac, item)
    else if (id === "gate") wdGate(mac, item === "shut" ? 0 : parseInt(item, 10))
    else if (id === "tactions") wdTicketAction(item)
    else if (id === "pin") wdPinAction(item)
  }

  // The buttons under a ticket. Both tickets name theirs in Model
  // (deviceActions, alertActions).
  function wdTicketAction(item) {
    if (wdTicket === null) return
    if (item === "close") { wdSetTicket(null); return }
    if (wdTicket.kind === "device") {
      if (item === "know") wdKnow(wdTicket.mac)
      else if (item === "forget") wdAction("forget", [wdTicket.mac])
      return
    }
    var call = Model.callOf(view, wdTicket.alertId)
    if (call === null) return
    if (item === "dismiss") wdDismiss(call.id)
    else if (item === "know" && call.mac !== null) wdKnow(call.mac)
    else if (item === "open") {
      var target = Model.alertOpenTarget(view, call)
      if (target !== null) wdOpenDevice(target.mac)
    }
  }

  function wdPinAction(item) {
    if (item === "clear") wdAction("pin", ["clear"])
    else if (item === "cancel") wdClosePin()
    else if (item === "set" && wdPinOpen) wdPinSubmitRequested()
    else wdOpenPin()
  }

  // -- Wi-Fi
  function toggleRadio() {
    if (!view.radio.hwEnabled || pending.radio !== "") return
    var on = !view.radio.wifiEnabled
    setPending({ radio: on ? "on" : "off" })
    runCli(Model.argvRadio(bin, on), {}, function(res) {
      if (res.ok) return
      setPending({ radio: "" })
      var words = failureText(Model.failure(res))
      if (words !== "") setNetNote(words)
    })
  }

  // The scan button forces a scan (the backend throttles it).
  function scan() {
    if (view.scan.running || !view.radio.wifiEnabled) return
    setPending({ scanUntilMs: Date.now() + Model.SCAN_SPIN_MS })
    runCli(Model.argvScan(bin), {}, function(res) {
      if (res.ok) return
      setPending({ scanUntilMs: 0 })
      var words = failureText(Model.failure(res))
      if (words !== "") setNetNote(words)
    })
  }

  // Entering the Wi-Fi view: scan only if the last scan is older than
  // ifStaleS. The backend may decline ("skipped", "too-soon", "busy"), and
  // then nothing is said: it was not asked for.
  function scanIfStale(ifStaleS) {
    if (!view.radio.wifiEnabled) return
    setPending({ scanUntilMs: Date.now() + Model.SCAN_SPIN_MS })
    runCli(Model.argvScan(bin, ifStaleS), {}, function(res) {
      if (!res.ok) setPending({ scanUntilMs: 0 })
    })
  }

  function netById(id) {
    for (var i = 0; i < view.networks.length; i++) if (view.networks[i].id === id) return view.networks[i]
    return null
  }

  function tipFor(net) {
    if (net.hidden) return strings.t("net.hiddenTip")
    if (net.known && !net.active) return strings.t("net.forgetHint")
    return ""
  }

  function activateNet(i) {
    var net = netList[i]
    if (!net) return
    if (armedUuid !== "") { disarmForget(); return }
    var plan = Model.connectPlan(net)
    if (plan === "none") return
    // One at a time, as a connect that is still going would be cut across.
    if (pending.connectId !== "" || pending.disconnecting) return
    netFail = ({ id: "", text: "" })
    if (passwordFor !== "" && passwordFor !== net.id) cancelPassword()
    if (plan === "disconnect") disconnectNet()
    else if (plan === "nmtui") openNmtui()
    else if (plan === "password") openPassword(net)
    else connectNet(net, "")
  }

  function connectNet(net, passphrase) {
    var argv = Model.argvConnect(bin, net.id)
    if (!argv) return
    passwordFor = ""
    passwordError = ""
    setPending({ connectId: net.id })
    // The passphrase goes in through stdin as one line, an empty one for an
    // open or saved network.
    var started = runCli(argv, { secret: passphrase, timeoutMs: 45000 }, function(res) {
      secretRun = null
      // A connect does not age out; its own answer ends it (a snapshot that
      // shows the network active may have done so already).
      setPending({ connectId: "" })
      if (res.ok) return
      var f = Model.failure(res)
      if (f.code === "enterprise") { openNmtui(); return }
      if (f.code === "wrongPassword" && !net.known && net.security !== "open" && net.security !== "owe") {
        passwordFor = net.id
        passwordError = strings.t("err.wrongPassword")
        return
      }
      var said = failureText(f)
      if (said === "") return
      netFail = ({ id: net.id, text: said })
      noteTimer.restart()
    })
    passphrase = ""
    if (!started) setPending({ connectId: "" })
  }

  function disconnectNet() {
    if (view.link.kind !== "wifi" || pending.disconnecting) return
    setPending({ disconnecting: true })
    runCli(Model.argvDown(bin), {}, function(res) {
      if (res.ok) return
      setPending({ disconnecting: false })
      var words = failureText(Model.failure(res))
      if (words !== "") setNetNote(words)
    })
  }

  function openPassword(net) {
    passwordError = ""
    passwordFor = net.id
  }

  function cancelPassword() {
    passwordFor = ""
    passwordError = ""
    Qt.callLater(function() { if (root.opened && root.passwordFor === "") keyGate.forceActiveFocus() })
  }

  // Called with the TextField: the passphrase is read, the field cleared in
  // the same breath, and neither is kept.
  function submitPassword(field) {
    var pass = field.text
    field.text = ""
    if (pass.length === 0 || passwordFor === "") return
    var net = netById(passwordFor)
    if (!net) { cancelPassword(); return }
    connectNet(net, pass)
    pass = ""
    Qt.callLater(function() { if (root.opened && root.passwordFor === "") keyGate.forceActiveFocus() })
  }

  function armForget(i) {
    var net = netList[i]
    if (net) armForgetUuid(net.uuid)
  }

  function armForgetUuid(uuid) {
    if (uuid === "") return
    armedUuid = uuid
    armedAt = Date.now()
    armTimer.restart()
  }

  function disarmForget() {
    armedUuid = ""
    armTimer.stop()
  }

  function confirmForget() {
    var uuid = armedUuid
    disarmForget()
    var argv = Model.argvForget(bin, uuid)
    if (!argv) return
    setPending({ forgetUuid: uuid })
    runCli(argv, {}, function(res) {
      if (res.ok) return
      setPending({ forgetUuid: "" })
      var words = failureText(Model.failure(res))
      if (words !== "") setNetNote(words)
    })
  }

  function openNmtui() {
    var argv = Model.argvTerminal("nmtui", bin)
    if (!argv) return
    Quickshell.execDetached(argv)
    close()
  }

  function openPortal() {
    var argv = Model.argvPortal(bin)
    if (!argv) return
    Quickshell.execDetached(argv)
    close()
  }

  // The share card and the speed test are shell plugins of their own
  // (omarchy.wifiqr, omarchy.speedtest), summoned the way the stock panel
  // does, with the connection this panel is showing.
  function summonQr() {
    if (!Model.canShareWifi(view) || !bar || !bar.shell) return
    var payload = {}
    if (view.link.device !== "") payload.iface = view.link.device
    if (view.link.ssid !== "") payload.ssid = view.link.ssid
    close()
    bar.shell.summon("omarchy.wifiqr", JSON.stringify(payload))
  }

  function summonSpeed() {
    if (view.link.kind === "none" || !bar || !bar.shell) return
    var name = view.link.kind === "wifi" ? (view.link.ssid || strings.t("header.wifi")) : strings.t("header.ethernet")
    close()
    bar.shell.summon("omarchy.speedtest", JSON.stringify({ connection: name }))
  }

  function copyIp() {
    var argv = Model.argvCopy(view.link.ip4)
    if (!argv) return
    Quickshell.execDetached(argv)
    copied = true
    copiedTimer.restart()
  }

  // -------------------------------------------------------------- IPC
  ShellIpc {
    target: "qqq.qnet"
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    // Open the panel on a view: "main", "dns", "wifi" or "watchdog" (for
    // scripts and screenshots; no synthetic input needed).
    function view(name: string): void {
      root.open()
      if (name === "dns" || name === "wifi" || name === "watchdog") root.openView(name, false)
      else if (root.page !== "main") root.goBack(false)
    }
  }

  // ---------------------------------------------------------- bar icon
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  readonly property string barTipText: {
    var tip = Model.barTip(view)
    return tip === "" ? "" : strings.t("bar." + tip)
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: Model.linkGlyph(root.view)
    active: Model.barActive(root.view)
    tooltipText: root.barTipText
    onPressed: function(b) { root.toggle() }
  }

  // ============================================================== PANEL
  // First frame: no text over a translucent background. KeyboardPanel fades
  // its card in with the card's `shown` (0..1); the content waits, hidden,
  // until the card is opaque and then appears at once (nothing animates on
  // open). The card is found by walking up from the key catcher (the first
  // ancestor with a numeric `shown`); without one the content follows
  // `opened`.
  property Item panelCard: null
  readonly property bool cardOpaque: panelCard ? panelCard.shown >= 0.999 && opened : opened

  function findPanelCard(item) {
    for (var p = item ? item.parent : null; p; p = p.parent)
      if (typeof p.shown === "number") return p
    return null
  }

  // The watchdog's board starts at the card's padding, as the mockup's does.
  readonly property int topPad: page === "watchdog" ? 0 : Style.space(8)
  readonly property int bottomPad: Style.space(2)

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyGate
    // As wide as Sound Hub: the width of the overclock panel's page column.
    // The board of the watchdog view is 488 wide (a 70 rail and a 418 bay), so
    // its card is 32 wider (the card's padding and border are 16 a side).
    contentWidth: panel.fittedContentWidth(Style.space(root.page === "watchdog" ? 520 : 488))
    contentHeight: panel.fittedContentHeight(views.current.implicitHeight + root.topPad + root.bottomPad, Style.space(820))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // The passphrase field owns the keys while its row is open, and so do
      // the watchdog's label and PIN fields while one of them has the focus.
      blocked: root.passwordFor !== "" || root.wdEditing
      Component.onCompleted: root.panelCard = root.findPanelCard(keyCatcher)

      onMoveRequested: function(dx, dy) {
        // The first key only shows the cursor.
        if (!root.cursorActive) {
          root.cursorActive = true
          root.cursorPointer = false
          if (Model.rowIndex(root.rows, root.cursor.row) < 0) root.cursor = Model.initialCursor(root.rows, root.page)
          return
        }
        root.moveCursor(dx, dy)
      }
      onActivateRequested: {
        if (!root.fresh("activate")) return
        if (root.armedUuid !== "") {
          if (Date.now() - root.armedAt > 400) root.confirmForget()
        } else if (root.cursorActive) root.activateCursor()
      }
      onCloseRequested: if (root.fresh("esc")) root.handleEscape()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onDeleteRequested: if (root.fresh("delete")) root.deleteKey()
      onTextKey: function(t) {
        var k = t.toLowerCase()
        if (k === "p") { if (root.fresh("key:p")) root.togglePause() }
        else if (k === "r") { if (root.page === "wifi" && root.fresh("key:r")) root.scan() }
        else if (k === "1") { if (root.fresh("key:1")) root.openView("dns") }
        else if (k === "2") { if (root.fresh("key:2")) root.openView("wifi") }
        else if (k === "3") { if (root.fresh("key:3")) root.openView("watchdog") }
        // Backspace goes back a view and never closes the panel.
        else if (t === "\b") { if (root.fresh("key:bs")) root.goBack() }
      }

      // Holds the keyboard focus: sees every key before the catcher (its
      // parent) and lets it through, noting whether it is an auto-repeat. It
      // takes the focus back if a control under the pointer took it, except
      // while the passphrase field, or a field of the watchdog tab, has it.
      Item {
        id: keyGate
        focus: true
        Keys.onPressed: function(event) { root.noteKey(event); event.accepted = false }
        onActiveFocusChanged: if (!activeFocus) Qt.callLater(keyGate.retakeFocus)
        function retakeFocus() {
          if (root.opened && root.passwordFor === "" && !root.wdEditing && keyGate.Window.active && !keyGate.activeFocus) keyGate.forceActiveFocus()
        }
      }

      Item {
        id: content
        anchors.fill: parent
        opacity: root.cardOpaque ? 1 : 0

        // The four views, one up at a time.
        Item {
          id: views
          y: root.topPad
          width: parent.width
          readonly property Item current: root.page === "dns" ? dnsView : root.page === "wifi" ? wifiView : root.page === "watchdog" ? watchdogView : mainView
          implicitHeight: current.implicitHeight
          height: implicitHeight

          MainView { id: mainView; hub: root; visible: root.page === "main" }
          DnsView { id: dnsView; hub: root; visible: root.page === "dns" }
          WifiView { id: wifiView; hub: root; visible: root.page === "wifi" }
          WatchdogView { id: watchdogView; hub: root; visible: root.page === "watchdog" }
        }
      }
    }
  }
}

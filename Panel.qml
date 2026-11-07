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
// Layout, top to bottom (components/PanelBody.qml): Header, DnsHero,
// LeakLines, DnsRow, NetworkList, IpFooter. One keyboard cursor runs through them
// (Model.focusRows), and the pointer moves the same cursor.
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
  readonly property int leakShown: Model.LEAKS_SHOWN

  // ------------------------------------------------------------- tokens
  // One font, the bar's, at the shell's Style.font sizes; the hierarchy is
  // size, weight and the dim colour. Surfaces follow lib/tokens.js, shared
  // with Sound Hub and the overclock panel.
  readonly property color fg: bar ? bar.foreground : Commons.Color.foreground
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property int typeTitle: Style.font.heading
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
  readonly property real pressScale: Tokens.PRESS_SCALE
  readonly property real disabledOpacity: Tokens.DISABLED_OPACITY
  readonly property int gutter: Style.space(8)

  function formatNumber(value, decimals) { return Commons.I18n.formatNumber(value, decimals) }
  function formatInt(n) { return Qt.locale(Commons.I18n.formatLocale).toString(n, "f", 0) }

  // -------------------------------------------------------------- state
  // rawState is the newest snapshot from the service; the view is that with
  // this panel's pending requests laid on it, which is what everything draws.
  readonly property var rawState: QnetService.snapshot
  property var pending: Model.emptyPending()
  property double nowMs: Date.now()
  readonly property var view: Model.effective(rawState, pending, QnetService.appliedMs, nowMs, QnetService.down)
  readonly property var hero: Model.heroState(view)
  readonly property var header: Model.headerInfo(view, formatNumber)
  readonly property var tiles: Model.dnsTiles(view)
  readonly property var chip: Model.pauseChip(view)
  readonly property var footer: Model.ipFooter(view)
  readonly property var netList: Model.orderNetworks(view.networks)
  readonly property var leakList: Model.leakLines(view, pending)

  // The graphs are rebuilt when their data changes, not on every snapshot.
  property var historySeries: null
  property var probeLive: ({ runs: [], head: null })
  property int probeTick: 0
  property string historySig: ""
  property string probeSig: ""

  function syncSeries(force) {
    var p = rawState.pihole
    var hs = Model.seriesSignature(p.history)
    if (force || hs !== historySig) {
      historySig = hs
      historySeries = Model.historySeries(p.history, Date.now() / 1000, Model.MAX_HISTORY)
    }
    var ps = Model.seriesSignature(p.probes)
    if (force || ps !== probeSig) {
      probeSig = ps
      var last = p.probes.length ? p.probes[p.probes.length - 1].t : Date.now() / 1000
      probeLive = Model.pulseRuns(p.probes, last)
      probeTick += 1
    }
  }

  onRawStateChanged: {
    nowMs = Date.now()
    pending = Model.reconcilePending(pending, rawState, nowMs)
    syncSeries(false)
  }

  // Counts the pause down and lets pending requests expire, only while the
  // panel is open and there is something to count.
  Timer {
    interval: 1000
    repeat: true
    running: root.opened && (root.view.pihole.blocking === "disabled" || Model.hasPending(root.pending))
    onTriggered: {
      root.nowMs = Date.now()
      root.pending = Model.reconcilePending(root.pending, root.rawState, root.nowMs)
    }
  }

  // Nothing animates while the panel opens: the behaviours that would (a
  // colour following a state that just arrived) wait for `settled`.
  property bool settled: false
  Timer { id: settleTimer; interval: 320; onTriggered: root.settled = root.opened }

  // ------------------------------------------------------ transient UI
  property string passwordFor: ""
  property string passwordError: ""
  property string armedUuid: ""
  property double armedAt: 0
  property var confirm: ({ open: false, verb: "", servers: "" })
  property var dnsNote: ({ tone: "", text: "" })
  property string netNote: ""
  property var netFail: ({ id: "", text: "" })
  property bool copied: false
  property var secretRun: null

  readonly property var captionContext: ({
    connectId: pending.connectId, disconnecting: pending.disconnecting, forgetUuid: pending.forgetUuid,
    failId: netFail.id, failText: netFail.text, armedUuid: armedUuid, connectivity: view.link.connectivity
  })

  // How many network rows show before the list scrolls: seven, fewer on a
  // short screen.
  readonly property int listRows: Math.max(3, Math.min(7, Math.floor((panel.availableCardHeight - Style.space(430)) / Style.space(40))))

  Timer { id: noteTimer; interval: 7000; onTriggered: { root.dnsNote = ({ tone: "", text: "" }); root.netNote = ""; root.netFail = ({ id: "", text: "" }) } }
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

  function failureText(f) {
    switch (f.code) {
    case "wrongPassword": return strings.t("err.wrongPassword")
    case "noAnswer": return strings.t("err.noAnswer")
    case "timeout": return strings.t("err.timeout")
    case "tooSoon": return strings.t("err.tooSoon")
    default: return f.text !== "" ? strings.t("err.failed").arg(f.text) : strings.t("err.generic")
    }
  }

  // Everything that belongs to one opening of the panel. The passphrase is
  // not kept anywhere but in its field, which clears itself when its row
  // closes.
  function resetUi() {
    passwordFor = ""
    passwordError = ""
    armedUuid = ""
    confirm = ({ open: false, verb: "", servers: "" })
    dnsNote = ({ tone: "", text: "" })
    netNote = ""
    netFail = ({ id: "", text: "" })
    copied = false
    wipeSecrets()
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
      syncSeries(true)
      cursorActive = false
      cursor = Model.initialCursor(rows)
      cursorMemory = ({})
      pointerGate.reset()
      Qt.callLater(function() { body.networks.flick.contentY = 0 })
    } else {
      settleTimer.stop()
      settled = false
      resetUi()
    }
  }

  Component.onCompleted: syncSeries(true)
  Component.onDestruction: QnetService.setOpen(root, false)

  // ------------------------------------------------------------- cursor
  // One cursor: a row of Model.focusRows and an item in it. The keyboard
  // moves it and so does the pointer (hoverCursor), so the screen never has
  // two highlights. It starts hidden; the first key shows it.
  property bool cursorActive: false
  property var cursor: ({ row: "net:0", item: 0 })
  property var cursorMemory: ({})
  property int lastRowIndex: 0

  readonly property var rows: Model.focusRows(view, { confirm: confirm.open }, pending, netList)
  readonly property string rowsSig: rows.map(function(r) { return r.id }).join(",")
  readonly property var headerItems: rows[Math.max(0, Model.rowIndex(rows, "header"))].items
  readonly property var dnsItems: rows[Math.max(0, Model.rowIndex(rows, "dns"))].items

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

  // Esc steps back one level: an armed Forget, the DNS confirm, the
  // passphrase row, then the panel.
  function handleEscape() {
    if (armedUuid !== "") disarmForget()
    else if (confirm.open) confirmCancel()
    else if (passwordFor !== "") cancelPassword()
    else close()
  }

  function activateCursor() {
    var i = Model.rowIndex(rows, cursor.row)
    if (i < 0) return
    var row = rows[i]
    var item = row.items[Math.min(cursor.item, row.items.length - 1)]
    var id = row.id
    if (id === "header") {
      if (item === "portal") openPortal()
      else if (item === "qr") summonQr()
      else if (item === "speed") summonSpeed()
      else if (item === "radio") toggleRadio()
    } else if (id === "setup") setup()
    else if (id.indexOf("leak:") === 0) fixLeak(parseInt(id.substring(5), 10))
    else if (id === "confirm") { if (item === "replace") confirmReplace(); else confirmCancel() }
    else if (id === "dns") {
      if (item === "tile:pihole") tapTile("pihole")
      else if (item === "tile:auto") tapTile("auto")
      else if (item === "pause") togglePause()
      else if (item === "admin") openAdmin()
    } else if (id === "scan") scan()
    else if (id.indexOf("net:") === 0) activateNet(parseInt(id.substring(4), 10))
    else if (id === "ip") copyIp()
  }

  function deleteKey() {
    if (!cursorActive || cursor.row.indexOf("net:") !== 0) return
    var i = parseInt(cursor.row.substring(4), 10)
    var net = netList[i]
    if (!net) return
    if (armedUuid !== "" && armedUuid === net.uuid) {
      // Asked, and answered by a new press, not by the repeat of the first.
      if (!keyAutoRepeat && Date.now() - armedAt > 400) confirmForget()
    } else armForget(i)
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
      timeoutMs: o.timeoutMs ? o.timeoutMs : 15000, done: cb
    })
    if (!r) return false
    if (hasSecret) secretRun = r
    r.running = true
    return true
  }

  function setPending(patch) { pending = Model.withPending(pending, patch, Date.now()) }

  // -- DNS
  function runDns(verb, force) {
    var argv = Model.argvDns(bin, verb, force)
    if (!argv) return
    dnsNote = ({ tone: "", text: "" })
    setPending({ dns: verb })
    runCli(argv, {}, function(res) {
      if (res.ok) {
        // The verification query went through the system resolver: if the
        // Pi-hole was asked for and something else answered, say so.
        var other = Model.verifyMismatch(verb, res, view)
        if (other !== "") setDnsNote("warning", strings.t("dns.answeredBy").arg(other))
        return
      }
      setPending({ dns: "" })
      var f = Model.failure(res)
      if (f.code === "confirm") {
        confirm = ({ open: true, verb: verb, servers: Model.confirmServers(res.detail, view) })
        return
      }
      setDnsNote("urgent", failureText(f))
    })
  }

  function tapTile(name) {
    var t = Model.tapDns(name, view)
    if (!t) return
    if (name === "pihole" && !view.pihole.configured) { setup(); return }
    confirm = ({ open: false, verb: "", servers: "" })
    runDns(t.verb, false)
  }

  function confirmReplace() {
    if (!confirm.open) return
    var verb = confirm.verb
    confirm = ({ open: false, verb: "", servers: "" })
    runDns(verb, true)
  }

  function confirmCancel() {
    confirm = ({ open: false, verb: "", servers: "" })
  }

  function togglePause() {
    if (!chip.enabled) return
    var now = Date.now()
    if (chip.mode === "pause") {
      setPending({ pause: "pause", pauseUntilMs: now + Model.PAUSE_SECONDS * 1000 })
      runCli(Model.argvPause(bin, Model.PAUSE_SECONDS), {}, function(res) {
        if (res.ok) return
        setPending({ pause: "", pauseUntilMs: 0 })
        setDnsNote("urgent", failureText(Model.failure(res)))
      })
    } else {
      setPending({ pause: "resume" })
      runCli(Model.argvResume(bin), {}, function(res) {
        if (res.ok) return
        setPending({ pause: "" })
        setDnsNote("urgent", failureText(Model.failure(res)))
      })
    }
  }

  function fixLeak(i) {
    var line = leakList[i]
    if (!line || !line.action) return
    if (line.action.verb === "pin") {
      setPending({ pinUuid: line.action.uuid })
      runCli(Model.argvPin(bin, line.action.uuid), {}, function(res) {
        if (res.ok) return
        setPending({ pinUuid: "" })
        setDnsNote("urgent", failureText(Model.failure(res)))
      })
    } else {
      runDns("pihole", false)
    }
  }

  function openAdmin() {
    var argv = Model.argvOpenUrl(view.pihole.adminUrl)
    if (!argv) return
    Quickshell.execDetached(argv)
    close()
  }

  function setup() {
    var argv = Model.argvTerminal("setup", bin, view.pihole.address)
    if (!argv) return
    Quickshell.execDetached(argv)
    close()
  }

  // -- Wi-Fi
  function toggleRadio() {
    if (!view.radio.hwEnabled) return
    var on = !view.radio.wifiEnabled
    setPending({ radio: on ? "on" : "off" })
    runCli(Model.argvRadio(bin, on), {}, function(res) {
      if (res.ok) return
      setPending({ radio: "" })
      setNetNote(failureText(Model.failure(res)))
    })
  }

  function scan() {
    if (view.scan.running || !view.radio.wifiEnabled) return
    setPending({ scanUntilMs: Date.now() + Model.SCAN_SPIN_MS })
    runCli(Model.argvScan(bin), {}, function(res) {
      if (res.ok) return
      setPending({ scanUntilMs: 0 })
      var f = Model.failure(res)
      if (f.code !== "tooSoon") setNetNote(failureText(f))
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
      if (res.ok) return
      setPending({ connectId: "" })
      var f = Model.failure(res)
      if (f.code === "enterprise") { openNmtui(); return }
      if (f.code === "wrongPassword" && !net.known && net.security !== "open" && net.security !== "owe") {
        passwordFor = net.id
        passwordError = strings.t("err.wrongPassword")
        return
      }
      netFail = ({ id: net.id, text: failureText(f) })
      noteTimer.restart()
    })
    passphrase = ""
    if (!started) setPending({ connectId: "" })
  }

  function disconnectNet() {
    setPending({ disconnecting: true })
    runCli(Model.argvDown(bin), {}, function(res) {
      if (res.ok) return
      setPending({ disconnecting: false })
      setNetNote(failureText(Model.failure(res)))
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
    if (!net || !net.known || net.uuid === "") return
    armedUuid = net.uuid
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
      setNetNote(failureText(Model.failure(res)))
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

  readonly property int topPad: Style.space(8)
  readonly property int bottomPad: Style.space(2)

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyGate
    // As wide as Sound Hub: the width of the overclock panel's page column.
    contentWidth: panel.fittedContentWidth(Style.space(488))
    contentHeight: panel.fittedContentHeight(body.implicitHeight + root.topPad + root.bottomPad, Style.space(820))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // The passphrase field owns the keys while its row is open.
      blocked: root.passwordFor !== ""
      Component.onCompleted: root.panelCard = root.findPanelCard(keyCatcher)

      onMoveRequested: function(dx, dy) {
        // The first key only shows the cursor.
        if (!root.cursorActive) {
          root.cursorActive = true
          if (Model.rowIndex(root.rows, root.cursor.row) < 0) root.cursor = Model.initialCursor(root.rows)
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
        else if (k === "r") { if (root.fresh("key:r")) root.scan() }
      }

      // Holds the keyboard focus: sees every key before the catcher (its
      // parent) and lets it through, noting whether it is an auto-repeat. It
      // takes the focus back if a control under the pointer took it, except
      // while the passphrase field has it.
      Item {
        id: keyGate
        focus: true
        Keys.onPressed: function(event) { root.noteKey(event); event.accepted = false }
        onActiveFocusChanged: if (!activeFocus) Qt.callLater(keyGate.retakeFocus)
        function retakeFocus() {
          if (root.opened && root.passwordFor === "" && keyGate.Window.active && !keyGate.activeFocus) keyGate.forceActiveFocus()
        }
      }

      Item {
        id: content
        anchors.fill: parent
        opacity: root.cardOpaque ? 1 : 0

        PanelBody {
          id: body
          hub: root
          y: root.topPad
        }
      }
    }
  }
}

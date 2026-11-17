// Renders the whole panel (Panel.qml) to a PNG; run through tools/shot:
//   qml6 -I imports Shot.qml -- <fixture.json> <out.png> [ui.json]
// The panel is the real one: it loads QnetService from the plugin's qmldir,
// whose `qnet watch` is the Process stub in imports/Quickshell/Io, which says
// the fixture as its one state line. Everything the panel imports from the
// shell (qs.Ui, qs.Commons, Quickshell) is a stub from imports/.
//
// The card (the KeyboardPanel stub's surface) is drawn on the page colour with
// a margin, once the state is in, the panel is open and settled, and the
// page's height has stood for two frames; then it is grabbed and the process
// exits 0. Anything that goes wrong is logged as a warning and exits 1.
//
// The card is drawn at the width the panel asks for (its contentWidth: 488
// for the main, DNS and Wi-Fi views, 520 for the watchdog's), with the
// shell's own padding and border, so every shot shows the real geometry
// (imports/qs/Ui/KeyboardPanel.qml).
//
// ui.json, optional:
//   { "view": "main|dns|wifi|watchdog",       openView(view, false) on the panel
//     "call": [["functionName", arg, …], …] } root[functionName](...args), in order
// A view that does not open, or a function the panel does not have, fails.
import QtQuick
import QtQuick.Window
import Harness
import "../.." as Plugin

Window {
  id: win

  readonly property int margin: 24
  readonly property color pageColor: "#0b0a14"
  readonly property Item card: Harness.card
  readonly property var panel: loader.item
  readonly property real cardWidth: card ? card.width : 0
  readonly property real cardHeight: card ? card.height : 0

  // Where the run is: waiting for the state, for the panel to settle, grabbing.
  property string stage: "load"
  // Frames still to wait before the grab; counted again from two whenever the
  // size changed since the last frame.
  property int framesLeft: 2
  property string lastSize: ""

  width: Math.max(1, Math.ceil(cardWidth) + 2 * margin)
  height: Math.max(1, Math.ceil(cardHeight) + 2 * margin)
  visible: true
  color: pageColor

  // Sized from the window's own size, not anchored to its content item: that
  // one follows the platform window's resize a moment later, and a card that
  // grows after the first frames (a taller view) must not be grabbed at the
  // old height.
  Rectangle {
    id: page
    width: win.width
    height: win.height
    color: win.pageColor

    // The panel's own item sits at the host's origin and its card at the
    // panel's origin, so the card lands at (margin, margin).
    Item {
      id: host
      x: win.margin
      y: win.margin
      Loader {
        id: loader
        // The service is up and has its state before the panel is built, as in
        // the shell, where it runs from the start. A panel built before the
        // first state makes the route draw once from an empty one (a transient
        // "Unable to assign [undefined] to y" in ResolverChain).
        active: Plugin.QnetService.haveState
        source: Qt.resolvedUrl("../../Panel.qml")
        onStatusChanged: if (status === Loader.Error) win.fail("cannot load Panel.qml")
      }
    }
  }

  function fail(message) {
    console.warn("shot: " + message)
    Qt.exit(1)
  }

  // Runs the ui.json steps; false after a failure.
  function applyUi() {
    var ui = Harness.ui
    var view = typeof ui.view === "string" ? ui.view : "main"
    if (view !== "main") {
      if (typeof panel.openView !== "function") { fail("ui.json: the panel has no openView()"); return false }
      panel.openView(view, false)
      if (panel.page !== view) { fail("ui.json: view \"" + view + "\" did not open (the panel is on \"" + panel.page + "\")"); return false }
    }
    // The Wi-Fi view asks for a scan on entering and spins for a few seconds;
    // a still is of the list, so that wait is over (a call can start it again).
    if (panel.pending && panel.pending.scanUntilMs > 0 && typeof panel.setPending === "function")
      panel.setPending({ scanUntilMs: 0 })
    var calls = Array.isArray(ui.call) ? ui.call : []
    for (var i = 0; i < calls.length; i++) {
      var name = Array.isArray(calls[i]) ? calls[i][0] : calls[i]
      if (typeof name !== "string" || typeof panel[name] !== "function") {
        fail("ui.json: the panel has no function \"" + name + "\"")
        return false
      }
      panel[name].apply(panel, Array.isArray(calls[i]) ? calls[i].slice(1) : [])
    }
    return true
  }

  onFrameSwapped: {
    if (!panel) { update(); return }
    if (stage === "load") {
      if (!card) { update(); return }
      panel.open()
      stage = "open"
    }
    if (stage === "open") {
      if (!panel.opened || !panel.settled) { update(); return }
      if (!applyUi()) { stage = "failed"; return }
      stage = "settle"
      framesLeft = 2
    }
    if (stage !== "settle") return
    var size = cardWidth + "x" + cardHeight
    if (size !== lastSize) { lastSize = size; framesLeft = 2 }
    if (framesLeft > 0) { framesLeft--; update(); return }
    stage = "grab"
    if (!(cardWidth > 0 && cardHeight > 0)) { fail("the card has no size"); return }
    var ok = page.grabToImage(function(result) {
      if (!result.saveToFile(Harness.outPath)) { win.fail("cannot write " + Harness.outPath); return }
      console.log("shot: " + Harness.outPath + " (" + page.width + "x" + page.height + " px at the scale of the run)")
      Qt.exit(0)
    })
    if (!ok) fail("cannot grab the page")
  }

  // A state that never comes, a panel that never settles, or a height that
  // never stands still must not hang the caller.
  Timer {
    interval: 15000
    running: true
    onTriggered: win.fail("timed out in the \"" + win.stage + "\" stage")
  }

  Component.onCompleted: {
    if (Harness.fixturePath === "" || Harness.outPath === "") fail("usage: Shot.qml -- <fixture.json> <out.png> [ui.json]")
  }
}

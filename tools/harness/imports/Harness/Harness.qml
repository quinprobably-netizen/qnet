pragma Singleton
import QtQuick

// What the stubs and Shot.qml share: the command line, the fixture and ui.json
// read from it, and the card the KeyboardPanel stub draws. tools/shot runs
//   qml6 -I tools/harness/imports tools/harness/Shot.qml -- <fixture> <out.png> [ui.json]
// with absolute paths. File reads need QML_XHR_ALLOW_FILE_READ=1 (tools/shot
// sets it).
QtObject {
  id: root

  readonly property var args: {
    var all = Qt.application.arguments
    var at = all.indexOf("--")
    return at < 0 ? [] : all.slice(at + 1)
  }
  readonly property string fixturePath: args[0] || ""
  readonly property string outPath: args[1] || ""
  readonly property string uiPath: args[2] || ""

  // The card (the KeyboardPanel stub's surface), for Shot.qml to size the page.
  property Item card: null

  // The 1x clock the fixtures were written for (tests/helpers.js NOW_S).
  readonly property real fixtureNowS: 1794122700

  function readFile(path) {
    var x = new XMLHttpRequest()
    x.open("GET", "file://" + path, false)
    x.send()
    if (x.status !== 200 && x.status !== 0) throw new Error("cannot read " + path + " (status " + x.status + ")")
    return x.responseText
  }

  // {view, call, realWidth}; an empty object without a ui.json.
  readonly property var ui: {
    if (uiPath === "") return ({})
    try { return JSON.parse(readFile(uiPath)) } catch (e) {
      console.warn("shot: cannot read the ui file " + uiPath + ": " + e)
      return ({})
    }
  }

  // The time fields of the state JSON (SPEC.md "State JSON"): a number named
  // `*Unix`, `*At`, `*Until` or `*Since`, `since`, `until`, or `t` (the
  // history and probe samples), once it is a unix time (> 1e9). Everything
  // else (ages, countdowns, seq) is relative and stays.
  function isTimeKey(key) {
    return key === "t" || key === "since" || key === "until" || /(Unix|At|Until|Since)$/.test(key)
  }

  function shifted(node, key, delta) {
    if (Array.isArray(node)) return node.map(function(v) { return shifted(v, key, delta) })
    if (node !== null && typeof node === "object") {
      var out = {}
      for (var k in node) out[k] = shifted(node[k], k, delta)
      return out
    }
    if (typeof node === "number" && node > 1e9 && isTimeKey(key)) return node + delta
    return node
  }

  // The fixture as the one stdout line `qnet watch` would send, its times
  // moved by (now - fixtureNowS) so ages and countdowns read as when the
  // fixture was made.
  function stateLine() {
    var state = JSON.parse(readFile(fixturePath))
    var delta = Math.floor(Date.now() / 1000) - fixtureNowS
    return JSON.stringify(shifted(state, "", delta))
  }
}

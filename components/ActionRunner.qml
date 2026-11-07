import QtQuick
import Quickshell.Io
import "../Model.js" as Model

// One `qnet <verb>` run to completion: an argv array (never a shell), an
// optional secret written to its stdin as one line, and a callback with the
// parsed result ({ ok, error, detail, verifiedVia }, see Model.parseResult).
// Panel.qml creates one per action and it destroys itself when done.
//
// The secret (a Wi-Fi passphrase) lives in `secret` only until the child has
// started: it is written then and the property cleared at once. Panel.qml
// also clears any unwritten secret when the panel closes (wipe()).
Process {
  id: run

  property string secret: ""
  property bool hasSecret: false
  property var done: null
  property int timeoutMs: 25000

  property bool streamDone: false
  property bool exitedDone: false
  property int code: -1
  property string output: ""
  property bool settled: false

  stdinEnabled: hasSecret

  stdout: StdioCollector {
    waitForEnd: true
    onStreamFinished: {
      run.output = text
      run.streamDone = true
      run.maybeSettle()
    }
  }

  onStarted: {
    if (run.hasSecret) {
      run.write(run.secret + "\n")
      run.secret = ""
    }
    guard.restart()
  }

  onExited: function(exitCode) {
    run.code = exitCode
    run.exitedDone = true
    // The collector's last chunk can land just after the exit.
    late.restart()
    run.maybeSettle()
  }

  function wipe() { secret = "" }

  Component.onCompleted: guard.start()

  function maybeSettle() {
    if (run.streamDone && run.exitedDone) run.finish()
  }

  function finish() {
    if (run.settled) return
    run.settled = true
    guard.stop()
    late.stop()
    run.secret = ""
    var result = Model.parseResult(run.output, run.code)
    var cb = run.done
    run.done = null
    if (typeof cb === "function") cb(result)
    Qt.callLater(function() { run.destroy() })
  }

  // The child never answered: give up, and make it stop.
  property Timer guard: Timer {
    interval: run.timeoutMs
    onTriggered: {
      if (run.running) run.signal(15)
      run.output = ""
      run.code = -1
      run.streamDone = true
      run.exitedDone = true
      run.finish()
    }
  }

  // Exited without the stream ever finishing (or the reverse).
  property Timer late: Timer {
    interval: 400
    onTriggered: run.finish()
  }
}

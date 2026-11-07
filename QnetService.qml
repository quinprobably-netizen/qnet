pragma Singleton
import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

// The one `qnet watch` for the whole shell. The bar instantiates a widget per
// monitor, so each Panel.qml would otherwise start its own poller; this
// singleton owns the single child, and every Panel reads `snapshot` from here and
// reports its open or closed state through setOpen().
//
//   stdout   one JSON object per line: a full snapshot at start, then on every
//            change (the backend coalesces to 4/s) and a heartbeat every 10 s
//   stdin    "open\n" while any panel is open, "closed\n" when the last closes,
//            which sets the backend's cadence; sent again after a restart
//   exit     restarted after 1 s, 2 s, 5 s, 10 s, then 30 s; the counter starts
//            over when a snapshot arrives. Silence for `silenceMs` (three
//            heartbeats) is a hung child and is terminated and restarted.
//
// The child's `seq` counts from its own start, so the last applied seq is
// forgotten whenever a new child starts.
Item {
  id: svc

  readonly property string bin: Quickshell.env("HOME") + "/.local/bin/qnet"

  // The newest snapshot, normalised (Model.normalizeState); an empty state
  // until the first one arrives. appliedMs is when it was applied, for the
  // pause countdown.
  property var snapshot: Model.emptyState()
  property double appliedMs: 0
  property int seq: -1
  property bool haveState: false
  // The child is running and has spoken since it started.
  property bool live: false
  // No snapshot for longer than the grace period: the panel says qnet is down.
  property bool down: false

  property int attempt: 0
  property var openers: []
  readonly property int silenceMs: 35000
  readonly property int graceMs: 4000

  function start() {
    if (watch.running) return
    seq = -1
    live = false
    watch.command = [bin, "watch"]
    watch.running = true
    startGuard.restart()
    if (!down && !downTimer.running) downTimer.start()
  }

  function scheduleRestart() {
    live = false
    silence.stop()
    startGuard.stop()
    if (!restart.running) {
      restart.interval = Model.backoffMs(attempt)
      attempt += 1
      restart.start()
    }
    if (!downTimer.running && !down) downTimer.start()
  }

  // A panel opened or closed. The first to open sends "open", the last to
  // close sends "closed", so the backend polls fast only while one is up.
  function setOpen(owner, open) {
    var i = openers.indexOf(owner)
    var before = openers.length
    if (open && i < 0) openers = openers.concat([owner])
    else if (!open && i >= 0) openers = openers.filter(function(o) { return o !== owner })
    if (before === 0 && openers.length > 0) send("open")
    else if (before > 0 && openers.length === 0) send("closed")
  }

  function refresh() { send("refresh") }

  function send(cmd) {
    if (watch.running) watch.write(cmd + "\n")
  }

  function handleLine(line) {
    var r = Model.parseStateLine(line, seq)
    if (r.kind === "bad") return
    silence.restart()
    attempt = 0
    live = true
    down = false
    downTimer.stop()
    if (r.kind !== "state") return
    seq = r.seq
    snapshot = r.state
    appliedMs = Date.now()
    haveState = true
  }

  Process {
    id: watch
    stdinEnabled: true
    stdout: SplitParser { onRead: function(line) { svc.handleLine(line) } }
    onStarted: {
      startGuard.stop()
      silence.restart()
      if (svc.openers.length > 0) svc.send("open")
    }
    onExited: svc.scheduleRestart()
  }

  // A child that never started (no binary yet) gives no exit; this notices.
  Timer {
    id: startGuard
    interval: 2500
    onTriggered: if (!watch.running) svc.scheduleRestart()
  }

  Timer {
    id: restart
    onTriggered: svc.start()
  }

  Timer {
    id: silence
    interval: svc.silenceMs
    onTriggered: if (watch.running) watch.signal(15)
  }

  Timer {
    id: downTimer
    interval: svc.graceMs
    onTriggered: svc.down = true
  }

  Component.onCompleted: start()

  // Best effort when the shell quits: ask the child to finish properly (it
  // ends its Pi-hole API session on SIGTERM). Quickshell may stop it first;
  // the backend must also cope with being killed (session timeouts).
  Connections {
    target: Qt.application
    function onAboutToQuit() { if (watch.running) watch.signal(15) }
  }
}

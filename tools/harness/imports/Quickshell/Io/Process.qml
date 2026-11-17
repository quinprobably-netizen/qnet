import QtQuick
import Harness

// Stub of Quickshell.Io.Process. Nothing is ever run.
//   [<bin>, "watch"]  the fake `qnet watch`: starts, then says the fixture
//                     (Harness.stateLine()) as one line on stdout and stays up
//   any other command an action: logged, then ok at once with {"ok":true}
// The start comes a turn after `running` is set, as a real child's does.
QtObject {
  id: p

  property var command: []
  property bool running: false
  property bool stdinEnabled: false
  property var stdout: null
  property var stderr: null

  signal started()
  signal exited(int exitCode, int exitStatus)

  // What QnetService sends the watcher ("open", "closed", "refresh") has no
  // effect here.
  function write(data) { }
  function signal(sig) { }

  readonly property bool isWatch: command.length === 2 && command[1] === "watch"

  onRunningChanged: if (running) Qt.callLater(p.begin)

  function begin() {
    if (!running) return
    started()
    if (isWatch) {
      if (stdout && stdout.feed) stdout.feed(Harness.stateLine() + "\n")
      return
    }
    console.log("shot: run " + JSON.stringify(command))
    if (stdout && stdout.feed) stdout.feed("{\"ok\":true}")
    running = false
    exited(0, 0)
  }
}

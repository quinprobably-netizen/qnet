pragma Singleton
import QtQuick

// Stub of the Quickshell singleton: a fixed HOME (QnetService builds the
// qnet path from it), and detached launches are logged, never run.
QtObject {
  function env(name) { return name === "HOME" ? "/home/example" : "" }
  function execDetached(args) { console.log("shot: execDetached " + JSON.stringify(args)) }
}

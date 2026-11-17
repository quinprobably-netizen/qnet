pragma Singleton
import QtQuick

// The Omarchy Amethyst theme as sampled from the mockup stills.
QtObject {
  readonly property color foreground: "#dad6ec"
  readonly property color accent: "#a08dff"
  readonly property color urgent: "#f06a8a"
  readonly property color background: "#151326"
  // The page behind the card in the stills (not a shell colour).
  readonly property color page: "#0b0a14"
  readonly property QtObject popups: QtObject {
    readonly property color background: "#151326"
    readonly property color text: "#dad6ec"
    // The 1 px line of the card: the foreground at 10.5 %.
    readonly property color border: Qt.rgba(0xda / 255, 0xd6 / 255, 0xec / 255, 0.105)
  }
  readonly property QtObject tooltip: QtObject {
    readonly property color background: "#151326"
    readonly property color text: "#dad6ec"
    readonly property color border: Qt.rgba(0xda / 255, 0xd6 / 255, 0xec / 255, 0.4)
  }
}

pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// Pause blocking, as a tile the weight of the DNS tiles, across the content
// column under the hero: "Pause blocking · 5 min"; while paused, "Paused ·
// 4:30 · Resume" in the warning colour on a warning tint (so is the hero's
// word). Dim and still when DNS is not going through a Pi-hole that can be
// told to pause. One press is the whole interaction: the answer is on the
// screen at once (Panel.qml lays the pending request over the view) and the
// countdown runs from there.
CursorSurface {
  id: tile

  required property var hub
  readonly property var chip: hub.chip
  readonly property bool resume: chip.mode === "resume"
  readonly property color tint: hub.warning

  x: hub.gutter
  width: (parent ? parent.width : 0) - 2 * hub.gutter
  height: Style.space(36)
  hasCursor: hub.has("pause")
  onHasCursorChanged: if (hasCursor) hub.ensureCursorVisible(tile)
  foreground: hub.fg
  color: resume ? Qt.rgba(tint.r, tint.g, tint.b, hasCursor ? 0.26 : 0.18) : (hasCursor ? hub.hoverFill : hub.restFill)
  opacity: chip.enabled ? 1 : hub.disabledOpacity
  scale: area.pressed && chip.enabled ? hub.pressScale : 1
  Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }
  Behavior on color { enabled: tile.hub.settled; ColorAnimation { duration: Style.duration(120) } }

  Text {
    anchors.centerIn: parent
    width: Math.min(implicitWidth, tile.width - Style.space(16))
    horizontalAlignment: Text.AlignHCenter
    elide: Text.ElideRight
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: tile.resume
      ? (tile.chip.remainingS > 0
        ? tile.hub.strings.t("pause.resume").arg(Model.formatCountdown(tile.chip.remainingS))
        : tile.hub.strings.t("pause.resumePlain"))
      : tile.hub.strings.t("pause.start")
    color: tile.resume ? tile.tint : tile.hub.fg
    font.family: tile.hub.fontFamily
    font.pixelSize: tile.hub.typeBody
  }

  MouseArea {
    id: area
    anchors.fill: parent
    enabled: tile.chip.enabled
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onPositionChanged: function(mouse) { tile.hub.hoverCursor(area, mouse, "pause", 0) }
    onClicked: tile.hub.togglePause()
  }

  PanelToolTip {
    visible: (area.containsMouse || tile.hasCursor) && tile.chip.enabled
    text: tile.resume ? tile.hub.strings.t("pause.resumeTip") : tile.hub.strings.t("pause.startTip")
    fontFamily: tile.hub.fontFamily
  }
}

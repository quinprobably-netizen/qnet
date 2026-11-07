pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import qs.Ui
import qs.Commons

// The Networks section: one list, the network in use first, then saved ones,
// then the rest (Model.orderNetworks). The label has the scan action, which
// shows its progress. Longer lists scroll inside their own box; the rest of
// the panel stays put.
Column {
  id: list

  required property var hub
  readonly property real rowHeight: Style.space(40)
  readonly property real maxHeight: rowHeight * hub.listRows
  property alias flick: flick

  width: parent ? parent.width : 0

  SectionHead {
    hub: list.hub
    text: list.hub.strings.t("net.title")

    // The scan action. While a scan runs its glyph turns, steadily.
    CursorSurface {
      id: scan
      width: Style.space(28)
      height: Style.space(24)
      hasCursor: list.hub.has("scan")
      onHasCursorChanged: if (hasCursor) list.hub.ensureCursorVisible(scan)
      foreground: list.hub.fg
      fill: list.hub.hoverFill
      scale: scanArea.pressed ? list.hub.pressScale : 1
      Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

      Text {
        id: scanGlyph
        anchors.centerIn: parent
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: list.hub.glyphs.refresh
        color: list.hub.view.scan.running ? list.hub.accent : (scan.hasCursor ? list.hub.fg : list.hub.dim)
        font.family: list.hub.fontFamily
        font.pixelSize: list.hub.typeBody
        RotationAnimator on rotation {
          from: 0; to: 360
          duration: Style.duration(900)
          loops: Animation.Infinite
          // A spinner is constant motion; with animations off it just sits.
          running: list.hub.view.scan.running && list.hub.opened && !Style.reduceMotion
          onRunningChanged: if (!running) scanGlyph.rotation = 0
        }
      }

      MouseArea {
        id: scanArea
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onPositionChanged: function(mouse) { list.hub.hoverCursor(scanArea, mouse, "scan", 0) }
        onClicked: list.hub.scan()
      }

      PanelToolTip {
        visible: scanArea.containsMouse || scan.hasCursor
        text: list.hub.strings.t("net.scanTip")
        fontFamily: list.hub.fontFamily
      }
    }
  }

  Text {
    visible: list.hub.netNote !== ""
    x: list.hub.gutter
    width: list.width - 2 * list.hub.gutter
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    wrapMode: Text.Wrap
    text: list.hub.netNote
    color: list.hub.urgent
    font.family: list.hub.fontFamily
    font.pixelSize: list.hub.typeSmall
    bottomPadding: Style.space(4)
  }

  Flickable {
    id: flick
    width: list.width
    height: Math.min(col.implicitHeight, list.maxHeight)
    contentWidth: width
    contentHeight: col.implicitHeight
    interactive: col.implicitHeight > list.maxHeight
    clip: col.implicitHeight > list.maxHeight
    boundsBehavior: Flickable.StopAtBounds
    // ensureCursorVisible() looks for this on a row's ancestors.
    property bool cursorScroll: true

    Column {
      id: col
      width: flick.width

      Repeater {
        model: ScriptModel { values: list.hub.netList; objectProp: "id" }
        NetworkRow { hub: list.hub }
      }

      // Nothing to list: say why.
      Text {
        visible: list.hub.netList.length === 0
        width: parent.width
        height: list.rowHeight
        leftPadding: list.hub.gutter
        verticalAlignment: Text.AlignVCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: !list.hub.view.radio.wifiEnabled ? list.hub.strings.t("net.radioOff")
          : list.hub.view.scan.running ? list.hub.strings.t("net.scanning") : list.hub.strings.t("net.none")
        color: list.hub.dim
        font.family: list.hub.fontFamily
        font.pixelSize: list.hub.typeSmall
      }
    }
  }
}

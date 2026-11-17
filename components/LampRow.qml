pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The lamp row along the top of the watchdog's board, as along the top of the
// TV's Switchboard: five windows, one per kind of alert (THREAT, NEW DEVICE,
// ARP SPOOF, REBIND, LOOKUPS). A dark window is a well with a line round it;
// a lit one is filled urgent (a high call) or warning, says how many are
// waiting, and opens that kind's newest call as a ticket (Panel.wdOpenLamp).
// An alert that rings no jack (an ARP spoof, a client that is no device on
// the board) rings only here and in the queue.
//
// The lit windows are the keyboard's "lamps" row (Model.focusRows). The one
// whose call is open wears a bright ring, as the mockup's outline.
Item {
  id: row

  required property var hub

  readonly property var lamps: hub.view.watchdog.bay.lamps
  // The lit kinds in order: the items of the keyboard's "lamps" row.
  readonly property var lit: {
    var out = []
    for (var i = 0; i < lamps.length; i++) if (lamps[i].count > 0) out.push(lamps[i].kind)
    return out
  }
  readonly property real gap: Style.spaceReal(3)

  width: parent ? parent.width : 0
  height: Style.space(22)

  Repeater {
    model: row.lamps

    Rectangle {
      id: win

      required property var modelData
      required property int index

      readonly property bool isLit: modelData.count > 0
      readonly property int litIndex: row.lit.indexOf(modelData.kind)
      readonly property color tone: modelData.tone === "high" ? row.hub.urgent : row.hub.warning
      readonly property bool hasCursor: isLit && row.hub.has("lamps", litIndex)
      readonly property bool on: isLit && row.hub.wdTicketLamp === modelData.kind

      x: index * ((row.width - 4 * row.gap) / 5 + row.gap)
      width: (row.width - 4 * row.gap) / 5
      height: row.height
      color: !isLit ? row.hub.well : (area.containsMouse ? Qt.lighter(tone, 1.08) : tone)
      border.width: 1
      border.color: isLit ? tone : row.hub.lineColor

      Text {
        anchors.centerIn: parent
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: win.isLit ? row.hub.strings.t("wd.lamp." + Model.lampKey(win.modelData.kind)) + " " + win.modelData.count : row.hub.strings.t("wd.lamp." + Model.lampKey(win.modelData.kind))
        color: win.isLit ? row.hub.cardColor : row.hub.muted
        font.family: row.hub.fontFamily
        font.pixelSize: Style.font.caption
        font.weight: Font.Bold
        font.letterSpacing: Style.spaceReal(0.8)
      }

      MouseArea {
        id: area
        anchors.fill: parent
        enabled: win.isLit
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onPositionChanged: function(mouse) { row.hub.hoverCursor(area, mouse, "lamps", win.litIndex) }
        onClicked: row.hub.wdOpenLamp(win.modelData.kind)
      }

      // The cursor's ring (grey for the keyboard, the accent for the pointer),
      // or the bright ring of the window whose call is open.
      Rectangle {
        visible: win.hasCursor || win.on
        x: -Style.space(3)
        y: -Style.space(3)
        width: win.width + Style.space(6)
        height: win.height + Style.space(6)
        color: "transparent"
        border.width: 2
        border.color: win.hasCursor ? (row.hub.cursorPointer ? row.hub.accent : Util.alpha(row.hub.fg, 0.7)) : row.hub.bright
      }
    }
  }
}

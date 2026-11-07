pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons

// A row that opens a view, in Sound Hub's "Bluetooth ›" pattern: the name on
// the left, its status dim and right-aligned (in a warning or urgent tone when
// something is wrong), a chevron on the content edge. Rests bare; the cursor
// or the pointer gives it the hover fill, a press shrinks it a little.
CursorSurface {
  id: row

  required property var hub
  property string name: ""
  property string cursorRow: ""
  property string value: ""
  // dim | warning | urgent
  property string tone: "dim"
  property string tipText: ""
  signal activated()

  width: parent ? parent.width : 0
  height: Style.space(40)
  hasCursor: hub.has(cursorRow)
  onHasCursorChanged: if (hasCursor) hub.ensureCursorVisible(row)
  foreground: hub.fg
  color: hasCursor ? hub.hoverFill : "transparent"
  scale: mouse.pressed ? hub.pressScale : 1
  Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

  Text {
    id: label
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: row.name
    color: row.hub.fg
    font.family: row.hub.fontFamily
    font.pixelSize: row.hub.typeBody
    anchors.left: parent.left
    anchors.leftMargin: row.hub.gutter
    anchors.verticalCenter: parent.verticalCenter
  }

  Text {
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: row.value
    color: row.tone === "urgent" ? row.hub.urgent : row.tone === "warning" ? row.hub.warning : row.hub.dim
    font.family: row.hub.fontFamily
    font.pixelSize: row.hub.typeSmall
    elide: Text.ElideRight
    horizontalAlignment: Text.AlignRight
    anchors.left: label.right
    anchors.leftMargin: Style.space(12)
    anchors.right: chevron.left
    anchors.rightMargin: Style.space(8)
    anchors.verticalCenter: parent.verticalCenter
  }

  Text {
    id: chevron
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: "\u{f0142}"
    color: row.hasCursor ? row.hub.fg : row.hub.dim
    font.family: row.hub.fontFamily
    font.pixelSize: row.hub.typeBody
    anchors.right: parent.right
    anchors.rightMargin: row.hub.gutter
    anchors.verticalCenter: parent.verticalCenter
  }

  MouseArea {
    id: mouse
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onPositionChanged: function(m) { row.hub.hoverCursor(mouse, m, row.cursorRow, 0) }
    onClicked: row.activated()
  }

  PanelToolTip {
    visible: mouse.containsMouse && row.tipText !== ""
    text: row.tipText
    fontFamily: row.hub.fontFamily
  }
}

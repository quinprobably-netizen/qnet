import QtQuick
import qs.Ui
import qs.Commons

// A word you can press: "Replace", "Cancel", "Pin all", "Admin ›", "Pause
// blocking 5m". Rests transparent (or on restFill with `filled`), takes the
// hover fill under the keyboard cursor or the pointer (the hub has one
// cursor, the mouse moves it) and shrinks to pressScale while pressed. A
// quiet one is dim and comes up to `hotColor` under the cursor or pointer.
// `cursorRow` and `cursorItem` name its stop in Model.focusRows; empty for a
// button the keyboard does not reach.
CursorSurface {
  id: btn

  required property var hub
  property string text: ""
  property color textColor: hub.fg
  property color hotColor: textColor
  property string cursorRow: ""
  property int cursorItem: 0
  property bool filled: false
  property int padX: Style.space(10)
  property int padY: Style.space(6)
  property int size: hub.typeSmall
  property int weight: Font.Normal
  property string tipText: ""
  signal clicked()

  implicitWidth: label.implicitWidth + padX * 2
  implicitHeight: label.implicitHeight + padY * 2

  hasCursor: cursorRow !== "" && hub.has(cursorRow, cursorItem)
  onHasCursorChanged: if (hasCursor) hub.ensureCursorVisible(btn)
  foreground: hub.fg
  fill: hub.hoverFill
  color: hasCursor ? hub.hoverFill : (filled ? hub.restFill : "transparent")
  opacity: enabled ? 1 : hub.disabledOpacity
  scale: area.pressed ? hub.pressScale : 1
  Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

  Text {
    id: label
    anchors.centerIn: parent
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: btn.text
    color: btn.hasCursor || area.containsMouse ? btn.hotColor : btn.textColor
    font.family: btn.hub.fontFamily
    font.pixelSize: btn.size
    font.weight: btn.weight
  }

  MouseArea {
    id: area
    anchors.fill: parent
    enabled: btn.enabled
    hoverEnabled: true
    cursorShape: Qt.PointingHandCursor
    onPositionChanged: function(mouse) {
      if (btn.cursorRow !== "") btn.hub.hoverCursor(area, mouse, btn.cursorRow, btn.cursorItem)
    }
    onClicked: btn.clicked()
  }

  PanelToolTip {
    visible: btn.tipText !== "" && (area.containsMouse || btn.hasCursor)
    text: btn.tipText
    fontFamily: btn.hub.fontFamily
  }
}

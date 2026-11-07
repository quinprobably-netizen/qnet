pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons

// The head of a drill-down view: a back button, the title, and, when there
// is one, a dim line under it. The back button is a cursor stop ("back"); its
// tooltip names the key. Esc and Backspace go back too (Panel.qml).
Item {
  id: vh

  required property var hub
  property string title: ""
  property string subtitle: ""

  width: parent ? parent.width : 0
  implicitHeight: Math.max(backBox.height, labels.implicitHeight) + Style.space(6)

  CursorSurface {
    id: backBox
    width: vh.hub.headerBackSize
    height: vh.hub.headerBackSize
    anchors.left: parent.left
    anchors.leftMargin: vh.hub.gutter
    anchors.verticalCenter: parent.verticalCenter
    hasCursor: vh.hub.has("back")
    onHasCursorChanged: if (hasCursor) vh.hub.ensureCursorVisible(backBox)
    foreground: vh.hub.fg
    color: hasCursor ? vh.hub.hoverFill : vh.hub.restFill
    scale: backMouse.pressed ? vh.hub.pressScale : 1
    Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

    Text {
      anchors.centerIn: parent
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: "\u{f004d}"
      color: vh.hub.fg
      font.family: vh.hub.fontFamily
      font.pixelSize: vh.hub.typeBody
    }

    MouseArea {
      id: backMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onPositionChanged: function(m) { vh.hub.hoverCursor(backMouse, m, "back", 0) }
      onClicked: vh.hub.goBack(true)
    }

    PanelToolTip {
      visible: backMouse.containsMouse
      text: vh.hub.strings.t("view.back")
      fontFamily: vh.hub.fontFamily
      x: 0
      y: backBox.height + Style.space(4)
    }
  }

  Column {
    id: labels
    anchors.left: backBox.right
    anchors.leftMargin: Style.space(12)
    anchors.right: parent.right
    anchors.rightMargin: vh.hub.gutter
    anchors.verticalCenter: parent.verticalCenter
    spacing: Style.space(1)

    Text {
      width: parent.width
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: vh.title
      color: vh.hub.fg
      font.family: vh.hub.fontFamily
      font.pixelSize: vh.hub.typeTitle
      font.weight: Font.DemiBold
      elide: Text.ElideRight
    }
    Text {
      visible: vh.subtitle !== ""
      width: parent.width
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: vh.subtitle
      color: vh.hub.dim
      font.family: vh.hub.fontFamily
      font.pixelSize: vh.hub.typeSmall
      elide: Text.ElideRight
    }
  }
}

import QtQuick
import qs.Ui
import qs.Commons

// "192.168.1.242 · gw 192.168.1.1", dim and small. A press copies the
// address. The placeholders ("--") keep the line the same width whatever the
// link is doing, so nothing under it moves.
CursorSurface {
  id: footer

  required property var hub

  width: parent ? parent.width : 0
  height: Style.space(30)
  hasCursor: hub.has("ip")
  onHasCursorChanged: if (hasCursor) hub.ensureCursorVisible(footer)
  foreground: hub.fg
  fill: hub.hoverFill
  scale: area.pressed && hub.footer.copyable ? hub.pressScale : 1
  Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

  Text {
    anchors.left: parent.left
    anchors.leftMargin: footer.hub.gutter
    anchors.verticalCenter: parent.verticalCenter
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: footer.hub.copied ? footer.hub.strings.t("footer.copied") : footer.hub.footer.text
    color: footer.hub.copied ? footer.hub.accent : (footer.hasCursor || area.containsMouse ? footer.hub.fg : footer.hub.dim)
    font.family: footer.hub.fontFamily
    font.pixelSize: footer.hub.typeSmall
  }

  MouseArea {
    id: area
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: footer.hub.footer.copyable ? Qt.PointingHandCursor : Qt.ArrowCursor
    onPositionChanged: function(mouse) { footer.hub.hoverCursor(area, mouse, "ip", 0) }
    onClicked: footer.hub.copyIp()
  }

  PanelToolTip {
    visible: area.containsMouse && footer.hub.footer.copyable
    text: footer.hub.strings.t("footer.copyTip")
    fontFamily: footer.hub.fontFamily
  }
}

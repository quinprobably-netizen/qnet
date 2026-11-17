import QtQuick
import qs.Commons
import qs.Commons as Commons

// The small icon button at the right edge of a row (22 px, its glyph in the
// panel's font); hover and cursor paint the same fill.
BorderSurface {
  id: root

  property string iconText: ""
  property string tooltipText: ""
  property color foreground: Commons.Color.foreground
  property color hoverColor: foreground
  property string fontFamily: Style.font.family
  property real fontSize: Style.font.icon
  property real size: Math.round(Math.max(Style.space(22), fontSize + Style.spacing.sm * 2)) | 1
  property bool focusable: false
  property bool hasCursor: false
  property bool bordered: false

  signal clicked()
  signal hovered(bool isHovered)

  implicitWidth: size
  implicitHeight: size
  radius: Style.cornerRadius

  readonly property bool _hot: (mouse.containsMouse || root.hasCursor) && root.enabled
  color: _hot ? Style.hoverFillFor(hoverColor, hoverColor) : "transparent"
  borderSpec: _hot && bordered ? Border.controlSpec("hover-cursor", hoverColor, hoverColor)
    : (bordered ? Border.controlSpec("normal", foreground, Commons.Color.accent) : Border.none())

  Text {
    textFormat: Text.PlainText
    x: Math.round((root.width - width) / 2)
    y: Math.round((root.height - height) / 2)
    text: root.iconText
    color: root.enabled ? (root._hot ? root.hoverColor : root.foreground) : Qt.darker(root.foreground, 2.0)
    font.family: root.fontFamily
    font.pixelSize: root.fontSize
  }

  MouseArea {
    id: mouse
    anchors.fill: parent
    hoverEnabled: true
    enabled: root.enabled
    onClicked: root.clicked()
  }
}

import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Commons as Commons

// The kit's text field: the Qt Quick Controls one with the shell's fill,
// border and padding; a password field masks with dots.
TextField {
  id: root

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property bool password: false
  property bool revealed: false
  property real horizontalPadding: Style.spacing.controlPaddingX
  property real verticalPadding: Style.spacing.inputPaddingY
  property bool hasCursor: false

  readonly property bool _hot: hovered || hasCursor
  readonly property var _borderSpec: Border.controlSpec(activeFocus ? "focus" : (_hot ? "hover-cursor" : "normal"), foreground, accent)
  readonly property bool _masked: password && !revealed

  echoMode: _masked ? TextInput.Password : TextInput.Normal
  passwordCharacter: "●"
  font.family: Style.font.family
  font.pixelSize: Style.font.body
  font.letterSpacing: _masked && text.length > 0 ? Math.round(font.pixelSize * 0.25) : 0
  color: foreground
  placeholderTextColor: Qt.darker(foreground, 1.6)

  leftPadding: horizontalPadding + Border.left(_borderSpec)
  rightPadding: horizontalPadding + Border.right(_borderSpec)
  topPadding: verticalPadding + Border.top(_borderSpec)
  bottomPadding: verticalPadding + Border.bottom(_borderSpec)

  background: BorderSurface {
    color: Style.controlFill(root.activeFocus, root._hot, root.foreground, root.accent)
    borderSpec: root._borderSpec
    radius: Style.cornerRadius
  }
}

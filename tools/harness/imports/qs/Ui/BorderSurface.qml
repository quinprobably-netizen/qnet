import QtQuick
import qs.Commons

// A Rectangle with a border spec ({ color, width }, see Border.qml) and the
// padding the shell's has; the content insets are border + padding.
Rectangle {
  id: root

  property var borderSpec: Border.none()
  property real padding: 0
  property real topPadding: padding
  property real rightPadding: padding
  property real bottomPadding: padding
  property real leftPadding: padding

  readonly property real contentTopInset: Border.top(borderSpec) + topPadding
  readonly property real contentRightInset: Border.right(borderSpec) + rightPadding
  readonly property real contentBottomInset: Border.bottom(borderSpec) + bottomPadding
  readonly property real contentLeftInset: Border.left(borderSpec) + leftPadding

  border.color: borderSpec.color
  border.width: borderSpec.width
}

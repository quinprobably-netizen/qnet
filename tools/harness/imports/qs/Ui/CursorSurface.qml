import QtQuick
import qs.Commons
import qs.Commons as Commons

// The chrome of a cursor target: the hover fill and border while it has the
// cursor, the selected fill while current, nothing otherwise.
BorderSurface {
  id: root

  property bool hasCursor: false
  property bool current: false
  property bool outline: false
  property bool bordered: false

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color fill: Style.hoverFillFor(foreground, accent)
  property color currentFill: Style.selectedFillFor(foreground, accent)

  radius: Style.cornerRadius
  color: hasCursor ? fill : (current ? currentFill : "transparent")
  borderSpec: hasCursor ? Border.controlSpec("hover-cursor", foreground, accent)
    : (current ? Border.controlSpec("selected", foreground, accent)
      : (bordered ? Border.controlSpec("normal", foreground, accent) : Border.none()))
}

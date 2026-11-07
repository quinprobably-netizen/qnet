import QtQuick
import qs.Commons

// One hairline across the content column, with a little air round it.
Item {
  id: rule

  required property var hub
  property int above: Style.space(6)
  property int below: Style.space(6)

  width: parent ? parent.width : 0
  height: above + 1 + below

  Rectangle {
    x: rule.hub.gutter
    y: rule.above
    width: rule.width - 2 * rule.hub.gutter
    height: 1
    color: rule.hub.lineColor
  }
}

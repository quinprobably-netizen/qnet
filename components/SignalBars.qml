pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import qs.Commons as Commons

// Four bars, as many lit as the signal has steps (Model.signalBars): the
// nearby list's signal glyph. (The fan is for the connection in use.)
Item {
  id: bars

  property int level: 0
  property color lit: Commons.Color.foreground
  property color unlit: Qt.rgba(1, 1, 1, 0.2)
  readonly property real barW: Style.space(3)
  readonly property real gap: Style.space(2)
  readonly property real maxH: Style.space(14)

  width: 4 * barW + 3 * gap
  height: maxH

  Repeater {
    model: 4

    Rectangle {
      required property int index
      width: bars.barW
      height: bars.maxH * (0.36 + index * 0.21)
      x: index * (bars.barW + bars.gap)
      y: bars.maxH - height
      radius: 1
      color: index < bars.level ? bars.lit : bars.unlit
    }
  }
}

import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons

// The card a ticket is written on, under the calls waiting: a well with a
// line round it and a dashed top edge, as a ticket torn off a pad. It takes
// the ticket's content (a Column of its own) with 14 at the sides, 10 above
// and 14 below, and 8 of air over the whole of it.
Item {
  id: frame

  required property var hub
  default property alias content: body.data

  readonly property real airAbove: Style.space(8)
  readonly property real sideGap: Style.space(14)

  implicitHeight: airAbove + Style.space(10) + body.implicitHeight + Style.space(14)

  Rectangle {
    id: card
    y: frame.airAbove
    width: frame.width
    height: frame.height - frame.airAbove
    color: frame.hub.well
  }

  // the line round the other three sides (the top has its own, below)
  Rectangle { x: 0; y: frame.airAbove; width: 1; height: card.height; color: frame.hub.lineColor }
  Rectangle { x: frame.width - 1; y: frame.airAbove; width: 1; height: card.height; color: frame.hub.lineColor }
  Rectangle { x: 0; y: frame.height - 1; width: frame.width; height: 1; color: frame.hub.lineColor }

  // The top edge is dashed and dim.
  Shape {
    x: 0
    y: frame.airAbove
    width: frame.width
    height: 1
    preferredRendererType: Shape.CurveRenderer
    ShapePath {
      strokeColor: frame.hub.dim
      strokeWidth: 1
      strokeStyle: ShapePath.DashLine
      dashPattern: [3, 3]
      fillColor: "transparent"
      startX: 0
      startY: 0.5
      PathLine { x: frame.width; y: 0.5 }
    }
  }

  Column {
    id: body
    x: frame.sideGap
    y: frame.airAbove + Style.space(10)
    width: frame.width - 2 * frame.sideGap
    spacing: 0
  }
}

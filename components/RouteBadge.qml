import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons
import qs.Commons as Commons

// A node of the route: a ring round a glyph, filled to hide the tube behind
// it. The same badge is the hero's (30 px) and the DNS chain's (24 px).
//
//   tone       the ring and glyph colour; `quiet` softens the ring (a dim node)
//   ghost      a dashed accent ring and a plus: where something could be set up
//   cursor     a ring round the badge: the keyboard cursor (grey) or the
//              pointer (the accent); transparent for none
//   badgeText  the small count on its corner ("2"), in badgeColor, or ""
Item {
  id: badge

  property real size: Style.space(30)
  property string glyph: ""
  property color tone: Commons.Color.foreground
  property bool quiet: false
  property bool ghost: false
  property color accent: Commons.Color.accent
  property color fill: Qt.rgba(Commons.Color.popups.background.r, Commons.Color.popups.background.g, Commons.Color.popups.background.b, 0.92)
  property color ringColor: "transparent"
  property string fontFamily: Style.font.family
  property real glyphSize: Style.space(15)
  property string badgeText: ""
  property color badgeColor: "#e8a950"

  width: size
  height: size

  Rectangle {
    anchors.fill: parent
    radius: width / 2
    color: badge.fill
  }
  Rectangle {
    anchors.fill: parent
    radius: width / 2
    visible: !badge.ghost
    color: Util.alpha(badge.tone, 0.14)
    border.width: 1.5
    border.color: Util.alpha(badge.tone, badge.quiet ? 0.55 : 0.95)
  }
  Shape {
    visible: badge.ghost
    anchors.fill: parent
    preferredRendererType: Shape.CurveRenderer
    ShapePath {
      strokeColor: Util.alpha(badge.accent, 0.8)
      strokeWidth: 1.5
      fillColor: "transparent"
      strokeStyle: ShapePath.DashLine
      dashPattern: [2.5, 2.5]
      PathAngleArc { centerX: badge.width / 2; centerY: badge.height / 2; radiusX: badge.width / 2 - 1; radiusY: badge.height / 2 - 1; startAngle: 0; sweepAngle: 360 }
    }
  }
  Text {
    anchors.centerIn: parent
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: badge.glyph
    color: badge.ghost ? badge.accent : badge.tone
    font.family: badge.fontFamily
    font.pixelSize: badge.glyphSize
  }

  // the cursor's ring, just outside
  Rectangle {
    visible: badge.ringColor.a > 0
    x: -Style.space(3)
    y: -Style.space(3)
    width: badge.width + Style.space(6)
    height: badge.height + Style.space(6)
    radius: width / 2
    color: "transparent"
    border.width: 2
    border.color: badge.ringColor
  }

  // the count on its corner
  Rectangle {
    visible: badge.badgeText !== ""
    x: badge.width - width * 0.62
    y: -height * 0.38
    width: Math.max(height, countLabel.implicitWidth + Style.space(7))
    height: Style.space(15)
    radius: height / 2
    color: badge.badgeColor
    Text {
      id: countLabel
      anchors.centerIn: parent
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: badge.badgeText
      color: Qt.rgba(0.07, 0.07, 0.08, 1)
      font.family: badge.fontFamily
      font.pixelSize: Style.space(10)
      font.weight: Font.Bold
    }
  }
}

import QtQuick
import qs.Ui
import qs.Commons

// The Wi-Fi switch: a track that is the accent at about a third when on and a
// faint fill when off, an accent knob when on, sliding across it. Disabled
// (dim, no answer to a press) while a change is pending. The track ends exactly where its box
// does, so it sits on the panel's right gutter like everything else; the
// cursor's fill is drawn out past the box and takes no room.
Item {
  id: sw

  required property var hub
  property bool checked: false
  property bool hasCursor: false
  property string tipText: ""
  signal toggled()
  signal hovered(bool on)

  readonly property bool rounded: Style.cornerRadius > 0
  readonly property int trackW: Style.space(38)
  readonly property int trackH: Style.space(20)
  readonly property int knob: trackH - Style.space(6)

  implicitWidth: trackW
  implicitHeight: trackH
  opacity: enabled ? 1 : hub.disabledOpacity

  Rectangle {
    anchors.fill: parent
    anchors.margins: -Style.space(5)
    radius: sw.rounded ? (sw.trackH + Style.space(10)) / 2 : 0
    color: sw.hub.hoverFill
    visible: sw.enabled && (sw.hasCursor || area.containsMouse)
  }

  Rectangle {
    id: track
    anchors.fill: parent
    radius: sw.rounded ? height / 2 : 0
    color: sw.checked ? Qt.rgba(sw.hub.accent.r, sw.hub.accent.g, sw.hub.accent.b, 0.3) : Qt.rgba(sw.hub.fg.r, sw.hub.fg.g, sw.hub.fg.b, 0.16)
    Behavior on color { enabled: sw.hub.settled; ColorAnimation { duration: Style.duration(120) } }

    Rectangle {
      width: sw.knob
      height: sw.knob
      radius: sw.rounded ? height / 2 : 0
      anchors.verticalCenter: parent.verticalCenter
      x: sw.checked !== LayoutMirroring.enabled ? track.width - width - Style.space(3) : Style.space(3)
      color: sw.checked ? sw.hub.accent : Qt.rgba(sw.hub.fg.r, sw.hub.fg.g, sw.hub.fg.b, 0.75)
      Behavior on x { enabled: sw.hub.settled; NumberAnimation { duration: Style.duration(120); easing.type: Easing.OutCubic } }
    }
  }

  MouseArea {
    id: area
    anchors.fill: parent
    anchors.margins: -Style.space(5)
    hoverEnabled: true
    enabled: sw.enabled
    cursorShape: Qt.PointingHandCursor
    onContainsMouseChanged: sw.hovered(containsMouse)
    onClicked: sw.toggled()
  }

  PanelToolTip {
    visible: area.containsMouse && sw.tipText !== ""
    text: sw.tipText
    fontFamily: sw.hub.fontFamily
  }
}

pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons

// What would send queries around the Pi-hole, as at most two lines.
//
//  - Urgent, only when this link itself can skip it (dns.bypassed): "Queries
//    on this link can bypass Pi-hole" with the way (the active link's leak,
//    if there is one) dim after it, and Pin, which applies the Pi-hole to
//    the link in use. The hero says "Bypassed" with it.
//  - Warning, for saved profiles that are not in use and would bypass it
//    when they are: ONE line however many ("2 saved profiles would bypass
//    Pi-hole"), with Pin all (one `qnet dns pin u1 u2`). Which profiles and
//    how are in its tooltip.
// resolved's compiled-in FallbackDNS is not a leak while links have servers.
Column {
  id: leaks

  required property var hub
  readonly property var bypass: hub.leaks.bypass
  readonly property var profiles: hub.leaks.profiles

  width: parent ? parent.width : 0

  // ------------------------------------------------------- this link
  Item {
    id: bypassLine
    visible: leaks.bypass !== null
    width: leaks.width
    height: Style.space(30)

    Row {
      anchors.left: parent.left
      anchors.leftMargin: leaks.hub.gutter
      anchors.right: pin.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      id: bypassWords

      Text {
        id: bypassHead
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: leaks.hub.strings.t("leak.bypass")
        color: leaks.hub.urgent
        font.family: leaks.hub.fontFamily
        font.pixelSize: leaks.hub.typeSmall
        elide: Text.ElideRight
        width: Math.min(implicitWidth, bypassWords.width)
      }
      Text {
        visible: leaks.bypass !== null && leaks.bypass.details.length > 0 && bypassWords.width - bypassHead.width > Style.space(60)
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: leaks.bypass !== null && leaks.bypass.details.length > 0 ? " · " + leaks.bypass.details[0] : ""
        color: Util.alpha(leaks.hub.urgent, 0.7)
        font.family: leaks.hub.fontFamily
        font.pixelSize: leaks.hub.typeSmall
        elide: Text.ElideRight
        width: Math.max(0, Math.min(implicitWidth, bypassWords.width - bypassHead.width))
      }
    }

    TextButton {
      id: pin
      hub: leaks.hub
      anchors.right: parent.right
      anchors.rightMargin: leaks.hub.gutter - padX
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: leaks.hub.strings.t("leak.pin")
      textColor: leaks.hub.urgent
      weight: Font.DemiBold
      cursorRow: "bypass"
      cursorItem: 0
      onClicked: leaks.hub.fixBypass()
    }

    MouseArea {
      id: bypassTip
      anchors.fill: parent
      anchors.rightMargin: pin.width + leaks.hub.gutter
      hoverEnabled: true
      acceptedButtons: Qt.NoButton
      PanelToolTip {
        visible: bypassTip.containsMouse && leaks.bypass !== null && leaks.bypass.details.length > 0
        text: leaks.bypass !== null ? leaks.bypass.details.join("\n") : ""
        fontFamily: leaks.hub.fontFamily
      }
    }
  }

  // ---------------------------------------------- profiles not in use
  Item {
    id: profileLine
    visible: leaks.profiles !== null
    width: leaks.width
    height: Style.space(30)

    Text {
      id: profileText
      anchors.left: parent.left
      anchors.leftMargin: leaks.hub.gutter
      anchors.right: pinAll.visible ? pinAll.left : parent.right
      anchors.rightMargin: pinAll.visible ? Style.space(8) : leaks.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: leaks.profiles !== null ? leaks.hub.strings.tn("leak.profiles", leaks.profiles.count).arg(leaks.profiles.count) : ""
      color: leaks.hub.warning
      font.family: leaks.hub.fontFamily
      font.pixelSize: leaks.hub.typeSmall
      elide: Text.ElideRight
    }

    TextButton {
      id: pinAll
      visible: leaks.profiles !== null && leaks.profiles.pinnable
      hub: leaks.hub
      anchors.right: parent.right
      anchors.rightMargin: leaks.hub.gutter - padX
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: leaks.profiles !== null && leaks.profiles.uuids.length > 1 ? leaks.hub.strings.t("leak.pinAll") : leaks.hub.strings.t("leak.pin")
      textColor: leaks.hub.warning
      weight: Font.DemiBold
      cursorRow: "profiles"
      cursorItem: 0
      onClicked: leaks.hub.pinAll()
    }

    MouseArea {
      id: profileTip
      anchors.fill: parent
      anchors.rightMargin: pinAll.visible ? pinAll.width + leaks.hub.gutter : 0
      hoverEnabled: true
      acceptedButtons: Qt.NoButton
      PanelToolTip {
        visible: profileTip.containsMouse && leaks.profiles !== null
        text: leaks.profiles !== null ? leaks.profiles.lines.join("\n") : ""
        fontFamily: leaks.hub.fontFamily
      }
    }
  }
}

pragma ComponentBehavior: Bound
import QtQuick
import qs.Commons

// The DNS view: which resolver is in use (the tiles, lit by what systemd-
// resolved reports, never by what was last asked for), what bypasses the
// Pi-hole and the way to pin it, a link to the Pi-hole's admin page, and the
// failover's state with its reason.
Column {
  id: view

  required property var hub

  width: parent ? parent.width : 0
  spacing: 0

  ViewHeader {
    hub: view.hub
    title: view.hub.strings.t("view.dns")
    subtitle: view.hub.dnsSubtitle
  }

  DnsTiles { hub: view.hub }
  LeakList { hub: view.hub }

  SectionHead {
    hub: view.hub
    text: view.hub.strings.t("dns.status")
  }

  // One line: a name dim on the left, its value on the right.
  component InfoRow: Item {
    id: info
    property string name: ""
    property string value: ""
    property color valueColor: view.hub.fg
    visible: value !== ""
    width: view.width
    height: Style.space(28)

    Text {
      id: infoName
      anchors.left: parent.left
      anchors.leftMargin: view.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: info.name
      color: view.hub.dim
      font.family: view.hub.fontFamily
      font.pixelSize: view.hub.typeSmall
    }
    Text {
      anchors.left: infoName.right
      anchors.leftMargin: Style.space(12)
      anchors.right: parent.right
      anchors.rightMargin: view.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      horizontalAlignment: Text.AlignRight
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: info.value
      color: info.valueColor
      font.family: view.hub.fontFamily
      font.pixelSize: view.hub.typeSmall
      elide: Text.ElideRight
    }
  }

  InfoRow {
    name: view.hub.strings.t("failover.title")
    value: view.hub.failoverText
    valueColor: view.hub.failoverActive ? view.hub.warning : view.hub.fg
  }
  InfoRow {
    name: view.hub.strings.t("failover.reason")
    value: view.hub.view.dns.failover.reason
    valueColor: view.hub.dim
  }
  InfoRow {
    name: view.hub.strings.t("dns.health")
    value: view.hub.view.pihole.healthReason
    valueColor: view.hub.view.pihole.health === "degraded" ? view.hub.warning : view.hub.dim
  }

  Item {
    visible: view.hub.view.pihole.configured && view.hub.view.pihole.adminUrl !== ""
    width: view.width
    height: Style.space(34)
    TextButton {
      hub: view.hub
      x: view.hub.gutter - padX
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(5)
      text: view.hub.strings.t("dns.admin") + " ›"
      textColor: view.hub.dim
      hotColor: view.hub.fg
      cursorRow: "admin"
      cursorItem: 0
      onClicked: view.hub.openAdmin()
    }
  }
}

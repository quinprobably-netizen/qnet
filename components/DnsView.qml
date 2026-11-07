pragma ComponentBehavior: Bound
import QtQuick
import qs.Commons

// The DNS view: the resolver chain on top (this PC, systemd-resolved, the
// Pi-hole, the resolvers it forwards to), the resolver choices as a list
// (lit by what systemd-resolved reports, never by what was last asked for),
// what bypasses the Pi-hole and the way to pin it, the failover's state with
// its reason, and a quiet link to the Pi-hole's admin page.
Column {
  id: page

  required property var hub

  width: parent ? parent.width : 0
  spacing: 0

  ViewHeader {
    hub: page.hub
    title: page.hub.strings.t("view.dns")
  }

  ResolverChain {
    width: page.width
    view: page.hub.view
    nowS: page.hub.nowMs / 1000
    frozen: page.hub.hero.desaturated
    animate: page.hub.opened
    accent: page.hub.accent
    fg: page.hub.fg
    dim: page.hub.dim
    urgent: page.hub.urgent
    warning: page.hub.warning
    fontFamily: page.hub.fontFamily
    fontSize: page.hub.typeSmall
    tr: page.hub.strings.t
    formatInt: page.hub.formatInt
    gutter: page.hub.gutter
  }

  ResolverChoices { hub: page.hub }
  LeakList { hub: page.hub }

  // The failover is the Pi-hole's: nothing to say without one.
  readonly property bool hasPihole: hub.view.pihole.configured

  SectionHead {
    visible: page.hasPihole
    hub: page.hub
    text: page.hub.strings.t("failover.title")
  }

  // One line: a name dim on the left, its value on the right.
  component InfoRow: Item {
    id: info
    property string name: ""
    property string value: ""
    property color valueColor: page.hub.fg
    visible: value !== "" && page.hasPihole
    width: page.width
    height: Style.space(28)

    Text {
      id: infoName
      anchors.left: parent.left
      anchors.leftMargin: page.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: info.name
      color: page.hub.dim
      font.family: page.hub.fontFamily
      font.pixelSize: page.hub.typeSmall
    }
    Text {
      anchors.left: infoName.right
      anchors.leftMargin: Style.space(12)
      anchors.right: parent.right
      anchors.rightMargin: page.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      horizontalAlignment: Text.AlignRight
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: info.value
      color: info.valueColor
      font.family: page.hub.fontFamily
      font.pixelSize: page.hub.typeSmall
      elide: Text.ElideRight
    }
  }

  InfoRow {
    name: page.hub.strings.t("failover.state")
    value: page.hub.failoverText
    valueColor: page.hub.failoverActive ? page.hub.warning : page.hub.fg
  }
  InfoRow {
    name: page.hub.strings.t("failover.reason")
    value: page.hub.view.dns.failover.reason
    valueColor: page.hub.dim
  }

  Item {
    visible: page.hub.view.pihole.configured && page.hub.view.pihole.adminUrl !== ""
    width: page.width
    height: Style.space(38)
    TextButton {
      hub: page.hub
      x: page.hub.gutter - padX
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(5)
      text: page.hub.strings.t("dns.admin") + " ›"
      textColor: page.hub.dim
      hotColor: page.hub.fg
      cursorRow: "admin"
      cursorItem: 0
      onClicked: page.hub.openAdmin()
    }
  }
}

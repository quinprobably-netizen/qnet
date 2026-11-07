pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons

// The DNS row: two segmented tiles, Pi-hole and Automatic, alone in their row.
// (Pause and Admin are in the hero.) The lit tile is the resolver in use, read from
// systemd-resolved: a runtime failover lights Pi-hole in the warning colour
// as "Pi-hole (fallback)", and custom servers light nothing and show a
// "Custom: 9.9.9.9" caption. Tapping the lit tile does nothing.
// Under the row, when there is something to say: the confirm line (replacing
// DNS the user set by hand), an error, or a note that the Pi-hole did not
// confirm blocking when it was switched to.
Column {
  id: dns

  required property var hub
  readonly property var tiles: hub.tiles
  readonly property var chip: hub.chip

  width: parent ? parent.width : 0
  topPadding: Style.space(4)
  spacing: Style.space(6)

  // ---------------------------------------------------------- tile row
  // The tiles, alone in their row, across the content column.
  Item {
    id: bar
    width: dns.width
    height: Style.space(36)

    Row {
      id: tileRow
      x: dns.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(4)
      readonly property real tileW: Math.floor((bar.width - 2 * dns.hub.gutter - spacing) / 2)

      Repeater {
        model: 2

        CursorSurface {
          id: tile
          required property int index
          readonly property string name: index === 0 ? "pihole" : "auto"
          // "on" | "warn" | "off"
          readonly property string lit: index === 0 ? dns.tiles.pihole : dns.tiles.auto
          readonly property color litColor: lit === "warn" ? dns.hub.warning : dns.hub.accent

          width: tileRow.tileW
          height: Style.space(36)
          hasCursor: dns.hub.has("dns", index)
          onHasCursorChanged: if (hasCursor) dns.hub.ensureCursorVisible(tile)
          foreground: dns.hub.fg
          color: lit !== "off"
            ? Qt.rgba(litColor.r, litColor.g, litColor.b, hasCursor ? 0.26 : 0.18)
            : (hasCursor ? dns.hub.hoverFill : dns.hub.restFill)
          scale: area.pressed ? dns.hub.pressScale : 1
          Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }
          Behavior on color { enabled: dns.hub.settled; ColorAnimation { duration: Style.duration(120) } }

          Text {
            anchors.centerIn: parent
            width: Math.min(implicitWidth, tile.width - Style.space(12))
            horizontalAlignment: Text.AlignHCenter
            elide: Text.ElideRight
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
            text: tile.index === 0
              ? (dns.tiles.fallbackLabel ? dns.hub.strings.t("dns.piholeFallback") : dns.hub.strings.t("dns.pihole"))
              : dns.hub.strings.t("dns.auto")
            color: tile.lit === "off" ? dns.hub.dim : tile.litColor
            font.family: dns.hub.fontFamily
            font.pixelSize: dns.hub.typeBody
          }

          MouseArea {
            id: area
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: tile.lit === "off" ? Qt.PointingHandCursor : Qt.ArrowCursor
            onPositionChanged: function(mouse) { dns.hub.hoverCursor(area, mouse, "dns", tile.index) }
            onClicked: dns.hub.tapTile(tile.name)
          }
        }
      }
    }
  }

  // ------------------------------------------------------ lines below
  Text {
    visible: dns.tiles.custom !== null && !dns.hub.confirm.open
    x: dns.hub.gutter
    width: dns.width - 2 * dns.hub.gutter
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: dns.tiles.custom ? dns.hub.strings.t("dns.custom").arg(dns.tiles.custom.join(", ")) : ""
    color: dns.hub.dim
    font.family: dns.hub.fontFamily
    font.pixelSize: dns.hub.typeSmall
    elide: Text.ElideRight
  }

  Item {
    visible: dns.hub.confirm.open
    width: dns.width
    height: Style.space(32)

    Text {
      id: confirmText
      anchors.left: parent.left
      anchors.leftMargin: dns.hub.gutter
      anchors.right: replace.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: dns.hub.strings.t("dns.replaceQ").arg(dns.hub.confirm.servers)
      color: dns.hub.fg
      font.family: dns.hub.fontFamily
      font.pixelSize: dns.hub.typeSmall
      elide: Text.ElideRight
    }

    TextButton {
      id: replace
      hub: dns.hub
      anchors.right: cancel.left
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: dns.hub.strings.t("dns.replace")
      textColor: dns.hub.urgent
      weight: Font.DemiBold
      cursorRow: "confirm"
      cursorItem: 0
      onClicked: dns.hub.confirmReplace()
    }

    TextButton {
      id: cancel
      hub: dns.hub
      anchors.right: parent.right
      anchors.rightMargin: dns.hub.gutter - padX + Style.space(4)
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: dns.hub.strings.t("dns.cancel")
      textColor: dns.hub.dim
      cursorRow: "confirm"
      cursorItem: 1
      onClicked: dns.hub.confirmCancel()
    }
  }

  Text {
    visible: dns.hub.dnsNote.text !== ""
    x: dns.hub.gutter
    width: dns.width - 2 * dns.hub.gutter
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    wrapMode: Text.Wrap
    text: dns.hub.dnsNote.text
    color: dns.hub.dnsNote.tone === "warning" ? dns.hub.warning : dns.hub.urgent
    font.family: dns.hub.fontFamily
    font.pixelSize: dns.hub.typeSmall
  }
}

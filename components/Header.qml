pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons

// The connection: its glyph and name, one status line under it, and on the
// right the QR share and speed-test buttons and, after a clear gap, the Wi-Fi
// switch. The status line reads "Connected · 5 GHz · 61% · 122 Mb/s · gw
// 4 ms" (the gateway's latency only while the panel measures it); when the
// link is limited or behind a portal its first word is urgent, and "Sign in
// required ›" is a button that opens the portal.
//
// This is also the connected network's row: a secondary click on it, or
// Delete or Enter with the cursor on it, drops the Wi-Fi link (its tooltip
// says so). Everything that sits on the right edge ends on the panel's one
// right gutter, the switch included.
Item {
  id: header

  required property var hub
  readonly property var info: hub.header
  readonly property var items: hub.headerItems
  readonly property int connIndex: items.indexOf("conn")

  width: parent ? parent.width : 0
  implicitHeight: Math.max(labels.implicitHeight, actions.implicitHeight, glyph.implicitHeight) + Style.space(6)

  function stateText(key) {
    return hub.strings.t("header.state." + key)
  }

  readonly property string titleText: {
    if (info.title !== "") return info.title
    if (info.kind === "ethernet") return hub.strings.t("header.ethernet")
    if (info.kind === "off") return hub.strings.t("header.wifiOff")
    if (info.kind === "offline") return hub.strings.t("header.offline")
    if (info.kind === "nobackend") return hub.strings.t("header.network")
    return hub.strings.t("header.wifi")
  }

  readonly property color glyphColor: info.kind === "nobackend" || info.restricted ? hub.urgent
    : (info.kind === "wifi" || info.kind === "ethernet") ? hub.accent : hub.dim

  // The connection as a row: the cursor's stop and the secondary click.
  CursorSurface {
    id: connBox
    visible: header.info.disconnectable
    x: header.hub.gutter - Style.space(8)
    width: labels.x + labels.width - x + Style.space(4)
    height: parent.height
    hasCursor: header.connIndex >= 0 && header.hub.has("header", header.connIndex)
    foreground: header.hub.fg
    fill: header.hub.hoverFill
    scale: connMouse.pressed && connMouse.pressedButtons === Qt.RightButton ? header.hub.pressScale : 1
    Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

    MouseArea {
      id: connMouse
      anchors.fill: parent
      enabled: header.info.disconnectable
      hoverEnabled: true
      acceptedButtons: Qt.RightButton
      onPositionChanged: function(mouse) { header.hub.hoverCursor(connMouse, mouse, "header", header.connIndex) }
      onClicked: header.hub.disconnectNet()
    }

    PanelToolTip {
      visible: (connMouse.containsMouse || connBox.hasCursor) && header.info.disconnectable
      text: header.hub.strings.t("header.disconnectTip")
      fontFamily: header.hub.fontFamily
    }
  }

  Text {
    id: glyph
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: header.info.glyph
    color: header.glyphColor
    font.family: header.hub.fontFamily
    font.pixelSize: header.hub.typeTitle + Style.space(6)
    anchors.left: parent.left
    anchors.leftMargin: header.hub.gutter
    anchors.verticalCenter: parent.verticalCenter
  }

  Column {
    id: labels
    anchors.left: glyph.right
    anchors.leftMargin: Style.space(12)
    anchors.right: actions.left
    anchors.rightMargin: Style.space(10)
    anchors.verticalCenter: parent.verticalCenter

    Text {
      width: parent.width
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: header.titleText
      color: header.hub.fg
      font.family: header.hub.fontFamily
      font.pixelSize: header.hub.typeTitle
      font.weight: Font.DemiBold
      elide: Text.ElideRight
    }

    Row {
      id: statusRow
      width: parent.width

      // The first part: the connection's state. Behind a portal it is a
      // button, its box reaching a little past the words.
      Item {
        id: firstPart
        implicitWidth: stateLabel.implicitWidth
        implicitHeight: stateLabel.implicitHeight
        width: implicitWidth
        height: implicitHeight

        CursorSurface {
          visible: header.info.portal
          anchors.fill: parent
          anchors.margins: -Style.space(5)
          hasCursor: header.info.portal && header.hub.has("header", header.items.indexOf("portal"))
          foreground: header.hub.fg
          fill: header.hub.hoverFill
          scale: portalMouse.pressed ? header.hub.pressScale : 1
          Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }
        }

        Text {
          id: stateLabel
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: {
            if (header.info.status.length === 0) return ""
            var word = header.stateText(header.info.status[0].key)
            return header.info.portal ? word + " ›" : word
          }
          color: header.info.urgent ? header.hub.urgent : header.hub.dim
          font.family: header.hub.fontFamily
          font.pixelSize: header.hub.typeSmall
        }

        MouseArea {
          id: portalMouse
          enabled: header.info.portal
          anchors.fill: parent
          anchors.margins: -Style.space(5)
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onPositionChanged: function(mouse) {
            header.hub.hoverCursor(portalMouse, mouse, "header", header.items.indexOf("portal"))
          }
          onClicked: header.hub.openPortal()
        }
      }

      Repeater {
        model: header.info.status.length > 1 ? header.info.status.slice(1) : []
        Text {
          id: extra
          required property var modelData
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: " · " + extra.modelData.text
          color: header.hub.dim
          font.family: header.hub.fontFamily
          font.pixelSize: header.hub.typeSmall
        }
      }
    }
  }

  Row {
    id: actions
    spacing: Style.space(6)
    anchors.right: parent.right
    anchors.rightMargin: header.hub.gutter
    anchors.verticalCenter: parent.verticalCenter

    PanelActionButton {
      visible: header.items.indexOf("qr") >= 0
      anchors.verticalCenter: parent.verticalCenter
      iconText: header.hub.glyphs.qr
      tooltipText: header.hub.strings.t("header.qr")
      foreground: header.hub.fg
      fontFamily: header.hub.fontFamily
      fontSize: Style.font.subtitle * 1.5
      hasCursor: header.hub.has("header", header.items.indexOf("qr"))
      onHovered: function(on) { if (on) header.hub.setCursor("header", header.items.indexOf("qr")) }
      onClicked: header.hub.summonQr()
    }

    PanelActionButton {
      visible: header.items.indexOf("speed") >= 0
      anchors.verticalCenter: parent.verticalCenter
      iconText: header.hub.glyphs.speed
      tooltipText: header.hub.strings.t("header.speed")
      foreground: header.hub.fg
      fontFamily: header.hub.fontFamily
      fontSize: Style.font.subtitle * 1.5
      hasCursor: header.hub.has("header", header.items.indexOf("speed"))
      onHovered: function(on) { if (on) header.hub.setCursor("header", header.items.indexOf("speed")) }
      onClicked: header.hub.summonSpeed()
    }

    // A clear gap before the one switch.
    Item { width: Style.space(10); height: 1 }

    Switch {
      anchors.verticalCenter: parent.verticalCenter
      hub: header.hub
      checked: header.hub.view.radio.wifiEnabled
      enabled: header.hub.view.radio.hwEnabled
      hasCursor: header.hub.has("header", header.items.indexOf("radio"))
      tipText: checked ? header.hub.strings.t("header.wifiOffTip") : header.hub.strings.t("header.wifiOnTip")
      onHovered: function(on) { if (on) header.hub.setCursor("header", header.items.indexOf("radio")) }
      onToggled: header.hub.toggleRadio()
    }
  }
}

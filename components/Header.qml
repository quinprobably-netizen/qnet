pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons

// The connection: its glyph and name, one line under it, and on the right the
// QR share and speed-test buttons and, after a clear gap, the Wi-Fi switch.
// The line under the name is what is worth saying about the link: "5 GHz ·
// 58%" ("Connected" is left out while all is well, and the gateway's latency
// appears only when it is slow); when the link is limited or behind a portal
// its first word is urgent, and "Sign in required ›" is a button that opens
// the portal. The line is elided at its end, so it never runs under the
// buttons. Everything on the right ends on the panel's one right gutter, the
// switch included; the switch is dim and still while a change is pending.
Item {
  id: header

  required property var hub
  readonly property var info: hub.header
  readonly property var items: hub.headerItems

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

  // The state word leads the line only when there is one to say.
  readonly property bool hasState: info.status.length > 0 && info.status[0].k === "state"
  // The rest, one string, so one elision covers it.
  readonly property string tailText: {
    var parts = []
    for (var i = hasState ? 1 : 0; i < info.status.length; i++) parts.push(info.status[i].text)
    if (parts.length === 0) return ""
    return (hasState ? " · " : "") + parts.join(" · ")
  }

  readonly property color glyphColor: info.kind === "nobackend" || info.restricted ? hub.urgent
    : (info.kind === "wifi" || info.kind === "ethernet") ? hub.accent : hub.dim

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

      // The state word, when there is one. Behind a portal it is a button,
      // its box reaching a little past the words.
      Item {
        id: firstPart
        visible: header.hasState
        implicitWidth: header.hasState ? stateLabel.implicitWidth : 0
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
            if (!header.hasState) return ""
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

      Text {
        width: Math.max(0, statusRow.width - (header.hasState ? firstPart.width : 0))
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: header.tailText
        color: header.hub.dim
        font.family: header.hub.fontFamily
        font.pixelSize: header.hub.typeSmall
        elide: Text.ElideRight
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
      enabled: header.hub.view.radio.hwEnabled && header.hub.pending.radio === ""
      hasCursor: header.hub.has("header", header.items.indexOf("radio"))
      tipText: checked ? header.hub.strings.t("header.wifiOffTip") : header.hub.strings.t("header.wifiOnTip")
      onHovered: function(on) { if (on) header.hub.setCursor("header", header.items.indexOf("radio")) }
      onToggled: header.hub.toggleRadio()
    }
  }
}

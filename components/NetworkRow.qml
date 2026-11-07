import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// One network. A glyph for its signal (the one in use leads the list: its
// glyph and "Connected" are the accent, and "Disconnect" is on the row), its
// name, and on the right a dim caption: "Saved", "Open" (an unsaved open
// network is marked), "802.1X", or what is happening ("Connecting…", an error
// in urgent). There is no lock on the others.
//
//   press / Enter     saved or open: connect; secured and unknown: the
//                     passphrase row opens under this one; 802.1X that is not
//                     saved: nmtui in a terminal. On the one in use a press
//                     does nothing (Disconnect is its own button; Enter on it
//                     disconnects).
//   right-click / Delete   saved networks, the one in use included: Forget,
//                     asked again in place ("Forget  Cancel"; Enter forgets,
//                     Esc cancels)
//
// The passphrase row lives here, under its network, so it stays with that
// network if the list reorders. The text is cleared when it closes.
Item {
  id: row

  required property var hub
  required property var modelData
  required property int index

  readonly property var net: modelData
  readonly property bool pwOpen: hub.passwordFor === net.id
  readonly property bool armed: net.uuid !== "" && hub.armedUuid === net.uuid
  readonly property bool cursor: hub.has("net:" + index)
  readonly property var caption: Model.rowCaption(net, hub.captionContext)

  readonly property string captionText: {
    if (armed) return ""
    switch (caption.key) {
    case "": return ""
    case "text": return caption.text
    default: return hub.strings.t("net.caption." + caption.key)
    }
  }
  readonly property color captionColor: caption.tone === "accent" ? hub.accent
    : caption.tone === "urgent" ? hub.urgent : hub.dim

  width: parent ? parent.width : 0
  implicitHeight: surface.height + (pwOpen ? pw.height : 0)

  onPwOpenChanged: {
    if (pwOpen) {
      field.text = ""
      Qt.callLater(function() { if (row.pwOpen) field.forceActiveFocus() })
    } else {
      // The passphrase leaves with the row.
      field.text = ""
    }
  }

  CursorSurface {
    id: surface
    width: row.width
    height: Style.space(36)
    property bool hover: false
    hasCursor: row.cursor
    onHasCursorChanged: if (hasCursor) row.hub.ensureCursorVisible(row)
    foreground: row.hub.fg
    fill: row.hub.hoverFill

    Text {
      id: glyph
      anchors.left: parent.left
      anchors.leftMargin: row.hub.gutter + Style.space(2)
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: row.net.active ? Model.linkGlyph(row.hub.view) : Model.wifiGlyph(row.net.signal)
      color: row.net.active ? row.hub.accent : row.hub.dim
      font.family: row.hub.fontFamily
      font.pixelSize: row.hub.typeBody + Style.space(3)
    }

    Text {
      id: name
      anchors.left: glyph.right
      anchors.leftMargin: Style.space(12)
      anchors.right: tail.left
      anchors.rightMargin: Style.space(10)
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: row.net.hidden ? row.hub.strings.t("net.hidden") : row.net.ssid
      color: row.net.hidden ? row.hub.dim : row.hub.fg
      font.family: row.hub.fontFamily
      font.pixelSize: row.hub.typeBody
      elide: Text.ElideRight
    }

    // The right edge: a caption, or the forget question in its place.
    Item {
      id: tail
      anchors.right: parent.right
      anchors.rightMargin: row.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      width: row.armed ? armedRow.width
        : Math.min(captionLabel.implicitWidth, surface.width * 0.4) + (disconnect.visible ? disconnect.width - disconnect.padX + Style.space(6) : 0)
      height: surface.height

      Text {
        id: captionLabel
        visible: !row.armed
        anchors.right: disconnect.visible ? disconnect.left : parent.right
        anchors.rightMargin: disconnect.visible ? Style.space(6) - disconnect.padX : 0
        anchors.verticalCenter: parent.verticalCenter
        width: Math.min(implicitWidth, surface.width * 0.4)
        horizontalAlignment: Text.AlignRight
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: row.captionText
        color: row.captionColor
        font.family: row.hub.fontFamily
        font.pixelSize: row.hub.typeSmall
        elide: Text.ElideRight
      }

      // The one in use can be dropped from its own row.
      TextButton {
        id: disconnect
        visible: row.net.active && !row.armed && !row.hub.pending.disconnecting
        hub: row.hub
        anchors.right: parent.right
        anchors.rightMargin: -padX
        anchors.verticalCenter: parent.verticalCenter
        padX: Style.space(6)
        padY: Style.space(4)
        text: row.hub.strings.t("net.disconnect")
        textColor: row.hub.dim
        hotColor: row.hub.fg
        onClicked: row.hub.disconnectNet()
      }

      Row {
        id: armedRow
        visible: row.armed
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(2)
        TextButton {
          hub: row.hub
          padX: Style.space(8)
          padY: Style.space(4)
          text: row.hub.strings.t("net.forgetYes")
          textColor: row.hub.urgent
          weight: Font.DemiBold
          onClicked: row.hub.confirmForget()
        }
        TextButton {
          hub: row.hub
          padX: Style.space(8)
          padY: Style.space(4)
          text: row.hub.strings.t("net.forgetNo")
          textColor: row.hub.dim
          onClicked: row.hub.disarmForget()
        }
      }
    }

    MouseArea {
      id: area
      anchors.fill: parent
      anchors.rightMargin: row.armed ? armedRow.width + row.hub.gutter : 0
      hoverEnabled: true
      acceptedButtons: Qt.LeftButton | Qt.RightButton
      cursorShape: row.net.hidden ? Qt.ArrowCursor : Qt.PointingHandCursor
      onContainsMouseChanged: surface.hover = containsMouse
      onPositionChanged: function(mouse) { row.hub.hoverCursor(area, mouse, "net:" + row.index, 0) }
      onClicked: function(mouse) {
        row.hub.setCursor("net:" + row.index, 0)
        if (mouse.button === Qt.RightButton) row.hub.armForget(row.index)
        else if (!row.net.active) row.hub.activateNet(row.index)
      }
    }

    PanelToolTip {
      visible: (area.containsMouse || row.cursor) && !row.armed && !row.pwOpen && row.hub.tipFor(row.net) !== ""
      text: row.hub.tipFor(row.net)
      fontFamily: row.hub.fontFamily
    }
  }

  // The passphrase, under its network.
  Item {
    id: pw
    visible: row.pwOpen
    y: surface.height
    width: row.width
    height: visible ? field.y + field.height + (errorLabel.visible ? errorLabel.height + Style.space(4) : 0) + Style.space(8) : 0

    TextField {
      id: field
      anchors.left: parent.left
      anchors.leftMargin: row.hub.gutter + Style.space(2)
      anchors.right: join.left
      anchors.rightMargin: Style.space(6)
      y: Style.space(2)
      password: true
      placeholderText: row.hub.strings.t("net.passphrase")
      font.family: row.hub.fontFamily
      font.pixelSize: row.hub.typeBody
      foreground: row.hub.fg
      accent: row.hub.accent
      horizontalPadding: Style.spacing.controlGap
      verticalPadding: Style.spacing.controlPaddingY
      onAccepted: row.hub.submitPassword(field)
      Keys.onEscapePressed: row.hub.cancelPassword()
    }

    PanelActionButton {
      id: join
      anchors.right: parent.right
      anchors.rightMargin: row.hub.gutter
      y: field.y + (field.height - height) / 2
      enabled: field.text.length > 0
      iconText: row.hub.glyphs.check
      tooltipText: row.hub.strings.t("net.join")
      foreground: row.hub.accent
      fontFamily: row.hub.fontFamily
      onClicked: row.hub.submitPassword(field)
    }

    Text {
      id: errorLabel
      visible: row.hub.passwordError !== ""
      anchors.left: field.left
      anchors.right: join.right
      y: field.y + field.height + Style.space(4)
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: row.hub.passwordError
      color: row.hub.urgent
      font.family: row.hub.fontFamily
      font.pixelSize: row.hub.typeSmall
      elide: Text.ElideRight
    }
  }
}

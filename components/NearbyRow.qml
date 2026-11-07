import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// One nearby network: four signal bars, its name, and on the right a band chip
// ("5G"), then a lock when it is secured and not saved, or a dim caption
// ("Saved", what is happening, an error in urgent).
//
//   press / Enter     saved or open: connect; secured and unknown: the
//                     passphrase row opens under this one; 802.1X that is not
//                     saved: nmtui in a terminal
//   right-click / Delete   saved networks: Forget, asked again in place
//                     ("Forget  Cancel"; Enter forgets, Esc cancels)
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
  readonly property string chip: Model.bandChip(net.band, net.frequencyMhz)
  readonly property bool lock: Model.showLock(net)

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
    hasCursor: row.cursor
    onHasCursorChanged: if (hasCursor) row.hub.ensureCursorVisible(row)
    foreground: row.hub.fg
    fill: row.hub.hoverFill

    SignalBars {
      id: bars
      anchors.left: parent.left
      anchors.leftMargin: row.hub.gutter + Style.space(4)
      anchors.verticalCenter: parent.verticalCenter
      level: Model.signalBars(row.net.signal)
      lit: row.hub.fg
      unlit: Qt.rgba(row.hub.fg.r, row.hub.fg.g, row.hub.fg.b, 0.2)
    }

    Text {
      id: name
      anchors.left: bars.right
      anchors.leftMargin: Style.space(14)
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

    // The right edge: the band chip, then a lock or a caption, each in a
    // column of its own so the chips and the words line up down the list; the
    // forget question in their place.
    Row {
      id: tail
      anchors.right: parent.right
      anchors.rightMargin: row.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(8)

      Text {
        id: chipMeasure
        visible: false
        textFormat: Text.PlainText
        text: "2.4G"
        font.family: row.hub.fontFamily
        font.pixelSize: row.hub.typeSmall
      }

      Item {
        visible: !row.armed
        width: chipMeasure.implicitWidth + Style.space(10)
        height: surface.height

        Rectangle {
          visible: row.chip !== ""
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          width: chipLabel.implicitWidth + Style.space(8)
          height: chipLabel.implicitHeight + Style.space(2)
          radius: Style.space(4)
          color: "transparent"
          border.width: 1
          border.color: row.hub.lineColor
          Text {
            id: chipLabel
            anchors.centerIn: parent
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
            text: row.chip
            color: row.hub.dim
            font.family: row.hub.fontFamily
            font.pixelSize: row.hub.typeSmall
          }
        }
      }

      Item {
        visible: !row.armed
        width: Math.max(Style.space(52), Math.min(captionLabel.implicitWidth, surface.width * 0.4))
        height: surface.height

        Text {
          visible: row.lock && row.captionText === ""
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: row.hub.glyphs.lock
          color: row.hub.dim
          font.family: row.hub.fontFamily
          font.pixelSize: row.hub.typeSmall
        }

        Text {
          id: captionLabel
          visible: row.captionText !== ""
          anchors.right: parent.right
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
      }

      Row {
        id: armedRow
        visible: row.armed
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
      onPositionChanged: function(mouse) { row.hub.hoverCursor(area, mouse, "net:" + row.index, 0) }
      onClicked: function(mouse) {
        row.hub.setCursor("net:" + row.index, 0)
        if (mouse.button === Qt.RightButton) row.hub.armForget(row.index)
        else row.hub.activateNet(row.index)
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

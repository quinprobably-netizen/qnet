pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The connection in use, at the top of the Wi-Fi view: a card of monospace
// key/value lines (Model.connectionCard) under its name and signal glyph,
//
//   (fan)  Redwood                              Disconnect
//   Link     5 GHz . ch 149 . 866 Mb/s
//   Signal   72%
//   IP       192.168.1.242/24
//   Gateway  192.168.1.1 . 4 ms
//   DNS      192.168.1.153
//
// with Disconnect on the card (and, secondary click or Delete, Forget, asked
// again in place). A wire has no Disconnect; with no link the card says so.
Item {
  id: card

  required property var hub
  readonly property var info: Model.connectionCard(hub.view, hub.formatNumber)
  readonly property bool armed: info.uuid !== "" && hub.armedUuid === info.uuid
  readonly property bool busy: hub.pending.disconnecting || (info.uuid !== "" && hub.pending.forgetUuid === info.uuid)
  readonly property real pad: Style.space(12)
  readonly property real keyW: Style.space(70)

  visible: info.kind !== "nobackend"
  width: parent ? parent.width : 0
  implicitHeight: visible ? box.height + Style.space(8) : 0

  Rectangle {
    id: box
    x: card.hub.gutter
    y: Style.space(4)
    width: card.width - 2 * card.hub.gutter
    height: card.pad + head.height + (rows.count > 0 ? Style.space(6) + rows.height : 0) + card.pad
    radius: Style.cornerRadius
    color: card.hub.restFill

    // Forget, on a secondary click.
    MouseArea {
      id: area
      anchors.fill: parent
      hoverEnabled: true
      acceptedButtons: Qt.RightButton
      onClicked: card.hub.armForgetUuid(card.info.uuid)

      PanelToolTip {
        visible: area.containsMouse && card.info.uuid !== "" && !card.armed && card.info.kind === "wifi"
        text: card.hub.strings.t("net.forgetHint")
        fontFamily: card.hub.fontFamily
      }
    }

    // ---------------------------------------------------------- the head
    Item {
      id: head
      x: card.pad
      y: card.pad
      width: box.width - 2 * card.pad
      height: Style.space(26)

      Text {
        id: glyph
        anchors.verticalCenter: parent.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: card.info.glyph
        color: card.info.kind === "none" || card.info.kind === "off" ? card.hub.dim : (card.info.urgent ? card.hub.urgent : card.hub.accent)
        font.family: card.hub.fontFamily
        font.pixelSize: card.hub.typeBody + Style.space(5)
      }

      Text {
        anchors.left: glyph.right
        anchors.leftMargin: Style.space(10)
        anchors.right: tail.left
        anchors.rightMargin: Style.space(8)
        anchors.verticalCenter: parent.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: {
          switch (card.info.kind) {
          case "wifi": return card.info.title !== "" ? card.info.title : card.hub.strings.t("header.wifi")
          case "ethernet": return card.hub.strings.t("header.ethernet")
          case "off": return card.hub.strings.t("header.wifiOff")
          default: return card.hub.strings.t("header.state.offline")
          }
        }
        color: card.info.kind === "none" || card.info.kind === "off" ? card.hub.dim : card.hub.fg
        font.family: card.hub.fontFamily
        font.pixelSize: card.hub.typeBody
        font.weight: Font.DemiBold
        elide: Text.ElideRight
      }

      // The right edge: Disconnect, or what is happening, or the forget
      // question in its place.
      Item {
        id: tail
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        width: card.armed ? armedRow.width : (card.busy ? busyLabel.implicitWidth : (disconnect.visible ? disconnect.width - disconnect.padX : 0))
        height: head.height

        TextButton {
          id: disconnect
          visible: card.info.canDisconnect && !card.armed && !card.busy
          hub: card.hub
          anchors.right: parent.right
          anchors.rightMargin: -padX
          anchors.verticalCenter: parent.verticalCenter
          padX: Style.space(8)
          padY: Style.space(4)
          text: card.hub.strings.t("net.disconnect")
          textColor: card.hub.dim
          hotColor: card.hub.fg
          cursorRow: "card"
          cursorItem: 0
          onClicked: card.hub.disconnectNet()
        }

        Text {
          id: busyLabel
          visible: card.busy && !card.armed
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: card.hub.pending.disconnecting ? card.hub.strings.t("net.caption.disconnecting") : card.hub.strings.t("net.caption.forgetting")
          color: card.hub.dim
          font.family: card.hub.fontFamily
          font.pixelSize: card.hub.typeSmall
        }

        Row {
          id: armedRow
          visible: card.armed
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(2)
          TextButton {
            hub: card.hub
            padX: Style.space(8)
            padY: Style.space(4)
            text: card.hub.strings.t("net.forgetYes")
            textColor: card.hub.urgent
            weight: Font.DemiBold
            onClicked: card.hub.confirmForget()
          }
          TextButton {
            hub: card.hub
            padX: Style.space(8)
            padY: Style.space(4)
            text: card.hub.strings.t("net.forgetNo")
            textColor: card.hub.dim
            onClicked: card.hub.disarmForget()
          }
        }
      }
    }

    // ------------------------------------------------------------ the lines
    Column {
      id: rows
      readonly property int count: card.info.rows.length
      x: card.pad
      y: head.y + head.height + Style.space(6)
      width: box.width - 2 * card.pad
      spacing: Style.space(3)

      Repeater {
        model: card.info.rows

        Item {
          id: line
          required property var modelData
          width: rows.width
          height: Math.max(keyText.implicitHeight, valueText.implicitHeight)

          Text {
            id: keyText
            width: card.keyW
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
            text: card.hub.strings.t("card.k." + line.modelData.k)
            color: card.hub.dim
            font.family: card.hub.fontFamily
            font.pixelSize: card.hub.typeSmall
          }
          Text {
            id: valueText
            anchors.left: keyText.right
            anchors.right: parent.right
            textFormat: Text.PlainText
            renderType: Text.NativeRendering
            text: line.modelData.key !== "" ? card.hub.strings.t(line.modelData.key) : line.modelData.v
            color: line.modelData.key !== "" ? card.hub.urgent : card.hub.fg
            font.family: card.hub.fontFamily
            font.pixelSize: card.hub.typeSmall
            elide: Text.ElideRight
          }
        }
      }
    }
  }
}

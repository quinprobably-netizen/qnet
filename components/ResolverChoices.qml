pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons

// The resolver choices, a selectable list (radio rows, not tiles): the
// Pi-hole and Automatic. The lit row is the resolver in use, read from
// systemd-resolved, never what was last asked for: a runtime failover lights
// the Pi-hole row in the warning colour and says so, custom servers light
// neither and get a "Custom: 9.9.9.9" caption. Picking the lit row does
// nothing; picking the Pi-hole when none is set up starts setup.
//
// Leaving the Pi-hole is asked first, inline, under the list: "Stop using
// Pi-hole?  Use automatic DNS  Cancel" (and so is replacing DNS the user set
// by hand), then an error, or a note that the Pi-hole did not confirm
// blocking when it was switched to.
Column {
  id: pick

  required property var hub
  readonly property var choices: hub.choices
  readonly property var tiles: hub.tiles

  width: parent ? parent.width : 0
  spacing: 0

  SectionHead {
    hub: pick.hub
    text: pick.hub.strings.t("dns.resolver")
  }

  // ---------------------------------------------------------------- rows
  Repeater {
    model: pick.choices

    CursorSurface {
      id: row
      required property var modelData
      required property int index
      readonly property string name: modelData.id
      readonly property bool isPihole: name === "pihole"
      readonly property bool lit: modelData.lit !== "off"
      readonly property color litColor: modelData.lit === "warn" ? pick.hub.warning : pick.hub.accent
      readonly property bool needsSetup: isPihole && !modelData.configured

      width: pick.width
      height: Style.space(36)
      hasCursor: pick.hub.has("choice:" + name)
      onHasCursorChanged: if (hasCursor) pick.hub.ensureCursorVisible(row)
      foreground: pick.hub.fg
      fill: pick.hub.hoverFill
      scale: area.pressed ? pick.hub.pressScale : 1
      Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

      // the radio
      Rectangle {
        id: radio
        anchors.left: parent.left
        anchors.leftMargin: pick.hub.gutter + Style.space(4)
        anchors.verticalCenter: parent.verticalCenter
        width: Style.space(14)
        height: width
        radius: width / 2
        color: "transparent"
        border.width: 1.5
        border.color: row.lit ? row.litColor : Qt.rgba(pick.hub.fg.r, pick.hub.fg.g, pick.hub.fg.b, 0.4)
        Rectangle {
          visible: row.lit
          anchors.centerIn: parent
          width: parent.width - Style.space(7)
          height: width
          radius: width / 2
          color: row.litColor
        }
      }

      Text {
        id: nameText
        anchors.left: radio.right
        anchors.leftMargin: Style.space(12)
        anchors.verticalCenter: parent.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: row.isPihole ? pick.hub.strings.t("dns.pihole") : pick.hub.strings.t("dns.auto")
        color: row.lit ? row.litColor : pick.hub.fg
        font.family: pick.hub.fontFamily
        font.pixelSize: pick.hub.typeBody
      }

      // what it is: the Pi-hole's address, Automatic's "router"
      Text {
        anchors.left: nameText.right
        anchors.leftMargin: Style.space(10)
        anchors.right: tag.left
        anchors.rightMargin: Style.space(8)
        anchors.verticalCenter: parent.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: row.isPihole ? row.modelData.detail : pick.hub.strings.t("dns.autoDetail")
        color: pick.hub.dim
        font.family: pick.hub.fontFamily
        font.pixelSize: pick.hub.typeSmall
        elide: Text.ElideRight
      }

      // a word on the right where there is one: the failover, or the setup
      Text {
        id: tag
        anchors.right: parent.right
        anchors.rightMargin: pick.hub.gutter
        anchors.verticalCenter: parent.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: row.modelData.warn ? pick.hub.strings.t("dns.fallbackTag")
          : (row.needsSetup ? pick.hub.strings.t("dns.setupTag") : "")
        color: row.modelData.warn ? pick.hub.warning : pick.hub.accent
        font.family: pick.hub.fontFamily
        font.pixelSize: pick.hub.typeSmall
      }

      MouseArea {
        id: area
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: row.lit && !row.modelData.warn ? Qt.ArrowCursor : Qt.PointingHandCursor
        onPositionChanged: function(mouse) { pick.hub.hoverCursor(area, mouse, "choice:" + row.name, 0) }
        onClicked: {
          pick.hub.setCursor("choice:" + row.name, 0)
          pick.hub.tapTile(row.name)
        }
      }
    }
  }

  // ------------------------------------------------------ lines below
  Text {
    visible: pick.tiles.custom !== null && !pick.hub.confirm.open
    x: pick.hub.gutter
    width: pick.width - 2 * pick.hub.gutter
    topPadding: Style.space(4)
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: pick.tiles.custom ? pick.hub.strings.t("dns.custom").arg(pick.tiles.custom.join(", ")) : ""
    color: pick.hub.dim
    font.family: pick.hub.fontFamily
    font.pixelSize: pick.hub.typeSmall
    elide: Text.ElideRight
  }

  Item {
    visible: pick.hub.confirm.open
    width: pick.width
    height: Style.space(34)

    Text {
      anchors.left: parent.left
      anchors.leftMargin: pick.hub.gutter
      anchors.right: replace.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: pick.hub.confirm.kind === "leave" ? pick.hub.strings.t("dns.leaveQ") : pick.hub.strings.t("dns.replaceQ").arg(pick.hub.confirm.servers)
      color: pick.hub.fg
      font.family: pick.hub.fontFamily
      font.pixelSize: pick.hub.typeSmall
      elide: Text.ElideRight
    }

    TextButton {
      id: replace
      hub: pick.hub
      anchors.right: cancel.left
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: pick.hub.confirm.kind === "leave" ? pick.hub.strings.t("dns.leaveYes") : pick.hub.strings.t("dns.replace")
      textColor: pick.hub.urgent
      weight: Font.DemiBold
      cursorRow: "confirm"
      cursorItem: 0
      onClicked: pick.hub.confirmReplace()
    }

    TextButton {
      id: cancel
      hub: pick.hub
      anchors.right: parent.right
      anchors.rightMargin: pick.hub.gutter - padX + Style.space(4)
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: pick.hub.strings.t("dns.cancel")
      textColor: pick.hub.dim
      cursorRow: "confirm"
      cursorItem: 1
      onClicked: pick.hub.confirmCancel()
    }
  }

  Text {
    visible: pick.hub.dnsNote.text !== ""
    x: pick.hub.gutter
    width: pick.width - 2 * pick.hub.gutter
    topPadding: Style.space(4)
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    wrapMode: Text.Wrap
    text: pick.hub.dnsNote.text
    color: pick.hub.dnsNote.tone === "warning" ? pick.hub.warning : pick.hub.urgent
    font.family: pick.hub.fontFamily
    font.pixelSize: pick.hub.typeSmall
  }
}

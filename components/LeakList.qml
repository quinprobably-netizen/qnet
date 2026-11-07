pragma ComponentBehavior: Bound
import QtQuick
import qs.Commons

// What sends queries around the Pi-hole, on the DNS view. Each line says what
// and where in dim body text; the only colour on it is the amber of its
// "Pin".
//  - When this link itself can skip the Pi-hole (dns.bypassed), one line
//    names the extra resolver ("Also resolving through router via IPv6 RA"),
//    or says the link is not pinned; Pin applies the Pi-hole to the link in
//    use.
//  - Saved profiles that are not in use and would bypass it when they are:
//    one line each, "Wired connection 1 · uses router DNS (automatic)", each
//    with its own Pin, and Pin all under them when there are two or more
//    (one `qnet dns pin u1 u2`).
// resolved's compiled-in FallbackDNS is not a leak while links have servers.
Column {
  id: list

  required property var hub
  readonly property var bypass: hub.leaks.bypass
  readonly property var profiles: hub.leaks.profiles
  readonly property var extra: hub.leakExtra

  width: parent ? parent.width : 0
  visible: bypass !== null || profiles !== null

  SectionHead {
    hub: list.hub
    text: list.hub.strings.t("leak.title")
  }

  // ------------------------------------------------------- this link
  Item {
    id: bypassLine
    visible: list.bypass !== null
    width: list.width
    height: Style.space(34)

    Text {
      id: bypassText
      anchors.left: parent.left
      anchors.leftMargin: list.hub.gutter
      anchors.right: pin.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: {
        if (list.extra === null) return list.hub.strings.t("leak.unpinned")
        return list.hub.strings.t("leak.also" + (list.extra.viaRa ? "Ra" : "")).arg(list.extra.who)
      }
      color: list.hub.dim
      font.family: list.hub.fontFamily
      font.pixelSize: list.hub.typeSmall
      elide: Text.ElideRight
    }

    TextButton {
      id: pin
      hub: list.hub
      anchors.right: parent.right
      anchors.rightMargin: list.hub.gutter - padX
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: list.hub.strings.t("leak.pin")
      textColor: list.hub.warning
      weight: Font.DemiBold
      cursorRow: "bypass"
      cursorItem: 0
      onClicked: list.hub.fixBypass()
    }
  }

  // ---------------------------------------------- profiles not in use
  Repeater {
    model: list.profiles !== null ? list.profiles.items : []

    Item {
      id: line
      required property var modelData
      required property int index
      width: list.width
      height: Style.space(34)

      Row {
        anchors.left: parent.left
        anchors.leftMargin: list.hub.gutter
        anchors.right: pinOne.left
        anchors.rightMargin: Style.space(8)
        anchors.verticalCenter: parent.verticalCenter
        id: words

        Text {
          id: nameText
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: line.modelData.where
          color: list.hub.fg
          font.family: list.hub.fontFamily
          font.pixelSize: list.hub.typeSmall
          elide: Text.ElideRight
          width: Math.min(implicitWidth, words.width)
        }
        Text {
          visible: line.modelData.detail !== "" && words.width - nameText.width > Style.space(50)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: " · " + line.modelData.detail
          color: list.hub.dim
          font.family: list.hub.fontFamily
          font.pixelSize: list.hub.typeSmall
          elide: Text.ElideRight
          width: Math.max(0, Math.min(implicitWidth, words.width - nameText.width))
        }
      }

      TextButton {
        id: pinOne
        visible: line.modelData.uuid !== ""
        hub: list.hub
        anchors.right: parent.right
        anchors.rightMargin: list.hub.gutter - padX
        anchors.verticalCenter: parent.verticalCenter
        padX: Style.space(8)
        padY: Style.space(4)
        text: list.hub.strings.t("leak.pin")
        textColor: list.hub.warning
        weight: Font.DemiBold
        cursorRow: "leak:" + line.index
        cursorItem: 0
        onClicked: list.hub.pinOne(line.index)
      }
    }
  }

  Item {
    visible: list.profiles !== null && list.profiles.uuids.length > 1
    width: list.width
    height: Style.space(30)
    TextButton {
      hub: list.hub
      anchors.right: parent.right
      anchors.rightMargin: list.hub.gutter - padX
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(4)
      text: list.hub.strings.t("leak.pinAll")
      textColor: list.hub.warning
      weight: Font.DemiBold
      cursorRow: "pinall"
      cursorItem: 0
      onClicked: list.hub.pinAll()
    }
  }
}

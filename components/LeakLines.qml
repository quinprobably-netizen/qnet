pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import qs.Commons

// Anything that would send queries around the Pi-hole, one urgent line each:
// "Wired connection 1 would bypass Pi-hole · uses router DNS   Pin". Shown
// only when there are leaks (at most three; the rest are a count). Pin applies
// the Pi-hole to that saved profile; Fix applies it to the link in use.
// resolved's compiled-in FallbackDNS is not a leak while links have servers.
Column {
  id: leaks

  required property var hub
  readonly property var lines: hub.leakList.slice(0, hub.leakShown)
  readonly property int more: Math.max(0, hub.leakList.length - hub.leakShown)

  width: parent ? parent.width : 0
  visible: hub.leakList.length > 0

  Repeater {
    model: ScriptModel { values: leaks.lines; objectProp: "key" }

    Item {
      id: line
      required property var modelData
      required property int index
      width: leaks.width
      height: Style.space(32)

      // "<where> would bypass Pi-hole", then the dim detail; both elide, the
      // detail first.
      Row {
        id: words
        anchors.left: parent.left
        anchors.leftMargin: leaks.hub.gutter
        anchors.right: fix.visible ? fix.left : parent.right
        anchors.rightMargin: fix.visible ? Style.space(8) : leaks.hub.gutter
        anchors.verticalCenter: parent.verticalCenter
        spacing: 0

        Text {
          id: head
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: (line.modelData.would ? leaks.hub.strings.t("leak.would") : leaks.hub.strings.t("leak.bypasses")).arg(line.modelData.where)
          color: leaks.hub.urgent
          font.family: leaks.hub.fontFamily
          font.pixelSize: leaks.hub.typeSmall
          elide: Text.ElideRight
          width: Math.min(implicitWidth, words.width)
        }
        Text {
          visible: line.modelData.detail !== "" && words.width - head.width > Style.space(40)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: " · " + line.modelData.detail
          color: Util.alpha(leaks.hub.urgent, 0.7)
          font.family: leaks.hub.fontFamily
          font.pixelSize: leaks.hub.typeSmall
          elide: Text.ElideRight
          width: Math.max(0, Math.min(implicitWidth, words.width - head.width))
        }
      }

      TextButton {
        id: fix
        visible: line.modelData.action !== null
        hub: leaks.hub
        anchors.right: parent.right
        anchors.rightMargin: leaks.hub.gutter - padX + Style.space(4)
        anchors.verticalCenter: parent.verticalCenter
        padX: Style.space(8)
        padY: Style.space(4)
        text: line.modelData.action && line.modelData.action.verb === "pin" ? leaks.hub.strings.t("leak.pin") : leaks.hub.strings.t("leak.fix")
        textColor: leaks.hub.urgent
        weight: Font.DemiBold
        cursorRow: "leak:" + line.index
        cursorItem: 0
        onClicked: leaks.hub.fixLeak(line.index)
      }
    }
  }

  Text {
    visible: leaks.more > 0
    x: leaks.hub.gutter
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: leaks.hub.strings.tn("leak.more", leaks.more).arg(leaks.more)
    color: leaks.hub.dim
    font.family: leaks.hub.fontFamily
    font.pixelSize: leaks.hub.typeSmall
    height: Style.space(22)
    verticalAlignment: Text.AlignVCenter
  }
}

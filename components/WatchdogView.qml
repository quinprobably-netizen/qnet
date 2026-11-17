pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The watchdog view, the third drill-down: a qberrypi's patch bay. Reached
// from the Pi-hole's node on the route ("route › qbp" in the corner says so).
// Top to bottom:
//
//   head      back, "Watchdog", "qbp ·2 · 8 devices · 2 offline", the small route
//   lamps     one window per kind of alert, lit with their count (LampRow.qml)
//   board     the rail with the NORMAL key, and the bays (PatchBay.qml)
//   readout   under the board: what NORMAL means, or the name and state of the
//             jack under the pointer or the cursor, or the NORMAL confirm
//             ("Flip normal to ADS PASS? 4 devices will see ads."), or the
//             note of a failed action; on its right the pager
//
//   calls     the calls waiting, newest first (CallQueue.qml)
//   ticket    the open ticket, one at a time: a device's (DeviceTicket.qml) or
//             a call's trouble ticket (AlertTicket.qml); the board shrinks to
//             the one bay it belongs to while one is open
//   lock      the PIN of the Pi's screen (PinFooter.qml)
//
// The board draws at the full 488 of the content column, which is why the card
// is wider on this view (Panel.qml: contentWidth).
//
// The words are the catalog's (wd.*); Model.jackReadout, sentenceRuns and
// boardHead say what to put in them.
Column {
  id: page

  required property var hub

  readonly property var wd: hub.view.watchdog
  readonly property var pager: hub.wdLayout.pager

  width: parent ? parent.width : 0
  spacing: 0

  function t(key) { return hub.strings.t(key) }

  readonly property string subtitle: {
    var h = Model.boardHead(hub.view)
    var parts = [h.qbp !== "" ? t("wd.qbp").arg(h.qbp) : t("wd.qbpPlain"), hub.strings.tn("wd.devices", h.devices).arg(h.devices)]
    if (h.offline > 0) parts.push(t("wd.offlineCount").arg(h.offline))
    return parts.join(" · ")
  }

  ViewHeader {
    hub: page.hub
    inset: 0
    title: page.t("view.watchdog")
    subtitle: page.subtitle

    // the small route: four nodes, the third (qbp) lit
    Item {
      width: Style.space(92)
      height: Style.space(30)

      Rectangle {
        x: Style.spaceReal(8)
        y: Style.spaceReal(9) - height / 2
        width: Style.spaceReal(76)
        height: Style.spaceReal(2.5)
        color: page.hub.ring
      }
      Repeater {
        model: [8, 33, 59, 84]

        Rectangle {
          required property int modelData
          required property int index
          readonly property bool lit: index === 2
          width: lit ? Style.spaceReal(15) : Style.spaceReal(10.4)
          height: width
          radius: width / 2
          x: Style.spaceReal(modelData) - width / 2
          y: Style.spaceReal(9) - height / 2
          color: lit ? page.hub.accent : page.hub.cardColor
          border.width: lit ? Style.spaceReal(2) : Style.spaceReal(1.4)
          border.color: lit ? page.hub.cardColor : page.hub.dim
        }
      }
      Text {
        x: parent.width - width
        y: Style.spaceReal(27) - baselineOffset
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: page.t("wd.route")
        color: page.hub.dim
        font.family: page.hub.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }

  Item { width: 1; height: Style.space(4) }

  LampRow { hub: page.hub }

  Item { width: 1; height: Style.space(8) }

  PatchBay { id: board; hub: page.hub }

  // ------------------------------------------------------------ readout
  // The jack the pointer is over, else the one the keyboard cursor is on.
  readonly property string readoutMac: board.hoverMac !== "" ? board.hoverMac : Model.bayCursorMac(hub.wdLayout, hub.cursorActive && !hub.cursorPointer ? hub.cursor : null)

  // What the line says, as { kind, tone, strongTone, runs }: the runs are
  // words (Model.sentenceRuns) that wrap, the strong ones bright and bold.
  readonly property var readout: {
    var h = page.hub
    var normalPass = wd.exemptDefault
    var jack = readoutMac !== "" ? board.byMac[readoutMac] || null : null
    if (h.wdFlip && !normalPass) {
      var n = wd.bay.flipCount
      return { kind: "confirm", tone: h.warning, runs: Model.sentenceRuns(h.strings.tn("wd.flipQ", n).arg(n) + " ") }
    }
    if (jack !== null) {
      var r = Model.jackReadout(jack, h.nowMs / 1000)
      var rest = (r.name !== "" ? r.tail + " · " : "") + h.say(r.how) + (r.offline ? " · " + t("wd.ro.offline") : "") + (r.isNew ? " · " + t("wd.new") : "")
      return { kind: "jack", tone: h.dim, runs: Model.sentenceRuns(Model.strong(r.name !== "" ? r.name : r.tail) + " " + rest) }
    }
    if (h.wdNote !== "") return { kind: "note", tone: h.urgent, runs: Model.sentenceRuns(h.wdNote) }
    return {
      kind: "normal", tone: normalPass ? h.warning : h.dim,
      runs: normalPass ? Model.sentenceRuns(t("wd.normal.pass").arg(Model.strong(t("wd.rail.pass")))) : Model.sentenceRuns(t("wd.normal.blocked").arg(Model.strong(t("wd.rail.blocked"))))
    }
  }

  Item {
    id: line
    width: page.width
    height: Math.max(Style.space(32), words.implicitHeight + Style.space(8))

    Flow {
      id: words
      anchors.left: parent.left
      anchors.verticalCenter: parent.verticalCenter
      width: pagerBox.visible ? pagerBox.x - Style.space(8) : parent.width
      spacing: 0

      Repeater {
        model: page.readout.runs

        Text {
          required property var modelData
          height: Style.space(17)
          verticalAlignment: Text.AlignVCenter
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: modelData.text
          color: modelData.strong ? page.hub.bright : page.readout.tone
          font.family: page.hub.fontFamily
          font.pixelSize: Style.font.caption
          font.weight: modelData.strong ? Font.Bold : Font.Normal
        }
      }

      // NORMAL at rest: the way to flip it, in words
      TextButton {
        visible: page.readout.kind === "normal"
        hub: page.hub
        text: page.t("wd.flip")
        textColor: page.hub.accent
        hotColor: Qt.lighter(page.hub.accent, 1.25)
        size: Style.font.caption
        padX: Style.space(6)
        padY: Style.space(2)
        onClicked: page.hub.wdPressKey()
      }

      // the confirm: Flip and Cancel follow the sentence as two more words,
      // so they sit on its line while they fit and wrap with it when they do not
      TextButton {
        visible: page.readout.kind === "confirm"
        hub: page.hub
        text: page.t("wd.flipYes")
        textColor: page.hub.bright
        weight: Font.Bold
        size: Style.font.caption
        padX: Style.space(8)
        padY: Style.space(3)
        filled: true
        restColor: page.hub.sel
        hoverFilled: true
        radius: Math.min(Style.cornerRadius, Style.space(3))
        cursorRow: "flip"
        cursorItem: 0
        onClicked: page.hub.wdConfirmFlip()
      }
      TextButton {
        visible: page.readout.kind === "confirm"
        hub: page.hub
        text: page.t("wd.flipNo")
        textColor: page.hub.dim
        hotColor: page.hub.fg
        size: Style.font.caption
        padX: Style.space(8)
        padY: Style.space(3)
        hoverFilled: true
        radius: Math.min(Style.cornerRadius, Style.space(3))
        cursorRow: "flip"
        cursorItem: 1
        onClicked: page.hub.wdCancelFlip()
      }
    }

    // ------------------------------------------------------------ pager
    // "bays 3–4 of 4" and two buttons; each carries a small urgent lamp when a
    // jack with an alert is out of sight in that direction. Dead while a ticket
    // holds the board on its own bay.
    Row {
      id: pagerBox
      visible: page.pager !== null
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(8)

      Text {
        anchors.verticalCenter: parent.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: page.pager === null ? "" : (page.pager.from === page.pager.to
          ? page.t("wd.pager.one").arg(page.pager.from).arg(page.pager.total)
          : page.t("wd.pager.many").arg(page.pager.from).arg(page.pager.to).arg(page.pager.total))
        color: page.hub.dim
        font.family: page.hub.fontFamily
        font.pixelSize: Style.font.caption
      }

      Repeater {
        model: [-1, 1]

        CursorSurface {
          id: pb
          required property int modelData
          required property int index
          readonly property bool canGo: page.pager !== null && page.hub.wdTicketMac === "" && (modelData < 0 ? page.pager.canUp : page.pager.canDown)
          readonly property bool ring: page.pager !== null && (modelData < 0 ? page.pager.upRing : page.pager.downRing)
          width: Style.space(22)
          height: Style.space(22)
          hasCursor: page.hub.has("pager", index)
          foreground: page.hub.fg
          color: hasCursor || pbArea.containsMouse ? page.hub.hoverFill : page.hub.restFill
          opacity: canGo ? 1 : page.hub.disabledOpacity
          scale: pbArea.pressed && canGo ? page.hub.pressScale : 1
          Behavior on scale { NumberAnimation { duration: Style.duration(80); easing.type: Easing.OutCubic } }

          Shape {
            anchors.centerIn: parent
            width: Style.spaceReal(10)
            height: Style.spaceReal(6)
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
              strokeColor: page.hub.fg
              strokeWidth: Style.spaceReal(1.5)
              fillColor: "transparent"
              capStyle: ShapePath.RoundCap
              joinStyle: ShapePath.RoundJoin
              startX: Style.spaceReal(1)
              startY: Style.spaceReal(pb.modelData < 0 ? 5 : 1)
              PathLine { x: Style.spaceReal(5); y: Style.spaceReal(pb.modelData < 0 ? 1 : 5) }
              PathLine { x: Style.spaceReal(9); y: Style.spaceReal(pb.modelData < 0 ? 5 : 1) }
            }
          }
          // an alerting jack is out of sight that way
          Rectangle {
            visible: pb.ring
            x: parent.width - width - Style.space(2)
            y: Style.space(2)
            width: Style.space(6)
            height: Style.space(4)
            color: page.hub.urgent
          }

          MouseArea {
            id: pbArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: pb.canGo ? Qt.PointingHandCursor : Qt.ArrowCursor
            onPositionChanged: function(mouse) { page.hub.hoverCursor(pbArea, mouse, "pager", pb.index) }
            onClicked: if (pb.canGo) page.hub.wdPage(pb.modelData)
          }
          PanelToolTip {
            visible: pbArea.containsMouse
            text: pb.modelData < 0 ? page.t("wd.pager.up") : page.t("wd.pager.down")
            fontFamily: page.hub.fontFamily
          }
        }
      }
    }
  }

  // ------------------------------------------------- calls, ticket, lock
  // The jack or the call whose ticket is open: one at a time, in the same
  // place, between the calls and the lock.
  readonly property var ticketJack: hub.wdTicket !== null && hub.wdTicket.kind === "device" ? Model.jackOf(hub.view, hub.wdTicket.mac) : null
  readonly property var ticketCall: hub.wdTicket !== null && hub.wdTicket.kind === "alert" ? Model.callOf(hub.view, hub.wdTicket.alertId) : null

  CallQueue { hub: page.hub }

  Loader {
    width: page.width
    active: page.ticketJack !== null
    sourceComponent: Component { DeviceTicket { hub: page.hub; jack: page.ticketJack } }
  }

  Loader {
    width: page.width
    active: page.ticketCall !== null
    sourceComponent: Component { AlertTicket { hub: page.hub; call: page.ticketCall } }
  }

  PinFooter { hub: page.hub }
}

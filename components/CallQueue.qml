pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The calls waiting, under the board: a head ("CALLS WAITING 2", Dismiss all
// on the right) and one row for each alert not yet dismissed, newest first.
// A row says what rang (a lamp and the kind in capitals, in the tone of the
// call: urgent for a high one, warning for the rest), which jack it rang (its
// name, or its tail like ·216; LAN when it rings no jack), a dim brief (the
// subject, and ×n when it came more than once) and the time of the last ring.
// Pressing a row opens its trouble ticket (or closes it); the row of the open
// one is lit. With no calls, one line says how long it has been quiet.
//
// Keyboard stops (Model.focusRows): "queue" (dismissall) and "call:ID".
// What each word is comes from Model (callTitle, callJackName, callBrief,
// quietLine); the panel says them in the catalog's language.
Item {
  id: queue

  required property var hub

  readonly property var wd: hub.view.watchdog
  readonly property var calls: wd.bay.calls
  readonly property int openId: hub.wdTicket !== null && hub.wdTicket.kind === "alert" ? hub.wdTicket.alertId : -1

  width: parent ? parent.width : 0
  implicitHeight: head.height + list.height
  height: implicitHeight

  component Tx: Text {
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    color: queue.hub.fg
    font.family: queue.hub.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  // ------------------------------------------------------------- the head
  // a line over it, 4 of air, then 26 for the words
  Item {
    id: head
    width: queue.width
    height: Style.space(31)

    Rectangle { width: parent.width; height: 1; color: queue.hub.lineColor }

    Item {
      y: Style.space(5)
      width: parent.width
      height: Style.space(26)

      Row {
        visible: queue.calls.length > 0
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(8)

        Tx {
          text: queue.hub.strings.t("wd.queue.head")
          font.pixelSize: Style.font.caption
          font.weight: Font.Bold
          font.letterSpacing: Style.spaceReal(0.8)
        }
        Tx {
          text: String(queue.calls.length)
          color: queue.hub.dim
          font.pixelSize: Style.font.caption
        }
      }

      Tx {
        visible: queue.calls.length === 0
        anchors.verticalCenter: parent.verticalCenter
        text: queue.hub.say(Model.quietLine(queue.hub.view, queue.hub.timeFmt))
        color: queue.hub.dim
      }

      TextButton {
        visible: queue.calls.length > 0
        hub: queue.hub
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        text: queue.hub.strings.t("wd.queue.dismissAll")
        textColor: queue.hub.dim
        hotColor: queue.hub.fg
        size: Style.font.caption
        padX: Style.space(8)
        padY: Style.space(3)
        hoverFilled: true
        enabled: !queue.hub.wdBusy
        cursorRow: "queue"
        cursorItem: 0
        onClicked: queue.hub.wdDismissAll()
      }
    }
  }

  // ------------------------------------------------------------ the calls
  Column {
    id: list
    y: head.height
    width: queue.width
    spacing: 0

    Repeater {
      model: queue.calls

      Item {
        id: row

        required property var modelData

        readonly property var call: modelData
        readonly property bool selected: queue.openId === call.id
        readonly property bool hasCursor: queue.hub.has("call:" + call.id)
        readonly property color tone: call.tone === "high" ? queue.hub.urgent : queue.hub.warning
        readonly property string brief: {
          var b = Model.callBrief(queue.hub.view, call)
          return b === null ? "" : queue.hub.say(b)
        }

        width: list.width
        height: Style.space(32)

        // the ground: lit under the cursor, quieter for the open call or the pointer
        CursorSurface {
          y: 1
          width: parent.width
          height: parent.height - 1
          radius: 0
          hasCursor: row.hasCursor
          foreground: queue.hub.fg
          fill: queue.hub.hoverFill
          color: row.hasCursor ? queue.hub.hoverFill : (row.selected || area.containsMouse ? queue.hub.restFill : "transparent")
        }
        Rectangle { width: parent.width; height: 1; color: queue.hub.lineColor }

        Rectangle {
          id: lamp
          x: Style.space(4)
          anchors.verticalCenter: parent.verticalCenter
          anchors.verticalCenterOffset: 1
          width: Style.space(8)
          height: Style.space(5)
          color: row.tone
        }

        Tx {
          id: title
          anchors.left: lamp.right
          anchors.leftMargin: Style.space(8)
          anchors.verticalCenter: parent.verticalCenter
          anchors.verticalCenterOffset: 1
          text: queue.hub.say(Model.callTitle(row.call))
          color: row.tone
          font.pixelSize: Style.font.caption
          font.weight: Font.Bold
          font.letterSpacing: Style.spaceReal(0.8)
        }

        Tx {
          id: who
          anchors.left: title.right
          anchors.leftMargin: Style.space(8)
          anchors.verticalCenter: parent.verticalCenter
          anchors.verticalCenterOffset: 1
          text: queue.hub.say(Model.callJackName(queue.hub.view, row.call))
        }

        Tx {
          id: when
          anchors.right: parent.right
          anchors.rightMargin: Style.space(4)
          anchors.verticalCenter: parent.verticalCenter
          anchors.verticalCenterOffset: 1
          text: queue.hub.formatClock(row.call.lastUnix)
          color: queue.hub.dim
          font.pixelSize: Style.font.caption
        }

        Tx {
          anchors.left: who.right
          anchors.leftMargin: Style.space(8)
          anchors.right: when.left
          anchors.rightMargin: Style.space(8)
          anchors.verticalCenter: parent.verticalCenter
          anchors.verticalCenterOffset: 1
          text: row.brief
          color: queue.hub.dim
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }

        MouseArea {
          id: area
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onPositionChanged: function(mouse) { queue.hub.hoverCursor(area, mouse, "call:" + row.call.id, 0) }
          onClicked: queue.hub.wdOpenAlert(row.call.id)
        }
      }
    }
  }
}

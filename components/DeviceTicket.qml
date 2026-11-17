pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The ticket of one device, open under the calls waiting (a click or Enter on
// its column, or "Open device ›" on an alert's ticket). Top to bottom:
//
//   LINE ·23                                   BLOCKED | ADS PASS | ALWAYS | FIXED | 14:32
//   LABEL  Sam's phone_______________________  the name, up to 24 characters
//   192.0.2.23 · 02:00:00:00:00:17 · phone-7a · first seen 2 Nov
//   PATCH  [BLOCKED|ADS PASS]  what the state means, and whether it is a cord
//   GATE   shut: Open 5 m, 30 m, 60 m    or    open, shuts in 14:32: Shut now
//   Mark known | Forget device, Close
//
// The router, the Pi and a device the Pi's own configuration decides (ALWAYS,
// FIXED) say so in a line instead of the patch and gate rows. The label is
// sent when Enter is pressed or the field loses the keys (and when the ticket
// changes, the tab is left or the panel closes), only if it changed; empty
// clears it; Esc takes the edit back. If an action is running the label waits
// its turn (hub.wdAction queues it) and is never dropped. While an action runs
// (or has just succeeded, until the board shows it) every button is dead
// (hub.wdBusy), so none runs twice. There is no "recent lookups" section: the
// Pi keeps no query log per device.
//
// Keyboard stops: "label" (edit), "patch" (blocked, pass), "gate" (300, 1800,
// 3600, or shut), "tactions" (know or forget, close).
TicketFrame {
  id: tk

  required property var jack

  readonly property string mac: jack.mac
  readonly property string name: jack.name
  readonly property real nowS: hub.nowMs / 1000
  readonly property var stateWord: Model.ticketWord(jack, nowS)
  readonly property var gate: Model.gateRow(jack, nowS)
  readonly property var note: Model.jackNote(jack)
  readonly property bool idle: !hub.wdBusy
  readonly property real rowH: Style.space(27)
  readonly property real keyW: Style.space(56)
  readonly property real segRadius: Math.min(Style.cornerRadius, Style.space(3))

  function t(key) { return hub.strings.t(key) }

  component Tx: Text {
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    color: tk.hub.fg
    font.family: tk.hub.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  // A key of the grid: PATCH, GATE.
  component Key: Tx {
    y: Style.space(6)
    color: tk.hub.dim
    font.pixelSize: Style.font.caption
    font.letterSpacing: Style.spaceReal(0.8)
  }

  // ------------------------------------------------------------- the head
  Item {
    width: parent.width
    height: Style.space(14)

    Tx {
      text: tk.t("wd.ticket.line").arg(tk.jack.tail)
      color: tk.hub.dim
      font.pixelSize: Style.font.caption
      font.letterSpacing: Style.spaceReal(0.8)
    }
    Tx {
      anchors.right: parent.right
      text: tk.hub.say(tk.stateWord.word)
      color: {
        switch (tk.stateWord.kind) {
        case "blocked": return tk.hub.accent
        case "pass": return tk.hub.bright
        case "gate": return tk.hub.warning
        default: return tk.hub.muted
        }
      }
      font.pixelSize: Style.font.caption
      font.weight: Font.Bold
      font.letterSpacing: Style.spaceReal(0.8)
    }
  }

  Item { width: 1; height: Style.space(8) }

  // ------------------------------------------------------------ the label
  Item {
    id: labelRow
    width: parent.width
    height: Style.space(25)

    CursorSurface {
      anchors.fill: parent
      anchors.leftMargin: -Style.space(4)
      anchors.rightMargin: -Style.space(4)
      radius: 0
      hasCursor: tk.hub.has("label")
      foreground: tk.hub.fg
      fill: tk.hub.hoverFill
    }

    Tx {
      id: labelKey
      y: field.y + field.baselineOffset - baselineOffset
      text: tk.t("wd.ticket.label")
      color: tk.hub.dim
      font.pixelSize: Style.font.caption
      font.letterSpacing: Style.spaceReal(0.8)
    }

    Item {
      id: box
      x: labelKey.width + Style.space(10)
      width: parent.width - x
      height: parent.height

      TextInput {
        id: field

        // What the Pi knows now (what was sent last, or what the field was
        // given): an edit is sent only when the text differs from it.
        property string sent: ""

        x: 0
        y: Style.space(3)
        width: parent.width
        color: tk.hub.bright
        selectionColor: Util.alpha(tk.hub.accent, 0.35)
        selectedTextColor: tk.hub.bright
        font.family: tk.hub.fontFamily
        font.pixelSize: Style.font.subtitle
        font.weight: Font.Medium
        maximumLength: Model.LABEL_MAX
        selectByMouse: true
        clip: true
        inputMethodHints: Qt.ImhNoPredictiveText

        // Shows the jack's name. `sent` is what the field then holds, not
        // the name: maximumLength cuts a longer one (the CLI takes 64), and
        // an untouched field, or an Esc, must never count as an edit.
        function sync() {
          text = tk.name
          sent = text
        }

        // Sends the edit if there is one. The label is sent or waits its turn
        // behind the action that is running (hub.wdLabel true); if it is
        // refused (the note says busy) the field shows the jack's name again:
        // it never looks saved when it was not sent.
        function commit() {
          if (text === sent) return
          var e = Model.labelEdit(sent, text)
          if (!e.changed) return
          if (tk.hub.wdLabel(tk.mac, text)) sent = e.text
          else sync()
        }

        Component.onCompleted: sync()
        onAccepted: {
          commit()
          focus = false
        }
        onActiveFocusChanged: {
          tk.hub.wdFieldFocus("label", activeFocus)
          if (!activeFocus) commit()
        }
        // Esc cancels: the field goes back to what it had and lets go, and
        // that is no edit (text equals sent), so nothing is sent.
        Keys.onEscapePressed: {
          text = sent
          focus = false
        }
      }

      Text {
        visible: field.text.length === 0
        x: 0
        y: field.y
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: tk.t("wd.label.placeholder")
        color: tk.hub.dim
        font.family: tk.hub.fontFamily
        font.pixelSize: Style.font.subtitle
        font.weight: Font.Medium
      }

      // the line under the field: dim, the accent while it has the keys
      Rectangle {
        y: parent.height - 1
        width: parent.width
        height: 1
        color: field.activeFocus ? tk.hub.accent : tk.hub.dim
      }

      MouseArea {
        id: labelArea
        anchors.fill: parent
        acceptedButtons: Qt.NoButton
        hoverEnabled: true
        onPositionChanged: function(mouse) { tk.hub.hoverCursor(labelArea, mouse, "label", 0) }
      }
    }

    // the jack's name changed under a field that is not being typed in, or
    // the ticket moved to another jack
    Connections {
      target: tk
      function onNameChanged() { if (!field.activeFocus) field.sync() }
      function onMacChanged() { field.sync() }
    }
    // the label row of the keyboard took Enter, or a ticket is closing (or
    // the tab is left, or the panel closes) with the field being typed in; or
    // a label of this device did not get to the Pi
    Connections {
      target: tk.hub
      function onWdLabelFocusRequested() {
        field.forceActiveFocus()
        field.cursorPosition = field.length
      }
      function onWdCommitRequested() { if (field.activeFocus) field.commit() }
      function onWdLabelFailed(mac) { if (mac === tk.mac) field.sync() }
    }
  }

  // --------------------------------------------------------- the meta line
  Item { width: 1; height: Style.space(6) }

  Tx {
    width: parent.width
    wrapMode: Text.Wrap
    text: Model.deviceMeta(tk.jack, tk.hub.timeFmt).map(function(w) { return tk.hub.say(w) }).join(" · ")
    color: tk.hub.dim
    font.pixelSize: Style.font.caption
  }

  Item { width: 1; height: Style.space(10) }

  // ---------------------------------------------- ALWAYS and FIXED: a line
  Tx {
    visible: tk.note !== null
    width: parent.width
    wrapMode: Text.Wrap
    text: tk.note !== null ? tk.hub.say(tk.note) : ""
    color: tk.hub.dim
  }

  // ---------------------------------------------------------- the patch row
  Item {
    id: patchRow
    visible: tk.note === null
    width: parent.width
    height: tk.note === null ? patchFlow.height : 0

    Key { text: tk.t("wd.ticket.patch") }

    Flow {
      id: patchFlow
      x: tk.keyW
      width: parent.width - tk.keyW
      spacing: Style.space(8)

      // the two cords: a segmented key, the active one lit
      Rectangle {
        width: seg.width + 2
        height: tk.rowH
        radius: tk.segRadius
        color: "transparent"
        border.width: 1
        border.color: tk.hub.lineColor
        opacity: tk.idle ? 1 : tk.hub.disabledOpacity

        Row {
          id: seg
          x: 1
          y: 1
          height: parent.height - 2

          Repeater {
            model: ["blocked", "pass"]

            CursorSurface {
              id: sb

              required property string modelData
              required property int index

              readonly property bool on: tk.jack.patch === modelData

              width: label.implicitWidth + Style.space(20)
              height: seg.height
              radius: 0
              hasCursor: tk.hub.has("patch", index)
              foreground: tk.hub.fg
              fill: tk.hub.hoverFill
              color: on || hasCursor ? tk.hub.hoverFill : "transparent"

              Text {
                id: label
                anchors.centerIn: parent
                textFormat: Text.PlainText
                renderType: Text.NativeRendering
                text: sb.modelData === "pass" ? tk.t("wd.rail.pass") : tk.t("wd.rail.blocked")
                color: sb.on || area.containsMouse || sb.hasCursor ? tk.hub.bright : tk.hub.dim
                font.family: tk.hub.fontFamily
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Bold
                font.letterSpacing: Style.spaceReal(0.66)
              }
              Rectangle {
                visible: sb.on
                anchors.bottom: parent.bottom
                width: parent.width
                height: Style.space(2)
                color: tk.hub.accent
              }
              MouseArea {
                id: area
                anchors.fill: parent
                enabled: tk.idle
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onPositionChanged: function(mouse) { tk.hub.hoverCursor(area, mouse, "patch", sb.index) }
                onClicked: tk.hub.wdPatch(tk.mac, sb.modelData)
              }
            }
          }
        }
      }

      // what the state means, and whether the wiring is the normal one
      Item {
        width: patchFlow.width
        height: capText.implicitHeight
        Tx {
          id: capText
          width: parent.width
          wrapMode: Text.Wrap
          text: Model.patchCaption(tk.jack).map(function(w) { return tk.hub.say(w) }).join(" ")
          color: tk.hub.dim
          font.pixelSize: Style.font.caption
        }
      }
    }
  }

  // ----------------------------------------------------------- the gate row
  Item { visible: tk.note === null && tk.gate.show; width: 1; height: tk.note === null && tk.gate.show ? Style.space(10) : 0 }

  Item {
    id: gateRow
    visible: tk.note === null && tk.gate.show
    width: parent.width
    height: visible ? gateFlow.height : 0

    Key { text: tk.t("wd.ticket.gate") }

    Flow {
      id: gateFlow
      x: tk.keyW
      width: parent.width - tk.keyW
      spacing: Style.space(8)

      // already ADS PASS
      Item {
        visible: tk.gate.state === "notNeeded"
        width: notNeeded.implicitWidth
        height: visible ? tk.rowH : 0
        Tx { id: notNeeded; anchors.verticalCenter: parent.verticalCenter; text: tk.t("wd.gate.notNeeded"); color: tk.hub.dim }
      }

      // open: the time left, and the way to shut it
      Item {
        visible: tk.gate.state === "open"
        width: openText.width
        height: visible ? tk.rowH : 0
        Row {
          id: openText
          anchors.verticalCenter: parent.verticalCenter
          Tx { text: tk.t("wd.gate.open"); color: tk.hub.warning; font.weight: Font.Bold }
          Tx { text: tk.t("wd.gate.shutsIn").arg(tk.gate.text) }
        }
      }
      TicketButton {
        hub: tk.hub
        visible: tk.gate.state === "open"
        text: tk.t("wd.gate.shutNow")
        cursorRow: "gate"
        cursorItem: 0
        onClicked: tk.hub.wdGate(tk.mac, 0)
      }

      // shut: for how long to open it
      Item {
        visible: tk.gate.state === "shut"
        width: shutText.implicitWidth
        height: visible ? tk.rowH : 0
        Tx { id: shutText; anchors.verticalCenter: parent.verticalCenter; text: tk.t("wd.gate.shut"); color: tk.hub.dim }
      }
      Repeater {
        model: tk.gate.state === "shut" ? [300, 1800, 3600] : []

        TicketButton {
          hub: tk.hub
          required property int modelData
          required property int index
          text: tk.t("wd.gate.s" + modelData)
          cursorRow: "gate"
          cursorItem: index
          onClicked: tk.hub.wdGate(tk.mac, modelData)
        }
      }
      Item {
        visible: tk.gate.state === "shut"
        width: gateFlow.width
        height: visible ? gateCap.implicitHeight : 0
        Tx {
          id: gateCap
          width: parent.width
          wrapMode: Text.Wrap
          text: tk.t("wd.gate.cap")
          color: tk.hub.dim
          font.pixelSize: Style.font.caption
        }
      }
    }
  }

  // ------------------------------------------------------------- the buttons
  Item { width: 1; height: Style.space(12) }

  Flow {
    width: parent.width
    spacing: Style.space(6)

    TicketButton {
      hub: tk.hub
      kind: "primary"
      visible: Model.deviceActions(tk.jack).indexOf("know") >= 0
      text: tk.t("wd.act.know")
      cursorRow: "tactions"
      cursorItem: 0
      onClicked: tk.hub.wdTicketAction("know")
    }
    TicketButton {
      hub: tk.hub
      kind: "quiet"
      visible: Model.deviceActions(tk.jack).indexOf("forget") >= 0
      text: tk.t("wd.act.forget")
      cursorRow: "tactions"
      cursorItem: 0
      onClicked: tk.hub.wdTicketAction("forget")
    }
    TicketButton {
      hub: tk.hub
      kind: "quiet"
      text: tk.t("wd.act.close")
      cursorRow: "tactions"
      cursorItem: Model.deviceActions(tk.jack).length - 1
      enabled: true
      onClicked: tk.hub.wdTicketAction("close")
    }
  }
}

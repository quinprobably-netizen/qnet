pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The foot of the watchdog tab: the lock on the Pi's own screen.
//
//   Pi screen lock  PIN set                        Change ›   Clear
//   Pi screen lock  no PIN                                    Set ›
//   Pi screen lock  [····]  four digits, kept only as a hash   Set   Cancel
//
// Clear takes the PIN off at once. Set and Change open a field for four
// digits (numbers only, dots on screen): it takes the keys while it is open,
// Enter or Set sends it, Cancel or Esc closes it. The digits are read, the
// field is emptied in the same breath (Panel.wdSubmitPin) and they go to
// `qnet watchdog pin set` on its stdin and nowhere else: not on a command
// line, not in a property that outlives the call, not in a log. Anything but
// exactly four digits is refused here, in words under the footer's hint.
//
// Keyboard stops: "pin" (set, cancel while the field is open; change, clear
// with a PIN; set without).
Item {
  id: foot

  required property var hub

  readonly property bool pinSet: hub.view.watchdog.pinSet
  readonly property bool editing: hub.wdPinOpen
  readonly property real rowH: Style.space(27)

  width: parent ? parent.width : 0
  // a line, 10 of air over it, 8 under it, then 28 for the words
  implicitHeight: Style.space(10) + 1 + Style.space(8) + Style.space(28)
  height: implicitHeight

  function t(key) { return hub.strings.t(key) }

  component Tx: Text {
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    color: foot.hub.fg
    font.family: foot.hub.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  Rectangle {
    y: Style.space(10)
    width: parent.width
    height: 1
    color: foot.hub.lineColor
  }

  Item {
    y: Style.space(10) + 1 + Style.space(8)
    width: parent.width
    height: Style.space(28)

    Tx {
      id: lead
      anchors.verticalCenter: parent.verticalCenter
      text: foot.t("wd.pin.label")
      color: foot.hub.dim
    }

    // at rest: whether there is a PIN
    Tx {
      visible: !foot.editing
      anchors.left: lead.right
      anchors.leftMargin: Style.space(10)
      anchors.verticalCenter: parent.verticalCenter
      text: foot.pinSet ? foot.t("wd.pin.isSet") : foot.t("wd.pin.none")
      color: foot.pinSet ? foot.hub.fg : foot.hub.dim
    }

    // open: the field, and what it wants (the line wraps in the room between
    // the field and the buttons)
    Item {
      id: box
      visible: foot.editing
      anchors.left: lead.right
      anchors.leftMargin: Style.space(10)
      anchors.verticalCenter: parent.verticalCenter
      width: Style.space(84)
      height: Style.space(27)

      Rectangle { anchors.fill: parent; color: foot.hub.well }

      TextInput {
        id: field
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: Style.space(6)
        anchors.rightMargin: Style.space(6)
        anchors.verticalCenter: parent.verticalCenter
        echoMode: TextInput.Password
        passwordCharacter: "\u25CF"
        inputMethodHints: Qt.ImhDigitsOnly | Qt.ImhHiddenText | Qt.ImhNoPredictiveText
        maximumLength: 4
        validator: RegularExpressionValidator { regularExpression: /^[0-9]{0,4}$/ }
        color: foot.hub.fg
        selectionColor: Util.alpha(foot.hub.accent, 0.35)
        selectedTextColor: foot.hub.bright
        font.family: foot.hub.fontFamily
        font.pixelSize: Style.font.body
        font.letterSpacing: Style.spaceReal(3.6)
        clip: true

        onAccepted: foot.hub.wdSubmitPin(field)
        onTextChanged: if (foot.hub.wdPinNote !== "") foot.hub.wdPinNote = ""
        onActiveFocusChanged: foot.hub.wdFieldFocus("pin", activeFocus)
        Keys.onEscapePressed: foot.hub.wdClosePin()
      }

      Text {
        visible: field.text.length === 0
        anchors.left: field.left
        anchors.verticalCenter: parent.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: foot.t("wd.pin.placeholder")
        color: foot.hub.dim
        font.family: foot.hub.fontFamily
        font.pixelSize: Style.font.body
        font.letterSpacing: Style.spaceReal(3.6)
      }

      Rectangle {
        y: parent.height - 1
        width: parent.width
        height: 1
        color: field.activeFocus ? foot.hub.accent : foot.hub.dim
      }
    }

    Tx {
      visible: foot.editing
      anchors.left: box.right
      anchors.leftMargin: Style.space(10)
      anchors.right: buttons.left
      anchors.rightMargin: Style.space(10)
      anchors.verticalCenter: parent.verticalCenter
      wrapMode: Text.Wrap
      text: foot.hub.wdPinNote !== "" ? foot.hub.wdPinNote : foot.t("wd.pin.hint")
      color: foot.hub.wdPinNote !== "" ? foot.hub.urgent : foot.hub.dim
      font.pixelSize: Style.font.caption
    }

    // the field opens with the keys, and is empty each time it opens or closes
    Connections {
      target: foot
      function onEditingChanged() {
        field.text = ""
        if (foot.editing) Qt.callLater(function() { if (foot.editing) field.forceActiveFocus() })
      }
    }
    Connections {
      target: foot.hub
      function onWdPinSubmitRequested() { if (foot.editing) foot.hub.wdSubmitPin(field) }
    }

    Row {
      id: buttons
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(6)

      TicketButton {
        hub: foot.hub
        visible: !foot.editing && foot.pinSet
        kind: "quiet"
        text: foot.t("wd.pin.change")
        cursorRow: "pin"
        cursorItem: 0
        onClicked: foot.hub.wdPinAction("change")
      }
      TicketButton {
        hub: foot.hub
        visible: !foot.editing && foot.pinSet
        kind: "quiet"
        text: foot.t("wd.pin.clear")
        cursorRow: "pin"
        cursorItem: 1
        onClicked: foot.hub.wdPinAction("clear")
      }
      TicketButton {
        hub: foot.hub
        visible: !foot.editing && !foot.pinSet
        kind: "quiet"
        text: foot.t("wd.pin.setMore")
        cursorRow: "pin"
        cursorItem: 0
        onClicked: foot.hub.wdPinAction("set")
      }
      TicketButton {
        hub: foot.hub
        visible: foot.editing
        text: foot.t("wd.pin.set")
        cursorRow: "pin"
        cursorItem: 0
        onClicked: foot.hub.wdPinAction("set")
      }
      TicketButton {
        hub: foot.hub
        visible: foot.editing
        kind: "quiet"
        text: foot.t("wd.pin.cancel")
        enabled: true
        cursorRow: "pin"
        cursorItem: 1
        onClicked: foot.hub.wdPinAction("cancel")
      }
    }
  }
}

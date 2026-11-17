pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The trouble ticket of one call, open under the calls waiting (a click or
// Enter on its row, on a lit window of the lamp row or on a jack's drop
// lamp):
//
//   TROUBLE TICKET
//   [lamp] THREAT BLOCKED   high · ×3 · 13:58 – 14:02
//   malware.example.org                         the subject
//   asked by Living room TV · 192.0.2.40        who it is about
//   A name on the threat list was asked ...     what the kind says
//   [Dismiss]  Mark known  Open device ›
//   Dismissing here clears it on the Pi's screen too.
//
// Dismiss clears the call on the Pi's screen as well (`ack`). Mark known is
// offered for a new device whose jack is not on this PC's list yet. "Open
// device ›" switches to that jack's ticket: the jack the call rings, or for
// an ARP spoof the jack of the second card. A call that rings no jack says
// so. Every word is Model's (callTitle, callMeta, callSubject, callWho,
// callWhy, alertActions); this only lays them out.
//
// Keyboard stops: "tactions" (dismiss, know, open).
TicketFrame {
  id: tk

  required property var call

  readonly property var wd: hub.view
  readonly property color tone: call.tone === "high" ? hub.urgent : hub.warning
  readonly property var actions: Model.alertActions(wd, call)
  readonly property var target: Model.alertOpenTarget(wd, call)
  // a paragraph is at most 56 characters wide, as in the mockup
  readonly property real paragraphW: Math.min(width - 2 * sideGap, 56 * charW.advanceWidth)

  function t(key) { return hub.strings.t(key) }
  function says(words) { return words.map(function(w) { return hub.say(w) }) }

  TextMetrics {
    id: charW
    text: "0"
    font.family: tk.hub.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  component Tx: Text {
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    color: tk.hub.fg
    font.family: tk.hub.fontFamily
    font.pixelSize: Style.font.bodySmall
  }

  Tx {
    text: tk.t("wd.ticket.alert")
    color: tk.hub.dim
    font.pixelSize: Style.font.caption
    font.letterSpacing: Style.spaceReal(0.8)
  }

  Item { width: 1; height: Style.space(8) }

  // the lamp, the title in capitals, and what it was
  Flow {
    width: parent.width
    spacing: Style.space(8)

    Item {
      width: Style.space(8)
      height: Style.space(17)
      Rectangle {
        anchors.verticalCenter: parent.verticalCenter
        width: Style.space(8)
        height: Style.space(5)
        color: tk.tone
      }
    }
    Tx {
      text: tk.hub.say(Model.callTitle(tk.call))
      color: tk.tone
      font.pixelSize: Style.font.body
      font.weight: Font.Bold
      font.letterSpacing: Style.spaceReal(0.96)
    }
    Item {
      height: Style.space(17)
      width: meta.implicitWidth
      Tx {
        id: meta
        anchors.verticalCenter: parent.verticalCenter
        text: tk.says(Model.callMeta(tk.call, tk.hub.timeFmt)).join(" · ")
        color: tk.hub.dim
        font.pixelSize: Style.font.caption
      }
    }
  }

  Item { width: 1; height: Style.space(8) }

  Tx {
    width: parent.width
    wrapMode: Text.WrapAnywhere
    text: tk.hub.say(Model.callSubject(tk.wd, tk.call))
    color: tk.hub.bright
    font.pixelSize: Style.font.subtitle
    font.weight: Font.Medium
  }

  Item { width: 1; height: Style.space(2) }

  Tx {
    width: parent.width
    wrapMode: Text.Wrap
    text: tk.hub.say(Model.callWho(tk.wd, tk.call))
    color: tk.hub.dim
  }

  Item { width: 1; height: Style.space(8) }

  Tx {
    width: tk.paragraphW
    wrapMode: Text.Wrap
    text: tk.says(Model.callWhy(tk.wd, tk.call, tk.hub.timeFmt)).join(" ")
  }

  Item { width: 1; height: Style.space(12) }

  Flow {
    width: parent.width
    spacing: Style.space(6)

    TicketButton {
      hub: tk.hub
      kind: "primary"
      visible: tk.actions.indexOf("dismiss") >= 0
      text: tk.t("wd.act.dismiss")
      cursorRow: "tactions"
      cursorItem: tk.actions.indexOf("dismiss")
      onClicked: tk.hub.wdTicketAction("dismiss")
    }
    TicketButton {
      hub: tk.hub
      visible: tk.actions.indexOf("know") >= 0
      text: tk.t("wd.act.know")
      cursorRow: "tactions"
      cursorItem: tk.actions.indexOf("know")
      onClicked: tk.hub.wdTicketAction("know")
    }
    TicketButton {
      hub: tk.hub
      kind: "quiet"
      visible: tk.actions.indexOf("open") >= 0
      text: tk.target !== null ? tk.hub.say(tk.target.label) : ""
      cursorRow: "tactions"
      cursorItem: tk.actions.indexOf("open")
      onClicked: tk.hub.wdTicketAction("open")
    }
  }

  Item { width: 1; height: Style.space(8) }

  Tx {
    text: tk.t("wd.alert.sync")
    color: tk.hub.dim
    font.pixelSize: Style.font.caption
  }
}

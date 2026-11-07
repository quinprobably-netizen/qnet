pragma ComponentBehavior: Bound
import QtQuick
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The hero: one line of words over the route (HeroViz.qml). The picture is
// its own piece (it takes the view and exposes its height) and can change
// without touching anything here. The route is also the navigation: its AP
// node opens the Wi-Fi view and the Pi-hole's node the DNS view.
//
// The line: the state word a step under the connection's name, then what the
// route cannot say ("blocking" or, urgent, "not blocking", from the canary; a
// certificate that changed), then the one thing to do if something is wrong:
//   - the API refuses the sign-in: "Sign in again ›" (runs setup)
//   - no DNS servers: "Use Pi-hole ›"
//   - queries can skip the Pi-hole: "Pin ›"
//   - nothing set up: "Set up Pi-hole ›", under the dashed node that stands
//     where the Pi-hole would be (the route draws the node; the button is here)
// and on the right the day's queries as a figure in the bar font at title
// size (Sound Hub's numerals), dim and with its age while the link is down.
// Where the Pi-hole is, what its latency is and who it forwards to are on the
// route, not in words.
Item {
  id: hero

  required property var hub

  readonly property var info: hub.hero
  readonly property var pihole: hub.view.pihole
  readonly property var today: pihole.today

  // How far the picture reaches past the content column: the card's padding,
  // out to its border.
  readonly property int bleed: Style.spacing.popupPadding
  readonly property int textX: bleed + hub.gutter

  readonly property real textZone: Style.space(10) + Math.max(word.implicitHeight, figure.height) + Style.space(6)

  x: -bleed
  width: (parent ? parent.width : 0) + 2 * bleed
  height: textZone - viz.overlap + viz.implicitHeight

  function t(key) { return hub.strings.t(key) }

  function toneColor(tone) {
    if (tone === "accent") return hub.accent
    if (tone === "warning") return hub.warning
    if (tone === "urgent") return hub.urgent
    return hub.dim
  }

  // ------------------------------------------------------------ picture
  HeroViz {
    id: viz
    y: hero.textZone - overlap
    width: hero.width
    view: hero.hub.view
    nowS: hero.hub.nowMs / 1000
    frozen: hero.info.desaturated
    animate: hero.hub.opened
    accent: hero.hub.accent
    fg: hero.hub.fg
    dim: hero.hub.dim
    urgent: hero.hub.urgent
    warning: hero.hub.warning
    fontFamily: hero.hub.fontFamily
    fontSize: hero.hub.typeSmall
    tr: hero.hub.strings.t
    leftInset: hero.textX
    rightInset: hero.textX
    pending: hero.hub.pending
    cursorNode: hero.hub.routeCursorNode
    cursorPointer: hero.hub.cursorPointer
    visible: hero.info.kind !== "nobackend"
    // The route is the navigation: the AP opens Wi-Fi, the Pi-hole's place DNS.
    onNodeMoved: function(id, area, mouse) { hero.hub.hoverCursor(area, mouse, "route", hero.hub.routeStops.indexOf(id)) }
    onNodeClicked: function(id) { hero.hub.openRouteNode(id) }
  }

  // The place the route offers setup: a button under the dashed node.
  TextButton {
    visible: viz.visible && viz.ghost && hero.info.action === "setup"
    hub: hero.hub
    x: viz.ghostRect.x + (viz.ghostRect.width - width) / 2
    y: viz.y + viz.ghostRect.y + (viz.ghostRect.height - height) / 2
    padX: Style.space(8)
    padY: Style.space(3)
    text: hero.t("hero.setup") + " ›"
    textColor: hero.hub.accent
    weight: Font.DemiBold
    cursorRow: "hero"
    cursorItem: 0
    onClicked: hero.hub.heroAction()
  }

  // -------------------------------------------------------------- words
  readonly property string wordText: {
    switch (info.kind) {
    case "pihole": return t("hero.pihole")
    case "paused": return info.pauseS > 0 ? t("hero.paused").arg(Model.formatCountdown(info.pauseS)) : t("hero.pausedPlain")
    case "degraded": return t("hero.degraded")
    case "fallback": return t("hero.fallback").arg(t("fallback." + info.fallback))
    case "bypassed": return t("hero.bypassed")
    case "unreachable": return t("hero.unreachable")
    case "none": return t("hero.none")
    case "checking": return t("hero.checking")
    case "custom": return t("hero.custom")
    case "offline": return t("hero.offline")
    case "nobackend": return t("hero.nobackend")
    default: return t("hero.router")
    }
  }

  // What follows the word, as [{ text, tone }].
  readonly property var subParts: {
    var out = []
    if (info.apiIssue !== "" && info.apiIssue !== "auth") out.push({ text: t("hero.api." + info.apiIssue), tone: "urgent" })
    if (info.blocking === "blocking") out.push({ text: t("hero.blocking"), tone: "dim" })
    else if (info.blocking === "notBlocking") out.push({ text: t("hero.notBlocking"), tone: "urgent" })
    if (info.kind === "nobackend") out.push({ text: t("hero.nobackendHint"), tone: "dim" })
    return out
  }

  // The corrective step on the line itself (setup is on the route).
  readonly property string actionText: {
    switch (info.action) {
    case "signin": return t("hero.signIn") + " ›"
    case "usepihole": return t("hero.usePihole") + " ›"
    case "pin": return t("leak.pin") + " ›"
    default: return ""
    }
  }
  readonly property color actionColor: info.action === "usepihole" ? hub.accent : hub.urgent

  readonly property bool showCount: pihole.configured && !hub.view.backendDown && today.total > 0
  readonly property bool stale: info.frozen && hub.statsAgeText !== ""

  Row {
    id: line
    x: hero.textX
    y: Style.space(10)
    spacing: 0

    Text {
      id: word
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: hero.wordText
      color: hero.toneColor(hero.info.tone)
      font.family: hero.hub.fontFamily
      font.pixelSize: hero.hub.typeHero
      font.weight: Font.DemiBold
      Behavior on color { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(120) } }
    }

    Repeater {
      model: hero.subParts
      Text {
        id: sub
        required property var modelData
        anchors.verticalCenter: word.verticalCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: "   " + sub.modelData.text
        color: hero.toneColor(sub.modelData.tone)
        font.family: hero.hub.fontFamily
        font.pixelSize: hero.hub.typeSmall
      }
    }

    // The one thing to do about it.
    TextButton {
      visible: hero.actionText !== ""
      hub: hero.hub
      anchors.verticalCenter: word.verticalCenter
      padX: Style.space(6)
      padY: Style.space(1)
      text: hero.actionText
      textColor: hero.actionColor
      weight: Font.DemiBold
      cursorRow: "hero"
      cursorItem: 0
      onClicked: hero.hub.heroAction()
    }
  }

  // ------------------------------------------------------------ numbers
  // The query count as a figure, in Sound Hub's numeral style: the bar font,
  // title size, Medium where the family has it; its unit small and dim.
  Item {
    id: figure
    visible: hero.showCount
    anchors.right: parent.right
    anchors.rightMargin: hero.textX
    y: Style.space(10)
    width: figureNumber.implicitWidth + Style.space(5) + figureUnit.implicitWidth + (hero.stale ? figureAge.implicitWidth : 0)
    height: hero.showCount ? figureNumber.implicitHeight : 0

    Text {
      id: figureNumber
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: Model.formatCount(hero.today.total, hero.hub.formatInt)
      color: hero.info.frozen ? hero.hub.dim : hero.hub.fg
      font.family: hero.hub.fontFamily
      font.pixelSize: hero.hub.typeTitle
      font.weight: Font.Medium
    }
    Text {
      id: figureUnit
      anchors.left: figureNumber.right
      anchors.leftMargin: Style.space(5)
      anchors.baseline: figureNumber.baseline
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: hero.hub.strings.tn("hero.queryWord", hero.today.total)
      color: hero.hub.dim
      font.family: hero.hub.fontFamily
      font.pixelSize: hero.hub.typeSmall
    }
    // Old numbers say how old.
    Text {
      id: figureAge
      visible: hero.stale
      anchors.left: figureUnit.right
      anchors.baseline: figureNumber.baseline
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: " · " + hero.hub.statsAgeText
      color: hero.hub.dim
      font.family: hero.hub.fontFamily
      font.pixelSize: hero.hub.typeSmall
    }
  }

  // The hero is not a button; its tooltip says what the picture is.
  MouseArea {
    id: tipArea
    anchors.fill: parent
    z: -1
    hoverEnabled: true
    acceptedButtons: Qt.NoButton
    PanelToolTip {
      visible: tipArea.containsMouse && viz.visible && viz.hoveredId === ""
      text: hero.t("hero.tip") + (hero.today.selfQueries > 0 ? "\n" + hero.t("hero.tipSelf").arg(hero.today.selfQueries) : "")
      fontFamily: hero.hub.fontFamily
    }
  }
}

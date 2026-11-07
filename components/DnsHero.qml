pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons
import qs.Commons as Commons
import "../Model.js" as Model

// The panel's identity: the Pi-hole's day of DNS queries as a plasma area
// graph, a sibling of Sound Hub's spectrum header. No box, no grid, no rules:
// the graph runs full bleed across the card and its crest comes up to the
// foot of the state word and the numbers.
//
//  - total queries: a gradient fill that shifts hue down its height (accent
//    leaning toward magenta at the crest, toward blue at the foot) under a
//    rim-lit edge
//  - blocked queries: a brighter accent band along the floor, on the same
//    scale, so the share of the area it fills is the share blocked
//  - the x-axis fits the history there is: three hours at least, a day at
//    most, right-anchored on now. A Pi-hole installed an hour and a half ago
//    draws a hill on the right, nothing on the left, and a small dim "last
//    1.5 h" says so. Where the data is zero nothing is stroked.
//  - one head dot at the graph's right edge, inside the gutter, breathes
//    while the Pi-hole answers its probes; when it does not it is a hollow
//    urgent ring and still. It is the only thing here that moves.
//  - unreachable, or the Pi-hole's API failing: the graph stays, frozen and
//    desaturated, and the state word says what is wrong
//  - not configured: no graph, and "Set up ›" (with the Pi-hole detected on
//    the LAN named, as a candidate and nothing more) in its place
//
// Over the graph, top left: the state word, a step under the connection's
// name, with one line under it ("via 192.168.1.153 · 8 ms · blocking": the
// latency urgent only when slow, the last word urgent as "not blocking" when
// the canary says so). Top right: the day's queries and blocked share. Under
// the graph, one quiet line: how much history this is on the left, and on the
// right "Pause blocking 5m" (or "Resume 4:32") and "Admin ›".
Item {
  id: hero

  required property var hub

  readonly property var info: hub.hero
  readonly property var series: hub.historySeries
  readonly property var head: hub.probeHead
  readonly property bool frozen: info.frozen
  readonly property var pihole: hub.view.pihole

  // How far the graph reaches past the content column: the card's padding,
  // out to its border.
  readonly property int bleed: Style.spacing.popupPadding
  readonly property int textX: bleed + hub.gutter
  readonly property int quietPad: Style.space(6)

  // Zones: text on top, the plot under it, one quiet line under the plot.
  readonly property real rightHeight: counts.visible ? counts.height : 0
  readonly property real leftHeight: word.implicitHeight + Style.space(2) + subLine.height
  readonly property real textZone: Style.space(10) + Math.max(leftHeight, rightHeight) + Style.space(6)
  readonly property real plotBelow: Style.space(98)
  // The plot's top reaches a little into the text zone's last line, so the
  // crest meets the words; the words that low carry a halo.
  readonly property real ceilingY: textZone - Style.space(14)
  readonly property real floorY: ceilingY + plotBelow
  readonly property real footerH: showFooter ? Style.space(26) : 0
  // The graph ends inside the right gutter, not at the card's edge.
  readonly property real graphRight: width - Style.space(16)

  x: -bleed
  width: (parent ? parent.width : 0) + 2 * bleed
  height: floorY + footerH + Style.space(4)

  // ------------------------------------------------------------ colours
  // The theme's accent with plasma in it: more saturation, a second hue
  // stop, the crest leaning round the colour wheel. Frozen, it is the plain
  // foreground and everything fades.
  function shifted(c, dHue, sat, light, satFloor) {
    var h = c.hslHue < 0 ? 0 : c.hslHue
    var s = c.hslSaturation < 0.08 ? c.hslSaturation : Math.min(1, Math.max(satFloor, c.hslSaturation * sat))
    return Qt.hsla((h + dHue + 1) % 1, s, Math.min(0.78, c.hslLightness * light), c.a)
  }

  property color baseColor: frozen ? hub.fg : shifted(hub.accent, 0, 1.15, 1.0, 0.5)
  property color crestColor: frozen ? hub.fg : shifted(hub.accent, 0.09, 1.2, 1.15, 0.6)
  property color footColor: frozen ? hub.fg : shifted(hub.accent, -0.07, 1.2, 0.9, 0.55)
  property color bandColor: frozen ? hub.fg : shifted(hub.accent, 0.025, 1.1, 1.3, 0.6)
  readonly property real fillTop: frozen ? 0.22 : 0.62
  readonly property real bandTop: frozen ? 0.3 : 0.9
  readonly property real rimAlpha: frozen ? 0.34 : 0.95
  Behavior on baseColor { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(160) } }
  Behavior on crestColor { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(160) } }
  Behavior on footColor { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(160) } }
  Behavior on bandColor { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(160) } }

  // A halo of the card's colour for the small words the crest can reach.
  readonly property color halo: Util.alpha(Commons.Color.popups.background, 0.85)

  function toneColor(tone) {
    if (tone === "accent") return hub.accent
    if (tone === "warning") return hub.warning
    if (tone === "urgent") return hub.urgent
    return hub.dim
  }

  // --------------------------------------------------------------- text
  function t(key) { return hub.strings.t(key) }

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

  // The line under the word, as [{ text, tone }] joined with " · ".
  readonly property var subParts: {
    var out = []
    var k = info.kind
    var fmt = hub.formatNumber
    if (k === "pihole" || k === "paused" || k === "bypassed" || k === "degraded") {
      if (info.via !== "") out.push({ text: t("hero.via").arg(info.via), tone: "dim" })
      if (info.latencyMs !== null) out.push({ text: Model.formatLatency(info.latencyMs, fmt), tone: info.latencyBad ? "urgent" : "dim" })
      if (info.apiIssue !== "") out.push({ text: t("hero.api." + info.apiIssue), tone: "urgent" })
      if (k === "degraded") out.push({ text: t("hero.upstream"), tone: "warning" })
      if (info.blocking === "blocking") out.push({ text: t("hero.blocking"), tone: "dim" })
      else if (info.blocking === "notBlocking") out.push({ text: t("hero.notBlocking"), tone: "urgent" })
    } else if (k === "fallback") {
      if (info.via !== "") out.push({ text: t("hero.via").arg(info.via), tone: "dim" })
      out.push({ text: t("hero.piholeDown"), tone: "warning" })
    } else if (k === "unreachable") {
      if (info.via !== "") out.push({ text: info.via, tone: "dim" })
      out.push({ text: t("hero.noAnswer"), tone: "urgent" })
    } else if (k === "none") {
      if (info.resolvedFallback !== "") out.push({ text: t("hero.resolvedFallback").arg(info.resolvedFallback), tone: "urgent" })
    } else if ((k === "router" || k === "custom") && info.via !== "") {
      out.push({ text: t("hero.via").arg(info.via), tone: "dim" })
    } else if (k === "nobackend") {
      out.push({ text: t("hero.nobackendHint"), tone: "dim" })
    }
    return out
  }

  readonly property var today: pihole.today
  readonly property bool showCounts: pihole.configured && !hub.view.backendDown && (today.total > 0 || series !== null)
  readonly property bool showActions: pihole.configured && !hub.view.backendDown

  Text {
    id: word
    x: hero.textX
    y: Style.space(10)
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: hero.wordText
    color: hero.toneColor(hero.info.tone)
    font.family: hero.hub.fontFamily
    font.pixelSize: hero.hub.typeHero
    font.weight: Font.DemiBold
    Behavior on color { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(120) } }
  }

  Row {
    id: subLine
    x: hero.textX
    y: word.y + word.implicitHeight + Style.space(2)
    height: subMetrics.height
    FontMetrics { id: subMetrics; font.family: hero.hub.fontFamily; font.pixelSize: hero.hub.typeSmall }

    Repeater {
      model: hero.subParts
      Row {
        id: part
        required property var modelData
        required property int index
        Text {
          visible: part.index > 0
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: " · "
          color: hero.hub.dim
          font.family: hero.hub.fontFamily
          font.pixelSize: hero.hub.typeSmall
          style: Text.Outline
          styleColor: hero.halo
        }
        Text {
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: part.modelData.text
          color: hero.toneColor(part.modelData.tone)
          font.family: hero.hub.fontFamily
          font.pixelSize: hero.hub.typeSmall
          style: Text.Outline
          styleColor: hero.halo
        }
      }
    }
  }

  Column {
    id: counts
    visible: hero.showCounts
    anchors.right: parent.right
    anchors.rightMargin: hero.textX
    y: word.y
    Text {
      anchors.right: parent.right
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: hero.hub.strings.tn("hero.queries", hero.today.total).arg(Model.formatCount(hero.today.total, hero.hub.formatInt))
      color: hero.frozen ? hero.hub.dim : hero.hub.fg
      font.family: hero.hub.fontFamily
      font.pixelSize: hero.hub.typeBody
    }
    Text {
      anchors.right: parent.right
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: hero.t("hero.blocked").arg(Model.formatPercent(hero.today.percent, hero.hub.formatNumber))
      color: hero.hub.dim
      font.family: hero.hub.fontFamily
      font.pixelSize: hero.hub.typeSmall
      style: Text.Outline
      styleColor: hero.halo
    }
  }

  // ------------------------------------------------------------- graph
  function toPoints(list) {
    var out = []
    for (var i = 0; i < list.length; i++) out.push(Qt.point(list[i].x, list[i].y))
    return out
  }

  function toRuns(runs) {
    var out = []
    for (var i = 0; i < runs.length; i++) out.push(toPoints(runs[i]))
    return out
  }

  readonly property real plotH: floorY - ceilingY
  readonly property var totalPlain: series && width > 0 ? Model.smoothEdge(series.total, 0, graphRight, floorY, plotH, 6) : []
  readonly property var blockedPlain: series && width > 0 ? Model.smoothEdge(series.blocked, 0, graphRight, floorY, plotH, 6) : []
  readonly property var totalEdge: toPoints(totalPlain)
  readonly property var blockedEdge: toPoints(blockedPlain)
  // Strokes only where there is something standing off the floor.
  readonly property var totalRuns: toRuns(Model.strokeRuns(totalPlain, floorY, 1.2))
  readonly property var blockedRuns: toRuns(Model.strokeRuns(blockedPlain, floorY, 1.2))
  readonly property point totalFirst: totalEdge.length ? totalEdge[0] : Qt.point(0, floorY)
  readonly property point totalLast: totalEdge.length ? totalEdge[totalEdge.length - 1] : Qt.point(0, floorY)
  readonly property point blockedFirst: blockedEdge.length ? blockedEdge[0] : Qt.point(0, floorY)
  readonly property point blockedLast: blockedEdge.length ? blockedEdge[blockedEdge.length - 1] : Qt.point(0, floorY)

  // The head: at the graph's right edge, on the newest value.
  readonly property real headX: graphRight
  readonly property real headY: totalPlain.length ? totalPlain[totalPlain.length - 1].y : floorY
  readonly property bool headOk: head.ok === true
  readonly property bool headFailed: head.ok === false

  readonly property bool showSpan: series !== null && Model.showSpanLabel(hub.historySpan)

  Item {
    id: face
    anchors.fill: parent
    visible: !hero.info.empty

    // The area under the total, one simple closed path.
    Shape {
      anchors.fill: parent
      visible: hero.totalEdge.length > 0
      preferredRendererType: Shape.GeometryRenderer
      asynchronous: true
      layer.enabled: true
      layer.samples: 4
      layer.smooth: true
      layer.textureSize: Qt.size(Math.ceil(width) * 2, Math.ceil(height) * 2)

      ShapePath {
        strokeWidth: -1
        strokeColor: "transparent"
        fillRule: ShapePath.WindingFill
        fillGradient: LinearGradient {
          x1: 0; y1: hero.ceilingY
          x2: 0; y2: hero.floorY
          GradientStop { position: 0; color: Util.alpha(hero.crestColor, hero.fillTop) }
          GradientStop { position: 0.5; color: Util.alpha(hero.baseColor, hero.fillTop * 0.62) }
          GradientStop { position: 1; color: Util.alpha(hero.footColor, hero.fillTop * 0.16) }
        }
        startX: hero.totalFirst.x
        startY: hero.totalFirst.y
        PathPolyline { path: hero.totalEdge }
        PathLine { x: hero.totalLast.x; y: hero.floorY }
        PathLine { x: hero.totalFirst.x; y: hero.floorY }
        PathLine { x: hero.totalFirst.x; y: hero.totalFirst.y }
      }
    }

    // The brighter band: what was blocked, along the floor.
    Shape {
      anchors.fill: parent
      visible: hero.blockedEdge.length > 0
      preferredRendererType: Shape.GeometryRenderer
      asynchronous: true
      layer.enabled: true
      layer.samples: 4
      layer.smooth: true
      layer.textureSize: Qt.size(Math.ceil(width) * 2, Math.ceil(height) * 2)

      ShapePath {
        strokeWidth: -1
        strokeColor: "transparent"
        fillRule: ShapePath.WindingFill
        fillGradient: LinearGradient {
          x1: 0; y1: hero.floorY - hero.plotH * 0.5
          x2: 0; y2: hero.floorY
          GradientStop { position: 0; color: Util.alpha(hero.bandColor, hero.bandTop) }
          GradientStop { position: 1; color: Util.alpha(hero.bandColor, hero.bandTop * 0.45) }
        }
        startX: hero.blockedFirst.x
        startY: hero.blockedFirst.y
        PathPolyline { path: hero.blockedEdge }
        PathLine { x: hero.blockedLast.x; y: hero.floorY }
        PathLine { x: hero.blockedFirst.x; y: hero.floorY }
        PathLine { x: hero.blockedFirst.x; y: hero.blockedFirst.y }
      }
    }

    // The rim light along the crest, and a finer one on the band.
    Shape {
      anchors.fill: parent
      visible: hero.totalRuns.length > 0
      preferredRendererType: Shape.CurveRenderer
      asynchronous: true
      ShapePath {
        fillColor: "transparent"
        strokeWidth: 1.4
        strokeColor: Util.alpha(Qt.lighter(hero.crestColor, 1.15), hero.rimAlpha)
        joinStyle: ShapePath.RoundJoin
        capStyle: ShapePath.RoundCap
        PathMultiline { paths: hero.totalRuns }
      }
      ShapePath {
        fillColor: "transparent"
        strokeWidth: 1
        strokeColor: Util.alpha(Qt.lighter(hero.bandColor, 1.2), hero.rimAlpha * 0.85)
        joinStyle: ShapePath.RoundJoin
        capStyle: ShapePath.RoundCap
        PathMultiline { paths: hero.blockedRuns }
      }
    }

    // The head: solid while the Pi-hole answers, a hollow urgent ring when it
    // does not.
    Rectangle {
      id: dot
      visible: hero.series !== null && hero.head.ok !== null
      width: Style.space(7)
      height: width
      radius: width / 2
      x: hero.headX - width / 2
      y: hero.headY - height / 2
      color: hero.headFailed ? "transparent" : Qt.lighter(hero.crestColor, 1.5)
      border.width: hero.headFailed ? 1.5 : 0
      border.color: hero.hub.urgent
    }

    // It breathes, slowly: a ring that opens out of the dot and fades. The
    // only motion on the panel; still when the Pi-hole is not answering, or
    // when animations are off.
    Rectangle {
      id: breath
      visible: dot.visible && hero.headOk
      width: dot.width
      height: width
      radius: width / 2
      x: dot.x
      y: dot.y
      color: "transparent"
      border.width: 1
      border.color: Qt.lighter(hero.crestColor, 1.5)
      opacity: 0
      SequentialAnimation {
        running: breath.visible && hero.hub.opened && !Style.reduceMotion && !hero.frozen
        loops: Animation.Infinite
        ParallelAnimation {
          NumberAnimation { target: breath; property: "scale"; from: 1; to: 3; duration: Style.duration(1600); easing.type: Easing.OutCubic }
          NumberAnimation { target: breath; property: "opacity"; from: 0.7; to: 0; duration: Style.duration(1600); easing.type: Easing.OutCubic }
        }
        PauseAnimation { duration: Style.duration(500) }
      }
    }
  }

  // ------------------------------------------------------------ footer
  readonly property bool showFooter: showActions || showSpan

  // How much history the graph holds, while that is less than a day.
  Text {
    id: spanLabel
    visible: hero.showSpan
    x: hero.textX
    y: hero.floorY + Style.space(6)
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: hero.t("hero.last").arg(Model.formatSpan(hero.hub.historySpan, hero.hub.formatNumber))
    color: Util.alpha(hero.hub.fg, 0.45)
    font.family: hero.hub.fontFamily
    font.pixelSize: hero.hub.typeSmall
  }

  // The two quiet actions, their words ending on the same right edge as the
  // numbers above the graph do.
  Row {
    id: actions
    visible: hero.showActions
    anchors.right: parent.right
    anchors.rightMargin: hero.textX - hero.quietPad
    y: hero.floorY + Style.space(2)
    spacing: Style.space(2)

    TextButton {
      hub: hero.hub
      padX: hero.quietPad
      padY: Style.space(4)
      enabled: hero.hub.chip.enabled
      text: hero.hub.chip.mode === "resume"
        ? (hero.hub.chip.remainingS > 0 ? hero.t("dns.resume").arg(Model.formatCountdown(hero.hub.chip.remainingS)) : hero.t("dns.resumePlain"))
        : hero.t("dns.pause")
      textColor: hero.hub.dim
      hotColor: hero.hub.fg
      cursorRow: "hero"
      cursorItem: hero.hub.heroItems.indexOf("pause")
      tipText: hero.hub.chip.mode === "resume" ? hero.t("dns.resumeTip") : hero.t("dns.pauseTip")
      onClicked: hero.hub.togglePause()
    }

    TextButton {
      visible: hero.hub.heroItems.indexOf("admin") >= 0
      hub: hero.hub
      padX: hero.quietPad
      padY: Style.space(4)
      text: hero.t("dns.admin") + " \u203a"
      textColor: hero.hub.dim
      hotColor: hero.hub.fg
      cursorRow: "hero"
      cursorItem: hero.hub.heroItems.indexOf("admin")
      onClicked: hero.hub.openAdmin()
    }
  }

  // Not set up: the way to do it, in the graph's place. A Pi-hole found on
  // the LAN is named as such; setup itself asks for the address.
  Row {
    id: setupRow
    visible: hero.info.setup && hero.info.kind !== "nobackend"
    x: hero.textX - (hero.info.detected !== "" ? 0 : Style.space(8))
    y: hero.ceilingY + (hero.plotBelow - implicitHeight) / 2
    spacing: 0

    Text {
      visible: hero.info.detected !== ""
      anchors.verticalCenter: parent.verticalCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: hero.t("hero.detected").arg(hero.info.detected) + "  "
      color: hero.hub.dim
      font.family: hero.hub.fontFamily
      font.pixelSize: hero.hub.typeSmall
    }

    TextButton {
      hub: hero.hub
      anchors.verticalCenter: parent.verticalCenter
      padX: Style.space(8)
      padY: Style.space(6)
      size: hero.hub.typeBody
      text: (hero.info.detected !== "" ? hero.t("hero.setupShort") : hero.t("hero.setup")) + " ›"
      textColor: hero.hub.accent
      cursorRow: "hero"
      cursorItem: 0
      onClicked: hero.hub.setup()
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
      visible: tipArea.containsMouse && hero.totalEdge.length > 0
      text: hero.today.selfQueries > 0
        ? hero.t("hero.tip") + "\n" + hero.t("hero.tipSelf").arg(hero.today.selfQueries)
        : hero.t("hero.tip")
      fontFamily: hero.hub.fontFamily
    }
  }
}

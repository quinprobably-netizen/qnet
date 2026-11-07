pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// The panel's identity: the last 24 hours of DNS queries as a plasma-accent
// area graph, a sibling of Sound Hub's spectrum header. No box and no grid:
// the graph runs full bleed across the card, with the state word and the
// day's numbers set over the empty top of it.
//
//  - total queries: a gradient fill under a soft accent edge
//  - blocked queries: a brighter band along the bottom of the same area, on
//    the same scale (the share of the area it fills is the share blocked)
//  - the live edge: the right-hand sixth is "now". A hairline marks where
//    the 24 h end, and in the room beyond it the Pi-hole's last five minutes
//    of health probes draw as a thin pulse line whose head is the newest
//    probe. A failed probe is a gap in the line. The head
//    rings once when a new probe lands (only after the panel has settled).
//  - unreachable, or the Pi-hole's API failing: the graph stays, frozen and
//    desaturated, and the state word says what is wrong
//  - not configured: no graph, and "Set up Pi-hole ›" in its place
//
// Over the graph, top left: the state word (title size) with one line under
// it ("via 192.168.1.153 · 3 ms", latency urgent only when it is slow or
// probes fail). Top right: the day's query count and blocked share.
Item {
  id: hero

  required property var hub

  readonly property var info: hub.hero
  readonly property var series: hub.historySeries
  readonly property var live: hub.probeLive
  readonly property bool frozen: info.frozen

  // How far the graph reaches past the content column: the card's padding,
  // out to its border.
  readonly property int bleed: Style.spacing.popupPadding
  readonly property int textX: bleed + hub.gutter

  // Zones: text on top (the graph never enters it), the plot under.
  readonly property real textZone: Style.space(10) + word.implicitHeight + Style.space(2) + subLine.implicitHeight + Style.space(10)
  readonly property real plotDepth: Style.space(80)
  readonly property real ceilingY: textZone
  readonly property real floorY: textZone + plotDepth
  readonly property real liveW: Math.round(width * 0.16)
  readonly property real histW: width - liveW

  x: -bleed
  width: (parent ? parent.width : 0) + 2 * bleed
  height: floorY + Style.space(10)

  // ------------------------------------------------------------ colours
  // The graph is the theme's accent with a little plasma in it: the fill's
  // top leans a few degrees round the colour wheel and lighter, so the area
  // reads as a lit liquid and not a flat wash. Frozen, it is the plain
  // foreground and everything fades.
  function shifted(c, dHue, sat, light) {
    var h = c.hslHue < 0 ? 0 : c.hslHue
    return Qt.hsla((h + dHue + 1) % 1, Math.min(1, c.hslSaturation * sat), Math.min(0.9, c.hslLightness * light), c.a)
  }

  property color baseColor: frozen ? hub.fg : hub.accent
  property color topColor: frozen ? Qt.lighter(hub.fg, 1.0) : shifted(hub.accent, 0.05, 1.05, 1.18)
  property color bandColor: frozen ? hub.fg : shifted(hub.accent, -0.025, 1.0, 1.45)
  readonly property color pulseColor: frozen ? hub.dim : shifted(hub.accent, -0.02, 0.9, 1.75)
  readonly property real fillTop: frozen ? 0.2 : 0.55
  readonly property real edgeAlpha: frozen ? 0.32 : 0.9
  readonly property real bandTop: frozen ? 0.28 : 0.78
  Behavior on baseColor { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(160) } }
  Behavior on topColor { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(160) } }
  Behavior on bandColor { enabled: hero.hub.settled; ColorAnimation { duration: Style.duration(160) } }

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
    case "fallback": return t("hero.fallback").arg(t("fallback." + info.fallback))
    case "bypassed": return t("hero.bypassed")
    case "unreachable": return t("hero.unreachable")
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
    if (k === "pihole" || k === "paused" || k === "bypassed") {
      if (info.via !== "") out.push({ text: t("hero.via").arg(info.via), tone: "dim" })
      if (info.latencyMs !== null) out.push({ text: Model.formatLatency(info.latencyMs, fmt), tone: info.latencyBad ? "urgent" : "dim" })
      if (info.apiIssue !== "") out.push({ text: t("hero.api." + info.apiIssue), tone: "urgent" })
    } else if (k === "fallback") {
      if (info.via !== "") out.push({ text: t("hero.via").arg(info.via), tone: "dim" })
      out.push({ text: t("hero.piholeDown"), tone: "warning" })
    } else if (k === "unreachable") {
      if (info.via !== "") out.push({ text: info.via, tone: "dim" })
      out.push({ text: t("hero.noAnswer"), tone: "urgent" })
    } else if ((k === "router" || k === "custom") && info.via !== "") {
      out.push({ text: t("hero.via").arg(info.via), tone: "dim" })
    } else if (k === "nobackend") {
      out.push({ text: t("hero.nobackendHint"), tone: "dim" })
    }
    return out
  }

  readonly property var today: hub.view.pihole.today
  readonly property bool showCounts: hub.view.pihole.configured && !hub.view.backendDown && (today.total > 0 || series !== null)

  Text {
    id: word
    x: hero.textX
    y: Style.space(10)
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    text: hero.wordText
    color: hero.toneColor(hero.info.tone)
    font.family: hero.hub.fontFamily
    font.pixelSize: hero.hub.typeTitle
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
        }
        Text {
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: part.modelData.text
          color: hero.toneColor(part.modelData.tone)
          font.family: hero.hub.fontFamily
          font.pixelSize: hero.hub.typeSmall
        }
      }
    }
  }

  Column {
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
    }
  }

  // ------------------------------------------------------------- graph
  function toPoints(list) {
    var out = []
    for (var i = 0; i < list.length; i++) out.push(Qt.point(list[i].x, list[i].y))
    return out
  }

  // The history's edge, from the left edge of the card to where "now" begins.
  function areaEdge(values) {
    if (!values || values.length < 2 || width <= 0) return []
    return toPoints(Model.edgePoints(values, 0, histW, floorY, floorY - ceilingY))
  }

  readonly property var totalEdge: areaEdge(series ? series.total : null)
  readonly property var blockedEdge: areaEdge(series ? series.blocked : null)
  readonly property point totalFirst: totalEdge.length ? totalEdge[0] : Qt.point(0, floorY)
  readonly property point totalLast: totalEdge.length ? totalEdge[totalEdge.length - 1] : Qt.point(0, floorY)
  readonly property point blockedFirst: blockedEdge.length ? blockedEdge[0] : Qt.point(0, floorY)
  readonly property point blockedLast: blockedEdge.length ? blockedEdge[blockedEdge.length - 1] : Qt.point(0, floorY)

  // The live pulse: the probe runs mapped into the live part's width, 10% to
  // 65% of the plot's height.
  readonly property real liveInset: Style.space(8)
  function pulseX(x) { return histW + liveInset + x * (liveW - 2 * liveInset) }
  function pulseY(v) { return floorY - (0.1 + 0.55 * v) * (floorY - ceilingY) }
  readonly property var pulsePaths: {
    var out = []
    if (!live || width <= 0) return out
    for (var i = 0; i < live.runs.length; i++) {
      var run = []
      for (var j = 0; j < live.runs[i].length; j++) run.push(Qt.point(pulseX(live.runs[i][j].x), pulseY(live.runs[i][j].v)))
      out.push(run)
    }
    return out
  }
  readonly property bool headOk: !!live && !!live.head && live.head.ok
  readonly property real headX: live && live.head ? pulseX(live.head.x) : histW + liveInset
  readonly property real headY: live && live.head ? pulseY(live.head.v) : floorY

  // Everything drawn below the text.
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
          GradientStop { position: 0; color: Util.alpha(hero.topColor, hero.fillTop) }
          GradientStop { position: 0.55; color: Util.alpha(hero.baseColor, hero.fillTop * 0.45) }
          GradientStop { position: 1; color: Util.alpha(hero.baseColor, 0.03) }
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
          x1: 0; y1: hero.floorY - (hero.floorY - hero.ceilingY) * 0.45
          x2: 0; y2: hero.floorY
          GradientStop { position: 0; color: Util.alpha(hero.bandColor, hero.bandTop) }
          GradientStop { position: 1; color: Util.alpha(hero.bandColor, hero.bandTop * 0.4) }
        }
        startX: hero.blockedFirst.x
        startY: hero.blockedFirst.y
        PathPolyline { path: hero.blockedEdge }
        PathLine { x: hero.blockedLast.x; y: hero.floorY }
        PathLine { x: hero.blockedFirst.x; y: hero.floorY }
        PathLine { x: hero.blockedFirst.x; y: hero.blockedFirst.y }
      }
    }

    // The two edges' strokes.
    Shape {
      anchors.fill: parent
      visible: hero.totalEdge.length > 0
      preferredRendererType: Shape.CurveRenderer
      asynchronous: true
      ShapePath {
        fillColor: "transparent"
        strokeWidth: 1
        strokeColor: Util.alpha(hero.topColor, hero.edgeAlpha)
        joinStyle: ShapePath.RoundJoin
        capStyle: ShapePath.FlatCap
        PathPolyline { path: hero.totalEdge }
      }
      ShapePath {
        fillColor: "transparent"
        strokeWidth: 1
        strokeColor: Util.alpha(hero.bandColor, hero.edgeAlpha * 0.8)
        joinStyle: ShapePath.RoundJoin
        capStyle: ShapePath.FlatCap
        PathPolyline { path: hero.blockedEdge }
      }
    }

    // Where the 24 hours end and "now" begins.
    Rectangle {
      visible: hero.totalEdge.length > 0
      x: Math.round(hero.histW)
      y: hero.ceilingY
      width: 1
      height: hero.floorY - hero.ceilingY
      color: Util.alpha(hero.hub.fg, 0.1)
    }

    // The live pulse: a soft wide stroke under a thin bright one.
    Shape {
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      asynchronous: true
      ShapePath {
        fillColor: "transparent"
        strokeWidth: 4
        strokeColor: Util.alpha(hero.pulseColor, 0.18)
        joinStyle: ShapePath.RoundJoin
        capStyle: ShapePath.RoundCap
        PathMultiline { paths: hero.pulsePaths }
      }
      ShapePath {
        fillColor: "transparent"
        strokeWidth: 1.5
        strokeColor: Util.alpha(hero.pulseColor, hero.frozen ? 0.5 : 0.95)
        joinStyle: ShapePath.RoundJoin
        capStyle: ShapePath.RoundCap
        PathMultiline { paths: hero.pulsePaths }
      }
    }

    // The head: the newest probe. A failed one is a hollow urgent ring.
    Rectangle {
      id: head
      visible: !!hero.live && !!hero.live.head
      width: Style.space(6)
      height: width
      radius: width / 2
      x: hero.headX - width / 2
      y: hero.headY - height / 2
      color: hero.headOk ? hero.pulseColor : "transparent"
      border.width: hero.headOk ? 0 : 1
      border.color: hero.hub.urgent
    }

    // One ring out of the head when a probe lands.
    Rectangle {
      id: halo
      visible: head.visible
      width: Style.space(10)
      height: width
      radius: width / 2
      x: hero.headX - width / 2
      y: hero.headY - height / 2
      color: "transparent"
      border.width: 1
      border.color: hero.headOk ? hero.pulseColor : hero.hub.urgent
      opacity: 0
      ParallelAnimation {
        id: ping
        NumberAnimation { target: halo; property: "scale"; from: 0.6; to: 2.2; duration: Style.duration(280); easing.type: Easing.OutCubic }
        NumberAnimation { target: halo; property: "opacity"; from: 0.7; to: 0; duration: Style.duration(280); easing.type: Easing.OutCubic }
      }
    }
  }

  Connections {
    target: hero.hub
    function onProbeTickChanged() {
      if (hero.hub.settled && hero.live && hero.live.head) ping.restart()
    }
  }

  // A flat dim line where a graph would be: no data yet, or nothing set up.
  Rectangle {
    visible: hero.totalEdge.length === 0
    x: hero.textX
    y: hero.floorY - 1
    width: hero.width - 2 * hero.textX
    height: 1
    color: Util.alpha(hero.hub.fg, 0.1)
  }

  // Not set up: the way to do it, in the graph's place.
  TextButton {
    id: setupLink
    visible: hero.info.setup
    hub: hero.hub
    x: hero.textX - padX
    y: hero.ceilingY + (hero.plotDepth - implicitHeight) / 2
    padX: Style.space(8)
    padY: Style.space(6)
    size: hero.hub.typeBody
    text: hero.t("hero.setup") + " ›"
    textColor: hero.hub.accent
    cursorRow: "setup"
    cursorItem: 0
    onClicked: hero.hub.setup()
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
      text: hero.t("hero.tip")
      fontFamily: hero.hub.fontFamily
    }
  }
}

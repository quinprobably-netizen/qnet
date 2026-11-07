pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons
import qs.Commons as Commons
import "../Model.js" as Model

// THE ROUTE: the hero's picture. Not a chart: the path a DNS query takes from
// this machine out to the internet, hop by hop, with a state on every hop,
//
//    PC ═════ AP ═════ Pi-hole ═════ upstream ═▶
//   .242      58%       .153 ✓        9.9.9.9
//             2 ms       7 ms    ▼     12 ms
//                      ▓▓▓▓  50.7% blocked
//
// Small glyph badges for the nodes, their numbers under them in the bar font;
// between them thick rounded tubes filled with the plasma gradient (the dye
// bath lives here), and, while the panel is open, a slow constant flow of
// soft blobs left to right (about five seconds a hop, linear), as thick as DNS
// is busy. Under the Pi-hole a drain peels the blocked share off into a pool
// whose level is that share, so the flow after the Pi-hole is thinner than
// before it. What is wrong is drawn on the route: a Pi-hole that is paused is
// an open gate, a dead one is greyed with a cross while a dashed branch
// carries the traffic round it (warning: a failover; urgent: a bypass), a
// stalled flow stops at the node that is not answering, and so on
// (Model.routeModel decides all of that; this only draws it).
//
// A self-contained piece behind a small interface, so the picture can change
// without touching the layout or the words over it (Hero.qml):
//
//   in    view       the effective view (Model.effective)
//         nowS       the clock, for the failover countdown
//         frozen     desaturate: the numbers are old, or DNS is not going
//                    through the Pi-hole
//         animate    the flow may move (the panel is open); with animations
//                    off (Style.reduceMotion) the tubes are still
//         accent, fg, dim, urgent, warning   the host's colours
//         fontFamily, fontSize               the host's type
//         tr(key)    the host's words, for the parts the model names by key
//         leftInset, rightInset              the host's content margins
//         pending    the panel's pending requests (the leak count uses them)
//         cursorNode the node the cursor is on ("" for none); cursorPointer
//                    says the pointer put it there (the ring is the accent;
//                    the keyboard's is grey)
//   out   implicitHeight   its height
//         overlap          px it wants to reach up into the words above (0)
//         legendColor      the colour of the blocked share (the pool)
//         ghost, ghostRect where the picture offers "set up" (a dashed node
//                          in the Pi-hole's place); the host puts the button
//         nodeMoved(id, area, mouse), nodeClicked(id)   the route is the
//                    navigation: the nodes that open a view (the AP: Wi-Fi;
//                    the Pi-hole's place: DNS) take the pointer
//         hoveredId  the node under the pointer ("" for none)
Item {
  id: viz

  required property var view
  property real nowS: Date.now() / 1000
  property bool frozen: false
  property bool animate: false
  property color accent: Commons.Color.accent
  property color fg: Commons.Color.foreground
  property color dim: Qt.darker(Commons.Color.foreground, 1.4)
  property color urgent: Commons.Color.urgent
  property color warning: "#e8a950"
  property string fontFamily: Style.font.family
  property int fontSize: Style.font.bodySmall
  property var tr: function(key) { return key }
  property real leftInset: Style.space(22)
  property real rightInset: Style.space(16)
  property var pending: ({})
  property string cursorNode: ""
  property bool cursorPointer: false

  signal nodeMoved(string id, var area, var mouse)
  signal nodeClicked(string id)
  property string hoveredId: ""

  readonly property real overlap: 0
  readonly property color legendColor: pal.band
  readonly property bool ghost: route.ghost
  readonly property rect ghostRect: Qt.rect(slotX("ph") - Style.space(64), statY - Style.space(1), Style.space(128), Style.space(24))
  implicitHeight: Style.space(138)

  // ------------------------------------------------------------- model
  readonly property var route: Model.routeModel(view, nowS, pending)

  function nodeById(id) {
    for (var i = 0; i < route.nodes.length; i++) if (route.nodes[i].id === id) return route.nodes[i]
    return null
  }

  function linkOf(key) {
    for (var i = 0; i < route.links.length; i++) if (route.links[i].a + ">" + route.links[i].b === key) return route.links[i]
    return null
  }

  // A part { text } or { key, args } as the words to draw.
  function say(p) {
    if (!p) return ""
    if (p.key !== undefined) {
      var s = tr(p.key)
      for (var i = 0; i < p.args.length; i++) s = s.replace("%" + (i + 1), p.args[i])
      return s
    }
    return p.text
  }

  // What a node's tooltip says: where it goes, or what it is.
  function tipFor(n) {
    if (n.open === "wifi") return tr("route.tip.wifi")
    if (n.open === "dns") return n.glyph === "ghost" && n.tip !== "" ? tr("route.tip.dns") + "\n" + tr("hero.detected").replace("%1", n.tip) : tr("route.tip.dns")
    return n.tip
  }

  // ------------------------------------------------------------ colours
  PlasmaPalette { id: pal; accent: viz.accent; fg: viz.fg; dim: viz.dim; frozen: viz.frozen }

  // The plasma along the whole route.
  function plasmaAt(x) { return pal.at((x - x0) / Math.max(1, xEnd - x0)) }

  function toneColor(tone) {
    if (tone === "urgent") return urgent
    if (tone === "warning") return warning
    if (tone === "dim") return dim
    return frozen ? dim : pal.crest
  }

  function wordColor(tone) {
    if (tone === "urgent") return urgent
    if (tone === "warning") return warning
    if (tone === "legend") return legendColor
    return dim
  }

  // ----------------------------------------------------------- geometry
  readonly property real badge: Style.space(30)
  readonly property real tubeH: Style.space(9)
  readonly property real rowY: Style.space(24)
  readonly property real laneY: Style.space(57)
  readonly property real labelY: Style.space(63)
  readonly property real statY: labelY + fontSize + Style.space(5)
  readonly property real x0: leftInset + badge / 2
  readonly property real xEnd: width - rightInset
  readonly property real step: Math.max(1, (xEnd - x0 - Style.space(26)) / 3)
  readonly property var slots: ({ pc: 0, ap: 1, ph: 2, up: 3 })

  function slotX(id) { return id === "end" ? xEnd : x0 + slots[id] * step }

  // The tube between two slots: from the edge of one badge to the edge of the
  // next (the arrow's head for the last).
  function tubeLeft(a) { return slotX(a) + badge / 2 + Style.space(3) }
  function tubeRight(b) { return b === "end" ? xEnd - Style.space(9) : slotX(b) - badge / 2 - Style.space(3) }

  // How much thinner the flow is after the Pi-hole has peeled the blocked share off.
  readonly property real thinK: Math.max(0.4, 1 - 0.7 * route.flow.share)

  // The glyphs.
  readonly property var glyphOf: ({
    pc: Model.GLYPH.pc, ap: Model.GLYPH.ap, wire: Model.GLYPH.ethernet, shield: Model.GLYPH.shield,
    shieldOutline: Model.GLYPH.shieldOutline, shieldOff: Model.GLYPH.shieldOff, earth: Model.GLYPH.earth,
    ghost: Model.GLYPH.plus
  })

  // Whether the flow may move at all.
  readonly property bool flowing: animate && !Style.reduceMotion

  // ---------------------------------------------------------------- tubes
  Repeater {
    model: ["pc>ap", "ap>ph", "ph>up", "up>end", "ap>up"]

    Item {
      id: tube
      required property string modelData
      readonly property var lk: viz.linkOf(modelData)
      readonly property string a: modelData.split(">")[0]
      readonly property string b: modelData.split(">")[1]
      visible: lk !== null
      readonly property real xa: viz.tubeLeft(a)
      readonly property real xb: viz.tubeRight(b)
      readonly property real h: lk && lk.thin ? Math.max(3.5, viz.tubeH * viz.thinK) : viz.tubeH
      readonly property bool solid: lk !== null && (lk.state === "flow" || lk.state === "stalled" || lk.state === "dim")
      // (desaturated, the tubes are grey and quiet, not white)
      readonly property real tubeAlpha: lk && lk.state === "stalled" ? 0.5 : viz.frozen ? 0.42 : 0.9
      readonly property color from: !lk ? "transparent" : lk.state === "dim" ? Util.alpha(viz.dim, 0.3)
        : lk.tone === "accent" ? Util.alpha(viz.plasmaAt(xa), tubeAlpha)
        : Util.alpha(viz.toneColor(lk.tone), 0.85)
      readonly property color to: !lk ? "transparent" : lk.state === "dim" ? Util.alpha(viz.dim, 0.3)
        : lk.tone === "accent" ? Util.alpha(viz.plasmaAt(xb), tubeAlpha)
        : Util.alpha(viz.toneColor(lk.tone), 0.85)

      x: xa
      y: viz.rowY - h / 2
      width: Math.max(0, xb - xa)
      height: h

      // the glow round it: the dye bath's halo
      Rectangle {
        visible: tube.solid && tube.lk && tube.lk.state !== "dim"
        x: -Style.space(2)
        y: -Style.space(3)
        width: parent.width + Style.space(4)
        height: parent.height + Style.space(6)
        radius: height / 2
        color: Util.alpha(tube.to, 0.14)
      }

      Rectangle {
        id: body
        visible: tube.solid
        anchors.fill: parent
        radius: height / 2
        gradient: Gradient {
          orientation: Gradient.Horizontal
          GradientStop { position: 0; color: tube.from }
          GradientStop { position: 1; color: tube.to }
        }
        clip: true

        // the flow: soft blobs, left to right, linear
        Repeater {
          model: [0, 2, 1, 3]

          Rectangle {
            id: blob
            required property int modelData
            required property int index
            readonly property real w: Style.space(24)
            readonly property int count: tube.lk && tube.lk.flow && viz.route.flow.density > 0 ? 1 + Math.round(viz.route.flow.density * 3) : 0
            readonly property bool live: viz.flowing && index < count
            readonly property real phase: modelData / 4
            visible: live
            width: w
            height: parent.height
            radius: height / 2
            y: 0
            gradient: Gradient {
              orientation: Gradient.Horizontal
              GradientStop { position: 0; color: "transparent" }
              GradientStop { position: 0.5; color: Util.alpha(Qt.lighter(pal.crest, 1.9), viz.frozen ? 0.25 : 0.55) }
              GradientStop { position: 1; color: "transparent" }
            }

            SequentialAnimation {
              running: blob.live
              // the first lap starts part of the way along, so the blobs are
              // spread out from the start
              NumberAnimation {
                target: blob; property: "x"
                from: -blob.w + blob.phase * (body.width + blob.w); to: body.width
                duration: Style.duration(5000 * (1 - blob.phase))
              }
              SequentialAnimation {
                loops: Animation.Infinite
                NumberAnimation { target: blob; property: "x"; from: -blob.w; to: body.width; duration: Style.duration(5000) }
              }
            }
          }
        }

        // a stalled flow: the blobs bunch up against the node that is not answering
        Repeater {
          model: tube.lk && tube.lk.state === "stalled" ? 3 : 0
          Rectangle {
            required property int index
            width: Style.space(14)
            height: parent.height
            radius: height / 2
            x: body.width - (index + 1) * Style.space(10)
            color: Util.alpha(pal.crest, 0.35)
          }
        }
      }

      // a stalled flow ends against a bar at the node
      Rectangle {
        visible: tube.lk !== null && tube.lk.state === "stalled"
        x: parent.width - width / 2
        y: -Style.space(5)
        width: Style.space(3)
        height: parent.height + Style.space(10)
        radius: width / 2
        color: viz.urgent
      }

      // dashed: nothing is going this way
      Shape {
        visible: tube.lk !== null && tube.lk.state === "dashed"
        anchors.fill: parent
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
          strokeColor: tube.lk && tube.lk.tone !== "dim" && tube.lk.tone !== "accent" ? Util.alpha(viz.toneColor(tube.lk.tone), 0.9) : Util.alpha(viz.dim, 0.55)
          strokeWidth: Style.space(2)
          fillColor: "transparent"
          strokeStyle: ShapePath.DashLine
          dashPattern: [3, 3]
          capStyle: ShapePath.RoundCap
          startX: 0; startY: tube.height / 2
          PathLine { x: tube.width; y: tube.height / 2 }
        }
      }
    }
  }

  // The arrowhead into the internet.
  Shape {
    id: arrow
    readonly property var lk: viz.linkOf("up>end")
    readonly property bool shown: lk !== null && viz.route.kind !== "offline"
    visible: shown
    x: viz.xEnd - Style.space(10)
    y: viz.rowY - Style.space(7)
    width: Style.space(12)
    height: Style.space(14)
    preferredRendererType: Shape.CurveRenderer
    ShapePath {
      fillColor: !arrow.lk ? "transparent" : arrow.lk.state === "flow" ? Util.alpha(arrow.lk.tone === "accent" ? viz.plasmaAt(viz.xEnd) : viz.toneColor(arrow.lk.tone), 0.95) : Util.alpha(viz.dim, 0.4)
      strokeWidth: -1
      startX: 0; startY: 0
      PathLine { x: Style.space(11); y: Style.space(7) }
      PathLine { x: 0; y: Style.space(14) }
      PathLine { x: 0; y: 0 }
    }
  }

  // ------------------------------------------------------------- branch
  // From the AP, under the Pi-hole, round to the internet: dashed, in the
  // colour of what it is (warning: failover; urgent: a bypass), with the
  // flow that takes it as dots and its name over the lane.
  Item {
    id: branch
    visible: viz.route.branch !== null
    readonly property var br: viz.route.branch
    readonly property real r: Style.space(7)
    readonly property real xa: viz.slotX("ap")
    readonly property real xb: viz.xEnd - Style.space(5)
    readonly property color col: br ? Util.alpha(viz.toneColor(br.tone), 0.95) : "transparent"
    anchors.fill: parent

    Shape {
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      ShapePath {
        strokeColor: branch.col
        strokeWidth: Style.space(2.5)
        fillColor: "transparent"
        strokeStyle: ShapePath.DashLine
        dashPattern: [3, 2.2]
        capStyle: ShapePath.RoundCap
        joinStyle: ShapePath.RoundJoin
        startX: branch.xa; startY: viz.rowY + viz.badge / 2 + Style.space(1)
        PathLine { x: branch.xa; y: viz.laneY - branch.r }
        PathArc { x: branch.xa + branch.r; y: viz.laneY; radiusX: branch.r; radiusY: branch.r; direction: PathArc.Counterclockwise }
        PathLine { x: branch.xb - branch.r; y: viz.laneY }
        PathArc { x: branch.xb; y: viz.laneY - branch.r; radiusX: branch.r; radiusY: branch.r; direction: PathArc.Counterclockwise }
        PathLine { x: branch.xb; y: viz.rowY + Style.space(5) }
      }
    }

    // the flow that takes it
    Item {
      x: branch.xa + branch.r
      y: viz.laneY - Style.space(5)
      width: branch.xb - branch.r - x
      height: Style.space(10)
      clip: true
      visible: branch.br !== null && branch.br.flow

      Repeater {
        model: [0, 2, 1, 3]
        Rectangle {
          id: dot
          required property int modelData
          required property int index
          readonly property real w: Style.space(7)
          visible: viz.flowing && index < 1 + Math.round(viz.route.flow.density * 3)
          width: w
          height: w
          radius: w / 2
          y: (parent.height - height) / 2
          color: Util.alpha(Qt.lighter(viz.toneColor(branch.br ? branch.br.tone : "dim"), 1.4), 0.9)
          SequentialAnimation {
            running: dot.visible
            NumberAnimation { target: dot; property: "x"; from: dot.modelData / 4 * dot.parent.width; to: dot.parent.width; duration: Style.duration(5000 * (1 - dot.modelData / 4)) }
            SequentialAnimation {
              loops: Animation.Infinite
              NumberAnimation { target: dot; property: "x"; from: -dot.w; to: dot.parent.width; duration: Style.duration(5000) }
            }
          }
        }
      }
    }

    // its name, on the lane's upper side
    Text {
      visible: branch.br !== null
      x: Math.max(viz.leftInset, Math.min(viz.slotX("ph") - width / 2, viz.xEnd - width))
      y: viz.laneY - implicitHeight - Style.space(2)
      width: Math.min(implicitWidth, viz.step - Style.space(8))
      horizontalAlignment: Text.AlignHCenter
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: branch.br ? viz.say(branch.br.label) : ""
      color: branch.br ? viz.toneColor(branch.br.tone) : viz.dim
      font.family: viz.fontFamily
      font.pixelSize: viz.fontSize
      elide: Text.ElideRight
    }
  }

  // -------------------------------------------------------------- nodes
  // The nodes that open a view (the AP, the Pi-hole's place) are the route's
  // navigation: a pointer cursor, a ring under the cursor (grey for the
  // keyboard, the accent for the pointer), a tooltip that says where it goes.
  Repeater {
    model: ["pc", "ap", "ph", "up"]

    Item {
      id: nd
      required property string modelData
      readonly property var n: viz.nodeById(modelData)
      readonly property color tone: n ? viz.toneColor(n.tone) : "transparent"
      readonly property bool ghostNode: n !== null && n.glyph === "ghost"
      readonly property bool opens: n !== null && n.open !== ""
      readonly property bool hasCursor: viz.cursorNode === modelData
      visible: n !== null
      x: viz.slotX(modelData) - viz.badge / 2
      y: viz.rowY - viz.badge / 2
      width: viz.badge
      height: viz.badge

      RouteBadge {
        anchors.fill: parent
        size: viz.badge
        glyph: nd.n ? viz.glyphOf[nd.n.glyph] : ""
        tone: nd.tone
        quiet: nd.n !== null && nd.n.tone === "dim"
        ghost: nd.ghostNode
        accent: viz.accent
        fontFamily: viz.fontFamily
        ringColor: nd.hasCursor ? (viz.cursorPointer ? viz.accent : Util.alpha(viz.fg, 0.7)) : "transparent"
        badgeText: nd.n && nd.n.badge ? String(nd.n.badge.n) : ""
        badgeColor: nd.n && nd.n.badge ? viz.toneColor(nd.n.badge.tone) : viz.warning
      }

      // under it: what it is (its address, its signal), then how it is doing
      Text {
        x: Math.max(viz.leftInset - nd.x, Math.min((parent.width - width) / 2, viz.xEnd - nd.x - width))
        y: viz.labelY - nd.y
        width: Math.min(implicitWidth, viz.step - Style.space(8))
        horizontalAlignment: Text.AlignHCenter
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: nd.n ? viz.say(nd.n.label) : ""
        color: nd.n ? (nd.n.tone === "urgent" ? viz.urgent : nd.n.tone === "warning" ? viz.warning : nd.n.tone === "dim" ? viz.dim : viz.fg) : viz.fg
        font.family: viz.fontFamily
        font.pixelSize: viz.fontSize
        elide: Text.ElideRight
      }
      Text {
        x: Math.max(viz.leftInset - nd.x, Math.min((parent.width - width) / 2, viz.xEnd - nd.x - width))
        y: viz.statY - nd.y
        width: Math.min(implicitWidth, viz.step - Style.space(8))
        horizontalAlignment: Text.AlignHCenter
        visible: text !== ""
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: nd.n && nd.n.stat ? viz.say(nd.n.stat) : ""
        color: nd.n ? (nd.n.statTone === "urgent" ? viz.urgent : nd.n.statTone === "warning" ? viz.warning : viz.dim) : viz.dim
        font.family: viz.fontFamily
        font.pixelSize: viz.fontSize
        elide: Text.ElideRight
      }

      // The hit area: the badge and the words under it.
      MouseArea {
        id: hit
        readonly property real w: Math.min(viz.step - Style.space(8), Style.space(96))
        x: (parent.width - w) / 2
        y: -Style.space(4)
        width: w
        height: viz.statY + viz.fontSize + Style.space(4) - nd.y
        hoverEnabled: true
        acceptedButtons: nd.opens ? Qt.LeftButton : Qt.NoButton
        cursorShape: nd.opens ? Qt.PointingHandCursor : Qt.ArrowCursor
        onContainsMouseChanged: {
          if (containsMouse) viz.hoveredId = nd.modelData
          else if (viz.hoveredId === nd.modelData) viz.hoveredId = ""
        }
        onPositionChanged: function(mouse) { if (nd.opens) viz.nodeMoved(nd.modelData, hit, mouse) }
        onClicked: viz.nodeClicked(nd.modelData)

        PanelToolTip {
          visible: (hit.containsMouse || nd.hasCursor) && nd.n !== null && viz.tipFor(nd.n) !== ""
          text: nd.n ? viz.tipFor(nd.n) : ""
          fontFamily: viz.fontFamily
        }
      }
    }
  }

  // --------------------------------------------------------------- sink
  // The drain under the Pi-hole: the blocked share peeled off the flow, down
  // into a pool whose level is that share.
  Item {
    id: sink
    visible: viz.route.sink !== null
    readonly property var sk: viz.route.sink
    readonly property real cx: viz.slotX("ph")
    readonly property real drainTop: viz.statY + viz.fontSize + Style.space(7)
    readonly property real poolW: Style.space(58)
    readonly property real poolH: Style.space(17)
    readonly property real poolY: drainTop + Style.space(9)
    readonly property real peel: sk && !sk.empty ? Math.max(2.5, viz.tubeH * 0.7 * viz.route.flow.share) : 0
    anchors.fill: parent

    // the drain and its arrowhead
    Rectangle {
      visible: sink.peel > 0
      x: sink.cx - width / 2
      y: sink.drainTop
      width: sink.peel
      height: Style.space(5)
      radius: width / 2
      color: Util.alpha(pal.band, 0.9)
    }
    Shape {
      visible: sink.peel > 0
      x: sink.cx - Style.space(4)
      y: sink.drainTop + Style.space(3)
      width: Style.space(8)
      height: Style.space(6)
      preferredRendererType: Shape.CurveRenderer
      ShapePath {
        fillColor: Util.alpha(pal.band, 0.95)
        strokeWidth: -1
        startX: 0; startY: 0
        PathLine { x: Style.space(8); y: 0 }
        PathLine { x: Style.space(4); y: Style.space(6) }
        PathLine { x: 0; y: 0 }
      }
    }

    // the pool
    Rectangle {
      id: pool
      x: sink.cx - width / 2
      y: sink.poolY
      width: sink.poolW
      height: sink.poolH
      radius: Style.space(4)
      color: Util.alpha(viz.dim, 0.08)
      border.width: 1
      border.color: Util.alpha(viz.dim, 0.5)
      clip: true

      Rectangle {
        visible: sink.sk !== null && !sink.sk.empty
        anchors.bottom: parent.bottom
        width: parent.width
        height: Math.max(Style.space(3), parent.height * (sink.sk ? sink.sk.pct / 100 : 0))
        gradient: Gradient {
          GradientStop { position: 0; color: Util.alpha(pal.band, 0.95) }
          GradientStop { position: 1; color: Util.alpha(pal.foot, 0.7) }
        }
      }
    }

    Text {
      visible: sink.sk !== null && sink.sk.label !== null
      x: pool.x + pool.width + Style.space(8)
      y: pool.y + (pool.height - implicitHeight) / 2
      width: Math.min(implicitWidth, viz.width - viz.rightInset - x)
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: sink.sk && sink.sk.label ? viz.say(sink.sk.label) : ""
      color: viz.legendColor
      font.family: viz.fontFamily
      font.pixelSize: viz.fontSize
      elide: Text.ElideRight
    }
  }

  // -------------------------------------------------------- note: no DNS
  // The words for why the route stops: "no DNS" over "resolved fallback
  // 9.9.9.9" under the DNS node's place.
  Item {
    id: note
    visible: viz.route.note !== null
    readonly property var nt: viz.route.note
    anchors.fill: parent

    Column {
      x: Math.max(viz.leftInset, Math.min(viz.slotX("ph") - width / 2, viz.xEnd - width))
      y: viz.labelY - Style.space(1)
      spacing: Style.space(2)
      Repeater {
        model: note.nt ? viz.say(note.nt).split(" \u00b7 ") : []
        Text {
          required property string modelData
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: modelData
          color: viz.toneColor(note.nt.tone)
          font.family: viz.fontFamily
          font.pixelSize: viz.fontSize
        }
      }
    }
  }
}

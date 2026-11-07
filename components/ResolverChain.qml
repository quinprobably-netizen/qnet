pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons
import qs.Commons as Commons
import "../Model.js" as Model

// The DNS view's picture: the hero's route in the same visual language (round
// badges, plasma tubes, a slow flow while the panel is open), drawn top to
// bottom and compact, one row a node:
//
//    (PC)    This PC            192.168.1.242
//     ║
//    (res)   systemd-resolved
//     ║
//    (ph)    Pi-hole  .153 ✓                             7 ms
//     ║        blocked 1,734 · cached 1,075 · forwarded 430
//     ╠═(up)  9.9.9.9   dns9.quad9.net              15% · 159 ms
//     ╚═(up)  1.1.1.1   one.one.one.one             12% · 11 ms
//
// What is wrong is on the chain (Model.chainModel decides; this draws): a
// bypass or a failover is a side node off the trunk (dashed urgent; solid
// warning), a paused Pi-hole is an outline, an unreachable one a cross with
// its countdown and a stalled tube. How the Pi-hole's answers divided is three
// small labelled counts on its branch, not a meter.
//
//   in    view, nowS, frozen, animate, the host's colours and type, tr(key),
//         formatInt(n), gutter
//   out   implicitHeight
Item {
  id: chain

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
  property var formatInt: function(n) { return String(n) }
  property real gutter: Style.space(8)

  readonly property var model: Model.chainModel(view, nowS)
  readonly property var nodes: model.nodes

  // ----------------------------------------------------------- geometry
  readonly property real rowH: Style.space(38)
  readonly property real countsH: Style.space(22)
  readonly property real bs: Style.space(24)
  readonly property real tubeW: Style.space(6)
  readonly property real trunkX: gutter + Style.space(4) + bs / 2
  readonly property real branchX: trunkX + Style.space(34)
  readonly property real topPad: Style.space(4)
  readonly property real bottomPad: Style.space(6)

  // Where each node's row starts, the tubes between the trunk's nodes, the
  // stubs of the ones hanging off it, and the total height.
  readonly property var geo: {
    var ns = nodes
    var ys = []
    var y = topPad
    var i
    for (i = 0; i < ns.length; i++) { ys.push(y); y += rowH + (ns[i].counts ? countsH : 0) }
    var tubes = []
    var stubs = []
    var prev = -1
    var gap = Style.space(2)
    function cy(k) { return ys[k] + rowH / 2 }
    var tail = null
    for (i = 0; i < ns.length; i++) {
      var n = ns[i]
      if (n.depth === 0) {
        if (prev >= 0) {
          var y0 = cy(prev) + bs / 2 + gap
          tubes.push({ y: y0, h: Math.max(0, cy(i) - bs / 2 - gap - y0), state: n.via, tone: n.viaTone })
        }
        prev = i
        tail = null
      } else {
        stubs.push({ y: cy(i), state: n.via, tone: n.viaTone })
        // children after the last trunk node: the trunk runs down to them
        if (prev >= 0 && ns[prev].id === "ph" && i > prev) {
          if (tail === null) tail = { y: cy(prev) + bs / 2 + gap, h: 0, state: n.via, tone: n.viaTone }
          tail.h = cy(i) - tail.y
        }
      }
    }
    if (tail !== null) tubes.push(tail)
    return { ys: ys, tubes: tubes, stubs: stubs, height: ns.length > 0 ? y + bottomPad : 0 }
  }

  implicitHeight: geo.height
  visible: nodes.length > 0

  readonly property bool flowing: animate && !Style.reduceMotion && model.flow.density > 0

  PlasmaPalette { id: pal; accent: chain.accent; fg: chain.fg; dim: chain.dim; frozen: chain.frozen }

  function say(p) {
    if (!p) return ""
    if (p.key !== undefined) {
      var s = tr(p.key)
      for (var i = 0; i < p.args.length; i++) s = s.replace("%" + (i + 1), p.args[i])
      return s
    }
    return p.text
  }

  function toneColor(tone) {
    if (tone === "urgent") return urgent
    if (tone === "warning") return warning
    if (tone === "dim") return dim
    return frozen ? dim : pal.crest
  }

  readonly property var glyphOf: ({
    pc: Model.GLYPH.pc, resolver: Model.GLYPH.resolver, shield: Model.GLYPH.shield, shieldOutline: Model.GLYPH.shieldOutline,
    shieldOff: Model.GLYPH.shieldOff, earth: Model.GLYPH.earth
  })

  // A vertical tube: plasma (or the colour of its tone), its flow as blobs
  // sliding down, dashed when nothing goes this way, stalled at its end when
  // the node below does not answer.
  component Tube: Item {
    id: tube
    required property real startY
    required property real span
    required property string kind
    required property string tone

    x: chain.trunkX - chain.tubeW / 2
    y: startY
    width: chain.tubeW
    height: span

    readonly property bool solid: kind === "flow" || kind === "stalled" || kind === "dim"
    readonly property real alpha: kind === "stalled" ? 0.5 : (chain.frozen ? 0.42 : 0.9)
    readonly property color topColor: kind === "dim" ? Util.alpha(chain.dim, 0.3) : (tone === "accent" ? Util.alpha(pal.at(startY / Math.max(1, chain.geo.height)), alpha) : Util.alpha(chain.toneColor(tone), 0.85))
    readonly property color bottomColor: kind === "dim" ? Util.alpha(chain.dim, 0.3) : (tone === "accent" ? Util.alpha(pal.at((startY + span) / Math.max(1, chain.geo.height)), alpha) : Util.alpha(chain.toneColor(tone), 0.85))

    Rectangle {
      id: body
      visible: tube.solid
      anchors.fill: parent
      radius: width / 2
      clip: true
      gradient: Gradient {
        orientation: Gradient.Vertical
        GradientStop { position: 0; color: tube.topColor }
        GradientStop { position: 1; color: tube.bottomColor }
      }

      Rectangle {
        id: blob
        readonly property real h: Style.space(14)
        visible: chain.flowing && tube.kind === "flow" && tube.span > Style.space(8)
        width: parent.width
        height: h
        radius: width / 2
        gradient: Gradient {
          orientation: Gradient.Vertical
          GradientStop { position: 0; color: "transparent" }
          GradientStop { position: 0.5; color: Util.alpha(Qt.lighter(pal.crest, 1.9), chain.frozen ? 0.25 : 0.55) }
          GradientStop { position: 1; color: "transparent" }
        }
        SequentialAnimation on y {
          running: blob.visible
          loops: Animation.Infinite
          NumberAnimation { from: -blob.h; to: body.height; duration: Style.duration(5000) }
        }
      }
    }

    // stalled: the flow ends against a bar at the node that is not answering
    Rectangle {
      visible: tube.kind === "stalled"
      x: -Style.space(4)
      y: parent.height - height / 2
      width: parent.width + Style.space(8)
      height: Style.space(3)
      radius: height / 2
      color: chain.urgent
    }

    Shape {
      visible: tube.kind === "dashed"
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      ShapePath {
        strokeColor: tube.tone === "accent" || tube.tone === "dim" ? Util.alpha(chain.dim, 0.55) : Util.alpha(chain.toneColor(tube.tone), 0.9)
        strokeWidth: Style.space(2)
        fillColor: "transparent"
        strokeStyle: ShapePath.DashLine
        dashPattern: [3, 3]
        capStyle: ShapePath.RoundCap
        startX: tube.width / 2; startY: 0
        PathLine { x: tube.width / 2; y: tube.height }
      }
    }
  }

  Repeater {
    model: chain.geo.tubes
    Tube {
      required property var modelData
      startY: modelData.y
      span: modelData.h
      kind: modelData.state
      tone: modelData.tone
    }
  }

  // The short horizontal tubes into the nodes that hang off the trunk.
  Repeater {
    model: chain.geo.stubs

    Item {
      id: stub
      required property var modelData
      readonly property bool solid: modelData.state === "flow" || modelData.state === "dim"
      x: chain.trunkX
      y: modelData.y - chain.tubeW * 0.35
      width: chain.branchX - chain.bs / 2 - Style.space(2) - chain.trunkX
      height: chain.tubeW * 0.7

      Rectangle {
        visible: stub.solid
        anchors.fill: parent
        radius: height / 2
        color: stub.modelData.state === "dim" ? Util.alpha(chain.dim, 0.3)
          : (stub.modelData.tone === "accent" ? Util.alpha(pal.at(stub.modelData.y / Math.max(1, chain.geo.height)), chain.frozen ? 0.42 : 0.9)
            : Util.alpha(chain.toneColor(stub.modelData.tone), 0.85))
      }
      Shape {
        visible: stub.modelData.state === "dashed"
        anchors.fill: parent
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
          strokeColor: stub.modelData.tone === "accent" || stub.modelData.tone === "dim" ? Util.alpha(chain.dim, 0.55) : Util.alpha(chain.toneColor(stub.modelData.tone), 0.9)
          strokeWidth: Style.space(2)
          fillColor: "transparent"
          strokeStyle: ShapePath.DashLine
          dashPattern: [3, 3]
          capStyle: ShapePath.RoundCap
          startX: 0; startY: stub.height / 2
          PathLine { x: stub.width; y: stub.height / 2 }
        }
      }
    }
  }

  // --------------------------------------------------------------- nodes
  Repeater {
    model: chain.nodes

    Item {
      id: row
      required property var modelData
      required property int index
      readonly property var n: modelData
      readonly property real cx: n.depth === 1 ? chain.branchX : chain.trunkX
      readonly property real textX: cx + chain.bs / 2 + Style.space(10)
      y: chain.geo.ys[index]
      width: chain.width
      height: chain.rowH + (n.counts ? chain.countsH : 0)

      RouteBadge {
        x: row.cx - chain.bs / 2
        y: (chain.rowH - chain.bs) / 2
        size: chain.bs
        glyph: chain.glyphOf[row.n.glyph]
        tone: chain.toneColor(row.n.tone)
        quiet: row.n.tone === "dim"
        accent: chain.accent
        fontFamily: chain.fontFamily
        glyphSize: Style.space(12)
      }

      // its name, then what it is (dim)
      Row {
        id: words
        x: row.textX
        y: (chain.rowH - height) / 2
        width: statText.x - row.textX - Style.space(8)
        spacing: Style.space(8)

        Text {
          id: labelText
          width: Math.min(implicitWidth, words.width)
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: chain.say(row.n.label)
          color: row.n.tone === "urgent" ? chain.urgent : (row.n.tone === "warning" ? chain.warning : (row.n.tone === "dim" ? chain.dim : chain.fg))
          font.family: chain.fontFamily
          font.pixelSize: chain.fontSize
          font.weight: Font.DemiBold
          elide: Text.ElideRight
        }
        Text {
          visible: row.n.sub !== null && words.width - labelText.width > Style.space(40)
          width: Math.max(0, Math.min(implicitWidth, words.width - labelText.width - parent.spacing))
          textFormat: Text.PlainText
          renderType: Text.NativeRendering
          text: row.n.sub ? chain.say(row.n.sub) : ""
          color: row.n.sub && row.n.sub.tone === "urgent" ? chain.urgent : chain.dim
          font.family: chain.fontFamily
          font.pixelSize: chain.fontSize
          elide: Text.ElideRight
        }
      }

      // how it is doing, at the right edge
      Text {
        id: statText
        x: chain.width - chain.gutter - width
        y: (chain.rowH - height) / 2
        width: Math.min(implicitWidth, chain.width * 0.4)
        horizontalAlignment: Text.AlignRight
        textFormat: Text.PlainText
        renderType: Text.NativeRendering
        text: row.n.stat ? chain.say(row.n.stat) : ""
        color: row.n.statTone === "urgent" ? chain.urgent : (row.n.statTone === "warning" ? chain.warning : chain.dim)
        font.family: chain.fontFamily
        font.pixelSize: chain.fontSize
        elide: Text.ElideRight
      }

      // how its answers divided: three labelled counts on its branch
      Row {
        id: counts
        visible: row.n.counts !== null
        x: chain.trunkX + Style.space(12)
        y: chain.rowH - Style.space(3)
        spacing: Style.space(10)

        Repeater {
          model: row.n.counts ? row.n.counts : []

          Row {
            id: one
            required property var modelData
            spacing: Style.space(4)
            Text {
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
              text: chain.tr("chain.counts." + one.modelData.key)
              color: chain.dim
              font.family: chain.fontFamily
              font.pixelSize: chain.fontSize
            }
            Text {
              textFormat: Text.PlainText
              renderType: Text.NativeRendering
              text: chain.formatInt(one.modelData.n)
              color: chain.fg
              font.family: chain.fontFamily
              font.pixelSize: chain.fontSize
            }
          }
        }
      }

      MouseArea {
        id: tipArea
        x: row.textX
        y: 0
        width: row.width - row.textX
        height: chain.rowH
        hoverEnabled: true
        acceptedButtons: Qt.NoButton
        PanelToolTip {
          visible: tipArea.containsMouse && row.n.tip !== ""
          text: row.n.tip
          fontFamily: chain.fontFamily
        }
      }
    }
  }
}

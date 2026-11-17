pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Shapes
import qs.Ui
import qs.Commons
import "../Model.js" as Model

// THE BOARD of the watchdog view: a patch bay, the way a telephone exchange
// wires lines to a few rows. Each device is a column of three jacks (ADS PASS
// above, the device's own line in the middle, BLOCKED below). The line goes
// where the normal wiring sends it: a dotted wire to the row NORMAL names, or
// a cord to the other row when someone patched it by hand. An amber cord and
// its "gate" tag mean ADS PASS for a while, shutting by itself. The router and
// the Pi are riveted: a bar, never a cord.
//
//   rail    fixed, 70 wide: the row names (ADS PASS, BLOCKED) and the NORMAL
//           key, a slot with a knob that sits at the row normal is; two bays
//           in view tie their keys together
//   bays    418 by 192 each, 8 columns of 51, 6 between bays; every device
//           shows up to 16, past that two bays are in view and the wheel (or
//           the pager) moves a bay at a time, with a ticket open only that
//           ticket's bay (Model.bayLayout decides which; Panel.wdLayout holds
//           the state)
//   column  drop lamp (lit while an alert rings this jack), the strip (the
//           name in one or two lines, a dashed blank that says "new" for a
//           device nobody has named), its address, three jacks (ring and hole)
//           and what the line is doing, and under it the one word
//           (BLOCKED, PASS, ALWAYS, FIXED, or the gate's time left)
//
// Drawn with items and QtQuick.Shapes (the cords, the dotted wires and the
// dashed blank), at the mockup's own sizes, 1 px = Style.spaceReal(1).
// Colours are the panel's: the foreground and the accent, the warning amber
// and urgent, and the board's surfaces (well, raise, sel, hole, ring, muted,
// bright: derived from the theme in Panel.qml). Clicking a column opens its
// device's ticket, clicking its lit drop lamp the alert's; hovering one puts
// its name in the readout under the board (hoverMac).
//
// The keyboard's stops are "bay:I" (one row a bay in view, the columns its
// items) and "normal" (the key); the pager and the readout are the view's.
Item {
  id: board

  required property var hub

  readonly property var wd: hub.view.watchdog
  readonly property var layout: hub.wdLayout
  readonly property bool normalPass: wd.exemptDefault
  readonly property real nowS: hub.nowMs / 1000
  readonly property var byMac: {
    var out = ({})
    var js = wd.bay.jacks
    for (var i = 0; i < js.length; i++) out[js[i].mac] = js[i]
    return out
  }
  // The jack under the pointer ("" for none): the readout says its name.
  property string hoverMac: ""

  function px(n) { return Style.spaceReal(n) }
  function tr(key) { return hub.strings.t(key) }

  // ----------------------------------------------------------- geometry
  readonly property real railW: px(70)
  readonly property real bayW: px(418)
  readonly property real bayH: px(192)
  readonly property real gap: px(6)
  readonly property real slotH: bayH + gap
  readonly property real colW: px(51)
  readonly property real pad: px(5)
  // the rows of jacks and the row of words
  readonly property real yT: px(84)
  readonly property real yD: px(120)
  readonly property real yB: px(156)
  readonly property int shownCount: layout.shown[1]
  readonly property int firstBay: layout.shown[0]

  implicitWidth: railW + bayW
  implicitHeight: shownCount > 0 ? shownCount * slotH - gap : 0
  width: implicitWidth
  height: implicitHeight

  // -------------------------------------------------------------- parts
  // A line of the bar's font at the caption size, set by its baseline.
  component Cap: Text {
    property real base: 0
    y: base - baselineOffset
    textFormat: Text.PlainText
    renderType: Text.NativeRendering
    color: board.hub.fg
    font.family: board.hub.fontFamily
    font.pixelSize: Style.font.caption
  }

  // A circle as a path, with the stroke centred on the edge (as the mockup's
  // SVG draws it): true circles on every renderer. A width of 0 is no stroke.
  component Dot: ShapePath {
    id: dot
    property real cx: 0
    property real cy: 0
    property real r: 1
    property real w: 0
    strokeWidth: dot.w > 0 ? dot.w : -1
    fillColor: "transparent"
    PathAngleArc { centerX: dot.cx; centerY: dot.cy; radiusX: dot.r; radiusY: dot.r; startAngle: 0; sweepAngle: 360 }
  }

  // A jack: a ring (8 by 2.5) round a hole (3.4) at (cx, cy).
  component JackPath: Item {
    id: jp
    property real cx: 0
    property real cy: 0
    property color ringColor: board.hub.ring
    anchors.fill: parent
    Shape {
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      Dot { cx: jp.cx; cy: jp.cy; r: board.px(8); w: board.px(2.5); fillColor: board.hub.raise; strokeColor: jp.ringColor }
      Dot { cx: jp.cx; cy: jp.cy; r: board.px(3.4); w: board.px(1); fillColor: board.hub.hole; strokeColor: board.hub.sel }
    }
  }

  // A spare position: an empty ring.
  component SparePath: Item {
    id: sp
    property real cx: 0
    property real cy: 0
    anchors.fill: parent
    Shape {
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      Dot { cx: sp.cx; cy: sp.cy; r: board.px(8); w: board.px(1.5); strokeColor: board.hub.lineColor }
    }
  }

  // A cord: a plug in each jack and the lead between them, bulging to the
  // right, on a dark under-stroke so it reads over the dotted wires.
  component Cord: Item {
    id: cord
    property real cx: 0
    property real y1: 0
    property real y2: 0
    property color tone: board.hub.fg
    readonly property real dy: y2 - y1
    anchors.fill: parent

    Shape {
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      ShapePath {
        strokeColor: board.hub.well
        strokeWidth: board.px(8)
        fillColor: "transparent"
        capStyle: ShapePath.RoundCap
        startX: cord.cx
        startY: cord.y1
        PathCubic {
          x: cord.cx
          y: cord.y2
          control1X: cord.cx + board.px(18)
          control1Y: cord.y1 + cord.dy * 0.2
          control2X: cord.cx + board.px(18)
          control2Y: cord.y1 + cord.dy * 0.8
        }
      }
      ShapePath {
        strokeColor: cord.tone
        strokeWidth: board.px(4)
        fillColor: "transparent"
        capStyle: ShapePath.RoundCap
        startX: cord.cx
        startY: cord.y1
        PathCubic {
          x: cord.cx
          y: cord.y2
          control1X: cord.cx + board.px(18)
          control1Y: cord.y1 + cord.dy * 0.2
          control2X: cord.cx + board.px(18)
          control2Y: cord.y1 + cord.dy * 0.8
        }
      }
      Dot { cx: cord.cx; cy: cord.y1; r: board.px(6); w: board.px(1.5); fillColor: cord.tone; strokeColor: board.hub.well }
      Dot { cx: cord.cx; cy: cord.y2; r: board.px(6); w: board.px(1.5); fillColor: cord.tone; strokeColor: board.hub.well }
    }
  }

  // One column of a bay: pos is its place in the bay, 0..7. A place with no
  // device is three spare rings.
  component Col: Item {
    id: col

    required property int bayIndex
    required property int pos

    readonly property string mac: (board.layout.bays[bayIndex] || [])[pos] || ""
    readonly property var jack: mac !== "" ? (board.byMac[mac] || null) : null
    readonly property var said: jack !== null ? Model.jackWord(jack, board.nowS) : null
    readonly property bool riveted: jack !== null && (jack.patch === "always" || jack.patch === "fixed")
    readonly property bool gate: said !== null && said.kind === "gate"
    // the row the wire, the cord or the rivets' bar runs to
    readonly property real rowY: jack !== null && jack.row === "pass" ? board.yT : board.yB
    readonly property real otherY: jack !== null && jack.row === "pass" ? board.yB : board.yT
    readonly property bool selected: jack !== null && jack.mac === board.hub.wdTicketMac
    readonly property bool kbCursor: jack !== null && !board.hub.cursorPointer && board.hub.has("bay:" + bayIndex, pos)
    readonly property real cx: board.colW / 2
    readonly property real rowH: board.px(24)

    x: board.pad + pos * board.colW
    width: board.colW
    height: board.bayH

    function wordColor(kind) {
      if (kind === "blocked") return board.hub.accent
      if (kind === "pass") return board.hub.bright
      if (kind === "gate") return board.hub.warning
      return board.hub.muted
    }

    // the joint between two strips
    Rectangle {
      visible: col.pos > 0
      x: -board.px(0.75)
      y: board.px(20)
      width: board.px(1.5)
      height: board.px(30)
      color: board.hub.well
    }

    SparePath { visible: col.jack === null; cx: col.cx; cy: board.yT }
    SparePath { visible: col.jack === null; cx: col.cx; cy: board.yD }
    SparePath { visible: col.jack === null; cx: col.cx; cy: board.yB }

    // everything of a device; an offline one is dimmed
    Item {
      id: face
      visible: col.jack !== null
      anchors.fill: parent
      opacity: col.jack !== null && col.jack.offline ? 0.38 : 1

      Rectangle {
        visible: col.selected
        y: board.px(2)
        width: col.width
        height: board.bayH - board.px(4)
        color: board.hub.hoverFill
      }

      // the drop lamp: lit while an alert rings this jack
      Rectangle {
        x: col.cx - board.px(6)
        y: board.px(8)
        width: board.px(12)
        height: board.px(6)
        color: col.jack === null || col.jack.lamp === "" ? board.hub.raise : (col.jack.lamp === "high" ? board.hub.urgent : board.hub.warning)
        border.width: 1
        border.color: col.jack === null || col.jack.lamp === "" ? board.hub.lineColor : (col.jack.lamp === "high" ? board.hub.urgent : board.hub.warning)
      }

      // the strip: the name in one or two lines, or a dashed blank ("new"
      // while nobody has known the device)
      Cap {
        visible: col.jack !== null && col.jack.strip.length > 0
        width: col.width
        horizontalAlignment: Text.AlignHCenter
        base: col.jack !== null && col.jack.strip.length > 1 ? board.px(32.5) : board.px(38.5)
        text: col.jack !== null && col.jack.strip.length > 0 ? col.jack.strip[0] : ""
      }
      Cap {
        visible: col.jack !== null && col.jack.strip.length > 1
        width: col.width
        horizontalAlignment: Text.AlignHCenter
        base: board.px(44.5)
        text: col.jack !== null && col.jack.strip.length > 1 ? col.jack.strip[1] : ""
      }
      Shape {
        visible: col.jack !== null && col.jack.strip.length === 0
        anchors.fill: parent
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
          strokeColor: col.jack !== null && col.jack.isNew ? board.hub.warning : board.hub.muted
          strokeWidth: 1
          fillColor: "transparent"
          strokeStyle: ShapePath.DashLine
          dashPattern: [board.px(3), board.px(3)]
          startX: col.cx - board.px(21)
          startY: board.px(23)
          PathLine { x: col.cx + board.px(21); y: board.px(23) }
          PathLine { x: col.cx + board.px(21); y: board.px(47) }
          PathLine { x: col.cx - board.px(21); y: board.px(47) }
          PathLine { x: col.cx - board.px(21); y: board.px(23) }
        }
      }
      Cap {
        visible: col.jack !== null && col.jack.strip.length === 0 && col.jack.isNew
        width: col.width
        horizontalAlignment: Text.AlignHCenter
        base: board.px(38.5)
        text: board.tr("wd.new")
        color: board.hub.warning
      }

      // its address
      Cap {
        width: col.width
        horizontalAlignment: Text.AlignHCenter
        base: board.px(64)
        text: col.jack !== null ? col.jack.tail : ""
        color: board.hub.dim
      }

      // the router and the Pi: rivets and a bar to the row they are fixed
      // to, a tick where the other row would be
      Rectangle {
        visible: col.riveted
        x: col.cx - board.px(5)
        y: col.otherY - board.px(0.5)
        width: board.px(10)
        height: 1
        color: board.hub.muted
      }
      Rectangle {
        visible: col.riveted
        x: col.cx - board.px(1.5)
        y: Math.min(board.yD, col.rowY)
        width: board.px(3)
        height: Math.abs(col.rowY - board.yD)
        color: board.hub.muted
      }
      Rectangle {
        visible: col.riveted
        x: col.cx - board.px(5)
        y: board.yD - board.px(5)
        width: board.px(10)
        height: board.px(10)
        color: board.hub.muted
      }
      Rectangle {
        visible: col.riveted
        x: col.cx - board.px(5)
        y: col.rowY - board.px(5)
        width: board.px(10)
        height: board.px(10)
        color: board.hub.muted
      }

      // three jacks
      JackPath { visible: !col.riveted; cx: col.cx; cy: board.yT }
      JackPath { visible: !col.riveted; cx: col.cx; cy: board.yD; ringColor: col.selected ? board.hub.bright : board.hub.ring }
      JackPath { visible: !col.riveted; cx: col.cx; cy: board.yB }

      // the normal wiring: a dotted wire from the line to the row NORMAL
      // names, with a dot in the jack it reaches
      Shape {
        visible: !col.riveted && col.jack !== null && !col.jack.cord
        anchors.fill: parent
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
          strokeColor: board.hub.dim
          strokeWidth: board.px(1.2)
          fillColor: "transparent"
          strokeStyle: ShapePath.DashLine
          dashPattern: [1 / 1.2, 4 / 1.2]
          capStyle: ShapePath.FlatCap
          startX: col.cx
          startY: board.yD
          PathLine { x: col.cx; y: col.rowY }
        }
        Dot { cx: col.cx; cy: col.rowY; r: board.px(2); fillColor: board.hub.dim }
      }

      // a cord somebody patched: ADS PASS is white, BLOCKED the accent
      Cord {
        visible: !col.riveted && col.jack !== null && col.jack.cord
        cx: col.cx
        y1: board.yD
        y2: col.rowY
        tone: col.jack !== null && col.jack.patch === "pass" ? board.hub.fg : board.hub.accent
      }

      // a gate: ADS PASS for a while, in amber, with its tag
      Cord {
        visible: col.gate
        cx: col.cx
        y1: board.yD
        y2: board.yT
        tone: board.hub.warning
      }
      Rectangle {
        visible: col.gate
        x: col.cx + board.px(10)
        y: board.yT + board.px(11)
        width: board.px(30)
        height: board.px(13)
        color: board.hub.cardColor
        border.width: 1
        border.color: board.hub.warning
      }
      Cap {
        visible: col.gate
        x: col.cx + board.px(10)
        width: board.px(30)
        horizontalAlignment: Text.AlignHCenter
        base: board.yT + board.px(21)
        text: board.tr("wd.gate")
        color: board.hub.warning
      }

      // the one word: BLOCKED, PASS, ALWAYS, FIXED, or the time a gate has left
      Cap {
        width: col.width
        horizontalAlignment: Text.AlignHCenter
        base: board.px(179)
        font.weight: Font.Bold
        font.letterSpacing: board.px(0.5)
        text: col.said === null ? "" : (col.said.kind === "gate" ? col.said.text : board.tr("wd.word." + col.said.kind))
        color: col.said === null ? board.hub.muted : col.wordColor(col.said.kind)
      }
    }

    // the pointer: hover puts the name in the readout, a click opens the ticket
    MouseArea {
      id: hit
      enabled: col.jack !== null
      x: 0
      y: board.px(17)
      width: col.width
      height: board.bayH - board.px(19)
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onContainsMouseChanged: {
        if (containsMouse) board.hoverMac = col.mac
        else if (board.hoverMac === col.mac) board.hoverMac = ""
      }
      onPositionChanged: function(mouse) { board.hub.hoverCursor(hit, mouse, "bay:" + col.bayIndex, col.pos) }
      onClicked: board.hub.wdToggleDevice(col.mac)

      Rectangle {
        anchors.fill: parent
        visible: hit.containsMouse
        color: Util.alpha(board.hub.fg, 0.05)
      }
    }

    // the drop lamp, when it is lit, opens the alert's ticket
    MouseArea {
      id: lampHit
      enabled: col.jack !== null && col.jack.lamp !== "" && col.jack.alertId !== null
      x: col.cx - board.px(20)
      y: board.px(1)
      width: board.px(40)
      height: board.px(16)
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: board.hub.wdOpenAlert(col.jack.alertId)
    }

    // the keyboard's ring
    Rectangle {
      visible: col.kbCursor
      x: 0
      y: board.px(17)
      width: col.width
      height: board.bayH - board.px(19)
      color: "transparent"
      border.width: 2
      border.color: Util.alpha(board.hub.fg, 0.7)
    }
  }

  // One bay: the plate with its four screws, the beds behind the rows of
  // jacks, the strip band, and eight columns.
  component Bay: Item {
    id: bay

    required property int bayIndex

    width: board.bayW
    height: board.bayH

    Rectangle {
      anchors.fill: parent
      radius: board.px(2)
      color: board.hub.well
      border.width: 1
      border.color: board.hub.lineColor
    }
    Shape {
      anchors.fill: parent
      preferredRendererType: Shape.CurveRenderer
      Dot { cx: board.px(6); cy: board.px(6); r: board.px(2.5); w: 1; fillColor: board.hub.cardColor; strokeColor: board.hub.muted }
      Dot { cx: board.bayW - board.px(6); cy: board.px(6); r: board.px(2.5); w: 1; fillColor: board.hub.cardColor; strokeColor: board.hub.muted }
      Dot { cx: board.px(6); cy: board.bayH - board.px(6); r: board.px(2.5); w: 1; fillColor: board.hub.cardColor; strokeColor: board.hub.muted }
      Dot { cx: board.bayW - board.px(6); cy: board.bayH - board.px(6); r: board.px(2.5); w: 1; fillColor: board.hub.cardColor; strokeColor: board.hub.muted }
    }
    Rectangle {
      x: board.pad
      y: board.yT - board.px(12)
      width: board.colW * 8
      height: board.px(24)
      color: Util.alpha(board.hub.fg, 0.03)
    }
    Rectangle {
      x: board.pad
      y: board.yB - board.px(12)
      width: board.colW * 8
      height: board.px(24)
      color: Util.alpha(board.hub.fg, 0.03)
    }
    Rectangle {
      x: board.pad
      y: board.px(20)
      width: board.colW * 8
      height: board.px(30)
      color: Util.alpha(board.hub.fg, 0.08)
    }
    Repeater {
      model: 8
      Col {
        required property int index
        bayIndex: bay.bayIndex
        pos: index
      }
    }
  }

  // The rail's part for one bay in view: the row names, the slot with its
  // knob (the NORMAL key) and the word "normal".
  component RailSlot: Item {
    id: slot

    required property int slotIndex
    readonly property real knobY: board.normalPass ? board.yT + board.px(12) : board.yB - board.px(26)
    readonly property bool hasCursor: board.hub.has("normal")

    y: slotIndex * board.slotH
    width: board.railW
    height: board.bayH

    Cap {
      x: board.px(6)
      base: board.yT + board.px(3.5)
      text: board.tr("wd.rail.pass")
      font.weight: Font.Bold
      font.letterSpacing: board.px(0.6)
      color: board.normalPass ? board.hub.fg : board.hub.dim
    }
    Cap {
      x: board.px(6)
      base: board.yB + board.px(3.5)
      text: board.tr("wd.rail.blocked")
      font.weight: Font.Bold
      font.letterSpacing: board.px(0.6)
      color: board.normalPass ? board.hub.dim : board.hub.fg
    }
    Rectangle {
      x: board.px(8)
      y: board.yT + board.px(14)
      width: board.px(12)
      height: board.px(44)
      radius: board.px(2)
      color: board.hub.hole
      border.width: 1
      border.color: board.hub.muted
    }
    Rectangle {
      x: board.px(4)
      y: slot.knobY
      width: board.px(20)
      height: board.px(14)
      radius: board.px(2)
      color: board.hub.fg
    }
    Cap {
      x: board.px(29)
      base: board.yD + board.px(3.5)
      text: board.tr("wd.rail.normal")
      color: board.hub.dim
    }

    MouseArea {
      id: keyHit
      x: 0
      y: board.yT + board.px(10)
      width: board.railW
      height: board.px(52)
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onPositionChanged: function(mouse) { board.hub.hoverCursor(keyHit, mouse, "normal", 0) }
      onClicked: board.hub.wdPressKey()

      Rectangle {
        anchors.fill: parent
        visible: keyHit.containsMouse
        color: Util.alpha(board.hub.fg, 0.05)
      }
      PanelToolTip {
        visible: keyHit.containsMouse
        text: board.tr("wd.keyTip")
        fontFamily: board.hub.fontFamily
      }
    }
    Rectangle {
      visible: slot.hasCursor
      x: 0
      y: board.yT + board.px(10)
      width: board.railW
      height: board.px(52)
      color: "transparent"
      border.width: 2
      border.color: board.hub.cursorPointer ? board.hub.accent : Util.alpha(board.hub.fg, 0.7)
    }
  }

  // ------------------------------------------------------------------ rail
  Repeater {
    model: board.shownCount
    RailSlot { required property int index; slotIndex: index }
  }

  // two bays in view: their keys are tied, and move as one
  Shape {
    id: tie
    readonly property real tieTop: (board.normalPass ? board.yT + board.px(12) : board.yB - board.px(26)) + board.px(7)
    readonly property real tieBottom: tieTop + (board.shownCount - 1) * board.slotH
    visible: board.shownCount > 1
    anchors.fill: parent
    preferredRendererType: Shape.CurveRenderer
    ShapePath {
      strokeColor: board.hub.muted
      strokeWidth: board.px(1.5)
      fillColor: "transparent"
      startX: board.px(4)
      startY: tie.tieTop
      PathLine { x: board.px(1.5); y: tie.tieTop }
      PathLine { x: board.px(1.5); y: tie.tieBottom }
      PathLine { x: board.px(4); y: tie.tieBottom }
    }
  }

  // ------------------------------------------------------------------ bays
  // Only the bays in view are built, and they snap into place when the board
  // scrolls: a bay at a time, never half of one.
  Item {
    x: board.railW
    width: board.bayW
    height: board.height
    clip: true

    Repeater {
      model: board.layout.bays.length

      Loader {
        id: bayLoader
        required property int index
        y: (index - board.firstBay) * board.slotH
        active: index >= board.firstBay && index < board.firstBay + board.shownCount
        sourceComponent: Bay { bayIndex: bayLoader.index }
      }
    }

    // the wheel moves a bay at a time
    WheelHandler {
      property real acc: 0
      enabled: board.layout.pager !== null
      acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
      onWheel: function(event) {
        acc += event.angleDelta.y
        if (Math.abs(acc) < 120) return
        board.hub.wdPage(acc < 0 ? 1 : -1)
        acc = 0
      }
    }
  }
}

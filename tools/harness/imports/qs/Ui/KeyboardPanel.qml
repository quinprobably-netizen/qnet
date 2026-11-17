import QtQuick
import qs.Commons
import qs.Commons as Commons
import Harness

// The shell's keyboard panel as an Item: the card without the layer-shell
// window. Same API as the real one, which Panel.qml reads:
//   contentWidth / contentHeight   the CARD's size (the real card is as wide
//                                  as the width asked for, its content
//                                  narrower by the padding and the border)
//   fittedContentWidth/Height      what the panel asks for + the insets
//   default children               go in the content holder, inside the padding
//   card.shown                     0..1, here 1 once open (Panel.qml walks up
//                                  from its key catcher to the first `shown`)
//
// The harness card is 520 px wide: the 488 px content column the panel asks
// for, and 16 px of padding on each side with the 1 px line inside it, as in
// the mockup stills. ui.json {"realWidth": true} draws it as the shell does
// instead: the card as wide as the 488 asked for, the content 456.
Item {
  id: root

  property Item anchorItem: null
  property var owner: null
  property var bar: null
  property bool open: false
  property Item focusTarget: null
  property int contentWidth: 520
  property int contentHeight: 200

  readonly property real padding: 16
  // A tall screen: the panel's list rows depend on it.
  readonly property real availableCardHeight: 1000
  readonly property real availableCardWidth: 1800

  default property alias contentItem: holder.children

  function fittedContentWidth(width, cap) {
    var w = Math.max(1, Number(width) || 1)
    return Harness.ui.realWidth === true ? w : w + 2 * padding
  }

  function fittedContentHeight(implicitHeight, cap) {
    var h = Math.max(2 * padding, (Number(implicitHeight) || 0) + 2 * padding)
    if (cap !== undefined && Number(cap) > 0) h = Math.min(h, Number(cap))
    return Math.round(Math.min(h, availableCardHeight))
  }

  width: card.width
  height: card.height

  BorderSurface {
    id: card
    width: root.contentWidth
    height: root.contentHeight
    color: Commons.Color.popups.background
    radius: Style.cornerRadius
    borderSpec: Border.flat(Commons.Color.popups.border, 1)
    property real shown: root.open ? 1 : 0

    Item {
      id: holder
      x: root.padding
      y: root.padding
      width: root.contentWidth - 2 * root.padding
      height: root.contentHeight - 2 * root.padding
    }
  }

  Component.onCompleted: Harness.card = card
  onOpenChanged: if (open && focusTarget) focusTarget.forceActiveFocus()
}

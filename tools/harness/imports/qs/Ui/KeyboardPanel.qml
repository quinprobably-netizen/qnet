import QtQuick
import qs.Commons
import qs.Commons as Commons
import Harness

// The shell's keyboard panel as an Item: the card without the layer-shell
// window. Same API as the real one, which Panel.qml reads:
//   contentWidth / contentHeight   the CARD's size (as in the shell, the card
//                                  is as wide as the width asked for; its
//                                  content is narrower by the padding and the
//                                  border on each side)
//   fittedContentWidth/Height      what the panel asks for, within the screen
//                                  (the height gains the insets)
//   default children               go in the content holder, inside the padding
//   card.shown                     0..1, here 1 once open (Panel.qml walks up
//                                  from its key catcher to the first `shown`)
//
// The geometry is the shell's own: popup padding 14 plus a border of
// max(1, Style.space(2)) = 2 on every side, so a card of width W holds a
// content column of W - 32 (456 for the 488 the panel asks for, 488 for the
// 520 the watchdog view asks for). The card is drawn at exactly that size, on
// every view.
Item {
  id: root

  property Item anchorItem: null
  property var owner: null
  property var bar: null
  property bool open: false
  property Item focusTarget: null
  property int contentWidth: 488
  property int contentHeight: 200

  readonly property real padding: Style.spacing.popupPadding
  readonly property real borderWidth: Math.max(1, Style.space(2))
  readonly property real inset: padding + borderWidth
  // A tall screen: the panel's list rows depend on it.
  readonly property real availableCardHeight: 1000
  readonly property real availableCardWidth: 1800

  default property alias contentItem: holder.children

  function fittedContentWidth(width, cap) {
    var w = Math.max(1, Number(width) || 1)
    var m = availableCardWidth
    if (cap !== undefined && Number(cap) > 0) m = Math.min(m, Number(cap))
    return Math.round(Math.min(w, m))
  }

  function fittedContentHeight(implicitHeight, cap) {
    var h = Math.max(2 * inset, (Number(implicitHeight) || 0) + 2 * inset)
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
    borderSpec: Border.flat(Commons.Color.popups.border, root.borderWidth)
    property real shown: root.open ? 1 : 0

    Item {
      id: holder
      x: root.inset
      y: root.inset
      width: root.contentWidth - 2 * root.inset
      height: root.contentHeight - 2 * root.inset
    }
  }

  Component.onCompleted: Harness.card = card
  onOpenChanged: if (open && focusTarget) focusTarget.forceActiveFocus()
}

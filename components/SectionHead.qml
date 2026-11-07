import QtQuick
import qs.Commons

// A section's top: one hairline across the content column, then a small
// sentence-case dim label (the same head Sound Hub's sections wear). Whatever
// is put inside `trailing` sits on the label's row at the right edge.
Item {
  id: head

  required property var hub
  property string text: ""
  property int above: Style.space(14)
  property int below: Style.space(8)
  default property alias trailing: trailingSlot.data

  width: parent ? parent.width : 0
  implicitHeight: row.y + row.height

  Rectangle {
    id: line
    y: head.above
    x: head.hub.gutter
    width: head.width - 2 * head.hub.gutter
    height: 1
    color: head.hub.lineColor
  }

  Item {
    id: row
    y: line.y + line.height + head.below
    width: head.width
    height: Math.max(label.implicitHeight, trailingSlot.childrenRect.height) + Style.space(2)

    Text {
      id: label
      textFormat: Text.PlainText
      renderType: Text.NativeRendering
      text: head.text
      color: head.hub.dim
      font.family: head.hub.fontFamily
      font.pixelSize: head.hub.typeSmall
      anchors.left: parent.left
      anchors.leftMargin: head.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
    }

    Item {
      id: trailingSlot
      anchors.right: parent.right
      anchors.rightMargin: head.hub.gutter
      anchors.verticalCenter: parent.verticalCenter
      width: childrenRect.width
      height: childrenRect.height
    }
  }
}

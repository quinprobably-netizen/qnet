import QtQuick
import qs.Commons

// A section's head: a small dim label with its rule running on to the right
// edge (or to whatever is put inside `trailing`, which sits at the right
// edge of the same row: the scan button).
Item {
  id: head

  required property var hub
  property string text: ""
  property int above: Style.space(12)
  property int below: Style.space(4)
  default property alias trailing: trailingSlot.data

  width: parent ? parent.width : 0
  implicitHeight: above + row.height + below

  Item {
    id: row
    y: head.above
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

    Rectangle {
      anchors.left: label.right
      anchors.leftMargin: Style.space(10)
      anchors.right: trailingSlot.left
      anchors.rightMargin: trailingSlot.width > 0 ? Style.space(6) : 0
      anchors.verticalCenter: parent.verticalCenter
      height: 1
      color: head.hub.lineColor
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

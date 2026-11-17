import QtQuick

// The bar's icon: not part of a shot (the card is), so it draws nothing.
Item {
  property var bar: null
  property string text: ""
  property bool active: false
  property string tooltipText: ""
  signal pressed(int b)
  signal wheelMoved(real delta)
  implicitWidth: 20
  implicitHeight: 20
}

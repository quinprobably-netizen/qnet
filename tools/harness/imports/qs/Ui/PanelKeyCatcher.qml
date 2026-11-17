import QtQuick

// The shell's key dispatcher without the keys: no input is ever sent, so only
// the properties and signals the panel connects to are here.
Item {
  property bool blocked: false
  property bool reorderable: false
  signal moveRequested(int dx, int dy)
  signal reorderRequested(int dy)
  signal activateRequested()
  signal returnRequested()
  signal closeRequested()
  signal deleteRequested()
  signal tabRequested(int direction)
  signal textKey(string text, int modifiers)
  focus: true
}

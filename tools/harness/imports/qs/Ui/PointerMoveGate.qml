import QtQuick

// No pointer moves in a shot: nothing is ever "moved".
QtObject {
  property Item referenceItem: null
  property real threshold: 1
  function reset() { }
  function allowInitialSample() { }
  function moved(item, mouse) { return false }
}

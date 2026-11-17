import QtQuick

// A stdout collector the Process stub feeds: all of it at once, then the end.
QtObject {
  property string text: ""
  property bool waitForEnd: false
  signal streamFinished()
  function feed(t) { text = t; streamFinished() }
}

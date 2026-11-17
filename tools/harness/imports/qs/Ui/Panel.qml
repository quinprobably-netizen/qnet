import QtQuick

// The bar plugin base: a bar widget that opens a panel. Here `opened` is
// all there is to it; Shot.qml calls open().
Item {
  property QtObject bar: null
  property string moduleName: ""
  property var settings: ({})
  property string ipcTarget: ""
  property bool manageIpc: true
  property bool opened: false
  function open() { opened = true }
  function close() { opened = false }
  function toggle() { opened ? close() : open() }
  function switchPanel(direction) { }
}

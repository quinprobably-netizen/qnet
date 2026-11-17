import QtQuick
import QtQml.Models

// Quickshell's ScriptModel: a model of a JS array, each entry as `modelData`.
// The real one diffs by objectProp so a row keeps its identity when the list
// reorders; a shot only needs the rows.
ListModel {
  id: root

  dynamicRoles: true
  property var values: []
  property string objectProp: ""

  function sync() {
    clear()
    var list = Array.isArray(values) ? values : []
    for (var i = 0; i < list.length; i++) append({ modelData: list[i] })
  }

  onValuesChanged: sync()
  Component.onCompleted: sync()
}

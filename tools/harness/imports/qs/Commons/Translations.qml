import QtQuick
import Harness

// The plugin's own catalog, as Commons.Translations reads it: <directory>/en.json,
// read once. A value is a string, or an object of plural forms ({one, other}).
QtObject {
  id: root

  property var directory: ""
  readonly property string language: "en"
  readonly property string directoryPath: String(directory).replace(/^file:\/\//, "").replace(/\/+$/, "")
  readonly property var strings: {
    try { return JSON.parse(Harness.readFile(directoryPath + "/en.json")) } catch (e) {
      console.warn("shot: cannot read " + directoryPath + "/en.json: " + e)
      return ({})
    }
  }

  function t(key, fallback) {
    var value = root.strings[key]
    if (value && typeof value === "object") value = value.other
    if (typeof value === "string" && value.length > 0) return value
    return fallback !== undefined ? fallback : key
  }

  // English plural rule: "one" for exactly 1, else "other".
  function tn(key, count, fallback) {
    var value = root.strings[key]
    if (value && typeof value === "object") value = Number(count) === 1 && value.one !== undefined ? value.one : value.other
    if (typeof value === "string" && value.length > 0) return value
    return fallback !== undefined ? fallback : key
  }
}

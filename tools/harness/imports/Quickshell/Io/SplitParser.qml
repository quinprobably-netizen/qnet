import QtQuick

// A stdout parser the Process stub feeds: one `read` per non-empty line.
QtObject {
  signal read(string data)
  function feed(text) {
    var lines = String(text).split("\n")
    for (var i = 0; i < lines.length; i++) if (lines[i] !== "") read(lines[i])
  }
}

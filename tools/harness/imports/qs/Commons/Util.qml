pragma Singleton
import QtQuick

QtObject {
  function clampAlpha(a) { var n = Number(a); return isFinite(n) ? Math.max(0, Math.min(1, n)) : 1 }
  // `c` at the given opacity; a string colour is parsed first.
  function alpha(c, opacity) {
    var a = clampAlpha(opacity)
    if (!c) return Qt.rgba(0, 0, 0, a)
    if (typeof c === "string") c = Qt.color(c)
    return Qt.rgba(c.r, c.g, c.b, a)
  }
}

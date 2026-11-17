pragma Singleton
import QtQuick

// English, the way the shell's I18n answers for it.
QtObject {
  readonly property string language: "en"
  readonly property string formatLocale: "en-US"
  readonly property string decimal: "."
  readonly property string zeroDigit: "0"
  readonly property bool rightToLeft: false

  function formatNumber(value, decimals) {
    var n = Number(value)
    if (!isFinite(n)) return String(value)
    return decimals === undefined ? String(n) : n.toFixed(decimals)
  }
}

pragma Singleton
import QtQuick
import qs.Commons as Commons

// Stub of the shell's Style at scale 1 and font base size 12. Motion is off
// (reduceMotion), so a shot never catches an animation half way and the
// route's flow stands still, as the panel draws it with animations off.
QtObject {
  readonly property int cornerRadius: 6
  readonly property bool reduceMotion: true
  readonly property var easeOut: [0.23, 1.0, 0.32, 1.0, 1.0, 1.0]

  function spaceReal(px) { return Math.max(0, Number(px) || 0) }
  function space(px) { var n = Number(px) || 0; return n <= 0 ? 0 : Math.max(1, Math.round(n)) }
  function duration(ms) { return reduceMotion ? 0 : ms }

  readonly property QtObject font: QtObject {
    readonly property string family: "JetBrainsMono Nerd Font"
    readonly property int caption: 10
    readonly property int bodySmall: 11
    readonly property int body: 12
    readonly property int subtitle: 13
    readonly property int title: 14
    readonly property int heading: 16
    readonly property int display: 24
    readonly property int icon: 14
    readonly property int iconSmall: 11
    readonly property int iconLarge: 18
  }

  readonly property QtObject spacing: QtObject {
    readonly property int hairline: 1
    readonly property int xxs: 2
    readonly property int xs: 3
    readonly property int sm: 4
    readonly property int md: 6
    readonly property int lg: 8
    readonly property int xl: 10
    readonly property int xxl: 12
    readonly property int xxxl: 14
    readonly property int huge: 18
    readonly property int controlGap: 8
    readonly property int controlPaddingX: 10
    readonly property int controlPaddingY: 6
    readonly property int inputPaddingY: 7
    readonly property int popupPadding: 14
  }

  // The state tokens of the shell's defaults.
  readonly property real normalFillAlpha: 0.04
  readonly property real hoverFillAlpha: 0.08
  readonly property real selectedFillAlpha: 0.18
  readonly property real selectionFillAlpha: 0.35
  readonly property real normalBorderAlpha: 0.4
  readonly property real hoverBorderAlpha: 0.25
  readonly property real selectedBorderAlpha: 1.0
  readonly property int normalBorderWidth: 1
  readonly property int hoverBorderWidth: 1
  readonly property int selectedBorderWidth: 0

  function normalFillFor(fg, accent) { return Commons.Util.alpha(fg, normalFillAlpha) }
  function hoverFillFor(fg, accent) { return Commons.Util.alpha(fg, hoverFillAlpha) }
  function selectedFillFor(fg, accent) { return Commons.Util.alpha(fg, selectedFillAlpha) }
  function focusFillFor(fg, accent) { return Commons.Util.alpha(fg, hoverFillAlpha) }
  function selectionFillFor(fg, accent) { return Commons.Util.alpha(fg, selectionFillAlpha) }
  function controlFill(focused, hot, fg, accent) {
    return focused ? focusFillFor(fg, accent) : (hot ? hoverFillFor(fg, accent) : normalFillFor(fg, accent))
  }
}

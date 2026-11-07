import QtQuick
import qs.Commons
import qs.Commons as Commons

// The plasma of the route, as colours: the theme's accent with more life in
// it (saturation, a second hue stop, the crest leaning round the colour
// wheel). Desaturated (`frozen`: the numbers are old, or DNS is not going
// through the Pi-hole) it is the plain foreground, fading. The hero's route
// and the DNS view's chain draw their tubes with the same palette.
QtObject {
  id: pal

  property color accent: Commons.Color.accent
  property color fg: Commons.Color.foreground
  property color dim: Qt.darker(Commons.Color.foreground, 1.4)
  property bool frozen: false

  function shifted(c, dHue, sat, light, satFloor) {
    var h = c.hslHue < 0 ? 0 : c.hslHue
    var s = c.hslSaturation < 0.08 ? c.hslSaturation : Math.min(1, Math.max(satFloor, c.hslSaturation * sat))
    return Qt.hsla((h + dHue + 1) % 1, s, Math.min(0.78, c.hslLightness * light), c.a)
  }

  function mix(a, b, k) {
    return Qt.rgba(a.r + (b.r - a.r) * k, a.g + (b.g - a.g) * k, a.b + (b.b - a.b) * k, a.a + (b.a - a.a) * k)
  }

  property color base: frozen ? fg : shifted(accent, 0, 1.15, 1.0, 0.5)
  property color crest: frozen ? fg : shifted(accent, 0.09, 1.2, 1.15, 0.6)
  property color foot: frozen ? fg : shifted(accent, -0.07, 1.2, 0.9, 0.55)
  property color band: frozen ? dim : shifted(accent, 0.025, 1.1, 1.3, 0.6)
  Behavior on base { ColorAnimation { duration: Style.duration(160) } }
  Behavior on crest { ColorAnimation { duration: Style.duration(160) } }
  Behavior on foot { ColorAnimation { duration: Style.duration(160) } }
  Behavior on band { ColorAnimation { duration: Style.duration(160) } }

  // The plasma along a run, foot to base to crest, t in 0..1.
  function at(t) {
    var k = Math.max(0, Math.min(1, t))
    return k < 0.5 ? mix(foot, base, k * 2) : mix(base, crest, (k - 0.5) * 2)
  }
}

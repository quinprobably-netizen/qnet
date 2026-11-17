pragma Singleton
import QtQuick
import qs.Commons as Commons

// Border specs of the stub BorderSurface: { color, width }, all four sides
// alike (the shell's are per side and may be gradients).
QtObject {
  function none() { return { color: "transparent", width: 0 } }
  function flat(color, width) { return { color: color || "transparent", width: width || 0 } }

  // state: "normal" | "hover-cursor" | "selected" | "focus", in the shell's
  // default tokens.
  function controlSpec(state, fg, accent) {
    switch (state) {
    case "selected": return flat(Commons.Util.alpha(fg, Commons.Style.selectedBorderAlpha), Commons.Style.selectedBorderWidth)
    case "hover-cursor":
    case "focus": return flat(Commons.Util.alpha(fg, Commons.Style.hoverBorderAlpha), Commons.Style.hoverBorderWidth)
    default: return flat(Commons.Util.alpha(fg, Commons.Style.normalBorderAlpha), Commons.Style.normalBorderWidth)
    }
  }

  function top(spec) { return spec ? spec.width : 0 }
  function right(spec) { return spec ? spec.width : 0 }
  function bottom(spec) { return spec ? spec.width : 0 }
  function left(spec) { return spec ? spec.width : 0 }
}

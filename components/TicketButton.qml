import QtQuick
import qs.Ui
import qs.Commons

// A button of a ticket or of the PIN footer: the mockup's .btn. `kind` says
// what it is: "plain" (a ground of its own), "primary" (the ticket's one
// button that does the thing: the accent ground, bright bold type) or
// "quiet" (no ground, dim until the cursor or pointer is on it). Dead while
// an action of the tab runs (hub.wdBusy), so none of them runs twice.
TextButton {
  id: btn

  property string kind: "plain"

  height: Style.space(27)
  padX: Style.space(10)
  padY: Style.space(6)
  radius: Math.min(Style.cornerRadius, Style.space(3))
  hoverFilled: true
  filled: kind !== "quiet"
  restColor: kind === "primary" ? hub.sel : hub.restFill
  textColor: kind === "primary" ? hub.bright : (kind === "quiet" ? hub.dim : hub.fg)
  hotColor: kind === "primary" ? hub.bright : (kind === "quiet" ? hub.fg : hub.fg)
  weight: kind === "primary" ? Font.Bold : Font.Normal
  enabled: !hub.wdBusy
}

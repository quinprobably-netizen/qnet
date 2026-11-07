// Interaction and type tokens shared by every surface in the panel. No QML
// types and no imports, so node can load it; Panel.qml exposes them on
// root and the components read them here (some get a foreground, not root).
//
// Interaction (root.restFill / root.hoverFill / root.pressScale /
// root.disabledOpacity):
//   REST_FILL         foreground alpha of a clickable surface at rest
//   HOVER_FILL        foreground alpha while the pointer is over it
//   PRESS_SCALE       scale while it is pressed (one press rule)
//   DISABLED_OPACITY  the one opacity for a disabled control
//
// Surfaces (root.wellFill / root.lineColor / root.frameInset):
//   WELL_FILL         foreground alpha of an open Section's well, the one
//                     box besides the profile tiles
//   LINE_ALPHA        foreground alpha of the hairline between sections
//   FRAME_INSET       px from the card's border to the content (its ink, or
//                     a visible box) on all four sides, in every view
//
// Type (root.sansFamily, root.typeTitle / typeBody / typeSmall): a
// proportional sans for titles, names, labels and prose; the bar's mono
// (root.fontFamily) only for numbers, units next to them, and values.
// Three sizes, all derived from the shell's Style.font so `[font]
// base-size` scales them:
//   typeTitle  round(Style.font.body × TITLE_SCALE)  page title (20 at 12)
//   typeBody   round(Style.font.body × BODY_SCALE)   names, rows    (15)
//   typeSmall  Style.font.subtitle                    secondary, dim (13)
// The sizes of the approved A+B mockups (scratchpad/mockups/T.js).

var REST_FILL = 0.06
var HOVER_FILL = 0.12
var PRESS_SCALE = 0.97
var DISABLED_OPACITY = 0.45

var WELL_FILL = 0.045
var LINE_ALPHA = 0.11
var FRAME_INSET = 22

// The shell's own family (Style.font.family, the fontconfig alias `omarchy font set`
// writes), so the panel uses the native Omarchy plugin font for words too.
var SANS_FAMILY = "monospace"
var TITLE_SCALE = 1.667
var BODY_SCALE = 1.25

// The fill alpha for a surface: hover wins over rest.
function fillAlpha(hot) { return hot ? HOVER_FILL : REST_FILL }

// The page title size for a body size (Style.font.body).
function titleSize(body) {
  var b = Number(body)
  return Math.max(1, Math.round((isFinite(b) && b > 0 ? b : 12) * TITLE_SCALE))
}

// ---- mixed text: words in sans, numbers in mono ---------------------------
//
// A "part" is [text, kind] (or {text, kind}); components/Segments.qml draws
// a list of them on one baseline. Kinds:
//   w  word, sans, dim            ("max", "MHz", "stock,")
//   f  word, sans, foreground     (a profile name)
//   n  number, mono, foreground   ("5273")
//   a  accent: state/selection    ("−5" on a changed setting)
//   h  hint, sans, the fainter dim ("changes need Apply")
//   u  urgent: a real fault       ("lost")
// a, f and u pick mono or sans by their text (isNumber).
var KINDS = ["w", "f", "n", "a", "h", "u"]

// A figure: an optional sign, digits with . , : inside, an optional %.
// "5273", "−5", "±0", "1.16", "1:15", "62%".
var NUMBER_RE = /^[−+±-]?\d[\d.,:]*%?$/

function isNumber(text) {
  return NUMBER_RE.test(String(text === null || text === undefined ? "" : text).trim())
}

// One part as {text, kind}, or null for an empty one. An unknown kind
// reads as a word.
function part(p) {
  if (p === null || p === undefined) return null
  var text, kind
  if (Array.isArray(p)) { text = p[0]; kind = p[1] }
  else if (typeof p === "object") { text = p.text; kind = p.kind }
  else { text = p; kind = "w" }
  text = text === null || text === undefined ? "" : String(text)
  if (text === "") return null
  kind = KINDS.indexOf(String(kind)) >= 0 ? String(kind) : "w"
  return { text: text, kind: kind }
}

// Whether a part draws in the mono face.
function partMono(p) {
  var q = part(p)
  if (!q) return false
  if (q.kind === "n") return true
  if (q.kind === "w" || q.kind === "h") return false
  return isNumber(q.text)
}

// A list of parts cleaned to {text, kind}, empty ones dropped.
function normalize(parts) {
  var out = []
  if (!parts || typeof parts.length !== "number") return out
  for (var i = 0; i < parts.length; i++) {
    var q = part(parts[i])
    if (q) out.push(q)
  }
  return out
}

// A plain string split into parts: each figure its own `numberKind` part
// (default "n"), the words between joined into one `wordKind` part
// (default "w"). "max 5273 min 2394 MHz" →
// [max w][5273 n][min w][2394 n][MHz w].
function parts(text, numberKind, wordKind) {
  var nk = numberKind || "n"
  var wk = wordKind || "w"
  var s = String(text === null || text === undefined ? "" : text).trim()
  if (s === "") return []
  var out = []
  var words = []
  var toks = s.split(/\s+/)
  for (var i = 0; i < toks.length; i++) {
    if (isNumber(toks[i])) {
      if (words.length) { out.push({ text: words.join(" "), kind: wk }); words = [] }
      out.push({ text: toks[i], kind: nk })
    } else {
      words.push(toks[i])
    }
  }
  if (words.length) out.push({ text: words.join(" "), kind: wk })
  return out
}

// What a Section's header shows on the right: rich `rich` parts when given,
// else `summary` as words then `value` split by parts() (a figure and its
// unit: "88 W" → [88 n][W w]).
function summaryParts(summary, value, rich) {
  var r = normalize(rich)
  if (r.length) return r
  var out = []
  var s = part([summary, "w"])
  if (s) out.push(s)
  return out.concat(parts(value))
}

if (typeof module !== "undefined") {
  module.exports = {
    REST_FILL: REST_FILL, HOVER_FILL: HOVER_FILL, PRESS_SCALE: PRESS_SCALE,
    DISABLED_OPACITY: DISABLED_OPACITY, WELL_FILL: WELL_FILL, LINE_ALPHA: LINE_ALPHA,
    FRAME_INSET: FRAME_INSET,
    SANS_FAMILY: SANS_FAMILY, TITLE_SCALE: TITLE_SCALE, BODY_SCALE: BODY_SCALE, KINDS: KINDS,
    fillAlpha: fillAlpha, titleSize: titleSize, isNumber: isNumber, part: part, partMono: partMono,
    normalize: normalize, parts: parts, summaryParts: summaryParts
  }
}

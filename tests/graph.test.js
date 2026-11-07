"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, state, NOW_S } = require("./helpers.js")

const series = (name) => {
  const p = state(name).pihole
  const span = p.historySpanS > 0 ? p.historySpanS : Model.dataSpan(p.history, NOW_S)
  return Model.historySeries(p.history, NOW_S, span)
}

// ---- the x-axis fits the history ---------------------------------------

test("the axis is three hours at least, a day at most, and as long as the history between", () => {
  assert.equal(Model.axisSpan(0), 10800)
  assert.equal(Model.axisSpan(5400), 10800)
  assert.equal(Model.axisSpan(10800), 10800)
  assert.equal(Model.axisSpan(30000), 30000)
  assert.equal(Model.axisSpan(86400), 86400)
  assert.equal(Model.axisSpan(10 * 86400), 86400)
  assert.equal(Model.axisSpan(NaN), 10800)
})

test("a day of history is 144 columns", () => {
  const s = series("healthy")
  assert.equal(s.n, 144)
  assert.equal(s.axisS, 86400)
  assert.equal(s.start, 0)
  assert.equal(s.total.length, 144)
  const max = Math.max.apply(null, s.total)
  assert.ok(max < 1 && max > 0.8, "peak sits just under the top: " + max)
  for (let i = 0; i < 144; i++) {
    assert.ok(s.total[i] >= 0 && s.total[i] <= 1)
    assert.ok(s.blocked[i] >= 0 && s.blocked[i] <= s.total[i] + 1e-12, "blocked is a share of total")
  }
})

test("1.5 h of history on a 3 h axis: 18 columns, empty on the left, data on the right", () => {
  const s = series("partial")
  assert.equal(s.n, 18)
  assert.equal(s.axisS, 10800)
  assert.equal(s.start, 9, "the data begins half way across")
  for (let i = 0; i < 8; i++) assert.equal(s.total[i], 0, "column " + i)
  assert.ok(s.total[17] > 0.5)
  assert.ok(Math.max.apply(null, s.total) > 0.85 && Math.max.apply(null, s.total) < 1)
})

test("data that runs older than three hours widens the axis to fit it", () => {
  const h = []
  for (let i = 35; i >= 0; i--) h.push({ t: 1794122400 - i * 600, total: 50, blocked: 5 })
  const s = Model.historySeries(h, NOW_S, 36 * 600)
  assert.equal(s.axisS, 21600)
  assert.equal(s.n, 36)
  assert.equal(s.start, 0)
})

test("the span label is only for under a day", () => {
  assert.equal(Model.showSpanLabel(5400), true)
  assert.equal(Model.showSpanLabel(86400), false)
  assert.equal(Model.showSpanLabel(0), false)
  assert.equal(Model.formatSpan(5400), "1.5 h")
  assert.equal(Model.formatSpan(7200), "2 h")
  assert.equal(Model.formatSpan(2400), "40 min")
  assert.equal(Model.formatSpan(50000), "14 h")
  assert.equal(Model.formatSpan(30), "1 min")
  assert.equal(Model.formatSpan(5400, (v, d) => v.toFixed(d).replace(".", ",")), "1,5 h")
})

test("the span can be worked out from the data when the backend does not say", () => {
  const p = state("partial").pihole
  const span = Model.dataSpan(p.history, NOW_S)
  assert.ok(span > 4800 && span < 5400, "from the first non-empty bucket to now: " + span)
  assert.equal(Model.dataSpan([], NOW_S), 0)
  assert.equal(Model.dataSpan([{ t: 1, total: 0, blocked: 0 }], NOW_S), 0)
})

// ---- the series ---------------------------------------------------------

test("empty history has no series; flat zero keeps a zero peak", () => {
  assert.equal(Model.historySeries([], NOW_S, 0), null)
  const flat = Model.historySeries([{ t: NOW_S - 100, total: 0, blocked: 0 }], NOW_S, 0)
  assert.equal(flat.peak, 0)
  assert.ok(flat.total.every((v) => v === 0))
  assert.equal(flat.start, flat.n, "nothing begins anywhere")
})

test("buckets outside the axis are ignored; gaps are empty columns", () => {
  const h = [
    { t: NOW_S - 90000, total: 999, blocked: 0 },
    { t: NOW_S - 1200, total: 50, blocked: 10 },
    { t: NOW_S - 600, total: 50, blocked: 10 }
  ]
  const s = Model.historySeries(h, NOW_S, 86400)
  assert.ok(s.total[0] === 0 && s.total[10] === 0, "the old bucket did not land anywhere")
  assert.ok(s.total[142] > 0 && s.total[143] > 0)
  assert.ok(s.peak < 60)
})

test("the bucket still filling is scaled up, not drawn as a dip", () => {
  // now is 300 s into the newest bucket, which holds half a bucket's queries
  const h = []
  for (let i = 143; i >= 0; i--) h.push({ t: 1794122400 - i * 600, total: i === 0 ? 50 : 100, blocked: i === 0 ? 5 : 10 })
  const s = Model.historySeries(h, NOW_S, 86400)
  const last = s.total[143]
  const before = s.total[142]
  assert.ok(Math.abs(last - before) / before < 0.2, "the end holds level: " + last + " vs " + before)
})

test("a bucket with almost nothing in it yet repeats the one before", () => {
  const h = []
  for (let i = 143; i >= 0; i--) h.push({ t: 1794122400 - i * 600, total: i === 0 ? 1 : 100, blocked: 0 })
  const s = Model.historySeries(h, 1794122400 + 30, 86400)
  assert.ok(Math.abs(s.total[143] - s.total[142]) < 0.05)
})

// ---- the edge -----------------------------------------------------------

test("edge points run left to right over the width, 0 on the floor", () => {
  const pts = Model.edgePoints([0, 0.5, 1], 10, 100, 80, 60)
  assert.deepEqual(pts, [{ x: 10, y: 80 }, { x: 60, y: 50 }, { x: 110, y: 20 }])
  assert.deepEqual(Model.edgePoints([0.5], 0, 10, 10, 10), [])
  assert.equal(Model.edgePoints([-3, 7], 0, 10, 10, 10)[1].y, 0, "values are clamped to 0..1")
})

test("the smooth edge passes through every value, in order, inside the plot", () => {
  const vals = [0, 0, 0.2, 0.9, 0.5, 0.7]
  const pts = Model.smoothEdge(vals, 0, 500, 100, 80, 6)
  assert.equal(pts.length, (vals.length - 1) * 6 + 1)
  assert.equal(pts[0].x, 0)
  assert.equal(pts[pts.length - 1].x, 500)
  for (let i = 1; i < pts.length; i++) assert.ok(pts[i].x > pts[i - 1].x)
  for (const p of pts) assert.ok(p.y <= 100 + 1e-9 && p.y >= 20 - 1e-9, "inside the plot: " + p.y)
  // the sampled points at column boundaries are the values themselves
  vals.forEach((v, i) => {
    const p = i === vals.length - 1 ? pts[pts.length - 1] : pts[i * 6]
    assert.ok(Math.abs(p.y - (100 - v * 80)) < 1e-9, "column " + i)
  })
  assert.deepEqual(Model.smoothEdge([0.5], 0, 10, 10, 10, 6), [])
})

test("zero spans are not stroked: only runs that stand off the floor", () => {
  const s = series("partial")
  const pts = Model.smoothEdge(s.total, 0, 480, 140, 100, 6)
  const runs = Model.strokeRuns(pts, 140, 1.2)
  assert.equal(runs.length, 1, "one hill")
  assert.ok(runs[0][0].x > 150, "the stroke starts at the foot of the hill, not at the left edge: " + runs[0][0].x)
  assert.ok(runs[0][0].x >= pts[(s.start - 2) * 6].x, "and no earlier than a column before the data")
  assert.equal(runs[0][runs[0].length - 1].x, 480)
})

test("a flat graph has no stroke at all, two hills have two", () => {
  assert.deepEqual(Model.strokeRuns(Model.smoothEdge([0, 0, 0, 0], 0, 100, 50, 40, 4), 50, 1.2), [])
  const two = Model.smoothEdge([0, 0.8, 0, 0, 0.8, 0], 0, 500, 100, 80, 6)
  assert.equal(Model.strokeRuns(two, 100, 1.2).length, 2)
})

test("the head dot follows the newest probe", () => {
  assert.deepEqual(Model.headState(state("healthy").pihole.probes), { ok: true, ms: state("healthy").pihole.probes[59].ms })
  assert.equal(Model.headState(state("unreachable").pihole.probes).ok, false)
  assert.deepEqual(Model.headState([]), { ok: null, ms: null })
  assert.deepEqual(Model.headState(null), { ok: null, ms: null })
})

test("the series signature changes when data does, and not when it does not", () => {
  const a = state("healthy").pihole
  const b = state("healthy").pihole
  assert.equal(Model.seriesSignature(a.history), Model.seriesSignature(b.history))
  assert.equal(Model.seriesSignature(a.probes), Model.seriesSignature(b.probes))
  b.history[100].total += 1
  assert.notEqual(Model.seriesSignature(a.history), Model.seriesSignature(b.history))
  b.probes[59].t += 5
  assert.notEqual(Model.seriesSignature(a.probes), Model.seriesSignature(b.probes))
  assert.equal(Model.seriesSignature([]), "0")
})

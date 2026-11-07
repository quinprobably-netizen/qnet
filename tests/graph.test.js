"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, state, NOW_S } = require("./helpers.js")

test("24 h of history becomes 144 columns, scaled under 1 with headroom", () => {
  const s = Model.historySeries(state("healthy").pihole.history, NOW_S, 144)
  assert.equal(s.n, 144)
  assert.equal(s.total.length, 144)
  assert.equal(s.blocked.length, 144)
  const max = Math.max.apply(null, s.total)
  assert.ok(max < 1 && max > 0.8, "peak sits just under the top: " + max)
  for (let i = 0; i < 144; i++) {
    assert.ok(s.total[i] >= 0 && s.total[i] <= 1)
    assert.ok(s.blocked[i] >= 0 && s.blocked[i] <= s.total[i] + 1e-12, "blocked is a share of total")
  }
})

test("empty history has no series; flat zero keeps a zero peak", () => {
  assert.equal(Model.historySeries([], NOW_S, 144), null)
  const flat = Model.historySeries([{ t: NOW_S - 100, total: 0, blocked: 0 }], NOW_S, 144)
  assert.equal(flat.peak, 0)
  assert.ok(flat.total.every((v) => v === 0))
})

test("buckets outside the 24 h window are ignored; gaps are empty columns", () => {
  const h = [
    { t: NOW_S - 90000, total: 999, blocked: 0 },
    { t: NOW_S - 1200, total: 50, blocked: 10 },
    { t: NOW_S - 600, total: 50, blocked: 10 }
  ]
  const s = Model.historySeries(h, NOW_S, 144)
  assert.ok(s.total[0] === 0 && s.total[10] === 0, "the old bucket did not land anywhere")
  assert.ok(s.total[142] > 0 && s.total[143] > 0)
  assert.ok(s.peak < 60)
})

test("edge points run left to right over the width, 0 on the floor", () => {
  const pts = Model.edgePoints([0, 0.5, 1], 10, 100, 80, 60)
  assert.deepEqual(pts, [{ x: 10, y: 80 }, { x: 60, y: 50 }, { x: 110, y: 20 }])
  assert.deepEqual(Model.edgePoints([0.5], 0, 10, 10, 10), [])
  assert.equal(Model.edgePoints([-3, 7], 0, 10, 10, 10)[1].y, 0, "values are clamped to 0..1")
})

test("the live edge: ticks every 5 s, newest at the right, a failed probe is a gap", () => {
  const probes = state("healthy").pihole.probes
  const live = Model.pulseRuns(probes, NOW_S)
  assert.equal(live.runs.length, 1)
  assert.equal(live.runs[0].length, 60)
  assert.ok(live.head.ok && live.head.x > 0.99 && live.head.x <= 1)
  for (const p of live.runs[0]) assert.ok(p.v >= 0 && p.v <= 1 && p.x >= 0 && p.x <= 1)
  for (let i = 1; i < live.runs[0].length; i++) assert.ok(live.runs[0][i].x > live.runs[0][i - 1].x)

  const broken = probes.map((p) => Object.assign({}, p))
  broken[30].ok = false
  broken[30].ms = null
  const gap = Model.pulseRuns(broken, NOW_S)
  assert.equal(gap.runs.length, 2, "one run on each side of the failed probe")
  assert.equal(gap.runs[0].length + gap.runs[1].length, 59)
})

test("a dead Pi-hole draws no line, only a failing head", () => {
  const live = Model.pulseRuns(state("offline").pihole.probes, NOW_S)
  assert.deepEqual(live.runs, [])
  assert.equal(live.head.ok, false)
  assert.equal(Model.pulseRuns([], NOW_S).head, null)
})

test("probes older than five minutes fall off the left", () => {
  const old = [{ t: NOW_S - 400, ok: true, ms: 3 }, { t: NOW_S - 390, ok: true, ms: 3 }, { t: NOW_S - 10, ok: true, ms: 3 }, { t: NOW_S - 5, ok: true, ms: 3 }]
  const live = Model.pulseRuns(old, NOW_S)
  assert.equal(live.runs.length, 1)
  assert.equal(live.runs[0].length, 2)
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

test("the bucket still filling is scaled up, not drawn as a dip", () => {
  // now is 300 s into the newest bucket, which holds half a bucket's queries
  const h = []
  for (let i = 143; i >= 0; i--) h.push({ t: 1794122400 - i * 600, total: i === 0 ? 50 : 100, blocked: i === 0 ? 5 : 10 })
  const s = Model.historySeries(h, NOW_S, 144)
  const last = s.total[143]
  const before = s.total[142]
  assert.ok(Math.abs(last - before) / before < 0.2, "the end holds level: " + last + " vs " + before)
})

test("a bucket with almost nothing in it yet repeats the one before", () => {
  const h = []
  for (let i = 143; i >= 0; i--) h.push({ t: 1794122400 - i * 600, total: i === 0 ? 1 : 100, blocked: 0 })
  const s = Model.historySeries(h, 1794122400 + 30, 144)
  assert.ok(Math.abs(s.total[143] - s.total[142]) < 0.05)
})

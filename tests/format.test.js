"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model } = require("./helpers.js")

test("countdown reads m:ss and h:mm:ss", () => {
  assert.equal(Model.formatCountdown(272), "4:32")
  assert.equal(Model.formatCountdown(300), "5:00")
  assert.equal(Model.formatCountdown(65), "1:05")
  assert.equal(Model.formatCountdown(9), "0:09")
  assert.equal(Model.formatCountdown(0), "0:00")
  assert.equal(Model.formatCountdown(-4), "0:00")
  assert.equal(Model.formatCountdown(3725), "1:02:05")
  assert.equal(Model.formatCountdown("x"), "0:00")
})

test("counts are grouped, with the shell's formatter when given", () => {
  assert.equal(Model.formatCount(1204), "1,204")
  assert.equal(Model.formatCount(999), "999")
  assert.equal(Model.formatCount(1234567), "1,234,567")
  assert.equal(Model.formatCount(0), "0")
  assert.equal(Model.formatCount(1204, (n) => "<" + n + ">"), "<1204>")
})

test("percent and latency", () => {
  assert.equal(Model.formatPercent(13.64), "13.6%")
  assert.equal(Model.formatPercent(13.64, (v, d) => v.toFixed(d).replace(".", ",")), "13,6%")
  assert.equal(Model.formatLatency(3.1), "3 ms")
  assert.equal(Model.formatLatency(0.4), "<1 ms")
  assert.equal(Model.formatLatency(142.7), "143 ms")
  assert.equal(Model.formatLatency(null), "")
  assert.equal(Model.formatLatency(-1), "")
})

test("link rates", () => {
  assert.equal(Model.formatRate(866), "866 Mb/s")
  assert.equal(Model.formatRate(1000), "1 Gb/s")
  assert.equal(Model.formatRate(2500), "2.5 Gb/s")
  assert.equal(Model.formatRate(0), "")
  assert.equal(Model.formatRate(-5), "")
})

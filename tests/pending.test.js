"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const { Model, state, NOW_MS } = require("./helpers.js")

const eff = (s, pend, applied, now) => Model.effective(s, pend, applied === undefined ? NOW_MS : applied, now === undefined ? NOW_MS : now)

test("nothing pending: the view is the state", () => {
  const s = state("healthy")
  const v = eff(s, Model.emptyPending())
  assert.deepEqual(v.dns, s.dns)
  assert.deepEqual(v.pihole, s.pihole)
  assert.equal(v.radio, s.radio)
})

test("a pending DNS mode answers at once and ends a failover", () => {
  const pend = Model.withPending(Model.emptyPending(), { dns: "pihole" }, NOW_MS)
  const v = eff(state("fallback"), pend)
  assert.equal(v.dns.mode, "pihole")
  assert.equal(v.dns.failover.active, false)
  assert.equal(state("fallback").dns.mode, "fallback", "the source state is not mutated")
})

test("pause: a pending pause shows 5:00 counting down; resume shows 0", () => {
  const pend = Model.withPending(Model.emptyPending(), { pause: "pause", pauseUntilMs: NOW_MS + 300000 }, NOW_MS)
  let v = eff(state("healthy"), pend, NOW_MS, NOW_MS)
  assert.equal(v.pihole.blocking, "disabled")
  assert.equal(v.pihole.pauseRemainingS, 300)
  v = eff(state("healthy"), pend, NOW_MS, NOW_MS + 41000)
  assert.equal(v.pihole.pauseRemainingS, 259)

  const res = Model.withPending(Model.emptyPending(), { pause: "resume" }, NOW_MS)
  v = eff(state("paused"), res)
  assert.equal(v.pihole.blocking, "enabled")
  assert.equal(v.pihole.pauseRemainingS, 0)
})

test("the pause countdown runs down from the snapshot's time, never below zero", () => {
  const s = state("paused")
  assert.equal(Model.pauseRemaining(s, null, NOW_MS, NOW_MS), 272)
  assert.equal(Model.pauseRemaining(s, null, NOW_MS, NOW_MS + 2000), 270)
  assert.equal(Model.pauseRemaining(s, null, NOW_MS, NOW_MS + 999999), 0)
  assert.equal(Model.pauseRemaining(s, null, NOW_MS, NOW_MS - 5000), 272, "a clock step back does not add time")
  assert.equal(Model.pauseRemaining(state("healthy"), null, NOW_MS, NOW_MS + 5000), 0)
})

test("a pending radio and a pending scan show in the view", () => {
  let v = eff(state("healthy"), Model.withPending(Model.emptyPending(), { radio: "off" }, NOW_MS))
  assert.equal(v.radio.wifiEnabled, false)
  assert.equal(v.radio.hwEnabled, true)
  v = eff(state("healthy"), Model.withPending(Model.emptyPending(), { scanUntilMs: NOW_MS + 4000 }, NOW_MS))
  assert.equal(v.scan.running, true)
  v = eff(state("healthy"), Model.withPending(Model.emptyPending(), { scanUntilMs: NOW_MS - 1 }, NOW_MS))
  assert.equal(v.scan.running, false)
})

test("a request is dropped once the backend confirms it", () => {
  let pend = Model.withPending(Model.emptyPending(), { dns: "auto" }, NOW_MS)
  assert.equal(Model.reconcilePending(pend, state("healthy"), NOW_MS + 1000), pend, "unconfirmed: the same object")
  const done = Model.reconcilePending(pend, state("unconfigured"), NOW_MS + 1000)
  assert.equal(done.dns, "")

  pend = Model.withPending(Model.emptyPending(), { pause: "pause", pauseUntilMs: NOW_MS + 300000 }, NOW_MS)
  assert.equal(Model.reconcilePending(pend, state("paused"), NOW_MS + 1000).pause, "")
  pend = Model.withPending(Model.emptyPending(), { pause: "resume" }, NOW_MS)
  assert.equal(Model.reconcilePending(pend, state("healthy"), NOW_MS + 1000).pause, "")
  assert.equal(Model.reconcilePending(pend, state("paused"), NOW_MS + 1000).pause, "resume")

  pend = Model.withPending(Model.emptyPending(), { radio: "off" }, NOW_MS)
  assert.equal(Model.reconcilePending(pend, state("radio-off"), NOW_MS + 1000).radio, "")

  const ap = state("healthy").networks[2].id
  pend = Model.withPending(Model.emptyPending(), { connectId: ap }, NOW_MS)
  const joined = state("healthy")
  joined.networks[2].active = true
  assert.equal(Model.reconcilePending(pend, joined, NOW_MS + 1000).connectId, "")
  assert.equal(Model.reconcilePending(pend, state("healthy"), NOW_MS + 1000).connectId, ap)
})

test("a request nobody confirmed is given up after the timeout", () => {
  const pend = Model.withPending(Model.emptyPending(), { dns: "auto", connectId: "/org/freedesktop/NetworkManager/AccessPoint/99", pinUuid: "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66" }, NOW_MS)
  const later = Model.reconcilePending(pend, state("leaks"), NOW_MS + Model.PENDING_TTL_MS + 1)
  assert.equal(later.dns, "")
  assert.equal(later.connectId, "")
  assert.equal(later.pinUuid, "")
  assert.equal(Model.reconcilePending(pend, state("leaks"), NOW_MS + 1000).pinUuid, "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66")
})

test("a pin settles when the leak is gone", () => {
  const pend = Model.withPending(Model.emptyPending(), { pinUuid: "b7e1c0d4-6a52-4c39-8f10-3e9d2a4c5b66" }, NOW_MS)
  assert.equal(Model.reconcilePending(pend, state("healthy"), NOW_MS + 1).pinUuid, "")
})

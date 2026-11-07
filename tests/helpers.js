// Shared by the tests: the fixtures (SPEC "State JSON" snapshots) as
// normalised states, and the fixed clock they were generated against.
"use strict"
const fs = require("fs")
const path = require("path")
const Model = require("../Model.js")

const NOW_S = 1794122700           // tests/fixtures/*.json were generated at this time
const NOW_MS = NOW_S * 1000
const BIN = "/home/user/.local/bin/qnet"

function raw(name) {
  return JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures", name + ".json"), "utf8"))
}

function state(name) { return Model.normalizeState(raw(name)) }

// A fixture as the view the panel draws, with nothing pending.
function view(name, pending, appliedMs, nowMs) {
  return Model.effective(state(name), pending || Model.emptyPending(), appliedMs === undefined ? NOW_MS : appliedMs, nowMs === undefined ? NOW_MS : nowMs)
}

function hero(name) { return Model.heroState(view(name)) }

module.exports = { Model, NOW_S, NOW_MS, BIN, raw, state, view, hero }

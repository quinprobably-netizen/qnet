// `node --test tests/` (Node 22 does not expand a directory argument) runs
// this file, which loads every *.test.js here; `node --test tests/*.test.js`
// and a bare `node --test` run them one by one.
"use strict"
const fs = require("fs")
const path = require("path")
for (const f of fs.readdirSync(__dirname).sort()) {
  if (f.endsWith(".test.js")) require(path.join(__dirname, f))
}

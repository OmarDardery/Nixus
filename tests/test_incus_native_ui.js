"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");
const app = read("app.js");
assert.match(app, /projects: appsPage/);
assert.match(app, /bindApps\(\)/);
assert.match(read("index.html"), /apps\.js/);
for (const name of ["app.js", "projects.js", "events.js", "commands.js", "apps.js"])
  assert.doesNotMatch(read(name), /Arcane|Portainer|arcanePort|reuseArcanePassword/i, name + " uses retired application management");
const apps = read("apps.js");
for (const needle of [/crypto\.subtle\.digest\("SHA-256"/, /webkitdirectory/, /project-import\/prepare/, /project-import\/chunk/,
  /project-import\/finish/, /apps\/deploy/]) assert.match(apps, needle);
console.log("Incus-native portal baseline verified");

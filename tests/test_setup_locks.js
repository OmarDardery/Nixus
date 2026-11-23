"use strict";
// Controls that need an unfinished setup step are disabled with a lock and a link (#101).
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");
const context = vm.createContext({ state: { page: "projects" }, shell: () => {}, api: async () => ({}), File, console,
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
  card: (title, body) => "<section><h2>" + title + "</h2>" + body + "</section>",
  title: (_, h, t) => "<h1>" + h + "</h1><p>" + t + "</p>", badge: v => v, administrator: () => true });
vm.runInContext(read("setup.js") + read("apps.js") + read("backups.js") + "\nthis.appView = appView; this.setupView = setupView; this.backupView = backupView;", context);
const run = code => vm.runInContext(code, context);
const items = done => `setupView.progress = { complete: false, items: [
  { id: "secretsKey", page: "operations", done: ${done.key} }, { id: "backup", page: "projects", done: ${done.backup} }] }`;

// Unknown progress never locks.
assert.equal(run('gated("secretsKey", "x", "<b>ok</b>")'), "<b>ok</b>");

// Environment variables on the app page.
run('Object.assign(appView, { view: "web", tab: "env", overview: { projects: [{ name: "web", backend: "incus-compose", incusProject: "web", instances: [] }] } }); Object.assign(appView.env, { project: "web", names: [], rows: null })');
run(items({ key: false, backup: true }));
let html = run("appsPage()");
assert.match(html, /<div class="locked" aria-disabled="true">/);
assert.match(html, /Locked\.<\/b> Create the encryption key first\./);
assert.match(html, /data-go="operations">Open setup</);
assert.match(html, /<fieldset disabled>.*id="env-reveal"/s, "the control is inside a disabled fieldset");
run(items({ key: true, backup: true }));
html = run("appsPage()");
assert.doesNotMatch(html, /class="locked"|Locked\./);
assert.match(html, /id="env-reveal"/);

// Environment variables on New app.
run('appView.view = "new"');
run(items({ key: false, backup: true }));
html = run("appsPage()");
assert.match(html, /<section class="env-new">.*class="locked".*data-var-key="new:0"/s);
run(items({ key: true, backup: true }));
assert.doesNotMatch(run("appsPage()"), /class="locked"/);

// Back up now.
run('backupView.status = { phases: {}, lastSuccess: 0 }');
run(items({ key: true, backup: false }));
html = run("backupStatusCard()");
assert.match(html, /Set up backups first\./);
assert.match(html, /<fieldset disabled><button type="button" id="backups-run">/);
run(items({ key: true, backup: true }));
html = run("backupStatusCard()");
assert.doesNotMatch(html, /Locked\./);
assert.match(html, /id="backups-run"/);
console.log("Setup lock checks passed: env variables and Back up now lock and unlock with their setup step");

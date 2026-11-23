"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");
const context = vm.createContext({ state: { page: "projects" }, shell: () => {}, api: async () => ({}), File, console,
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
  card: (title, body) => "<section><h2>" + title + "</h2>" + body + "</section>",
  title: (_, h, t) => "<h1>" + h + "</h1><p>" + t + "</p>" });
vm.runInContext(read("apps.js") + "\nthis.appView = appView;", context);
const render = () => vm.runInContext("appsPage()", context);

vm.runInContext(`Object.assign(appView, { overview: { projects: [
    { name: "web", backend: "incus-compose", incusProject: "web", instances: [{ name: "<b>app</b>", status: "Running", ports: [3000, 3000, 70000] }] },
    { name: "printer", backend: "incus-native", incusProject: "printer", instances: [{ name: "printer", status: "Stopped" }] }] },
  jobs: { web: { status: "failed", error: "<i>bad</i>" } },
  updates: { projects: { web: { updates: 1, images: [{ ref: "<x>", status: "update-available", digest: "sha256:a", latest: "sha256:bbbb" }] } } } })`, context);

// Grid: one card per app, status, update badge, New app; everything escaped.
let html = render();
assert.match(html, /data-app-open="web"/);
assert.match(html, /data-app-open="printer"/);
assert.match(html, /data-app-new/);
assert.match(html, /class="app-pill" title="Update available"/);
// Header: an Add app button and an Import menu, both with icons and accessible names.
assert.match(html, /data-app-new aria-label="Add app"/);
assert.match(html, /<summary class="icon-button" aria-label="Import an app"/);
assert.match(html, /data-import="repo"/);
assert.match(html, /data-import="upload"/);
assert.doesNotMatch(html, /data-import="backup"/, "restoring a whole server is only offered before any app exists");
assert.match(html, /\.app-dot|app-dot bad/);
assert.doesNotMatch(html, /<b>app<\/b>|<i>bad<\/i>|<x>/);
vm.runInContext('appView.filter = "print"', context);
assert.doesNotMatch(render(), /data-app-open="web"/, "search filters the grid");
vm.runInContext('appView.filter = "zzz"', context);
assert.match(render(), /No apps match/);
vm.runInContext('appView.filter = ""', context);

// App page: four tabs and an update action.
vm.runInContext('Object.assign(appView, { view: "web", tab: "deployments" })', context);
html = render();
for (const tab of ["deployments", "logs", "env", "settings"]) assert.match(html, new RegExp('data-app-tab="' + tab + '"'));
assert.match(html, /id="app-update-start"/);
assert.match(html, /data-app-power="restart"/);
assert.match(html, /data-app-power="stop"/, "a running app offers Stop");
assert.doesNotMatch(html, /Open :3000/, "no Open link without a known server address");
vm.runInContext('state.status = { managementAddress: "192.0.2.10" }', context);
html = render();
assert.equal((html.match(/href="http:\/\/192\.0\.2\.10:3000"/g) || []).length, 1, "one Open link per published port");
assert.doesNotMatch(html, /70000/);
vm.runInContext("state.status = { managementAddress: 'evil<script>' }", context);
assert.doesNotMatch(render(), /Open :/, "only plain IP addresses become links");
assert.match(html, /data-image-hold="web" data-digest="sha256:bbbb" data-held="0"/);
assert.match(html, /failed/);
vm.runInContext("appView.confirmUpdate = true", context);
assert.match(render(), /id="update-password" type="password"/, "update asks for the password inline");

// Environment Variables: masked names first, then editable rows with show/hide.
vm.runInContext('Object.assign(appView, { tab: "env" }); Object.assign(appView.env, { project: "web", names: ["API_TOKEN"], rows: null })', context);
html = render();
assert.match(html, /API_TOKEN/);
assert.match(html, /id="env-reveal"/);
assert.doesNotMatch(html, /data-var-value/);
vm.runInContext('appView.env.rows = [{ key: "API_TOKEN", value: "<s3cret>", show: false }]', context);
html = render();
assert.match(html, /data-var-value="env:0" type="password" value="&lt;s3cret&gt;"/, "values masked and escaped");
assert.match(html, /data-var-paste="env"/);
assert.match(html, /id="env-save"/);

// .env parsing: comments, export, quotes, inline comments.
const parsed = vm.runInContext(`parseEnv("# c\\nexport A=1\\nB=\\"two words\\"\\nC='x # y'\\nD=plain # note\\n\\nE=")`, context);
assert.deepEqual(JSON.parse(JSON.stringify(parsed)), [{ key: "A", value: "1" }, { key: "B", value: "two words" }, { key: "C", value: "x # y" },
  { key: "D", value: "plain" }, { key: "E", value: "" }]);
assert.throws(() => vm.runInContext('parseEnv("not a pair")', context), /KEY=VALUE/);

// Settings: declaration editor and data import for this app only.
vm.runInContext('Object.assign(appView, { tab: "settings", nixLoaded: "web", nix: "{ ... }: {}" })', context);
html = render();
assert.match(html, /id="app-save-nix"/);
assert.match(html, /value="web\/&lt;b&gt;app&lt;\/b&gt;"/);
assert.doesNotMatch(html, /value="printer\//, "import targets only this app");

// New app: files or VM/container, pin and generator.
vm.runInContext('Object.assign(appView, { view: "new", mode: "files" })', context);
html = render();
assert.match(html, /id="app-pin"/);
assert.match(html, /data-app-template="compose"/);
vm.runInContext('appView.mode = "nix"', context);
assert.match(render(), /id="vm-generate"/);
const nix = vm.runInContext(`nixInstance("printer", { type: "virtual-machine", image: "images:debian/13", cpus: 2, memory: 4, disk: 20, usb: "1d50:614e" })`, context);
for (const want of ['backend = "incus-native";', 'instances.printer = {', 'type = "virtual-machine";', 'memory = "4GiB";', 'volumes.data.size = "20GiB";',
  'usb.device = { vendorId = "1d50"; productId = "614e"; };']) assert.ok(nix.includes(want), want);

// Source paths and pasted files.
assert.throws(() => vm.runInContext('sourcePath({ name: "../etc/passwd" })', context));
assert.throws(() => vm.runInContext('sourcePath({ name: ".env" })', context));
vm.runInContext('appView.uploads = []; appView.entries = [{ path: "Dockerfile", text: "FROM x@sha256:<digest>" }]', context);
assert.throws(() => vm.runInContext("appFiles()", context), /digest/);

const index = read("index.html");
assert.match(index, /\/apps\.js/);
console.log("Apps page verified");

// Empty state offers Add app, Git and backup imports.
{
  const ctx2 = vm.createContext({ state: { page: "projects" }, shell: () => {}, api: async () => ({}), File, console, esc: context.esc, card: context.card, title: context.title });
  vm.runInContext(read("apps.js") + "\nthis.appView = appView;", ctx2);
  vm.runInContext("Object.assign(appView, { overview: { projects: [] }, loading: true })", ctx2);
  const empty = vm.runInContext("appsPage()", ctx2);
  assert.match(empty, /No apps yet/);
  assert.match(empty, /data-import="backup"/);
  assert.match(empty, /data-import="repo"/);
  assert.doesNotMatch(empty, /id="apps-filter"/, "no search box without apps");
  console.log("Apps empty state verified");
}

// Deploying over an existing app's name asks first.
(async () => {
  const calls = [];
  const ctx3 = vm.createContext({ setTimeout: () => 0, state: { page: "projects" }, shell: () => {}, api: async (r, b) => { calls.push(r); return { id: "x", manifestHash: "y" }; }, File, console, esc: context.esc, card: context.card, title: context.title,
    document: { querySelector: id => id === "#app-password" ? { value: "pw" } : id === "#app-name" ? { value: "web" } : null, querySelectorAll: () => [] } });
  vm.runInContext(read("apps.js") + "\nthis.appView = appView;", ctx3);
  vm.runInContext('Object.assign(appView, { view: "new", name: "web", mode: "nix", nix: "{}", overview: { projects: [{ name: "web", instances: [] }] } })', ctx3);
  await vm.runInContext("deployApp()", ctx3);
  assert.match(vm.runInContext("appView.error", ctx3), /already exists/);
  assert.ok(!calls.includes("apps/deploy"), "nothing is sent before Replace is ticked");
  assert.match(vm.runInContext("addAppCard()", ctx3), /id="app-replace-ok"/, "the form offers Replace for an existing name");

  // Variables typed as rows are sent as an object; bad names are refused before sending.
  let body;
  vm.runInContext("api = async (r, b) => { if (r === 'apps/deploy') this.sent = b; return { id: 'x', manifestHash: 'y' }; }", ctx3);
  vm.runInContext('Object.assign(appView, { replaceOk: true, newVars: [{ key: "TUNNEL_TOKEN", value: "t=1$x" }, { key: "SECRET_KEY", value: "k" }, { key: "", value: "" }] })', ctx3);
  await vm.runInContext("deployApp()", ctx3);
  body = vm.runInContext("this.sent", ctx3);
  assert.deepEqual(JSON.parse(JSON.stringify(body.env)), { TUNNEL_TOKEN: "t=1$x", SECRET_KEY: "k" });
  assert.equal(vm.runInContext("appView.newVars.length", ctx3), 1, "the form is cleared after a deploy starts");
  vm.runInContext('this.sent = null; Object.assign(appView, { view: "new", replaceOk: true, newVars: [{ key: "1BAD", value: "x" }] })', ctx3);
  await vm.runInContext("deployApp()", ctx3);
  assert.equal(vm.runInContext("this.sent", ctx3), null);
  assert.match(vm.runInContext("appView.error", ctx3), /Invalid variable name: 1BAD/);
  assert.match(vm.runInContext("varsEditor('new', appView.newVars, false)", ctx3), /aria-invalid="true"/);

  // Deployment steps: where it is, and where it stopped.
  let steps = vm.runInContext('deploySteps({ status: "building" })', ctx3);
  assert.match(steps, /<li class="done">Publish files<\/li><li class="current">Build images/);
  steps = vm.runInContext('deploySteps({ status: "failed", failedStep: "deploying" })', ctx3);
  assert.match(steps, /<li class="failed">Start containers/);
  console.log("Replace, variables and steps verified");
})().catch(e => { console.error(e); process.exitCode = 1; });

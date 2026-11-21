"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");
const context = vm.createContext({ state: { page: "projects" }, shell: () => {}, api: async () => ({}), File, console,
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
  card: (title, body) => "<section><h2>" + title + "</h2>" + body + "</section>" });
vm.runInContext(read("apps.js") + "\nthis.appView = appView;", context);

// Apps list escapes everything and offers only real actions.
vm.runInContext(`appView.overview = { projects: [{ name: "web", backend: "incus-compose", incusProject: "web",
  instances: [{ name: "<b>app</b>", status: "Running" }] }] };
  appView.jobs = { web: { status: "failed", error: "<i>bad</i>" } };
  appView.updates = { projects: { web: { updates: 1, images: [{ ref: "<x>", status: "update-available", digest: "sha256:a", latest: "sha256:b" }] } } };`, context);
const list = vm.runInContext("appsCard()", context);
assert.match(list, /data-app-update="web"/);
assert.match(list, /data-app-edit="web"/);
assert.doesNotMatch(list, /<b>app<\/b>|<i>bad<\/i>/, "values are escaped");
const updates = vm.runInContext("updatesCard()", context);
assert.match(updates, /data-image-hold="web" data-digest="sha256:b" data-held="0"/);
assert.doesNotMatch(updates, /<x>/);

// No explanatory filler: every paragraph is a value, status or error.
const page = vm.runInContext("appsCard() + addAppCard() + updatesCard() + importCard()", context);
assert.doesNotMatch(page, /<p class="note">/, "no note paragraphs");
assert.doesNotMatch(page, /private|by default|nothing is|is never|only the|reviewed|safely/i, "no reassurance copy");

// Pasted and uploaded files: paths validated, credentials refused, digests required.
assert.throws(() => vm.runInContext('sourcePath({ name: "../etc/passwd" })', context));
assert.throws(() => vm.runInContext('sourcePath({ name: ".env" })', context));
assert.throws(() => vm.runInContext('sourcePath({ name: "id_ed25519" })', context));
assert.equal(vm.runInContext('sourcePath({ name: "app/Dockerfile" })', context), "app/Dockerfile");
vm.runInContext('appView.uploads = []; appView.entries = [{ path: "Dockerfile", text: "FROM x@sha256:<digest>" }]', context);
assert.throws(() => vm.runInContext("appFiles()", context), /digest/);
vm.runInContext('appView.entries = [{ path: "Dockerfile", text: "FROM x" }, { path: "Dockerfile", text: "FROM y" }]', context);
assert.throws(() => vm.runInContext("appFiles()", context), /Duplicate/);
vm.runInContext('appView.entries = [{ path: "compose.yaml", text: "services: {}" }]', context);
assert.equal(vm.runInContext("appFiles()[0].nixusPath", context), "compose.yaml");

// The VM/container form generates a valid native declaration.
const nix = vm.runInContext(`nixInstance("printer", { type: "virtual-machine", image: "images:debian/13", cpus: 2, memory: 4, disk: 20, usb: "1d50:614e" })`, context);
for (const want of ['backend = "incus-native";', 'instances.printer = {', 'type = "virtual-machine";', 'image = "images:debian/13";',
  'cpus = 2;', 'memory = "4GiB";', 'volumes.data.size = "20GiB";', 'usb.device = { vendorId = "1d50"; productId = "614e"; };'])
  assert.ok(nix.includes(want), "missing " + want + " in\n" + nix);
assert.doesNotMatch(vm.runInContext(`nixInstance("c", { type: "container", image: "images:alpine/3.20", cpus: 1, memory: 1, disk: 5, usb: "" })`, context), /usb/);
assert.match(vm.runInContext("addAppCard()", context), /id="app-pin"/, "pin action offered for pasted files");
vm.runInContext('appView.mode = "nix"', context);
assert.match(vm.runInContext("addAppCard()", context), /id="vm-generate"/, "VM/container form offered");
vm.runInContext('appView.mode = "files"', context);
assert.match(vm.runInContext("importCard()", context), /value="web\/&lt;b&gt;app&lt;\/b&gt;"/, "import targets escaped");
assert.match(vm.runInContext('NIX_TEMPLATES.native("printer")', context), /instances\.printer/);

const index = read("index.html");
assert.match(index, /\/apps\.js/);
assert.doesNotMatch(index, /incus-projects|project-console|paste-source/);
console.log("Apps page verified");

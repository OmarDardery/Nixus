"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");

const context = {
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c])),
  card: (heading, body) => "<section><h2>" + heading + "</h2>" + body + "</section>",
  state: { page: "other" }, shell() {}, nativeProjectTx: { path: "", source: "", error: "" },
  document: { querySelector: () => null, querySelectorAll: () => [] }, console,
};
vm.createContext(context);
vm.runInContext(read("project-console.js") + "\nthis.projectConsole = projectConsole;", context);

const pc = context.projectConsole;
pc.overview = { available: true, transaction: { status: "published-source", deployment: "verified" }, projects: [{
  name: "beta", backend: "incus-native", enable: true, incusProject: "beta", resources: { cpus: 2, memory: "2GiB" },
  backup: { consistency: "stop" }, declaredInstances: ["printer"], declaredVolumes: ["data"],
  sourceRevision: "a".repeat(64), backupCoverage: { config: true, data: "incus-export", unknowns: ["<script>x</script>"] },
  retained: [{ name: "old" }], instances: [{ name: "printer", type: "container", status: "Running", owned: true }] }] };
pc.expanded = "beta";
const html = vm.runInContext("projectConsoleCards()", context);
assert.match(html, /data-project-log="beta\/printer"/);
assert.match(html, /data-project-edit="beta\/default.nix"/);
assert.match(html, /Retained \(kept, not managed\)/);
assert.doesNotMatch(html, /<script>x<\/script>/, "coverage notes must be escaped");
assert.match(html, /Off-host upload/);

pc.policy = { schedule: "weekly", data: false, verification: "full", repository: "rclone:gdrive:nixus-backups",
  rcloneConfigFile: "/var/lib/nixus-secrets/rclone.conf", initialize: true, github: "git@github.com:me/cfg.git" };
const text = vm.runInContext("projectBackupPolicyText(projectConsole.policy)", context);
assert.match(text, /schedule = "weekly";/);
assert.match(text, /data = false;/);
assert.match(text, /repository = "rclone:gdrive:nixus-backups";/);
assert.match(text, /github.repository = "git@github.com:me\/cfg.git";/);
assert.doesNotMatch(text, /password/i, "the policy must never contain credentials");

vm.runInContext("imageUpdates.status = { checkedAt: 1, projects: { app: { updates: 1, images: [ { file: \"compose.yaml\", ref: \"<b>x</b>\", status: \"update-available\", digest: \"sha256:aa\", latest: \"sha256:bbbbbbbbbbbbbbbbbbbb\" } ] } } }", context);
const updates = vm.runInContext("imageUpdatesCard()", context);
assert.match(updates, /data-image-update="app"/);
assert.match(updates, /data-image-apply="app"/, "update-now action is offered");
assert.match(updates, /data-image-hold="app" data-digest="sha256:bbbbbbbbbbbbbbbbbbbb" data-held="0"/, "skip-this-version action is offered");
vm.runInContext("imageUpdates.status = { checkedAt: 1, projects: { app: { updates: 0, lastUpdate: { status: \"rolled-back\", error: \"<i>bad</i>\" }, images: [ { file: \"Dockerfile\", ref: \"r\", status: \"held\", digest: \"sha256:aa\", latest: \"sha256:cc\" } ] } } }", context);
const held = vm.runInContext("imageUpdatesCard()", context);
assert.match(held, /data-held="1"/, "held digests offer release");
assert.doesNotMatch(held, /data-image-apply/, "no update action without an unheld update");
assert.doesNotMatch(held, /<i>bad<\/i>/, "update errors are escaped");
assert.match(updates, /update-available/);
assert.doesNotMatch(updates, /<b>x<\/b>/, "image references must be escaped");

const index = read("index.html");
assert.ok(index.indexOf("project-console.js") < index.indexOf("incus-projects.js"), "console script loads before the project page");
assert.match(read("incus-projects.js"), /projectConsoleCards\(\)/);
console.log("Project console UI verified");

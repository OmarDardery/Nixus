"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");
const context = vm.createContext({ console, state: { page: "operations" }, shell: () => {}, api: async () => ({}),
  badge: v => "<b>" + v + "</b>", administrator: () => true,
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
  card: (t, b) => "<section><h2>" + t + "</h2>" + b + "</section>" });
vm.runInContext(read("backups.js") + "\nthis.backupView = backupView;", context);

for (const kind of ["rclone", "s3", "b2", "local"]) {
  vm.runInContext('backupView.kind = "' + kind + '"', context);
  const html = vm.runInContext('destinationFields("dest")', context);
  assert.match(html, /id="dest-kind"/);
  assert.ok(vm.runInContext("BACKUP_FIELDS[backupView.kind]", context).every(([id]) => html.includes('id="dest-' + id + '"')), kind);
}
assert.match(vm.runInContext('backupView.kind = "s3"; destinationFields("dest")', context), /id="dest-secretKey" type="password"/, "secrets are masked");

// Restore is offered on a server without apps and hidden once apps exist.
vm.runInContext("backupView.status = { phases: { keys: { state: 'complete' } }, lastSuccess: 0 }; backupView.snapshots = { configured: false }", context);
let page = vm.runInContext("backupsCards()", context);
assert.match(page, /Restore this server from a backup/);
assert.match(page, /Set up backups/);
assert.match(page, /Secrets <b>complete<\/b>/, "the secrets phase is shown");
context.appView = { overview: { projects: [{ name: "web" }] } };
assert.doesNotMatch(vm.runInContext("backupsCards()", context), /Restore this server/);

// The generated password is shown once, escaped.
vm.runInContext('backupView.password = "<pw>"', context);
assert.match(vm.runInContext("backupDestinationCard()", context), /&lt;pw&gt;/);
vm.runInContext("backupView.snapshots = { configured: true, repository: 'rclone:gdrive:x', snapshots: [{ id: 'abc12345', time: '2026-01-01T00:00:00Z' }] }", context);
assert.match(vm.runInContext("snapshotsCard()", context), /abc12345/);
console.log("Backups page verified");

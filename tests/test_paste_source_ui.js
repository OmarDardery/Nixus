"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");

const context = {
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c])),
  card: (heading, body) => "<section><h2>" + heading + "</h2>" + body + "</section>",
  state: { page: "other" }, shell() {}, File, console,
  document: { querySelector: () => null, querySelectorAll: () => [] },
};
vm.createContext(context);
vm.runInContext(read("incus-projects.js") + "\n" + read("paste-source.js") +
  "\nthis.pasteSource = pasteSource; this.nativeProjectTx = nativeProjectTx;", context);

const files = vm.runInContext(`pastedFiles([
  { path: "Dockerfile", text: "FROM debian:13@sha256:" + "a".repeat(64) + "\\n" },
  { path: "app/compose.yaml", text: "services: {}\\n" },
])`, context);
assert.equal(files.length, 2);
assert.equal(vm.runInContext("nativeSourcePath", context)(files[1]), "app/compose.yaml", "pasted path is preserved");

for (const [entries, message] of [
  ['[{ path: "Dockerfile", text: "FROM debian:13@sha256:<digest>\\n" }]', /real sha256 digest/],
  ['[{ path: "a", text: "x" }, { path: "a", text: "y" }]', /Duplicate pasted path/],
  ['[{ path: ".env", text: "TOKEN=1" }]', /credentials/],
  ['[{ path: "../x", text: "x" }]', /Unsafe/],
  ['[{ path: "Dockerfile", text: "" }]', /empty/],
]) {
  assert.throws(() => vm.runInContext("pastedFiles(" + entries + ")", context), message);
}

const card = vm.runInContext("pasteSourceCard()", context);
assert.match(card, /data-paste-template="compose"/);
assert.match(card, /id="paste-use"/);
const native = vm.runInContext("NIX_TEMPLATES.native('printer')", context);
assert.match(native, /backend = "incus-native";/);
assert.match(native, /instances\.printer = \{/);
assert.match(vm.runInContext("NIX_TEMPLATES.compose()", context), /backend = "incus-compose";/);
assert.match(read("index.html"), /paste-source\.js/);
console.log("Paste source UI verified");

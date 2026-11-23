"use strict";
// The encryption key panel shows only the fields of the chosen action (#102).
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const code = fs.readFileSync(path.join(__dirname, "../admin/static/incus-secrets.js"), "utf8");
const ctx = vm.createContext({console, TextEncoder, document: {getElementById: () => null, querySelector: () => null, querySelectorAll: () => []}});
vm.runInContext(code, ctx);
ctx.state = {principal: {role: "admin"}};
ctx.card = (t, b) => t + b;
ctx.esc = v => String(v).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const run = x => vm.runInContext(x, ctx);
// Fields inside the collapsed Advanced section are not visible.
const passwords = html => (html.replace(/<details class="advanced".*<\/details>/s, "").match(/type="password"/g) || []).length;
const set = (data, extra = "") => { ctx.data = data; run("Object.assign(nativeSecretsView, {data, loaded: true, review: null, choice: 'create', haveVia: 'key', kit: 'export'});" + extra); return run("nativeSecretsPanel()"); };
const noKey = {identity: {configured: false}, projects: []};
const withKey = {identity: {configured: true, healthy: true, recipient: "age1" + "a".repeat(58)}, projects: [{project: "a", keys: ["K"], revision: "r".repeat(64), indexed: true}]};

// Fresh server: only create / I already have a key.
let html = set(noKey);
assert.match(html, /Create a key/); assert.match(html, /I already have a key/);
assert.doesNotMatch(html, /native-age-restore/, "recovery key box hidden when creating");
assert.doesNotMatch(html, /Recovery kit|Download encrypted|Verify kit|Advanced/);
assert.equal(passwords(html), 1);

// "I already have a key": paste key shows the box; kit shows the kit form; one form at a time.
html = set(noKey, "nativeSecretsView.choice='have'");
assert.match(html, /native-age-restore/); assert.doesNotMatch(html, /native-recovery-kit-file/); assert.equal(passwords(html), 1);
html = set(noKey, "nativeSecretsView.choice='have'; nativeSecretsView.haveVia='kit'");
assert.match(html, /native-recovery-kit-file/); assert.doesNotMatch(html, /native-age-restore/);
assert.match(html, /Restore from recovery kit/);

// Key present: export or verify only, collapsed Advanced, no setup or restore.
html = set(withKey);
assert.match(html, /Download encrypted recovery kit/); assert.doesNotMatch(html, /native-recovery-kit-file|Restore from recovery kit|Create a key/);
assert.match(html, /<details class="advanced">/); assert.equal(passwords(html), 3);
html = set(withKey, "nativeSecretsView.kit='verify'");
assert.match(html, /Verify kit<\/button>/); assert.doesNotMatch(html, /Download encrypted recovery kit|native-recovery-export/);
assert.equal(passwords(html), 2);
console.log("Key panel states: create, have a key, export, verify");

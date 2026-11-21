"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");
const context = vm.createContext({ console, state: { page: "repository" }, shell: () => {}, api: async () => ({}),
  badge: v => "<b>" + v + "</b>", title: (a, b, c) => "<h1>" + b + "</h1><p>" + c + "</p>", takeValue: () => "",
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
  card: (t, b) => "<section><h2>" + t + "</h2>" + b + "</section>" });
vm.runInContext(read("repo.js") + "\nthis.repoView = repoView;", context);

// Not connected: create a key first, then check the host key, then connect.
vm.runInContext("repoView.data = { configured: false }", context);
let page = vm.runInContext("repositoryPage()", context);
assert.match(page, /id="repo-key"/);
assert.doesNotMatch(page, /id="repo-connect"/);
vm.runInContext("repoView.data = { configured: false, publicKey: 'ssh-ed25519 AAAA nixus' }; repoView.fingerprints = ['256 SHA256:abc host (ED25519)']", context);
page = vm.runInContext("repositoryPage()", context);
assert.match(page, /ssh-ed25519 AAAA nixus/);
assert.match(page, /SHA256:abc/);
assert.match(page, /id="repo-trust"/);
assert.match(page, /id="repo-connect"/);

// Connected with remote changes: commits and apps are listed for review.
vm.runInContext(`repoView.data = { configured: true, url: 'git@h:me/apps.git', branch: 'main', status: { checkedAt: 1, pending: {
  head: 'a'.repeat(40), commits: ['abc1234 add <notes>'], apps: ['notes'], removed: ['old'] } } }`, context);
page = vm.runInContext("repositoryPage()", context);
assert.match(page, /Remote changes/);
assert.match(page, /add &lt;notes&gt;/, "commit messages are escaped");
assert.match(page, /data-head="a{40}"/);
assert.match(page, /<code>old<\/code>/);
assert.match(page, /git@h:me\/apps\.git/);
console.log("repo ui ok");

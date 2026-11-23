"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");

function makeContext(responses) {
  const calls = [];
  const context = vm.createContext({
    console, setTimeout: (fn) => fn(), Date,
    state: { page: "overview", status: { release: { version: "0.1", revision: "a".repeat(40) }, settings: { x: 1 }, job: null } },
    administrator: () => true, stagedCount: () => 0, shell: () => {}, navigateTo: page => { context.state.page = page; },
    esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
    card: (t, b) => "<section><h2>" + t + "</h2>" + b + "</section>",
    api: async (p, body) => { calls.push([p, body]); const r = responses(p, body, context); if (r instanceof Error) throw r; return r; },
  });
  vm.runInContext(read("quick.js") + "\nthis.quick = quick;", context);
  return { context, calls };
}

(async () => {
  // Next step follows setup progress, then apps, then backups.
  let { context } = makeContext(() => ({}));
  context.setupView = { progress: { complete: false, items: [{ title: "Activate the hypervisor", page: "review", required: true, done: false }] } };
  assert.deepEqual([...vm.runInContext("nextStep()", context)], ["Activate the hypervisor", "review"]);
  context.setupView = { progress: { complete: true, items: [] } };
  vm.runInContext('Object.assign(quick, { loaded: true, apps: { projects: [] }, backups: {}, updates: { projects: {} } })', context);
  assert.deepEqual([...vm.runInContext("nextStep()", context)], ["Add your first app", "projects"]);
  vm.runInContext('quick.apps = { projects: [{ name: "web" }] }', context);
  assert.deepEqual([...vm.runInContext("nextStep()", context)], ["Set up backups", "operations"]);
  vm.runInContext("quick.backups = { lastSuccess: 1 }", context);
  assert.equal(vm.runInContext("nextStep()", context), null);
  const html = vm.runInContext("quickActions()", context);
  for (const id of ["quick-update-nixus", "quick-update-apps", "quick-backup"]) assert.match(html, new RegExp('id="' + id + '"'));
  assert.match(html, /id="quick-update-apps" disabled/, "no app updates → button disabled");
  assert.doesNotMatch(html, /Next step/);

  // Update Nixus: builds and activates, then requires a fresh login.
  let statuses = ["building", "ready", "applying", "awaiting-confirmation", "confirmed"];
  ({ context, calls } = makeContext((p) => {
    if (p === "main-revision") return { revision: "b".repeat(40) };
    if (p === "status") {
      const status = statuses.length > 1 ? statuses.shift() : statuses[0];
      return { release: { revision: "a".repeat(40) }, settings: {}, job: { id: "j1", status, impactPlan: { blocked: false }, platformChanges: [{ path: "x" }], changes: [] } };
    }
    return {};
  }));
  var calls;
  await vm.runInContext('updateNixus("pw")', context);
  const names = calls.map(c => c[0]);
  assert.deepEqual(names.filter(n => ["review", "apply", "confirm"].includes(n)), ["review", "apply"]);
  const review = calls.find(c => c[0] === "review")[1];
  assert.equal(review.revision, "b".repeat(40));
  assert.equal(review.updateInputs, true);
  assert.equal(review.adminPassword, "pw");
  assert.match(vm.runInContext("quick.message", context), /Sign out.*sign in again/);
  assert.equal(context.state.page, "review");

  // A blocked impact plan never activates.
  ({ context, calls } = makeContext((p) => p === "main-revision" ? { revision: "b".repeat(40) }
    : p === "status" ? { job: { id: "j2", status: "ready", impactPlan: { blocked: true } } } : {}));
  await assert.rejects(vm.runInContext('updateNixus("pw")', context), /needs a decision/);
  assert.ok(!calls.some(c => c[0] === "apply"), "blocked update must not activate");

  // Nothing new: the candidate is discarded, nothing activates.
  ({ context, calls } = makeContext((p) => p === "main-revision" ? { revision: "a".repeat(40) }
    : p === "status" ? { job: { id: "j3", status: "ready", impactPlan: { blocked: false }, changes: [], platformChanges: [], inputChanges: {} } } : {}));
  await vm.runInContext('updateNixus("pw")', context);
  assert.ok(calls.some(c => c[0] === "cancel") && !calls.some(c => c[0] === "apply"));
  assert.equal(vm.runInContext("quick.message", context), "Nixus is up to date.");

  // An in-flight change blocks the one-click update.
  ({ context } = makeContext(() => ({})));
  context.state.status.job = { status: "awaiting-confirmation" };
  await assert.rejects(vm.runInContext('updateNixus("pw")', context), /Finish the current change/);
  console.log("Quick actions verified");
})().catch(error => { console.error(error); process.exit(1); });

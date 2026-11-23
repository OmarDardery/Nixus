"use strict";
// New app drafts: save, list, resume and delete (kept on the server).
const assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path"), vm = require("node:vm");
const read = name => fs.readFileSync(path.join(__dirname, "..", "admin", "static", name), "utf8");
const calls = [];
const store = {};
const context = vm.createContext({ state: { page: "projects" }, shell: () => {}, console, File,
  document: { querySelector: () => null, querySelectorAll: () => [] },
  esc: v => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]),
  card: (title, body) => "<section><h2>" + title + "</h2>" + body + "</section>",
  title: (_, h, t) => "<h1>" + h + "</h1><p>" + t + "</p>",
  api: async (route, body) => {
    calls.push({ route, body });
    if (route === "apps/draft-save") { store[body.name] = { ...body, updatedAt: 1700000000 }; return { saved: true, envSaved: Boolean(body.env) }; }
    if (route === "apps/drafts") return { drafts: Object.values(store).map(d => ({ name: d.name, updatedAt: d.updatedAt })) };
    if (route === "apps/draft-read") return store[body.name];
    if (route === "apps/draft-delete") { delete store[body.name]; return { deleted: true }; }
    return {};
  } });
vm.runInContext(read("apps.js") + "\nthis.appView = appView;", context);
const run = code => vm.runInContext(code, context);

(async () => {
  // Fill the New app form, then save it as a draft.
  run(`Object.assign(appView, { view: "new", name: "notes", mode: "files", entries: [{ path: "compose.yaml", text: "services: {}\\n" }],
    newEnv: "GREETING=hello\\nTOKEN=abc", nix: "" })`);
  assert.match(run("appsPage()"), /id="app-draft-save"/);
  await run("saveDraftApp()");
  const saved = calls.find(c => c.route === "apps/draft-save").body;
  assert.equal(saved.name, "notes");
  assert.deepEqual(JSON.parse(JSON.stringify(saved.env)), { GREETING: "hello", TOKEN: "abc" });
  assert.equal(saved.entries[0].path, "compose.yaml");
  assert.match(run("appView.message"), /Draft saved/);

  // The Apps page lists it with Resume and Delete.
  run('Object.assign(appView, { view: "list", overview: { projects: [] } })');
  let html = run("appsPage()");
  assert.match(html, /<h2>Drafts<\/h2>/);
  assert.match(html, /data-draft-resume="notes"/);
  assert.match(html, /data-draft-delete="notes"/);

  // Resuming restores the form, including the variables.
  run('Object.assign(appView, { name: "", entries: [{ path: "Dockerfile", text: "" }], newEnv: "" })');
  await run('resumeDraft("notes")');
  assert.equal(run("appView.view"), "new");
  assert.equal(run("appView.name"), "notes");
  assert.equal(run("appView.entries[0].path"), "compose.yaml");
  assert.equal(run("appView.newEnv"), "GREETING=hello\nTOKEN=abc");

  // A name is required, and nothing is sent without one.
  calls.length = 0;
  run('appView.name = ""; appView.view = "new"');
  await run("saveDraftApp()");
  assert.equal(calls.length, 0);
  assert.match(run("appView.error"), /Name/);

  // Delete removes it from the list.
  await run('deleteDraftApp("notes")');
  run('Object.assign(appView, { view: "list", error: "" })');
  assert.doesNotMatch(run("appsPage()"), /Drafts<\/h2>/);
  console.log("App draft UI checks passed: save, list, resume with variables, delete");
})().catch(e => { console.error(e); process.exitCode = 1; });

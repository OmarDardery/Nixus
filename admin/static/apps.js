"use strict";

// Apps page: running apps, one-step add/update and image updates.
// Deploy runs the same reviewed, hash-checked steps as the broker API.

const appView = {
  overview: null, jobs: {}, updates: null, backups: null, loading: false, error: "", message: "",
  busy: false, log: null, mode: "files", drafts: [],
  entries: [{ path: "Dockerfile", text: "" }], uploads: [], nix: "",
  instance: { type: "container", image: "images:debian/13", cpus: 2, memory: 2, disk: 10, usb: "" },
  importTarget: "", importError: "", importMessage: "",
  view: "list", tab: "deployments", filter: "", nixLoaded: "",
  newVars: [{ key: "", value: "", show: true }], newPaste: false, replaceOk: false,
  env: { project: "", names: null, rows: null, revision: null, paste: false, error: "", message: "" },
};

const APP_TEMPLATES = {
  dockerfile: [{ path: "Dockerfile", text: "FROM debian:13@sha256:<digest>\nCOPY app /app\nCMD [\"/app/run\"]\n" }],
  compose: [
    { path: "compose.yaml", text: "services:\n  web:\n    build: .\n    ports:\n      - \"8080:8080\"\n    volumes:\n      - data:/var/lib/app\nvolumes:\n  data: {}\n" },
    { path: "Dockerfile", text: "FROM debian:13@sha256:<digest>\nCOPY app /app\nCMD [\"/app/run\"]\n" },
  ],
};

// nixInstance turns the VM/container form into a native app declaration.
function nixInstance(name, o) {
  const usb = /^[0-9a-f]{4}:[0-9a-f]{4}$/.test(o.usb || "")
    ? "      usb.device = { vendorId = \"" + o.usb.slice(0, 4) + "\"; productId = \"" + o.usb.slice(5) + "\"; };\n" : "";
  return "{ ... }: {\n  nixus.project = {\n    backend = \"incus-native\";\n" +
    "    volumes.data.size = \"" + Number(o.disk) + "GiB\";\n    instances." + name + " = {\n" +
    "      type = \"" + (o.type === "virtual-machine" ? "virtual-machine" : "container") + "\";\n" +
    "      image = \"" + o.image + "\";\n      cpus = " + Number(o.cpus) + ";\n      memory = \"" + Number(o.memory) + "GiB\";\n" +
    "      disks.data = { volume = \"data\"; path = \"/srv/data\"; };\n" + usb + "    };\n  };\n}\n";
}

const APP_MAX_FILES = 256, APP_MAX_FILE = 64 * 1024 * 1024, APP_MAX_TOTAL = 128 * 1024 * 1024;

function badge(value) {
  const text = String(value || "—");
  const tone = /^(Running|complete|verified|deployed|updated|current)$/.test(text) ? "ok"
    : /^(failed|partial|interrupted|Error|rolled-back|rollback-failed)$/.test(text) ? "bad" : "muted";
  return '<span class="badge ' + tone + '">' + esc(text) + "</span>";
}

// sourcePath validates a relative path and refuses credential-like files.
function sourcePath(file) {
  const name = file.nixusPath || file.webkitRelativePath || file.name;
  if (!name || name.length > 255 || name.startsWith("/") || name.includes("\\") ||
      name.split("/").some(part => !part || part === "." || part === ".." || /[\x00-\x1f]/.test(part)))
    throw Error("Invalid path: " + name);
  const parts = name.split("/");
  if (parts.length > 12 || parts.some(part => !/^(?:[A-Za-z0-9][A-Za-z0-9_.-]*|\.[A-Za-z0-9][A-Za-z0-9._-]*)$/.test(part)))
    throw Error("Invalid path: " + name);
  if (parts.some(part => {
    const lower = part.toLowerCase();
    return [".git", ".ssh", ".gnupg", ".nixus", "node_modules", ".env", "id_rsa", "id_ed25519", "id_ecdsa", "projects.agekey"].includes(lower) ||
      (lower.startsWith(".env.") && ![".env.example", ".env.sample", ".env.template"].includes(lower)) ||
      [".agekey", ".p12", ".pfx", ".key"].some(ext => lower.endsWith(ext)) ||
      (lower.startsWith("secrets.") && !/^secrets\.enc\.(?:ya?ml|json)$/.test(lower));
  })) throw Error("Refusing credential file: " + name);
  return name;
}

// appFiles merges uploaded and pasted files into File objects with paths.
function appFiles() {
  const files = [];
  const seen = new Set();
  const add = (file, path) => {
    if (seen.has(path)) throw Error("Duplicate path: " + path);
    seen.add(path);
    Object.defineProperty(file, "nixusPath", { value: path });
    sourcePath(file);
    files.push(file);
  };
  for (const file of appView.uploads) add(file, file.webkitRelativePath || file.name);
  for (const entry of appView.entries) {
    if (!entry.path && !entry.text) continue;
    if (!entry.path) throw Error("Pasted file needs a path.");
    if (!entry.text) throw Error(entry.path + " is empty.");
    if (/<digest>/.test(entry.text)) throw Error("Replace <digest> in " + entry.path + ".");
    add(new File([entry.text], entry.path.split("/").pop(), { type: "text/plain" }), entry.path);
  }
  if (!files.length) throw Error("Add a Dockerfile or compose.yaml.");
  if (files.length > APP_MAX_FILES) throw Error("At most 256 files.");
  return files;
}

async function sha256Hex(file) {
  const hash = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// stageFiles uploads files in 64 KiB chunks after hashing them in the browser.
async function stageAppFiles(project, files, current) {
  let total = 0;
  const items = [];
  for (const file of files) {
    if (file.size > APP_MAX_FILE) throw Error(file.nixusPath + " exceeds 64 MiB.");
    total += file.size;
    if (total > APP_MAX_TOTAL) throw Error("Files exceed 128 MiB.");
    items.push({ path: file.nixusPath, size: file.size, sha256: await sha256Hex(file) });
  }
  const candidate = await api("project-import/prepare", { project, files: items, archive: false, current });
  for (const file of files) {
    for (let offset = 0; offset < file.size; offset += 65536) {
      const bytes = new Uint8Array(await file.slice(offset, Math.min(offset + 65536, file.size)).arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
      const result = await api("project-import/chunk", { id: candidate.id, path: file.nixusPath, offset, data: btoa(binary) });
      if (result.offset !== offset + bytes.length) throw Error("Upload acknowledgment mismatch.");
    }
  }
  return api("project-import/finish", { id: candidate.id, manifestHash: candidate.manifestHash });
}

// --- views ------------------------------------------------------------------

function consoleLink(project, instance) {
  const incus = typeof managementServices === "function" ? managementServices().find(s => s.name === "Incus" && s.url) : null;
  if (!incus) return "";
  return ' <a class="small" target="_blank" rel="noopener noreferrer" href="' + esc(incus.url.replace(/\/$/, "") + "/ui/project/" +
    encodeURIComponent(project) + "/instance/" + encodeURIComponent(instance) + "/console") + '">Console ↗</a>';
}

function appProjects() { return appView.overview?.projects || []; }
function appByName(name) { return appProjects().find(p => p.name === name); }

function appStatus(p) {
  const instances = p.instances || [];
  const running = instances.filter(i => i.status === "Running").length;
  const job = appView.jobs[p.name];
  if (job && !["deployed", "failed", "interrupted"].includes(job.status)) return job.status;
  if (job?.status === "failed" || job?.status === "interrupted") return job.status;
  return !instances.length ? "Stopped" : running === instances.length ? "Running" : running ? "Degraded" : "Stopped";
}

// Monochrome line icons (24px grid), drawn with currentColor.
const ICONS = {
  plus: '<path d="M12 5v14M5 12h14"/>',
  import: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.34-5.66L20 8.5M20 3.5v5h-5"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  git: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="7" r="2"/><path d="M6 7v10M18 9c0 5-6 4-6 9"/>',
  archive: '<path d="M3 4h18v4H3zM5 8v12h14V8M10 12h4"/>',
  folder: '<path d="M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/>',
};

function icon(name) {
  return '<svg class="icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.75" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICONS[name] + "</svg>";
}

// ago formats a Unix time as "5 min ago", "2 h ago" or "3 d ago".
function ago(t) {
  if (!t) return "";
  const s = Math.max(0, Date.now() / 1000 - t);
  return s < 60 ? "just now" : s < 3600 ? Math.floor(s / 60) + " min ago" : s < 86400 ? Math.floor(s / 3600) + " h ago" : Math.floor(s / 86400) + " d ago";
}

function appCard(p) {
  const instances = p.instances || [];
  const running = instances.filter(i => i.status === "Running").length;
  const updates = (appView.updates?.projects || {})[p.name]?.updates > 0;
  const status = appStatus(p);
  const tone = status === "Running" ? "ok" : /failed|Degraded/.test(status) ? "bad" : /Stopped/.test(status) ? "off" : "busy";
  const ports = [...new Set(instances.flatMap(i => i.ports || []).filter(n => Number.isInteger(n) && n > 0 && n < 65536))];
  const job = appView.jobs[p.name];
  return '<button type="button" class="app-card" data-app-open="' + esc(p.name) + '" aria-label="Open ' + esc(p.name) + ", " + esc(status) + '">' +
    '<span class="app-card-top"><span class="app-name"><span class="app-dot ' + tone + '" aria-hidden="true"></span>' + esc(p.name) + "</span>" +
    (updates ? '<span class="app-pill" title="Update available">Update</span>' : "") + "</span>" +
    '<span class="app-sub">' + (p.backend === "incus-compose" ? "Compose" : "VM / container") + " · " + running + "/" + instances.length + " running</span>" +
    '<span class="app-foot">' + (status === "Running" ? "" : "<span>" + esc(status) + "</span>") +
    (ports.length ? '<span class="mono">' + ports.slice(0, 3).map(n => ":" + n).join(" ") + "</span>" : "") +
    (job?.completedAt ? "<span>Deployed " + esc(ago(job.completedAt)) + "</span>" : "") + "</span></button>";
}

function appsHasProjects() { return appProjects().length > 0; }

function importMenu() {
  return '<details class="menu"><summary class="icon-button" aria-label="Import an app" title="Import">' + icon("import") + '<span class="label">Import</span></summary>' +
    '<div class="menu-list" role="menu">' +
    '<button type="button" role="menuitem" data-import="repo">' + icon("git") + "<span><b>From a Git repository</b><small>Deploy apps from your apps repo</small></span></button>" +
    '<button type="button" role="menuitem" data-import="upload">' + icon("folder") + "<span><b>Upload a folder</b><small>A compose.yaml and its files</small></span></button>" +
    (appsHasProjects() ? "" : '<button type="button" role="menuitem" data-import="backup">' + icon("archive") +
      "<span><b>From a backup</b><small>Restore this server's apps and data</small></span></button>") +
    "</div></details>";
}

function appsList() {
  const filter = appView.filter.toLowerCase();
  const all = appProjects();
  const projects = all.filter(p => !filter || p.name.includes(filter));
  const head = '<div class="page-title apps-head"><div><h1>Apps</h1><p>' +
    (all.length ? all.length + " app" + (all.length === 1 ? "" : "s") + " on this server." : "Deploy apps, VMs and containers.") + "</p></div>" +
    '<div class="apps-actions">' + importMenu() +
    '<button type="button" class="primary icon-button" data-app-new aria-label="Add app" title="Add app">' + icon("plus") + '<span class="label">Add app</span></button></div></div>';
  const tools = all.length ? '<div class="apps-tools"><label class="search">' + icon("search") +
    '<input type="search" id="apps-filter" placeholder="Search apps…" value="' + esc(appView.filter) + '" aria-label="Search apps"></label>' +
    '<button type="button" class="icon-button ghost" id="apps-refresh" aria-label="Refresh" title="Refresh">' + icon("refresh") + "</button></div>" : "";
  const empty = '<div class="apps-empty"><h2>No apps yet</h2><p>Add one from a Compose file or Dockerfile, or import your apps.</p>' +
    '<div class="apps-actions"><button type="button" class="primary icon-button" data-app-new>' + icon("plus") + '<span class="label">Add app</span></button>' +
    '<button type="button" class="icon-button" data-import="repo">' + icon("git") + '<span class="label">From Git</span></button>' +
    '<button type="button" class="icon-button" data-import="backup">' + icon("archive") + '<span class="label">From a backup</span></button></div></div>';
  return head + (appView.error ? '<p class="error" role="alert">' + esc(appView.error) + "</p>" : "") +
    (appView.message ? '<p role="status" class="notice">' + esc(appView.message) + "</p>" : "") + tools + draftsCard() +
    (projects.length ? '<div class="app-grid">' + projects.map(appCard).join("") + "</div>"
      : all.length ? '<p class="apps-none">No apps match “' + esc(appView.filter) + "”.</p>" : empty);
}

function draftsCard() {
  const drafts = appView.drafts || [];
  if (!drafts.length) return "";
  const withEnv = drafts.some(d => d.envCount > 0);
  return '<section class="drafts" aria-label="Drafts"><h2>Drafts</h2>' +
    (withEnv ? '<label class="field draft-password"><span>Password, to open saved variables</span><input id="draft-password" type="password" autocomplete="current-password"></label>' : "") +
    "<ul>" + drafts.map(d =>
    '<li><span class="draft-tag">Draft</span><span class="draft-name">' + esc(d.name) + "</span>" + (d.envCount > 0 ? '<span class="draft-env" title="Has saved variables">' + d.envCount + " vars</span>" : "") +
    '<span class="draft-name-fill"></span><span class="draft-when">saved ' + esc(ago(d.updatedAt)) + "</span>" +
    '<span class="draft-do"><button type="button" class="small" data-draft-resume="' + esc(d.name) + '">Resume</button>' +
    '<button type="button" class="small icon-button ghost" data-draft-delete="' + esc(d.name) + '" aria-label="Delete draft ' + esc(d.name) + '" title="Delete">' +
    icon("trash") + "</button></span></li>").join("") + "</ul></section>";
}

// openImport sends the user to where each kind of import lives.
function openImport(kind) {
  if (kind === "upload") { Object.assign(appView, { view: "new", mode: "files", error: "", message: "" }); rerender(); return; }
  const heading = kind === "repo" ? "apps repository" : "restore this server from a backup";
  if (typeof navigateTo === "function") navigateTo("operations");
  setTimeout(() => {
    const panel = document.querySelector('[data-panel="operations:' + heading + '"]');
    if (panel) { panel.open = true; panel.scrollIntoView({ block: "start", behavior: "smooth" }); }
  }, 80);
}

function appTabs() {
  return '<nav class="tabs" aria-label="App">' + [["deployments", "Deployments"], ["logs", "Logs"], ["env", "Environment Variables"], ["settings", "Settings"]]
    .map(([id, label]) => '<button type="button" class="' + (appView.tab === id ? "active" : "") + '" data-app-tab="' + id + '">' + label + "</button>").join("") + "</nav>";
}

function deploymentsTab(p) {
  const job = appView.jobs[p.name];
  const images = ((appView.updates?.projects || {})[p.name]?.images || []).map(img =>
    "<tr><td><code>" + esc(img.ref) + "</code></td><td>" + badge(img.status) + "</td><td>" +
    (img.latest && img.latest !== img.digest
      ? '<button type="button" class="small" data-image-hold="' + esc(p.name) + '" data-digest="' + esc(img.latest) + '" data-held="' +
        (img.status === "held" ? "1" : "0") + '">' + (img.status === "held" ? "Unskip" : "Skip") + "</button>" : "") + "</td></tr>").join("");
  const when = t => t ? new Date(t * 1000).toLocaleString() : "—";
  return card("Latest deployment", job
      ? "<p>" + badge(job.status) + " · started " + esc(when(job.startedAt)) + (job.completedAt ? " · finished " + esc(when(job.completedAt)) : "") +
        (job.revision ? " · source <code>" + esc(String(job.revision).slice(0, 12)) + "</code>" : "") + "</p>" + deploySteps(job) +
        (job.error ? '<pre class="deploy-error" role="alert">' + esc(job.error) + "</pre>" +
          '<div class="actions"><button type="button" class="small" data-app-tab="env">Edit variables</button> ' +
          ((p.instances || []).some(i => i.status !== "Running") ? '<button type="button" class="small" data-app-power="start">Start again</button>' : "") + "</div>" : "")
      : "<p>No deployments from this console yet.</p>") +
    card("Images", (images ? '<div class="table-wrap"><table><thead><tr><th>Image</th><th>Status</th><th></th></tr></thead><tbody>' + images +
      "</tbody></table></div>" : "<p>No tracked images.</p>") + '<p><button type="button" class="small" id="image-updates-check">Check for updates</button></p>');
}

const DEPLOY_STEPS = [["preparing", "Prepare"], ["publishing", "Publish files"], ["building", "Build images"],
  ["deploying", "Start containers"], ["configuring", "Save variables"], ["deployed", "Done"]];

// deploySteps shows where a deployment is, or where it stopped.
function deploySteps(job) {
  const status = job.status === "failed" || job.status === "interrupted" ? (job.failedStep || "") : job.status === "queued" ? "preparing" : job.status;
  const at = DEPLOY_STEPS.findIndex(([id]) => id === status);
  if (at < 0) return "";
  const stopped = job.status === "failed" || job.status === "interrupted";
  return '<ol class="deploy-steps">' + DEPLOY_STEPS.map(([id, label], i) => {
    const cls = i < at || (job.status === "deployed") ? "done" : i === at ? (stopped ? "failed" : "current") : "";
    return '<li class="' + cls + '">' + esc(label) + "</li>";
  }).join("") + "</ol>";
}

function logsTab(p) {
  const instances = p.instances || [];
  return card("Logs", (instances.length ? '<div class="actions">' + instances.map(i =>
      '<button type="button" class="small' + (appView.log?.instance === i.name ? " active" : "") + '" data-app-log="' + esc(p.incusProject + "/" + i.name) + '">' +
      esc(i.name) + "</button>" + consoleLink(p.incusProject, i.name)).join(" ") + "</div>" : "<p>No instances.</p>") +
    (appView.log ? '<pre class="log">' + esc(appView.log.log || "(empty)") + "</pre>" : ""));
}

// parseEnv reads KEY=VALUE lines (comments, blank lines, `export ` and quotes allowed).
function parseEnv(text) {
  const out = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.replace(/^export\s+/, "").match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) throw Error("Not KEY=VALUE: " + line.slice(0, 40));
    let value = m[2];
    if (/^".*"$/.test(value)) value = value.slice(1, -1).replace(/\\n/g, "\n").replace(/\\"/g, '"');
    else if (/^'.*'$/.test(value)) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, "");
    out.push({ key: m[1], value });
  }
  return out;
}

const VAR_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

function varRows(scope) { return scope === "new" ? appView.newVars : (appView.env.rows || []); }

// varsEditor renders Name / Value rows. Every keystroke is copied into state
// (bindVars), so a re-render never loses what was typed.
function varsEditor(scope, rows, pasteOpen) {
  const bad = rows.filter(r => r.key && !VAR_NAME.test(r.key)).map(r => r.key);
  return '<div class="vars">' + rows.map((r, i) => {
    const id = scope + ":" + i;
    const invalid = r.key && !VAR_NAME.test(r.key);
    return '<div class="env-row"><input data-var-key="' + id + '" value="' + esc(r.key) + '" placeholder="NAME" spellcheck="false" autocomplete="off" aria-label="Name"' +
      (invalid ? ' aria-invalid="true" class="invalid"' : "") + ">" +
      '<input data-var-value="' + id + '" type="' + (r.show ? "text" : "password") + '" value="' + esc(r.value) + '" placeholder="value" spellcheck="false" autocomplete="off" aria-label="Value">' +
      '<button type="button" class="small" data-var-show="' + id + '" aria-label="Show or hide">' + (r.show ? "Hide" : "Show") + "</button>" +
      '<button type="button" class="small" data-var-remove="' + id + '" aria-label="Remove">✕</button></div>';
  }).join("") + "</div>" +
    (bad.length ? '<p class="error">Names use letters, digits and _, and do not start with a digit: ' + esc(bad.join(", ")) + "</p>" : "") +
    '<p><button type="button" class="small" data-var-add="' + scope + '">Add variable</button> <button type="button" class="small" data-var-paste="' + scope + '">Paste .env</button></p>' +
    (pasteOpen ? '<textarea id="var-paste-' + scope + '" rows="6" spellcheck="false" autocomplete="off" placeholder="KEY=value&#10;OTHER=value" aria-label="Paste .env"></textarea>' +
      '<p><button type="button" class="small" data-var-paste-apply="' + scope + '">Add to list</button></p>' : "");
}

// varsObject turns rows into { NAME: value }, refusing bad or repeated names.
function varsObject(rows) {
  const vars = {};
  for (const r of rows) {
    if (!r.key && !r.value) continue;
    if (!VAR_NAME.test(r.key)) throw Error("Invalid variable name: " + (r.key || "(empty)"));
    if (r.key in vars) throw Error("Variable listed twice: " + r.key);
    vars[r.key] = r.value;
  }
  return vars;
}

function varsFrom(env) {
  const rows = Object.entries(env || {}).map(([key, value]) => ({ key, value, show: false }));
  return rows.length ? rows : [{ key: "", value: "", show: true }];
}

function syncVars() {
  for (const input of document.querySelectorAll("[data-var-key]")) {
    const [scope, i] = input.dataset.varKey.split(":");
    const row = varRows(scope)[Number(i)];
    if (row) row.key = input.value.trim();
  }
  for (const input of document.querySelectorAll("[data-var-value]")) {
    const [scope, i] = input.dataset.varValue.split(":");
    const row = varRows(scope)[Number(i)];
    if (row) row.value = input.value;
  }
}

function envTab(p) {
  const e = appView.env;
  if (e.project !== p.name) Object.assign(e, { project: p.name, names: null, rows: null, revision: null, paste: false, error: "", message: "" });
  if (e.names === null) void loadEnvNames(p.name);
  const status = (e.error ? '<p class="error" role="alert">' + esc(e.error) + "</p>" : "") + (e.message ? '<p role="status">' + esc(e.message) + "</p>" : "");
  if (!e.rows) {
    const names = e.names || [];
    const job = appView.jobs[p.name];
    const pending = !names.length && (job?.envKeys || []).length && !["deployed"].includes(job.status) ? job.envKeys : [];
    return card("Environment Variables", needsKey(
      (pending.length ? '<p class="hint">Entered with the ' + (job.status === "failed" ? "failed" : "current") + " deployment: " +
        pending.map(n => "<code>" + esc(n) + "</code>").join(" ") + "</p>" : "") +
      (names.length ? '<div class="table-wrap"><table><tbody>' + names.map(n => "<tr><td><code>" + esc(n) + "</code></td><td>••••••••</td></tr>").join("") +
        "</tbody></table></div>" : "<p>No variables.</p>") +
      '<div class="toolbar"><input id="env-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
      '<button type="button" class="primary" id="env-reveal">' + (names.length ? "Reveal & edit" : "Add variables") + "</button></div>") + status);
  }
  return card("Environment Variables", varsEditor("env", e.rows, e.paste) +
    '<div class="toolbar"><input id="env-save-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
    '<button type="button" class="primary" id="env-save">Save & apply</button></div>' +
    '<p class="hint">Saved encrypted. Running containers get the new values; stopped ones are started with them.</p>' + status);
}

function settingsTab(p) {
  if (appView.nixLoaded !== p.name) void loadNix(p.name);
  const instances = p.instances || [];
  const options = instances.map(i => '<option value="' + esc(p.incusProject + "/" + i.name) + '">' + esc(i.name) + "</option>").join("");
  return card("Declaration", '<textarea id="app-nix" rows="14" spellcheck="false" aria-label="Nix declaration">' + esc(appView.nix) + "</textarea>" +
      '<div class="toolbar"><input id="app-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
      '<button type="button" class="primary" id="app-save-nix">Save & deploy</button></div>' +
      (appView.error ? '<p class="error" role="alert">' + esc(appView.error) + "</p>" : "") + (appView.message ? '<p role="status">' + esc(appView.message) + "</p>" : "")) +
    (options ? card("Import data",
      '<label class="field"><span>Instance</span><select id="import-target">' + options + "</select></label>" +
      '<label class="field"><span>Folder</span><input id="import-path" type="text" spellcheck="false" placeholder="/srv/data"></label>' +
      '<label class="field"><span>.tar or .tar.gz</span><input id="import-file" type="file" accept=".tar,.tgz,.tar.gz,application/x-tar,application/gzip"></label>' +
      '<div class="toolbar"><input id="import-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
      '<button type="button" id="import-start">Import</button></div>' +
      (appView.importError ? '<p class="error" role="alert">' + esc(appView.importError) + "</p>" : "") +
      (appView.importMessage ? '<p role="status">' + esc(appView.importMessage) + "</p>" : "")) : "") +
    devicesCard(p) + deleteCard(p);
}

// deleteCard removes the app with everything it has on this server.
function deleteCard(p) {
  return '<section class="danger-zone"><h2>Delete app</h2>' +
    "<p>Deletes <b>" + esc(p.name) + "</b> from this server: its containers or VMs, their data volumes and snapshots, images, variables, " +
    "files and deployment history. This cannot be undone. Existing off-host backups are kept until your retention policy removes them.</p>" +
    '<label class="field"><span>Type <b>' + esc(p.name) + '</b> to confirm</span><input id="delete-confirm" type="text" spellcheck="false" autocomplete="off"></label>' +
    '<div class="toolbar"><input id="delete-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
    '<button type="button" class="danger" id="app-delete"' + (appView.busy ? " disabled" : "") + ">Delete app</button></div>" +
    (appView.deleteError ? '<p class="error" role="alert">' + esc(appView.deleteError) + "</p>" : "") + "</section>";
}

// Detected host serial/USB devices with the line that passes each through.
function devicesCard(p) {
  if (appView.devices === undefined) {
    appView.devices = null;
    api("devices").then(d => { appView.devices = d; }, () => { appView.devices = { serial: [], usb: [] }; })
      .finally(() => { if (state.page === "projects") shell(); });
  }
  const d = appView.devices;
  if (!d) return card("Devices", "<p>Loading…</p>");
  const key = p.backend === "incus-compose" ? "compose" : "nix";
  const rows = [...(d.serial || []).map(x => [x.source, x.product, x[key]]), ...(d.usb || []).map(x => [x.id, x.product, x[key]])];
  if (!rows.length) return card("Devices", "<p>No USB or serial devices detected.</p>");
  return card("Devices", '<div class="table-wrap"><table><thead><tr><th>Device</th><th>Name</th><th>' +
    (key === "compose" ? "Add to the service in compose.yaml" : "Add to the instance") + "</th></tr></thead><tbody>" +
    rows.map(([id, name, line]) => "<tr><td><code>" + esc(id) + "</code></td><td>" + esc(name || "") +
      '</td><td><code>' + esc(line) + '</code> <button type="button" class="link" data-copy="' + esc(line) + '">Copy</button></td></tr>').join("") +
    "</tbody></table></div>");
}

function appDetail(name) {
  const p = appByName(name);
  if (!p) return '<p><button type="button" class="link" data-app-back>← Apps</button></p>' + card(name, "<p>Loading…</p>");
  const updates = (appView.updates?.projects || {})[p.name]?.updates > 0;
  const tab = { deployments: deploymentsTab, logs: logsTab, env: envTab, settings: settingsTab }[appView.tab] || deploymentsTab;
  return '<p><button type="button" class="link" data-app-back>← Apps</button></p>' +
    '<div class="page-title"><div><h1>' + esc(p.name) + "</h1><p>" + badge(appStatus(p)) + " " + (p.backend === "incus-compose" ? "Compose" : "VM / container") + "</p></div>" +
    '<div class="toolbar">' + appOpenLinks(p) + appPowerButtons(p) + (!updates ? "" : appView.confirmUpdate
      ? '<input id="update-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
        '<button type="button" class="primary" data-app-update="' + esc(p.name) + '">Confirm update</button>'
      : '<button type="button" class="primary" id="app-update-start">Update image</button>') + "</div></div>" +
    appTabs() + tab(p);
}

// Links to each published port on the server's address.
function appOpenLinks(p) {
  const host = state.status?.managementAddress;
  if (!host || !/^[0-9a-fA-F.:]+$/.test(host)) return "";
  const authority = host.includes(":") ? "[" + host + "]" : host;
  const ports = [...new Set((p.instances || []).flatMap(i => i.ports || []))].filter(n => Number.isInteger(n) && n > 0 && n < 65536).sort((a, b) => a - b);
  return ports.map(n => '<a class="button" href="http://' + esc(authority) + ":" + n + '" target="_blank" rel="noopener noreferrer">Open :' + n + " ↗</a>").join("");
}

function appPowerButtons(p) {
  const instances = p.instances || [];
  if (!instances.length) return "";
  const running = instances.some(i => i.status === "Running");
  return '<button type="button" data-app-power="restart">Restart</button>' +
    (running ? '<button type="button" data-app-power="stop">Stop</button>' : '<button type="button" data-app-power="start">Start</button>');
}

// needsKey locks a control until the secrets encryption key exists.
function needsKey(html) {
  return typeof gated === "function" ? gated("secretsKey", "Create the encryption key first.", html) : html;
}

function newAppView() {
  return '<p><button type="button" class="link" data-app-back>← Apps</button></p>' + title("", "New app", "Paste or upload a Dockerfile and Compose file, or describe a VM or container.") + addAppCard();
}

function addAppCard() {
  const files = appView.mode === "files";
  const entries = appView.entries.map((e, i) =>
    '<div class="paste-entry"><input type="text" spellcheck="false" data-app-path="' + i + '" value="' + esc(e.path) +
    '" placeholder="path" aria-label="File path"><textarea rows="8" spellcheck="false" data-app-text="' + i +
    '" aria-label="File contents">' + esc(e.text) + "</textarea>" +
    (appView.entries.length > 1 ? '<button type="button" class="small" data-app-remove="' + i + '">Remove</button>' : "") + "</div>").join("");
  const exists = appProjects().some(p => p.name === appView.name);
  return card("App",
    '<label class="field"><span>Name</span><input id="app-name" type="text" spellcheck="false" placeholder="my-app" value="' +
    esc(appView.name || "") + '"></label>' +
    (exists ? '<label class="check replace-ok"><input type="checkbox" id="app-replace-ok"' + (appView.replaceOk ? " checked" : "") +
      "> Replace the files of the existing app <b>" + esc(appView.name) + "</b> (its data and variables are kept)</label>" : "") +
    '<nav class="tabs"><button type="button" class="' + (files ? "active" : "") + '" data-app-mode="files">Dockerfile / Compose</button>' +
    '<button type="button" class="' + (files ? "" : "active") + '" data-app-mode="nix">VM / container</button></nav>' +
    (files
      ? '<div class="actions"><button type="button" class="small" data-app-template="dockerfile">Dockerfile template</button> ' +
        '<button type="button" class="small" data-app-template="compose">Compose template</button></div>' + entries +
        '<p><button type="button" class="small" id="app-add-file">Add file</button> ' +
        '<button type="button" class="small" id="app-pin">Pin image digests</button></p>' +
        '<label class="field"><span>Upload files</span><input id="app-upload" type="file" multiple></label>' +
        '<label class="field"><span>Upload folder</span><input id="app-upload-dir" type="file" webkitdirectory></label>' +
        (appView.uploads.length ? "<p>" + appView.uploads.length + " uploaded file(s)</p>" : "")
      : instanceForm() +
        '<textarea id="app-nix" rows="14" spellcheck="false" aria-label="Nix declaration">' + esc(appView.nix) + "</textarea>") +
    '<section class="env-new"><h3>Environment variables</h3>' +
    needsKey(varsEditor("new", appView.newVars, appView.newPaste) +
      '<p class="hint">Every service gets these. Saved encrypted with your secrets key; values never leave this server.</p>') + "</section>" +
    '<div class="toolbar"><input id="app-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
    '<button type="button" id="app-draft-save"' + (appView.busy ? " disabled" : "") + '>Save draft</button> ' +
    '<button type="button" class="primary" id="app-deploy"' + (appView.busy ? " disabled" : "") + ">Deploy</button></div>" +
    (appView.error ? '<p class="error" role="alert">' + esc(appView.error) + "</p>" : "") +
    (appView.message ? '<p role="status">' + esc(appView.message) + "</p>" : ""));
}

function instanceForm() {
  const o = appView.instance;
  const num = (id, label, value, min, max) => '<label class="field"><span>' + label + '</span><input id="vm-' + id +
    '" type="number" min="' + min + '" max="' + max + '" value="' + esc(value) + '"></label>';
  return '<div class="fields">' +
    '<label class="field"><span>Type</span><select id="vm-type"><option value="container"' + (o.type === "container" ? " selected" : "") +
    '>Container</option><option value="virtual-machine"' + (o.type === "virtual-machine" ? " selected" : "") + ">VM</option></select></label>" +
    '<label class="field"><span>Image</span><input id="vm-image" type="text" spellcheck="false" value="' + esc(o.image) + '"></label>' +
    num("cpus", "CPUs", o.cpus, 1, 64) + num("memory", "Memory (GiB)", o.memory, 1, 512) + num("disk", "Data disk (GiB)", o.disk, 1, 16384) +
    '<label class="field"><span>USB device (vendor:product)</span><input id="vm-usb" type="text" spellcheck="false" placeholder="optional" value="' +
    esc(o.usb) + '"></label></div>' +
    '<p><button type="button" class="small" id="vm-generate">Generate</button></p>';
}

function appsPage() {
  if (!appView.overview && !appView.loading) void refreshApps();
  if (appView.view === "new") return newAppView();
  if (appView.view !== "list") return appDetail(appView.view);
  return appsList();
}

// --- actions ----------------------------------------------------------------

function rerender() { if (state.page === "projects") shell(); }

// typing is true while the cursor is in a form field, so background refreshes
// wait instead of redrawing under it.
function typing() {
  const el = document.activeElement;
  return !!el && el.id !== "apps-filter" && (el.tagName === "TEXTAREA" || el.tagName === "SELECT" || (el.tagName === "INPUT" && el.type !== "button"));
}

async function refreshApps() {
  if (appView.loading) return;
  appView.loading = true;
  try {
    const [overview, jobs, updates, backups, drafts] = await Promise.all([
      api("project-overview"), api("apps"), api("image-updates"), api("project-backups"), api("apps/drafts")]);
    Object.assign(appView, { overview, jobs, updates, backups, drafts: drafts?.drafts || [] });
  } catch (error) {
    appView.error = error.message || "Could not load appView.";
  } finally {
    appView.loading = false;
    if (!typing()) rerender();
  }
  if (Object.values(appView.jobs || {}).some(j => !["deployed", "failed", "interrupted"].includes(j.status)))
    setTimeout(() => { if (state.page === "projects") void refreshApps(); }, 4000);
}

function syncForm() {
  const typed = document.querySelector("#app-name")?.value.trim() ?? appView.name;
  if (typed !== appView.name) appView.replaceOk = false;
  appView.name = typed;
  for (const input of document.querySelectorAll("[data-app-path]")) appView.entries[Number(input.dataset.appPath)].path = input.value.trim();
  for (const area of document.querySelectorAll("[data-app-text]")) appView.entries[Number(area.dataset.appText)].text = area.value;
  const nix = document.querySelector("#app-nix");
  if (nix) appView.nix = nix.value;
  syncVars();
}

async function deployApp() {
  syncForm();
  const project = appView.name || "";
  const passwordInput = document.querySelector("#app-password");
  const current = passwordInput?.value || "";
  if (passwordInput) passwordInput.value = "";
  appView.error = appView.message = "";
  try {
    if (!/^[a-z][a-z0-9-]{0,62}$/.test(project)) throw Error("Name: lowercase letters, digits and dashes.");
    if (appProjects().some(p => p.name === project) && !appView.replaceOk)
      throw Error("An app named " + project + " already exists. Tick “Replace” above to update it.");
    const env = varsObject(appView.newVars);
    if (!current) throw Error("Enter your password.");
    appView.busy = true;
    rerender();
    let body;
    if (appView.mode === "files") {
      const staged = await stageAppFiles(project, appFiles(), current);
      body = { project, kind: "source", stagingId: staged.id, manifestHash: staged.manifestHash, current };
    } else {
      body = { project, kind: "nix", declaration: appView.nix, current };
    }
    if (Object.keys(env).length) body.env = env;
    await api("apps/deploy", body);
    appView.message = "";
    appView.uploads = [];
    Object.assign(appView, { view: project, tab: "deployments", newVars: varsFrom({}), newPaste: false, replaceOk: false });
  } catch (error) {
    appView.error = error.message || "Deploy failed.";
  } finally {
    appView.busy = false;
    void refreshApps();
  }
}

async function saveDraftApp() {
  syncForm();
  appView.error = appView.message = "";
  try {
    const name = appView.name || "";
    if (!/^[a-z][a-z0-9-]{0,62}$/.test(name)) throw Error("Name: lowercase letters, digits and dashes.");
    const entries = appView.entries.map(e => ({ path: e.path, text: e.text })).filter(e => e.path || e.text);
    let skipped = 0;
    for (const file of appView.uploads) {
      const text = file.size > 256 * 1024 ? null : await file.text();
      if (text === null || text.includes("\u0000")) { skipped++; continue; }
      entries.push({ path: file.webkitRelativePath || file.name, text });
    }
    const env = varsObject(appView.newVars);
    const result = await api("apps/draft-save", { name, mode: appView.mode, entries, nix: appView.nix, instance: appView.instance,
      env: Object.keys(env).length ? env : undefined });
    appView.message = "Draft saved." + (skipped ? " " + skipped + " file(s) were too large or binary and were not saved." : "") + (result?.note ? " " + result.note : "");
    const listed = await api("apps/drafts");
    appView.drafts = listed?.drafts || [];
  } catch (error) {
    appView.error = error.message || "Could not save the draft.";
  }
  rerender();
}

async function resumeDraft(name) {
  appView.error = appView.message = "";
  try {
    const input = document.querySelector("#draft-password");
    const current = input?.value || "";
    if (input) input.value = "";
    const listed = (appView.drafts || []).find(x => x.name === name);
    if (listed?.envCount > 0 && !current) throw Error("Enter your password to open this draft's variables.");
    const d = await api("apps/draft-read", current ? { name, current } : { name });
    Object.assign(appView, { name, mode: d.mode === "nix" ? "nix" : "files", uploads: [], nix: d.nix || "", newVars: varsFrom(d.env), view: "new", replaceOk: false,
      entries: (d.entries || []).length ? d.entries.map(e => ({ path: e.path, text: e.text })) : [{ path: "Dockerfile", text: "" }],
      message: d.envError || "" });
    Object.assign(appView.instance, d.instance || {});
  } catch (error) {
    appView.error = error.message || "Could not open the draft.";
  }
  rerender();
}

async function deleteDraftApp(name) {
  try {
    await api("apps/draft-delete", { name });
    appView.drafts = (appView.drafts || []).filter(d => d.name !== name);
  } catch (error) {
    appView.error = error.message || "Could not delete the draft.";
  }
  rerender();
}

async function loadNix(name) {
  appView.nixLoaded = name;
  try {
    const file = await api("project-file?path=" + encodeURIComponent(name + "/default.nix"));
    appView.nix = file.exists ? file.content : "";
  } catch (error) {
    appView.error = error.message || "Could not open " + name + ".";
  }
  rerender();
}

async function saveNix(name) {
  syncForm();
  const input = document.querySelector("#app-password");
  const current = input?.value || "";
  if (input) input.value = "";
  appView.error = appView.message = "";
  try {
    if (!current) throw Error("Enter your password.");
    await api("apps/deploy", { project: name, kind: "nix", declaration: appView.nix, current });
    appView.tab = "deployments";
  } catch (error) {
    appView.error = error.message || "Deploy failed.";
  }
  void refreshApps();
}

async function deleteApp(name) {
  const confirmInput = document.querySelector("#delete-confirm");
  const passwordInput = document.querySelector("#delete-password");
  const confirm = confirmInput?.value.trim() || "";
  const current = passwordInput?.value || "";
  if (passwordInput) passwordInput.value = "";
  appView.deleteError = "";
  try {
    if (confirm !== name) throw Error("Type " + name + " to confirm.");
    if (!current) throw Error("Enter your password.");
    appView.busy = true;
    rerender();
    const result = await api("apps/delete", { project: name, confirm, current });
    Object.assign(appView, { view: "list", tab: "deployments", log: null, error: "", message: "Deleted " + name + "." + (result?.note ? " " + result.note : "") });
    delete appView.jobs[name];
  } catch (error) {
    appView.deleteError = error.message || "Could not delete the app.";
  } finally {
    appView.busy = false;
    void refreshApps();
  }
}

async function loadEnvNames(name) {
  appView.env.names = [];
  try { appView.env.names = (await api("apps/env?project=" + encodeURIComponent(name))).keys || []; }
  catch (error) { appView.env.error = error.message || "Could not load variables."; }
  rerender();
}

async function revealEnv(name) {
  const e = appView.env;
  const input = document.querySelector("#env-password");
  const current = input?.value || "";
  if (input) input.value = "";
  e.error = e.message = "";
  try {
    if (!current) throw Error("Enter your password.");
    const result = await api("apps/env-read", { project: name, current });
    e.revision = result.revision ?? null;
    e.rows = Object.entries(result.vars || {}).map(([key, value]) => ({ key, value, show: false }));
    if (!e.rows.length) e.rows.push({ key: "", value: "", show: true });
  } catch (error) {
    e.error = error.message || "Could not read variables.";
  }
  rerender();
}

async function saveEnvVars(name) {
  syncVars();
  const e = appView.env;
  const input = document.querySelector("#env-save-password");
  const current = input?.value || "";
  if (input) input.value = "";
  e.error = e.message = "";
  try {
    const vars = varsObject(e.rows);
    if (!Object.keys(vars).length) throw Error("Add at least one variable.");
    if (!current) throw Error("Enter your password.");
    const result = await api("apps/env", { project: name, vars, revision: e.revision, current });
    e.revision = result.revision ?? e.revision;
    e.names = Object.keys(vars);
    e.rows = null;
    e.message = result.delivery?.error ? "Saved. " + result.delivery.error : "Saved and applied.";
    const stopped = (appByName(name)?.instances || []).some(i => i.status !== "Running");
    if (stopped && !result.delivery?.error) {
      await api("apps/power", { project: name, action: "start" });
      e.message = "Saved. Starting the app with the new variables…";
      void refreshApps();
    }
  } catch (error) {
    e.error = error.message || "Could not save.";
  }
  rerender();
}

async function showLog(target) {
  const [project, instance] = target.split("/");
  try {
    appView.log = await api("project-logs?project=" + encodeURIComponent(project) + "&instance=" + encodeURIComponent(instance));
  } catch (error) {
    appView.error = error.message || "Log unavailable.";
  }
  rerender();
}

async function appRequest(path, body, message) {
  appView.error = appView.message = "";
  try {
    await api(path, body);
    appView.message = message;
  } catch (error) {
    appView.error = error.message || "Request failed.";
  }
  void refreshApps();
}


async function pinApp() {
  syncForm();
  appView.error = appView.message = "";
  try {
    const files = appView.entries.filter(e => e.path && e.text);
    if (!files.length) throw Error("Paste a Dockerfile or compose.yaml first.");
    const result = await api("image-updates/pin", { files });
    const byPath = new Map(result.files.map(f => [f.path, f.text]));
    for (const entry of appView.entries) if (byPath.has(entry.path)) entry.text = byPath.get(entry.path);
    appView.message = result.changes.length ? "Pinned " + result.changes.length + " image(s)." : "Already pinned.";
  } catch (error) {
    appView.error = error.message || "Could not pin images.";
  }
  rerender();
}

function generateInstance() {
  syncForm();
  const value = id => document.querySelector("#vm-" + id)?.value || "";
  appView.instance = { type: value("type"), image: value("image").trim(), cpus: value("cpus"), memory: value("memory"), disk: value("disk"), usb: value("usb").trim().toLowerCase() };
  appView.error = "";
  if (!/^[a-z][a-z0-9-]{0,62}$/.test(appView.name || "")) appView.error = "Name: lowercase letters, digits and dashes.";
  else if (!/^images:[a-z0-9][a-z0-9._/-]{0,127}$/.test(appView.instance.image)) appView.error = "Image: e.g. images:debian/13 or images:ubuntu/24.04";
  else if (appView.instance.usb && !/^[0-9a-f]{4}:[0-9a-f]{4}$/.test(appView.instance.usb)) appView.error = "USB: vendor:product, e.g. 1d50:614e";
  else appView.nix = nixInstance(appView.name, appView.instance);
  rerender();
}

async function importData() {
  appView.importError = appView.importMessage = "";
  const target = document.querySelector("#import-target")?.value || "";
  const folder = (document.querySelector("#import-path")?.value || "").trim();
  const file = document.querySelector("#import-file")?.files?.[0];
  const passwordInput = document.querySelector("#import-password");
  const current = passwordInput?.value || "";
  if (passwordInput) passwordInput.value = "";
  appView.importTarget = target;
  try {
    const [project, instance] = target.split("/");
    if (!file) throw Error("Choose a .tar or .tar.gz file.");
    if (!/^\/[A-Za-z0-9._\/-]*$/.test(folder)) throw Error("Folder: an absolute path such as /srv/data");
    if (!current) throw Error("Enter your password.");
    const sha256 = await sha256Hex(file);
    const started = await api("apps/import-data/start", { project, instance, path: folder, size: file.size, sha256, current });
    const step = 128 * 1024;
    for (let offset = 0; offset < file.size; offset += step) {
      const bytes = new Uint8Array(await file.slice(offset, Math.min(offset + step, file.size)).arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
      await api("apps/import-data/chunk", { id: started.id, offset, data: btoa(binary) });
      appView.importMessage = "Uploading " + Math.round(100 * Math.min(offset + step, file.size) / file.size) + "%";
      rerender();
    }
    const done = await api("apps/import-data/finish", { id: started.id });
    appView.importMessage = "Imported " + done.files + " file(s) into " + instance + ":" + folder + ".";
  } catch (error) {
    appView.importError = error.message || "Import failed.";
    appView.importMessage = "";
  }
  rerender();
}

function bindApps() {
  if (state.page !== "projects") return;
  const on = (selector, handler) => document.querySelector(selector)?.addEventListener("click", handler);
  const each = (selector, handler) => { for (const el of document.querySelectorAll(selector)) el.addEventListener("click", () => handler(el)); };
  on("#apps-refresh", () => void refreshApps());
  each("[data-app-power]", el => {
    const action = el.dataset.appPower;
    if (action === "stop" && !window.confirm("Stop " + appView.view + "?")) return;
    el.disabled = true;
    api("apps/power", { project: appView.view, action }).then(() => { appView.message = ""; },
      error => { appView.error = error.message || "Failed."; }).finally(() => void refreshApps());
  });
  each("[data-copy]", el => { void navigator.clipboard?.writeText(el.dataset.copy); el.textContent = "Copied"; });
  document.querySelector("#apps-filter")?.addEventListener("input", event => {
    appView.filter = event.target.value;
    const caret = event.target.selectionStart;
    rerender();
    const box = document.querySelector("#apps-filter");
    if (box) { box.focus(); box.setSelectionRange(caret, caret); }
  });
  each("[data-import]", el => { el.closest("details")?.removeAttribute("open"); openImport(el.dataset.import); });
  each("[data-app-new]", () => { Object.assign(appView, { view: "new", error: "", message: "" }); rerender(); });
  each("[data-app-back]", () => { Object.assign(appView, { view: "list", log: null, error: "", message: "" }); rerender(); });
  each("[data-app-open]", el => { Object.assign(appView, { view: el.dataset.appOpen, tab: "deployments", log: null, error: "", message: "" }); rerender(); });
  each("[data-app-tab]", el => { appView.tab = el.dataset.appTab; appView.error = appView.message = ""; rerender(); });
  on("#app-deploy", () => void deployApp());
  on("#app-save-nix", () => void saveNix(appView.view));
  on("#app-delete", () => void deleteApp(appView.view));
  on("#app-add-file", () => { syncForm(); appView.entries.push({ path: "", text: "" }); rerender(); });
  on("#app-pin", () => void pinApp());
  on("#app-draft-save", () => void saveDraftApp());
  each("[data-draft-resume]", el => void resumeDraft(el.dataset.draftResume));
  each("[data-draft-delete]", el => void deleteDraftApp(el.dataset.draftDelete));
  on("#vm-generate", generateInstance);
  on("#import-start", () => void importData());
  on("#image-updates-check", () => void appRequest("image-updates/check", {}, "Checked."));
  on("#env-reveal", () => void revealEnv(appView.view));
  on("#env-save", () => void saveEnvVars(appView.view));
  const scopeOf = id => id.split(":")[0];
  const rowOf = id => varRows(scopeOf(id))[Number(id.split(":")[1])];
  each("[data-var-add]", el => { syncVars(); varRows(el.dataset.varAdd).push({ key: "", value: "", show: true }); rerender(); });
  each("[data-var-paste]", el => {
    syncVars();
    if (el.dataset.varPaste === "new") appView.newPaste = !appView.newPaste; else appView.env.paste = !appView.env.paste;
    rerender();
  });
  each("[data-var-paste-apply]", el => {
    syncVars();
    const scope = el.dataset.varPasteApply;
    const target = scope === "new" ? appView : appView.env;
    try {
      const parsed = parseEnv(document.querySelector("#var-paste-" + scope)?.value || "");
      const rows = varRows(scope).filter(r => r.key || r.value);
      for (const { key, value } of parsed) {
        const existing = rows.find(r => r.key === key);
        if (existing) existing.value = value; else rows.push({ key, value, show: false });
      }
      if (!rows.length) rows.push({ key: "", value: "", show: true });
      if (scope === "new") Object.assign(appView, { newVars: rows, newPaste: false, error: "", message: parsed.length + " variable(s) added." });
      else Object.assign(appView.env, { rows, paste: false, error: "", message: parsed.length + " variable(s) added; Save to apply." });
    } catch (error) {
      target.error = error.message;
    }
    rerender();
  });
  each("[data-var-show]", el => { syncVars(); const r = rowOf(el.dataset.varShow); if (r) r.show = !r.show; rerender(); });
  each("[data-var-remove]", el => {
    syncVars();
    const rows = varRows(scopeOf(el.dataset.varRemove));
    rows.splice(Number(el.dataset.varRemove.split(":")[1]), 1);
    if (!rows.length) rows.push({ key: "", value: "", show: true });
    rerender();
  });
  // Keep state in step with every keystroke so background refreshes never drop input.
  for (const el of document.querySelectorAll("#app-name, [data-app-path], [data-app-text], #app-nix, [data-var-key], [data-var-value]"))
    el.addEventListener("input", () => { syncForm(); });
  for (const el of document.querySelectorAll("[data-var-key]"))
    el.addEventListener("input", () => {
      const bad = el.value.trim() !== "" && !VAR_NAME.test(el.value.trim());
      el.classList.toggle("invalid", bad);
      el.setAttribute("aria-invalid", bad ? "true" : "false");
    });
  document.querySelector("#app-name")?.addEventListener("change", () => { syncForm(); rerender(); });
  document.querySelector("#app-replace-ok")?.addEventListener("change", event => { appView.replaceOk = event.target.checked; });
  for (const input of ["#app-upload", "#app-upload-dir"]) {
    document.querySelector(input)?.addEventListener("change", event => { syncForm(); appView.uploads = [...event.target.files]; rerender(); });
  }
  each("[data-app-mode]", el => { syncForm(); appView.mode = el.dataset.appMode; rerender(); });
  each("[data-app-template]", el => { syncForm(); appView.entries = APP_TEMPLATES[el.dataset.appTemplate].map(e => ({ ...e })); rerender(); });
  each("[data-app-remove]", el => { syncForm(); appView.entries.splice(Number(el.dataset.appRemove), 1); rerender(); });
  each("[data-app-log]", el => void showLog(el.dataset.appLog));
  on("#app-update-start", () => { appView.confirmUpdate = true; rerender(); document.querySelector("#update-password")?.focus(); });
  each("[data-app-update]", el => {
    const input = document.querySelector("#update-password");
    const current = input?.value || "";
    if (input) input.value = "";
    if (!current) { appView.error = "Enter your password."; rerender(); return; }
    appView.confirmUpdate = false;
    void appRequest("image-updates/apply", { project: el.dataset.appUpdate, current }, "Updating " + el.dataset.appUpdate + "…");
  });
  each("[data-image-hold]", el => void appRequest("image-updates/hold",
    { project: el.dataset.imageHold, digest: el.dataset.digest, hold: el.dataset.held !== "1" }, "Saved."));
}

"use strict";

// Apps page: running apps, one-step add/update and image updates.
// Deploy runs the same reviewed, hash-checked steps as the broker API.

const appView = {
  overview: null, jobs: {}, updates: null, backups: null, loading: false, error: "", message: "",
  busy: false, log: null, mode: "files",
  entries: [{ path: "Dockerfile", text: "" }], uploads: [], nix: "",
  instance: { type: "container", image: "images:debian/13", cpus: 2, memory: 2, disk: 10, usb: "" },
  importTarget: "", importError: "", importMessage: "",
  view: "list", tab: "deployments", filter: "", nixLoaded: "",
  env: { project: "", names: null, rows: null, revision: null, paste: false, error: "", message: "" },
};

const APP_TEMPLATES = {
  dockerfile: [{ path: "Dockerfile", text: "FROM debian:13@sha256:<digest>\nCOPY app /app\nCMD [\"/app/run\"]\n" }],
  compose: [
    { path: "compose.yaml", text: "services:\n  web:\n    build: .\n    ports:\n      - \"8080:8080\"\n    volumes:\n      - data:/var/lib/app\nvolumes:\n  data: {}\n" },
    { path: "Dockerfile", text: "FROM debian:13@sha256:<digest>\nCOPY app /app\nCMD [\"/app/run\"]\n" },
  ],
};

const NIX_TEMPLATES = {
  native: name => "{ ... }: {\n  nixus.project = {\n    backend = \"incus-native\";\n" +
    "    volumes.data.size = \"10GiB\";\n    instances." + name + " = {\n      image = \"images:debian/13\";\n" +
    "      cpus = 2;\n      memory = \"2GiB\";\n      disks.data = { volume = \"data\"; path = \"/srv/data\"; };\n" +
    "      # usb.device = { vendorId = \"1d50\"; productId = \"614e\"; };\n    };\n  };\n}\n",
  compose: () => "{ ... }: {\n  nixus.project = {\n    backend = \"incus-compose\";\n" +
    "    updates = { policy = \"auto\"; window = \"02:00-05:00\"; healthSeconds = 60; };\n  };\n}\n",
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
  if (job && !["deployed", "failed"].includes(job.status)) return job.status;
  if (job?.status === "failed") return "failed";
  return !instances.length ? "Stopped" : running === instances.length ? "Running" : running ? "Degraded" : "Stopped";
}

function appCard(p) {
  const instances = p.instances || [];
  const running = instances.filter(i => i.status === "Running").length;
  const updates = (appView.updates?.projects || {})[p.name]?.updates > 0;
  return '<button type="button" class="app-card" data-app-open="' + esc(p.name) + '">' +
    '<span class="app-name"><span class="app-icon" aria-hidden="true">' + esc(p.name.slice(0, 1).toUpperCase()) + "</span>" + esc(p.name) + "</span>" +
    '<span class="app-meta"><span>' + badge(appStatus(p)) + "</span><span>" + (p.backend === "incus-compose" ? "Compose" : "VM / container") +
    "</span><span>" + running + "/" + instances.length + " running</span>" + (updates ? '<span class="badge">Update available</span>' : "") + "</span></button>";
}

function appsList() {
  const filter = appView.filter.toLowerCase();
  const projects = appProjects().filter(p => !filter || p.name.includes(filter));
  return title("", "Apps", "Deploy and update your apps, VMs and containers.") +
    '<div class="toolbar"><input type="search" id="apps-filter" placeholder="Search apps…" value="' + esc(appView.filter) + '" aria-label="Search apps">' +
    '<span><button type="button" class="small" id="apps-refresh">Refresh</button> <button type="button" class="primary" data-app-new>New app</button></span></div>' +
    (appView.error ? '<p class="error" role="alert">' + esc(appView.error) + "</p>" : "") +
    (projects.length ? '<div class="app-grid">' + projects.map(appCard).join("") + "</div>"
      : card("No apps yet", '<p><button type="button" class="primary" data-app-new>New app</button> <button type="button" data-go="operations">Restore from a backup</button></p>'));
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
      ? "<p>" + badge(job.status) + " · started " + esc(when(job.startedAt)) + (job.completedAt ? " · finished " + esc(when(job.completedAt)) : "") + "</p>" +
        (job.error ? '<p class="error">' + esc(job.error) + "</p>" : "") + (job.revision ? "<p>Source <code>" + esc(String(job.revision).slice(0, 12)) + "</code></p>" : "")
      : "<p>No deployments from this console yet.</p>") +
    card("Images", (images ? '<div class="table-wrap"><table><thead><tr><th>Image</th><th>Status</th><th></th></tr></thead><tbody>' + images +
      "</tbody></table></div>" : "<p>No tracked images.</p>") + '<p><button type="button" class="small" id="image-updates-check">Check for updates</button></p>');
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

function envTab(p) {
  const e = appView.env;
  if (e.project !== p.name) Object.assign(e, { project: p.name, names: null, rows: null, revision: null, paste: false, error: "", message: "" });
  if (e.names === null) void loadEnvNames(p.name);
  const status = (e.error ? '<p class="error" role="alert">' + esc(e.error) + "</p>" : "") + (e.message ? '<p role="status">' + esc(e.message) + "</p>" : "");
  if (!e.rows) {
    const names = e.names || [];
    return card("Environment Variables",
      (names.length ? '<div class="table-wrap"><table><tbody>' + names.map(n => "<tr><td><code>" + esc(n) + "</code></td><td>••••••••</td></tr>").join("") +
        "</tbody></table></div>" : "<p>No variables.</p>") +
      '<div class="toolbar"><input id="env-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
      '<button type="button" class="primary" id="env-reveal">' + (names.length ? "Reveal & edit" : "Add variables") + "</button></div>" + status);
  }
  const rows = e.rows.map((r, i) => '<div class="env-row"><input data-env-key="' + i + '" value="' + esc(r.key) + '" placeholder="KEY" spellcheck="false" aria-label="Name">' +
    '<input data-env-value="' + i + '" type="' + (r.show ? "text" : "password") + '" value="' + esc(r.value) + '" placeholder="value" spellcheck="false" autocomplete="off" aria-label="Value">' +
    '<button type="button" class="small" data-env-show="' + i + '" aria-label="Show or hide">' + (r.show ? "Hide" : "Show") + "</button>" +
    '<button type="button" class="small" data-env-remove="' + i + '" aria-label="Remove">✕</button></div>').join("");
  return card("Environment Variables",
    rows + '<p><button type="button" class="small" id="env-add">Add variable</button> <button type="button" class="small" id="env-paste-toggle">Paste .env</button></p>' +
    (e.paste ? '<textarea id="env-paste" rows="8" spellcheck="false" placeholder="KEY=value&#10;OTHER=value"></textarea><p><button type="button" class="small" id="env-paste-apply">Add to list</button></p>' : "") +
    '<div class="toolbar"><input id="env-save-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
    '<button type="button" class="primary" id="env-save">Save & redeploy</button></div>' + status);
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
    devicesCard(p);
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
  return card("App",
    '<label class="field"><span>Name</span><input id="app-name" type="text" spellcheck="false" placeholder="my-app" value="' +
    esc(appView.name || "") + '"></label>' +
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
    '<details class="env-new"' + (appView.newEnv ? " open" : "") + '><summary>Environment variables (optional)</summary>' +
    '<textarea id="app-env" rows="5" spellcheck="false" autocomplete="off" placeholder="KEY=value&#10;OTHER_KEY=value" aria-label="Environment variables">' +
    esc(appView.newEnv || "") + '</textarea><p class="hint">One KEY=value per line, or paste a .env file. Saved encrypted with your secrets key.</p></details>' +
    '<div class="toolbar"><input id="app-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
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

async function refreshApps() {
  if (appView.loading) return;
  appView.loading = true;
  try {
    const [overview, jobs, updates, backups] = await Promise.all([
      api("project-overview"), api("apps"), api("image-updates"), api("project-backups")]);
    Object.assign(appView, { overview, jobs, updates, backups });
  } catch (error) {
    appView.error = error.message || "Could not load appView.";
  } finally {
    appView.loading = false;
    rerender();
  }
  if (Object.values(appView.jobs || {}).some(j => !["deployed", "failed"].includes(j.status)))
    setTimeout(() => { if (state.page === "projects") void refreshApps(); }, 4000);
}

function syncForm() {
  appView.name = document.querySelector("#app-name")?.value.trim() ?? appView.name;
  for (const input of document.querySelectorAll("[data-app-path]")) appView.entries[Number(input.dataset.appPath)].path = input.value.trim();
  for (const area of document.querySelectorAll("[data-app-text]")) appView.entries[Number(area.dataset.appText)].text = area.value;
  const nix = document.querySelector("#app-nix");
  if (nix) appView.nix = nix.value;
  const env = document.querySelector("#app-env");
  if (env) appView.newEnv = env.value;
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
    if (!current) throw Error("Enter your password.");
    const env = {};
    for (const { key, value } of parseEnv(appView.newEnv || "")) env[key] = value;
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
    appView.newEnv = "";
    Object.assign(appView, { view: project, tab: "deployments" });
  } catch (error) {
    appView.error = error.message || "Deploy failed.";
  } finally {
    appView.busy = false;
    void refreshApps();
  }
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

async function loadEnvNames(name) {
  appView.env.names = [];
  try { appView.env.names = (await api("apps/env?project=" + encodeURIComponent(name))).keys || []; }
  catch (error) { appView.env.error = error.message || "Could not load variables."; }
  rerender();
}

function syncEnv() {
  const rows = appView.env.rows || [];
  for (const input of document.querySelectorAll("[data-env-key]")) rows[Number(input.dataset.envKey)].key = input.value.trim();
  for (const input of document.querySelectorAll("[data-env-value]")) rows[Number(input.dataset.envValue)].value = input.value;
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
  syncEnv();
  const e = appView.env;
  const input = document.querySelector("#env-save-password");
  const current = input?.value || "";
  if (input) input.value = "";
  e.error = e.message = "";
  try {
    const vars = {};
    for (const r of e.rows) {
      if (!r.key && !r.value) continue;
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(r.key)) throw Error("Invalid name: " + (r.key || "(empty)"));
      if (r.key in vars) throw Error("Duplicate name: " + r.key);
      vars[r.key] = r.value;
    }
    if (!Object.keys(vars).length) throw Error("Add at least one variable.");
    if (!current) throw Error("Enter your password.");
    const result = await api("apps/env", { project: name, vars, revision: e.revision, current });
    e.revision = result.revision ?? e.revision;
    e.names = Object.keys(vars);
    e.message = result.delivery?.error ? "Saved. " + result.delivery.error : "Saved and applied.";
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
  each("[data-app-new]", () => { Object.assign(appView, { view: "new", error: "", message: "" }); rerender(); });
  each("[data-app-back]", () => { Object.assign(appView, { view: "list", log: null, error: "", message: "" }); rerender(); });
  each("[data-app-open]", el => { Object.assign(appView, { view: el.dataset.appOpen, tab: "deployments", log: null, error: "", message: "" }); rerender(); });
  each("[data-app-tab]", el => { appView.tab = el.dataset.appTab; appView.error = appView.message = ""; rerender(); });
  on("#app-deploy", () => void deployApp());
  on("#app-save-nix", () => void saveNix(appView.view));
  on("#app-add-file", () => { syncForm(); appView.entries.push({ path: "", text: "" }); rerender(); });
  on("#app-pin", () => void pinApp());
  on("#vm-generate", generateInstance);
  on("#import-start", () => void importData());
  on("#image-updates-check", () => void appRequest("image-updates/check", {}, "Checked."));
  on("#env-reveal", () => void revealEnv(appView.view));
  on("#env-save", () => void saveEnvVars(appView.view));
  on("#env-add", () => { syncEnv(); appView.env.rows.push({ key: "", value: "", show: true }); rerender(); });
  on("#env-paste-toggle", () => { syncEnv(); appView.env.paste = !appView.env.paste; rerender(); });
  on("#env-paste-apply", () => {
    syncEnv();
    try {
      const parsed = parseEnv(document.querySelector("#env-paste")?.value || "");
      const rows = appView.env.rows.filter(r => r.key || r.value);
      for (const { key, value } of parsed) {
        const existing = rows.find(r => r.key === key);
        if (existing) existing.value = value; else rows.push({ key, value, show: false });
      }
      Object.assign(appView.env, { rows, paste: false, error: "", message: parsed.length + " variable(s) added; Save to apply." });
    } catch (error) {
      appView.env.error = error.message;
    }
    rerender();
  });
  each("[data-env-show]", el => { syncEnv(); const r = appView.env.rows[Number(el.dataset.envShow)]; r.show = !r.show; rerender(); });
  each("[data-env-remove]", el => { syncEnv(); appView.env.rows.splice(Number(el.dataset.envRemove), 1); rerender(); });
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

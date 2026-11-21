"use strict";

// Apps page: running apps, one-step add/update and image updates.
// Deploy runs the same reviewed, hash-checked steps as the broker API.

const appView = {
  overview: null, jobs: {}, updates: null, backups: null, loading: false, error: "", message: "",
  busy: false, log: null, mode: "files",
  entries: [{ path: "Dockerfile", text: "" }], uploads: [], nix: "",
  instance: { type: "container", image: "images:debian/13", cpus: 2, memory: 2, disk: 10, usb: "" },
  importTarget: "", importError: "", importMessage: "",
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

// --- cards ------------------------------------------------------------------

function consoleLink(project, instance) {
  const incus = typeof managementServices === "function" ? managementServices().find(s => s.name === "Incus" && s.url) : null;
  if (!incus) return "";
  return ' <a class="small" target="_blank" rel="noopener noreferrer" href="' + esc(incus.url.replace(/\/$/, "") + "/ui/project/" +
    encodeURIComponent(project) + "/instance/" + encodeURIComponent(instance) + "/console") + '">Console</a>';
}

function appsCard() {
  const view = appView.overview;
  const updates = appView.updates?.projects || {};
  const rows = (view?.projects || []).map(p => {
    const instances = p.instances || [];
    const running = instances.filter(i => i.status === "Running").length;
    const job = appView.jobs[p.name];
    const update = updates[p.name] || {};
    return "<tr><td>" + esc(p.name) + "</td><td>" + (p.backend === "incus-compose" ? "Compose" : "Nix") + "</td><td>" +
      running + "/" + instances.length + "</td><td>" +
      (job ? badge(job.status) + (job.error ? " " + esc(job.error) : "") : "") + "</td><td>" +
      (update.updates > 0 ? '<button type="button" class="small" data-app-update="' + esc(p.name) + '">Update</button> ' : "") +
      '<button type="button" class="small" data-app-edit="' + esc(p.name) + '">Edit</button> ' +
      instances.map(i => '<button type="button" class="small" data-app-log="' + esc(p.incusProject + "/" + i.name) + '">' +
        esc(i.name) + " log</button>" + consoleLink(p.incusProject, i.name)).join(" ") + "</td></tr>";
  }).join("");
  const log = appView.log
    ? "<h3>" + esc(appView.log.project + "/" + appView.log.instance) + '</h3><pre class="log">' + esc(appView.log.log || "") +
      '</pre><button type="button" class="small" id="app-log-close">Close</button>' : "";
  return card("Apps",
    (rows ? '<div class="table-wrap"><table><thead><tr><th>App</th><th>Type</th><th>Running</th><th>Last deploy</th><th></th></tr></thead><tbody>' +
      rows + "</tbody></table></div>" : "<p>No appView.</p>") +
    log + '<button type="button" class="small" id="apps-refresh">Refresh</button>');
}

function addAppCard() {
  const files = appView.mode === "files";
  const entries = appView.entries.map((e, i) =>
    '<div class="paste-entry"><input type="text" spellcheck="false" data-app-path="' + i + '" value="' + esc(e.path) +
    '" placeholder="path" aria-label="File path"><textarea rows="8" spellcheck="false" data-app-text="' + i +
    '" aria-label="File contents">' + esc(e.text) + "</textarea>" +
    (appView.entries.length > 1 ? '<button type="button" class="small" data-app-remove="' + i + '">Remove</button>' : "") + "</div>").join("");
  return card("Add or update app",
    '<label class="field"><span>Name</span><input id="app-name" type="text" spellcheck="false" placeholder="my-app" value="' +
    esc(appView.name || "") + '"></label>' +
    '<div class="actions"><button type="button" class="small' + (files ? " active" : "") + '" data-app-mode="files">Dockerfile / Compose</button>' +
    '<button type="button" class="small' + (files ? "" : " active") + '" data-app-mode="nix">Nix</button></div>' +
    (files
      ? '<div class="actions"><button type="button" class="small" data-app-template="dockerfile">Dockerfile template</button>' +
        '<button type="button" class="small" data-app-template="compose">Compose template</button></div>' + entries +
        '<button type="button" class="small" id="app-add-file">Add file</button> ' +
        '<button type="button" class="small" id="app-pin">Pin image digests</button>' +
        '<label class="field"><span>Upload files</span><input id="app-upload" type="file" multiple></label>' +
        '<label class="field"><span>Upload folder</span><input id="app-upload-dir" type="file" webkitdirectory></label>' +
        (appView.uploads.length ? "<p>" + appView.uploads.length + " uploaded file(s)</p>" : "")
      : instanceForm() +
        '<div class="actions"><button type="button" class="small" data-nix-template="compose">Compose settings template</button></div>' +
        '<textarea id="app-nix" rows="14" spellcheck="false" aria-label="Nix declaration">' + esc(appView.nix) + "</textarea>") +
    '<label class="field"><span>Password</span><input id="app-password" type="password" autocomplete="current-password"></label>' +
    '<button type="button" id="app-deploy"' + (appView.busy ? " disabled" : "") + ">Deploy</button>" +
    (appView.error ? '<p class="error" role="alert">' + esc(appView.error) + "</p>" : "") +
    (appView.message ? '<p role="status">' + esc(appView.message) + "</p>" : ""));
}

function instanceForm() {
  const o = appView.instance;
  const num = (id, label, value, min, max) => '<label class="field"><span>' + label + '</span><input id="vm-' + id +
    '" type="number" min="' + min + '" max="' + max + '" value="' + esc(value) + '"></label>';
  return "<fieldset><legend>VM or container</legend>" +
    '<label class="field"><span>Type</span><select id="vm-type"><option value="container"' + (o.type === "container" ? " selected" : "") +
    '>Container</option><option value="virtual-machine"' + (o.type === "virtual-machine" ? " selected" : "") + ">VM</option></select></label>" +
    '<label class="field"><span>Image</span><input id="vm-image" type="text" spellcheck="false" value="' + esc(o.image) + '"></label>' +
    num("cpus", "CPUs", o.cpus, 1, 64) + num("memory", "Memory (GiB)", o.memory, 1, 512) + num("disk", "Data disk (GiB)", o.disk, 1, 16384) +
    '<label class="field"><span>USB device (vendor:product, optional)</span><input id="vm-usb" type="text" spellcheck="false" placeholder="1d50:614e" value="' +
    esc(o.usb) + '"></label>' +
    '<button type="button" class="small" id="vm-generate">Generate Nix</button></fieldset>';
}

function importCard() {
  const view = appView.overview;
  const options = (view?.projects || []).flatMap(p => (p.instances || []).map(i =>
    '<option value="' + esc(p.incusProject + "/" + i.name) + '"' + (appView.importTarget === p.incusProject + "/" + i.name ? " selected" : "") + ">" +
    esc(p.name + " · " + i.name) + "</option>")).join("");
  if (!options) return "";
  return card("Import data",
    '<label class="field"><span>Into</span><select id="import-target">' + options + "</select></label>" +
    '<label class="field"><span>Folder inside the instance</span><input id="import-path" type="text" spellcheck="false" placeholder="/srv/data"></label>' +
    '<label class="field"><span>.tar or .tar.gz file</span><input id="import-file" type="file" accept=".tar,.tgz,.tar.gz,application/x-tar,application/gzip"></label>' +
    '<label class="field"><span>Password</span><input id="import-password" type="password" autocomplete="current-password"></label>' +
    '<button type="button" id="import-start">Import</button>' +
    (appView.importError ? '<p class="error" role="alert">' + esc(appView.importError) + "</p>" : "") +
    (appView.importMessage ? '<p role="status">' + esc(appView.importMessage) + "</p>" : ""));
}

function updatesCard() {
  const projects = Object.entries(appView.updates?.projects || {});
  const rows = projects.flatMap(([name, p]) => (p.images || []).map(img =>
    "<tr><td>" + esc(name) + "</td><td><code>" + esc(img.ref) + "</code></td><td>" + badge(img.status) + "</td><td>" +
    (img.latest && img.latest !== img.digest
      ? '<button type="button" class="small" data-image-hold="' + esc(name) + '" data-digest="' + esc(img.latest) + '" data-held="' +
        (img.status === "held" ? "1" : "0") + '">' + (img.status === "held" ? "Unskip" : "Skip") + "</button>" : "") +
    "</td></tr>")).join("");
  return card("Image updates",
    (rows ? '<div class="table-wrap"><table><thead><tr><th>App</th><th>Image</th><th>Status</th><th></th></tr></thead><tbody>' +
      rows + "</tbody></table></div>" : "<p>No tracked images.</p>") +
    '<button type="button" class="small" id="image-updates-check">Check now</button>');
}



function appsPage() {
  if (!appView.overview && !appView.loading) void refreshApps();
  return title("", "Apps", "Deploy and update your apps, VMs and containers.") + appsCard() + addAppCard() + importCard() + updatesCard() +
    (typeof nativeSecretsPanel === "function" ? nativeSecretsPanel() : "");
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
    appView.busy = true;
    rerender();
    let body;
    if (appView.mode === "files") {
      const staged = await stageAppFiles(project, appFiles(), current);
      body = { project, kind: "source", stagingId: staged.id, manifestHash: staged.manifestHash, current };
    } else {
      body = { project, kind: "nix", declaration: appView.nix, current };
    }
    await api("apps/deploy", body);
    appView.message = "Deploying " + project + "…";
    appView.uploads = [];
  } catch (error) {
    appView.error = error.message || "Deploy failed.";
  } finally {
    appView.busy = false;
    void refreshApps();
  }
}

async function editApp(name) {
  appView.error = appView.message = "";
  try {
    const file = await api("project-file?path=" + encodeURIComponent(name + "/default.nix"));
    appView.name = name;
    appView.mode = "nix";
    appView.nix = file.exists ? file.content : "";
  } catch (error) {
    appView.error = error.message || "Could not open " + name + ".";
  }
  rerender();
  document.querySelector("#app-name")?.scrollIntoView({ block: "center" });
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
  if (typeof bindNativeSecrets === "function") bindNativeSecrets();
  const on = (selector, handler) => document.querySelector(selector)?.addEventListener("click", handler);
  on("#apps-refresh", () => void refreshApps());
  on("#app-log-close", () => { appView.log = null; rerender(); });
  on("#app-deploy", () => void deployApp());
  on("#app-add-file", () => { syncForm(); appView.entries.push({ path: "", text: "" }); rerender(); });
  on("#app-pin", () => void pinApp());
  on("#vm-generate", generateInstance);
  on("#import-start", () => void importData());
  on("#image-updates-check", () => void appRequest("image-updates/check", {}, "Checked."));
  for (const input of ["#app-upload", "#app-upload-dir"]) {
    document.querySelector(input)?.addEventListener("change", event => { syncForm(); appView.uploads = [...event.target.files]; rerender(); });
  }
  const each = (selector, handler) => { for (const el of document.querySelectorAll(selector)) el.addEventListener("click", () => handler(el)); };
  each("[data-app-mode]", el => { syncForm(); appView.mode = el.dataset.appMode; rerender(); });
  each("[data-app-template]", el => { syncForm(); appView.entries = APP_TEMPLATES[el.dataset.appTemplate].map(e => ({ ...e })); rerender(); });
  each("[data-nix-template]", el => { syncForm(); appView.nix = NIX_TEMPLATES[el.dataset.nixTemplate](appView.name || "my-app"); rerender(); });
  each("[data-app-remove]", el => { syncForm(); appView.entries.splice(Number(el.dataset.appRemove), 1); rerender(); });
  each("[data-app-edit]", el => void editApp(el.dataset.appEdit));
  each("[data-app-log]", el => void showLog(el.dataset.appLog));
  each("[data-app-update]", el => {
    const input = document.querySelector("#app-password");
    const current = input?.value || "";
    if (input) input.value = "";
    if (!current) { appView.error = "Enter your password below, then press Update."; rerender(); return; }
    void appRequest("image-updates/apply", { project: el.dataset.appUpdate, current }, "Updating " + el.dataset.appUpdate + "…");
  });
  each("[data-image-hold]", el => void appRequest("image-updates/hold",
    { project: el.dataset.imageHold, digest: el.dataset.digest, hold: el.dataset.held !== "1" }, "Saved."));
}

"use strict";

// Projects console additions: per-project overview, loading reviewed Nix files
// into the revision editor, bounded instance logs and the project backup view.
// Every value is escaped; every change still goes through the reviewed
// project transaction. Nothing here can run commands or edit Incus directly.

const projectConsole = {
  overview: null, overviewLoading: false, overviewError: "",
  backups: null, backupsLoading: false,
  expanded: "", log: null, logError: "", fileError: "",
  policy: { schedule: "daily", data: true, verification: "metadata", repository: "", rcloneConfigFile: "", initialize: false, github: "" },
};

const PROJECT_BACKUP_PHASES = [
  ["config", "Configuration snapshot"], ["data", "Incus data export"], ["offHost", "Off-host upload"],
  ["verification", "Repository verification"], ["github", "GitHub configuration mirror"],
];

function projectStatusBadge(value) {
  const text = String(value || "unknown");
  const tone = /^(Running|complete|verified|published-source|noop)$/.test(text) ? "ok"
    : /^(failed|partial|interrupted|Error)$/.test(text) ? "bad" : "muted";
  return '<span class="badge ' + tone + '">' + esc(text) + "</span>";
}

function projectOverviewCard() {
  const view = projectConsole.overview;
  if (projectConsole.overviewError) return card("Projects", '<p class="error" role="alert">' + esc(projectConsole.overviewError) + "</p>");
  if (!view) return card("Projects", "<p>Loading project overview…</p>");
  if (!view.available) return card("Projects", "<p>" + esc(view.reason || "No reviewed project revision yet.") +
    " Review a project <code>default.nix</code> below to declare your first project.</p>");
  const tx = view.transaction || {};
  const rows = (view.projects || []).map(p => {
    const open = projectConsole.expanded === p.name;
    const runtime = (p.instances || []).map(i =>
      "<tr><td><code>" + esc(i.name) + "</code></td><td>" + esc(i.type) + "</td><td>" + projectStatusBadge(i.status) +
      "</td><td>" + (i.compose ? "Compose" : i.owned ? "Nixus" : "unmanaged") + "</td><td>" +
      '<button type="button" class="small" data-project-log="' + esc(p.incusProject) + "/" + esc(i.name) + '">Log</button></td></tr>').join("");
    const coverage = p.backupCoverage
      ? "<p>Backup coverage: config " + (p.backupCoverage.config ? "yes" : "no") + " · data " + esc(p.backupCoverage.data) +
        ((p.backupCoverage.unknowns || []).length ? "</p><ul>" + p.backupCoverage.unknowns.map(u => "<li>" + esc(u) + "</li>").join("") + "</ul>" : "</p>")
      : "<p>No project backup has run yet.</p>";
    const retained = (p.retained || []).length
      ? "<p>Retained (kept, not managed): " + p.retained.map(r => "<code>" + esc(r.name) + "</code>").join(", ") + "</p>" : "";
    const detail = open
      ? '<tr class="detail"><td colspan="6"><p>Incus project <code>' + esc(p.incusProject) + "</code> · CPUs " + esc(p.resources?.cpus) +
        " · memory " + esc(p.resources?.memory) + " · backup consistency " + esc(p.backup?.consistency) + "</p>" +
        "<p>Declared instances: " + esc((p.declaredInstances || []).join(", ") || "none") +
        " · volumes: " + esc((p.declaredVolumes || []).join(", ") || "none") + "</p>" +
        "<p>Published source: " + (p.sourceRevision ? "<code>" + esc(p.sourceRevision.slice(0, 16)) + "</code>" : "none") + "</p>" +
        coverage + retained +
        (runtime ? '<div class="table-wrap"><table><thead><tr><th>Instance</th><th>Type</th><th>Status</th><th>Owner</th><th></th></tr></thead><tbody>' +
          runtime + "</tbody></table></div>" : "<p>No Incus instances observed in this project.</p>") +
        '<button type="button" class="small" data-project-edit="' + esc(p.name) + '/default.nix">Edit default.nix</button></td></tr>'
      : "";
    return "<tr><td><button type=\"button\" class=\"link\" data-project-expand=\"" + esc(p.name) + "\">" + (open ? "▾ " : "▸ ") + esc(p.name) +
      "</button></td><td>" + esc(p.backend) + "</td><td>" + (p.enable ? "enabled" : "disabled") + "</td><td>" + esc((p.instances || []).length) +
      "</td><td>" + (p.sourceRevision ? "yes" : "—") + "</td><td>" + (p.backupCoverage ? "covered" : "—") + "</td></tr>" + detail;
  }).join("");
  const log = projectConsole.log
    ? "<section><h3>Log: <code>" + esc(projectConsole.log.project + "/" + projectConsole.log.instance) + "</code>" +
      (projectConsole.log.truncated ? " (last 64 KiB)" : "") + '</h3><pre class="log">' + esc(projectConsole.log.log || "(empty)") +
      '</pre><button type="button" class="small" id="project-log-close">Close log</button></section>' : "";
  return card("Projects",
    '<button type="button" id="project-overview-refresh">Refresh</button>' +
    "<p>Latest revision " + projectStatusBadge(tx.status) + " · deployment " + projectStatusBadge(tx.deployment) +
    (tx.recoveryRequired ? ' · <b class="error">recovery required</b>' : "") + "</p>" +
    '<div class="table-wrap"><table><thead><tr><th>Project</th><th>Backend</th><th>State</th><th>Instances</th><th>Source</th><th>Backup</th></tr></thead><tbody>' +
    rows + "</tbody></table></div>" +
    (projectConsole.logError ? '<p class="error" role="alert">' + esc(projectConsole.logError) + "</p>" : "") + log +
    '<p class="note">Instances and volumes are created or changed only by an approved deployment. Removing a declaration keeps the resource and its data.</p>');
}

function projectBackupPolicyText(p) {
  const lines = ["{ ... }: {", "  nixus.backups = {", "    enable = true;", '    includeProjects = "all";',
    "    schedule = " + JSON.stringify(p.schedule) + ";", "    data = " + (p.data ? "true" : "false") + ";",
    "    verification = " + JSON.stringify(p.verification) + ";", "    restic = {",
    "      repository = " + JSON.stringify(p.repository) + ";"];
  if (p.rcloneConfigFile) lines.push("      rcloneConfigFile = " + JSON.stringify(p.rcloneConfigFile) + ";");
  if (p.initialize) lines.push("      initialize = true;");
  lines.push("    };");
  if (p.github) lines.push("    github.repository = " + JSON.stringify(p.github) + ";");
  lines.push("  };", "}", "");
  return lines.join("\n");
}

function projectBackupCard() {
  const status = projectConsole.backups || {};
  const phases = status.phases || {};
  const p = projectConsole.policy;
  const phaseRows = PROJECT_BACKUP_PHASES.map(([id, label]) => {
    const item = phases[id] || {};
    return "<tr><td>" + esc(label) + "</td><td>" + projectStatusBadge(item.state || "not run") + "</td><td>" + esc(item.detail || "") + "</td></tr>";
  }).join("");
  const last = status.lastSuccess ? new Date(status.lastSuccess * 1000).toLocaleString() : "never";
  return card("Project backups",
    "<p>Last fully successful run: " + esc(last) + ". " + esc(status.restoreTest || "") + "</p>" +
    '<div class="table-wrap"><table><thead><tr><th>Phase</th><th>State</th><th>Detail</th></tr></thead><tbody>' + phaseRows + "</tbody></table></div>" +
    "<h3>Backup policy</h3><p>This writes <code>backups.nix</code> into the revision editor below. Nothing changes until you review and publish it. Credentials stay in root-only files on the host.</p>" +
    '<label class="field"><span>Schedule</span><select id="backup-schedule">' +
    ["hourly", "daily", "weekly"].map(v => '<option value="' + v + '"' + (p.schedule === v ? " selected" : "") + ">" + v + "</option>").join("") + "</select></label>" +
    '<label><input type="checkbox" id="backup-data"' + (p.data ? " checked" : "") + "> Also export Incus instances and volumes</label>" +
    '<label class="field"><span>Verification</span><select id="backup-verification">' +
    ["none", "metadata", "full"].map(v => '<option value="' + v + '"' + (p.verification === v ? " selected" : "") + ">" + v + "</option>").join("") + "</select></label>" +
    '<label class="field"><span>Restic repository (for Google Drive: rclone:gdrive:nixus-backups)</span><input id="backup-repository" type="text" spellcheck="false" value="' + esc(p.repository) + '"></label>' +
    '<label class="field"><span>rclone config file (Google Drive)</span><input id="backup-rclone" type="text" spellcheck="false" placeholder="/var/lib/nixus-secrets/rclone.conf" value="' + esc(p.rcloneConfigFile) + '"></label>' +
    '<label><input type="checkbox" id="backup-initialize"' + (p.initialize ? " checked" : "") + "> Initialize a brand new restic repository</label>" +
    '<label class="field"><span>Private GitHub configuration mirror (optional)</span><input id="backup-github" type="text" spellcheck="false" placeholder="git@github.com:you/nixus-config.git" value="' + esc(p.github) + '"></label>' +
    '<button type="button" id="backup-policy-generate">Put policy in the revision editor</button>' +
    (projectConsole.policyError ? '<p class="error" role="alert">' + esc(projectConsole.policyError) + "</p>" : "") +
    '<p class="note">Before the first run, create the restic password at /var/lib/nixus-secrets/project-restic-password. For the GitHub mirror, run <code>sudo nixus-admin project-backup github-key</code> and add the printed public key as a deploy key. See <a href="/docs/recovery.md">Backups &amp; recovery</a>.</p>');
}

function projectConsoleCards() {
  return projectOverviewCard() + projectBackupCard();
}

async function refreshProjectConsole() {
  if (projectConsole.overviewLoading) return;
  projectConsole.overviewLoading = true;
  try {
    const [overview, backups] = await Promise.all([api("project-overview"), api("project-backups")]);
    projectConsole.overview = overview;
    projectConsole.backups = backups;
    projectConsole.overviewError = "";
  } catch (error) {
    projectConsole.overviewError = error.message || "Project overview is unavailable.";
  } finally {
    projectConsole.overviewLoading = false;
    if (state.page === "projects") shell();
  }
}

async function projectLoadFile(path) {
  projectConsole.fileError = "";
  try {
    const file = await api("project-file?path=" + encodeURIComponent(path));
    nativeProjectTx.path = file.path;
    nativeProjectTx.source = file.exists ? file.content : "";
    nativeProjectTx.error = file.exists ? "" : "This file does not exist yet; reviewing it will create it.";
  } catch (error) {
    nativeProjectTx.error = error.message || "Could not open the project file.";
  }
  if (state.page === "projects") {
    shell();
    document.querySelector("#native-nix-editor")?.scrollIntoView({ block: "center" });
  }
}

async function projectShowLog(target) {
  const [project, instance] = target.split("/");
  projectConsole.logError = "";
  try {
    projectConsole.log = await api("project-logs?project=" + encodeURIComponent(project) + "&instance=" + encodeURIComponent(instance));
  } catch (error) {
    projectConsole.log = null;
    projectConsole.logError = error.message || "The instance log is unavailable.";
  }
  if (state.page === "projects") shell();
}

function projectGeneratePolicy() {
  const p = projectConsole.policy;
  p.schedule = document.querySelector("#backup-schedule")?.value || "daily";
  p.data = document.querySelector("#backup-data")?.checked === true;
  p.verification = document.querySelector("#backup-verification")?.value || "metadata";
  p.repository = (document.querySelector("#backup-repository")?.value || "").trim();
  p.rcloneConfigFile = (document.querySelector("#backup-rclone")?.value || "").trim();
  p.initialize = document.querySelector("#backup-initialize")?.checked === true;
  p.github = (document.querySelector("#backup-github")?.value || "").trim();
  projectConsole.policyError = "";
  if (!/^(rclone:[A-Za-z0-9_-]+:[A-Za-z0-9._/-]+|sftp:[A-Za-z0-9._@:/-]+|s3:[A-Za-z0-9._:/-]+|b2:[A-Za-z0-9._:/-]+|rest:https:\/\/[A-Za-z0-9._:/-]+|\/[A-Za-z0-9._/-]+)$/.test(p.repository)) {
    projectConsole.policyError = "Enter a restic repository reference without credentials.";
  } else if (p.repository.startsWith("rclone:") && !/^\/(var\/lib|run|etc)\/[A-Za-z0-9._/-]+$/.test(p.rcloneConfigFile)) {
    projectConsole.policyError = "Google Drive (rclone) needs a root-only rclone config file path.";
  } else if (p.github && !/^git@github\.com:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/.test(p.github)) {
    projectConsole.policyError = "Use an SSH repository address such as git@github.com:you/nixus-config.git.";
  } else {
    nativeProjectTx.path = "backups.nix";
    nativeProjectTx.source = projectBackupPolicyText(p);
    nativeProjectTx.error = "";
  }
  if (state.page === "projects") {
    shell();
    document.querySelector(projectConsole.policyError ? "#backup-repository" : "#native-nix-editor")?.scrollIntoView({ block: "center" });
  }
}

function bindProjectConsole() {
  if (!projectConsole.overview && !projectConsole.overviewLoading && !projectConsole.overviewError) void refreshProjectConsole();
  document.querySelector("#project-overview-refresh")?.addEventListener("click", () => void refreshProjectConsole());
  for (const button of document.querySelectorAll("[data-project-expand]")) {
    button.addEventListener("click", () => {
      projectConsole.expanded = projectConsole.expanded === button.dataset.projectExpand ? "" : button.dataset.projectExpand;
      shell();
    });
  }
  for (const button of document.querySelectorAll("[data-project-edit]")) {
    button.addEventListener("click", () => void projectLoadFile(button.dataset.projectEdit));
  }
  for (const button of document.querySelectorAll("[data-project-log]")) {
    button.addEventListener("click", () => void projectShowLog(button.dataset.projectLog));
  }
  document.querySelector("#project-log-close")?.addEventListener("click", () => { projectConsole.log = null; shell(); });
  document.querySelector("#backup-policy-generate")?.addEventListener("click", projectGeneratePolicy);
  document.querySelector("#native-nix-load")?.addEventListener("click", () => {
    const path = document.querySelector("#native-nix-path")?.value?.trim() || "";
    void projectLoadFile(path);
  });
}

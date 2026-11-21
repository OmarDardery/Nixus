"use strict";

// Backups page: where backups go, what's backed up, snapshots and restore.

const backupView = {
  status: null, snapshots: null, restore: null, loading: false, kind: "rclone",
  error: "", message: "", password: "", restoreError: "",
};

const BACKUP_KINDS = [["rclone", "Google Drive / rclone"], ["s3", "S3"], ["b2", "Backblaze B2"], ["local", "Local disk"]];
const BACKUP_FIELDS = {
  local: [["path", "Folder", "/mnt/backup/nixus"]],
  s3: [["endpoint", "Endpoint", "s3.amazonaws.com"], ["bucket", "Bucket/path", "my-bucket/nixus"], ["accessKey", "Access key", ""], ["secretKey", "Secret key", "", "password"]],
  b2: [["bucket", "Bucket/path", "my-bucket:nixus"], ["accountId", "Key ID", ""], ["accountKey", "Application key", "", "password"]],
  rclone: [["remote", "Remote name", "gdrive"], ["folder", "Folder", "nixus-backups"], ["config", "rclone config (from `rclone config show`)", "", "textarea"]],
};
const BACKUP_PHASE_LABELS = [["config", "Config"], ["keys", "Secrets"], ["data", "Data"], ["offHost", "Upload"], ["verification", "Check"]];

async function refreshBackups() {
  if (backupView.loading) return;
  backupView.loading = true;
  try {
    const [status, restore] = await Promise.all([api("project-backups"), api("backups/restore-status")]);
    Object.assign(backupView, { status, restore });
    try { backupView.snapshots = await api("backups/snapshots"); } catch (error) { backupView.snapshots = { error: error.message }; }
  } catch (error) {
    backupView.error = error.message || "Backup status unavailable.";
  } finally {
    backupView.loading = false;
    if (state.page === "operations") shell();
  }
  const running = ["starting", "restoring"].includes(backupView.restore?.status);
  if (running) setTimeout(() => { if (state.page === "operations") void refreshBackups(); }, 4000);
}

function destinationFields(prefix) {
  return '<label class="field"><span>Destination</span><select id="' + prefix + '-kind">' +
    BACKUP_KINDS.map(([id, label]) => '<option value="' + id + '"' + (backupView.kind === id ? " selected" : "") + ">" + esc(label) + "</option>").join("") +
    "</select></label>" +
    BACKUP_FIELDS[backupView.kind].map(([id, label, placeholder, type]) => type === "textarea"
      ? '<label class="field"><span>' + esc(label) + '</span><textarea id="' + prefix + "-" + id + '" rows="5" spellcheck="false"></textarea></label>'
      : '<label class="field"><span>' + esc(label) + '</span><input id="' + prefix + "-" + id + '" type="' + (type || "text") +
        '" spellcheck="false" autocomplete="off" placeholder="' + esc(placeholder) + '"></label>').join("");
}

function readDestination(prefix) {
  const body = { kind: backupView.kind };
  for (const [id] of BACKUP_FIELDS[backupView.kind]) body[id] = document.querySelector("#" + prefix + "-" + id)?.value || "";
  return body;
}

function backupStatusCard() {
  const status = backupView.status || {};
  const phases = status.phases || {};
  const last = status.lastSuccess ? new Date(status.lastSuccess * 1000).toLocaleString() : "never";
  return card("Status",
    "<p>Last success: " + esc(last) + "</p><p>" +
    BACKUP_PHASE_LABELS.map(([id, label]) => esc(label) + " " + badge(phases[id]?.state || "—")).join(" · ") + "</p>" +
    '<button type="button" id="backups-run">Back up now</button>');
}

function backupDestinationCard() {
  const configured = backupView.snapshots?.configured;
  return card(configured ? "Destination" : "Set up backups",
    (configured ? "<p><code>" + esc(backupView.snapshots.repository) + "</code></p>" : "") +
    destinationFields("dest") +
    '<label class="field"><span>Schedule</span><select id="dest-schedule"><option>daily</option><option>hourly</option><option>weekly</option></select></label>' +
    '<label class="field"><span>Verify</span><select id="dest-verification"><option>metadata</option><option>full</option><option>none</option></select></label>' +
    '<label class="field"><span>Password</span><input id="dest-password" type="password" autocomplete="current-password"></label>' +
    '<button type="button" id="backups-save">Save</button>' +
    (backupView.password ? '<p role="status"><b>Repository password — save it in your password manager now; it is shown once:</b> <code>' +
      esc(backupView.password) + "</code></p>" : "") +
    (backupView.error ? '<p class="error" role="alert">' + esc(backupView.error) + "</p>" : "") +
    (backupView.message ? '<p role="status">' + esc(backupView.message) + "</p>" : ""), "", { open: configured ? undefined : true });
}

function snapshotsCard() {
  const s = backupView.snapshots;
  if (!s?.configured) return "";
  if (s.error) return card("Snapshots", '<p class="error">' + esc(s.error) + "</p>");
  const rows = (s.snapshots || []).slice().reverse().map(x =>
    "<tr><td><code>" + esc(x.id) + "</code></td><td>" + esc(new Date(x.time).toLocaleString()) + "</td></tr>").join("");
  return card("Snapshots", rows ? '<div class="table-wrap"><table><thead><tr><th>ID</th><th>Time</th></tr></thead><tbody>' + rows +
    "</tbody></table></div>" : "<p>No snapshots yet.</p>");
}

function restoreCard() {
  const r = backupView.restore || {};
  const status = r.status ? "<p>" + badge(r.status) + (r.error ? " " + esc(r.error) : "") +
    (r.failedStage ? " (" + esc(r.failedStage) + ")" : "") + "</p>" : "";
  const known = [typeof quick === "object" ? quick.apps : null, typeof appView === "object" ? appView.overview : null];
  const hasApps = known.some(view => (view?.projects || []).length > 0);
  if (hasApps && r.status !== "restoring") return "";
  return card("Restore this server from a backup",
    status + destinationFields("restore") +
    '<label class="field"><span>Repository password</span><input id="restore-repo-password" type="password" autocomplete="off"></label>' +
    '<label class="field"><span>Snapshot ID (empty = latest)</span><input id="restore-snapshot" type="text" spellcheck="false"></label>' +
    '<label class="field"><span>Your password</span><input id="restore-password" type="password" autocomplete="current-password"></label>' +
    '<button type="button" id="backups-restore">Restore</button>' +
    (backupView.restoreError ? '<p class="error" role="alert">' + esc(backupView.restoreError) + "</p>" : ""));
}

function backupsCards() {
  if (!backupView.status && !backupView.loading) void refreshBackups();
  return backupStatusCard() + restoreCard() + backupDestinationCard() + snapshotsCard() +
    (typeof nativeSecretsPanel === "function" ? nativeSecretsPanel() : "");
}

function takeValue(id) {
  const input = document.querySelector(id);
  const value = input?.value || "";
  if (input) input.value = "";
  return value;
}

async function saveBackups() {
  backupView.error = backupView.message = backupView.password = "";
  try {
    const current = takeValue("#dest-password");
    if (!current) throw Error("Enter your password.");
    const body = Object.assign(readDestination("dest"), {
      schedule: document.querySelector("#dest-schedule")?.value, verification: document.querySelector("#dest-verification")?.value,
      data: true, current,
    });
    const result = await api("apps/backup-setup", body);
    backupView.password = result.password || "";
    backupView.message = "Saved. Backups go to " + result.repository + ".";
  } catch (error) {
    backupView.error = error.message || "Could not save.";
  }
  void refreshBackups();
}

async function startRestore() {
  backupView.restoreError = "";
  try {
    const password = takeValue("#restore-repo-password");
    const current = takeValue("#restore-password");
    if (!password || !current) throw Error("Enter both passwords.");
    await api("backups/restore", Object.assign(readDestination("restore"),
      { password, snapshot: document.querySelector("#restore-snapshot")?.value || "", current }));
  } catch (error) {
    backupView.restoreError = error.message || "Restore failed to start.";
  }
  void refreshBackups();
}

function bindBackups() {
  if (state.page !== "operations") return;
  if (typeof bindNativeSecrets === "function") bindNativeSecrets();
  for (const prefix of ["dest", "restore"]) {
    document.querySelector("#" + prefix + "-kind")?.addEventListener("change", event => { backupView.kind = event.target.value; shell(); });
  }
  document.querySelector("#backups-save")?.addEventListener("click", () => void saveBackups());
  document.querySelector("#backups-restore")?.addEventListener("click", () => void startRestore());
  document.querySelector("#backups-run")?.addEventListener("click", async () => {
    try { await api("apps/backup-run", {}); backupView.message = "Backup started."; }
    catch (error) { backupView.error = error.message; }
    void refreshBackups();
  });
}

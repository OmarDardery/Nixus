"use strict";

// Overview: the next setup step and one-click server/app updates and backups.

const quick = { loaded: false, loading: false, busy: "", phase: "", message: "", error: "", apps: null, updates: null, backups: null };

async function refreshQuick() {
  if (quick.loading || !administrator()) return;
  quick.loading = true;
  try {
    const [apps, updates, backups] = await Promise.all([api("project-overview"), api("image-updates"), api("project-backups")]);
    Object.assign(quick, { apps, updates, backups, loaded: true });
  } catch (error) {
    quick.error = error.message || "Status unavailable.";
  } finally {
    quick.loading = false;
    if (state.page === "overview") shell();
  }
}

function pendingAppUpdates() {
  return Object.values(quick.updates?.projects || {}).reduce((n, p) => n + (p.updates > 0 ? 1 : 0), 0);
}

// nextStep returns [label, page] for the most useful next action, or null.
function nextStep() {
  const progress = typeof setupView === "object" ? setupView.progress : null;
  if (progress && !progress.complete) {
    const item = progress.items.find(i => i.required && !i.done) || progress.items.find(i => !i.done);
    if (item) return [item.title, item.page];
  }
  if (!quick.loaded) return null;
  if (!(quick.apps?.projects || []).length) return ["Add your first app", "projects"];
  if (!quick.backups?.lastSuccess) return ["Set up backups", "operations"];
  return null;
}

function quickActions() {
  if (!administrator()) return "";
  if (!quick.loaded && !quick.loading) void refreshQuick();
  const step = nextStep();
  const release = state.status.release || {};
  const appUpdates = pendingAppUpdates();
  const lastBackup = quick.backups?.lastSuccess ? new Date(quick.backups.lastSuccess * 1000).toLocaleString() : "never";
  const busy = quick.busy ? " disabled" : "";
  const restore = step && step[0] === "Add your first app" ? ' <button type="button" data-go="operations">Restore from a backup →</button>' : "";
  return (step ? card("Next step", '<button type="button" class="primary" data-go="' + esc(step[1]) + '">' + esc(step[0]) + " →</button>" + restore) : "") +
    card("Quick actions",
      '<div class="quick-actions">' +
      '<div><button type="button" id="quick-update-nixus"' + busy + '>Update Nixus</button><small>' +
        esc(release.version || "") + " <code>" + esc((release.revision || "").slice(0, 12)) + "</code></small></div>" +
      '<div><button type="button" id="quick-update-apps"' + busy + (appUpdates ? "" : " disabled") + '>Update all apps</button><small>' +
        (appUpdates ? esc(appUpdates) + " with updates" : "Up to date") + "</small></div>" +
      '<div><button type="button" id="quick-backup"' + busy + '>Back up now</button><small>Last: ' + esc(lastBackup) + "</small></div>" +
      "</div>" +
      '<label class="field"><span>Password</span><input id="quick-password" type="password" autocomplete="current-password"></label>' +
      (quick.phase ? '<p role="status">' + esc(quick.phase) + "</p>" : "") +
      (quick.message ? '<p role="status">' + esc(quick.message) + "</p>" : "") +
      (quick.error ? '<p class="error" role="alert">' + esc(quick.error) + "</p>" : ""));
}

function quickPassword() {
  const input = document.querySelector("#quick-password");
  const value = input?.value || "";
  if (input) input.value = "";
  if (!value) throw Error("Enter your password.");
  return value;
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// waitForJob polls host status until test(job) holds, tolerating the portal
// restarting during activation.
async function waitForJob(test, minutes) {
  const deadline = Date.now() + minutes * 60000;
  while (Date.now() < deadline) {
    try {
      state.status = await api("status");
      const job = state.status.job;
      if (job && test(job)) return job;
    } catch (_) { /* portal restarting */ }
    await sleep(4000);
  }
  throw Error("Timed out; open Changes to continue.");
}

// updateNixus builds the latest main with a package refresh, activates it and
// confirms access from this browser. If this browser cannot reach the portal
// after activation, nothing confirms and the host rolls back on its own.
async function updateNixus(current) {
  if (stagedCount()) throw Error("Apply or discard staged changes first.");
  const active = state.status.job;
  if (state.status.pending || (active && ["queued", "building", "ready", "applying", "activating", "awaiting-confirmation", "rolling-back"].includes(active.status)))
    throw Error("Finish the current change in Changes first.");
  quick.phase = "Checking for a new version…"; shell();
  const main = await api("main-revision");
  if (!/^[a-f0-9]{40}$/.test(main.revision || "")) throw Error("Could not read the latest version.");
  const sameSource = main.revision === state.status.release?.revision;
  quick.phase = "Building " + main.revision.slice(0, 12) + "…"; shell();
  await api("review", { settings: state.status.settings, secrets: {}, updateInputs: true, modules: {},
    revision: sameSource ? null : main.revision, adminPassword: current, acknowledgePrivilegedModules: true });
  let job = await waitForJob(j => !["queued", "building"].includes(j.status), 90);
  if (job.status !== "ready") throw Error(job.error || "Build failed; see Changes.");
  if (!job.impactPlan || job.impactPlan.blocked) throw Error("This update needs a decision; open Changes.");
  if (!(job.changes || []).length && !(job.platformChanges || []).length && !Object.keys(job.inputChanges || {}).length) {
    await api("cancel", { id: job.id });
    quick.message = "Nixus is up to date.";
    return;
  }
  quick.phase = "Activating…"; shell();
  await api("apply", { id: job.id });
  job = await waitForJob(j => ["awaiting-confirmation", "confirmed", "failed", "rolled-back", "cancelled"].includes(j.status), 20);
  if (job.status === "awaiting-confirmation") {
    quick.phase = "Confirming access…"; shell();
    await api("confirm", { id: job.id });
    state.status = await api("status");
    job = state.status.job || job;
  }
  if (job.status !== "confirmed") throw Error(job.error || "Update did not complete (" + job.status + ").");
  quick.message = "Updated to " + main.revision.slice(0, 12) + "." + (job.rebootRequired ? " Reboot to use the new kernel." : "");
}

async function quickRun(name, run) {
  if (quick.busy) return;
  quick.error = quick.message = quick.phase = "";
  try {
    const current = name === "backup" ? "" : quickPassword();
    quick.busy = name;
    shell();
    await run(current);
  } catch (error) {
    quick.error = error.message || "Action failed.";
  } finally {
    quick.busy = quick.phase = "";
    quick.loaded = false;
    shell();
  }
}

function bindQuickActions() {
  const on = (id, handler) => document.querySelector(id)?.addEventListener("click", handler);
  on("#quick-update-nixus", () => void quickRun("nixus", updateNixus));
  on("#quick-update-apps", () => void quickRun("apps", async current => {
    const result = await api("image-updates/apply-all", { current });
    quick.message = "Updating " + result.apps + " app(s). Progress shows on the Apps page.";
  }));
  on("#quick-backup", () => void quickRun("backup", async () => {
    await api("apps/backup-run", {});
    quick.message = "Backup started.";
  }));
}

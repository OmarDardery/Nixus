"use strict";
let operationView = {
  loaded: false,
  network: null,
  networkError: "",
  jobs: [],
  archives: [],
  health: null,
  users: [],
  loading: false,
  error: "",
};
const administrator = () => (state.principal?.role || "admin") === "admin";

function healthSummary() {
  const h = operationView.health;
  if (!h)
    return "<p>Health information is unavailable. Refresh to try again.</p>";
  const units = (h.services || []).filter((u) => u.LoadState === "loaded");
  const services = units
    .map(
      (u) =>
        `<li><code>${esc(u.Id)}</code>: ${esc(u.ActiveState)}${u.Result && u.Result !== "success" ? " · " + esc(u.Result) : ""}</li>`,
    )
    .join("");
  const certificates = Object.entries(h.certificates || {})
    .map(
      ([name, c]) =>
        `<li>${esc(name)}: ${c.present ? (c.expiresWithin30Days ? "expires soon" : esc(c.expires || "present")) : "not present"}</li>`,
    )
    .join("");
  const clock = h.clock ? `<p>Host clock: <b>${esc(h.clock.state)}</b>${h.clock.evidenceWarning ? ` · ${esc(h.clock.guidance)}` : ""}</p>` : "";
  return `${clock}<p>Backup: <b>${esc(h.backup?.health || "unknown")}</b> · Guests awaiting restart: ${esc(h.guestsAwaitingRestart ?? "unknown")}</p>${h.rootStorage ? `<p>Root storage: ${esc(formatBytes(h.rootStorage.availableBytes))} available of ${esc(formatBytes(h.rootStorage.totalBytes))}</p>` : ""}<ul>${services}${certificates}</ul>`;
}

function operationsPage() {
  return title("", "Backups", "Apps, their data, their secrets and this server's settings, backed up off this server.") +
    (administrator() && typeof backupsCards === "function" ? backupsCards() : "");
}


// Changes shows what a candidate brings; Nixus itself is updated with
// Overview → Update Nixus. Staged Nix modules still need password approval.
function platformReview() {
  if (!administrator()) return "";
  const job = state.status.job;
  const files = job?.platformChanges || [];
  const approval = Object.keys(state.modules || {}).length
    ? card("Approve staged Nix modules", `<div class="fields"><label class="field"><span>Your password</span><input id="platform-password" type="password" autocomplete="current-password"></label></div><label class="toggle"><input id="platform-ack" type="checkbox">I approve building the staged Nix modules (they run as root).</label>`, "", { open: true })
    : "";
  if (!job?.platformRevision && !Object.keys(job?.inputChanges || {}).length) return approval;
  const changes = files.map(file => `<tr><td><code>${esc(file.path)}</code></td><td>${file.after === null ? "Removed" : file.before === null ? "Added" : "Changed"}</td></tr>`).join("");
  return approval + card("Nixus version in this candidate",
    (job.platformRevision ? `<p><a href="${projectRepository}/commit/${esc(job.platformRevision)}" target="_blank" rel="noopener noreferrer">${esc(job.platformRevision.slice(0, 12))}</a> · ${files.length} platform file(s)</p><div class="table-wrap"><table><thead><tr><th>Path</th><th>Change</th></tr></thead><tbody>${changes || '<tr><td colspan="2">No platform file changes.</td></tr>'}</tbody></table></div>` : "") +
    (Object.keys(job.inputChanges || {}).length ? `<details><summary>Changed pinned inputs</summary><pre class="log">${esc(JSON.stringify(job.inputChanges, null, 2))}</pre></details>` : "") +
    (job.rebootRequired ? '<p class="note">The new kernel needs a reboot after confirming activation.</p>' : ""), job.platformRevision ? job.platformRevision.slice(0, 12) : "inputs");
}

async function refreshOperations(full = true) {
  if (operationView.loading) return;
  operationView.loading = true;
  let changed = false;
  try {
    const operations = await api("operations");
    changed = JSON.stringify(operations.jobs) !== JSON.stringify(operationView.jobs);
    Object.assign(operationView, operations);
    if (full || changed) {
      operationView.health = await api("health");
    }
    operationView.error = "";
    operationView.loaded = true;
  } catch (error) {
    operationView.error = error.message;
    operationView.loaded = true;
    changed = true;
  } finally {
    operationView.loading = false;
    if (
      state.page === "operations" &&
      (full || changed) &&
      !document.activeElement?.matches("input,textarea,select")
    )
      shell();
  }
}

async function submitOperation(request) {
  await api("operation", request);
  await refreshOperations();
}
function bindOperations() {
  const safe = (fn) => async (event) => {
    const el = event.currentTarget;
    el.disabled = true;
    try {
      await fn(el);
    } catch (error) {
      toast(error.message, "error");
    } finally {
      if (el.isConnected) el.disabled = false;
    }
  };
  document
    .querySelectorAll("[data-ops-refresh]")
    .forEach((el) => (el.onclick = safe(() => refreshOperations())));
  const by = (id) => document.getElementById(id);
  document
    .querySelectorAll("[data-download-diagnostics]")
    .forEach(
      (el) =>
        (el.onclick = () =>
          download(
            "nixus-diagnostics.json",
            JSON.stringify(operationView.health, null, 2),
            "application/json",
          )),
    );
  document.querySelectorAll("[data-overview-refresh]").forEach(el => {
    el.onclick = safe(async () => { await refreshOverview(); shell(); });
  });
  if (
    state.page === "operations" &&
    !operationView.loaded &&
    !operationView.loading
  )
    refreshOperations();
  if (!administrator()) {
    document
      .querySelectorAll(
        "[data-path],[data-secret],[data-mount],[data-remove-mount],[data-ingress]",
      )
      .forEach((el) => (el.disabled = true));
    document.querySelectorAll("[data-action]").forEach((el) => {
      if (
        !["logout", "copy-ssh", "export-settings"].includes(el.dataset.action)
      )
        el.disabled = true;
    });
  }
}

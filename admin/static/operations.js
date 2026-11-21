"use strict";
let operationView = {
  loaded: false,
  network: null,
  networkError: "",
  jobs: [],
  archives: [],
  health: null,
  users: [],
  generations: [],
  backupStatus: {},
  backupService: {},
  backupVerification: {},
  releases: [],
  loading: false,
  error: "",
};
const administrator = () => (state.principal?.role || "admin") === "admin";

function repositoryVerification() {
  const verification = operationView.backupVerification || {};
  const mode = verification.lastMode || verification.mode;
  const scope = mode === "full" ? "full repository data read" : mode === "metadata" ? "metadata only; data blocks were not read" : "scope unknown";
  return `<p>Repository verification: <b>${esc(verification.state || "unknown")}</b> · ${esc(scope)}</p>${verification.reason === "repository-unverified" ? "<p>The repository target has no matching verification evidence. Run a new check.</p>" : ""}${verification.finishedAt ? `<p>Last check: ${esc(new Date(verification.finishedAt * 1000).toLocaleString())}</p>` : ""}${verification.scheduled ? `<p>Schedule: ${esc(verification.schedule)} · next checks use ${verification.mode === "full" ? "full data reads" : "metadata checks"}</p>` : ""}${verification.timeWarning ? '<p class="error">Verification timestamps are unreliable; check host time synchronization.</p>' : ""}`;
}

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

function backupCoverage(status) {
  const coverage = status.coverage, capacity = status.capacity;
  const gaps = (coverage?.items || []).filter(item => item.status !== "included");
  return `<p>Coverage: <b>${coverage ? (coverage.complete ? "Inventoried exports included" : "Incomplete") : "Not assessed"}</b></p>${gaps.length ? `<ul class="error">${gaps.map(item => `<li>${esc(item.identity)}: ${esc(item.status)}</li>`).join("")}</ul>` : ""}${capacity ? `<p>Estimated new staging: ${esc(formatBytes(capacity.estimatedNewBytes))} plus ${esc(formatBytes(capacity.reserveBytes))} reserve; ${esc(formatBytes(capacity.availableBytes))} available.</p>${capacity.unknown?.length ? `<p class="error">Current size unknown for ${esc(capacity.unknown.length)} archive(s). Estimates may be incomplete.</p>` : ""}` : ""}`;
}

function operationsPage() {
  const busy = operationView.jobs.some((j) =>
    ["queued", "running"].includes(j.status),
  );
  const status = operationView.backupStatus || {};
  const backupRunning = ["active", "activating", "deactivating"].includes(
    operationView.backupService?.ActiveState,
  );
  const localComplete = ["complete", "complete-with-exclusions"].includes(
    status.phase,
  );
  const failedUpload =
    localComplete &&
    !backupRunning &&
    operationView.backupService?.Result &&
    operationView.backupService.Result !== "success";
  const phase =
    backupRunning && localComplete
      ? "Local export complete; off-host transfer/retention running"
      : failedUpload
        ? "Local export complete; off-host backup failed"
        : status.phase || "No backup recorded";
  return (
    title("", "Backups", "Apps, their data and their secrets, backed up off this server.") +
    (administrator() && typeof backupsCards === "function" ? backupsCards() : "") +
    // Whole-host export tooling is advanced; fold it into one panel.
    '<details class="card panel advanced-block" data-panel="operations:advanced"' + (panelState["operations:advanced"] ? " open" : "") +
      '><summary class="card-header"><h2>Advanced · full-server export</h2><span class="caption">' + esc(phase) + '</span></summary><div class="panel-body">' +
    card(
      "Backup status",
      `<p>Current phase: <b>${esc(phase)}</b> ${status.group ? `· group ${esc(status.group)} of ${esc(status.groups)}` : ""}</p><p>${esc((status.members || []).join(", "))}</p>${status.excluded?.length ? `<p class="error">Excluded from coverage: ${esc(status.excluded.join(", "))}</p>` : ""}<p>Last full-host success: ${operationView.health?.lastBackupSuccess ? esc(new Date(operationView.health.lastBackupSuccess * 1000).toLocaleString()) : "Not recorded"}</p><p>Guests awaiting restart recovery: ${esc(operationView.health?.guestsAwaitingRestart ?? "Unknown")}</p>${operationView.error ? `<p class="error">${esc(operationView.error)}</p>` : ""}${repositoryVerification()}<button data-ops-refresh>Refresh</button> <button data-run-backup ${!administrator() || busy || !state.status.settings.backup.enable ? "disabled" : ""}>Run scheduled backup</button> <button data-check-backup ${!administrator() || busy || !state.status.settings.backup.enable ? "disabled" : ""}>Check restic repository</button> <button data-cancel-backup ${!administrator() || !backupRunning ? "disabled" : ""}>Cancel scheduled backup</button>`,
    ) +
    backupCoverage(status) +
    backupSettings() +
    card(
      "Complete local generations",
      `<div class="table-wrap"><table><thead><tr><th>Created</th><th>Coverage</th><th>Archives</th></tr></thead><tbody>${operationView.generations.map((g) => `<tr><td>${esc(new Date(g.created * 1000).toLocaleString())}<br><code>${esc(g.id)}</code></td><td>${esc(g.coverage)} · ${esc(g.guests)} guest(s)${g.excluded.length ? `<br>Excluded: ${esc(g.excluded.join(", "))}` : ""}</td><td>${esc(g.archives)}</td></tr>`).join("") || '<tr><td colspan="3">No complete generations recorded.</td></tr>'}</tbody></table></div>`,
    ) +
    card(
      "Restore an independent export",
      `<div class="fields"><label class="field"><span>Available archive</span><select id="restore-archive"><option value="">Select an export</option>${operationView.archives.map((a) => `<option value="${esc(a.id)}" ${a.available === false ? "disabled" : ""}>${esc(a.project)}/${esc(a.name)} · ${esc(new Date(a.created * 1000).toLocaleString())}${a.available === false ? " (unavailable)" : ""}</option>`).join("")}</select></label><label class="field"><span>New stopped instance name</span><input id="restore-target" placeholder="restore-test"></label></div><button data-restore-export ${!administrator() || busy ? "disabled" : ""}>Restore stopped copy</button><a href="/docs/backups.md">Full off-host recovery procedure</a>`,
    ) +
    card(
      "Nixus task history",
      `<div class="table-wrap"><table><thead><tr><th>Action</th><th>Target</th><th>Status</th><th>Result</th></tr></thead><tbody>${operationView.jobs
        .filter((j) => ["backup", "backup-check", "restore"].includes(j.action))
        .map(
          (j) =>
            `<tr><td>${esc(j.action)}</td><td>${esc(j.project)}/${esc(j.name)}</td><td>${esc(j.status)}</td><td>${esc(j.error || j.restoredInstance || "")}</td></tr>`,
        )
        .join("")}</tbody></table></div>`,
    ) +
    card(
      "Host service and certificate health",
      healthSummary() +
        `<details><summary>Diagnostic details</summary><pre class="log">${esc(JSON.stringify(operationView.health, null, 2))}</pre></details><button data-download-diagnostics>Download diagnostics</button>`,
    ) +
    (administrator()
      ? card(
          "Portable recovery kit",
          `<div class="fields"><label class="field full"><span>age public recipient (optional)</span><input id="recovery-recipient" placeholder="age1…"></label><label class="field"><span>Your password</span><input id="recovery-password" type="password" autocomplete="current-password"></label></div><button data-download-recovery>Download recovery kit</button>`,
        )
      : "") + "</div></details>"
  );
}


function platformSelectionText() {
  if (!state.platformRevision) return "No platform update selected.";
  if (!platformUpdateSelected()) return "Selected installed revision: rebuild only; no platform update.";
  return "Proposed: " + state.platformRevision + ". File changes will be calculated by a new review.";
}
function platformReview() {
  if (!administrator()) return "";
  const job = state.status.job;
  const files = job?.platformChanges || [];
  const historical = job?.status === "confirmed";
  const changes = files.map(file => `<tr><td><code>${esc(file.path)}</code></td><td>${file.after === null ? "Removed" : file.before === null ? "Added" : "Changed"}</td></tr>`).join("");
  return card("Platform update", `<p>Installed: ${esc(state.status.release?.version || "unknown")} · <code>${esc((state.status.release?.revision || "unknown").slice(0, 12))}</code></p>
    <button type="button" data-load-main>Review latest main</button><p class="note" id="platform-selected">${esc(platformSelectionText())}</p>
    <details><summary>Advanced: published release or commit</summary><button type="button" data-load-releases>Find published releases</button><label class="field full"><span>Release</span><select id="platform-release"><option value="">Select a release</option>${operationView.releases.map(r => `<option value="${esc(r.revision)}">${esc(r.name)} · ${esc(r.tag)}</option>`).join("")}</select></label><label class="field full"><span>Upstream commit SHA (optional)</span><input id="platform-revision" value="${esc(state.platformRevision || "")}" maxlength="40" placeholder="40 hexadecimal characters"></label></details>
    <div class="fields"><label class="field"><span>Current portal password for privileged code</span><input id="platform-password" type="password" autocomplete="current-password"></label></div><label class="toggle"><input id="platform-ack" type="checkbox">I approve building the selected privileged platform revision and staged Nix modules.</label>
    ${job?.platformRevision ? `<p>${historical ? "Historical confirmed review" : "Existing job (not a preview of the selection above)"}: <a href="${projectRepository}/commit/${esc(job.platformRevision)}" target="_blank" rel="noopener noreferrer">${esc(job.platformRevision.slice(0, 12))}</a></p><details><summary>${historical ? "Historical platform files" : "Existing job platform files"} (${files.length})</summary><div class="table-wrap"><table><thead><tr><th>Path</th><th>Change</th></tr></thead><tbody>${changes || '<tr><td colspan="2">No platform file changes.</td></tr>'}</tbody></table></div></details>` : ""}
    ${job?.inputChanges && Object.keys(job.inputChanges).length ? `<details><summary>Changed pinned inputs</summary><pre class="log">${esc(JSON.stringify(job.inputChanges, null, 2))}</pre></details>` : ""}
    ${job?.rebootRequired ? '<p class="note">The new kernel needs a separate reboot after confirming activation.</p>' : ""}`);
}

async function refreshOperations(full = true) {
  if (operationView.loading) return;
  operationView.loading = true;
  let changed = false;
  try {
    const operations = await api("operations");
    changed =
      JSON.stringify([
        operations.jobs,
        operations.generations,
        operations.backupStatus,
        operations.backupService,
        operations.backupVerification,
      ]) !==
      JSON.stringify([
        operationView.jobs,
        operationView.generations,
        operationView.backupStatus,
        operationView.backupService,
        operationView.backupVerification,
      ]);
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
  const restore = by("restore-archive");
  if (restore)
    document.querySelector("[data-restore-export]").onclick = safe(async () => {
      const archive = operationView.archives.find(
        (a) => a.id === restore.value,
      );
      if (!archive) throw Error("Select an export.");
      if (window.confirm("Restore to a new stopped instance?"))
        await submitOperation({
          action: "restore",
          project: archive.project,
          name: archive.name,
          archive: archive.id,
          target: by("restore-target").value.trim(),
          acknowledge: true,
        });
    });
  for (const [selector, action] of [
    ["[data-run-backup]", "backup"],
    ["[data-check-backup]", "backup-check"],
  ])
    document.querySelectorAll(selector).forEach(
      (el) =>
        (el.onclick = safe(async () => {
          if (
            window.confirm(
              action === "backup"
                ? "Back up the configured scope? Selected guest groups stop briefly."
                : "Check the independent repository?",
            )
          )
            await submitOperation({
              action,
              project: "lab",
              name: "all",
              acknowledge: true,
            });
        })),
    );
  document.querySelectorAll("[data-cancel-backup]").forEach(
    (el) =>
      (el.onclick = safe(async () => {
        if (
          window.confirm(
            "Cancel the scheduled backup and recover stopped guests?",
          )
        ) {
          await api("cancel-backup", {});
          await refreshOperations();
        }
      })),
  );
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
  document.querySelectorAll("[data-download-recovery]").forEach(
    (el) =>
      (el.onclick = safe(async () => {
        const result = await api("recovery-export", {
          recipient: by("recovery-recipient").value.trim() || null,
          current: by("recovery-password").value,
        });
        for (const [name, data] of Object.entries(result.files))
          download(
            name,
            Uint8Array.from(atob(data), (c) => c.charCodeAt(0)),
            "application/octet-stream",
          );
        by("recovery-password").value = "";
      })),
  );
  document.querySelectorAll("[data-load-main]").forEach(el => {
    el.onclick = safe(async () => {
      const result = await api("main-revision");
      if (!/^[a-f0-9]{40}$/.test(result.revision)) throw Error("Invalid upstream revision");
      state.platformRevision = result.revision;
      shell();
    });
  });
  document.querySelectorAll("[data-overview-refresh]").forEach(el => {
    el.onclick = safe(async () => { await refreshOverview(); shell(); });
  });
  document.querySelectorAll("[data-load-releases]").forEach(
    (el) =>
      (el.onclick = safe(async () => {
        operationView.releases = (await api("releases")).releases;
        const select = by("platform-release");
        select.innerHTML =
          '<option value="">Select a release</option>' +
          operationView.releases
            .map(
              (r) =>
                `<option value="${esc(r.revision)}">${esc(r.name)} · ${esc(r.tag)} · ${esc(r.revision.slice(0, 12))}</option>`,
            )
            .join("");
        if (!operationView.releases.length)
          toast("No published releases are available yet.");
      })),
  );
  const release = by("platform-release");
  if (release)
    release.onchange = () => {
      state.platformRevision = release.value;
      by("platform-password").value = "";
      by("platform-ack").checked = false;
      const revision = by("platform-revision");
      if (revision) revision.value = release.value;
      shell();
    };
  const revision = by("platform-revision");
  if (revision)
    revision.oninput = () => {
      state.platformRevision = revision.value.trim();
      by("platform-password").value = "";
      by("platform-ack").checked = false;
      by("platform-selected").textContent = platformSelectionText();
    };
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

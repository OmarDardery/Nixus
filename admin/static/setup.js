"use strict";
// First-run walkthrough. Progress is computed by the host on every request,
// so nothing here is persisted in the browser and refresh or reboot resumes.
const setupView = { progress: null, error: "" };

async function refreshSetupProgress() {
  if (typeof administrator === "function" && !administrator()) { setupView.progress = null; return; }
  try {
    setupView.progress = await api("setup-progress");
    setupView.error = "";
  } catch (err) {
    setupView.error = "Setup progress is unavailable: " + err.message;
  }
}

function setupIncomplete() {
  return Boolean(setupView.progress && !setupView.progress.complete);
}

function setupBanner() {
  const progress = setupView.progress;
  if (!progress || progress.complete || state.page === "setup") return "";
  return `<div class="banner"><b>Setup ${esc(progress.completed)}/${esc(progress.total)}</b> Finish the remaining setup steps to complete your hypervisor. <button class="small" data-go="setup">Continue setup</button></div>`;
}

function setupStep(item, index, next) {
  const status = item.done ? "Done" : item.required ? "To do" : "Optional";
  const action = item.done ? "Review" : item.id === next?.id ? "Start" : "Open";
  return `<li class="setup-step${item.done ? " done" : ""}${item.id === next?.id ? " current" : ""}" data-step="${esc(item.id)}">
    <span class="setup-mark" aria-hidden="true">${item.done ? "✓" : esc(index + 1)}</span>
    <div class="setup-copy"><h3>${esc(item.title)}</h3><small>${esc(item.detail)}</small></div>
    <span class="setup-state">${esc(status)}</span>
    <button class="small${item.id === next?.id ? " primary" : ""}" data-go="${esc(item.page)}">${esc(action)}</button></li>`;
}

function setupPage() {
  const intro = title("", "Set up your hypervisor",
    "Work through these steps in any order. Progress is read from the host, so you can leave and come back at any time.");
  if (setupView.error) return intro + card("Setup", `<p class="error">${esc(setupView.error)}</p><button data-action="setup-refresh">Retry</button>`);
  const progress = setupView.progress;
  if (!progress) return intro + card("Setup", "<p>Loading setup progress…</p>");
  const next = progress.items.find(item => item.required && !item.done) || progress.items.find(item => !item.done);
  const percent = progress.total ? Math.round(100 * progress.completed / progress.total) : 100;
  const summary = progress.complete
    ? "<p><b>Setup complete.</b> Optional steps remain available below.</p>"
    : `<p>${esc(progress.completed)} of ${esc(progress.total)} required steps done.</p>`;
  return intro + card("Progress", `${summary}<div class="setup-meter" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}" aria-label="Required setup steps completed"><span style="width:${percent}%"></span></div>
    <ol class="setup-steps">${progress.items.map((item, index) => setupStep(item, index, next)).join("")}</ol>
    <button class="small" data-action="setup-refresh">Refresh progress</button>`);
}

function bindSetup() {
  document.querySelectorAll('[data-action="setup-refresh"]').forEach(button => button.addEventListener("click", async () => {
    await refreshSetupProgress();
    shell();
  }));
}

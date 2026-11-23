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

// setupPending returns the unfinished setup step with this id. It is null when
// the step is done or progress is not known, so nothing is locked on a guess.
function setupPending(stepId) {
  const item = setupView.progress?.items?.find(i => i.id === stepId);
  return item && !item.done ? item : null;
}

// gated wraps a control that needs a setup step. While the step is unfinished
// the control is disabled and a lock note links to the step.
function gated(stepId, reason, html) {
  const item = setupPending(stepId);
  if (!item) return html;
  return '<div class="locked" aria-disabled="true"><p class="lock-note"><svg class="lock-icon" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">' +
    '<path d="M4.5 7V5a3.5 3.5 0 0 1 7 0v2M3 7h10v7H3z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg> ' +
    '<b>Locked.</b> ' + esc(reason) + ' <button type="button" class="link" data-go="' + esc(item.page) + '">Open setup</button></p>' +
    '<fieldset disabled>' + html + "</fieldset></div>";
}

function setupBanner() {
  const progress = setupView.progress;
  if (!progress || progress.complete || state.page === "setup" || state.page === "overview") return ""; // Overview shows the next step itself
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
  const intro = title("", "Setup", "Finish these steps once after installing.");
  if (setupView.error) return intro + card("Setup", `<p class="error">${esc(setupView.error)}</p><button data-action="setup-refresh">Retry</button>`);
  const progress = setupView.progress;
  if (!progress) return intro + card("Setup", "<p>Loading setup progress…</p>");
  const next = progress.items.find(item => item.required && !item.done) || progress.items.find(item => !item.done);
  const percent = progress.total ? Math.round(100 * progress.completed / progress.total) : 100;
  const summary = progress.complete
    ? "<p><b>Setup complete.</b></p>"
    : `<p>${esc(progress.completed)} of ${esc(progress.total)} required steps done.</p>`;
  // Inline styles are blocked by the console's CSP, so use a native <progress>.
  const steps = progress.items.map((item, index) => [item, index]);
  const done = steps.filter(([item]) => item.done), open = steps.filter(([item]) => !item.done);
  return intro + card("Progress", `${summary}<progress class="setup-meter" max="100" value="${percent}" aria-label="Required setup steps completed">${percent}%</progress>
    <ol class="setup-steps">${open.map(([item, index]) => setupStep(item, index, next)).join("")}</ol>
    ${done.length ? `<details class="done-steps"><summary>${done.length} done</summary><ol class="setup-steps">${done.map(([item, index]) => setupStep(item, index, next)).join("")}</ol></details>` : ""}
    <button class="small" data-action="setup-refresh">Refresh progress</button>`, "", { open: true });
}

function bindSetup() {
  document.querySelectorAll('[data-action="setup-refresh"]').forEach(button => button.addEventListener("click", async () => {
    await refreshSetupProgress();
    shell();
  }));
}

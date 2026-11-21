"use strict";

// Backups → Apps repository: connect an apps repository, review remote changes
// and deploy them. Console changes are pushed automatically.

const repoView = { data: null, loading: false, fingerprints: null, error: "", message: "", url: "", branch: "main" };

async function refreshRepo() {
  if (repoView.loading) return;
  repoView.loading = true;
  try { repoView.data = await api("apps-repo"); }
  catch (error) { repoView.error = error.message || "Repository status unavailable."; }
  finally {
    repoView.loading = false;
    if (state.page === "operations") shell();
  }
  const job = repoView.data?.status?.deploy;
  if (job && !["deployed", "failed"].includes(job.status)) setTimeout(() => { if (state.page === "operations") void refreshRepo(); }, 4000);
}

function repoNotice() {
  return (repoView.error ? '<p class="error" role="alert">' + esc(repoView.error) + "</p>" : "") +
    (repoView.message ? '<p role="status">' + esc(repoView.message) + "</p>" : "");
}

function repoTime(seconds) { return seconds ? new Date(seconds * 1000).toLocaleString() : "never"; }

function repoConnectCard(d) {
  const key = d.publicKey
    ? '<label class="field"><span>Deploy key — add it to the repository with write access</span><textarea readonly rows="2" id="repo-pubkey">' + esc(d.publicKey) +
      '</textarea></label><button type="button" class="link" data-copy="' + esc(d.publicKey) + '">Copy</button>'
    : '<button type="button" id="repo-key">Create deploy key</button>';
  const fps = repoView.fingerprints;
  return card("Apps repository",
    '<label class="field"><span>SSH URL</span><input id="repo-url" type="text" spellcheck="false" autocomplete="off" placeholder="git@github.com:you/apps.git" value="' + esc(repoView.url) + '"></label>' +
    '<label class="field"><span>Branch</span><input id="repo-branch" type="text" spellcheck="false" value="' + esc(repoView.branch) + '"></label>' +
    key +
    (d.publicKey ? '<div class="toolbar"><button type="button" id="repo-scan">Check host key</button></div>' : "") +
    (fps ? '<p>Host key fingerprints — compare with your git host:</p><pre>' + esc(fps.join("\n")) + "</pre>" +
      '<label class="check"><input id="repo-trust" type="checkbox"> The fingerprint matches</label>' +
      '<div class="toolbar"><input id="repo-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
      '<button type="button" class="primary" id="repo-connect">Connect</button></div>' : "") +
    repoNotice());
}

function repoPendingCard(d) {
  const p = d.status?.pending;
  if (!p) return "";
  const apps = (p.apps || []).map(a => "<li><code>" + esc(a) + "</code></li>").join("");
  const removed = (p.removed || []).length ? "<p>Removed in the repository (not applied; delete them here first): " +
    p.removed.map(a => "<code>" + esc(a) + "</code>").join(", ") + "</p>" : "";
  return card("Apps repository · remote changes",
    "<ul>" + (p.commits || []).map(c => "<li><code>" + esc(c) + "</code></li>").join("") + "</ul>" +
    (apps ? "<p>Apps to deploy:</p><ul>" + apps + "</ul>" : "<p>No app changes.</p>") + removed +
    '<div class="toolbar"><input id="repo-deploy-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
    '<button type="button" class="primary" id="repo-deploy" data-head="' + esc(p.head) + '">Deploy</button></div>', (p.commits || []).length + " commit(s)", { open: true });
}

function repoStatusCard(d) {
  const s = d.status || {};
  const job = s.deploy;
  return card("Apps repository",
    "<p><code>" + esc(d.url) + "</code> · " + esc(d.branch) + "</p>" +
    "<p>Checked " + esc(repoTime(s.checkedAt)) + " · Pushed " + esc(repoTime(s.pushedAt)) + "</p>" +
    (s.error ? '<p class="error">' + esc(s.error) + "</p>" : "") +
    (s.pushError ? '<p class="error">Push failed: ' + esc(s.pushError) + "</p>" : "") +
    (job ? "<p>Deploy " + badge(job.status) + (job.app ? " " + esc(job.app) : "") + (job.error ? " " + esc(job.error) : "") + "</p>" : "") +
    '<div class="toolbar"><button type="button" id="repo-check">Check now</button>' +
    '<details><summary>Disconnect</summary><input id="repo-disconnect-password" type="password" autocomplete="current-password" placeholder="Your password" aria-label="Password">' +
    '<button type="button" class="danger" id="repo-disconnect">Disconnect</button></details></div>' + repoNotice());
}

// Shown on the Backups page: the apps repository is the readable,
// off-server copy of your apps; restic holds data and keys.
function repositoryCards() {
  if (!repoView.data && !repoView.loading && !repoView.error) void refreshRepo();
  const d = repoView.data;
  if (!d) return card("Apps repository", "<p>Loading…</p>" + repoNotice());
  return d.configured ? repoPendingCard(d) + repoStatusCard(d) : repoConnectCard(d);
}

async function repoAction(path, body, message) {
  repoView.error = repoView.message = "";
  try {
    const result = await api(path, body);
    repoView.message = message || "";
    return result;
  } catch (error) {
    repoView.error = error.message || "Request failed.";
    return null;
  } finally {
    void refreshRepo();
  }
}

function bindRepository() {
  if (state.page !== "operations") return;
  const on = (id, fn) => document.querySelector(id)?.addEventListener("click", fn);
  const keep = () => {
    repoView.url = document.querySelector("#repo-url")?.value.trim() || repoView.url;
    repoView.branch = document.querySelector("#repo-branch")?.value.trim() || repoView.branch;
  };
  for (const el of document.querySelectorAll("[data-copy]")) el.addEventListener("click", () => { void navigator.clipboard?.writeText(el.dataset.copy); el.textContent = "Copied"; });
  on("#repo-key", () => { keep(); void repoAction("apps-repo/key", {}); });
  on("#repo-scan", async () => {
    keep();
    const r = await repoAction("apps-repo/scan", { url: repoView.url });
    repoView.fingerprints = r ? r.fingerprints : null;
  });
  on("#repo-connect", () => {
    keep();
    if (!document.querySelector("#repo-trust")?.checked) { repoView.error = "Confirm the fingerprint first."; shell(); return; }
    const current = takeValue("#repo-password");
    repoView.fingerprints = null;
    void repoAction("apps-repo/connect", { url: repoView.url, branch: repoView.branch, current }, "Connected.");
  });
  on("#repo-check", () => void repoAction("apps-repo/check", {}, "Checked."));
  on("#repo-deploy", event => void repoAction("apps-repo/deploy", { head: event.target.dataset.head, current: takeValue("#repo-deploy-password") }, "Deploying…"));
  on("#repo-disconnect", () => void repoAction("apps-repo/disconnect", { current: takeValue("#repo-disconnect-password") }, "Disconnected."));
}

"use strict";

// Metadata-only project secrets UI. Secret values live solely in password
// inputs until a reauthenticated POST, never in browser-visible JS state.
const nativeSecretsView = {
  loaded: false, loading: false, busy: false, data: null, selected: "",
  error: "", message: "", review: null, editKey: "",
  choice: "create", haveVia: "key", kit: "export",
};

// A row of buttons that picks which single form is shown below it.
function nativeChoice(name, current, options) {
  return '<nav class="tabs" role="group">' + options.map(([id, label]) =>
    '<button type="button" class="' + (current === id ? "active" : "") + '" data-native-' + name + '="' + id + '"' +
    (current === id ? ' aria-pressed="true"' : ' aria-pressed="false"') + ">" + label + "</button>").join("") + "</nav>";
}

function nativeSecretProject() {
  const projects = nativeSecretsView.data?.projects || [];
  return projects.find(item => item.project === nativeSecretsView.selected) || projects[0] || null;
}

function nativeSecretsPanel() {
  const v = nativeSecretsView;
  if (state.principal?.role !== "admin")
    return card("Project secrets", "<p>Only administrators can manage encrypted project secrets.</p>");
  if (!v.loaded)
    return card("Project secrets", "<p>Loading metadata-only SOPS secret inventory…</p>");
  const identity = v.data?.identity || {};
  const status = identity.configured && identity.healthy
    ? '<p>Your encryption key is ready.</p><details><summary>Details</summary><p>Public recipient (age): <code>' +
      esc(identity.recipient) + '</code></p></details>'
    : identity.configured
      ? '<p role="alert" class="error">The installed encryption key is unhealthy. Never create a new one over it; restore the original safely.</p>'
      : '<p>No encryption key yet. You need one to keep environment variables and other app secrets.</p>';
  const password = (id, label) => '<label class="field"><span>' + label + '</span><input type="password" id="' + id +
    '" autocomplete="current-password"></label>';
  const keyForm = mode => '<p>' + (mode === "restore"
      ? "Paste the key you saved earlier. It starts with AGE-SECRET-KEY-1."
      : "Nixus creates the key on this server. Afterwards, download a recovery kit and keep it off this server.") + '</p>' +
    (mode === "restore"
      ? '<label class="field"><span>Your key</span><textarea id="native-age-restore" rows="3" autocomplete="off" spellcheck="false" placeholder="AGE-SECRET-KEY-1…"></textarea></label>'
      : "") +
    password("native-age-password", "Your password") +
    '<label><input id="native-age-ack" type="checkbox"> I will back this key up separately; Nixus never replaces it silently</label>' +
    '<button type="button" id="native-age-enroll"' + (v.busy ? " disabled" : "") + ">" +
    (mode === "restore" ? "Use this key" : "Create key") + "</button>";
  const kitFile = '<label class="field"><span>Recovery kit file</span><input id="native-recovery-kit-file" type="file" accept=".json,application/json"></label>' +
    '<label class="field"><span>Recovery passphrase</span><input id="native-recovery-import-passphrase" type="password" autocomplete="off"></label>' +
    password("native-recovery-import-admin", "Your password");
  const kitRestore = kitFile +
    '<label><input type="checkbox" id="native-recovery-import-ack"> I understand this restores this server\'s protected key and credentials</label>' +
    '<button type="button" id="native-recovery-restore"' + (v.busy || identity.configured ? " disabled" : "") + ">Restore from recovery kit</button>";
  const setup = !identity.configured
    ? '<fieldset><legend>Set up the encryption key</legend>' +
      nativeChoice("choice", v.choice, [["create", "Create a key"], ["have", "I already have a key"]]) +
      (v.choice === "have"
        ? nativeChoice("have", v.haveVia, [["key", "Paste my key"], ["kit", "Use a recovery kit"]]) +
          (v.haveVia === "kit" ? kitRestore : keyForm("restore"))
        : keyForm("generate")) + '</fieldset>'
    : "";
  const project = nativeSecretProject();
  const recipientsPanel = identity.healthy && project && project.revision && !v.review
    ? '<fieldset><legend>Rotate SOPS/age recipients</legend>' +
      '<p>Current public recipients: <code>' +
      esc((project.recipients || [identity.recipient]).join(", ")) + '</code></p>' +
      '<label class="field"><span>Complete recipient list, one age1 public key per line</span>' +
      '<textarea id="native-recipient-list" rows="3" spellcheck="false" autocomplete="off">' +
      esc((project.recipients || [identity.recipient]).join("\n")) + '</textarea></label>' +
      '' +
      '<label class="field"><span>Administrator password</span><input type="password" id="native-recipient-password" autocomplete="current-password"></label>' +
      '<button type="button" id="native-recipient-review"' + (v.busy || !project.indexed ? ' disabled' : '') +
      '>Review recipient rekey</button></fieldset>'
    : "";
  const review = v.review
    ? '<fieldset><legend>Approve ciphertext-only publication</legend>' +
      '<p>Project: <code>' + esc(v.review.project) + '</code> · ' +
      esc(v.review.action) + ' <code>' + esc(v.review.action === "recipients" ? (v.review.recipients || []).join(", ") :
         (v.review.changedKeys || [v.review.key]).join(", ")) + '</code></p>' +
      '<p>From: <code>' + esc(v.review.baseRevision || "none") +
      '</code> → <code>' + esc(v.review.revision) + '</code></p>' +
      '<p>Publishing does not restart running apps.</p>' +
      '<label class="field"><span>Current administrator password</span>' +
      '<input id="native-secret-publish-password" type="password" autocomplete="current-password"></label>' +
      '<label><input type="checkbox" id="native-secret-publish-ack"> Publish this exact encrypted revision</label>' +
      '<button id="native-secret-publish" type="button"' + (v.busy ? " disabled" : "") +
      '>Publish encrypted secrets</button></fieldset>'
    : "";
  const exportForm = '<label class="field"><span>Recovery passphrase (16+ characters)</span><input id="native-recovery-export-passphrase" type="password" autocomplete="new-password"></label>' +
    '<label class="field"><span>Repeat passphrase</span><input id="native-recovery-export-confirm" type="password" autocomplete="new-password"></label>' +
    '<label><input type="checkbox" id="native-recovery-backup" checked> Include the backup repository credentials (recommended for restoring on new hardware)</label>' +
    password("native-recovery-export-admin", "Your password") +
    '<button type="button" id="native-recovery-export"' + (v.busy ? " disabled" : "") + '>Download encrypted recovery kit</button>';
  const verifyForm = '<p>Checks that a saved kit opens with its passphrase. Nothing on this server changes.</p>' + kitFile +
    '<button type="button" id="native-recovery-verify"' + (v.busy ? " disabled" : "") + ">Verify kit</button>";
  const recoveryPanel = identity.healthy
    ? '<fieldset><legend>Recovery kit</legend><p>Store the kit off this server. You need it to restore your secrets on new hardware.</p>' +
      nativeChoice("kit", v.kit, [["export", "Download kit"], ["verify", "Verify kit"]]) +
      (v.kit === "verify" ? verifyForm : exportForm) + '</fieldset>'
    : "";
  const reindexPanel = project && !project.indexed
    ? '<fieldset><legend>Reconcile restored ciphertext</legend>' +
      '<p>The encrypted file differs from its index.</p>' +
      '<label class="field"><span>Administrator password</span><input id="native-reindex-password" type="password" autocomplete="current-password"></label>' +
      '<label><input id="native-reindex-ack" type="checkbox"> Adopt verified SOPS ciphertext and rebuild key-name metadata</label>' +
      '<button type="button" id="native-secret-reindex">Rebuild metadata</button></fieldset>'
    : '';
  const errors = (v.error ? '<p role="alert" class="error">' + esc(v.error) + '</p>' : '') +
                 (v.message ? '<p role="status">' + esc(v.message) + '</p>' : '');
  // Per-app values are edited on each app's Environment Variables tab; this
  // panel keeps the encryption key, its recipients and the recovery kit.
  const advanced = recipientsPanel
    ? '<details class="advanced"' + (v.review ? " open" : "") + '><summary>Advanced</summary>' +
      '<p class="hint">Rotate the recipients that can decrypt a project. App variables are set on each app\'s own page.</p>' +
      recipientsPanel + '</details>'
    : "";
  return card("Encryption key & recovery kit", status + setup + review + reindexPanel + recoveryPanel + advanced + errors);
}

async function nativeSecretsRefresh() {
  if (nativeSecretsView.loading) return;
  const v = nativeSecretsView;
  v.loading = true;
  try {
    v.data = await api("project-secrets");
    if (!v.data?.projects?.some(p => p.project === v.selected))
      v.selected = v.data?.projects?.[0]?.project || "";
    v.error = "";
  } catch (error) {
    v.data = {identity: {}, projects: []};
    v.error = error.message || "Secret metadata inventory unavailable.";
  } finally {
    v.loaded = true;
    v.loading = false;
    if (state.page === "operations") shell();
  }
}

async function nativeEnrollIdentity() {
  const v = nativeSecretsView;
  if (v.busy) return;
  const mode = v.choice === "have" ? "restore" : "generate";
  const privateEl = document.getElementById("native-age-restore");
  const passwordEl = document.getElementById("native-age-password");
  const privateKey = privateEl?.value || "";
  const current = passwordEl?.value || "";
  const acknowledge = document.getElementById("native-age-ack")?.checked === true;
  if (privateEl) privateEl.value = "";
  if (passwordEl) passwordEl.value = "";
  v.busy = true;
  v.error = "";
  try {
    if (!acknowledge || !current) throw Error("Confirm backup responsibility and reauthenticate.");
    await api("project-secrets/enroll", {
      mode, privateKey: mode === "restore" ? privateKey : null, current, acknowledge,
    });
    v.message = "Identity enrolled. Make a separately protected offline backup before using it.";
    await nativeSecretsRefresh();
  } catch (error) {
    v.error = error.message || "Age identity enrollment failed.";
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

async function nativeSecretReview() {
  const v = nativeSecretsView, project = nativeSecretProject();
  if (v.busy || !project || v.review) return;
  const key = document.getElementById("native-secret-key")?.value?.trim();
  const action = document.getElementById("native-secret-action")?.value;
  const valueEl = document.getElementById("native-secret-value");
  const passwordEl = document.getElementById("native-secret-review-password");
  const value = valueEl?.value;
  const current = passwordEl?.value;
  if (valueEl) valueEl.value = "";
  if (passwordEl) passwordEl.value = "";
  v.busy = true; v.error = ""; v.message = "";
  try {
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key || "")) throw Error("Invalid variable name.");
    if (!current) throw Error("Administrator password is required.");
    if (action === "set" && (!value || new TextEncoder().encode(value).length > 8192))
      throw Error("Enter a secret of at most 8192 UTF-8 bytes.");
    v.review = await api("project-secrets/review", {
      project: project.project, key, action,
      value: action === "set" ? value : null,
      expectedRevision: project.revision, current,
    });
    v.editKey = "";
    v.message = "Encrypted review prepared. No running workload changed.";
  } catch (error) {
    v.error = error.message || "Encrypted review failed.";
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

async function nativeRecipientReview() {
  const v = nativeSecretsView, project = nativeSecretProject();
  if (v.busy || !project || v.review) return;
  const input = document.getElementById("native-recipient-list");
  const password = document.getElementById("native-recipient-password");
  const recipients = (input?.value || "").split(/[\s,]+/).filter(Boolean);
  const current = password?.value || "";
  if (password) password.value = "";
  v.busy = true; v.error = ""; v.message = "";
  try {
    if (!current) throw Error("Administrator password required.");
    if (!recipients.length || recipients.length > 16 || new Set(recipients).size !== recipients.length)
      throw Error("Specify 1–16 unique age recipients.");
    if (!recipients.includes(v.data?.identity?.recipient))
      throw Error("Host age recipient must remain.");
    if (recipients.some(value => !/^age1[ac-hj-np-z02-9]{58}$/.test(value)))
      throw Error("Malformed age public recipient.");
    v.review = await api("project-secrets/review", {
      project: project.project, key: null, action: "recipients",
      value: recipients, expectedRevision: project.revision, current,
    });
    v.message = "Encrypted recipient rekey reviewed. No workload changed.";
  } catch (error) {
    v.error = error.message || "Recipient rekey rejected.";
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

async function nativeSecretPublish() {
  const v = nativeSecretsView;
  if (v.busy || !v.review) return;
  const passwordEl = document.getElementById("native-secret-publish-password");
  const current = passwordEl?.value || "";
  const acknowledge = document.getElementById("native-secret-publish-ack")?.checked === true;
  if (passwordEl) passwordEl.value = "";
  v.busy = true; v.error = ""; v.message = "";
  try {
    if (!acknowledge || !current) throw Error("Approve the reviewed revision and reauthenticate.");
    const result = await api("project-secrets/publish", {
      reviewId: v.review.reviewId, acknowledge, current,
    });
    v.review = null;
    v.message = "Ciphertext revision " + result.revision + " published. Workload apply remains separate.";
    await nativeSecretsRefresh();
  } catch (error) {
    v.error = error.message || "Secret publication failed. Refresh metadata before retry.";
    v.review = null; // never reuse a possibly stale approved review
    await nativeSecretsRefresh();
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

function nativeParseEnv(text) {
  if (typeof text !== "string" || text.length > 64 * 1024)
    throw Error(".env import exceeds the 64 KiB limit.");
  const values = Object.create(null);
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    const match = line.match(/^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.*)$/);
    if (!match) throw Error("Unsupported .env syntax at line " + (i + 1) + ".");
    const key = match[1];
    if (Object.hasOwn(values, key)) throw Error("Duplicate secret name at line " + (i + 1) + ".");
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    } else if (value.startsWith('"') || value.startsWith("'")) {
      throw Error("Unclosed .env quoted value at line " + (i + 1) + ".");
    }
    if (/[\u0000-\u001f]/.test(value) || value.includes("$" + "{") ||
        value.includes("$(") || value.includes(String.fromCharCode(96)))
      throw Error("Unsupported control characters or interpolation at line " + (i + 1) + ".");
    if (new TextEncoder().encode(value).length > 8192)
      throw Error("A secret value exceeds 8192 bytes.");
    values[key] = value;
    if (Object.keys(values).length > 64) throw Error("Import limit is 64 variables.");
  }
  if (!Object.keys(values).length) throw Error("The .env file has no importable variables.");
  return values;
}

async function nativeEnvImportReview() {
  const v = nativeSecretsView, project = nativeSecretProject();
  if (v.busy || !project || v.review) return;
  const fileInput = document.getElementById("native-env-import-file");
  const file = fileInput?.files?.[0];
  const password = document.getElementById("native-env-import-password");
  const current = password?.value;
  if (password) password.value = "";
  if (fileInput) fileInput.value = "";
  v.busy = true; v.error = ""; v.message = "";
  try {
    if (!file || file.size > 64 * 1024 || !current)
      throw Error("Select a .env file of at most 64 KiB and enter the administrator password.");
    const values = nativeParseEnv(await file.text());
    v.review = await api("project-secrets/review", {
      project: project.project, action: "import", key: null, value: values,
      expectedRevision: project.revision, current,
    });
    v.message = "Environment values encrypted in a review; the original .env was not stored.";
  } catch (error) {
    v.error = error.message || "Environment import failed.";
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

async function nativeRecoveryExport() {
  const v = nativeSecretsView;
  if (v.busy) return;
  const passEl = document.getElementById("native-recovery-export-passphrase");
  const repeatEl = document.getElementById("native-recovery-export-confirm");
  const adminEl = document.getElementById("native-recovery-export-admin");
  const passphrase = passEl?.value || "", repeat = repeatEl?.value || "", current = adminEl?.value || "";
  const includeBackup = document.getElementById("native-recovery-backup")?.checked === true;
  if (passEl) passEl.value = "";
  if (repeatEl) repeatEl.value = "";
  if (adminEl) adminEl.value = "";
  v.busy = true; v.error = ""; v.message = "";
  try {
    if (passphrase.length < 16 || passphrase !== repeat || !current)
      throw Error("Enter and confirm a 16+ character recovery passphrase and reauthenticate.");
    const result = await api("project-secrets/recovery-export", {passphrase, includeBackup, current});
    if (result.verified !== false || result.requiresOfflineUnlockVerification !== true)
      throw Error("Recovery kit must require independent SOPS unlock verification.");
    const bytes = Uint8Array.from(atob(result.encrypted), c => c.charCodeAt(0));
    download("nixus-project-secrets-recovery.json", bytes, "application/json");
    v.message = "Encrypted recovery kit downloaded; store it offline and verify it before trusting backups.";
  } catch (error) {
    v.error = error.message || "Recovery kit export failed.";
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

async function nativeRecoveryImport(action) {
  const v = nativeSecretsView;
  if (v.busy || !["verify", "restore"].includes(action)) return;
  const file = document.getElementById("native-recovery-kit-file")?.files?.[0];
  const passEl = document.getElementById("native-recovery-import-passphrase");
  const adminEl = document.getElementById("native-recovery-import-admin");
  const passphrase = passEl?.value || "", current = adminEl?.value || "";
  const acknowledge = document.getElementById("native-recovery-import-ack")?.checked === true;
  if (passEl) passEl.value = "";
  if (adminEl) adminEl.value = "";
  v.busy = true; v.error = ""; v.message = "";
  try {
    if (!file || file.size > 256 * 1024 || !passphrase || !current)
      throw Error("Select a bounded encrypted recovery kit and enter both passwords.");
    if (action === "restore" && !acknowledge)
      throw Error("Explicitly acknowledge the host recovery operation.");
    const bytes = new Uint8Array(await file.arrayBuffer());
    let encoded = "";
    for (let i = 0; i < bytes.length; i += 16384)
      encoded += String.fromCharCode(...bytes.subarray(i, i + 16384));
    const result = await api("project-secrets/recovery-" + action, {
      encrypted: btoa(encoded), passphrase, current,
      acknowledge: action === "restore" ? acknowledge : false,
    });
    v.message = action === "verify"
      ? "Recovery kit authenticated for age recipient " + result.recipient + "."
      : "Recovery identity restored; separately restore and verify encrypted project source/data.";
    if (action === "restore") await nativeSecretsRefresh();
  } catch (error) {
    v.error = error.message || "Recovery kit rejected.";
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

async function nativeSecretsReindex() {
  const v = nativeSecretsView, project = nativeSecretProject();
  if (v.busy || !project || project.indexed) return;
  const password = document.getElementById("native-reindex-password");
  const current = password?.value;
  if (password) password.value = "";
  const acknowledge = document.getElementById("native-reindex-ack")?.checked === true;
  v.busy = true; v.error = ""; v.message = "";
  try {
    if (!current || !acknowledge) throw Error("Reauthenticate and acknowledge metadata recovery.");
    const result = await api("project-secrets/reindex", {
      project: project.project, current, acknowledge,
    });
    v.message = "Encrypted source authenticated and indexed at " + result.revision + ".";
    await nativeSecretsRefresh();
  } catch (error) {
    v.error = error.message || "Secret metadata cannot be recovered.";
  } finally {
    v.busy = false;
    if (state.page === "operations") shell();
  }
}

function bindNativeSecrets() {
  if (state.principal?.role !== "admin") return;
  if (!nativeSecretsView.loaded && !nativeSecretsView.loading) void nativeSecretsRefresh();
  for (const [name, key] of [["choice", "choice"], ["have", "haveVia"], ["kit", "kit"]])
    for (const button of document.querySelectorAll("[data-native-" + name + "]"))
      button.addEventListener("click", () => {
        nativeSecretsView[key] = button.dataset["native" + name[0].toUpperCase() + name.slice(1)];
        nativeSecretsView.error = nativeSecretsView.message = "";
        shell();
      });
  document.querySelector("#native-age-enroll")?.addEventListener("click", () => {
    void nativeEnrollIdentity();
  });
  document.querySelector("#native-recovery-export")?.addEventListener("click", () => {
    void nativeRecoveryExport();
  });
  document.querySelector("#native-env-import-review")?.addEventListener("click", () => {
    void nativeEnvImportReview();
  });
  document.querySelector("#native-recovery-verify")?.addEventListener("click", () => {
    void nativeRecoveryImport("verify");
  });
  document.querySelector("#native-recovery-restore")?.addEventListener("click", () => {
    void nativeRecoveryImport("restore");
  });
  document.querySelector("#native-secret-reindex")?.addEventListener("click", () => {
    void nativeSecretsReindex();
  });
  document.querySelector("#native-secret-project")?.addEventListener("change", event => {
    nativeSecretsView.selected = event.currentTarget.value;
    nativeSecretsView.editKey = "";
    nativeSecretsView.review = null;
    nativeSecretsView.error = "";
    shell();
  });
  for (const button of document.querySelectorAll("[data-native-secret-rotate]")) {
    button.addEventListener("click", () => {
      nativeSecretsView.editKey = button.dataset.nativeSecretRotate;
      nativeSecretsView.review = null;
      shell();
    });
  }
  document.querySelector("#native-secret-review")?.addEventListener("click", () => {
    void nativeSecretReview();
  });
  document.querySelector("#native-recipient-review")?.addEventListener("click", () => {
    void nativeRecipientReview();
  });
  document.querySelector("#native-secret-publish")?.addEventListener("click", () => {
    void nativeSecretPublish();
  });
}

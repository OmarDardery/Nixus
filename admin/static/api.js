'use strict';

async function api(path, body, csrf = state.csrf) {
  const options = { credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    options.method = "POST";
    options.headers = {
      "Content-Type": "application/json",
      "X-Nixus-CSRF": csrf,
    };
    options.body = JSON.stringify(body);
  }
  const r = await fetch("/api/" + path, options);
  if (r.status === 401 && path !== "login")
    login("Sign in again to continue.");
  let result;
  try { result = await r.json(); }
  catch { throw Error("Host returned an unreadable response. Check the connection and refresh status before retrying."); }
  if (!r.ok) {
    throw Error(result?.error || "Request failed (HTTP " + r.status + ")");
  }
  return result;
}

function download(name, bytes, type) {
  const blob = new Blob([bytes], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

async function claimCertificate() {
  const response = await fetch("/api/browser-certificate/download", {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Nixus-CSRF": state.csrf },
    body: "{}",
  });
  if (!response.ok) {
    const error = await response.json();
    throw Error(error.error || "Certificate download unavailable; refresh the identity list");
  }
  return new Uint8Array(await response.arrayBuffer());
}

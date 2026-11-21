"use strict";

// Copy-and-paste source entry. Pasted Dockerfiles, Compose files and build
// context text become ordinary in-browser files with explicit relative paths,
// then follow exactly the same hash, stage, review and publish path as uploads.
// Pasted bytes are kept as typed (UTF-8); nothing is rewritten.

const pasteSource = { entries: [{ path: "Dockerfile", text: "" }], error: "" };

const PASTE_TEMPLATES = {
  dockerfile: [{ path: "Dockerfile", text: "FROM debian:13@sha256:<digest>\nCOPY app /app\nCMD [\"/app/run\"]\n" }],
  compose: [
    { path: "compose.yaml", text: "services:\n  web:\n    build: .\n    ports:\n      - \"8080:8080\"\n    volumes:\n      - data:/var/lib/app\nvolumes:\n  data: {}\n" },
    { path: "Dockerfile", text: "FROM debian:13@sha256:<digest>\nCOPY app /app\nCMD [\"/app/run\"]\n" },
  ],
};

// Nix declarations pasted into the reviewed revision editor.
const NIX_TEMPLATES = {
  native: (name) => "{ ... }: {\n  nixus.project = {\n    backend = \"incus-native\";\n" +
    "    volumes.data.size = \"10GiB\";\n    instances." + name + " = {\n      image = \"images:debian/13\";\n" +
    "      cpus = 2;\n      memory = \"2GiB\";\n      disks.data = { volume = \"data\"; path = \"/srv/data\"; };\n" +
    "      # usb.device = { vendorId = \"1d50\"; productId = \"614e\"; };\n    };\n  };\n}\n",
  compose: () => "{ ... }: {\n  nixus.project = {\n    backend = \"incus-compose\";\n" +
    "    resources = { cpus = 2; memory = \"2GiB\"; };\n  };\n}\n",
};

function pasteSourceCard() {
  const rows = pasteSource.entries.map((entry, index) =>
    '<div class="paste-entry"><label class="field"><span>Relative path</span><input type="text" spellcheck="false" ' +
    'data-paste-path="' + index + '" value="' + esc(entry.path) + '" placeholder="Dockerfile"></label>' +
    '<label class="field"><span>Contents</span><textarea rows="10" spellcheck="false" data-paste-text="' + index + '">' +
    esc(entry.text) + "</textarea></label>" +
    (pasteSource.entries.length > 1 ? '<button type="button" class="small" data-paste-remove="' + index + '">Remove file</button>' : "") +
    "</div>").join("");
  return card("Paste Dockerfile and Compose source",
    "<p>Paste a Dockerfile, Containerfile, <code>compose.yaml</code> and any small build-context files. Each pasted file is hashed in this browser and staged exactly as typed, like an uploaded file.</p>" +
    '<p><button type="button" class="small" data-paste-template="dockerfile">Start from a Dockerfile</button> ' +
    '<button type="button" class="small" data-paste-template="compose">Start from Compose + Dockerfile</button></p>' +
    rows +
    '<button type="button" id="paste-add">Add another file</button> ' +
    '<button type="button" id="paste-use"' + (nativeImportState.busy ? " disabled" : "") + ">Use pasted files</button>" +
    (pasteSource.error ? '<p class="error" role="alert">' + esc(pasteSource.error) + "</p>" : "") +
    '<p class="note">Base images must be pinned by digest (<code>name:tag@sha256:…</code>). Keep the tag so update checks can follow it. Never paste secrets; use the encrypted project secrets instead.</p>');
}

function nixTemplateButtons() {
  return '<p>Paste a complete Nix file below, or start from a template: ' +
    '<button type="button" class="small" data-nix-template="native">Native Incus instance</button> ' +
    '<button type="button" class="small" data-nix-template="compose">Compose project</button></p>';
}

function pasteSync() {
  for (const input of document.querySelectorAll("[data-paste-path]"))
    pasteSource.entries[Number(input.dataset.pastePath)].path = input.value.trim();
  for (const area of document.querySelectorAll("[data-paste-text]"))
    pasteSource.entries[Number(area.dataset.pasteText)].text = area.value;
}

// pastedFiles turns entries into File objects carrying an explicit path.
function pastedFiles(entries) {
  const seen = new Set();
  return entries.map(entry => {
    if (!entry.path) throw Error("Give every pasted file a relative path.");
    if (seen.has(entry.path)) throw Error("Duplicate pasted path: " + entry.path);
    seen.add(entry.path);
    if (!entry.text) throw Error("Pasted file " + entry.path + " is empty.");
    if (/<digest>/.test(entry.text)) throw Error("Replace <digest> in " + entry.path + " with the image's real sha256 digest.");
    const name = entry.path.split("/").pop();
    const file = new File([entry.text], name, { type: "text/plain" });
    Object.defineProperty(file, "nixusPath", { value: entry.path });
    nativeSourcePath(file);
    return file;
  });
}

function bindPasteSource() {
  for (const button of document.querySelectorAll("[data-paste-template]")) {
    button.addEventListener("click", () => {
      pasteSource.entries = PASTE_TEMPLATES[button.dataset.pasteTemplate].map(e => ({ ...e }));
      pasteSource.error = "";
      shell();
    });
  }
  document.querySelector("#paste-add")?.addEventListener("click", () => {
    pasteSync();
    pasteSource.entries.push({ path: "", text: "" });
    shell();
  });
  for (const button of document.querySelectorAll("[data-paste-remove]")) {
    button.addEventListener("click", () => {
      pasteSync();
      pasteSource.entries.splice(Number(button.dataset.pasteRemove), 1);
      shell();
    });
  }
  document.querySelector("#paste-use")?.addEventListener("click", () => {
    pasteSync();
    try {
      const files = pastedFiles(pasteSource.entries);
      pasteSource.error = "";
      void nativePreviewFiles(files, false);
    } catch (error) {
      pasteSource.error = error.message || "Pasted source is invalid.";
      shell();
    }
  });
  for (const button of document.querySelectorAll("[data-nix-template]")) {
    button.addEventListener("click", () => {
      const kind = button.dataset.nixTemplate;
      const project = (nativeProjectTx.path.split("/")[0] || "").match(/^[a-z][a-z0-9-]{0,62}$/) ? nativeProjectTx.path.split("/")[0] : "my-app";
      nativeProjectTx.path = project + "/default.nix";
      nativeProjectTx.source = NIX_TEMPLATES[kind](project);
      nativeProjectTx.error = "";
      shell();
      document.querySelector("#native-nix-editor")?.scrollIntoView({ block: "center" });
    });
  }
}

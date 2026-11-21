"use strict";

// References only. Copying a command never calls a host execution endpoint.

function referenceLink(label, url) {
  return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`;
}

const userGuides = [["Install & update", "install"], ["Apps", "apps"], ["Apps repository", "apps-repo"], ["Env vars & secrets", "secrets"],
  ["Backups & restore", "backups"], ["Networking", "networking"], ["Troubleshooting", "troubleshooting"], ["CLI", "administration"], ["Credits", "credits"]];

function referenceCatalog() {
  const row = item => "<tr><td><b>" + esc(item.name) + "</b><br><small>" + esc(item.detail) + "</small></td><td class=\"reference-links\">" +
    [...item.docs, ...item.community].map(([label, url]) => referenceLink(label, url)).join(" · ") + "</td><td>" + (item.source ? referenceLink("Source", item.source) : "") + "</td></tr>";
  const table = items => '<div class="table-wrap"><table><thead><tr><th>Project</th><th>Docs</th><th>Code</th></tr></thead><tbody>' + items.map(row).join("") + "</tbody></table></div>";
  return '<section class="reference-catalog" id="project-docs"><h2>Built with</h2>' + table(projectReferences.filter(item => !item.optional)) +
    "<details><summary>Optional integrations</summary>" + table(projectReferences.filter(item => item.optional)) + "</details></section>";
}

function infoHeader() {
  const release = state.status?.release || {};
  const revision = release.revision ? String(release.revision).slice(0, 12) : "";
  return card("Nixus", "<p>Version <b>" + esc(release.version || "unknown") + "</b>" + (revision ? " · <code>" + esc(revision) + "</code>" : "") + " · " +
      referenceLink("Source", projectRepository) + " · " + referenceLink("Issues", projectRepository + "/issues") + "</p>") +
    card("Guides", '<div class="guide-shortcuts">' + userGuides.map(([label, slug]) => referenceLink(label, "/docs/" + slug + ".md")).join("") + "</div>");
}

function commandGroups() {
  const settings = state.status.effectiveSettings || state.status.settings;
  const address = state.status.managementAddress || settings.management.address;
  const host = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(address) && address.split('.').every(n => Number(n) <= 255) ? address : "HOST_IP";
  return [
    { id: "cheatsheet", title: "Everyday homelab cheatsheet", guide: "administration.md", items: [
      ["quick-doctor", "Nixus health", "Host terminal", "Check host and management endpoint readiness.", "sudo nixus doctor"],
      ["quick-guests", "Show all guests", "Host terminal", "Instances and their current states across Incus projects.", "sudo incus list --all-projects"],
      ["quick-failures", "Failed services", "Host terminal", "Inspect failed systemd units.", "systemctl --failed"],
      ["quick-log", "Follow Nixus web logs", "Host terminal", "Investigate authentication or startup problems.", "sudo journalctl -u nixus-ui -f"],
      ["quick-incus-projects", "List Incus namespaces", "Host terminal", "Inspect named Incus projects.", "sudo incus project list"],
      ["quick-guest-logs", "Guest service logs", "Host terminal", "Inspect the selected guest without publishing its admin interfaces.", "sudo incus exec GUEST --project lab -- journalctl -b --no-pager -n 50"],
      ["quick-recovery", "Show pending install checklist", "Host terminal", "See pending guest network, device and backup commissioning steps.", "sudo nixus install-plan"],
      ["quick-config", "Current change status", "Host terminal", "View reviewed configuration transactions.", "sudo nixus-admin config status"],
    ] },
    { id: "updates", title: "Install & update", guide: "install.md", items: [
      ["platform-update", "Update Nixus", "Host terminal", "Update from main with build/impact review, guarded activation and separate fresh-session access confirmation. Requests sudo and resumes interrupted updates; no automatic reboot.", "nix run --refresh github:OmarDardery/Nixus#update"],
      ["package-review", "Review a package refresh", "Host terminal", "Build a candidate with refreshed pinned inputs. This does not activate it; inspect and apply it under Changes.", "sudo nixus-admin config review --update-inputs"],
      ["review-status", "Inspect the current transaction", "Host terminal", "Check build, activation or confirmation state before starting another change.", "sudo nixus-admin config status"],
    ] },
    { id: "health", title: "Health, logs & SSH", guide: "troubleshooting.md", items: [
      ["doctor", "Check the management stack", "Host terminal", "Probe the actual address and enabled management interfaces.", "sudo nixus doctor"],
      ["failed-units", "Find failed services", "Host terminal", "List failed systemd units on the host.", "systemctl --failed"],
      ["cockpit-boot", "Read Cockpit’s boot logs", "Host terminal", "Collect evidence before restarting a service.", "sudo journalctl -b -u cockpit.socket -u cockpit.service -u nixus-management-identity.service --no-pager"],
      ["ssh", "Connect to this host", "Your laptop", "Use the operator Linux password or an enrolled client key.", "ssh operator@" + host],
      ["commissioning", "Collect commissioning evidence", "Host terminal", "Read-only probes record revision-bound results. Reboots, installation retry and restore drills remain separate procedures in the commissioning guide.", "sudo nixus commissioning collect --mode fresh"],
    ] },
    { id: "guests", title: "Incus resources", guide: "administration.md", items: [
      ["list-guests", "List instances across projects", "Host terminal", "Read-only Incus inventory.", "sudo incus list --all-projects"],
      ["list-projects", "List project namespaces", "Host terminal", "Inspect Incus projects and their limits.", "sudo incus project list"],
      ["list-images", "List OCI and system images", "Host terminal", "Inspect available images; no build is triggered.", "sudo incus image list"],
      ["list-storage", "List storage pools", "Host terminal", "Inspect pools without deleting data.", "sudo incus storage list"],
      ["list-networks", "List networks", "Host terminal", "Inspect Incus network definitions.", "sudo incus network list"],
      ["guest-info", "Inspect a guest", "Host terminal", "Inspect resources, state and devices.", "sudo incus info GUEST --project PROJECT"],
      ["guest-shell", "Open a guest shell", "Host terminal", "Interactive access explicitly names its project.", "sudo incus exec GUEST --project PROJECT -- sh"],
    ] },
    { id: "helpers", title: "Community helper commands", guide: "administration.md", items: [
      ["helper-list", "Browse the packaged helper catalog", "Host terminal", "List script IDs and compatibility metadata from the pinned sources.", "nixus-helpers list"],
      ["helper-doctor", "Check helper prerequisites", "Host terminal", "Verify Incus, images, networks and storage for the lab project.", "sudo nixus-helpers doctor --project lab"],
      ["helper-debian", "Example: Debian container wizard", "Host terminal", "Interactive Incus wizard; creates a guest. Helpers must be enabled. Choose its storage and network in the terminal.", "sudo nixus-helpers run debian --project lab"],
      ["helper-catalog", "Select a community helper", "Host terminal", "Browse application choices; review upstream scripts and prerequisites before use.", "nixus-helpers list"],
    ] },
  ];
}

function commandRow(item) {
  const [id, label, where, detail, command] = item;
  return `<div class="command-row"><div class="command-description"><h3>${esc(label)}</h3><span class="command-location">${esc(where)}</span><p>${esc(detail)}</p></div><div class="command-code"><pre><code id="command-${id}">${esc(command)}</code></pre><button class="small" type="button" data-copy-command="${id}" aria-label="Copy ${esc(label)} command">Copy</button></div></div>`;
}

function commandsPage() {
  return title("", "Info", "Version, guides, the projects Nixus is built on, and handy commands.") + infoHeader() + referenceCatalog()
    + `<section class="command-library" id="commands"><h2>Commands</h2>${commandGroups().map((group, index) => `<details class="command-group" ${index === 0 ? "open" : ""}><summary><span>${esc(group.title)}</span><span class="group-count">${group.items.length} commands</span></summary><div class="command-group-body"><p class="group-guide">${referenceLink("Read the guide", "/docs/" + group.guide)}</p>${group.items.map(commandRow).join("")}</div></details>`).join("")}</section>${publicApplications()}`;
}

function bindCommands() {
  document.querySelectorAll("[data-copy-command]").forEach(button => {
    button.onclick = async () => {
      const code = document.getElementById("command-" + button.dataset.copyCommand);
      try {
        await navigator.clipboard.writeText(code.textContent);
        button.textContent = "Copied";
        toast("Command copied. Run it in the indicated terminal.");
      } catch {
        const range = document.createRange(); range.selectNodeContents(code);
        const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
        button.textContent = "Selected";
        toast("Clipboard unavailable. The command is selected for manual copying.");
      }
      setTimeout(() => { button.textContent = "Copy"; }, 2500);
    };
  });
}

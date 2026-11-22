"use strict";

function settingsMigrationReview() {
  const migration = state.status.job?.settingsMigration;
  if (!migration || migration.from === migration.to) return "";
  return card("Settings schema migration", `<p>Version ${esc(migration.from)} → ${esc(migration.to)}.</p>`);
}

function candidateOverridesReview() {
  const overrides = state.status.job?.candidateOverrides;
  if (!overrides?.length) return "";
  return card("Host module overrides in this candidate", `${overrides.map(item => `<div class="diff"><code>${esc(item.setting)}</code><span class="before">${esc(JSON.stringify(item.before))}</span><span class="after">${esc(JSON.stringify(item.after))}</span></div>`).join("")}`);
}

function impactReview() {
  const plan = state.status.job?.impactPlan;
  if (!plan) return state.status.job?.status === "ready"
    ? card("Change impact", '<p>An older candidate has no impact plan. Build a new review before activation.</p>') : "";
  const labels = {configuration: "Configuration", "restart-required": "Possible restart", "migration-required": "Migration required", "ownership-conflict": "Ownership conflict", unknown: "Unknown effects"};
  const renderRows = items => items.map(item => `<tr><td><code>${esc(item.identity)}</code><br><small>${esc(item.scope)}</small></td><td>${esc(labels[item.kind] || item.kind)}${item.blocked ? ' · blocked' : ''}</td><td>${esc(item.message)}${item.fields.length ? `<p><small>Fields: ${esc(item.fields.join(", "))}</small></p>` : ""}${item.affected.length ? `<p><small>Affects: ${esc(item.affected.join(", "))}</small></p>` : ""}${item.resolution ? `<p>${esc(item.resolution)}</p>` : ""}</td></tr>`).join("");
  const rows = renderRows(plan.changes.filter(item => item.scope !== "service"));
  const services = plan.changes.filter(item => item.scope === "service");
  const owners = plan.ownership.map(item => `<tr><td><code>${esc(item.identity)}</code></td><td>${esc(item.owner)}</td><td>${esc(item.fields.join(", ") || "Native/external configuration")}${item.consumers.length ? `<br><small>Consumers: ${esc(item.consumers.join(", "))}</small>` : ""}</td></tr>`).join("");
  return card("Change impact", `<p>${plan.blocked ? "Resolve the blocking changes before activation." : "Review affected resources and activation output before applying."} Runtime: ${esc(plan.runtimeState)} · ${esc(plan.preconditionCount)} observed preconditions.</p>${plan.refreshedAfterDrift ? '<p class="error">Runtime changed since review. This plan was refreshed; review it again before activation.</p>' : ""}${state.status.job.rebootRequired ? '<p class="note">The candidate requires a host reboot.</p>' : ""}<div class="table-wrap" tabindex="0"><table><thead><tr><th>Resource</th><th>Change</th><th>Impact & resolution</th></tr></thead><tbody>${rows || '<tr><td colspan="3">No modeled resource changes.</td></tr>'}</tbody></table></div>${services.length ? `<details><summary>Changed host services (${services.length})</summary><div class="table-wrap" tabindex="0"><table><thead><tr><th>Service</th><th>Change</th><th>Impact</th></tr></thead><tbody>${renderRows(services)}</tbody></table></div></details>` : ""}<details><summary>Who owns what</summary><div class="table-wrap" tabindex="0"><table><thead><tr><th>Resource</th><th>Owner</th><th>Fields & consumers</th></tr></thead><tbody>${owners}</tbody></table></div></details>${plan.boundaries.map(value => `<p class="note">${esc(value)}</p>`).join("")}<p><a href="/docs/apps.md">Ownership and review boundaries →</a></p>`);
}

function freshObservation(value) {
  return Number.isFinite(value?.checkedAt) && Date.now() / 1000 - value.checkedAt >= -5 && Date.now() / 1000 - value.checkedAt < 90;
}

function guestNicDetails(nic) {
  const link = {disabled: "Attachment disabled", stopped: "Guest stopped", up: "Link reported up",
    down: "Link reported down", unknown: "Link not reported"}[nic.linkState];
  const origin = {instance: "Instance device", profile: "Profile device"}[nic.deviceSource];
  const conflict = nic.bridgeConflict;
  return [link, origin].filter(Boolean).map(value => `<br><small>${esc(value)}</small>`).join("")
    + (conflict ? `<br><small class="error">Macvlan parent ${esc(conflict.port)} belongs to bridge ${esc(conflict.bridge)}. Review attachment in Incus.</small>` : "")
    + (nic.lanIPv4Missing ? '<br><small class="error">No LAN IPv4 reported. Check guest addressing and upstream DHCP if used.</small>' : "");
}

function guestNetwork() {
  const snapshot = operationView.network;
  const failed = operationView.networkError;
  const stale = !freshObservation(snapshot);
  const tools = managementServices();
  const incus = tools.find(tool => tool.name === "Incus");
  if (!snapshot?.available) return card("Guests & addresses", `<p>${esc(failed || "Guest inventory is not available yet.")}</p><a href="/docs/networking.md">Networking guide</a>`);
  const conflicts = (snapshot.conflicts || []).map(item => `<li><code>${esc(item.address)}</code> on ${esc(item.project)}/${esc(item.network)}: ${esc(item.owners.join(", "))}</li>`).join("");
  const topologyNote = snapshot.bridgeTopologyAvailable === false
    ? '<p class="note">Host bridge membership is unavailable.</p>' : "";
  const rows = snapshot.guests.flatMap(guest => {
    const nics = guest.nics.length ? guest.nics : [{name: "—", network: "Not reported", observed: guest.observed, reserved: []}];
    return nics.map((nic, index) => `<tr>${index === 0 ? `<td rowspan="${nics.length}"><b>${esc(guest.name)}</b><br><small>${esc(guest.project)} · ${esc(guest.type === "virtual-machine" ? "VM" : guest.type)}</small></td><td rowspan="${nics.length}">${esc(guest.status)}</td>` : ""}<td>${esc(nic.network)}<br><small>${esc(nic.name)}</small>${guestNicDetails(nic)}</td><td>${nic.observed.map(ip => `<code>${esc(ip)}</code>`).join("<br>") || '<span class="muted">Not reported</span>'}</td><td>${nic.reserved.map(ip => `<code>${esc(ip)}</code>`).join("<br>") || '<span class="muted">Dynamic / not set</span>'}${nic.unobservedReservation ? '<br><small class="error">Reservation not observed</small>' : ""}</td></tr>`);
  }).join("");
  return card("Guests & addresses", `${failed || stale ? `<p class="error">${esc(failed || "Inventory is stale. Refresh before relying on these addresses.")}</p>` : ""}${conflicts ? `<div class="network-warning"><b>Potential address conflict</b><ul>${conflicts}</ul></div>` : ""}${topologyNote}<div class="table-wrap guest-addresses" tabindex="0" role="region" aria-label="Guest network addresses"><table><thead><tr><th>Guest / project</th><th>State</th><th>Network / NIC</th><th>Reported IP</th><th>Reservation</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No guests reported by Incus.</td></tr>'}</tbody></table></div><p class="note">Last checked: ${esc(new Date(snapshot.checkedAt * 1000).toLocaleTimeString())}.</p><div class="service-shortcuts">${incus?.url ? `<a href="${esc(incus.url)}" target="_blank" rel="noopener noreferrer">Manage guests & IPs in Incus</a>` : ""}<a href="/docs/networking.md">Addressing & routing guide</a><a href="https://linuxcontainers.org/incus/docs/main/howto/network_manage/" target="_blank" rel="noopener noreferrer">Incus network docs</a></div>`, "Read-only · all projects");
}

function hostOverview() {
  const s = state.status.effectiveSettings || state.status.settings;
  const health = operationView.health;
  const required = ["incus.service", "nixus-admin-backend.service", "nixus-ui.service",
    ...(s.cockpit?.enable ? ["cockpit.socket"] : []), ...(s.apps?.enable ? ["nginx.service"] : [])];
  const fresh = freshObservation(health);
  const degraded = required.filter(id => !(health?.services || []).some(unit => unit.Id === id && unit.LoadState === "loaded" && unit.ActiveState === "active"));
  const failed = (health?.services || []).filter(unit => unit.ActiveState === "failed" || unit.Result && unit.Result !== "success");
  const known = (health?.services || []).length > 0;
  const services = !fresh ? "Unavailable or stale" : !known ? "Unavailable" : degraded.length || failed.length ? "Needs attention" : "Management services active";
  const network = operationView.network;
  const observedGuests = network?.available && freshObservation(network);
  const guestCount = observedGuests ? network.guests.length : "—";
  const guestDetail = observedGuests ? network.guests.filter(g => g.status === "Running").length + " running · observed" : "Inventory unavailable or stale";
  const hostSignal = !fresh || !known ? "Unknown" : degraded.length || failed.length ? "Attention" : "Healthy";
  const hostDetail = !fresh ? "Status unavailable or stale" : !known ? "No loaded services observed" : "Observed host services";
  return title("", "Overview", "Server status and quick actions.")
    + (typeof quickActions === "function" ? quickActions() : "")
    + `<div class="stats">
       <div class="stat"><div class="label">Host services</div><div class="value">${esc(hostSignal)}</div><div class="detail">${esc(hostDetail)}</div></div>
       <div class="stat"><div class="label">Incus guests</div><div class="value">${esc(guestCount)}</div><div class="detail">${esc(guestDetail)}</div></div>
       <div class="stat"><div class="label">Apps</div><div class="value">${esc(typeof quick === "object" && quick.apps ? (quick.apps.projects || []).length : "—")}</div><div class="detail">Deployed apps</div></div>
       <div class="stat"><div class="label">Backups</div><div class="value">${esc(typeof quick === "object" && quick.backups?.lastSuccess ? "OK" : "None")}</div><div class="detail">${esc(typeof quick === "object" && quick.backups?.lastSuccess ? "Last " + new Date(quick.backups.lastSuccess * 1000).toLocaleString() : "Set up on Backups")}</div></div>
     </div><div class="grid overview-grid">${homepageTools()}${card("Host", `<dl class="host-facts"><div><dt>Management</dt><dd><code>${esc(s.management.interface)} · ${esc(state.status.managementAddress || s.management.address)}</code></dd></div><div><dt>Services</dt><dd class="${fresh && known && (degraded.length || failed.length) ? "error" : ""}">${esc(services)}</dd></div><div><dt>Virtualization</dt><dd>${state.host.kvm ? "KVM device detected" : "KVM not detected"}</dd></div><div><dt>Backup</dt><dd>${esc(fresh ? health?.backup?.health || "unknown" : "unknown")}</dd></div><div><dt>Reboot</dt><dd>${state.status.rebootRequired ? "Required" : "Not pending"}</dd></div>${health?.rootStorage && fresh ? `<div><dt>Free root space</dt><dd>${esc(formatBytes(health.rootStorage.availableBytes))}</dd></div>` : ""}<div><dt>Changes</dt><dd>${esc(state.status.job?.status || "None pending")}</dd></div></dl>${fresh && known && degraded.length ? `<p class="error">${esc(degraded.join(", "))}</p>` : ""}<div class="actions"><button class="small" data-overview-refresh>Refresh status</button><a href="/docs/troubleshooting.md">Troubleshooting</a></div>`, fresh ? "Checked " + new Date(health.checkedAt * 1000).toLocaleTimeString() : "Health unknown")}</div>${guestNetwork()}`;
}

function recordEditor(heading, path, columns, defaults) {
  const values = at(state.draft, path) || [];
  return card(
    heading,
    values
      .map(
        (row, index) =>
          `<div class="mount-row"><div class="fields">${columns.map(([key, label, kind = "text"]) => `<label class="field"><span>${esc(label)}</span>${kind === "protocol" ? `<select data-record="${path}" data-index="${index}" data-key="${key}"><option ${row[key] === "tcp" ? "selected" : ""}>tcp</option><option ${row[key] === "udp" ? "selected" : ""}>udp</option></select>` : `<input data-record="${path}" data-index="${index}" data-key="${key}" data-kind="${kind}" type="${kind === "number" ? "number" : "text"}" value="${esc(Array.isArray(row[key]) ? row[key].join(", ") : row[key])}">`}</label>`).join("")}</div><button class="small danger" data-record-remove="${path}" data-index="${index}">Remove declaration</button></div>`,
      )
      .join("") +
      `<button data-record-add="${path}" data-defaults="${esc(JSON.stringify(defaults))}">Add declaration</button>`,
  );
}

function hostConnectivity() {
  const choices = [
    ...state.host.interfaces.map((i) => i.name),
    ...(state.draft.connectivity?.bridges || []).map((b) => b.name),
    ...(state.draft.connectivity?.vlans || []).map((v) => v.name),
  ];
  return (
    title(
      "PHYSICAL NETWORKING",
      "Networking", "Host network, bridges and VLANs.",
    ) +
    card(
      "Management addressing",
      `${toggle("Declare management addressing", "management.configure")}<div class="fields">${field("Interface or declared bridge", "management.interface", { hint: "Discovered/declared: " + [...new Set(choices)].join(", ") })}${field("IPv4 address", "management.address")}${field("Prefix length", "management.prefixLength", { type: "number" })}${field("Gateway", "management.gateway")}${field("DNS servers", "management.dns", { list: true, type: "textarea" })}${field("Trusted management CIDRs", "management.trustedCIDRs", { list: true, type: "textarea" })}</div><p>Move the management address onto the bridge in the same change and keep console access.</p>`,
    ) +
    recordEditor(
      "Ethernet LAN bridges",
      "connectivity.bridges",
      [
        ["name", "Bridge name"],
        ["interfaces", "Ethernet/VLAN ports", "list"],
      ],
      { name: "br-lan", interfaces: [] },
    ) +
    recordEditor(
      "VLAN interfaces",
      "connectivity.vlans",
      [
        ["name", "Interface name"],
        ["interface", "Ethernet parent"],
        ["id", "VLAN tag", "number"],
      ],
      { name: "vlan20", interface: "", id: 20 },
    ) +
    card(
      "Private guest firewall integration",
      `<div class="fields">${field("Private Incus bridge interfaces", "connectivity.guestInterfaces", { list: true, type: "textarea", full: true, hint: "Register private bridge names after creating them in Incus. Never list physical/LAN interfaces here." })}</div>${toggle("Permit trusted LAN clients to reach private guests", "connectivity.trustedLANAccess", "Private guest addresses require a route on your router/client. Incus forwards and ACLs remain in Incus.")}`,
    ) +
    recordEditor(
      "Narrow guest access to LAN services",
      "connectivity.privateAccess",
      [
        ["cidr", "Destination IPv4 CIDR"],
        ["protocol", "Protocol", "protocol"],
        ["ports", "Ports", "ports"],
      ],
      { cidr: "", protocol: "udp", ports: [53] },
    ) +
    card(
      "Bootstrap guest network",
      `<div class="fields">${field("Subnet", "guests.cidr")}${field("Bridge address/prefix", "guests.gatewayCIDR")}${field("DHCP range", "guests.dhcpRange")}</div><button data-action="suggest">Suggest an unused subnet</button><a href="/docs/networking.md">Network ownership and examples</a>`,
    )
  );
}


function integrations() {
  return (
    title(
      "SERVICES",
      "Services", "Turn on Cockpit and other host tools.",
    ) +
    card("Cockpit host terminal", `${toggle("Enable Cockpit on the host", "cockpit.enable")}<div class="fields">${field("Cockpit HTTPS port", "cockpit.port", { type: "number" })}</div><p>Sign in with your Linux account, the same as this console.</p>`)
  );
}

function bindFoundation() {
  const writable = (path) =>
    administrator() &&
    !(state.status.codeOverrides || []).some(
      (c) => c.setting === path || path.startsWith(c.setting + "."),
    );
  document.querySelectorAll("[data-record]").forEach((el) => {
    el.disabled = !writable(el.dataset.record);
    el.onchange = () => {
      const kind = el.dataset.kind;
      const value =
        kind === "number"
          ? Number(el.value)
          : ["list", "ports"].includes(kind)
            ? el.value
                .split(/[\n,]/)
                .map((v) => v.trim())
                .filter(Boolean)
                .map((v) => (kind === "ports" ? Number(v) : v))
            : el.value;
      at(state.draft, el.dataset.record)[Number(el.dataset.index)][
        el.dataset.key
      ] = value;
    };
  });
  document
    .querySelectorAll("[data-record-add],[data-record-remove]")
    .forEach((el) => {
      const path = el.dataset.recordAdd || el.dataset.recordRemove;
      el.disabled = !writable(path);
      el.onclick = () => {
        if (el.dataset.recordAdd)
          at(state.draft, path).push(JSON.parse(el.dataset.defaults));
        else at(state.draft, path).splice(Number(el.dataset.index), 1);
        shell();
      };
    });

}

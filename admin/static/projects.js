"use strict";

// Shared native-tool identity, credits and documentation. No remote assets load.
const projectRepository = "https://github.com/OmarDardery/Nixus";
const projectReferences = [
  { name: "Nixus", source: "https://github.com/OmarDardery/Nixus", detail: "This console, installer and app pipeline", guide: "install.md",
    docs: [["Issues", "https://github.com/OmarDardery/Nixus/issues"]], community: [] },
  { name: "NixOS & Nix", source: "https://github.com/NixOS/nixpkgs", detail: "Declarative host and pinned packages", guide: "administration.md",
    docs: [["NixOS manual", "https://nixos.org/manual/nixos/stable/"], ["Nix", "https://nix.dev/manual/nix/stable/"]], community: [] },
  { name: "Incus", source: "https://github.com/lxc/incus", detail: "Containers, VMs, images, networks, storage", guide: "apps.md",
    docs: [["Docs", "https://linuxcontainers.org/incus/docs/main/"]], community: [["Forum", "https://discuss.linuxcontainers.org/"]] },
  { name: "Incus Compose", source: "https://github.com/lxc/incus-compose", detail: "Runs Compose apps as Incus containers", guide: "apps.md",
    docs: [["README", "https://github.com/lxc/incus-compose#readme"]], community: [] },
  { name: "QEMU / KVM", source: "https://gitlab.com/qemu-project/qemu", detail: "Virtual machines", guide: "apps.md",
    docs: [["Docs", "https://www.qemu.org/docs/master/"]], community: [] },
  { name: "Buildah", source: "https://github.com/containers/buildah", detail: "Offline sandboxed image builds", guide: "apps.md",
    docs: [["Docs", "https://buildah.io/"]], community: [] },
  { name: "skopeo", source: "https://github.com/containers/skopeo", detail: "Registry digests for pinning and updates", guide: "apps.md",
    docs: [["README", "https://github.com/containers/skopeo#readme"]], community: [] },
  { name: "SOPS", source: "https://github.com/getsops/sops", detail: "Encrypted env vars and secrets", guide: "secrets.md",
    docs: [["Docs", "https://getsops.io/docs/"]], community: [] },
  { name: "age", source: "https://github.com/FiloSottile/age", detail: "The encryption key behind SOPS", guide: "secrets.md",
    docs: [["Spec", "https://age-encryption.org/"]], community: [] },
  { name: "sops-nix", source: "https://github.com/Mic92/sops-nix", detail: "Host secrets at activation", guide: "secrets.md",
    docs: [["README", "https://github.com/Mic92/sops-nix#readme"]], community: [] },
  { name: "restic", source: "https://github.com/restic/restic", detail: "Encrypted, deduplicated backups", guide: "backups.md",
    docs: [["Docs", "https://restic.readthedocs.io/en/stable/"]], community: [["Related tools", "https://github.com/restic/others"]] },
  { name: "rclone", source: "https://github.com/rclone/rclone", detail: "Google Drive and other backup destinations", guide: "backups.md",
    docs: [["Docs", "https://rclone.org/docs/"]], community: [] },
  { name: "Git & OpenSSH", source: "https://github.com/git/git", detail: "Apps repository sync", guide: "apps-repo.md",
    docs: [["Git", "https://git-scm.com/doc"], ["OpenSSH", "https://www.openssh.com/manual.html"]], community: [] },
  { name: "Cockpit", source: "https://github.com/cockpit-project/cockpit", detail: "Host terminal, services, journal", guide: "administration.md",
    docs: [["Docs", "https://cockpit-project.org/documentation.html"]], community: [["Plugins", "https://cockpit-project.org/applications.html"]] },
  { name: "Go", source: "https://github.com/golang/go", detail: "The Nixus runtime", guide: "administration.md",
    docs: [["Docs", "https://go.dev/doc/"]], community: [] },
  { name: "Geist", source: "https://github.com/vercel/geist-font", detail: "Console typeface (OFL)", guide: "credits.md",
    docs: [["Font", "https://vercel.com/font"]], community: [] },
  { name: "Cloudflare Tunnel", source: "https://github.com/cloudflare/cloudflared", detail: "Public ingress, run as an app", guide: "networking.md", optional: true,
    docs: [["Docs", "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/"]], community: [] },
  { name: "Tailscale", source: "https://github.com/tailscale/tailscale", detail: "Optional private access", guide: "networking.md", optional: true,
    docs: [["Docs", "https://tailscale.com/kb"]], community: [] },
  { name: "Prometheus", source: "https://github.com/prometheus/prometheus", detail: "Optional metrics history", guide: "administration.md", optional: true,
    docs: [["Docs", "https://prometheus.io/docs/introduction/overview/"]], community: [] },
  { name: "Host networking", detail: "SSH, NetworkManager, nftables, systemd", guide: "networking.md", optional: true,
    docs: [["NixOS options", "https://search.nixos.org/options"], ["NetworkManager", "https://networkmanager.dev/docs/"], ["systemd", "https://systemd.io/"]], community: [] },
];

function managementServices() {
  const active = state.status.effectiveSettings || state.status.settings;
  const host = state.status.managementAddress || active.management.address;
  const rows = [
    ["Incus", 8443, true],
    ["Cockpit", active.cockpit?.port, active.cockpit?.enable],
  ];
  return rows.map(([name, port, enabled]) => {
    const project = projectReferences.find(item => item.name === name);
    let url = null;
    const ip = typeof host === "string" && !/[\s/@?#\\]/.test(host) &&
      (host.includes(":") || host.split(".").length === 4 && host.split(".").every(n => /^(0|[1-9]\d{0,2})$/.test(n) && Number(n) <= 255));
    if (state.status.setupComplete && enabled && ip && Number.isInteger(port) && port > 0 && port < 65536) {
      try {
        const authority = host.includes(":") ? `[${host}]` : host;
        url = new URL(`https://${authority}:${port}`).href.replace(/\/$/, "");
      } catch { /* Invalid/unobserved endpoints are not clickable. */ }
    }
    return {...project, port, enabled, url};
  });
}

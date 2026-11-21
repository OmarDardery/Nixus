# Deployment and commissioning

For an installed NixOS server, the recommended path is the
[single-command installer](plain-nixos.md). It detects hardware/network values locally
and supports subsequent settings/rebuilds through the CLI or optional portal. The steps below remain the
manual/advanced source workflow.

The optional initial `--wizard` installer uses the same guarded transaction as
full installation. It adds only onboarding/recovery and retains the installed
network and boot configuration. Confirm fresh management access from a newly authenticated remote session or the physical console before starting
the full configuration review; rerunning `--wizard` resumes its pending job. It
refuses already configured hosts. Direct `nixos-rebuild` commands in the advanced
workflow below bypass Nixus's access-confirmation guard.

## Collect real inventory first

Do not copy the evaluation fixture into production. From the physical machine or its
installer, collect:

```console
lscpu
ip -br link
ip -br address
ip -4 route
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL
findmnt
```

Record CPU vendor/architecture, VT-x/AMD-V firmware availability, boot mode,
management NIC, management IP/prefix, gateway/DNS and trusted administrator subnet.
Choose a guest subnet that overlaps neither LAN, VPN, Docker networks nor upstream routes.
Reserve the apps IP outside the guest DHCP range. Identify existing storage, free staging
space, and an independent backup target. Keep serial/local console access during network changes.

This project does not install onto or repartition the running Proxmox disk. Install NixOS
onto a separate verified disk/host or use a recoverable maintenance plan with tested backups.
Disk and bootloader setup are inherently hardware-specific and intentionally omitted from defaults.

## Configure and build

On the installed NixOS host, use this repository as `/etc/nixos`, retaining the actual
installer-generated hardware configuration. Add the correct bootloader configuration from
the installation; the repository does not guess BIOS versus UEFI or a boot device.

Edit `site.nix` with collected inventory. Keep `management.configure = false` while retaining
the installer's working networking. If enabling managed static networking, verify all values
and disable conflicting installer NetworkManager/networkd/DHCP definitions explicitly.
`false` does not erase an installed network manager's configuration. Ensure the chosen
management IP is already assigned before binding Incus.

Add your SSH public keys, never a private key. Verify the guest subnet/DHCP/static reservation.
Use `driver = "dir"` unless a reviewed existing ZFS dataset is available. Enable backups only
when independent storage and credentials exist. Set `ready = true` last.

```console
cd /etc/nixos
git add site.nix hardware-configuration.nix
nix flake metadata
find . -name '*.nix' -exec nix-instantiate --parse '{}' ';' >/dev/null
nix eval .#nixosConfigurations.hypervisor.config.system.build.toplevel.drvPath
nix build .#nixosConfigurations.hypervisor.config.system.build.toplevel --out-link result-host
sudo nixos-rebuild test --flake .#hypervisor
```

`test` activates services and firewall rules immediately; it is not a passive preview.
Run it with local console access and a second authenticated SSH session. Verify connectivity,
then persist the generation:

```console
sudo nixos-rebuild switch --flake .#hypervisor
```

Use `nixos-rebuild boot` and activate on reboot when a maintenance window is required.
Rebuilds do not format disks or delete omitted instances. They can still change profile
limits/live networking and restart services; review the diff before each deployment.

Applications are not part of the host derivation. Deploy them as reviewed projects after
installation; see [administration](administration.md#compose-applications).

## Secrets and first boot

Fresh installations keep every host credential as SOPS/age ciphertext, with no manual step:

1. The installer creates the host age identity at `/var/lib/sops-nix/key.txt`
   (mode 0600, directory 0700) and never overwrites an existing one.
2. It writes `machine/secrets/host.yaml`, encrypted to that identity, and sets
   `secrets.enable = true` and `secrets.hostFile = "machine/secrets/host.yaml"`.
   The managed `operator` account starts with an unusable password hash and an
   unset marker until you choose a password in the portal.
3. Credentials entered in the portal (Cockpit operator password, Wi-Fi WPA key,
   restic password and environment, tunnel JSON) are encrypted into the job's
   staged copy of `host.yaml` during review. No plaintext is staged or logged.
   Apply publishes the reviewed ciphertext; rollback restores the previous file.
4. sops-nix decrypts at activation into the paths below and restarts dependants.
5. Every encrypted recovery kit includes the host age identity. Without it,
   `host.yaml` cannot be decrypted on replacement hardware.

| Key in `host.yaml` | Decrypted to | Written by |
|---|---|---|
| `cockpit-operator-password` | `/run/secrets-for-users/…` (SHA-512 crypt hash) | Services → Local operator password |
| `wifi-env` | `/var/lib/nixus-secrets/wifi.env` | Networking → managed Wi-Fi |
| `restic-password`, `restic-environment` | `backup.passwordFile`, `backup.environmentFile` | Backups |
| `cloudflared` | `tunnel.credentialsFile` | Public ingress |

Top-level key names in `host.yaml` stay readable, so the portal can tell which
credentials exist without decrypting anything. Never commit or copy the age
private key into the source tree.

Hosts with `secrets.enable = false` keep the older root-owned files under
`/var/lib/nixus-secrets` (directory 0700, files 0600).

## Deploy changes into the existing VM

Use [reviewed guest deployments](guest-deployments.md) for dependency ordering,
health checks and resumable updates of existing source-owned NixOS guests. The
SSH-based commands below remain alternatives outside that journal.

Importing a newer image changes future creations only. Existing guest disks retain their OS.
Use NixOS deployment over SSH with the same reviewed inventory/repository revision, for example
from the host or a management client with a guest route and authorized SSH key:

```console
nixos-rebuild switch --flake .#apps --target-host root@APPS_IP
```

If networking intentionally permits only the host to reach guest SSH, use an SSH config
`ProxyJump operator@HOST_IP` for the VM. Validate host keys independently. Alternatively,
execute `nixos-rebuild switch --flake <reviewed-flake-reference>#apps` through authenticated
`homelab exec apps -- ...`; that reference must include your completed inventory, not the
unconfigured public template. No browser-terminal keystrokes are needed.

Colmena/deploy-rs add coordinated fleet deployment and rollback health checks; they are
not required for one VM. Ansible is useful for repeatable operations on non-NixOS guests;
use SSH keys or the maintained Incus connection plugin, inventory by names, check mode where
supported and explicit command modules instead of terminal automation. No web task runner
is exposed; SSH, Incus and packaged predefined actions already meet the requirement.

## Cloudflare Tunnel

Set `site.tunnel.enable`, tunnel UUID and application-only ingress, for example after assigning
real reachable addresses:

```nix
tunnel = {
  enable = true;
  uuid = "YOUR-EXISTING-TUNNEL-UUID";
  credentialsFile = "/var/lib/nixus-secrets/cloudflared.json";
  ingress = {
    "photos.example.com" = "http://APPS_IP:2283";
    "git.example.com" = "http://APPS_IP:3000";
    "app.example.com" = "http://APPS_IP:8080";
  };
};
```

These hostname/service strings illustrate syntax, not deployable IPs. Immich and Forgejo are
not installed by this example; deploy their maintained upstream Compose projects separately.
The complete included demo is the app/PostgreSQL/Redis project.

Use a **locally managed** tunnel: Nix owns ingress, including a final `http_status:404`.
Create the tunnel and hostname DNS routes in the Cloudflare control plane once, then deliver
its tunnel-specific JSON through the secret mechanism. The broader account `cert.pem` is not
needed to run an already-created tunnel and is deliberately not installed on the hypervisor.
Cloud account resources cannot be manufactured by an unauthenticated Nix rebuild.

A remotely managed token tunnel instead makes dashboard/API ingress authoritative; do not
combine that mode with these local rules. Use external IaC for Cloudflare resource creation
if you need account-level reproducibility. The native module uses `LoadCredential`, a dynamic
user, boot startup and restart-on-failure; a ten-second retry delay is configured.

No incoming firewall ports are opened for the tunnel. Default NixOS outbound policy permits
Cloudflare connectivity; restrictive egress gateways must allow its documented endpoints on
UDP/TCP 7844 and DNS. Protect application identities with application auth/Cloudflare Access
as appropriate. Never add Incus, SSH, Prometheus or Cockpit hostnames to public ingress.

Sources: [NixOS module](https://github.com/NixOS/nixpkgs/blob/718f670e845328e9c2cecdd832835712b2cbd065/nixos/modules/services/networking/cloudflared.nix),
[locally managed tunnels](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/local-management/),
[sops-nix](https://github.com/Mic92/sops-nix).


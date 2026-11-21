# Install on an existing NixOS system

## Direct clone, build and switch

For a plain installed NixOS server, run:

```console
sudo nix --extra-experimental-features 'nix-command flakes' \
  run github:OmarDardery/Nixus#install
```

The default now installs the full stack. Retries resume automatically; local
console installation needs no SSH key. See [plain NixOS installation](plain-nixos.md)
for supported scope, source updates, Incus adoption, login policy, credential
recovery and diagnostics. The rest of this guide documents the optional web-wizard
workflow, selected explicitly with `--wizard`.

`--wizard` is only for initial onboarding. It refuses an already configured host
before staging source or building the bootstrap system, whose role does not
include hypervisor services. Use the installed portal or `#update` for an existing
host; use `sudo nixus-admin reset-password` from an authorized local/sudo session
for portal account recovery. Pending transaction recovery remains authoritative.

## Portal-first installation

Nixus now includes a bootstrap installer and a self-hosted first-run/settings portal.
The supported starting point is a **fresh conventional Intel/AMD x86_64 NixOS installation**
with working IPv4 networking, `/etc/nixos/configuration.nix` and `hardware-configuration.nix`.
NixOS runs directly on the hardware; Incus uses the Linux KVM subsystem. Installing the
portal alone does not make the machine a complete hypervisor—the reviewed wizard activation does.

Custom flake-only configurations, externally linked module trees, TPM/LUKS enrollment,
root filesystem migration and creating/formatting ZFS pools require an explicit import/storage
plan. The installer fails before activation when it cannot preserve a conventional configuration.
It does not promise to convert every arbitrary existing NixOS desktop/flake automatically.

## Run on the target host

```console
sudo nix --extra-experimental-features 'nix-command flakes' \
  run github:OmarDardery/Nixus#install -- --wizard
```

The packaged installer provides its own runtime tools. Run it on the target
NixOS host. Omit `--wizard` for the default complete installation.

Optional network selection flags:

```console
sudo nix --extra-experimental-features 'nix-command flakes' \
  run github:OmarDardery/Nixus#install -- --wizard --interface enp2s0 --address CURRENT_ASSIGNED_IP --trusted-cidr YOUR_ADMIN_SUBNET
```

Without these flags the installer selects the existing default-route interface, its actual
assigned IPv4 address and its connected subnet. It never invents a physical NIC, host address,
boot device or filesystem UUID. Use explicit flags for multi-uplink/VPN/routed management.
`--address` selects an already assigned address during bootstrap; static changes happen in the UI.
The installer prints the HTTPS URL, one-time initial password and local CA fingerprint.
Keep console access for the first activation.

## What the first switch preserves

1. Saves a root-only complete copy of the original `/etc/nixos` under
   `/var/lib/nixus-admin/original-config` and pins the original OS generation for recovery.
2. Clones the chosen repository/ref into `/var/lib/nixus/config`.
3. Copies the actual `hardware-configuration.nix` and imports a preserved local Nix module tree
   under `installed-system/`. Keeping only the hardware file would lose bootloader settings,
   existing accounts, `system.stateVersion`, and often the management network.
4. Includes only `.nix` modules in that imported tree. Unrelated plaintext files/private keys
   are excluded from the flake source. Configurations importing additional assets/remote modules
   need an import plan; build failure leaves the old installation recoverable. Existing inline
   secrets in Nix source remain Nix source; this tool does not attempt to rewrite arbitrary Nix.
5. Creates a local CA, separate host/application TLS leaf keys and a salted password hash under
   the root-owned runtime state directory. They never enter Git or the Nix store.
6. Reviews and builds the **bootstrap** target through the same Manager/worker
   transaction as full installation. It adds setup/recovery services and the KVM
   module while retaining the installed base. Activation switches the exact
   reviewed closure and arms the independent rollback guard.
7. Renames the original directory to `/etc/nixos.pre-nixus` and points `/etc/nixos` at the managed
   clone. The preserved backup remains root-only. Builds use explicit flake targets.

No disks are partitioned or formatted. No VM or guest bridge is initialized by bootstrap.
The worker restores the preceding profile/generation if activation fails or its
access-confirmation deadline expires. Confirm portal/SSH access from a fresh
connection, or explicitly acknowledge it at the host console, before completing
setup. Rerun with `--wizard` to resume the same initial transaction after a
disconnect; `--resume` is optional. An existing
checkout/configuration is never blindly overwritten. Lost portal passwords can be reset locally
with `sudo nixus-admin reset-password` from a private host terminal. Existing
sessions are rejected after the replacement verifier commits; no UI restart is needed.
The installer does not overwrite a pre-existing Incus database.

## First-run wizard

Verify the CA fingerprint against the installer output **before signing in**. The login page
provides a CA download without authentication; it is a public certificate, not a private key.
The HTTPS certificate chain also includes the local CA. In installer mode the Incus server uses that CA too; existing ACME configuration, if present, retains certificate ownership. Trust it on your administrator devices
only after checking the fingerprint. You can then use ordinary HTTPS for the private portal.

The portal is at `https://HOST_IP:9440` by default. Sign in with the initial password and configure:

- **Network:** preserve the installed uplink or declare a static address/gateway/DNS. Set trusted
  management CIDRs. Select a non-overlapping guest subnet, bridge address and DHCP range.
  “Suggest an unused subnet” proposes a new private range from detected routes; review disconnected
  LAN/VPN networks too. It is a proposal, not a discovered host address.
- **Storage:** choose detected existing filesystem UUIDs and a role. Select no additional disk to
  keep the safe system-filesystem baseline. Root/boot/swap or already-mounted-elsewhere devices,
  duplicate UUIDs, mismatched filesystem types and mount paths that hide files are rejected.
- **Access:** paste an SSH public key for the `operator` account. Existing local accounts remain
  in the imported installation. SSH password login is enabled by default for non-root Linux accounts; Access can select key-only login.
- **Radios:** choose Wi-Fi/Bluetooth on or off. Wi-Fi uses NetworkManager with the iwd backend.
  Existing NetworkManager profiles can remain; an old Nix wpa_supplicant profile requires entering
  its SSID/password in the wizard. WPA personal networks are supported, not enterprise 802.1X.
  Wi-Fi cannot be disabled while it remains the selected management uplink.
- **Host preferences:** host name, time zone, TRIM, Nix store optimisation, setup port and activation
  confirmation window. Updates/reboots stay explicit; there is no automatic image or volume pruning.
- **Backups/tunnel:** optionally configure the independent restic repository/credentials and an
  already-created locally managed Cloudflare Tunnel. Runtime secret inputs stay outside the source.

Click **Build & review configuration**. The server validates the schema and actual inventory,
creates an immutable source snapshot and runs real Nix evaluation/build plus `dry-activate`.
Inspect the setting diff and activation log. Then **Activate reviewed generation** runs
`nixos-rebuild switch` on that exact snapshot. Sign in again if the HTTPS service restarts.
Use the displayed new URL if you changed the IP/port, and click **Confirm access** before the
countdown expires (ten minutes by default after activation completes).

An unapplied candidate can be discarded; this stops its build worker without changing live settings. Only the active reviewed candidate can be activated. The last confirmed change remains available for one-step rollback even if a later build fails.

A persistent systemd guard restores the prior OS profile/settings if activation fails or remains
unconfirmed. It also runs after a reboot. An interrupted activation has a separate maximum activation
window before recovery. Rollback restores managed secret files, TLS leaf identity, NetworkManager
profiles and recorded radio block state as well as the prior configuration. Source drift after a
review blocks activation. Build failures never overwrite the live settings or credentials.

Rollback restores OS/configuration state, not guest/application data or Incus database migrations.
Pool creation, first guest creation and database writes can persist through a rollback. Retry after
a partial first activation preserves that attempt's pool/network identity. Moving initialized pools
or guest address space requires a deliberate migration rather than editing the wizard fields.

## Drives and tool integration

| Role | Declarative result |
|---|---|
| General data | UUID-backed `fileSystems` entry at `/srv/nixus/NAME`; optional read-only mount |
| Primary guest storage | Same mount plus the `guests` directory pool at `MOUNT/incus` |
| Additional Incus pool | Same mount plus a `disk-NAME` pool visible in the Incus UI/CLI |
| Backup staging | Same mount plus offline export staging at `MOUNT/exports` |

Managed mounts use `nofail` and a device timeout so a missing data disk does not trap the host
in an emergency boot without its management UI. Required mounts participate in a storage-readiness
target. Incus and backups additionally use native `RequiresMountsFor`, so the relevant service
fails rather than storing guest/backup data on an unmounted fallback directory. A preseed guard
checks mount points before creating a pool subdirectory. Monitoring/journal show failures.

Incus/backup roles need writable ext4/XFS/Btrfs filesystems. FAT/exFAT/NTFS data mounts are general
file mounts, not recommended guest pools; NTFS is mapped to the kernel ntfs3 driver. Existing
filesystem ownership is preserved. Directory pools still have the quota/snapshot limitations in
the architecture guide. This wizard does not turn a filesystem into a ZFS pool or claim RAID safety.

An initialized Incus pool mount cannot be removed, rebound to another UUID or moved in this UI.
Use an export/restore or supported pool migration procedure first. Snapshot/backup data lives outside
NixOS generations. Shrinking or moving storage needs migration. A backup staging disk alone is not an independent backup.

## Applications

Applications are not part of the host wizard. After setup, manage them on the **Projects**
page: upload original Dockerfile and Compose source, build images offline, and deploy a
reviewed project revision into its own Incus project. Native guests are declared in the
project's `default.nix`. See [administration](administration.md#compose-applications).

The Incus Web UI is at `https://HOST_IP:8443`. Under access settings, enter a device name
and a dedicated bundle passphrase, then choose **Create an Incus browser identity**. Import
the encrypted PKCS#12 file using that passphrase. Restricted identities expire after 90 days;
revoke one by its displayed fingerprint in the native Incus trust list. Browser identity
import is a client-side trust step, not a hand-written Nix configuration change.

## Ongoing use and security boundary

The ordinary forms edit `machine/settings.json` (or legacy `local/settings.json`).
The inventory is checked as typed Nix options under `nixus.settings`; file modules
can override individual options. The portal displays effective values and identifies
file-owned overrides. It does not parse or rewrite arbitrary Nix functions.

The Configuration files page accepts reviewed administrator Nix modules in the
machine module directory. It requires password reauthentication and explicit
acknowledgment of root-equivalent configuration authority. This is trusted system
code, not a sandboxed plugin mechanism. Path/type/size limits and staging protect
the workflow; they cannot make malicious NixOS modules safe. There is no general
shell-command endpoint or arbitrary destination path. See [file modules](file-modules.md).

The HTTPS process runs as an unprivileged `nixus-ui` user. Its root broker accepts only defined
operations over a mode-0660 local UNIX socket. The portal has TLS, a salted PBKDF2 password hash,
rate-limited login, secure HttpOnly/SameSite cookies, idle/hard session expiration, CSRF tokens,
same-origin checks and management hostname/source checks. It supports administrator, operator and viewer portal accounts; configuration and
code changes remain administrator-only. Native Incus/SSH permissions are separate.
It is not a multi-tenant isolation or SSO system. Keep it off public tunnels.

Build/apply run in independent systemd units, so restarting the web process does not abandon the
activation or its recovery guard. Logs are visible in the UI and journal; important operations are
recorded in root-only `/var/lib/nixus-admin/audit.jsonl`. Runtime credential inputs are excluded from the Nix snapshot and job metadata.
Administrator-uploaded source is shown in review and must not contain credentials. Discarded/superseded candidates release their build GC roots and staged
credentials. One-step confirmed recovery remains pinned; obsolete recovery secret copies and older
transaction roots are released after the next successful confirmation. The original installation
generation remains pinned separately for console recovery. The broker/UI are restarted after a switch to load updated runtimes.

Package refresh is a review checkbox: the Nixpkgs stable input advances inside the candidate,
its lock file is built/reviewed and only then becomes live. Repository code updates use the Review page with a full reviewed upstream commit SHA
and password reauthentication. The isolated candidate preserves machine files and records
platform changes before activation; source participates in recovery. No executable code
is blindly pulled on a timer. See [ongoing operations](operations.md).
A monthly service renews local leaf certificates before expiry, reloads the Incus server identity without intentionally stopping guests, and reprovisions the VM identity.

If sops-nix is enabled by an advanced source configuration, it retains ownership of secret
provisioning; conflicting plaintext secret inputs are refused. Ordinary first-run users can use
the root-owned runtime secret files through the wizard without creating an age identity manually.

For diagnostics:

```console
journalctl -u nixus-admin-backend -u nixus-ui -u nixus-rollback-guard
journalctl -u nixus-project-backup -u nginx
systemctl --failed
nixos-rebuild switch --flake /etc/nixos#hypervisor
```

For original-system recovery from a console, inspect `/var/lib/nixus-admin/original-system`,
restore that profile and activate its `bin/switch-to-configuration switch`, then restore
`/etc/nixos.pre-nixus` to `/etc/nixos` after removing only the managed symlink. Guest data is
retained separately. If a console/manual rollback leaves a radio blocked, `rfkill unblock wifi`
restores it; the portal's managed rollback restores its recorded radio state automatically.

## Lightweight defaults and declarative ownership

A new installation starts with Incus, its embedded web UI, the Go setup frontend and root
broker, and a host node exporter. There is no Node.js runtime, SPA build service, Cockpit,
libvirtd, host Docker, Grafana or database for the setup portal. Browser assets are static files
served by the authenticated HTTPS process that is already needed for configuration requests.
Adding BusyBox httpd, Apache httpd or a separate static web server here would add a daemon
without removing that API process. Authentication, TLS and source checks also apply to assets.

No Docker engine, applications VM or application proxy runs on the host. Wi-Fi, Bluetooth,
Cloudflare and backups remain opt-in. Backup protection still
requires configuring an independent destination; the lightweight preset is not a backup policy.

Local metrics collection and Prometheus history are **opt-in** on Host preferences. With both disabled,
Incus live resource views, persistent journal and systemd service health remain available; there
is no local historical database or Prometheus alert evaluation.  Enable history for trend graphs/alert rules, with a default
60-second interval and 14-day retention. External alert delivery still requires a receiver.

Nginx only redirects port 80 to the HTTPS portal. No throughput or RAM benchmark is implied
by these configuration choices. Incus, QEMU and the application workloads dominate
resource requirements; ordinary containers avoid the overhead of an additional guest kernel.

All of these choices flow through typed desired settings into native NixOS modules.  The UI exports desired settings JSON without secret values for review
and backup. After activation the authoritative inputs are the machine settings JSON and modules; back these
up together with the source revision, `flake.lock`, preserved installation modules and separate
secrets. Imported settings must be reviewed for the target machine rather than blindly restored.

Nix declares services, packages, mounts, firewall rules, radios, Compose definitions and desired
Incus resources. Native options are preferred; guarded initialization/reconciliation covers
Incus state and runtime credentials. VM disks, snapshots, volume and database
contents, certificate enrollment and backup contents are mutable state, not reproducible Nix
configuration. Applications are reproducible through published project source and reviewed project
revisions; changes made only in the Incus UI are not declarative.

## Homepage launcher

The overview links to active Incus and Cockpit endpoints, upstream Incus helper scripts
and the Community Scripts catalog, SSH administration, Cloudflare, project guides and source.
Disabled tools link to their configuration page. Management URLs use the currently active address,
not an unsaved edit. Only configured non-wildcard tunnel hostnames become public application links;
this does not test their availability. Prometheus stays private on loopback.

Helper links open upstream documentation; they do not execute installers or establish Nixus
compatibility. See the [quality-of-life roadmap](roadmap.md) for the proposed curated integration.

For guest jobs, account roles, recipes, reviewed platform updates,
local documentation and recovery exports, see [operations](operations.md).

## Focused host portal

The five primary pages are Overview, Host, Backups, Changes and Help. Host tabs
cover Networking, Hardware & storage, Services, Access, System and Advanced. Guest lifecycle, consoles, snapshots,
resources and native guest networking stay in Incus. The legacy guest CLI/API is
retained; it is not a second guest dashboard.

Configure Ethernet host prerequisites in **Host → Networking** and attach guest NICs in
Incus. **Host → Hardware & storage** can declare an exact USB serial alias but does not assign
it or install a workload. Backups has schedule/coverage/group controls and
independent recovery. Overview links to enabled native tools; **Host → Services**
configures optional tools and a packaged upstream helper wizard. Help supplies
copyable commands and upstream credits; its links never execute installers. See
[ownership](ownership.md), [helpers](helpers.md) and [hardware](hardware.md).

## Access confirmation after terminal installation

The direct installer, initial wizard bootstrap, resumed installations and `#update`
share the same Manager/worker review, exact built closure and rollback guard.
After local health checks pass, activation remains **unconfirmed**. Open a new
SSH or Cockpit terminal **after** the new system is ready, or use the physical
host console; verify management access and then run
`sudo nixus-admin config confirm TRANSACTION_ID` in that new session. A
`/dev/pts` session that predates activation cannot confirm. Alternatively,
reconnect to the current HTTPS portal from a non-loopback client, **sign out
and sign in again after activation**, then click **Confirm access**. A previous
browser cookie or a loopback-only portal probe cannot confirm remote access.

The printed deadline applies; without confirmation the independent guard
restores the previous generation. You may request `config rollback` before
expiry if a new session fails. An existing-host installer retry now snapshots
source and installation metadata into the *same* guarded transaction; it does
not publish either during planning. A host generation rollback restores
matching Nixus platform/settings/inventory, not arbitrary guest or app data.

Bootstrap jobs use the fixed `bootstrap` role and preserve `ready=false`; ordinary
host jobs use `hypervisor`. Historical jobs without a role remain hypervisor jobs.
This is transaction metadata, not a settings-schema change or a new deployment
framework. Bootstrap requires addressed management access, preserves physical
networking and can run before any guest subnet is chosen. It cannot enable optional
host services/mounts or downgrade a configured host. Finish confirmation before
reviewing the complete hypervisor configuration in the portal.


### Console-approved first administrator

Every fresh installation opens console-approved enrollment; `--wizard` installs
only the portal first.
Open the portal and verify the management CA fingerprint before approving the
browser. In the host terminal, run `sudo nixus-admin approve-enrollment`
and paste the code displayed by that browser into the prompt. Return to the
same page to set the first portal password, then sign in as `admin`.

Approval expires in ten minutes or on host reboot. Refreshing the page creates
a new code. Existing portal accounts keep their normal login and recovery flow.


On a fresh installation, use **Verify this machine** in the HTTPS portal. An existing local Linux sudo administrator can verify via PAM, or an SSH-key-only administrator can approve the browser code through `sudo nixus-admin approve-enrollment` at a private terminal. Approval is browser-bound and expires after ten minutes or reboot. Then choose your independent Nixus username/password; successful creation signs that browser in normally. Existing installations keep their current accounts and never reopen anonymous first claiming. See [administrator enrollment](administration.md#verify-this-machine-before-first-admin-creation) for policy, rate limits and recovery details.

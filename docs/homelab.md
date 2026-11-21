# Cockpit, Incus and Nixus projects

Cockpit supplies the **host** terminal, services and journal. Incus runs every
workload: system containers, VMs and OCI application containers. Compose
applications are deployed into their own Incus project with `incus-compose`,
built offline from your original Dockerfile and Compose files. No Docker daemon
or separate applications VM is used, and Docker never runs on the hypervisor.

For a plain NixOS server, use the [single-command workflow](plain-nixos.md).
The steps below enable the optional tools from the host console.

## Enable and activate

1. Upgrade to the reviewed source revision. Preserve the machine directory, Incus
   database, storage pools, existing guests and hardware configuration.
2. In **Host → Services**, enable Cockpit. This stages desired settings;
   file-owned settings are retained. Laptop power policy is separate under
   **Host → System**; enabling tools does not change it.
3. Enter a separate **local operator password for Cockpit** (16–256 characters).
4. Build and review, activate, verify access, then confirm. When you enroll the
   local account, check the automatic `cockpit.managePassword` change in the review.
5. Open the active homepage links. Use the detected address printed by
   installation (shown as `HOST_IP` below):

   | Interface | URL | Authentication |
   |---|---|---|
   | Incus | `https://HOST_IP:8443` | Enrolled Incus browser certificate |
   | Cockpit | `https://HOST_IP:9090` | Linux `operator` account or existing non-root local account |
   | Nixus console | `https://HOST_IP:9440` | Nixus portal account |

Management ports are configurable and collision-checked. Homepage links use the
observed management address, falling back to active settings.

For file configuration, upload the following as `homelab/management.nix` or copy
`examples/homelab/management.nix` to `machine/modules/homelab/management.nix`:

```nix
{ ... }: {
  nixus.settings = {
    cockpit.enable = true;
    maintenance.laptopMode = true;
  };
}
```

Use the [reviewed module workflow](file-modules.md). A direct rebuild uses
`sudo nixos-rebuild switch --flake path:/etc/nixos#hypervisor` from that installation
root. Direct switches do not arm portal confirmation recovery.

## Host login and commands

Cockpit is installed natively and authenticates through PAM. SSH password login is
enabled by default, and the same Linux password works for SSH and Cockpit. Select
key-only SSH under Access if needed. Root SSH and root web login remain disabled.
The operator is a trusted infrastructure administrator with sudo access. Portal
roles, Incus identities and Linux users remain separate.

The portal hashes the Linux password before staging it. Only a salted SHA-512
hash enters its root-only runtime secret file; neither the plaintext nor the hash
enters the Nix source or store. Guarded activation preserves the old local operator
credential for recovery, including locking a newly enrolled account on rollback.
The encrypted-secret kit includes the managed hash. sops-nix users instead supply
`cockpit-operator-password` in the encrypted host file and set
`cockpit.managePassword = true`.

Alternatively, keep `managePassword = false` and use an existing local-account
password, or run `sudo passwd operator` from the console or SSH. Manual password
changes are outside the portal transaction. On immutable-user setups, declare the
local account and password through the preserved NixOS configuration.

Cockpit uses the local management CA while the Nixus setup service is enabled;
verify its fingerprint from the host console. A manual setup without the portal
uses Cockpit's own certificate. Reach management only over a trusted LAN or
private VPN. Cloudflare ingress rejects management ports, including a customized
Cockpit port.

Use Cockpit's Terminal for `sudo incus list --all-projects`, journals and reviewed
Nix rebuilds. Use Incus consoles for guest commands.

## Applications

Applications live in **Projects** in the Nixus console:

- **Compose apps:** upload the original Dockerfile, build context and Compose
  file, review and publish the exact bytes, build and import the images offline,
  then deploy a reviewed project revision that links that source. See
  [OCI source uploads](oci-source-intake.md).
- **Native guests:** declare instances, volumes and USB devices in the project's
  `default.nix`. A reviewed deployment creates or reconciles them. See
  `examples/project-workspace/README.md`.

Each Incus instance and volume has exactly one owner: the native reconciler or
`incus-compose`, never both. Removing a declaration keeps the resource and its
data. Secrets go through the SOPS project secrets UI, never into Nix files.

## Keep the working services and network

The host management address and private guest bridge are separate networks. NAT
guests do not acquire `192.168.1.x` addresses automatically. Do not assign the
host's management address to a guest. Do not remap an initialized Incus subnet,
pool or project merely to match a fresh-install example.

For directly addressed LAN guests, use a reviewed **wired** bridge, VLAN
or routed network, and reserve distinct free addresses after checking router
exclusions. Moving host addressing onto a bridge is a network migration;
retain console access and confirmation recovery. A private NAT bridge does
not automatically expose guest services to the LAN. Validate routing,
firewall rules, DNS and application reachability before changing router
settings. See [networking](networking.md).

Preserve all existing workloads and their data volumes, credentials and
application URLs. Guests outside declared ownership remain Incus-managed;
Nixus never adopts them silently.

For hardware-backed workloads, identify stable `/dev/serial/by-id/...` paths
or declared device aliases under **Hardware & Disks**, then attach only the
selected device to the correct guest with reviewed permissions. Back up
application configuration separately. Enabling management tools never attaches
peripherals or reinstalls third-party applications.

## Verification

Test the following before retiring the previous system:

- Cockpit login, terminal and sudo.
- Incus guest consoles.
- A deployed Compose project and its persistent volume.
- Rejection from an untrusted client.
- Access after a host reboot.
- Lid-closed operation.
- Application data and an off-host restore.

See [commissioning](commissioning.md).

New-name archive or snapshot restores reset generated NIC MAC addresses while
stopped, so they can coexist with the original. Explicit NIC MACs and fixed
addresses are retained for administrator review; conflicting identities block
release from quarantine. The original guest and backup archive remain unchanged.

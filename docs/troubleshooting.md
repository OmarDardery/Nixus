# Troubleshooting

## Ethernet is up but there is no management address or web page

A physical Ethernet port can be `UP` while its address belongs to a bridge. If
Nixus still selects the port, identity generation fails and dependent services,
including Incus, cannot start. Saved profiles with autoconnect disabled also
explain a bridge disappearing after reload or reboot.

Use the [console recovery command](install.md).
It repairs the existing connection and feeds the corrected selection through the
normal guarded main update. Do not disable the firewall, delete Incus data, assign
a guessed static address or reboot an unconfirmed test activation to hide this
failure. Confirm portal/SSH access and inspect the boot-default notice first.

Start with the symptom. Keep the original error. Resist the traditional homelab
ritual of changing six things and discovering none of them was the problem.

## Start here: collect the useful evidence

```sh
sudo nixus doctor
systemctl --failed
```

`doctor` checks the actual management address and enabled HTTPS interfaces.
Its concise report is saved at `/var/lib/nixus-admin/last-health.json`.

The installer reports its original failure separately from rollback failures.
Its report is `/var/lib/nixus-admin/installation-failure.json`; detailed build
logs are under `/var/lib/nixus-admin/jobs/<transaction-id>/build.log`.
Review logs before sharing them; do not publish passwords, tokens or private keys.

## Every management check times out against the host's own address

Read the saved result before running another check:

```sh
sudo cat /var/lib/nixus-admin/last-health.json
sudo journalctl -b -u nixus-management-health.service --no-pager -n 60
```

An earlier firewall configuration forced `trustedInterfaces = [ ]`, removing
NixOS's loopback allowance. Connections from the host to its own LAN address
arrive through `lo`; all six HTTPS probes could time out even with listeners
running. Current Nixus trusts only `lo`, while retaining the LAN source/interface
restrictions and guest isolation. Update with the installation command after the
fix is available. Do not disable the firewall or skip health checks.

If the problem persists, check `ip -4 address`, `ip -4 route get HOST_IP` and
`sudo nft list ruleset`. Missing addresses, custom firewall rules and service
failures still need their own diagnosis. A failed activation rolls back, so
listener checks after rollback describe the restored system.

## Cockpit works only after a manual restart

First collect the boot evidence, before restarting anything:

```sh
sudo systemctl status cockpit.socket cockpit.service nixus-management-identity.service
sudo journalctl -b -u cockpit.socket -u cockpit.service -u nixus-management-identity.service --no-pager
sudo systemctl status nixus-management-health.service
sudo journalctl -b -u nixus-management-health.service --no-pager
ip -4 address
```

Current Nixus listens on `0.0.0.0` for Cockpit, rather than binding the socket to
a DHCP address that may not exist yet. The activated service waits for the
management TLS identity and exact WebSocket origins. Failed Cockpit workers retry;
the boot health unit checks enabled interfaces and retries readiness failures.

If the journal still shows Cockpit binding to an old address such as
`192.168.1.9`, check the active configuration and any local overrides:

```sh
systemctl cat cockpit.socket
systemctl cat cockpit.service
```

Update using the installation command in the [install guide](install.md),
then verify `doctor`, login and the Cockpit terminal after a reboot. Do not add
network-online dependencies to `cockpit.socket`: early socket ordering can create
a boot cycle. The service waits for identity preparation instead.

An inactive `cockpit.service` after an idle timeout can be normal: the socket
starts it on demand. A failed socket, failed requests or an unusable terminal is not.

## The URL says .9, but I wanted .240

The installer preserves working addressing. Keeping DHCP does not assign a static
address, regardless of how confidently it was written in a plan.

```sh
ip -4 address
ip -4 route
sudo nixus doctor
```

Use the actual address in the installer output. Reserve your preferred address
in the router, or make a reviewed static-network change in Nixus with console
access available. Do not copy example NIC names or guest addresses into your host.

Default interfaces use `https://HOST_IP:9440` (Nixus), `:8443` (Incus) and `:9090`
(Cockpit). Use the reported or configured port.

## SSH or Cockpit rejects my password

SSH and Cockpit use **Linux accounts**, not the Nixus portal password. Root SSH and root Cockpit login are disabled. Try your existing
non-root administrator account or the verified `operator` credential printed by
the installer.

```sh
ssh operator@HOST_IP
```

Password SSH is enabled by default. If you explicitly selected key-only access,
enroll your **laptop's public key** through a local host terminal:

```sh
sudo nixus enroll-key /path/to/laptop.pub
```

Key enrollment leaves the rollback guard armed. Open a new SSH session using
the enrolled key, verify access, then run the printed
`sudo nixus-admin config confirm TRANSACTION_ID` command from that session.
The portal can also confirm the pending transaction. If access fails, leave it
unconfirmed so the deadline restores the previous generation.

A key generated on the server does not authorize your laptop. Check **Access**
for the password-login policy. A locked Linux account still needs a usable password;
enabling password authentication alone does not create one.

## Installation stopped halfway through

Run the **same command** again:

```sh
sudo nix --extra-experimental-features 'nix-command flakes' \
  run github:OmarDardery/Nixus#install
```

Active transactions are reattached; interrupted recovery is completed before a
new attempt. Credentials survive failed activation. You do not normally need
`--resume`, a fresh clone or an improvised database cleanup.

If the installer reports locally edited platform files, it preserves them and
skips the source update. Inspect the listed edits; move intended configuration
into `machine/modules/` before reviewing an update. Use `--no-update` only when
you deliberately want to retain the current platform source.

## An existing Incus database blocks installation

Select the adoption workflow.
The installer inventories the host and backs up guests and custom volumes before
using a separate Nixus bridge/pool. Interactive runs ask; unattended runs need
`--adopt-incus`.

Existing clusters and an unrelated `lab` project require an explicit migration
plan. Never delete the Incus database to get past this check. It is not a cache.

## Incus works, but another interface is broken

Incus being reachable does not prove Cockpit or Nixus is ready.

```sh
sudo nixus doctor
sudo systemctl status nixus-ui.service nixus-admin-backend.service nginx.service
```

For a project application, check its Incus project and the deployment journal:

```sh
sudo incus list --all-projects
sudo nixus-admin projects status
```

The **Apps** page in the console shows each instance's status and a bounded
read-only log. A failed deployment stays `partial` with its resources untouched;
re-review and resume it rather than deleting instances.

## The browser does not trust the certificate

Private management uses a locally generated CA. Verify its fingerprint against
the host console before trusting that CA on a client. Use the detected address
from installation; an old DHCP address can also cause a hostname mismatch.

The public documentation site uses GitHub Pages HTTPS and is a separate service.
See [website hosting](dev/website.md) for public-domain certificate and DNS problems.

## Rollback failed too

Treat the original activation error and `rollbackError` as separate failures.
Keep both reports and use a local console. Current recovery skips absent services
and NetworkManager UUIDs that no longer exist, but OS rollback cannot restore
Incus schema or guest database contents. Follow the [recovery guide](backups.md)
before attempting manual state changes.

# Start with Nixus

## Port 80 and management shortcuts

Open `http://HOST_IP/` from a trusted LAN client. The lightweight port-80
entrypoint sends an HTTP 308 redirect to `https://HOST_IP:9440/` (or your
configured Nixus HTTPS port). **Authentication and session cookies are
never served over HTTP.** Keep using the Nixus-generated TLS identity and
verify its fingerprint on initial enrollment.

The portal Overview and sidebar link to the enabled Incus UI (:8443)
and Cockpit (configured port, normally :9090).
Disabled or unconfigured services are not advertised as live. The
**Help** page includes a copy-only homelab cheatsheet.
Port 80 belongs to the *Nixus host IP*; a Mainsail server inside a
separate Incus guest may independently listen on port 80 on its own IP.

The port-80 listener uses Nginx on the host management interface. Do not
install a second host web server that also binds 0.0.0.0:80. After an
upgrade, run `sudo nixus doctor` and check the HTTP-entry redirect
result; the recovery guard still protects unconfirmed configuration
switches. Do not expose management ports through Cloudflare tunnels.

For an installed NixOS server without a desktop, run:

```sh
sudo nix --extra-experimental-features 'nix-command flakes' \
  run github:OmarDardery/Nixus#install
```

The command installs the full stack with safe defaults (Incus and its UI,
Cockpit, the console and the Nixus portal) without asking questions, then hands
off to the browser: open the printed portal URL and approve its code with
`sudo nixus-admin approve-enrollment`. Use `--interactive` for a terminal
interview, `--answers /root/answers.json` for headless choices, or `--plan-only`
to preview without publishing. Answers files contain **no secrets**.
See [the generic homelab scenario](home-server-scenario.md) for Incus guests,
optional device passthrough, Compose applications and backup/restore checks.

Use the same command after an interrupted attempt. Local console installation
does not require an SSH key. Follow [plain NixOS installation](plain-nixos.md)
for adoption, key enrollment, credential recovery and diagnostics.

SSH password login works for non-root Linux accounts. Use your existing Linux
password. For managed operator access, choose its persistent password under
**Host → Services** in the portal and review/activate the change. For unmanaged
accounts, use `sudo passwd operator` from an authorized host terminal. The installer
never prints a password. The host
disables desktop startup and suspend/hibernation. After reboot, run
`sudo nixus doctor` to check the management stack.

Open Incus from the portal and enroll its browser certificate. Create your first
container or VM in Incus. For application helpers, run `sudo nixus-helpers doctor`
then select a reviewed helper from `nixus-helpers list` on the host terminal.
Review [networking](networking.md) before exposing LAN services.

Configure independent backups under Recovery and perform an isolated restore.
The [trial checklist](trial.md) covers reboot, networking, devices and rollback.
Advanced settings, Nix modules, optional integrations and maintenance remain in
the [operations guide](operations.md).


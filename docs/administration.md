# Administration

## Native service sessions

Nixus, Incus and Cockpit authenticate separately. Browsers share cookies across
ports, so the Nixus session cookie is host-only, `Secure`, `HttpOnly` and
`SameSite=Strict`, and no other service receives it through a Nixus proxy.

## Commands, docs and community resources

Open **Help** in the Nixus host console for copyable platform updates,
package-refresh reviews, health checks, guest examples and community helper
commands. Each example says where to run it. Copying never executes a command or
creates a guest from the browser. Application wizards run interactively in the host
terminal.

The same section groups Nixus guides, upstream documentation and community resources
by project. Incus helpers, Cockpit plugins and Compose examples are labeled separately. Optional backup, secret, ingress and monitoring
references are under the expanded resources list. Community compatibility and
Nixus qualification remain separate.

## Signing in

The console is single-user. Sign in with a Linux account that has sudo; the
root broker checks the password through PAM (`nixus-enrollment` service) and
the sudo rights. There are no console-only accounts, roles or enrollment codes.
A forgotten password is a Linux password: reset it with `passwd`.

Passwords never appear in argv, public output, operation records or the Nix
store. Five failed sign-ins from one address lock that address out for five
minutes. Privileged builds and secret changes ask for the password again.

## Management HTTPS transport and hostile-client limits

The management HTTPS port is a **private trusted-LAN service**, not an
Internet-facing web application. The portal enforces the declared source CIDRs,
a validated Host, exact Origin on mutations, CSRF for authenticated changes,
HttpOnly/Secure/SameSite session cookies, password attempt throttling, idle
session expiry (30 minutes) and absolute session expiry (8 hours). TLS 1.0/1.1,
compression and plaintext portal authentication are disabled; TLS 1.2 is the
minimum. Validate the management certificate/CA or its fingerprint before login.

The existing stdlib HTTP server is constrained to **32 concurrent client
threads**, a 16 KiB aggregate header budget, a 4 KiB request line, a 256 KiB
JSON body, a 15-second **total header-read deadline**, a 30-second **total
body-read deadline**, and a 20-second socket idle/write timeout. Read budgets
are wall-clock limits, so trickling a byte before each idle timeout cannot
monopolize all worker slots indefinitely. Accepted POST requests require one
unambiguous length; GET/other requests reject bodies, duplicate
Content-Length, Transfer-Encoding, ambiguous request targets and Expect:
100-continue. An overloaded connection is dropped before a worker is created.
The UI service additionally has a 96-task and 512 MiB systemd cgroup budget
and a 1,024-FD soft/hard service limit. Root broker operations are separate
and not cut short by header/body-read timers.

Bad HTTP framing returns fixed generic errors without echoing submitted
Authorization, Cookie or body content. Interrupted connections may close
without a response. Normal browser imports, login and one-time certificate
downloads remain authenticated; do not expose their traffic to support logs.
Use the actual `nixus-ui` unit, HTTPS port and certificate when diagnosing
clients; no reverse-proxy forwarding or arbitrary internet ingress is assumed.

Validation runs socket-level malformed/duplicate length, header overflow,
trickle, worker saturation, modern/legacy TLS, real NixOS portal CSRF and
trusted-CIDR checks. This does **not** establish external penetration-test
coverage or qualify an internet-exposed deployment; record client-specific
TLS/import smoke testing before calling a remote setup supported.

## SSH and Incus CLI

The `operator` account accepts Linux passwords by default and optional declared SSH keys. Root SSH login is disabled. It may use sudo for infrastructure
administration. Neither ordinary users nor `operator` receive an unrestricted Incus/Docker
socket group automatically. Sudo-all is intentional for the trusted infrastructure operator;
use separate accounts/project-scoped Incus identities for less-trusted users.

```console
ssh operator@HOST_IP
sudo homelab list
sudo homelab exec apps -- systemctl --failed
sudo homelab exec apps
sudo homelab exec-many apps,web -- df -h
sudo homelab action apps disk
sudo homelab restart apps
```

`exec` without a command opens `/bin/sh`. With a command it forwards argument vectors,
stdout/stderr and the actual guest exit status. `exec-many` runs sequentially and returns
nonzero if any command fails. Only the explicit `action` whitelist supplies predefined commands.
No unauthenticated command execution server is installed.

For a trusted client, install the packaged helper with this flake's `packages.x86_64-linux.homelab`
or add the derivation to a Nix/Home Manager package list. A non-Nix client can use native `incus`
directly. Enroll a separate client certificate rather than sharing the host administrator identity:

```console
# On host; generated token is sensitive and short-lived, do not put in Git or chat logs.
sudo incus config trust add laptop
# On trusted client, use the token or endpoint as prompted; verify the server fingerprint.
incus remote add labserver https://HOST_IP:8443
incus --project lab list labserver:
incus --project lab exec labserver:apps -- uname -a
```

Confirm the displayed server TLS fingerprint through the physical console or independent
trusted SSH connection before accepting it. Tokens bootstrap certificate trust; normal operations
use authenticated TLS. An unrestricted certificate is host-root-equivalent. Use Incus restricted
project certificates/authorization for delegated users; review the version's supported controls.
Revoke a lost client with `incus config trust list` / `incus config trust remove FINGERPRINT`.

Default `/etc/nixus/client.json` targets the local host and project `lab`. On a client, set
`HOMELAB_CONFIG` to a JSON file such as:

```json
{
  "remote": "labserver",
  "project": "lab",
  "appsInstance": "apps",
  "exportDirectory": "/home/USER/nixus-exports",
  "aliases": { "100": "web", "105": "database" }
}
```

Those numeric aliases are examples, not migrated instances. Remote options also work directly:
`homelab --remote labserver --project lab list`.
Audit records include uid, action, target, duration and exit code through syslog. They deliberately
exclude arbitrary command arguments/output that might contain secrets. These records are not an
immutable privileged-session recorder; retain central logs if tamper resistance is required.
Native Incus/UI actions bypass this helper; Incus lifecycle events and the host journal complement it.

## Incus Web UI

Browse `https://HOST_IP:8443` only from a trusted management source. Incus generates a server
TLS key/certificate under `/var/lib/incus`; preserve it securely or re-verify fingerprints after
reinstallation. Certificate rotation must be planned. Optionally configure the native
`virtualisation.incus.useACMEHost` with a real DNS/ACME certificate; no public management port is needed.

In the Nixus portal, open **Host → Access**. Enter a device name, a dedicated
bundle import passphrase (16–256 characters), and your current Nixus password.
The default identity manages only the `lab` project and lasts 90 days. The advanced
unrestricted checkbox explicitly grants Incus host administration; it requires the
same fresh password check and a separate acknowledgement in the API. Use it only
for a trusted host administrator. Incus authentication remains independent of your
Nixus portal session; no blanket CA trust is installed.

The portal generates an ECDSA P-384 client identity with client-authentication EKU,
digital-signature key usage and `CA:FALSE`. It registers only the public certificate
and offers the encrypted PKCS#12 bundle once, in the issuing browser session, for
two minutes. JSON contains fingerprint, scope and expiry metadata, never the key,
bundle or import passphrase. The passphrase goes through protected request/stdin
channels and is never returned separately. A **Claim pending download** button lets
the same session recover a lost receipt. A consumed or expired download cannot be
replayed, including after a broken connection. Logout/revocation drops pending
material; encrypted bytes live only in frontend memory, with expiry enforced on
claim and stale-buffer removal on subsequent requests or process shutdown.

Import the `.p12` using your dedicated bundle passphrase:

- Firefox: Settings → Privacy & Security → Certificates → View Certificates →
  Your Certificates → Import.
- Chromium: Settings → Privacy and security → Security → Manage certificates, or
  the operating system certificate manager used by that Chromium build.

Open the Incus HTTPS endpoint, select this browser identity and switch to the
**lab** project. Independently verify the server TLS fingerprint. Server trust does
not authorize the browser as an administrator. Supported browser/OS import stores
and selection dialogs must be qualified on the actual client versions in use.

Use **Refresh browser identities** to view Nixus-owned fingerprints, their actual
Incus project restrictions, expiration and trust status. **Renew** creates a new
identity and encrypted bundle; the previous identity stays trusted until explicitly
revoked or its disclosed expiration. **Revoke** requires your current Nixus
password and removes only the selected owned fingerprint through Incus trust APIs.
It also invalidates any pending portal download. The existing guard removes expired
Nixus-owned trust; unrelated and older external trust entries are never adopted
or removed automatically. Manage legacy/external certificates through Incus itself.
The separate encrypted recovery kit preserves the root ownership registry;
configuration-only exports and support metadata do not carry browser keys or bundles.

If download/import is cancelled, a timeout occurs, or the broker restarts, inspect
the identity list before retrying. Ownership intent is durable before Incus mutation,
so even uncertain registration remains individually visible/revocable. Private keys
are confined to root-only `/run/nixus-browser` directories and cleaned on normal
success/failure. The existing locked guard removes crash remnants older than five
minutes; reboot clears `/run`. Guard failures are health findings, not silent cleanup.

For local recovery, inspect `sudo incus config trust list` and revoke a verified
full fingerprint with `sudo incus config trust remove FINGERPRINT`. Do not remove
other operators' trust. Browser bundle renewal/revocation does not change Linux,
Nixus portal, or application passwords.

The Go and HTTPS tests cover cryptography, failure cleanup, ownership, reauthentication,
CSRF/session binding and single-claim races. The real Incus fixture checks TLS 1.3,
lab mutations, rejection of other-project/global mutations, explicit unrestricted
scope, revocation and owned expiration while preserving pre-existing trust. Passing
those fixtures does not prove a browser's native import dialog or certificate
selection UI. Record Firefox/Chromium versions, OS store, import, lab selection,
expiry and revoke smoke results before claiming that client combination qualified.


Use Incus for containers, VMs, image templates, limits, devices, volumes, networks and snapshots.
For a UI-created guest, runtime state belongs to Incus until deliberately adopted. Adoption
requires reviewing its full configuration and explicitly setting `user.nixus.managed=true`;
the reconciler refuses a name collision without that marker. A marker is authorization, not
an ownership proof against someone who already has root access.

Create a container from an image by adding a `site.instances` declaration with `name`, `project`,
`image`, `type`, `profiles`, `config`, `devices`. Use a full immutable image fingerprint for
repeatable initial root filesystems. Floating `images:debian/13`-style aliases track a moving image.
Images are templates; they do not restore current guest data. `base` provides resource limits,
root disk/NIC and daily snapshots with seven-day expiry. Guest-specific device definitions
must contain complete replacement devices, not partial profile patches.

Example shape (replace fingerprint and reserved IP before enabling):

```nix
instances = [ {
  name = "utility"; project = "lab"; type = "container";
  image = "images:FULL-IMAGE-FINGERPRINT";
  profiles = [ "base" ];
  config = { "limits.cpu" = "2"; "limits.memory" = "1GiB"; };
  devices.eth0 = {
    type = "nic"; name = "eth0"; network = "incusbr0";
    "ipv4.address" = "CHOSEN-GUEST-IP";
  };
} ];
```

Unprivileged Linux containers are the default. NixOS system containers additionally need the
supported NixOS image and `security.nesting=true`; do not substitute a privileged container.
Full VMs need a bootable VM image and KVM. Resizing disks upward and changing limits is supported;
shrinking disks requires a separate migration/recovery procedure. Deleting a declaration never
means deleting data. Explicit deletion uses authenticated `incus delete` after a reviewed backup.

## Compose applications

Compose applications are managed on the **Apps** page and run as Incus OCI
containers in their own Nixus-owned Incus project; there is no Docker daemon or
applications VM. The workflow is:

1. Upload the original Dockerfile, build context and Compose file; review the
   SHA-256 manifest and publish the exact bytes.
2. Review and run the offline image build. Images are imported into the project
   with verified fingerprints.
3. In a reviewed project revision, set `backend = "incus-compose"` and link the
   exact published source revision, then deploy it.

Named volumes are Incus custom volumes and survive redeployments; Nixus never
removes volumes. Runtime secrets use the SOPS project secrets UI. Each Incus
project has one owner, so do not also manage Compose services by hand with
`incus-compose`. Pin base images by digest for reproducible rebuilds, and review
security updates regularly.

## Logs and monitoring

```console
journalctl -u incus -u incus-preseed -u nixus-instances --since today
journalctl -u nixus-incus-audit --since today
journalctl -t nixus
systemctl --failed
sudo incus info NAME --project PROJECT --show-log
sudo homelab logs demo
sudo nft list ruleset
sudo incus network show incusbr0
sudo incus storage show guests
```

Forward host TCP 9091 over SSH to inspect Prometheus (`ssh -L 9091:127.0.0.1:9091 operator@HOST_IP`).
Port 9090 remains available for Cockpit; history and Cockpit can be enabled together.
Only loopback exposes Prometheus and the host node exporter. Incus metrics are fetched through
its authenticated local UNIX socket into node-exporter textfiles. The VM node exporter is reached
by the host bridge IP; other guest monitoring requires enabling/configuring an exporter in that guest.
Incus UI/metrics supply per-instance CPU, memory, disk and network counters; node exporter supplies
host and VM OS metrics. Journal storage is persistent and size/retention bounded.

Prometheus alert rules cover missing targets, low disk space, failed units and stale backups.
There is no configured external Alertmanager receiver: alerts/local failure logs are not a promise
of a phone/email notification. Add your real receiver and runtime credentials before relying on
unattended alert delivery. Logs are not shipped to a remote collector by default.

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




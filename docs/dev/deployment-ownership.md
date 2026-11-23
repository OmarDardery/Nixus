# Deployment ownership

Nixus is a reviewed configuration and environment UI around Incus. It keeps
source approval, ownership checks and recovery records; maintained runtimes own
the actual deployment mechanisms.

| Capability | Mechanism |
|---|---|
| Containers, VMs, resources, devices, storage, image import/export | Incus API/CLI |
| Compose parsing, dependencies, image pulls/builds, service creation and recreation | Pinned incus-compose; Buildah for Dockerfiles |
| Restart policy and declared health checks | Upstream shared `ic-healthd`, digest pinned to the same Compose release |
| Private addresses, DHCP, single-network service DNS, NAT | Incus auto-allocated external app bridges and native dnsmasq |
| Environment changes | Incus `environment.*`, scoped by existing secret bindings; native empty-value/unset semantics |
| Host settings and activation | NixOS modules and generation/rollback tooling |
| Backup storage, encryption and retention | Restic; Incus exports provide the offline guest archives |
| Tunnel routing and transport | Cloudflare dashboard and official cloudflared |

The shared controller runs in the upstream `incus-compose` project. Its client
certificate has host-wide Incus authority: treat it as host infrastructure.
The local socket deployment supplies the controller an explicit reachable API
URL, using the allocated bridge gateway for wildcard listeners and the actual
configured HTTPS port. A loopback-only listener fails with an actionable error.
Only its dedicated `icompose0` bridge gets DHCP/DNS and authenticated Incus API
input access. Ordinary `nxa-*` app bridges retain management isolation. Do not
attach untrusted workloads to the controller bridge/project. Nixus does not add
a second health scheduler or grant app containers access to the host socket.

The UI's Stop and backup/restore lifecycle use upstream's stop-intent marker so
healthd does not undo deliberate downtime. Cold exports journal the original
marker before stopping, restore it after restarting, and retain the journal if
recovery fails. A restored archive also has its temporary backup marker removed
or reset from the original inventory before starting.

Updates use upstream `up --recreate` with explicit service names, preserving
named volumes and shared infrastructure. Nixus retains revision/source approval
and checks ownership before invoking it. Existing apps adopt the new startup
bindings and native restart settings on their next reviewed deployment; the
runtime version marker makes this migration explicit.

Custom orchestration remains for cross-system approval, scoped secret delivery,
backup consistency groups and durable interruption recovery. Incus does not
supply those application-level policies. Physical recovery and passthrough
qualification still need the real hardware commissioning checks.

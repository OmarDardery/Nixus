# Deployment ownership

Nixus is a reviewed configuration and environment UI around Incus. It keeps
source approval, ownership checks and recovery records; maintained runtimes own
the actual deployment mechanisms.

| Capability | Mechanism |
|---|---|
| Containers, VMs, resources, devices, storage, image import/export | Incus API/CLI |
| Compose parsing, dependencies, image pulls/builds, service creation and recreation | Pinned incus-compose; Buildah for Dockerfiles |
| Restart policy and declared health checks | Upstream shared `ic-healthd`, digest pinned to the same Compose release |
| Private addresses, DHCP, single-network service DNS, NAT | Native incus-compose networks with Incus DHCP/NAT and upstream `ic-dns` service discovery |
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
input access. Ordinary Compose app bridges retain management isolation. Do not
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
bindings, per-service secret mounts and native restart settings on their next reviewed deployment; the
runtime version marker makes this migration explicit.

Custom orchestration remains for cross-system approval, scoped secret delivery,
backup consistency groups and durable interruption recovery. Incus does not
supply those application-level policies. Physical recovery and passthrough
qualification still need the real hardware commissioning checks.

Upstream prefetches its health, DNS and init/sleep tools even for apps with
`--no-dns`. All three official images are pinned to release digests. Use the
upstream `INCUS_COMPOSE_HEALTHD_IMAGE`, `INCUS_COMPOSE_DNS_IMAGE` and
`INCUS_COMPOSE_SLEEP_IMAGE` environment variables for registry mirrors; Nixus
forwards them to deployment/update workers. The offline VM fixture supplies all
three official tools locally, including for commands invoked outside the broker.

The pinned Incus LTS preseed schema does not accept ACL definitions. Nixus
applies its reserved guest ACL through the native Incus API before preseed
attaches it to the bridge, checking ownership/drift and conditional ETags.
Compose creates app networks and their ACLs itself. Host forwarding filtering
is disabled; default-reject native ACLs with explicit allows implement private
network isolation without competing host firewall or address allocation code.

The control bridge is bootstrapped with native Incus preseed but excluded from
Nixus’s source-owned drift inventory: Compose adjusts its DHCP and resolver
settings. These native changes must not block subsequent host rebuilds. Native
ACL definitions are included in encrypted exports and restored before networks
that reference them; conflicting existing policy is refused. Cold restore
imports data and materializes secrets, then asks for a reviewed app redeploy
to rebuild images and reestablish the shared runtime controllers on the new host.

For a private or local helper registry, also configure it as a native Incus OCI
remote in `/etc/incus/config.yml` (including its protocol and credentials as
required). The containers registry file configures Buildah/Skopeo; it does not
register a remote with incus-compose. Production TLS policy stays native to
those tools; the VM fixture explicitly uses HTTP only for its loopback mirror.

During a reviewed upgrade, instances with the old Nixus-forced service names
are retired through `incus-compose down` while preserving volumes, networks
and controllers. Explicit source `container_name` values are retained. New
instances use upstream naming. Nixus verifies retirement through the native
inventory before creating replacements, because an upstream `down` may log
deletion failures while returning success. Shared `ic-dns`/`ic-healthd` instances are host
infrastructure and excluded from guest exports; their credentials are issued
by upstream on deployment to the replacement host.

# Networking and Cloudflare Tunnel audit

Base: `89747c685c576d63e2004dbf8425f5132aabea91`.
Date: 2026-11-23. This review did not access or modify the deployed Nixus host.

## Observed Cloudflare state

Read-only API inspection of the requested `aiostreams` tunnel found it remotely
managed, status `down`, with an empty result from the dedicated connections
endpoint. Its route targets `http://aiostreams:3000`, followed by an HTTP 404
catch-all. No token was retrieved, rotated or written. No Cloudflare resource
was modified.

This establishes absence of registered connectors at observation time, not its
cause. A wrong origin normally produces an origin error after the connector is
registered; it does not by itself explain zero connector sessions. Host logs
and same-network connectivity evidence are needed to separate process startup,
missing/wrong token, resolver failure and blocked outbound port 7844. Opening
inbound router ports is not the remedy for outbound Tunnel connections.

## Findings and changes

| Priority | Finding | Change |
|---|---|---|
| High | The OCI VM fixture imports the bootstrap role, so its successful app DNS checks do not exercise `modules/networking.nix` or `filterForward = true`. | Add a separate production-firewall VM check to CI. It uses real Incus bridges and isolated network namespaces to test DHCP, native service DNS, upstream DNS over UDP/TCP, NAT, TCP/UDP 7844, private/management denial, explicit private-access exceptions and connectivity after a firewall reload. It needs no public network or tunnel token. |
| Medium | App subnet selection is a second IPAM implementation: a hashed slot in a fixed `10.120.0.0/16` pool, checking only network gateway addresses, without host routes or complete prefix overlaps. Malformed inventory could look empty. | Delegate allocation to Incus `network create … ipv4.address=auto`; read and validate the assigned gateway. Preserve existing addresses. Pass the resulting bridge to Compose as external, making Incus the single network authority. Refuse invalid/unavailable inventory and conflicting ownership. |
| Medium | `privateAccess` exceptions precede private-range drops for registered native guest bridges, but not for `nxa-*` Compose app bridges. | Apply the same explicit destination/protocol/port exception to apps, retaining the default private-range and host-input restrictions. |
| Medium | Running-state deployment verification is presented as application health. Nixus disables upstream `ic-healthd`; a running disconnected cloudflared can pass the current check. | Correct the operational documentation and use cloudflared's native prechecks, connection records and `/ready` for Tunnel health. Do not claim this change implements continuous health monitoring. |
| Low | Networking documentation still describes a Docker applications VM, although Compose runs directly on Incus OCI containers. | Document the current data path, NAT owners, port input versus forwarding, macvlan limits and the existing preserved-bridge exemption. Add the Tunnel guide. |

The network changes keep the reserved baseline bridge policy intact and do not
renumber deployed app bridges. Subnet allocation happens only during deployment,
after existing project ownership checks. If allocation succeeds and a later
step fails, the empty bridge remains for retry. Deletion already has an explicit
app-bridge cleanup path. There is no automatic migration of existing local or
externally routed subnets.

## Simplification and delegation

| Concern | Owner / recommendation |
|---|---|
| Public hostnames, DNS routing and tunnel settings | Keep the existing remotely managed Cloudflare configuration. Do not add a second local ingress file or a custom Cloudflare reconciler. |
| Tunnel connection retry, DNS/transport diagnostics, QUIC/HTTP2 selection | Use official cloudflared. Current releases provide these checks and a readiness endpoint; avoid a parallel Nixus connector-health implementation. |
| Private subnet allocation, DHCP, bridge DNS and NAT | Use native Incus, including automatic subnet allocation. The default single-network app does not need an extra DNS daemon or proxy. |
| App health/restart scheduling | Evaluate the pinned incus-compose `ic-healthd` integration before extending the custom three-sample Running-state check. Enabling it needs scoped identity, sidecar ownership and restore tests, not just deleting `--no-healthd`. |
| Multi-app, server-wide Tunnel | Consider maintained NixOS `services.cloudflared` when required. First change origin addressing: a host-level connector cannot assume that per-app short names resolve. For the current same-app origin, keeping the sidecar is simpler. |

## Remaining boundaries

- The exact deployed failure is unresolved without its cloudflared logs or host
  evidence. Cloudflare-side configuration alone cannot show whether a token was
  injected or the container can reach its resolver and Cloudflare's edge.
- Automatic Incus allocation only knows the routes/networks visible on the
  server. Check disconnected VPNs and external router allocations separately.
- `preservedIncusBridges` accepts forwarding in both directions before private
  range drops. This is an intentional adoption compatibility exception, not
  equivalent to new-app isolation. Review its configured list.
- Nixus currently distributes app startup variables to all Compose services.
  Treat app siblings as one trust boundary; file secret bindings alone do not
  isolate the startup environment. Scope-aware startup injection is follow-up
  work before claiming per-service token isolation.
- Multiple NICs/default routes, Wi-Fi macvlan, guest IPv6, externally routed
  networks and published host-port input permissions need their own topology
  tests. A tunnel connector normally needs none of these features.
- The new VM check verifies transport reachability with echo listeners; it is
  not a Cloudflare authentication or QUIC-handshake test. Full Nix evaluation
  and VM execution require CI; syntax checks alone do not establish them.

References and the diagnostic sequence are in [Cloudflare Tunnel](../cloudflare-tunnel.md).

## Validation performed

Go tests with the race detector and Go vet passed. All existing JavaScript
checks passed. The documentation build checked 13 pages, internal links,
anchors/assets and 10 search entries. Tree-sitter parsed the changed Nix files;
the new VM fixture's embedded Python and 45 generated shell commands passed
syntax checks. These are source-level checks. This environment has neither
Nix nor KVM, so the new production-networking VM test and the modified OCI VM
scenario have not been executed here and remain CI gates before merging.

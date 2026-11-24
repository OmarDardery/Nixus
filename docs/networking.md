# Networking and IP management

The default keeps the physical management NIC intact. NixOS owns only the host's
management input firewall (`table inet nixos-fw` with `filterForward = false` and
`flushRuleset = false`). **Incus** owns the private guest bridge (`incusbr0`), its
DHCP/DNS input rules, NAT, forwarding, and `network_acl` (`nixus-guest-egress`),
while **`incus-compose`** manages per-app project networks and service discovery.

## Illustrative address plan — adapt every value

| Object | Example only | Meaning |
|---|---|---|
| Physical management NIC | `enp2s0` | Must be discovered, never guessed |
| LAN | `192.168.50.0/24` | Existing router-managed network |
| Hypervisor | `192.168.50.10/24` | Host management address, not a guest |
| LAN gateway | `192.168.50.1` | Existing router |
| Incus bridge | `10.77.0.1/24` | Host-side address for private guests/DNS/DHCP |
| Incus DHCP | `10.77.0.100`–`10.77.0.199` | Dynamic guest reservations |
| Example guest | `10.77.0.20` | Static DHCP reservation outside the range |
| Compose project networks | Incus networks created by incus-compose | Internal app services, not LAN addresses |
| Public hostname | `app.example.com` | Cloudflare endpoint routed to an application port |

Guests use DHCP normally; Incus assigns the same reserved address
from `eth0.ipv4.address`. The guest IP is a guest endpoint, distinct from the host IP and
from Compose-internal addresses. Fixed guest IPs must remain outside the DHCP dynamic range.
Container CPU/RAM are profile/config limits. VM disk sizes use block images; a directory
pool cannot promise enforced system-container disk quotas.

## Access paths and isolation

- Trusted management source CIDRs on the specified physical interface may reach host TCP
  22 and 8443. No global allow rule exposes those ports on other interfaces.
- Guests reach host DHCP/DNS only. The bridge is not a trusted host firewall interface.
- Guests on the bridge can communicate. This is one application trust zone, not per-tenant
  isolation; use separate bridges/ACLs for untrusted tenants.
- Guest forwarding to RFC1918, CGNAT and link-local destinations is blocked, protecting the
  LAN/VPN management ranges. Guest internet egress uses NAT through the explicit uplink.
- Replies to allowed established flows are accepted by NixOS. Host-originated connections
  can reach guest metrics and application ports directly.
- LAN-to-private-guest forwarding is disabled by default. Enable `connectivity.trustedLANAccess` to permit trusted management CIDRs through the registered guest interfaces; Incus retains guest ACL/forward ownership. Routed LAN access requires
  a static route `10.77.0.0/24 via 192.168.50.10` on the real router/client, using adapted values.
  This route is an external network initialization step; the host does not change the router.

If guests need a LAN DNS/NTP/server, add a narrowly scoped `connectivity.privateAccess` allow rule. Do not broadly trust `incusbr0` as a connectivity workaround. Verify new rules with nft
counters and connectivity tests, including after a firewall rebuild.

A guest or host with multiple interfaces may require reviewing reverse-path filtering and
routes. This default is a simple single-uplink topology, not a multi-router policy.

## Giving a guest a LAN address

Default guest IPs are private routed/NAT addresses, not layer-2 LAN leases.
On wired Ethernet hosts, Nixus preseeds an Incus `macvlan` network (`nixus-lan`)
bound to the physical management interface (or uses the host bridge directly if
management runs on a bridge). Compose apps can attach to it via the console's
**Own IP on your router** toggle or standard `networks:` (`external: true`).

Optional VLAN configuration uses native `networking.vlans`, `networking.bridges` (or equivalent
NetworkManager profiles), with a switch trunk and router/firewall rules. Device
NICs can use an existing bridge's `nictype = "bridged"` and `parent = "br-apps"`, or
reference the host bridge directly as an external network in `incus-compose`. Do not
attach an Incus-managed `network` and an unmanaged `parent` in the same NIC definition.
No interface, VLAN tag, router route or IPv6 prefix is guessed here.

## Compose networking

Services in a Compose project share an isolated Incus bridge network created by
`incus-compose` and resolve one another by service name via `ic-dns` without
exposing internal databases or caches to the LAN. Custom `networks:` in
`compose.yaml` are supported natively; only `network_mode: host` is blocked.

IPv4 is the supported default. Host IPv6 policy can follow the installer; the Incus bridge has
`ipv6.address = "none"`. Enable guest IPv6 only with an allocated routed prefix, IPv6 firewall
and tested router advertisements/DNS. The source-CIDR management allow rules here are IPv4.

Private Tailscale access is an optional extension: enable its native module and define tailnet
ACLs, explicit interface/source firewall allowances and service reachability. This repository
does not silently enroll a node, trust all `tailscale0` traffic, or open management to a VPN.


## Reviewed Ethernet configuration

**Host → Networking** creates host interfaces, not guest network objects. For example:

```nix
nixus.settings.connectivity = {
  bridges = [
    { name = "br-lan"; interfaces = [ "enp2s0" ]; }
    { name = "br-apps"; interfaces = [ "vlan20" ]; }
  ];
  vlans = [ { name = "vlan20"; interface = "enp3s0"; id = 20; } ];
  trustedLANAccess = false;
  privateAccess = [ { cidr = "192.168.50.53/32"; protocol = "udp"; ports = [ 53 ]; } ];
};
```

Replace names and addresses from real inventory. If the selected port carries
management, configure the same address/gateway/DNS on `br-lan` in that review.
Review the new management URL, keep console access, activate and confirm. An
interface belongs to only one bridge, VLAN parents must be discovered Ethernet
interfaces, and Wi-Fi bridge ports are rejected. The installed NetworkManager
owner is preserved; conventional hosts use native NixOS bridge/VLAN options.

In Incus, attach guests to `br-lan` or `br-apps` as existing unmanaged bridges.
Their addresses come from the LAN/VLAN router; Incus DHCP reservations do not
configure an unmanaged bridge. These guests share that LAN's trust boundary.
Do not assume the private-NAT ACL isolates a guest attached directly
to the LAN. Configure guest/native Incus policy as appropriate.

Additional private managed networks created in Incus work directly without
host firewall registration: Incus owns their NAT, DHCP/DNS, forwarding, and ACLs.
`privateAccess` and `trustedLANAccess` configure the reserved `nixus-guest-egress`
Incus network ACL attached to `incusbr0` and are supplied to native Compose app
network ACLs at reviewed deployment. They never grant host management input.
External networks retain their native owner’s policy. ACLs use explicit allows
and default rejection: a blanket deny rule would override permitted exceptions.

No demo-specific port is opened automatically. Without a router route, use native
Incus network forwards directly on `incusbr0` or another Incus-owned network, or attach
a guest to a LAN bridge/`nixus-lan`. Switch trunks/router changes are external actions.
See [ownership](apps.md) before editing the reserved bootstrap network in Incus.


## Guest addresses in the Nixus console

Overview shows a bounded read-only inventory across Incus projects: reported NIC
addresses, reservations, network/NIC names and guest state. Addresses inside
Docker bridges are not presented as Incus guest endpoints. A VM with no agent
address report remains unknown, even when a reservation exists. Incus owns DHCP,
IPAM, ACLs and guest network changes; use its linked native UI and
[network manual](https://linuxcontainers.org/incus/docs/main/howto/network_manage/).

Potential duplicate addresses are flagged only inside a known managed-network
namespace (including projects sharing default networks). Identical IPs on separate
isolated networks are legitimate. The inventory flags attached macvlan NICs whose
parent is already a Linux bridge port. For unmanaged LAN attachments, it also
flags a reported up link with no LAN IPv4 and identifies disabled attachments and
profile-provided devices. Running status, link state, address assignment, and
client/application reachability each require their own evidence. Failed or
older-than-90-second observations are visibly unavailable/stale.

### Moving a guest NIC onto a host bridge

The host change review blocks adding an interface to a declared bridge if a guest
has an attached macvlan NIC on that interface. Before changing the host, identify
the guest project and compare `incus config show NAME --project PROJECT` with its
`--expanded` output. Check other consumers before changing a profile. Plan the
single LAN device change from `nictype: macvlan, parent: PHYSICAL` to
`nictype: bridged, parent: BRIDGE`. Record its MAC and guest-side name, preserve
the private NAT NIC, and keep the original device definition for recovery. Use
the local console or independent management access. If the bridge does not exist
yet, plan a maintenance window to detach the affected LAN device in Incus before
reviewing the host change, then attach it to the bridge once the host change is
confirmed. Nixus does not edit guest NICs or shared profiles during review.

After attachment, check the guest link and configured address source. For a
DHCP client, inspect `networkctl status INTERFACE` when the guest uses
systemd-networkd. An authorized DHCP capture can distinguish no client Discover,
a Discover without an upstream Offer, and an Offer without a completed lease.
Verify routing and the expected service from a separate LAN client, then repeat
after restarting the guest and rebooting the host.

Host bridges, VLANs, management addressing, baseline guest subnet/DHCP range and
reserved apps IP stay under Host → Networking and the existing reviewed activation
flow. Per-guest reservations and networks stay in Incus. No router or DNS-provider
changes are made automatically. Nixus portal roles are host-console roles and
can read this all-project inventory; they are not Incus project permissions.

### Inspect management exposure

On the hypervisor, `/etc/nixus/management-exposure.json` lists the evaluated
Nixus listener addresses and ports, the management interface and the trusted
IPv4 client CIDRs. The same list generates the host's management input rule.
An IPv4 wildcard listener still binds all IPv4 addresses so DHCP renewals can
keep using it. Incoming management connections must arrive on the selected
interface from a trusted source. Local metrics stay off the management rule.
The JSON describes the Nixus policy. Check custom firewall rules and actual
socket state with `sudo nft list ruleset` and `sudo ss -ltn`.

Bootstrap retains the installed firewall and interface-scoped portal ports.

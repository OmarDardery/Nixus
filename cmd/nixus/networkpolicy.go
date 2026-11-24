package main

import (
	_ "embed"
)

// This public-range allow list preserves the prior private-range policy.
// It was generated with Python's ipaddress.address_exclude, not a subnet allocator.
//
//go:embed public-ipv4.json
var publicIPv4JSON []byte

// composeNetworkPolicy expresses the host's policy in upstream Compose ACLs.
// incus-compose resolves network names to native allocated bridge subnets and
// creates/attaches the Incus ACLs. Nixus creates no bridge, DNS or firewall table.
func composeNetworkPolicy(networks M, settings M, controllerCIDR string) M {
	out := M{}
	if len(networks) == 0 {
		networks = M{"default": M{}}
	}
	for name, raw := range networks {
		network := obj(raw)
		if isTrue(network["external"]) {
			continue
		}
		ingress := []any{M{"from": name}}
		if isTrue(jget(settings, "connectivity", "trustedLANAccess")) {
			for _, cidr := range list(jget(settings, "management", "trustedCIDRs")) {
				ingress = append(ingress, M{"from": cidr})
			}
		}
		egress := []any{M{"to": name}}
		for _, cidr := range list(must(parseJSON(publicIPv4JSON))) {
			egress = append(egress, M{"to": cidr})
		}
		if controllerCIDR != "" {
			egress = append(egress, M{"to": controllerCIDR, "ports": []any{"53/tcp", "53/udp"}})
		}
		for _, raw := range list(jget(settings, "connectivity", "privateAccess")) {
			rule := obj(raw)
			ports := []any{}
			for _, port := range list(rule["ports"]) {
				ports = append(ports, str(port)+"/"+str(rule["protocol"]))
			}
			egress = append(egress, M{"to": rule["cidr"], "ports": ports})
		}
		out[name] = M{"x-incus": M{"security.acls.default.ingress.action": "reject", "security.acls.default.egress.action": "reject"}, "x-incus-compose": M{"acl": M{"ingress": ingress, "egress": egress}}}
	}
	return out
}

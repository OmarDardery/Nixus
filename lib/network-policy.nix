# Native Incus ACL allow rules plus network default-reject actions. Incus gives
# explicit denies priority, so exceptions must not compete with a blanket deny.
{ lib, site, name ? "nixus-guest-egress" }:
let publicIPv4 = builtins.fromJSON (builtins.readFile ../cmd/nixus/public-ipv4.json);
in {
    inherit name;
    description = "Isolate private guests from RFC1918/CGNAT/link-local except explicit allowances";
    ingress = [
      { action = "allow"; source = site.guests.cidr; state = "enabled"; }
    ] ++ lib.optional (site.connectivity.trustedLANAccess && site.management.trustedCIDRs != [ ]) {
      action = "allow";
      source = lib.concatStringsSep "," site.management.trustedCIDRs;
      state = "enabled";
    };
    egress = [
      { action = "allow"; destination = site.guests.cidr; state = "enabled"; }
    ] ++ map (rule: {
      action = "allow";
      destination = rule.cidr;
      protocol = rule.protocol;
      destination_port = lib.concatMapStringsSep "," toString rule.ports;
      state = "enabled";
    }) site.connectivity.privateAccess ++ map (cidr: {
      action = "allow"; destination = cidr; state = "enabled";
    }) publicIPv4;
  }

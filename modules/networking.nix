{ lib, site, installedNetworking ? { networkManager = false; }, ... }:
let
  m = site.management;
  trusted = lib.concatStringsSep ", " m.trustedCIDRs;
  iface = builtins.toJSON m.interface;
  isBridge = lib.any (b: b.name == m.interface) site.connectivity.bridges;
  vlan = lib.findFirst (v: v.name == m.interface) null site.connectivity.vlans;
  nmWired = installedNetworking.networkManager && m.interface != site.radios.wifi.interface;
  useNM = nmWired || (site.radios.wifi.enable && m.interface == site.radios.wifi.interface);
in {
  imports = [ ./management.nix ];
  nixus.managementPolicy.enforceFirewall = true;
  boot.kernel.sysctl."net.ipv4.ip_forward" = lib.mkDefault 1;
  # Keep unrelated nftables tables intact so Incus owns guest NAT, DHCP/DNS
  # input, forwarding, and network ACLs in table inet incus.
  networking.nftables = { enable = true; flushRuleset = false; };
  networking.firewall = {
    enable = true;
    filterForward = false;
    allowedTCPPorts = lib.mkForce [ ];
    allowedUDPPorts = lib.mkForce [ ];
    # NixOS adds lo through this option. Dropping it also blocks connections
    # to the host's own LAN address, including every management health probe.
    trustedInterfaces = lib.mkForce [ "lo" ];
    allowPing = false;
    # Host input stays closed by default; management ports are scoped to
    # management.interface + trustedCIDRs in modules/management.nix.
    # Allow DHCP/DNS input on non-management interfaces so Incus's own
    # table inet incus has sole authority over bridge dnsmasq access
    # (incusbr0, incus-compose bridges, and custom Compose networks).
    extraInputRules = ''
      iifname ${iface} ip saddr { ${trusted} } icmp type echo-request accept
      iifname != ${iface} udp dport { 53, 67 } accept
      iifname != ${iface} tcp dport 53 accept
    '';
  };
  networking.dhcpcd.denyInterfaces = [ "veth*" "ic-*" "incus*" ];
  # Opt-in change: never enslave or rename an existing management NIC on rebuild.
  networking.useDHCP = lib.mkIf (m.configure && !useNM) (lib.mkForce false);
  networking.interfaces = lib.mkIf (m.configure && !useNM) {
    "${m.interface}" = {
      useDHCP = lib.mkForce false;
      ipv4.addresses = lib.mkForce [ { address = m.address; prefixLength = m.prefixLength; } ];
    };
  };
  networking.defaultGateway = lib.mkIf (m.configure && !useNM) (lib.mkForce m.gateway);
  networking.nameservers = lib.mkIf (m.configure && !useNM) (lib.mkForce m.dns);
  networking.networkmanager.ensureProfiles.profiles = lib.mkIf (m.configure && nmWired) {
    nixus-management = {
      connection = { id = "nixus-management"; type = if isBridge then "bridge" else if vlan != null then "vlan" else "ethernet";
        interface-name = m.interface; autoconnect = true; autoconnect-priority = 200; };
      ipv4 = { method = "manual"; address1 = "${m.address}/${toString m.prefixLength},${m.gateway}"; dns = lib.concatStringsSep ";" m.dns; };
      ipv6.method = "auto";
    } // lib.optionalAttrs isBridge { bridge.stp = false; }
      // lib.optionalAttrs (vlan != null) { vlan = { id = vlan.id; parent = vlan.interface; }; };
  };
}


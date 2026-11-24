{ config, lib, pkgs, site, ... }:
let
  base = {
    name = "base"; project = "lab";
    config = {
      "limits.cpu" = "2"; "limits.memory" = "2GiB";
      "snapshots.schedule" = "@daily";
      "snapshots.expiry" = "7d";
      "snapshots.pattern" = "auto-%Y%m%d-%H%M";
    };
    devices = {
      root = { type = "disk"; path = "/"; pool = site.storage.pool; size = "32GiB"; };
      eth0 = { type = "nic"; name = "eth0"; network = site.guests.bridge; };
    };
  };
  mgmtIsBridge = lib.any (b: b.name == site.management.interface) site.connectivity.bridges;
  mgmtIsWifi = site.radios.wifi.enable && site.management.interface == site.radios.wifi.interface;
  inventory = pkgs.writeText "inventory.json" (builtins.toJSON site);
  nixus = import ../pkgs/nixus.nix { inherit pkgs; };
  guestEgressACL = import ../lib/network-policy.nix { inherit lib site; };
  # icompose0 is only bootstrapped here; upstream owns its DHCP/resolver
  # settings. Recording its full runtime config would mistake native changes
  # made by Compose for source-owned drift on the next host rebuild.
  ownedInfrastructure = config.virtualisation.incus.preseed // {
    networks = lib.filter (network: network.name != "icompose0") config.virtualisation.incus.preseed.networks;
    network_acls = [ guestEgressACL ];
  };

in {
  imports = [ ./incus-apparmor.nix ./compose-runtime.nix ];
  environment.etc."nixus/owned-infrastructure.json".text = builtins.toJSON ownedInfrastructure;
  virtualisation.incus = {
    enable = true;
    ui.enable = true;
    preseed = {
      config."core.https_address" = "0.0.0.0:8443";
      storage_pools = [ { name = site.storage.pool; driver = site.storage.driver;
        config.source = site.storage.source; } ];
      networks = [ {
        name = site.guests.bridge; type = "bridge";
        config = {
          "ipv4.address" = site.guests.gatewayCIDR;
          "ipv4.dhcp.ranges" = site.guests.dhcpRange;
          "ipv4.nat" = "true"; "ipv4.firewall" = "true";
          "ipv6.address" = "none"; "ipv6.firewall" = "false";
          "dns.domain" = "guests.internal";
          "security.acls" = guestEgressACL.name;
          "security.acls.default.ingress.action" = "reject";
          "security.acls.default.egress.action" = "reject";
        };
      } ] ++ lib.optional (site.management.interface != "" && !mgmtIsBridge && !mgmtIsWifi) {
        name = "nixus-lan";
        type = "macvlan";
        config.parent = site.management.interface;
      };
      projects = [ {
        name = "lab";
        config = { "features.images" = "false"; "features.profiles" = "true";
          "features.networks" = "false"; "features.storage.volumes" = "true"; };
      } ];
      profiles = [ base ];
    };
  };
  systemd.services.nixus-incus-audit = {
    description = "Record Incus lifecycle events in the persistent journal";
    wantedBy = [ "multi-user.target" ];
    # First-run CLI configuration is not written atomically by Incus. Do not
    # race preseed's local infrastructure checks with client initialization.
    after = [ "incus.service" "incus-preseed.service" ]; requires = [ "incus.service" ];
    serviceConfig = {
      ExecStart = "${pkgs.incus-lts.client}/bin/incus --force-local monitor --type=lifecycle --all-projects";
      Restart = "on-failure"; RestartSec = "5s";
    };
  };
  systemd.services.incus-preseed.preStart = lib.mkBefore ''
    ${nixus}/bin/nixus-go preflight ${inventory}
    ${nixus}/bin/nixus-go infrastructure check ${pkgs.writeText "nixus-owned-infrastructure.json" (builtins.toJSON ownedInfrastructure)}
    ${nixus}/bin/nixus-go infrastructure apply-acls ${pkgs.writeText "nixus-owned-infrastructure.json" (builtins.toJSON ownedInfrastructure)}
  '';
  systemd.services.incus-preseed.postStart = ''
    ${nixus}/bin/nixus-go infrastructure record ${pkgs.writeText "nixus-owned-infrastructure.json" (builtins.toJSON ownedInfrastructure)}
  '';
  systemd.services.incus-preseed.path = [ pkgs.incus-lts.client ];
}


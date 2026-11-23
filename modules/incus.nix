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
  # Legacy UI inventory only; apps are deployed per project.
  declared = site.instances;
  instances = declared;
  inventory = pkgs.writeText "inventory.json" (builtins.toJSON (site // { instances = declared; }));
  desired = pkgs.writeText "instances.json" (builtins.toJSON instances);
  nixus = import ../pkgs/nixus.nix { inherit pkgs; };
  reconcile = pkgs.writeShellApplication {
    name = "nixus-reconcile";
    runtimeInputs = [ pkgs.incus-lts.client ];
    text = ''exec ${nixus}/bin/nixus-go reconcile ${desired}'';
  };
in {
  nixus.incus.desiredInstances = instances;
  environment.etc."nixus/desired-instances.json".source = desired;
  environment.etc."nixus/owned-infrastructure.json".text = builtins.toJSON config.virtualisation.incus.preseed;
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
          "ipv4.nat" = "false"; "ipv4.firewall" = "false";
          "ipv6.address" = "none"; "ipv6.firewall" = "false";
          "dns.domain" = "guests.internal";
        };
      } ];
      projects = [ {
        name = "lab";
        config = { "features.images" = "false"; "features.profiles" = "true";
          "features.networks" = "false"; "features.storage.volumes" = "true"; };
      } ];
      profiles = [ base ];
    };
  };
  # NixOS wraps gzip: bin/gzip is a script that execs bin/.gzip-wrapped. Incus
  # generates an AppArmor profile per archive operation (it includes
  # abstractions/base) that allows only the resolved `gzip`, so unpacking an
  # image's gzip layer was denied at the wrapped binary (#117). Allow exactly
  # that file, taken from the same gzip package Incus runs with, so it follows
  # store-path changes on rebuild.
  security.apparmor.includes."abstractions/base" = lib.mkIf config.security.apparmor.enable (lib.mkAfter ''
    ${pkgs.gzip}/bin/.gzip-wrapped mixr,
  '');
  systemd.services.nixus-incus-audit = {
    description = "Record Incus lifecycle events in the persistent journal";
    wantedBy = [ "multi-user.target" ];
    # First-run CLI configuration is not written atomically by Incus. Do not
    # race preseed's local infrastructure checks with client initialization.
    after = [ "incus.service" "incus-preseed.service" ]; requires = [ "incus.service" ];
    before = [ "nixus-instances.service" ];
    serviceConfig = {
      ExecStart = "${pkgs.incus-lts.client}/bin/incus --force-local monitor --type=lifecycle --all-projects";
      Restart = "on-failure"; RestartSec = "5s";
    };
  };
  systemd.services.incus-preseed.preStart = lib.mkBefore ''
    ${nixus}/bin/nixus-go preflight ${inventory}
    ${nixus}/bin/nixus-go infrastructure check ${pkgs.writeText "nixus-owned-infrastructure.json" (builtins.toJSON config.virtualisation.incus.preseed)}
  '';
  systemd.services.incus-preseed.postStart = ''
    ${nixus}/bin/nixus-go infrastructure record ${pkgs.writeText "nixus-owned-infrastructure.json" (builtins.toJSON config.virtualisation.incus.preseed)}
  '';
  systemd.services.incus-preseed.path = [ pkgs.incus-lts.client ];
  systemd.services.nixus-instances = {
    description = "Reconcile owned Incus instances without deleting guest data";
    wantedBy = [ "multi-user.target" ];
    after = [ "incus-preseed.service" "nixus-kvm-check.service" ];
    requires = [ "incus-preseed.service" "nixus-kvm-check.service" ];
    path = [ pkgs.incus-lts.client pkgs.findutils ];
    restartTriggers = [ desired ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; TimeoutStartSec = "30min"; };
    script = "${reconcile}/bin/nixus-reconcile";
  };
}


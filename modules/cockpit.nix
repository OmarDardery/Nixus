{ config, lib, pkgs, site, ... }:
let
  c = site.cockpit;
in {
  config = lib.mkIf c.enable {
    services.cockpit = {
      enable = true;
      inherit (c) port;
      openFirewall = false;
      showBanner = false;
      allowed-origins = [ "https://${site.management.address}:${toString c.port}" ];
      settings.WebService = { LoginTo = false; AllowMultiHost = false; AllowUnencrypted = false; };
    };
    systemd.sockets.cockpit.listenStreams = lib.mkForce [ "" "0.0.0.0:${toString c.port}" ];
    # Keep socket activation available through DHCP startup. A transient TLS or
    # worker failure must recover without an administrator restarting Cockpit.
    systemd.services.cockpit = {
      startLimitIntervalSec = 0;
      serviceConfig = { Restart = "on-failure"; RestartSec = "3s"; };
    };
    environment.etc = {
      "cockpit/disallowed-users".text = "root\n";
    } // lib.optionalAttrs site.setup.enable {
      # Retain the declarative settings as a template; the startup identity
      # service replaces only Origins with exact assigned-address origins.
      "nixus/cockpit-base.conf".source = (pkgs.formats.ini { }).generate "nixus-cockpit-base.conf" config.services.cockpit.settings;
      "cockpit/cockpit.conf".source = lib.mkForce "/run/nixus/cockpit.conf";
      # Runtime symlinks: private material is never copied into the Nix store.
      "cockpit/ws-certs.d/90-nixus.cert".source = "/var/lib/nixus-admin/tls.crt";
      "cockpit/ws-certs.d/90-nixus.key".source = "/var/lib/nixus-admin/tls.key";
    };
    systemd.tmpfiles.rules = lib.optional site.setup.enable "d /run/nixus 0755 root root -";
    users.users.operator.hashedPasswordFile = lib.mkIf c.managePassword
      (if site.secrets.enable then config.sops.secrets.cockpit-operator-password.path else "/var/lib/nixus-secrets/cockpit-operator-password");
    assertions = [
      { assertion = !c.managePassword || config.users.mutableUsers;
        message = "Cockpit password enrollment requires mutable local accounts; manage immutable accounts in your source instead."; }
    ];
  };
}


{ config, lib, pkgs, site, ... }:
let
  enabled = site.setup.enable;
  tool = import ../admin/package.nix { inherit pkgs; };
  install = if builtins.pathExists (import ../lib/machine.nix ../.).installation
    then builtins.fromJSON (builtins.readFile (import ../lib/machine.nix ../.).installation)
    else { interface = site.management.interface; trustedCIDRs = site.management.trustedCIDRs; };
in {
  imports = [ ./management.nix ];
  config = lib.mkIf enabled {
    # Dedicated password/account verification only; no session or credential
    # changes and no permissive root/sudo/NOPASSWD PAM shortcuts.
    security.pam.services.nixus-enrollment = {
      # Use NixOS's normal PAM rule generation (including configured additional
      # authentication policy), but never let a root-run helper skip the password.
      rootOK = lib.mkForce false;
      allowNullPassword = lib.mkForce false;
      unixAuth = true;
      startSession = false;
    };
    users.groups.nixus-ui = { };
    users.users.nixus-ui = { isSystemUser = true; group = "nixus-ui"; };
    environment.systemPackages = [ tool ];
    systemd.services.nixus-management-identity = {
      description = "Refresh management TLS identity from the assigned address";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ]; after = [ "network-online.target" ];
      before = [ "incus.service" "cockpit.service" "nginx.service" "nixus-ui.service" ];
      path = [ pkgs.iproute2 ];
      serviceConfig = {
        Type = "oneshot"; RemainAfterExit = true;
        ExecStart = "${tool}/bin/nixus-admin identity";
        Restart = "on-failure"; RestartSec = "3s"; TimeoutStartSec = "120s";
      };
    };
    systemd.tmpfiles.rules = [
      # Restorable declarative projects are intentionally outside /etc/nixos
      # and the world-readable Nix store. Only the root broker may write them.
      "d /srv/nixus 0700 root root -"
      "d /var/lib/nixus-admin 0710 root nixus-ui -"
      "d /var/lib/nixus-admin/jobs 0700 root root -"
      "d /run/nixus-admin 0750 root nixus-ui -"
      "d /run/nixus-browser 0700 root root -"
    ];
    # During bootstrap retain the existing firewall implementation. The HTTPS process
    # also enforces source CIDRs; after conversion the host uses nftables.
    networking.firewall.interfaces."${if site.ready then site.management.interface else install.interface}".allowedTCPPorts =
      lib.mkIf (!config.nixus.managementPolicy.enforceFirewall) [ 80 site.setup.port ];
    # Port 80 is an entry point only. Authenticate over the existing private
    # HTTPS portal, never a plaintext HTTP login/session. Keep the Nixus host
    # UI separate from guest applications which may also use port 80 on their IP.
    services.nginx = {
      enable = true;
      virtualHosts.nixus-entry = {
        serverName = "_";
        default = true;
        listen = [ { addr = "0.0.0.0"; port = 80; } ];
        locations."/".return = "308 https://$host:${toString site.setup.port}$request_uri";
      };
    };
    systemd.services.nixus-admin-backend = {
      description = "Nixus typed configuration and transaction broker";
      wantedBy = [ "multi-user.target" ]; after = [ "local-fs.target" ];
      path = [ pkgs.networkmanager ];
      environment.NIXUS_ROOT = "/var/lib/nixus/config";
      serviceConfig = {
        ExecStart = "${tool}/bin/nixus-admin backend";
        Restart = "on-failure"; RestartSec = "3s";
        UMask = "0027"; RuntimeDirectory = "nixus-admin"; RuntimeDirectoryMode = "0750";
        RuntimeDirectoryPreserve = "yes"; Group = "nixus-ui";
      };
      restartIfChanged = false; stopIfChanged = false;
    };
    systemd.services.nixus-ui = {
      description = "Nixus HTTPS first-run setup and host settings";
      wantedBy = [ "multi-user.target" ];
      after = [ "nixus-admin-backend.service" "nixus-management-identity.service" ];
      requires = [ "nixus-admin-backend.service" "nixus-management-identity.service" ];
      environment = { NIXUS_ROOT = "/var/lib/nixus/config"; NIXUS_PORT = toString site.setup.port; };
      serviceConfig = {
        ExecStart = "${tool}/bin/nixus-admin web";
        User = "nixus-ui"; Group = "nixus-ui";
        LoadCredential = [ "tls.crt:/var/lib/nixus-admin/tls.crt" "tls.key:/var/lib/nixus-admin/tls.key" ];
        Restart = "on-failure"; RestartSec = "3s";
        # The HTTPS process is deliberately finite even if every trusted-LAN
        # connection stalls. Root broker jobs run in the separate service.
        TasksMax = 96; LimitNOFILE = 1024; MemoryMax = "512M";
        NoNewPrivileges = true; PrivateTmp = true; ProtectHome = true;
        ProtectSystem = "strict"; ProtectKernelTunables = true; ProtectKernelModules = true;
        ProtectControlGroups = true; RestrictSUIDSGID = true;
        CapabilityBoundingSet = ""; RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      };
      restartIfChanged = false; stopIfChanged = false;
    };
    systemd.services.nixus-rollback-guard = {
      description = "Recover an unconfirmed Nixus activation";
      environment.NIXUS_ROOT = "/var/lib/nixus/config";
      path = [ pkgs.networkmanager ];
      serviceConfig = { Type = "oneshot"; ExecStart = "${tool}/bin/nixus-admin guard"; };
    };
    systemd.services.incus = lib.mkIf config.virtualisation.incus.enable {
      requires = [ "nixus-management-identity.service" ];
      after = [ "nixus-management-identity.service" ];
      serviceConfig.BindReadOnlyPaths = lib.mkIf (config.virtualisation.incus.useACMEHost == null) [
        "/var/lib/nixus-admin/tls.crt:/var/lib/incus/server.crt"
        "/var/lib/nixus-admin/tls.key:/var/lib/incus/server.key"
      ];
    };
    # Sockets are ordered before basic.target; waiting for network-online there
    # creates a boot cycle. The activated service consumes the certificate.
    systemd.services.cockpit = lib.mkIf site.cockpit.enable {
      requires = [ "nixus-management-identity.service" ];
      after = [ "nixus-management-identity.service" ];
    };
    systemd.services.nixus-tls-renew = {
      environment.NIXUS_ROOT = "/var/lib/nixus/config";
      serviceConfig = { Type = "oneshot"; ExecStart = "${tool}/bin/nixus-admin renew"; };
    };
    systemd.services.nixus-management-health = lib.mkIf site.ready {
      description = "Verify enabled management interfaces after boot";
      wantedBy = [ "multi-user.target" ];
      after = [ "nixus-management-identity.service" "nixus-ui.service" ]
        ++ lib.optional site.cockpit.enable "cockpit.socket";
      path = [ pkgs.iproute2 ];
      serviceConfig = {
        Type = "oneshot"; RemainAfterExit = true;
        ExecStart = "${tool}/bin/nixus-admin doctor --wait";
        TimeoutStartSec = "4min";
        Restart = "on-failure"; RestartSec = "30s";
      };
    };
    systemd.timers.nixus-tls-renew = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnCalendar = "monthly"; Persistent = true; };
    };
    systemd.timers.nixus-rollback-guard = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "20s"; OnUnitActiveSec = "15s"; AccuracySec = "1s"; };
    };
  };
}


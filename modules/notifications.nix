{ config, lib, pkgs, site, ... }:
let cfg = config.nixus.notifications;
in {
  options.nixus.notifications = {
    enable = lib.mkEnableOption "failure webhook notifications";
    webhookFile = lib.mkOption { type = lib.types.str; default = "/var/lib/nixus-secrets/notification-url";
      description = "Root-owned runtime file containing an HTTPS webhook URL; never place its value in Nix."; };
  };
  config = lib.mkIf cfg.enable {
    assertions = [ { assertion = lib.hasPrefix "/" cfg.webhookFile && !(lib.hasPrefix "/nix/store/" cfg.webhookFile);
      message = "Notification credentials must come from an absolute runtime file outside the Nix store."; } ];
    environment.etc."nixus/notification-settings.json".text = builtins.toJSON { inherit (cfg) webhookFile; };
    systemd.services."nixus-notify@" = {
      description = "Send a bounded Nixus failure notification";
      wants = [ "network-online.target" ]; after = [ "network-online.target" ];
      environment.SSL_CERT_FILE = "/etc/ssl/certs/ca-certificates.crt";
      unitConfig = { StartLimitIntervalSec = 300; StartLimitBurst = 3; };
      serviceConfig = {
        Type = "oneshot"; TimeoutStartSec = "30s"; Restart = "on-failure"; RestartSec = "10s";
        LoadCredential = [ "webhook:${cfg.webhookFile}" ];
        ExecStart = "${import ../pkgs/nixus.nix { inherit pkgs; }}/bin/nixus-go notify %i";
        NoNewPrivileges = true; PrivateTmp = true; ProtectSystem = "strict"; ProtectHome = true;
      };
    };
    systemd.services.nixus-instances.onFailure = [ "nixus-notify@%n.service" ];
    systemd.services.nixus-kvm-check.onFailure = [ "nixus-notify@%n.service" ];
    systemd.services.nixus-image-updates.onFailure = [ "nixus-notify@%n.service" ];
    systemd.services.nixus-project-backup.onFailure = [ "nixus-notify@%n.service" ];
    systemd.services.nixus-rollback-guard = lib.mkIf site.setup.enable { onFailure = [ "nixus-notify@%n.service" ]; };
  };
}

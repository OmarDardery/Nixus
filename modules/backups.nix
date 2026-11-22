{ pkgs, ... }:
let
  admin = import ../admin/package.nix { inherit pkgs; };
  backup = pkgs.writeShellApplication {
    name = "nixus-export";
    runtimeInputs = [ admin ];
    text = ''exec nixus-admin backup "$@"'';
  };
in {
  config = {
    # Detects newer digests; applies them only for projects with updates.policy = "auto".
    systemd.timers.nixus-image-updates = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnCalendar = "daily"; Persistent = true; RandomizedDelaySec = "1h"; };
    };
    systemd.timers.nixus-secrets-deliver = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "2min"; OnUnitActiveSec = "10min"; };
    };
    systemd.timers.nixus-apps-repo-check = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "3min"; OnUnitActiveSec = "10min"; RandomizedDelaySec = "1min"; };
    };
    systemd.timers.nixus-project-backup = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnCalendar = "*:0/15"; Persistent = true; RandomizedDelaySec = "2min"; };
    };
    systemd.services = {
      # Stable unit: project backup policy lives in the reviewed workspace
      # backups.nix, so policy edits never need a host rebuild.
      nixus-image-updates = {
        description = "Check tracked project images and apply updates allowed by each project policy";
        restartIfChanged = false;
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = { Type = "oneshot"; ExecStart = [ "${admin}/bin/nixus-admin image-updates check" "${admin}/bin/nixus-admin image-updates auto" ]; TimeoutStartSec = "6h"; UMask = "0077"; };
      };
      # Containers lose /run on restart; re-deliver app secrets after boot and periodically.
      nixus-secrets-deliver = {
        description = "Deliver each app's decrypted secrets into its running instances";
        restartIfChanged = false;
        after = [ "incus.service" ];
        serviceConfig = { Type = "oneshot"; ExecStart = "${admin}/bin/nixus-admin apps deliver-secrets"; TimeoutStartSec = "10min"; UMask = "0077"; };
      };
      # Fetch the apps repository: list remote changes for review, push console changes.
      nixus-apps-repo-check = {
        description = "Check the apps repository for changes";
        restartIfChanged = false;
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        unitConfig.ConditionPathExists = "/var/lib/nixus-secrets/apps-repo.json";
        serviceConfig = { Type = "oneshot"; ExecStart = "${admin}/bin/nixus-admin apps-repo check"; TimeoutStartSec = "30min"; UMask = "0077"; };
      };
      nixus-project-backup = {
        description = "Run the reviewed declarative project backup policy when due";
        restartIfChanged = false;
        after = [ "network-online.target" "incus.service" ];
        wants = [ "network-online.target" ];
        serviceConfig = { Type = "oneshot"; ExecStart = "${admin}/bin/nixus-admin project-backup tick"; TimeoutStartSec = "12h"; UMask = "0077"; };
      };
      nixus-backup-recover = {
        wantedBy = [ "multi-user.target" ];
        after = [ "incus-preseed.service" ];
        requires = [ "incus-preseed.service" ];
        unitConfig.ConditionPathExists = "/var/lib/nixus/restart-pending.json";
        serviceConfig.Type = "oneshot";
        script = "${backup}/bin/nixus-export --recover";
      };
    };
  };
}

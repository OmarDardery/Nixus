{ config, lib, pkgs, site, ... }:
let
  verification = config.nixus.backupVerification;
  admin = import ../admin/package.nix { inherit pkgs; };
  backup = pkgs.writeShellApplication {
    name = "nixus-export";
    runtimeInputs = [ pkgs.python3 pkgs.incus-lts.client ];
    text = ''PYTHONPATH=${../scripts} exec python3 ${../scripts/backup.py} "$@"'';
  };
  prepare = pkgs.writeShellApplication {
    name = "nixus-backup-prepare";
    runtimeInputs = [ pkgs.util-linux pkgs.coreutils ];
    text = ''
      mkdir -p /var/lib/nixus-admin
      exec 9>/var/lib/nixus-admin/mutation.lock
      flock 9
      ${backup}/bin/nixus-export --with-recovery
    '';
  };
in {
  options.nixus.backupVerification = {
    enable = lib.mkOption { type = lib.types.bool; default = site.backup.enable;
      description = "Schedule integrity checks of the configured restic repository."; };
    schedule = lib.mkOption { type = lib.types.str; default = "Sun *-*-* 05:00:00";
      description = "Native systemd calendar for repository verification."; };
    mode = lib.mkOption { type = lib.types.enum [ "metadata" "full" ]; default = "metadata";
      description = "Metadata checks or a full read of every repository data pack; neither proves application restore."; };
  };
  config = {
    assertions = [ { assertion = !site.backup.enable || site.backup.repository != "";
      message = "Set an independent restic repository before enabling backups."; }
      { assertion = !verification.enable || site.backup.enable;
        message = "Enable and configure restic backups before scheduling repository verification."; } ];
    environment.etc."nixus/backup-verification.json".text = builtins.toJSON {
      version = 1; inherit (verification) enable schedule mode;
    };
    systemd.timers.nixus-backup-check = lib.mkIf verification.enable {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnCalendar = verification.schedule; Persistent = true; RandomizedDelaySec = "30min"; };
    };
    services.restic.backups.nixus = lib.mkIf site.backup.enable {
      repository = site.backup.repository;
      passwordFile = site.backup.passwordFile;
      environmentFile = site.backup.environmentFile;
      initialize = site.backup.initialize;
      paths = [ site.backup.stagingDirectory ];
      exclude = [ "${site.backup.stagingDirectory}/.incomplete" ];
      backupPrepareCommand = "${prepare}/bin/nixus-backup-prepare";
      backupCleanupCommand = "${backup}/bin/nixus-export --recover";
      timerConfig = { OnCalendar = site.backup.schedule; Persistent = true; RandomizedDelaySec = "10min"; };
      pruneOpts = [ "--keep-daily 7" "--keep-weekly 4" "--keep-monthly 6" ];
    };
    systemd.services = {
      restic-backups-nixus = lib.mkIf site.backup.enable {
        after = [ "incus-preseed.service" "nixus-instances.service" ];
        requires = [ "incus.service" ];
        environment.NIXUS_EXPORT_DIRECTORY = site.backup.stagingDirectory;
        environment.NIXUS_RECOVERY_TOOL = "${admin}/bin/nixus-admin";
        environment.NIXUS_BACKUP_POLICY = pkgs.writeText "nixus-backup-policy.json" (builtins.toJSON {
          inherit (site.backup) groups exclude reserveMiB;
        });
        onFailure = [ "nixus-backup-failed.service" ];
        serviceConfig = {
          TimeoutStartSec = "12h";
          # Cancellation must leave time for the exporter to restart its group.
          TimeoutStopSec = "10min";
        };
        postStart = ''
          # A deliberately excluded workload must not make the full-host freshness
          # indicator green. Detailed coverage remains in backup-status.json.
          if ${pkgs.python3}/bin/python3 -c 'import json; import sys; sys.exit(json.load(open("/var/lib/nixus/backup-status.json"))["phase"] != "complete")'; then
            date +%s > /var/lib/nixus/last-backup-success
          fi
        '';
      };
      nixus-backup-check = lib.mkIf site.backup.enable {
        description = "Verify independent restic repository integrity";
        restartIfChanged = false; # Let a long read finish; the next check uses new policy.
        environment.RESTIC_REPOSITORY = site.backup.repository;
        environment.RESTIC_PASSWORD_FILE = site.backup.passwordFile;
        path = [ pkgs.restic pkgs.systemd ];
        serviceConfig = {
          Type = "oneshot"; EnvironmentFile = site.backup.environmentFile;
          ExecStart = "${pkgs.python3}/bin/python3 ${../scripts/backup_verification.py} --mode ${verification.mode}";
          TimeoutStartSec = "12h"; UMask = "0077";
        };
        environment.PYTHONPATH = "${../admin}:${../scripts}";
      };
      nixus-backup-recover = {
        wantedBy = [ "multi-user.target" ];
        after = [ "incus-preseed.service" ];
        requires = [ "incus-preseed.service" ];
        unitConfig.ConditionPathExists = "/var/lib/nixus/restart-pending.json";
        serviceConfig.Type = "oneshot";
        script = "${backup}/bin/nixus-export --recover";
      };
      nixus-backup-failed = lib.mkIf site.backup.enable {
        serviceConfig.Type = "oneshot";
        script = ''${pkgs.util-linux}/bin/logger -p daemon.err -t nixus "Backup failed: inspect journalctl -u restic-backups-nixus; verify guest recovery"'';
      };
    };
  };
}

{ config, lib, site, ... }:
{
  options.nixus.recovery.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Replacement-host recovery: suppress automatic guest creation, onboarding, backups and public ingress.";
  };
  config = lib.mkIf config.nixus.recovery.enable {
    environment.etc."nixus/recovery-mode".text = "1\n";
    systemd.services = lib.genAttrs [
      "nixus-instances" "nixus-backup-recover"
      "restic-backups-nixus" "nixus-backup-check"
      "cloudflared-tunnel-${site.tunnel.uuid}"
    ] (_: { enable = lib.mkForce false; });
    systemd.timers.restic-backups-nixus.enable = lib.mkForce false;
  };
}

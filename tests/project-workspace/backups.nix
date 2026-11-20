{ ... }: {
  nixus.backups = {
    enable = true;
    schedule = "daily";
    restic = {
      repository = "rclone:gdrive:nixus-backups";
      rcloneConfigFile = "/var/lib/nixus-secrets/rclone.conf";
    };
    github.repository = "git@github.com:example/nixus-config.git";
  };
}

{ lib, site, ... }:
{
  assertions = [ { assertion = !site.secrets.enable || site.secrets.guestFile != "";
    message = "sops-nix requires an encrypted guest secrets file."; } ];
  sops = lib.mkIf site.secrets.enable {
    defaultSopsFile = ../. + "/${site.secrets.guestFile}";
    age.keyFile = site.secrets.ageKeyFile;
    secrets = { };
  };
  systemd.tmpfiles.rules = [ "d /var/lib/nixlab-secrets 0700 root root -" ];
}

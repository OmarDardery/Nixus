{ lib, site, ... }:
{
  assertions = [ { assertion = !site.secrets.enable || site.secrets.hostFile != "";
    message = "sops-nix requires an encrypted host secrets file."; } ];
  # Host credentials are SOPS/age ciphertext in the reviewed machine source
  # (machine/secrets/host.yaml), written by the Web UI and decrypted here.
  sops = lib.mkIf site.secrets.enable {
    defaultSopsFile = ../. + "/${site.secrets.hostFile}";
    age.keyFile = site.secrets.ageKeyFile;
    secrets = (lib.optionalAttrs (site.radios.wifi.enable && site.radios.wifi.manageProfile) {
      wifi-env = { path = "/var/lib/nixus-secrets/wifi.env"; restartUnits = [ "NetworkManager-ensure-profiles.service" ]; };
    });
  };
  systemd.tmpfiles.rules = [ "d /var/lib/nixus-secrets 0700 root root -" ];
}

{ lib, pkgs, site, ... }:
{
  boot.kernelModules = [ (if site.cpuVendor == "amd" then "kvm-amd" else "kvm-intel") ];
  virtualisation.libvirtd.enable = lib.mkForce false;
  virtualisation.docker.enable = lib.mkForce false;
  systemd.services.nixus-kvm-check = {
    description = "Require usable hardware virtualization before provisioning VMs";
    wantedBy = [ "multi-user.target" ];
    before = [ "nixus-instances.service" ];
    serviceConfig.Type = "oneshot";
    script = ''
      test -c /dev/kvm
      ${import ../pkgs/nixus.nix { inherit pkgs; }}/bin/nixus-go kvm-check
    '';
  };
}

# incus-compose's shared health/restart controller uses a dedicated control
# bridge. Apps stay on native Compose bridges and cannot reach the host Incus listener.
{ config, lib, ... }:
{
  imports = [ ./management.nix ];
  config = lib.mkIf config.virtualisation.incus.enable {
    virtualisation.incus.preseed.networks = [ {
      name = "icompose0"; type = "bridge";
      # Incus allocates the address on creation. Do not keep "auto" as desired
      # configuration: subsequent infrastructure checks compare concrete values.
      config = { "ipv4.nat" = "false"; "ipv6.address" = "none"; };
    } ];
    nixus.managementPolicy.controllerBridges = [ "icompose0" ];
  };
}

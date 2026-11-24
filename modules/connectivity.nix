{ lib, pkgs, site, installedNetworking ? { networkManager = false; }, ... }:
let
  c = site.connectivity;
  nm = installedNetworking.networkManager;
  wifi = site.radios.wifi;
  managementProfiles = if site.management.interface == wifi.interface
    then lib.optional (site.management.configure && wifi.enable && wifi.manageProfile) "nixus-wifi"
    else lib.optional site.management.configure "nixus-management";
  bridgeNames = map (b: b.name) c.bridges;
  ports = lib.concatMap (b: b.interfaces) c.bridges;
  bridgeFor = name: lib.findFirst (b: builtins.elem name b.interfaces) null c.bridges;
  portConnection = name: {
    id = "nixus-port-${name}"; interface-name = name;
    autoconnect = true; autoconnect-priority = 200;
  } // lib.optionalAttrs (bridgeFor name != null) {
    master = (bridgeFor name).name; slave-type = "bridge";
  };
  vlanProfiles = builtins.listToAttrs (map (v: {
    name = "nixus-vlan-${v.name}";
    value = {
      connection = (portConnection v.name) // { id = "nixus-vlan-${v.name}"; type = "vlan"; };
      vlan = { id = v.id; parent = v.interface; };
    } // lib.optionalAttrs (bridgeFor v.name == null) { ipv4.method = "disabled"; ipv6.method = "disabled"; };
  }) (builtins.filter (v: v.name != site.management.interface) c.vlans));
  ethernetProfiles = builtins.listToAttrs (map (name: {
    name = "nixus-port-${name}";
    value.connection = (portConnection name) // { type = "ethernet"; };
  }) (builtins.filter (name: !(builtins.elem name (map (v: v.name) c.vlans))) ports));
  bridgeProfiles = builtins.listToAttrs (map (b: {
    name = "nixus-bridge-${b.name}";
    value = {
      connection = { id = "nixus-bridge-${b.name}"; type = "bridge"; interface-name = b.name; autoconnect = true; autoconnect-priority = 200; };
      bridge.stp = false;
      ipv4.method = "disabled"; ipv6.method = "disabled";
    };
  }) (builtins.filter (b: b.name != site.management.interface) c.bridges));
  activate = managementProfiles ++ builtins.attrNames bridgeProfiles
    ++ builtins.attrNames vlanProfiles ++ builtins.attrNames ethernetProfiles;
in {
  assertions = [
    { assertion = builtins.length ports == builtins.length (lib.unique ports);
      message = "An Ethernet/VLAN interface may belong to only one host bridge."; }
    { assertion = !(builtins.elem site.management.interface ports);
      message = "Move management addressing onto the bridge before enslaving its port."; }
    { assertion = !(builtins.elem site.guests.bridge (bridgeNames ++ ports ++ [ site.management.interface ]));
      message = "Incus guest bridge must be separate from host/LAN interfaces."; }
  ];
  networking.bridges = lib.mkIf (!nm) (builtins.listToAttrs (map (b: {
    name = b.name; value.interfaces = b.interfaces;
  }) c.bridges));
  networking.vlans = lib.mkIf (!nm) (builtins.listToAttrs (map (v: {
    name = v.name; value = { inherit (v) id interface; };
  }) c.vlans));
  # Bridge ports must not keep DHCP addresses from their previous standalone role.
  networking.interfaces = lib.mkIf (!nm) (builtins.listToAttrs (map (name: {
    inherit name; value = { useDHCP = lib.mkForce false; ipv4.addresses = lib.mkForce [ ]; ipv6.addresses = lib.mkForce [ ]; };
  }) ports));
  networking.networkmanager.ensureProfiles.profiles = lib.mkIf nm (vlanProfiles // ethernetProfiles // bridgeProfiles);
  networking.networkmanager.unmanaged = map (name: "interface-name:${name}")
    (lib.unique ([ site.guests.bridge "incus-*" "ic-*" ] ++ c.preservedIncusBridges
      ++ lib.optionals (!nm) (bridgeNames ++ map (v: v.name) c.vlans ++ ports)));
  systemd.services.nixus-connectivity = lib.mkIf (nm && activate != [ ]) {
    description = "Activate reviewed Ethernet/VLAN profiles";
    wantedBy = [ "multi-user.target" ];
    after = [ "NetworkManager.service" "NetworkManager-ensure-profiles.service" ];
    requires = [ "NetworkManager.service" "NetworkManager-ensure-profiles.service" ];
    before = [ "incus-preseed.service" ];
    path = [ pkgs.networkmanager ];
    restartTriggers = [ (pkgs.writeText "nixus-connectivity.json" (builtins.toJSON { connectivity = c; management = site.management; })) ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; TimeoutStartSec = "2min"; };
    script = lib.concatMapStringsSep "\n" (name: "nmcli --wait 20 connection up " + lib.escapeShellArg name) activate;
  };
}

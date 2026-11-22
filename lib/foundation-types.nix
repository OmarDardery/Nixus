{ lib }:
let
  inherit (lib) mkOption types;
  iface = types.strMatching "[A-Za-z0-9_.-]{1,15}";
  record = options: types.submodule { inherit options; };
  option = type: mkOption { inherit type; };
in {
  "connectivity.bridges" = types.listOf (record {
    name = option iface;
    interfaces = option (types.listOf iface);
  });
  "connectivity.vlans" = types.listOf (record {
    name = option iface;
    interface = option iface;
    id = option (types.ints.between 1 4094);
  });
  "connectivity.privateAccess" = types.listOf (record {
    cidr = option types.str;
    protocol = option (types.enum [ "tcp" "udp" ]);
    ports = option (types.listOf types.port);
  });
}

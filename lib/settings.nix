# A checked compatibility schema: the JSON UI and Nix use the same inventory shape.
{ lib, values ? { }, returnType ? false }:
let
  inherit (lib) mkOption types;
  defaults = import ../site-defaults.nix;
  foundationTypes = import ./foundation-types.nix { inherit lib; };
  mount = types.submodule {
    options = {
      name = mkOption { type = types.strMatching "[a-z][a-z0-9-]{0,31}"; };
      uuid = mkOption { type = types.strMatching "[A-Za-z0-9-]{4,80}"; };
      path = mkOption { type = types.str; };
      fsType = mkOption { type = types.enum [ "ext4" "xfs" "btrfs" "vfat" "exfat" "ntfs3" ]; };
      role = mkOption { type = types.enum [ "data" "guests" "pool" "backup" ]; };
      required = mkOption { type = types.bool; };
      readOnly = mkOption { type = types.bool; };
    };
  };
  makeType = path: value:
    if builtins.hasAttr path foundationTypes then foundationTypes.${path}
    else if path == "schemaVersion" then types.enum [ 4 ]
    else if builtins.elem path [ "cockpit.port" "setup.port" ] then types.port
    else if path == "mounts" then types.listOf mount
    else if builtins.isAttrs value then types.submodule {
      options = lib.mapAttrs (key: default: mkOption {
        type = makeType (if path == "" then key else path + "." + key) default;
        inherit default;
      }) value;
    }
    else if builtins.isList value then types.listOf types.str
    else if builtins.isBool value then types.bool
    else if builtins.isInt value then types.int
    else types.str;
  checked = (lib.evalModules {
    modules = [ { options.settings = mkOption { type = makeType "" defaults; default = defaults; }; }
      { settings = values; } ];
  }).config.settings;
in if returnType then makeType "" defaults else checked

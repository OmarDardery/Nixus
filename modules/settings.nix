{ config, lib, inventory ? import ../site.nix, ... }:
{
  options.nixus.desiredSettings = lib.mkOption {
    type = lib.types.attrs;
    readOnly = true;
    internal = true;
    description = "Normalized source inventory before host module overrides.";
  };
  options.nixus.settings = lib.mkOption {
    type = import ../lib/settings.nix { inherit lib; returnType = true; };
    default = import ../site-defaults.nix;
    description = "Typed host and application inventory, editable through NixOS modules.";
  };
  config = {
    nixus.desiredSettings = inventory;
    # Per-leaf defaults preserve unrelated UI values when one file overrides a setting.
    nixus.settings = lib.mapAttrsRecursive (_: value: lib.mkDefault value) inventory;
    _module.args.site = import ../lib/settings.nix { inherit lib; values = config.nixus.settings; };
    environment.etc."nixus/effective-settings.json".text = builtins.toJSON config.nixus.settings;
  };
}

# Read-only data the Go runtime serves or consults (NIXUS_SOURCE): portal
# assets, recipes, offline guides, helper pins, version and default settings.
{ pkgs }:
pkgs.runCommand "nixus-admin-data" { } ''
  mkdir -p "$out"
  cp -r ${./static} "$out/static"
  cp -r ${./recipes} "$out/recipes"
  cp -r ${../docs} "$out/docs"
  cp ${../helpers/sources.json} "$out/helper-sources.json"
  cp ${../helpers/compatibility.json} "$out/helper-compatibility.json"
  cp ${../VERSION} "$out/VERSION"
  cp ${pkgs.writeText "nixus-default-settings.json" (builtins.toJSON (import ../site-defaults.nix))} "$out/default-settings.json"
''

# Read-only data the Go runtime serves or consults (NIXUS_SOURCE): portal
# assets, offline guides, version and default settings.
{ pkgs }:
pkgs.runCommand "nixus-admin-data" { } ''
  mkdir -p "$out"
  cp -r ${./static} "$out/static"
  cp -r ${../docs} "$out/docs"
  cp ${../VERSION} "$out/VERSION"
  cp ${pkgs.writeText "nixus-default-settings.json" (builtins.toJSON (import ../site-defaults.nix))} "$out/default-settings.json"
''

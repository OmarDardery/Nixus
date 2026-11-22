root:
let
  marker = root + "/machine/format.json";
  version = if builtins.pathExists marker then (builtins.fromJSON (builtins.readFile marker)).version else 1;
  base = root + "/machine";
in if version != 1 then throw "Unsupported Nixus machine directory version" else {
  settings = base + "/settings.json";
  installation = base + "/installation.json";
  modules = base + "/modules";
  installed = base + "/installed-system/configuration.nix";
}

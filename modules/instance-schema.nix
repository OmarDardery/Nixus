{ lib, site, ... }:
let
  identities = map (i: "${i.project}/${i.name}") site.instances;
in {
  options.nixus.incus.desiredInstances = lib.mkOption {
    type = lib.types.listOf lib.types.attrs;
    readOnly = true;
    description = "Internal evaluated reconciliation input, shared with impact planning.";
  };
  config.assertions = [
    { assertion = builtins.length identities == builtins.length (lib.unique identities);
      message = "Instance project/name identities must be unique."; }
  ];
}

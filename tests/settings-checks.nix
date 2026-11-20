{ lib }:
let
  check = values: import ../lib/settings.nix { inherit lib values; };
  rejects = values: !(builtins.tryEval (builtins.deepSeq (check values) true)).success;
  defaults = import ../site-defaults.nix;
  migrate = import ../lib/settings-migrations.nix;
  legacy = { ready = true; monitoring.history = false; adminKeys = [ "fixture" ]; };
in {
  currentMonitoringUnchanged = !(((migrate { schemaVersion = 1; ready = true; monitoring.history = false; }).monitoring) ? collection);
  defaultsPreserved = check defaults == defaults;
  legacyCollectionPreserved = (migrate legacy).monitoring.collection;
  explicitFalsePreserved = !(migrate (legacy // { monitoring.collection = false; })).monitoring.collection;
  freshCollectionUnchanged = !(((migrate { }).monitoring or { }) ? collection);
  migrationIdempotent = migrate (migrate legacy) == migrate legacy;
  migrationPreservesUnrelated = (migrate legacy).adminKeys == legacy.adminKeys;
  currentSchemaPreserved = migrate defaults == defaults;
  futureSchemaRejected = !(builtins.tryEval (builtins.deepSeq (migrate { schemaVersion = 2; }) true)).success;
  effectiveSchemaCannotOverride = rejects { schemaVersion = 2; };
  invalidSchemaRejected = !(builtins.tryEval (builtins.deepSeq (migrate { schemaVersion = "1"; }) true)).success;
  partialInventory = (check { hostName = "fixture"; }).cockpit == defaults.cockpit;
  retiredAppsRejected = rejects { apps.enable = false; };
  unknownSettingRejected = rejects { inventedOption = true; };
  wrongBooleanRejected = rejects { cockpit.enable = "yes"; };
  invalidIngressRejected = rejects { tunnel.ingress."example.invalid" = 10; };
  invalidMountRejected = rejects { mounts = [ { name = "bad"; uuid = "abcd"; path = "/srv/nixus/bad"; fsType = "invented"; role = "data"; required = true; readOnly = false; } ]; };
  optionalStartIsAbsent = !((builtins.head (check { instances = [ { name = "example"; image = "images:fixture"; } ]; }).instances) ? start);
}

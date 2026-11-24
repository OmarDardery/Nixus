{ lib }:
let
  check = values: import ../lib/settings.nix { inherit lib values; };
  rejects = values: !(builtins.tryEval (builtins.deepSeq (check values) true)).success;
  defaults = import ../site-defaults.nix;
  migrate = import ../lib/settings-migrations.nix;
  legacy = { ready = true; monitoring.history = false; adminKeys = [ "fixture" ]; };
in {
  currentMonitoringUnchanged = !(((migrate { schemaVersion = 4; ready = true; monitoring.history = false; }).monitoring) ? collection);
  defaultsPreserved = check defaults == defaults;
  legacyCollectionPreserved = (migrate legacy).monitoring.collection;
  explicitFalsePreserved = !(migrate (legacy // { monitoring.collection = false; })).monitoring.collection;
  freshCollectionUnchanged = !(((migrate { }).monitoring or { }) ? collection);
  migrationIdempotent = migrate (migrate legacy) == migrate legacy;
  migrationPreservesUnrelated = (migrate legacy).adminKeys == legacy.adminKeys;
  currentSchemaPreserved = migrate defaults == defaults;
  futureSchemaRejected = !(builtins.tryEval (builtins.deepSeq (migrate { schemaVersion = 5; }) true)).success;
  effectiveSchemaCannotOverride = rejects { schemaVersion = 5; };
  retiredSectionsDropped = let m = migrate { schemaVersion = 1; hostName = "kept"; backup.enable = true; tunnel.enable = false;
      helpers.enable = true; hardware.serialAliases = [ ]; }; in
    m.schemaVersion == 4 && m.hostName == "kept" && !(m ? backup) && !(m ? tunnel) && !(m ? helpers) && !(m ? hardware);
  legacyReachesCurrent = (migrate legacy).schemaVersion == 4;
  managedPasswordDropped = let m = migrate { schemaVersion = 2; cockpit = { enable = true; port = 9090; managePassword = true; }; }; in
    m.schemaVersion == 4 && m.cockpit.enable && !(m.cockpit ? managePassword);
  legacyInstancesAndGuestInterfacesDropped = let m = migrate {
    schemaVersion = 3;
    instances = [ { name = "old"; } ];
    connectivity = { guestInterfaces = [ "incusbr0" ]; trustedLANAccess = true; };
  }; in m.schemaVersion == 4 && !(m ? instances) && m.connectivity.trustedLANAccess && !(m.connectivity ? guestInterfaces);
  invalidSchemaRejected = !(builtins.tryEval (builtins.deepSeq (migrate { schemaVersion = "1"; }) true)).success;
  partialInventory = (check { hostName = "fixture"; }).cockpit == defaults.cockpit;
  retiredAppsRejected = rejects { apps.enable = false; };
  retiredInstancesRejected = rejects { instances = [ ]; };
  unknownSettingRejected = rejects { inventedOption = true; };
  wrongBooleanRejected = rejects { cockpit.enable = "yes"; };
  retiredTunnelRejected = rejects { tunnel.enable = false; };
  invalidMountRejected = rejects { mounts = [ { name = "bad"; uuid = "abcd"; path = "/srv/nixus/bad"; fsType = "invented"; role = "data"; required = true; readOnly = false; } ]; };
}

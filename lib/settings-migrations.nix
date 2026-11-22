# Pure, read-compatible settings migrations. Directory layout versions are independent.
#   0 -> 1: monitoring.collection defaults on for hosts that were already set up.
#   1 -> 2: drop retired sections (legacy host backup, host tunnel, helpers, serial aliases).
#   2 -> 3: drop cockpit.managePassword (Cockpit uses your Linux login).
stored:
let
  version = stored.schemaVersion or 0;
  legacy = if (stored.ready or false) && !((stored.monitoring or { }) ? collection)
    then stored // { monitoring = (stored.monitoring or { }) // { collection = true; }; }
    else stored;
  v1 = if version == 0 then legacy // { schemaVersion = 1; } else stored;
  v2 = if v1.schemaVersion == 1
    then builtins.removeAttrs v1 [ "backup" "tunnel" "helpers" "hardware" ] // { schemaVersion = 2; }
    else v1;
  v3 = if v2.schemaVersion == 2
    then v2 // { schemaVersion = 3; } // (if v2 ? cockpit && builtins.isAttrs v2.cockpit
      then { cockpit = builtins.removeAttrs v2.cockpit [ "managePassword" ]; } else { })
    else v2;
in
if !builtins.isAttrs stored then throw "Nixus settings must be an object"
else if !builtins.isInt version || version < 0 || version > 3 then
  throw "Unsupported Nixus settings schema version"
else v3

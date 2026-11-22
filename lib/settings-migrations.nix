# Pure, read-compatible settings migrations. Directory layout versions are independent.
#   0 -> 1: monitoring.collection defaults on for hosts that were already set up.
#   1 -> 2: drop retired sections (legacy host backup, host tunnel, helpers, serial aliases).
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
in
if !builtins.isAttrs stored then throw "Nixus settings must be an object"
else if !builtins.isInt version || version < 0 || version > 2 then
  throw "Unsupported Nixus settings schema version"
else v2

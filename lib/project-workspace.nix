# Read-only, deterministic project workspace evaluator.
# Deliberately independent of the NixOS host/module system and Incus runtime.
{ lib }:
{ root }:
let
  inherit (lib) mkOption types;
  fail = message: throw "Nixus projects: ${message}";
  sorted = names: lib.sort builtins.lessThan names;
  isIgnored = name: lib.hasPrefix "_" name || lib.hasPrefix "." name;

  # A path reference in a manifest is never allowed to escape a project.
  validRelative = value:
    value == null ||
    (builtins.isString value &&
      lib.all (part:
        part != "" && part != "." && part != ".." &&
        builtins.match "[A-Za-z0-9._-]+" part != null
      ) (lib.splitString "/" value));

  # readDir detects symlinks without following them. Do not let a workspace
  # import files outside its immutable reviewed source by accident.
  entriesAt = dir:
    let entries = builtins.readDir dir;
        links = builtins.filter (name: entries.${name} == "symlink")
          (builtins.attrNames entries);
    in if links != [] then fail "Symlink forbidden in ${toString dir}: ${builtins.head links}"
       else entries;

  # Validate the *whole* project source tree, even inert resource files.
  # The later isolated evaluator must still use the Python preflight and a
  # frozen candidate: pure Nix cannot prevent arbitrary explicit imports.
  scanTree = directory: depth:
    if depth > 16 then fail "Project source exceeds 16 directory levels"
    else let
      entries = entriesAt directory;
      names = sorted (builtins.attrNames entries);
      forbidden = builtins.filter (name:
        name == ".env" || lib.hasPrefix ".env." name ||
        lib.hasSuffix ".agekey" name ||
        builtins.elem name [ "id_rsa" "id_ed25519" "id_ecdsa" ]
      ) names;
      childDirs = builtins.filter (name:
        entries.${name} == "directory" && name != ".git"
      ) names;
    in if forbidden != [] then
      fail "Potential plaintext credential in project source: ${builtins.head forbidden}"
    else builtins.deepSeq
      (map (name: scanTree (directory + "/${name}") (depth + 1)) childDirs)
      true;

  # Deterministic recursion, with disabled/hidden subtrees ignored. Paths in
  # files/ (including .nix files) are never discovered as modules.
  moduleFiles = directory: depth:
    if depth > 8 then fail "Module nesting exceeds eight directories"
    else let entries = entriesAt directory; in
      lib.concatMap (name:
        let kind = entries.${name};
            child = directory + "/${name}";
        in if isIgnored name then []
           else if kind == "directory" then moduleFiles child (depth + 1)
           else if kind == "regular" && lib.hasSuffix ".nix" name then [ child ]
           else if kind == "regular" then []
           else fail "Unsupported module entry ${toString child}"
      ) (sorted (builtins.attrNames entries));

  schema = directoryName: { lib, ... }: {
    options.nixus.project = {
      name = mkOption {
        type = types.strMatching "[a-z][a-z0-9-]{0,62}";
        default = directoryName;
        description = "Stable managed project identity.";
      };
      enable = mkOption { type = types.bool; default = true; };
      backend = mkOption {
        type = types.enum [ "incus-native" "incus-compose" ];
        default = "incus-native";
      };
      incusProject = mkOption {
        type = types.strMatching "[a-z][a-z0-9-]{0,62}";
        default = directoryName;
      };
      resources.cpus = mkOption { type = types.ints.positive; default = 2; };
      resources.memory = mkOption {
        type = types.strMatching "[1-9][0-9]*(KiB|MiB|GiB)";
        default = "2GiB";
      };
      # Values, passwords and token contents are not Nix options. Only the
      # relative name of the *ciphertext* resource is represented here.
      secrets.file = mkOption { type = types.nullOr types.str; default = null; };
      secrets.bindings = mkOption {
        # A binding declares which owned instance receives a secret, and
        # through which *file* path. Plaintext values never become Nix attrs.
        type = types.attrsOf (types.submodule ({ name, ... }: {
          options = {
            key = mkOption {
              type = types.strMatching "[A-Za-z_][A-Za-z0-9_]{0,127}";
              default = name;
              description = "SOPS YAML key; never its decrypted value.";
            };
            instance = mkOption {
              type = types.strMatching "[a-z][a-z0-9-]{0,62}";
              description = "Destination instance in this project's Incus namespace.";
            };
            backend = mkOption {
              type = types.enum [ "nixos-sops" "incus-file" ];
              default = "incus-file";
            };
            destination = mkOption {
              type = types.strMatching "/run/secrets/[A-Za-z_][A-Za-z0-9_/-]*";
              default = "/run/secrets/${name}";
              description = "Scoped read-only runtime secret-file path.";
            };
            restartUnits = mkOption {
              type = types.listOf (types.strMatching "[A-Za-z0-9_.@-]+\\.service");
              default = [];
              description = "NixOS service restart intent; only applied after a reviewed rollout.";
            };
          };
        }));
        default = {};
        description = "Metadata-only per-instance SOPS secret delivery declarations.";
      };
      # Image updates for Compose projects (#61): manual (default) only reports,
      # notify also fails the check unit so a webhook fires, auto applies
      # inside the optional maintenance window with snapshot and rollback.
      updates.policy = mkOption { type = types.enum [ "manual" "notify" "auto" ]; default = "manual"; };
      updates.window = mkOption {
        type = types.nullOr (types.strMatching "([01][0-9]|2[0-3]):[0-5][0-9]-([01][0-9]|2[0-3]):[0-5][0-9]");
        default = null;
        description = "Local-time maintenance window such as 02:00-05:00; null means any time.";
      };
      updates.healthSeconds = mkOption { type = types.ints.between 5 3600; default = 60; };
      backup.enable = mkOption { type = types.bool; default = true; };
      backup.consistency = mkOption {
        type = types.enum [ "stop" "quiesce" "none" ];
        default = "stop";
      };
      # Optional explicit pool; null uses the host guest storage pool.
      storagePool = mkOption {
        type = types.nullOr (types.strMatching "[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}");
        default = null;
      };
      # Custom volumes are created once and never resized or deleted by Nixus.
      volumes = mkOption {
        type = types.attrsOf (types.submodule {
          options.size = mkOption { type = types.strMatching "[1-9][0-9]*(MiB|GiB|TiB)"; default = "10GiB"; };
        });
        default = {};
      };
      # Declared native guests. Declaring an instance claims it exclusively.
      instances = mkOption {
        type = types.attrsOf (types.submodule {
          options = {
            type = mkOption { type = types.enum [ "container" "virtual-machine" ]; default = "container"; };
            image = mkOption {
              type = types.strMatching "images:[a-z0-9][a-z0-9._/-]{0,127}";
              description = "Public images: remote alias used only when the instance is first created.";
            };
            cpus = mkOption { type = types.nullOr types.ints.positive; default = null; };
            memory = mkOption { type = types.nullOr (types.strMatching "[1-9][0-9]*(KiB|MiB|GiB)"); default = null; };
            autostart = mkOption { type = types.bool; default = true; };
            network = mkOption {
              type = types.nullOr (types.strMatching "[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}");
              default = null;
              description = "Incus network for eth0; null uses the host guest bridge.";
            };
            disks = mkOption {
              type = types.attrsOf (types.submodule {
                options = {
                  volume = mkOption { type = types.strMatching "[a-z][a-z0-9-]{0,62}"; };
                  path = mkOption { type = types.strMatching "/[A-Za-z0-9._/-]*"; };
                  readOnly = mkOption { type = types.bool; default = false; };
                };
              });
              default = {};
            };
            usb = mkOption {
              type = types.attrsOf (types.submodule {
                options = {
                  vendorId = mkOption { type = types.strMatching "[0-9a-f]{4}"; };
                  productId = mkOption { type = types.strMatching "[0-9a-f]{4}"; };
                };
              });
              default = {};
              description = "Reviewed USB passthrough by vendor/product ID.";
            };
          };
        });
        default = {};
      };
      # Reserved identities used by later reconcilers; collisions are rejected
      # before anyone is authorized to mutate Incus.
      claims = mkOption {
        type = types.listOf (types.strMatching "[a-z][a-z0-9-]*/[A-Za-z0-9_.-]+");
        default = [];
      };
    };
  };

  runtimePath = types.strMatching "/(var/lib|run|etc)/[A-Za-z0-9._/-]+";
  backupSchema = { lib, ... }: {
    options.nixus.backups = {
      enable = mkOption { type = types.bool; default = false; };
      includeProjects = mkOption {
        type = types.either (types.enum [ "all" ]) (types.listOf (types.strMatching "[a-z][a-z0-9-]{0,62}"));
        default = "all";
        description = "\"all\" includes every project discovered at backup time, including new ones.";
      };
      schedule = mkOption { type = types.enum [ "hourly" "daily" "weekly" ]; default = "daily"; };
      data = mkOption { type = types.bool; default = true; description = "Also export Incus instances and custom volumes."; };
      retention = {
        daily = mkOption { type = types.ints.between 1 365; default = 7; };
        weekly = mkOption { type = types.ints.between 0 104; default = 4; };
        monthly = mkOption { type = types.ints.between 0 120; default = 6; };
      };
      verification = mkOption { type = types.enum [ "none" "metadata" "full" ]; default = "metadata"; };
      restic = {
        repository = mkOption {
          type = types.strMatching "(rclone:[A-Za-z0-9_-]+:[A-Za-z0-9._/-]+|sftp:[A-Za-z0-9._/-]+|s3:[A-Za-z0-9._:/-]+|b2:[A-Za-z0-9._:/-]+|rest:https://[A-Za-z0-9._:/-]+|/[A-Za-z0-9._/-]+)";
          description = "Repository reference only; credentials live in root-owned runtime files.";
        };
        passwordFile = mkOption { type = runtimePath; default = "/var/lib/nixus-secrets/project-restic-password"; };
        environmentFile = mkOption { type = types.nullOr runtimePath; default = null; };
        rcloneConfigFile = mkOption { type = types.nullOr runtimePath; default = null; };
        initialize = mkOption { type = types.bool; default = false; };
      };
      github = mkOption {
        type = types.nullOr (types.submodule {
          options = {
            repository = mkOption { type = types.strMatching "git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git"; };
            branch = mkOption { type = types.strMatching "[A-Za-z0-9._/-]{1,100}"; default = "main"; };
          };
        });
        default = null;
        description = "Private repository that receives non-secret project configuration and SOPS ciphertext.";
      };
    };
  };
  backups = if (rootEntries."backups.nix" or null) == "regular"
    then (lib.evalModules { modules = [ backupSchema (root + "/backups.nix") ]; }).config.nixus.backups
    else null;

  rootEntries = entriesAt root;
  projectDirs = builtins.filter (name:
    let kind = rootEntries.${name};
    in !isIgnored name && kind == "directory" &&
      ((entriesAt (root + "/${name}"))."default.nix" or null) == "regular"
  ) (sorted (builtins.attrNames rootEntries));

  projects = map (directoryName:
    let directory = root + "/${directoryName}";
        entries = entriesAt directory;
        hasModules = entries ? modules;
        sources = if !hasModules then []
          else if entries.modules == "directory"
            then moduleFiles (directory + "/modules") 0
            else fail "modules must be a directory in ${directoryName}";
        # The default module is first; all discovered fragments are sorted.
        evaluated = lib.evalModules {
          modules = [ (schema directoryName) (directory + "/default.nix") ] ++ sources;
        };
        p = evaluated.config.nixus.project;
        secret = p.secrets.file;
    in if !(scanTree directory 0) then
      fail "Unsafe project source directory"
    else if !validRelative secret then
      fail "Project ${directoryName} has an unsafe ciphertext reference"
    else if p.secrets.bindings != {} && secret == null then
      fail "Project ${directoryName} cannot bind secrets without encrypted SOPS ciphertext"
    else if p.backend == "incus-compose" && (p.instances != {} || p.volumes != {}) then
      fail "Compose project ${directoryName} cannot declare native instances or volumes"
    else if lib.any (i: lib.any (d: !(p.volumes ? ${d.volume})) (builtins.attrValues i.disks)) (builtins.attrValues p.instances) then
      fail "Project ${directoryName} attaches an undeclared volume"
    else if lib.any (n: builtins.match "[a-z][a-z0-9-]{0,62}" n == null) (builtins.attrNames p.instances ++ builtins.attrNames p.volumes) then
      fail "Project ${directoryName} has an invalid instance or volume name"
    else if builtins.length sources > 256 then
      fail "Project ${directoryName} exceeds 256 Nix module files"
    else {
      name = p.name;
      inherit (p) enable backend incusProject resources secrets backup storagePool volumes instances updates;
      claims = lib.unique (p.claims ++ map (name: "instance/${name}") (sorted (builtins.attrNames p.instances)));
      source = directoryName;
      modules = map (path:
        lib.removePrefix ("${toString directory}/") (toString path)
      ) sources;
    }
  ) projectDirs;

  names = map (p: p.name) projects;
  incusProjects = map (p: p.incusProject) projects;
  claims = lib.concatMap (p: p.claims) projects;
  noDuplicates = values: builtins.length values == builtins.length (lib.unique values);
in
  if builtins.length projectDirs > 128 then fail "Workspace exceeds 128 projects"
  else if !(noDuplicates names) then fail "Duplicate Nixus project identities"
  else if !(noDuplicates incusProjects) then fail "Multiple projects claim the same Incus project"
  else if !(noDuplicates claims) then fail "Conflicting declared resource claims"
  else {
    schemaVersion = 1;
    inherit backups;
    projects = builtins.listToAttrs (map (project: {
      name = project.name;
      value = project;
    }) projects);
  }

{
  description = "Nixus: Incus-native NixOS homelab management";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
  inputs.sops-nix = {
    url = "github:Mic92/sops-nix/60182817ee048ac94b4c68ea76d5ef2e8aac730d";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, sops-nix }:
    let
      checkSettings = values: import ./lib/settings.nix { lib = nixpkgs.lib; inherit values; };
      site = checkSettings (import ./site.nix);
      testSite = import ./tests/site.nix;
      bootstrap = nixpkgs.lib.nixosSystem {
        system = site.system; specialArgs = { inventory = site; installedBase = null; };
        modules = [ ./configuration-bootstrap.nix ];
      };
      installedNetworking = if builtins.pathExists (import ./lib/machine.nix ./.).installed
        then { networkManager = bootstrap.config.networking.networkmanager.enable; }
        else { networkManager = false; };
      # Incus is the only guest runtime: no built-in Docker applications VM.
      mkHost = inventory: extra: mkHostNetwork inventory extra installedNetworking;
      mkHostNetwork = inventory: extra: networking: nixpkgs.lib.nixosSystem {
        system = inventory.system;
        specialArgs = { inventory = checkSettings inventory; installedNetworking = networking; installedBase = null; };
        modules = [ sops-nix.nixosModules.sops ./configuration.nix ] ++ extra;
      };
      installer = import ./installer/package.nix { inherit pkgs; };
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      ethernetSite = testSite // {
        management = testSite.management // { interface = "br-lan"; configure = true; };
        connectivity = testSite.connectivity // {
          bridges = [ { name = "br-lan"; interfaces = [ "eth0" ]; } { name = "br-apps"; interfaces = [ "vlan20" ]; } ];
          vlans = [ { name = "vlan20"; interface = "eth1"; id = 20; } ];
          guestInterfaces = [ "incusbr0" "incus-private" ]; trustedLANAccess = true;
          privateAccess = [ { cidr = "192.0.2.53/32"; protocol = "udp"; ports = [ 53 ]; } ];
        };
      };
    in {
      # Reusable pure evaluator for a separate /srv/nixus/projects flake.
      # No system, Incus instance or host service is changed by this export.
      lib.evalProjects = import ./lib/project-workspace.nix { lib = nixpkgs.lib; };
      nixusProjectChecks = self.lib.evalProjects { root = ./tests/project-workspace; };
      nixusGuestSecretsChecks = let
        fragment = import ./lib/project-guest-secrets.nix { lib = nixpkgs.lib; };
        sample = fragment {
          project = "alpha";
          instance = "web";
          sopsFile = "/srv/nixus/projects/alpha/secrets.enc.yaml";
          guestAgeKeyFile = "/var/lib/sops-nix/guest.agekey";
          bindings = {
            TOKEN = {
              instance = "web"; key = "API_TOKEN"; backend = "nixos-sops";
              destination = "/run/secrets/TOKEN"; restartUnits = [ "web.service" ];
            };
            DB = {
              instance = "database"; key = "DB_PASSWORD"; backend = "nixos-sops";
              destination = "/run/secrets/DB"; restartUnits = [];
            };
          };
        };
        rejects = arg: !(builtins.tryEval (builtins.deepSeq (fragment arg) true)).success;
        args = {
          project = "alpha"; instance = "web";
          sopsFile = "/srv/nixus/projects/alpha/secrets.enc.yaml";
          guestAgeKeyFile = "/var/lib/sops-nix/guest.agekey";
          bindings.TOKEN = {
            instance = "web"; key = "API_TOKEN"; backend = "nixos-sops";
            destination = "/run/secrets/TOKEN"; restartUnits = [ "web.service" ];
          };
        };
      in {
        onlyScopedConsumer = builtins.attrNames sample.sops.secrets == [ "TOKEN" ];
        guestIdentityNotHostMaster = sample.sops.age.keyFile == "/var/lib/sops-nix/guest.agekey";
        fileOnlyCredentials = sample.sops.secrets.TOKEN.mode == "0400";
        runtimeCiphertextNoStoreImport = sample.sops.validateSopsFiles == false;
        explicitGuestKeyOnly = sample.sops.age.generateKey == false
          && sample.sops.age.sshKeyPaths == []
          && sample.sops.gnupg.sshKeyPaths == [];
        guestSecretsUseSystemdActivation = sample.sops.useSystemdActivation == true;
        declaredRestartOnly = sample.sops.secrets.TOKEN.restartUnits == [ "web.service" ];
        hostMasterKeyRejected = rejects (args // { guestAgeKeyFile = "/var/lib/nixus/keys/projects.agekey"; });
        missingGuestBindingRejected = rejects (args // { instance = "unlisted"; });
        plaintextSourceRejected = rejects (args // { sopsFile = "/srv/nixus/alpha/.env"; });
      };
      nixusProjectValidationChecks = let
        rejected = root: !(builtins.tryEval
          (builtins.deepSeq (self.lib.evalProjects { inherit root; }) true)).success;
      in {
        duplicateIdentitiesRejected = rejected ./tests/project-workspace-duplicates;
        secretTraversalRejected = rejected ./tests/project-workspace-invalid-secret;
        conflictingClaimsRejected = rejected ./tests/project-workspace-bad-claim;
        plaintextSourceRejected = rejected ./tests/project-workspace-plaintext;
      };
      nixosModules = import ./lib/platform.nix;
      nixosConfigurations = {
        hypervisor = mkHost site [ ];
        inherit bootstrap;
        # Evaluation fixtures, never an installation target.
        validation-minimal = mkHost testSite [ ./tests/hardware.nix ];
        validation-file-disk = mkHost testSite
          ([ ./tests/hardware.nix ] ++ (import ./lib/site-modules.nix ./tests/module-tree));
        validation-notifications = mkHost testSite [ ./tests/hardware.nix { nixus.notifications.enable = true; } ];
        validation-host = mkHost testSite [ ./tests/hardware.nix ];
        validation-management = mkHost (testSite // {
          monitoring = testSite.monitoring // { history = true; };
          cockpit = testSite.cockpit // { enable = true; };
          setup = testSite.setup // { enable = true; };
          maintenance = testSite.maintenance // { laptopMode = true; };
        }) [ ./tests/hardware.nix ];
        validation-ethernet = mkHost ethernetSite [ ./tests/hardware.nix ];
        validation-ethernet-nm = mkHostNetwork ethernetSite
          [ ./tests/hardware.nix { networking.networkmanager.enable = true; } ] { networkManager = true; };
        validation-ethernet-wifi = mkHostNetwork (ethernetSite // {
          management = ethernetSite.management // { interface = "wlan0"; };
          radios = ethernetSite.radios // { wifi = ethernetSite.radios.wifi // {
            enable = true; interface = "wlan0"; ssid = "FIXTURE-ONLY"; manageProfile = true;
          }; };
        }) [ ./tests/hardware.nix { networking.networkmanager.enable = true; } ] { networkManager = true; };
        validation-services = mkHost (testSite // {
          monitoring = testSite.monitoring // { history = true; };
        }) [ ./tests/hardware.nix ];
        # Fresh-install shape: every host credential is SOPS/age ciphertext.
        validation-sops = mkHost (testSite // {
          secrets = testSite.secrets // { enable = true; hostFile = "tests/fixtures/host-secrets.yaml"; };
          cockpit = testSite.cockpit // { enable = true; };
          radios = testSite.radios // { wifi = { enable = true; interface = "wlan0"; ssid = "FIXTURE-ONLY"; manageProfile = true; }; };
        }) [ ./tests/hardware.nix { networking.networkmanager.enable = true; } ];
        validation-bootstrap = nixpkgs.lib.nixosSystem {
          system = testSite.system;
          specialArgs = { inventory = testSite // { setup = testSite.setup // { enable = true; }; }; installedBase = ./tests/installed-base.nix; };
          modules = [ ./configuration-bootstrap.nix ];
        };
        validation-inherited = nixpkgs.lib.nixosSystem {
          system = testSite.system;
          specialArgs = { inventory = testSite; installedBase = ./tests/installed-base.nix; installedNetworking.networkManager = true; };
          modules = [ sops-nix.nixosModules.sops ./configuration.nix ];
        };
        validation-setup = mkHost (testSite // {
          setup = testSite.setup // { enable = true; };
          management = testSite.management // { configure = true; };
          radios = { wifi = { enable = true; interface = "wlan0"; ssid = "TEST-ONLY"; manageProfile = true; }; bluetooth.enable = true; };
          mounts = [
            { name = "guests"; uuid = "11111111-1111-1111-1111-111111111111"; path = "/srv/nixus/guests"; fsType = "ext4"; role = "guests"; required = true; readOnly = false; }
            { name = "archive"; uuid = "22222222-2222-2222-2222-222222222222"; path = "/srv/nixus/archive"; fsType = "xfs"; role = "pool"; required = true; readOnly = false; }
          ];
          storage = testSite.storage // { source = "/srv/nixus/guests/incus"; };
        }) [ ./tests/hardware.nix ];
        validation-zfs = mkHost (testSite // {
          storage = { driver = "zfs"; source = "testpool/incus";
            confirmedExistingZfsDataset = true; hostId = "1234abcd"; };
        }) [ ./tests/hardware.nix ];
      };
      packages.x86_64-linux = {
        inherit installer;
        nixus = import ./pkgs/nixus.nix { inherit pkgs; };
        default = self.packages.x86_64-linux.nixus;
        admin = import ./admin/package.nix { inherit pkgs; };
        homelab = import ./scripts/homelab.nix { inherit pkgs; };
      };
      apps.x86_64-linux.install = { type = "app"; program = "${self.packages.x86_64-linux.installer}/bin/nixus-install"; };
      apps.x86_64-linux.update = { type = "app"; program = "${self.packages.x86_64-linux.installer}/bin/nixus-update"; };
      nixusMigrationChecks = import ./tests/settings-checks.nix { lib = nixpkgs.lib; };
      # Fresh installs keep every host credential in SOPS ciphertext.
      nixusSecretsChecks = let
        c = self.nixosConfigurations.validation-sops.config;
        plain = self.nixosConfigurations.validation-services.config;
      in {
        hostFileIsDefault = toString c.sops.defaultSopsFile == toString ./tests/fixtures/host-secrets.yaml;
        wifiFromSops = c.sops.secrets.wifi-env.path == "/var/lib/nixus-secrets/wifi.env";
        disabledDeclaresNothing = plain.sops.secrets == { };
      };
      nixusManagementChecks = let
        c = self.nixosConfigurations.validation-management.config;
        lib = nixpkgs.lib;
        inventory = builtins.fromJSON c.environment.etc."nixus/management-exposure.json".text;
        filtered = builtins.filter (item: item.exposure == "local") inventory.listeners;
        actualLocalPorts = map (item: item.port) filtered;
        case = address: ([ ./tests/hardware.nix {
          services.openssh.listenAddresses = [{ addr = address; port = 9090; }];
          nixus.settings.cockpit.enable = true;
        } ]);
        collisions = address: builtins.filter (entry:
          !entry.assertion && lib.hasPrefix "Management listener collision" entry.message)
          (mkHost testSite (case address)).config.assertions;
        monitoringCollision = (mkHost testSite [ ./tests/hardware.nix {
          nixus.settings.cockpit = { enable = true; port = 9091; };
          nixus.settings.monitoring.history = true;
        } ]).config.assertions;
      in {
        onlyLoopbackTrusted = c.networking.firewall.trustedInterfaces == [ "lo" ];
        listenerInventory = inventory.firewallManaged && !inventory.ipv6TrustedIngress
          && actualLocalPorts == [ 9091 9100 ];
        scopedRuleExcludesMetrics = lib.hasInfix "tcp dport" c.networking.firewall.extraInputRules
          && !(lib.hasInfix "9091" c.networking.firewall.extraInputRules)
          && !(lib.hasInfix "9443" c.networking.firewall.extraInputRules)
          && !(lib.hasInfix "9441" c.networking.firewall.extraInputRules);
        ipv4Collision = builtins.length (collisions "127.0.0.1") == 1;
        ipv6SeparateBind = collisions "::1" == [ ];
        cockpitPrometheusCollision = lib.any (entry:
          !entry.assertion && lib.hasPrefix "Management listener collision on tcp/9091" entry.message) monitoringCollision;
        cockpitEnabled = c.services.cockpit.enable;
        cockpitLocalOnly = !c.services.cockpit.settings.WebService.LoginTo;
        cockpitAddress = c.systemd.sockets.cockpit.listenStreams == [ "" "0.0.0.0:9090" ];
        cockpitPAM = c.security.pam.services ? cockpit;
        monitoringWithCockpit = c.services.prometheus.enable
          && c.services.prometheus.listenAddress == "127.0.0.1"
          && c.services.prometheus.port == 9091
          && c.services.prometheus.port != c.nixus.settings.cockpit.port;
        hostDockerDisabled = !c.virtualisation.docker.enable;
        noLegacyExposedPorts = !(lib.any (item: builtins.elem item.port [ 9441 9443 ]) inventory.listeners);
        lidClosedOperation = c.services.logind.settings.Login.HandleLidSwitch == "ignore";
      };
      nixusFoundationChecks = let
        native = self.nixosConfigurations.validation-ethernet.config;
        nm = self.nixosConfigurations.validation-ethernet-nm.config;
        wifi = self.nixosConfigurations.validation-ethernet-wifi.config;
      in {
        nativeBridgePorts = native.networking.bridges.br-apps.interfaces == [ "vlan20" ];
        nativePortAddressRemoved = native.networking.interfaces.eth0.ipv4.addresses == [ ];
        vlanActivationName = nm.networking.networkmanager.ensureProfiles.profiles.nixus-vlan-vlan20.connection.id == "nixus-vlan-vlan20";
        vlanBridgeMembership = nm.networking.networkmanager.ensureProfiles.profiles.nixus-vlan-vlan20.connection.master == "br-apps";
        guestNetworkOwnership = builtins.elem "interface-name:incus-private" nm.networking.networkmanager.unmanaged;
        wifiManagementActivation = nixpkgs.lib.hasInfix "connection up nixus-wifi" wifi.systemd.services.nixus-connectivity.script;
        noWiredManagementOnWifi = !(nixpkgs.lib.hasInfix "connection up nixus-management" wifi.systemd.services.nixus-connectivity.script);
      };
      nixusDefaults = import ./site-defaults.nix;
      nixusDesiredSettings = site;
      nixusSettings = self.nixosConfigurations.hypervisor.config.nixus.settings;
      nixusOverview = {
        stateVersion = bootstrap.config.system.stateVersion;
        boot = { systemdBoot = bootstrap.config.boot.loader.systemd-boot.enable; grub = bootstrap.config.boot.loader.grub.enable; };
        networkManager = installedNetworking.networkManager;
        wpaProfiles = bootstrap.config.networking.wireless.networks != { };
        fileSystems = builtins.mapAttrs (_: fs: { inherit (fs) device fsType options; }) bootstrap.config.fileSystems;
        adminKeys = nixpkgs.lib.unique (nixpkgs.lib.concatMap (user: user.openssh.authorizedKeys.keys)
          (builtins.filter (user: user.name == "root" || builtins.elem "wheel" user.extraGroups)
            (builtins.attrValues bootstrap.config.users.users)));
      };
      checks.x86_64-linux = {
        # Builds the Go runtime and runs its unit tests (go test) in the sandbox.
        nixus = self.packages.x86_64-linux.nixus;
        # Boots the Go broker and portal in a NixOS VM (needs KVM).
        portal = import ./tests/portal-vm.nix { inherit pkgs; };
        networking = import ./tests/networking-vm.nix { inherit pkgs; };
        oci = import ./tests/oci-vm.nix { inherit pkgs; };
        admin = self.packages.x86_64-linux.admin;
        installer = self.packages.x86_64-linux.installer;
        host = self.nixosConfigurations.validation-host.config.system.build.toplevel;
        homelab = self.packages.x86_64-linux.homelab;
      };
      devShells.x86_64-linux = {
        default = pkgs.mkShell {
          packages = with pkgs; [ go gopls nixfmt shellcheck incus-lts.client sops age ];
        };
      };
    };
}


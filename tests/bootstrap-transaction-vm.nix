{ pkgs }:
let
  defaults = import ../site-defaults.nix;
  settings = defaults // {
    hostName = "bootstrap-test"; cpuVendor = "intel";
    setup = defaults.setup // { enable = true; };
    management = defaults.management // {
      interface = "eth1"; address = "192.168.1.1";
      trustedCIDRs = [ "192.168.1.0/24" ];
    };
  };
in pkgs.testers.runNixOSTest {
  name = "nixus-bootstrap-transaction";
  globalTimeout = 600;
  node.specialArgs = {
    inventory = settings;
    installedBase = { ... }: { system.stateVersion = "26.05"; };
  };
  nodes.machine = { lib, ... }: {
    imports = [ ../configuration-bootstrap.nix ];
    # Test nodes normally boot an image without activation tooling. This fixture
    # deliberately exercises the production switch/rollback implementation.
    system.activatable = lib.mkForce true;
    system.switch.enable = lib.mkForce true;
    boot.kernelModules = lib.mkForce [ ];
    virtualisation.memorySize = 2048;
    # A real switch installs the bootloader. The default partitionless direct-
    # boot scratch disk cannot embed GRUB; use NixOS's bootable test-disk layout.
    virtualisation.useBootLoader = true;
    virtualisation.installBootLoader = true;
    virtualisation.diskSize = 4096;
    virtualisation.vlans = [ 1 ];
    networking.interfaces.eth1.ipv4.addresses = [ { address = "192.168.1.1"; prefixLength = 24; } ];
    environment.etc."nixus-test-settings.json".text = builtins.toJSON settings;
    environment.systemPackages = [ pkgs.python3 pkgs.nix pkgs.openssl pkgs.iproute2 ];
    systemd.services.nixus-test-fixture = {
      wantedBy = [ "multi-user.target" ];
      after = [ "systemd-tmpfiles-setup.service" ];
      before = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
      requiredBy = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
      environment.NIXUS_TEST_SITE_SOURCE = toString (import ./site-source.nix { inherit pkgs; });
      path = [ pkgs.openssl ];
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; UMask = "0077"; };
      script = ''PYTHONPATH=${../admin}:${../scripts} ${pkgs.python3}/bin/python3 ${./bootstrap-transaction-fixture.py} initialize'';
    };
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("nixus-ui.service")
    machine.wait_for_unit("nginx.service")
    machine.wait_for_unit("nixus-rollback-guard.timer")
    try:
        machine.succeed("PYTHONPATH=${../admin}:${../scripts} python3 ${./bootstrap-transaction-fixture.py} activate")
    except Exception:
        # Disposable fixture only: retain the actual activation failure instead
        # of losing the worker's private log when the failed VM is destroyed.
        print(machine.execute("cat /var/lib/nixus-admin/jobs/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/build.log")[1])
        print(machine.execute("systemctl --failed --no-pager")[1])
        raise
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("nixus-ui.service")
    machine.wait_until_succeeds("PYTHONPATH=${../admin}:${../scripts} python3 ${./bootstrap-transaction-fixture.py} recovered", timeout=180)
    machine.fail("systemctl is-active incus.service docker.service cockpit.socket")
    machine.succeed("test ! -e /var/lib/incus/database")
  '';
}

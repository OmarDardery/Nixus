# Fresh-install state -> console-approved browser claim -> setup progress ->
# reboot. Exercises installer-equivalent enrollment and host SOPS tooling on
# real NixOS. Building the full hypervisor inside a VM stays with #44/#14.
{ pkgs }:
let
  defaults = import ../site-defaults.nix;
  settings = defaults // {
    hostName = "nixus-first-run"; cpuVendor = "intel";
    setup = defaults.setup // { enable = true; };
    cockpit = defaults.cockpit // { enable = true; };
    management = defaults.management // { interface = "eth0"; address = "127.0.0.1"; trustedCIDRs = [ "127.0.0.0/8" ]; };
  };
in pkgs.testers.runNixOSTest {
  globalTimeout = 900;
  name = "nixus-first-run";
  node.specialArgs = {
    inventory = settings;
    installedBase = { ... }: { system.stateVersion = "26.05"; };
  };
  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../configuration-bootstrap.nix ../modules/cockpit.nix ../modules/security.nix ];
    virtualisation.memorySize = 2048;
    boot.kernelModules = lib.mkForce [ ];
    environment.systemPackages = [ pkgs.python3 pkgs.sops pkgs.age pkgs.openssl ];
    environment.etc."nixus-test-settings.json".text = builtins.toJSON settings;
    environment.etc."nixus-test-client.py".source = ./first-run-client.py;
    environment.etc."nixus-test-admin".source = ../admin;
    environment.etc."nixus-test-scripts".source = ../scripts;
    systemd.services.nixus-test-fixture = {
      wantedBy = [ "multi-user.target" ]; after = [ "systemd-tmpfiles-setup.service" ];
      before = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
      requiredBy = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
      path = [ pkgs.openssl ];
      environment.NIXUS_TEST_SITE_SOURCE = toString (import ./site-source.nix { inherit pkgs; });
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; UMask = "0077"; };
      script = ''PYTHONPATH=${../admin}:${../scripts} ${pkgs.python3}/bin/python3 ${./first-run-fixture.py}'';
    };
  };
  testScript = ''
    machine.start()
    machine.wait_for_unit("nixus-admin-backend.service")
    machine.wait_for_unit("nixus-ui.service")
    machine.wait_for_open_port(9440)
    machine.succeed("python3 /etc/nixus-test-client.py claim", timeout=300)
    machine.wait_for_unit("cockpit.socket")
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("nixus-admin-backend.service")
    machine.wait_for_unit("nixus-ui.service")
    machine.wait_for_open_port(9440)
    machine.succeed("python3 /etc/nixus-test-client.py after-reboot", timeout=120)
    machine.succeed("python3 /etc/nixus-test-client.py recover", timeout=120)
    machine.succeed("systemctl is-active nixus-admin-backend.service nixus-ui.service cockpit.socket")
  '';
}

# Boots the Go broker and HTTPS portal on NixOS and exercises the real
# security boundaries: socket permissions, untrusted-network rejection,
# PBKDF2 login, CSRF/origin checks, admin-only views and reboot survival.
{ pkgs }:
let
  defaults = import ../site-defaults.nix;
  settings = defaults // {
    hostName = "nixus-test"; cpuVendor = "intel";
    setup = defaults.setup // { enable = true; };
    management = defaults.management // { interface = "eth0"; address = "127.0.0.1"; trustedCIDRs = [ "127.0.0.0/8" ]; };
  };
  siteSource = import ./site-source.nix { inherit pkgs; };
in pkgs.testers.runNixOSTest {
  name = "nixus-portal";
  globalTimeout = 900;
  node.specialArgs = {
    inventory = settings;
    installedBase = { ... }: { system.stateVersion = "26.05"; };
  };
  nodes.machine = { lib, pkgs, ... }: {
    imports = [ ../configuration-bootstrap.nix ../modules/security.nix ];
    virtualisation.memorySize = 2048;
    # Disposable fixture: let the untrusted node reach HTTPS so the test checks
    # the application's source-network denial rather than a packet drop.
    networking.firewall.allowedTCPPorts = [ 9440 ];
    boot.kernelModules = lib.mkForce [ ];
    environment.systemPackages = [ pkgs.curl pkgs.jq ];
    users.users.outsider = { isNormalUser = true; initialPassword = "vm-nonadmin-password"; };
    systemd.services.nixus-test-fixture = {
      wantedBy = [ "multi-user.target" ];
      after = [ "systemd-tmpfiles-setup.service" ];
      before = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
      requiredBy = [ "nixus-management-identity.service" "nixus-admin-backend.service" "nixus-ui.service" ];
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; UMask = "0077"; };
      script = ''
        root=/var/lib/nixus/config
        mkdir -p "$root/lib" "$root/machine"
        for f in site.nix site-defaults.nix lib/machine.nix lib/settings-migrations.nix; do
          install -m 0600 ${siteSource}/$f "$root/$f"
        done
        echo '{"version": 1}' > "$root/machine/format.json"
        cat > "$root/machine/settings.json" <<'JSON'
        ${builtins.toJSON settings}
        JSON
        echo '{"interface": "eth0", "trustedCIDRs": ["127.0.0.0/8"]}' > "$root/machine/installation.json"
        echo '["site.nix","site-defaults.nix","lib/machine.nix","lib/settings-migrations.nix","machine/format.json","machine/settings.json","machine/installation.json"]' > "$root/.nixus-files.json"
      '';
    };
  };
  nodes.outside = { pkgs, ... }: {
    virtualisation.memorySize = 384;
    environment.systemPackages = [ pkgs.curl ];
  };
  testScript = ''
    import hashlib, json, os

    start_all()
    machine.wait_for_unit("nixus-admin-backend.service")
    machine.wait_for_unit("nixus-ui.service")
    machine.wait_for_open_port(9440)

    with subtest("privilege boundaries"):
        assert machine.succeed("systemctl show nixus-ui -p User --value").strip() == "nixus-ui"
        assert machine.succeed("stat -c %a /run/nixus-admin/backend.sock").strip() == "660"
        machine.fail("runuser -u outsider -- curl -s --unix-socket /run/nixus-admin/backend.sock http://localhost/status")
        machine.fail("runuser -u nixus-ui -- cat /var/lib/nixus-admin/ca.key")
        machine.succeed("curl -sf --unix-socket /run/nixus-admin/backend.sock http://localhost/status | jq -e 'type == \"object\"'")

    with subtest("untrusted networks are rejected by the application"):
        code = outside.succeed("curl -sk -o /dev/null -w '%{http_code}' https://machine:9440/api/bootstrap").strip()
        assert code == "401", code

    with subtest("PBKDF2 login, CSRF and admin views"):
        salt = os.urandom(24)
        password = "vm-integration-password"
        record = {"salt": salt.hex(), "iterations": 600000,
                  "hash": hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, 32).hex()}
        machine.succeed("install -m 0640 -g nixus-ui /dev/stdin /var/lib/nixus-admin/auth.json <<'EOF'\n" + json.dumps(record) + "\nEOF")
        base = "curl -sk -c /tmp/jar -b /tmp/jar -H 'Origin: https://127.0.0.1:9440' https://127.0.0.1:9440"
        bad = machine.succeed(base + "/api/login -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data '{\"username\":\"admin\",\"password\":\"wrong-password-value\"}'").strip()
        assert bad == "400", bad
        login = json.loads(machine.succeed(base + "/api/login -H 'Content-Type: application/json' --data '{\"username\":\"admin\",\"password\":\"" + password + "\"}'"))
        assert login["role"] == "admin" and login["csrf"], login
        for view in ["status", "session", "project-overview", "project-backups", "image-updates", "project-sources", "apps"]:
            machine.succeed(base + "/api/" + view + " -f -o /dev/null")
        # A Linux sudo account signs in with its own password (checked through PAM).
        machine.succeed("useradd -m -G wheel -s /run/current-system/sw/bin/bash homelab && echo 'homelab:linux-account-password' | chpasswd")
        lbase = "curl -sk -c /tmp/ljar -b /tmp/ljar -H 'Origin: https://127.0.0.1:9440' https://127.0.0.1:9440"
        wrong = machine.succeed(lbase + "/api/login -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data '{\"username\":\"homelab\",\"password\":\"not-the-password\"}'").strip()
        assert wrong == "400", wrong
        linux = json.loads(machine.succeed(lbase + "/api/login -H 'Content-Type: application/json' --data '{\"username\":\"homelab\",\"password\":\"linux-account-password\"}'"))
        assert linux["role"] == "admin" and linux["username"] == "homelab", linux
        machine.succeed(lbase + "/api/status -f -o /dev/null")
        # A Linux account without sudo is refused.
        machine.succeed("useradd -m -s /run/current-system/sw/bin/bash guest && echo 'guest:linux-account-password' | chpasswd")
        nosudo = machine.succeed(lbase + "/api/login -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data '{\"username\":\"guest\",\"password\":\"linux-account-password\"}'").strip()
        assert nosudo == "400", nosudo
        # A mutation without the CSRF token, or from another origin, is refused.
        nocsrf = machine.succeed(base + "/api/cancel-backup -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data '{}'").strip()
        assert nocsrf == "401", nocsrf
        cross = machine.succeed("curl -sk -b /tmp/jar -o /dev/null -w '%{http_code}' -H 'Origin: https://evil.example' -H 'X-Nixus-CSRF: " + login["csrf"] + "' -H 'Content-Type: application/json' --data '{}' https://127.0.0.1:9440/api/cancel-backup").strip()
        assert cross == "401", cross
        # Static assets, including the new console scripts, are served.
        for asset in ["/", "/apps.js", "/quick.js", "/backups.js"]:
            machine.succeed("curl -skf -o /dev/null https://127.0.0.1:9440" + asset)

    with subtest("root CLI uses the same broker"):
        machine.succeed("nixus-admin config status | jq -e 'type == \"object\"'")
        machine.succeed("nixus-admin project-backup status | jq -e '.phases != null'")
        machine.succeed("nixus-admin commissioning matrix --revision " + "a" * 40 + " | grep -q 'Single-host qualification'")

    with subtest("services return after reboot"):
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("nixus-ui.service")
        machine.wait_for_open_port(9440)
        machine.succeed("curl -skf -o /dev/null https://127.0.0.1:9440/")
  '';
}

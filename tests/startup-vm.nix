{ pkgs }:
let
  defaults = import ../site-defaults.nix;
  settings = defaults // {
    ready = true; hostName = "nixus-startup"; cpuVendor = "intel";
    setup = defaults.setup // { enable = true; };
    cockpit = defaults.cockpit // { enable = true; };
    management = defaults.management // {
      interface = "eth1"; address = "192.0.2.10"; trustedCIDRs = [ "192.0.2.0/24" ];
    };
    guests = defaults.guests // { cidr = "10.77.0.0/24"; };
  };
  fixture = pkgs.writeText "management-backend.py" ''
    import http.server, ssl, json
    from pathlib import Path
    import runtime as rt
    import sys
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"fixture":"NIXUS_PROXY_READY"}')
        def log_message(self, *args): pass
    port = int(sys.argv[1])
    server = http.server.HTTPServer(('0.0.0.0', port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(rt.STATE / 'tls.crt', rt.STATE / 'tls.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
  '';
in pkgs.testers.runNixOSTest {
  name = "nixus-dhcp-management-reboot";
  globalTimeout = 600;
  defaults.virtualisation.vlans = [ 1 ];
  nodes.lan = { ... }: {
    networking.useDHCP = false;
    networking.interfaces.eth1.ipv4.addresses = [ { address = "192.0.2.1"; prefixLength = 24; } ];
    services.dnsmasq = {
      enable = true;
      settings = { interface = "eth1"; bind-interfaces = true;
        dhcp-range = "192.0.2.20,192.0.2.20,255.255.255.0,1h";
        dhcp-option = "option:router,192.0.2.1";
      };
    };
    networking.firewall.allowedUDPPorts = [ 53 67 ];
    environment.systemPackages = [ pkgs.curl pkgs.openssh pkgs.sshpass ];
  };
  nodes.machine = { lib, ... }: {
    imports = [ ../modules/networking.nix ../modules/admin-ui.nix ../modules/cockpit.nix ../modules/security.nix ../modules/quality-of-life.nix ../modules/console.nix ];
    _module.args.site = settings;
    virtualisation.memorySize = 1536;
    networking.useDHCP = false;
    # The test driver otherwise adds static 192.168.1.x addresses, which would
    # mask whether the management interface actually received its DHCP lease.
    networking.interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
    networking.interfaces.eth1.ipv6.addresses = lib.mkForce [ ];
    networking.networkmanager = {
      enable = true;
      unmanaged = [ "interface-name:eth0" "interface-name:lo" ];
      ensureProfiles.profiles.nixus-test = {
        connection = { id = "nixus-test"; type = "ethernet"; interface-name = "eth1"; };
        ipv4.method = "auto"; ipv6.method = "disabled";
      };
    };
    # Exercise the production host firewall, including local traffic to its own
    # DHCP address. A simplified test firewall previously hid loopback drops.
    environment.systemPackages = [ pkgs.curl (pkgs.python3.withPackages (ps: [ ps.websocket-client ])) ];
    users.users.operator.initialPassword = "vm-cockpit-password"; # disposable VM only
    environment.etc."nixus-test-cockpit.py".source = ./cockpit-client.py;
    environment.etc."nixus-console-client.py".source = ./console-client.py;
    environment.etc."nixus-test-settings.json".text = builtins.toJSON settings;
    environment.etc."nixus/effective-settings.json".text = builtins.toJSON settings;
    systemd.services.nixus-test-fixture = {
      wantedBy = [ "multi-user.target" ];
      before = [ "nixus-management-identity.service" "nixus-admin-backend.service" ];
      requiredBy = [ "nixus-management-identity.service" "nixus-admin-backend.service" ];
      after = [ "systemd-tmpfiles-setup.service" ];
      path = [ pkgs.openssl ];
      environment.NIXUS_TEST_SITE_SOURCE = toString (import ./site-source.nix { inherit pkgs; });
      serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
      script = ''PYTHONPATH=${../admin}:${../scripts} ${pkgs.python3}/bin/python ${./portal-fixture.py}'';
    };
    systemd.services.fixture-incus = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "nixus-management-identity.service" ];
      after = [ "nixus-management-identity.service" ];
      environment.PYTHONPATH = "${../admin}:${../scripts}";
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python ${fixture} 8443";
    };
  };
  testScript = ''
    import json
    machine.start(allow_reboot=True)
    # Exercise a real DHCP delay instead of assuming network-online means ready.
    machine.wait_for_unit("NetworkManager.service")
    lan.start()
    lan.wait_for_unit("dnsmasq.service")
    for boot in range(2):
        machine.wait_for_unit("nixus-management-identity.service")
        machine.wait_for_unit("cockpit.socket")
        machine.wait_for_unit("nginx.service")
        machine.wait_for_unit("fixture-incus.service")
        addresses = json.loads(machine.succeed("ip -j -4 address show dev eth1"))
        address = next(a["local"] for link in addresses for a in link["addr_info"] if a["scope"] == "global")
        assert address == "192.0.2.20", address
        summary = machine.succeed("nixus-status")
        assert f"https://{address}:9440" in summary, summary
        assert "https://192.0.2.10:" not in summary, summary
        machine.succeed("bash -n /etc/profile && bash -n /etc/bashrc")
        assert machine.succeed("bash --login -c 'printf NONINTERACTIVE_OK'") == "NONINTERACTIVE_OK"
        fetch = machine.succeed("nixus-fetch --pipe")
        assert "Nixus" in fetch and address in fetch, fetch
        if boot == 0:
            machine.succeed("python3 /etc/nixus-console-client.py", timeout=30)
        lan.wait_until_succeeds(f"curl --fail --silent --show-error --max-time 5 --insecure https://{address}:9090/ping", timeout=90)
        redirect = lan.succeed(f"curl --silent --show-error --max-time 5 -I http://{address}/")
        assert " 308 " in redirect and f"https://{address}:9440/" in redirect, redirect
        machine.succeed(f"python3 /etc/nixus-test-cockpit.py https://{address}:9090")
        lan.succeed(f"sshpass -p vm-cockpit-password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password operator@{address} 'test $(id -un) = operator'")
        machine.wait_until_succeeds("nixus-admin doctor", timeout=90)
        machine.wait_for_unit("nixus-management-health.service")
        if boot == 0:
            machine.reboot()
  '';
}

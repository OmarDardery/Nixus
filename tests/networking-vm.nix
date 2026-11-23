# Exercise the production forwarding policy, rather than the bootstrap firewall.
# An isolated namespace stands in for the Internet; no Cloudflare token or
# external connectivity is needed to test DNS, NAT and TCP/UDP port 7844.
{ pkgs }:
let
  defaults = import ../site-defaults.nix;
  site = defaults // {
    management = defaults.management // {
      interface = "uplink"; address = "203.0.113.2";
      trustedCIDRs = [ "203.0.113.0/24" ];
    };
    guests = {
      bridge = "incusbr0"; cidr = "10.77.0.0/24";
      gatewayCIDR = "10.77.0.1/24"; dhcpRange = "10.77.0.100-10.77.0.199";
    };
    connectivity = defaults.connectivity // {
      privateAccess = [ { cidr = "10.20.0.1/32"; protocol = "tcp"; ports = [ 8443 ]; } ];
    };
  };
  lease = pkgs.writeShellScript "test-dhcp-lease" ''
    case "$1" in
      bound|renew)
        ${pkgs.iproute2}/bin/ip address replace "$ip/24" dev "$interface"
        if [ -n "$router" ]; then
          ${pkgs.iproute2}/bin/ip route replace default via ''${router%% *} dev "$interface"
        fi
        ;;
    esac
  '';
  echo = pkgs.writeText "edge-echo.py" ''
    import socketserver, threading
    class TCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.sendall(self.request.recv(64))
    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(data, self.client_address)
    tcp = socketserver.ThreadingTCPServer(("0.0.0.0", 7844), TCP)
    allowed = socketserver.ThreadingTCPServer(("0.0.0.0", 8443), TCP)
    udp = socketserver.ThreadingUDPServer(("0.0.0.0", 7844), UDP)
    threading.Thread(target=allowed.serve_forever, daemon=True).start()
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    tcp.serve_forever()
  '';
  probe = pkgs.writeText "probe.py" ''
    import socket, sys
    proto, address, port = sys.argv[1:]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM) as sock:
        sock.settimeout(3)
        sock.connect((address, int(port)))
        if proto != "connect":
            sock.sendall(b"nixus-egress")
            assert sock.recv(64) == b"nixus-egress"
  '';
in pkgs.testers.runNixOSTest {
  name = "nixus-networking";
  globalTimeout = 600;
  node.specialArgs = { inherit site; };
  nodes.machine = { ... }: {
    imports = [ ../modules/networking.nix ../modules/compose-runtime.nix ];
    virtualisation = { memorySize = 2048; cores = 2; };
    virtualisation.incus = {
      enable = true;
      preseed = {
        config."core.https_address" = "0.0.0.0:8443";
        storage_pools = [ { name = "default"; driver = "dir"; } ];
        profiles = [ { name = "default"; } ];
      };
    };
    networking.useDHCP = false;
    networking.nameservers = [ "203.0.113.1" ];
    environment.systemPackages = [ pkgs.iproute2 pkgs.busybox pkgs.dnsutils pkgs.dnsmasq pkgs.python3 pkgs.nftables ];
  };
  testScript = ''
    import json
    machine.start()
    machine.wait_for_unit("incus-preseed.service")
    machine.wait_for_unit("nftables.service")
    machine.succeed("ip netns add edge; ip link add uplink type veth peer name edge0; ip link set edge0 netns edge")
    machine.succeed("ip address add 203.0.113.2/24 dev uplink; ip link set uplink up")
    machine.succeed("ip netns exec edge ip link set lo up; ip netns exec edge ip address add 203.0.113.1/24 dev edge0; ip netns exec edge ip link set edge0 up")
    machine.succeed("ip netns exec edge ip address add 10.20.0.1/32 dev lo; ip route add 10.20.0.1/32 via 203.0.113.1")
    machine.succeed("systemd-run --unit=edge-echo ip netns exec edge python3 ${echo}")
    machine.succeed("systemd-run --unit=edge-dns ip netns exec edge dnsmasq --keep-in-foreground --user=root --no-resolv --bind-interfaces --listen-address=203.0.113.1 --address=/edge.example/203.0.113.1")
    machine.succeed("systemd-run --unit=host-listener python3 -m http.server 9440 --bind 0.0.0.0")
    machine.wait_for_open_port(9440)
    machine.succeed("python3 ${probe} connect 203.0.113.2 9440")
    machine.wait_until_succeeds("python3 ${probe} tcp 203.0.113.1 7844")
    machine.succeed("python3 ${probe} udp 203.0.113.1 7844")
    machine.succeed("python3 ${probe} tcp 10.20.0.1 7844")

    gateways = {}
    for bridge in ["nxa-testa", "nxa-testb"]:
        machine.succeed(f"incus network create {bridge} --type=bridge ipv4.address=auto ipv4.nat=true ipv6.address=none")
        network = json.loads(machine.succeed(f"incus query /1.0/networks/{bridge}"))
        gateways[bridge] = network["config"]["ipv4.address"].split("/")[0]

    for name, bridge in [("client", "nxa-testa"), ("peer", "nxa-testa"), ("isolated", "nxa-testb"), ("controller", "icompose0")]:
        machine.succeed(f"ip netns add {name}; ip link add v-{name} type veth peer name eth0 netns {name}")
        machine.succeed(f"ip link set v-{name} master {bridge}; ip link set v-{name} up")
        machine.succeed(f"ip netns exec {name} ip link set lo up; ip netns exec {name} ip link set eth0 up")
        machine.succeed(f"ip netns exec {name} udhcpc -f -n -q -i eth0 -x hostname:{name} -s ${lease}")

    client_ip = json.loads(machine.succeed("ip -n client -j -4 address show eth0"))[0]["addr_info"][0]["local"]
    machine.succeed("systemd-run --unit=client-echo ip netns exec client python3 ${echo}")
    machine.wait_until_succeeds(f"ip netns exec peer python3 ${probe} tcp {client_ip} 7844")

    def check_egress():
        for proto in ["tcp", "udp"]:
            machine.succeed(f"ip netns exec client python3 ${probe} {proto} 203.0.113.1 7844")
        gateway = gateways["nxa-testa"]
        for transport in ["", "+tcp"]:
            answer = machine.succeed(f"ip netns exec client dig +short +time=2 +tries=1 {transport} @{gateway} edge.example")
            assert "203.0.113.1" in answer, answer
        machine.wait_until_succeeds(f"ip netns exec client dig +short +time=2 +tries=1 @{gateway} peer.incus | grep -E '^[0-9]+\\.'")

    with subtest("app DHCP, DNS and NAT permit outbound Tunnel transports"):
        check_egress()
    with subtest("apps cannot reach the private LAN or host management"):
        machine.succeed("ip netns exec client python3 ${probe} tcp 10.20.0.1 8443")
        machine.fail("ip netns exec client python3 ${probe} tcp 10.20.0.1 7844")
        machine.fail("ip netns exec client python3 ${probe} connect 203.0.113.2 9440")
        machine.fail(f"ip netns exec isolated python3 ${probe} connect {client_ip} 7844")
    with subtest("only the dedicated controller bridge reaches the authenticated Incus API"):
        machine.succeed("ip netns exec controller python3 ${probe} connect 203.0.113.2 8443")
        machine.fail("ip netns exec client python3 ${probe} connect 203.0.113.2 8443")
        machine.fail("ip netns exec controller python3 ${probe} connect 203.0.113.2 9440")
    with subtest("firewall reload preserves Incus NAT and app connectivity"):
        machine.succeed("systemctl restart nftables.service")
        check_egress()
  '';
}

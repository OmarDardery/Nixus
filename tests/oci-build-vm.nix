{ pkgs }:
let
  incusCompose = import ../pkgs/incus-compose.nix { inherit pkgs; };
  tool = import ../admin/package.nix { inherit pkgs; };
in pkgs.testers.runNixOSTest {
  name = "nixus-oci-isolated-builder";
  globalTimeout = 900;
  nodes.host = { ... }: {
    virtualisation = { memorySize = 3072; diskSize = 7168; };
    users.groups.nixus-oci = { };
    users.users.nixus-oci = {
      isSystemUser = true;
      group = "nixus-oci";
      home = "/var/empty";
      createHome = false;
    };
    systemd.tmpfiles.rules = [
      "d /srv/nixus 0700 root root -"
      "d /var/lib/nixus-oci 0711 root root -"
      "d /var/lib/nixus-oci/jobs 0711 root root -"
    ];
    environment.systemPackages = [ tool (pkgs.python3.withPackages (ps: [ ps.markdown ps.cryptography ps.pyyaml ])) pkgs.nix pkgs.buildah
      pkgs.bubblewrap incusCompose pkgs.util-linux ];
    environment.variables = {
      NIXUS_OCI_COMPOSE_BIN = "${incusCompose}/bin/incus-compose";
      NIXUS_OCI_BUILDAH_BIN = "${pkgs.buildah}/bin/buildah";
      NIXUS_OCI_BWRAP_BIN = "${pkgs.bubblewrap}/bin/bwrap";
      NIXUS_OCI_PATH = pkgs.lib.makeBinPath (with pkgs; [
        buildah bubblewrap incusCompose coreutils gnutar gzip xz bash shadow
      ]);
    };
  };
  testScript = ''
    host.start()
    host.wait_for_unit("multi-user.target")
    host.succeed("PYTHONPATH=${../admin}:${../scripts} python3 ${./oci-build-integration.py}", timeout=720)
  '';
}

{ pkgs }:
let
  incusCompose = import ../pkgs/incus-compose.nix { inherit pkgs; };
  source = pkgs.runCommand "nixus-admin-source" { } ''
    cp -r ${import ./source.nix { inherit pkgs; }} $out
    chmod -R u+w $out
    cp -r ${../docs} $out/docs
    cp ${../helpers/sources.json} $out/helper-sources.json
    cp ${../helpers/compatibility.json} $out/helper-compatibility.json
    cp ${../VERSION} $out/VERSION
  '';
in pkgs.writeShellApplication {
  name = "nixus-admin";
  runtimeInputs = with pkgs; [ (python3.withPackages (ps: [ ps.markdown ps.cryptography ps.pyyaml ])) nix nixos-rebuild git iproute2 util-linux openssl openssh shadow coreutils systemd networkmanager incus-lts.client age sops parted e2fsprogs pamtester buildah bubblewrap incusCompose ];
  text = ''
    NIXUS_WORKER_RUNTIME="$(dirname "$(dirname "$(readlink -f "$0")")")"
    export NIXUS_WORKER_RUNTIME
    export NIXUS_PROJECT_EVAL_LIB=${../lib/project-workspace.nix}
    export NIXUS_PROJECT_NIXPKGS_LIB=${pkgs.path}/lib
    export NIXUS_OCI_BUILDAH_BIN=${pkgs.buildah}/bin/buildah
    export NIXUS_OCI_BWRAP_BIN=${pkgs.bubblewrap}/bin/bwrap
    export NIXUS_OCI_COMPOSE_BIN=${incusCompose}/bin/incus-compose
    export NIXUS_OCI_PATH=${pkgs.lib.makeBinPath (with pkgs; [ buildah bubblewrap incusCompose coreutils gnutar gzip xz bash shadow ])}
    exec python3 ${source}/main.py "$@"
  '';
}

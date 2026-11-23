{ pkgs }:
let
  nixus = import ../pkgs/nixus.nix { inherit pkgs; };
  data = import ./source.nix { inherit pkgs; };
  incusCompose = import ../pkgs/incus-compose.nix { inherit pkgs; };
in pkgs.writeShellApplication {
  name = "nixus-admin";
  runtimeInputs = with pkgs; [ nix nixos-rebuild git iproute2 util-linux openssl openssh shadow coreutils systemd networkmanager
    incus-lts.client age sops parted e2fsprogs pamtester buildah incusCompose restic rclone skopeo ];
  text = ''
    NIXUS_ADMIN_LAUNCHER="$(readlink -f "$0")"
    NIXUS_WORKER_RUNTIME="$(dirname "$(dirname "$NIXUS_ADMIN_LAUNCHER")")"
    export NIXUS_ADMIN_LAUNCHER NIXUS_WORKER_RUNTIME
    export NIXUS_SOURCE=${data}
    export NIXUS_PROJECT_EVAL_LIB=${../lib/project-workspace.nix}
    export NIXUS_PROJECT_NIXPKGS_LIB=${pkgs.path}/lib
    export NIXUS_OCI_BUILDAH_BIN=${pkgs.buildah}/bin/buildah
    export NIXUS_OCI_COMPOSE_BIN=${incusCompose}/bin/incus-compose
    export NIXUS_OCI_PATH=${pkgs.lib.makeBinPath (with pkgs; [ buildah incusCompose coreutils gnutar gzip xz bash shadow ])}
    exec ${nixus}/bin/nixus-go admin "$@"
  '';
  passthru = { inherit nixus data; };
}

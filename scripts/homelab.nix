{ pkgs }:
let command = pkgs.writeShellApplication {
  name = "nixus";
  runtimeInputs = [ pkgs.python3 pkgs.incus-lts.client (import ../admin/package.nix { inherit pkgs; }) ];
  text = ''exec python3 ${./homelab.py} "$@"'';
};
in pkgs.symlinkJoin {
  name = "nixus-cli";
  paths = [ command ];
  postBuild = ''ln -s nixus $out/bin/homelab'';
}


{ pkgs }:
let
  nixus = import ../pkgs/nixus.nix { inherit pkgs; };
  command = pkgs.writeShellApplication {
    name = "nixus";
    runtimeInputs = [ pkgs.incus-lts.client (import ../admin/package.nix { inherit pkgs; }) ];
    text = ''exec ${nixus}/bin/nixus-go homelab "$@"'';
  };
in pkgs.symlinkJoin {
  name = "nixus-cli";
  paths = [ command ];
  postBuild = ''ln -s nixus $out/bin/homelab'';
}

{ pkgs }:
let
  pins = builtins.fromJSON (builtins.readFile ./sources.json);
  fetch = pin: pkgs.fetchFromGitHub {
    owner = "community-scripts"; repo = builtins.elemAt (pkgs.lib.splitString "/" pin.repository) 1;
    rev = pin.revision; hash = pin.hash;
  };
  core = fetch pins.core;
  scripts = fetch pins.scripts;
  nixus = import ../pkgs/nixus.nix { inherit pkgs; };
in pkgs.writeShellApplication {
  name = "nixus-helpers";
  runtimeInputs = with pkgs; [ bash incus-lts.client curl wget jq gawk gnused gnugrep coreutils
    findutils util-linux newt ncurses git openssl gnutar gzip xz unzip procps iproute2 iputils hostname systemd ];
  text = ''
    export NIXUS_HELPER_ENGINE=${core}
    export NIXUS_HELPER_SCRIPTS=${scripts}
    export NIXUS_HELPER_METADATA=${./.}
    exec ${nixus}/bin/nixus-go helpers "$@"
  '';
}

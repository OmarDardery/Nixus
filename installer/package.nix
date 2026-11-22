{ pkgs }:
let
  platform = pkgs.lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let relative = pkgs.lib.removePrefix (toString ../. + "/") (toString path);
          top = builtins.head (pkgs.lib.splitString "/" relative);
      in type != "symlink"
        && (toString path == toString ../. || builtins.elem top [
          "admin" "cmd" "pkgs" "installer" "scripts" "lib" "modules"
          "guests" "tests" "docs" "examples" "configuration.nix" "configuration-bootstrap.nix"
          "hardware-configuration.nix" "flake.nix" "flake.lock" "go.mod" "go.sum" "site.nix" "site-defaults.nix"
          "README.md" "VERSION" ".gitignore"
        ]);
  };
  admin = import ../admin/package.nix { inherit pkgs; };
  runtimeInputs = with pkgs; [ git openssl openssh shadow nix nixos-rebuild iproute2 util-linux kmod coreutils systemd
    networkmanager incus-lts.client age sops admin ];
  install = pkgs.writeShellApplication {
    name = "nixus-install";
    inherit runtimeInputs;
    text = ''exec nixus-admin install --checkout ${platform} "$@"'';
  };
  update = pkgs.writeShellApplication {
    name = "nixus-update";
    inherit runtimeInputs;
    text = ''
      if [[ "''${1:-}" != --help && "''${1:-}" != -h && "$(id -u)" != 0 ]]; then
        exec /run/wrappers/bin/sudo -- "$0" "$@"
      fi
      exec nixus-admin update "$@"
    '';
  };
in pkgs.symlinkJoin {
  name = "nixus-installer";
  paths = [ install update ];
}

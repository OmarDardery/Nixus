# Incus resolves symlinks but gzip's Nix wrapper executes a second file.
{ pkgs }:
pkgs.incus-lts.overrideAttrs (old: {
  postPatch = (old.postPatch or "") + ''
    substituteInPlace internal/server/apparmor/archive.profile.go \
      --replace-fail '#include <abstractions/nameservice>' '#include <abstractions/nameservice>
  ${pkgs.gzip}/bin/.gzip-wrapped mixr,
  /dev/tty rw,'
  '';
})

# NixOS wraps gzip: bin/gzip is a script that execs bin/.gzip-wrapped. Incus
# generates an AppArmor profile per archive operation (it includes
# abstractions/base) that allows only the resolved `gzip`, so unpacking an
# image's gzip layer, for example the first-time copy of an image's files into a
# named volume, was denied at the wrapped binary (#117). Allow exactly that
# file, taken from the same gzip package Incus runs with, so it follows
# store-path changes on rebuild.
{ config, lib, pkgs, ... }:
{
  security.apparmor.includes."abstractions/base" = lib.mkIf config.security.apparmor.enable (lib.mkAfter ''
    ${pkgs.gzip}/bin/.gzip-wrapped mixr,
  '');
}

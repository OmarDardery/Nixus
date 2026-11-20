# The single Go program behind every Nixus command (cmd/nixus) plus the
# documentation website builder (cmd/website).
{ pkgs }:
pkgs.buildGoModule {
  pname = "nixus";
  version = pkgs.lib.removeSuffix "\n" (builtins.readFile ../VERSION);
  src = pkgs.lib.fileset.toSource {
    root = ../.;
    fileset = pkgs.lib.fileset.unions [ ../go.mod ../go.sum ../cmd ];
  };
  vendorHash = "sha256-0xXl3CdgJN16Zyy9qhN9zXeAXleKJZaBmE+93YfCZbU=";
  subPackages = [ "cmd/nixus" "cmd/website" ];
  env.CGO_ENABLED = "0";
  ldflags = [ "-s" "-w" ];
  # Every command is one multi-call binary; wrappers choose the subcommand.
  postInstall = "mv $out/bin/nixus $out/bin/nixus-go";
  meta.mainProgram = "nixus-go";
}

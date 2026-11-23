# Official pinned upstream tools for the closed-network OCI fixture. Upstream
# prefetches all tools even when a particular sidecar is disabled.
{ pkgs }:
let
 pull = tool: digest: hash: pkgs.dockerTools.pullImage {
  imageName = "ghcr.io/lxc/incus-compose/ic-${tool}";
  imageDigest = digest;
  sha256 = hash;
  finalImageName = "nixus/${tool}";
  finalImageTag = "1";
 };
in {
 healthd = pull "healthd" "sha256:bb53707542f9f3095e2ac6b7ec85a9e2d81fff587ec186c4d300db40d56a5eaf" "sha256-QQFBeIgn4Nt2RGCyT3GlmZou3v3cw87IlyVnVEU3Wrs=";
 dns = pull "dns" "sha256:e44ffd96d745d1e04ac1036b9af499dce4eb32e0683663444bf07a79207bfb94" "sha256-Qz9cikIm0AY9NWNRdRftKcUsru8ACAb5p9uBR1U685Y=";
 sleep = pull "sleep" "sha256:6d11154d96a3f6af37b5e170426a8fd07b9cae81772d08ff0669619013e57d2c" "sha256-SzQC/JkBaxND/9XiqiEuhxxy4Io0IS3rgMTGUVHPbzE=";
}

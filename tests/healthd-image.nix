# Keep the production upstream controller available to the offline VM fixture.
{ pkgs }:
pkgs.dockerTools.pullImage {
  imageName = "ghcr.io/lxc/incus-compose/ic-healthd";
  imageDigest = "sha256:bb53707542f9f3095e2ac6b7ec85a9e2d81fff587ec186c4d300db40d56a5eaf";
  sha256 = "sha256-QQFBeIgn4Nt2RGCyT3GlmZou3v3cw87IlyVnVEU3Wrs=";
  finalImageName = "nixus/healthd";
  finalImageTag = "1";
}

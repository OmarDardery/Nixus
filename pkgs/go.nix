# Keep the runtime and development shell on the current Go 1.26 security
# release without changing the rest of the pinned host package collection.
{ pkgs }:
pkgs.go_1_26.overrideAttrs {
  version = "1.26.11";
  src = pkgs.fetchurl {
    url = "https://go.dev/dl/go1.26.11.src.tar.gz";
    sha256 = "d44101b0ff27ed2a4c75ad46c17b9c74359209e2eb2ca7c9df6cb4fdb68e1969";
  };
}

{
  description = "Portable, declarative Nixus project workspace";
  inputs.nixus.url = "github:OmarDardery/Nixus";
  outputs = { self, nixus, ... }: {
    # Resolve against the exact pinned Nixus revision in flake.lock.
    # Project source changes evaluate independently of the NixOS host flake.
    nixusProjects = nixus.lib.evalProjects { root = ./.; };
  };
}

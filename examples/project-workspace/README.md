# Independent declarative Nixus workspace (foundation only)

This example is a **template**, not a deployed workload. Copy its contents to
`/srv/nixus/projects/` on a host where that directory is outside the Nixus
OS checkout. It evaluates Nix source only, and does **not** start Incus instances
or rebuild NixOS.

```sh
# After reviewing the source and before allowing a project to be applied:
cd /srv/nixus/projects
nix flake lock --flake path:$PWD
nix eval --json path:$PWD#nixusProjects
```

Commit or independently back up **flake.lock** with the source. Never copy a
runtime credential, private age key, plaintext `.env`, Incus volume or mutable
application data into this source tree: the Nix flake source is copied to the Nix
store and may be publicly readable on a multi-user machine. A SOPS-encrypted
`secrets.enc.yaml` is acceptable after ciphertext and recipients are reviewed.

The first project entrypoint is `sample/default.nix`. `modules/**/*.nix` are
loaded automatically in deterministic order, except directories/files prefixed
with an underscore or dot. Other `.nix` files do not import automatically.
Project names and Incus project claims must be unique.

The broker workspace validator (`validateWorkspace` in `cmd/nixus/projects.go`) checks file types, symlinks,
source size and lock presence before a *future* privileged broker evaluates an
uploaded workspace. Running `nix eval` manually on untrusted Nix files is
**not** a security boundary; review and sandbox the input.

## Declared native guests

An `incus-native` project can declare its Incus resources directly:

```nix
{ ... }: {
  nixus.project = {
    backend = "incus-native";
    volumes.printer-data.size = "2GiB";
    instances.printer = {
      image = "images:debian/13";   # used only when the instance is first created
      cpus = 1; memory = "1GiB";
      disks.data = { volume = "printer-data"; path = "/srv/data"; };
      usb.board = { vendorId = "1d50"; productId = "614e"; };
    };
  };
}
```

A reviewed project deployment then, in order:

1. Creates the Nixus-owned Incus project, or claims an existing unowned one
   as an explicit reviewed action. Compose-owned, `default` and `lab` projects
   are refused.
2. Creates missing custom volumes. Resizing or adopting an unowned volume is
   refused.
3. Creates missing instances, or reconciles existing owned instances through
   ETag and last-applied checks. Runtime drift stops the deployment.

Removing a declaration, or disabling a project, never stops or deletes
anything. The plan lists such instances under `retained` and keeps them with
their data until an explicit migration.

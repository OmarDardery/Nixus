# Nixus

A declarative, Incus-native NixOS hypervisor for homelabs: Incus projects, OCI
containers, system containers and VMs, reviewed host transactions, encrypted
secrets, backups and restores, all managed from one Web UI. There is no Docker
daemon, Portainer or Arcane.

> **Pre-release.** Nixus is not yet qualified for installation. Do not deploy it
> to a production host. See [what is tested](docs/validation.md) and the
> [migration plan](docs/migration-plan.md).

## Origin

Nixus is a fresh rewrite of [NixLab](https://github.com/OmarDardery/nixlab),
built from NixLab's `incus-native` rebuild (`0242743`) without its git history.
The Docker/Arcane applications VM was removed rather than migrated, and the
project was renamed throughout (`nixus.*` options, `nixus-admin`, `/srv/nixus`).
Open NixLab issues were copied here with links back to the originals.

## Documentation

- [Migration plan and status](docs/migration-plan.md)
- [Architecture contract](docs/incus-native-architecture.md)
- [Repository and host layout](docs/incus-native-structure.md)
- [Rebuild execution plan](docs/incus-native-plan.md)
- [OCI source uploads and build safety](docs/oci-source-intake.md)
- [Declarative secrets UI](docs/incus-native-secrets-ui.md)

## Development checks

```sh
python3 -m unittest discover -s tests
nix eval .#nixusFoundationChecks --json
```

`nixosConfigurations.hypervisor` and `bootstrap` intentionally fail evaluation
until `site.nix` is filled from real hardware; use the `validation-*` fixtures.

CI runs the full set in [`.github/workflows/validate.yml`](.github/workflows/validate.yml).
VM, nested-KVM and physical-host qualification are tracked separately.
Passing unit tests do not prove that backups restore or that USB passthrough works.

Existing Incus guests, disks and volumes are never destroyed because Git
branches or configuration modules change.

# Validation and acceptance

The supported installation target is a conventional installed x86_64 NixOS server.
The pinned Nixpkgs revision is recorded in `flake.lock`. Use the latest successful
[validation run](https://github.com/OmarDardery/Nixus/actions/workflows/validate.yml)
for the exact source revision being installed.

## Automated checks

The workflow runs these checks on every pull request:

- Go formatting, `go vet` and unit tests, also run inside the Nix package build.
- JavaScript syntax and UI tests for every portal script.
- Nix parsing; pure settings, project, secret and management contract checks; and
  evaluation of every `validation-*` configuration, including preserved
  boot/users/mounts/stateVersion, NetworkManager, Wi-Fi and storage.
- Builds of the Go runtime, admin, installer and helper packages, service units and
  the complete hypervisor.

The earlier NixOS VM suites drove the retired Python modules and were removed in the Go
migration; their Go rewrites are tracked in #14.

Run the lightweight source checks locally:

```sh
nix develop -c go vet ./...
nix develop -c go test ./...
node tests/test_homepage.js
node tests/test_operations_ui.js
node tests/test_foundation_ui.js
```

## Target-host acceptance

Automated fixtures do not establish physical NIC/USB behavior, a complete nested-KVM
project deployment, live registry/helper recovery or independent off-host restore.
Follow [commissioning](commissioning.md) on a recoverable host. Record the exact
source revision, installed hardware, reboot results and redacted failure reports.
The installer is not run against a production machine from this development workspace.

The manual `hypervisor` output deliberately refuses incomplete inventory. Never
install a `validation-*` configuration: its addresses, keys and hardware are fixtures.
OS rollback does not roll back guest data or the Incus database schema.

The `guest-deployments` check boots two real NixOS Incus containers and tests
ordered in-place OS updates, preserved data, health rollback, dependency failure,
a killed export/import worker, and resume after rebooting the controller. It does
not establish VM/KVM qualification.


# Nixus

A NixOS homelab server you manage from the browser. Run Compose apps,
containers and VMs on Incus, keep their env vars encrypted, back everything up
(secrets included), and keep your apps in git. No Docker daemon.

```sh
sudo nix --extra-experimental-features 'nix-command flakes' \
  run github:OmarDardery/Nixus#install
```

> **Beta.** CI runs every feature end to end in VMs. Physical-hardware
> qualification (#44) is still open.

## Guides

| Guide | |
|---|---|
| [Install & update](docs/install.md) | Install, first sign-in, daily use |
| [Apps](docs/apps.md) | Compose apps, VMs, containers, USB/serial devices, updates |
| [Apps repository](docs/apps-repo.md) | Keep apps in git, layout and best practices |
| [Env vars & secrets](docs/secrets.md) | Encrypted env vars, the age key |
| [Backups & restore](docs/backups.md) | Destinations, what's backed up, restoring a server |
| [Networking](docs/networking.md) | Host and guest addressing, ingress |
| [Cloudflare Tunnel](docs/cloudflare-tunnel.md) | Connector setup, DNS, egress and disconnected tunnels |
| [Troubleshooting](docs/troubleshooting.md) | When something doesn't work |
| [CLI](docs/administration.md) | Host commands |
| [Credits](docs/credits.md) | The projects Nixus is built on |

Architecture, validation and qualification notes are in [docs/dev](docs/dev).

## Development

The runtime is one Go program (`cmd/nixus`); the console is plain JavaScript in
`admin/static`.

```sh
nix develop -c go test ./...
for t in tests/*.js; do node "$t"; done
nix build .#nixus
```

CI ([`validate.yml`](.github/workflows/validate.yml)) also runs the NixOS VM
tests: install, OCI build and Compose deploy, secrets, device passthrough, the
apps repository, backup and cold restore.

Nixus started as a rewrite of [NixLab](https://github.com/OmarDardery/nixlab).

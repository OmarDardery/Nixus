# Go runtime

Nixus runs as one statically linked Go program. The Nix package installs it once and exposes it under several command names:

| Command | Purpose |
|---|---|
| `nixus-admin` | Root broker, HTTPS portal, transaction workers and host administration CLI |
| `nixus-install` | One-command installation on an installed NixOS host |
| `nixus-update` | Guarded platform update, with optional local-console network repair |
| `nixus` | Authenticated Incus convenience wrapper for operators |
| `nixus-helpers` | Packaged upstream Incus helper-script runner |

The source lives in `cmd/nixus`. On-disk state, JSON formats and the browser API are unchanged from earlier releases, so an existing host keeps its accounts, transactions, backups and projects across the update.

The documentation website is built by `cmd/website`:

```sh
go run ./cmd/website --output _site --check
```

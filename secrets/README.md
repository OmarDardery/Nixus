Nixus keeps host credentials in `machine/secrets/host.yaml` on the installed host,
encrypted to the host age identity in `/var/lib/sops-nix/key.txt`. The portal
writes it; see `docs/deployment.md`. Commit encrypted SOPS YAML only. Never commit
age private identities, password files, database dumps or restic repository keys.

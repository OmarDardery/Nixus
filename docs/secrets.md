# Env vars and secrets

**Apps → app → Env**: paste `KEY=value` lines (a `.env` file works) or edit
them one per row, then save with your password.

You can also add them before the first deploy: **New app → Environment
variables**. They are encrypted right away and set on the app as soon as it
exists. Either way, create the encryption key first (**Backups → Encryption key
& recovery kit**).

What happens:

1. Values are encrypted with [SOPS](https://github.com/getsops/sops) to the
   server's [age](https://age-encryption.org/) key and stored as
   `secrets.enc.yaml` next to the app. Runtime environment delivery also stores plaintext values in the root-accessible Incus database and native instance export archives. Local export staging is sensitive and root-only; restic encrypts it before off-host storage. The separate backup inventory omits environment values.
2. Every container of the app gets them as **environment variables** and as
   files in `/run/secrets/<KEY>` (Docker's secrets convention, mode 0444).
3. Containers whose variables changed are restarted.

## Where values can exist

| Where | What is stored |
|---|---|
| `secrets.enc.yaml` and backups | Encrypted. Never plaintext. |
| `/run/secrets/<KEY>` inside a container | Plaintext in memory (tmpfs); gone when the container stops, restored by the delivery timer. |
| The container's environment (`incus config`) | **Plaintext in Incus's own configuration**, because that is how Incus passes environment variables. It is part of an Incus instance export. |
| Local backup staging (`/var/lib/nixus/exports`) | Instance exports (which hold the environment above), root-only, until restic encrypts them off-host. The backup inventory file lists variable *names* only; values are redacted. |

If a value must never rest in Incus's configuration, read it from the
`/run/secrets/<KEY>` file instead of the environment.

Values are re-applied after reboots and every 10 minutes. Nixus only manages
the variables it set; ones defined in `compose.yaml` or the image are left
alone. Keep secrets out of `compose.yaml`: Nixus refuses variables there whose
name contains `TOKEN`, `PASSWORD`, `PASSWD`, `SECRET`, `KEY`, `AUTH`, `PRIVATE` or
`CREDENTIAL`.

## The key

The age key lives at `/var/lib/nixus/keys/projects.agekey` (root only). It is:

- included in every backup snapshot, so a restore brings secrets back;
- exportable as a passphrase-encrypted **recovery kit** (Backups → Encryption
  key & recovery kit). Keep the kit off the server.

It never goes into the apps repository, images or containers. The
`secrets.enc.yaml` files are safe to commit: without the key they are
unreadable.

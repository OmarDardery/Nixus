# Env vars and secrets

**Apps → app → Env**: paste `KEY=value` lines (a `.env` file works) or edit
them one per row, then save with your password.

What happens:

1. Values are encrypted with [SOPS](https://github.com/getsops/sops) to the
   server's [age](https://age-encryption.org/) key and stored as
   `secrets.enc.yaml` next to the app. Plaintext never touches disk.
2. Every container of the app gets them as **environment variables** and as
   files in `/run/secrets/<KEY>` (Docker's secrets convention, mode 0444).
3. Containers whose variables changed are restarted.

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

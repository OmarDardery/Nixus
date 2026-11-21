# Backups and restore

## Set up

**Backups → Set up backups**: pick a destination (Google Drive via rclone, S3,
Backblaze B2 or a local disk), a schedule and a verification level, then
**Save**. Nixus creates the repository password and shows it **once**: put it in
your password manager. That password is all you need to restore.

For Google Drive, run `rclone config` on any computer, create a remote, then
paste the output of `rclone config show` into the form.

## What a snapshot holds

Backups use [restic](https://restic.net/): encrypted, deduplicated, verified.

| Phase | Contents |
|---|---|
| Config | Every app's declaration, Compose files, Dockerfiles and `secrets.enc.yaml` |
| Secrets | The age key, deploy key and backup credentials (inside the encrypted snapshot only) |
| Data | Incus exports of every instance and volume |
| Upload | Sends it to the destination and applies retention |
| Check | `restic check` (metadata, or full read) |

**Back up now** on Overview or Backups runs one immediately. Failures notify
you and show per phase on the Backups page.

## Restore a server

On a fresh install with no apps, **Backups → Restore this server from a
backup** takes the destination and the repository password. It restores the
keys, apps, data and secrets, then starts what was running. The progress and any
error show on the same page.

From a terminal:

```sh
sudo nixus-admin project-backup restore \
  --repository rclone:gdrive:nixus-backups \
  --rclone-config /path/to/rclone.conf \
  --password-file /path/to/password-file
```

A restore refuses to run on a server that already has apps.

## Backups and the apps repository

They complement each other:

- The **repository** holds configuration: what runs and how. It is readable and
  diffable, and safe to share with collaborators.
- **Backups** hold everything: configuration, data, and the keys that decrypt
  secrets.

To move to new hardware, restore a backup. To rebuild from scratch without
data, install Nixus, restore only the age key from the recovery kit, then
import the repository.

## Recovery kit

**Backups → Encryption key & recovery kit** exports the age key, encrypted
with a passphrase you choose. Store it away from the server (a password
manager attachment or a USB stick). It is the fallback if the backup
password is lost.

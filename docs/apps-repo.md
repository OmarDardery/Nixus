# Apps repository

Keep your apps in git, on any host that speaks SSH: GitHub, GitLab,
Gitea/Forgejo, or your own. Nixus pushes what you change in the console and
shows you what changed in git before deploying it.

## Layout

```text
README.md
backups.nix                  # backup policy (no credentials)
aiostreams/
  compose.yaml               # images pinned by digest
  secrets.enc.yaml           # env vars, SOPS-encrypted to the server's key
printer/
  compose.yaml
  default.nix                # optional: Nix options (updates, resources…)
nas/
  default.nix                # a VM or container declared in Nix
```

A folder is an app when it holds `compose.yaml` (or `docker-compose.yml`),
a `Dockerfile` or `default.nix`. Other folders and files (docs, CI) are
ignored and kept.

## Connect

1. Create an **empty private repository**, or use an existing apps repository.
2. **Backups → Apps repository**: enter the SSH URL (`git@github.com:you/apps.git`
   or `ssh://git@host:2222/you/apps.git`) and **Create deploy key**.
3. Add the shown public key to the repository as a deploy key **with write
   access** (GitHub: Settings → Deploy keys).
4. **Check host key**, compare the fingerprint with your git host's published
   one ([GitHub's](https://docs.github.com/en/authentication/keeping-your-account-and-data/githubs-ssh-key-fingerprints)),
   tick the box and **Connect**.

Connecting an empty repository pushes every app on the server. If the
repository already has apps, they appear under **Remote changes**: review
them and **Deploy**.

## Day to day

- **Change in the console** (deploy, env var, image update, backup policy):
  Nixus commits `nixus: update from console` and pushes within seconds.
- **Change in git** (edit `compose.yaml` on your laptop and push): within 10
  minutes, or straight away with **Check now**, the commits and affected apps
  appear under **Remote changes**. Nothing deploys until you click **Deploy**.
- While remote changes wait for review, Nixus does not push, so it never
  overwrites them. Deploy them first.
- Deleting an app folder in git does not delete the app. The review lists
  it as removed; delete the app on the server.

## Secrets

`secrets.enc.yaml` holds the app's env vars, encrypted with SOPS to the
server's age key. Edit them in the console's **Env** tab and the new
ciphertext is pushed. If you push your own `secrets.enc.yaml`, it must
decrypt with the server's key (`.sops.yaml` in each app folder lists the
recipient).

The age key and the deploy key are **never** committed. They are in your
encrypted backups and the recovery kit.

## Best practices

- Keep the repository **private**, even though secrets are encrypted.
- Pin images by digest. **Pin** on the app page rewrites tags to digests, and
  **Update image** moves to newer digests; both are pushed back.
- One app per folder; folder names are lowercase letters, digits and dashes.
- Use `/dev/serial/by-id/…` paths for devices so the repository works after
  replugging.
- Protect the branch from force-pushes. Nixus never force-pushes.
- Review the **Remote changes** list before deploying: it shows exactly which
  commits and apps are about to change.

# OCI source intake and build-boundary qualification (#47)

This document covers source intake, the isolated build and the verified Incus import. Starting containers from these images (`incus-compose up`, start order, ownership and rollback) is #45.

## Supported source intake

- Upload multiple original files, a folder, or **one explicitly selected** ZIP, TAR, TAR.GZ or TGZ archive from the Projects browser UI. Copy original file bytes and nested relative names without rewriting YAML, Dockerfiles or `.dockerignore`.
- Source is stored in root-owned staging, published into immutable revision directories at `/srv/nixus/project-sources/<project>/revisions/<sha256>/source/`, **never in the world-readable Nix store**. The existing separate reauthenticated review/publish contract applies.
- Direct and unpacked source quotas: at most **256 files**, **64 MiB per file**, **128 MiB total**, **12 path components**; archives at most **64 MiB compressed** and 1024 entries including directories. Realistic binary assets are supported up to these limits without silent truncation.
- ZIP/TAR extraction is data-only, bounded on archive metadata and actual bytes, refuses duplicate paths, traversal, absolute paths, backslashes, unsupported characters, symlinks, hardlinks, sparse entries, devices, FIFO, encrypted ZIP members, `.env` files, private keys, `.git`, and other unsafe names. The extracted manifest, not the compressed-file name, becomes the SHA-256 revision identity. A failed extraction leaves no published project or Incus mutation.
- Published source inspection returns exact file path/hash/size metadata. A Dockerfile-only source produces a separate, read-only generated Compose launch preview without adding a Compose file to the uploaded revision. The plan's `buildContextHash` and proposed image identity depend on the entire source revision, **including every context file**, not only the Dockerfile. An existing Compose source is preserved with its original paths and requires pinned parser/compatibility validation.
- High-confidence BuildKit-only features are flagged as unsupported, but source remains unchanged. The preview is **not** an approval to build or deploy.

## Build and import (implemented)

1. **Preflight:** the pinned `incus-compose config` validator runs on a read-only snapshot of the reviewed source inside bubblewrap (`--unshare-all`) as the unprivileged `nixus-oci` user. The Incus socket, host secrets and state directories are inaccessible. Built services get a *separate* Nixus override (`image: localhost/nixus-<project>-<service>:<revision>`, builds disabled); the uploaded Compose file is never edited.
2. **Build:** Buildah runs in the same sandbox with no network (`--pull=never`, empty network namespace) and an offline signature policy that only accepts local storage and the output archive. Each built service produces an OCI archive and a flattened rootfs tarball.
3. **Verify:** root re-hashes both outputs. The OCI archive's manifest graph is checked without extraction. The rootfs may contain only directories, regular files, symlinks and hard links to earlier members: no devices, FIFOs, sockets or path escapes. Root derives the runtime `config.json` (command, environment, working directory, user) from the verified OCI image config, never from the sandbox. Named users are resolved from the image's own `/etc/passwd`; an unresolved user fails instead of running as root.
4. **Import:** Incus 7 has no local OCI-archive import, so Nixus builds the same split OCI image incus-compose builds: a deterministic metadata tarball (`metadata.yaml` with `type: oci`, plus `config.json`) and the rootfs. Incus fingerprints a split image as SHA-256 of metadata followed by rootfs. Nixus computes that before import, refuses and removes any import whose fingerprint differs, and only then creates the alias `local/nixus-<project>-<service>:<revision>`. That is exactly the alias incus-compose resolves for the override's image reference, so `incus-compose up` reuses it and never pulls or builds. An alias that already points at other content is never moved.
5. **Project:** images go into the Incus project incus-compose uses for the Compose project. Nixus creates it, if missing, with its own image store and `user.nixus.owner=true`; it refuses a project that shares the default image store.

The `oci-builder` VM test runs the whole path for real: build in the sandbox, import into Incus, check the alias and fingerprint, then start the image as an OCI container and read a file from it.

## Deploy (#45)

A project with `nixus.project.backend = "incus-compose"` and a bound source revision deploys through the existing project transaction (review, publish, deploy, resumable journal):

- **Preconditions**, rechecked immediately before apply:
  - an `imported` build of exactly that revision exists;
  - every built alias still points at its verified fingerprint;
  - the Incus project carries `user.nixus.owner=true` and `user.nixus.backend=incus-compose`.
- **Exclusive ownership:**
  - A Compose project may not claim native resources.
  - The native adapter refuses Compose-owned Incus projects.
  - The Compose adapter refuses any instance in its project that lacks incus-compose's service label, or that is native-owned.
  - The `default` and `lab` projects are never used.
- **Apply:** `incus-compose up --detach --no-build --pull missing --no-healthd --no-dns` runs on a root-only copy of the reviewed source with the image override.
  - Nixus never runs `down`, `--volumes` or `--recreate`.
  - The review lists services whose image changes and are therefore recreated.
  - `up` is idempotent, so an interrupted deploy is resumed by running it again.
- **Verify:** every service must have running instances on the reviewed image fingerprints. The deployed intent is recorded on the Incus project, so an unchanged project plans as a no-op.

The `oci-builder` VM test deploys a two-service app, writes into a named volume, deploys a changed revision, then checks that the changed service was recreated and the volume data kept. It also checks that a stray instance blocks the adapter.

## Still open

- **#45 follow-ups:**
  - Native project creation, claim adoption and native instance templates (image, network, storage, USB).
  - The incus-compose health daemon and DNS sidecar (currently disabled because they pull registry images).
- **#46:** delivering Compose `.env`/`env_file:` secrets from SOPS at runtime only.
- **Base images:** builds are offline, so `FROM` must be `scratch` or an image already in local Buildah storage. Images whose files belong to non-root users cannot be built yet, because the sandbox maps only one user.

## Scope

Nixus is proceeding with a **clean-slate** installation. There is **no legacy Docker or Portainer/Arcane data migration to perform**. Do not create migration shims or quietly delete unknown host state.

Building and importing never starts a container, decrypts secrets or rebuilds the host OS.

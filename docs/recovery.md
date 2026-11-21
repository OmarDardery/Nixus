# Security, storage, snapshots and recovery

## Initial onboarding and host activation

The initial web-wizard bootstrap, full installer and updater share the existing
Manager/worker recovery manifest, previous-generation pin and independent pending
deadline. Local health checks leave access **unconfirmed**. A remote CLI
confirmation must originate from an interactive SSH/Cockpit session opened
**after** activation; an old SSH session is not proof. At a physical VT/serial
console, the operator may acknowledge local access directly. The HTTPS portal
requires a new post-activation login from a non-loopback client. If the new
address, certificate or login is unusable, do not confirm; request
`sudo nixus-admin config rollback TRANSACTION_ID` at the host console or let
the guard expire. After interrupted activation, re-running the original installer
or updater resumes/rechecks the same pending job. A stopped or missing worker
and an unknown status are not authorization to create a competing transaction.

The guarded worker also owns existing-install source and installation-metadata
publication. A rollback restores their exact saved predecessors, the matching
platform baseline and the old host generation. This does **not** revert arbitrary
Incus guest disks, custom volumes or an incompatible Incus database change.

After a disconnected initial wizard, rerun the installer with `--wizard` to resume
its transaction. After a disconnected full installation, rerun without that flag.
Do not delete pending/job/recovery files to force a retry. Inspect the transaction
and root worker journal from a local console if recovery fails; the retained
original OS generation and bootloader remain the fallback. Recovery does not need
any application workload or identity service.

## Scheduled repository verification

When restic backups are enabled, the existing `nixus-backup-check.service` has a
persistent Sunday 05:00 timer with up to 30 minutes of jitter. It defaults to
metadata checks, which validate repository structure and indexes but **do not read
every data block**. A full repository read is available through the same service:

```nix
{ ... }: {
  nixus.backupVerification = {
    enable = true;
    mode = "full";
    schedule = "Sun *-*-* 05:00:00";
  };
}
```

Review this module through the existing file configuration workflow. These are
typed NixOS options, not a second mutable settings file. The portal displays the
configured schedule, actual last-check scope and outcome; the existing **Check
restic repository** action and `sudo nixus-admin guests backup-check` run the
same service. Setting `enable=false` disables scheduling while preserving manual
checks. Changing policy lets an active read finish; its evidence retains its
actual scope and the next run uses the new policy.

Full reads can consume substantial bandwidth and I/O. Neither mode stops guests,
imports archives, prunes snapshots or proves that an application can be restored.
Restic's own repository locks remain in force; a simultaneous backup/prune,
unreachable repository or bad credential can fail a check. Adjust scheduling to
avoid long backups and rerun after resolving the cause. Existing service-failure
webhooks also cover checks when notifications are configured; full Alertmanager
routing and restore-drill qualification remain separate work.

The root-only `/var/lib/nixus/backup-verification.json` stores the latest result
and previous success. Root-only target fingerprints prevent evidence for an old
repository from qualifying a new one; fingerprints and repository URLs are not
public status fields. Raw restic stdout/stderr is discarded because remote errors
can contain credentials or server responses. The journal provides a static failure
notice, and protected host credentials remain available for deliberate console
diagnosis. Keep repository URI credentials outside Nix/Git; use the supported
runtime environment/password files, including RESTIC_REST_USERNAME/PASSWORD for
REST authentication.

Missing/corrupt/future evidence is unknown, an interrupted read remains
interrupted, and a later failure takes precedence over a previous success. A timer
trigger with no completed check becomes overdue using native systemd trigger
timestamps. Unsynchronized/invalid clock observations warn against treating check
timestamps as reliable freshness evidence. This does not certify off-host transfer
or a restore drill.

Existing settings JSON stays at schema version 1. A reviewed source update adds
the timer for hosts already enabling backups; no repository is reformatted and no
credential or guest state is migrated. Reverting source removes the new timer and
returns the previous check command. The extra evidence file can remain and is not
interpreted as backup/application state by older code. A failed evidence write or
read-only/full state filesystem fails verification rather than reporting success.

## Storage policy

| Backend | Benefits | Limits |
|---|---|---|
| ZFS | Efficient snapshots/clones, checksums, compression, datasets and enforced quotas | Needs deliberate disk/pool layout, RAM planning, scrub/recovery operations, compatible kernel |
| Btrfs | Efficient snapshots/clones and compression, native NixOS support | Requires suitable existing filesystem; redundancy/repair behavior needs planning |
| Directory on ext4/XFS | Portable, no format/create-pool action, simple baseline | File-copy snapshots, slower clones/exports; hard container quotas are not guaranteed |
| LVM-thin | Efficient block provisioning/snapshots | Thin-pool exhaustion and separate filesystem/metadata management |

The shipped baseline creates an Incus **directory** pool under its dedicated state tree.
It does not create a host filesystem, consume a raw device, or promise redundancy.
Persistent data lives under `/var/lib/incus` (instances and custom volumes, including Compose
named volumes). Project source lives under `/srv/nixus/projects` and published
Dockerfile/Compose sources under `/srv/nixus/project-sources`.
Nix source/store and runtime state have separate lifecycles.

For ZFS, first review physical disk identity/contents, backups and a recovery plan. Obtain
explicit operator confirmation before any first-time destructive disk/pool initialization.
No `zpool create`, partitioning, `mkfs`, force/wipe flag or disko destroy command runs on rebuild.
Initialize storage through your separately reviewed installer/storage procedure. Then create
or identify an **empty child dataset**, e.g. a chosen `POOL/incus`, and set:

```nix
storage = {
  driver = "zfs";
  source = "EXISTING-POOL/EXISTING-EMPTY-DATASET";
  confirmedExistingZfsDataset = true;
  hostId = "YOUR-UNIQUE-8-HEX-DIGIT-ID";
};
```

Use a real dataset and host ID. A preflight guard rejects raw device paths, pool roots and
missing datasets. The NixOS ZFS package/modules and scheduled scrub are enabled, but this
is not an automatic storage conversion. Switching an existing Incus pool's driver/source
is not an in-place migration: create a separate pool and migrate verified exports/volumes.
The preseed never deletes the old pool on omission. Host ZFS import/root configuration is
part of your hardware-specific installation.

Btrfs/LVM are evaluated alternatives, not supported values of this repository's pool selector.
Add a reviewed module/backend validation before choosing one. Never label an untested storage
layout as a drop-in configuration change.

## Snapshots versus backups

The `base` profile schedules daily Incus snapshots with seven-day expiration. These are
fast recovery points on the same storage. Live snapshots can be crash-consistent; they do
not replace database dumps and do not survive loss of the source disk/pool.

```console
sudo incus snapshot create apps manual-before-update --project lab
sudo incus snapshot list apps --project lab
```

Restoring a snapshot overwrites current guest state. Stop the guest, take/export a current
backup if possible, then explicitly restore the named snapshot and start it. Review the
installed `incus snapshot restore --help` syntax before applying a rollback. Test application
schema compatibility too; OS rollback does not undo a database migration.

## Independent scheduled backups

Set `site.backup.enable = true` only with an independent repository, runtime credentials
and enough staging disk. Default schedule is approximately 03:00 in the configured timezone with up to
ten minutes jitter; missed runs execute after boot. `initialize` is false until explicitly
approved for the chosen remote target. Repository initialization is not disk formatting,
but it still needs the correct remote path, access and retained recovery password.

The service:

1. Takes the shared Incus mutation lock and recovers pending guest restarts from a prior interrupted export.
2. Enumerates projects, instances, pools and custom volumes. Unsupported guest states fail explicitly.
3. Runs the demo PostgreSQL `pg_dump --format=custom` hook when the demo is enabled. Redis is a cache;
   it deliberately has no durable data. Other live-consistency hooks must be implemented per application.
4. Records restart intent on persistent disk, then gracefully stops each group's originally running guests.
   No forced shutdown is used. Each consistency group is stopped, exported with its
   custom volumes, and recovered before the next group begins. Shared writable volumes
   join their consumers into one group.
5. Publishes a complete generation only after all selected guest/volume exports and recovery kits succeed. Exports include
   instance configuration and snapshots. Inventory metadata is retained for reconstruction.
6. Restarts only guests that were previously running, including after an export error. A systemd
   `ExecStopPost` and boot recovery unit retry journaled restarts if the exporter was killed.
7. Runs restic against the completed exports and retains 7 daily, 4 weekly and 6 monthly snapshots.
   A success timestamp is written only after the restic service's successful command path.

This is a deliberate **offline backup** strategy with downtime for each selected running guest
during its group's export. Large exports can make that group's outage long.
Staging needs room for two retained complete generations plus a full new generation and overhead.
The free-space reserve is a minimum preflight check, not an export-size estimate; an export
that fills staging fails and recovers its guests without replacing prior complete generations.
Exports are root-readable plaintext on local disk; use encrypted host storage where required.
Only the off-host restic repository is encrypted by restic. Keep its password/private access
credentials separately from the failed host.

Do not attach guest custom volumes to concurrent host writers during backup. External databases,
NFS data, remote block storage, passthrough disks and application dependencies outside Incus
are not made consistent by stopping guests; include them in an explicit application backup plan.
The source root disk remains a single failure domain. Test exported volume coverage after adding
any new storage driver, content type or project-sharing configuration.

`homelab backup NAME` is a convenient native export to the configured client destination. It
does **not** stop a running guest or export separately attached custom volumes and therefore
has live/crash-consistency limitations. For the full scheduled path:

```console
sudo systemctl start restic-backups-nixus
sudo journalctl -u restic-backups-nixus -u nixus-backup-failed --since today
sudo systemctl list-timers '*restic*'
sudo cat /var/lib/nixus/restart-pending.json
```

A network/credential/prune error means the job is failed. Existing good restic snapshots are
retained by restic semantics; do not treat a local export or a fresh success timestamp from an
old run as proof that the current backup completed. Prometheus alerts on failed units and
backup age. External alert delivery requires your real Alertmanager/notification destination.

## Database restore drill

First test in a separate project or guest and avoid duplicate LAN addresses, DNS registrations,
webhooks or public ingress. A cold export of a Compose project includes each database volume as
it was when cleanly stopped. To restore a logical dump, stop the application service, restore
into the database container with its own client tools through `incus exec`, then start the
application again. This overwrites database objects: take a current backup first and test on an
isolated copy. A schema-changing application upgrade may require a matching older application
version. Follow each application's documented backup workflow (for example Immich's uploads
and library) rather than relying on volume exports alone.

Configured recovery credentials and SOPS links must live under trusted root-owned
parent directories; writable non-sticky or unprivileged-owned parents make
coverage incomplete. Move affected credentials to root-controlled storage and
review their configured paths. This preflight refuses
backup before guest shutdown.

## Host-loss restore

### Guided, checkpointed imports

The replacement-host CLI restores a complete version-2 generation into a fresh
Incus project, using a pre-existing reviewed local storage pool. It stages source
and credentials for review, imports separate custom volumes and stopped guests,
then removes network/passthrough access before validation. It never formats disks,
activates archived Nix modules, overwrites runtime credentials, starts a guest or
reconnects production addresses. This is a local-backend recovery increment;
privileged/raw guests, unmanaged NICs, passthrough and missing attached data stop
with a required separate review. Source material is never modified or deleted.
The planner accepts existing dir, ZFS, Btrfs and LVM pools; automated recovery
coverage currently exercises only dir. Other backends, VM recovery and application
consistency require separate qualification before relying on them.

1. Install fresh NixOS on the replacement machine with console recovery available.
   Preserve its own boot/hardware configuration. Use the normal single-command
   Nixus installer, initially selecting containers only and no scheduled backups
   or public ingress. Do not import old guest declarations yet.
2. Before enabling recovered services, add this reviewed machine module to the
   installed source (`/var/lib/nixus/config/machine/modules/recovery.nix` on the
   modern layout), then build/review/activate through the usual host workflow:

   ```nix
   { ... }: { nixus.recovery.enable = true; }
   ```

   This disables instance reconciliation, apps onboarding, backup/restart timers
   and configured Cloudflare ingress. Verify the resulting marker and units:

   ```sh
   test "$(cat /etc/nixus/recovery-mode)" = 1
   systemctl is-enabled nixus-instances.service nixus-apps-onboarding.service
   ip -br link
   ls -l /dev/disk/by-uuid
   incus storage list
   ```

   Disabled/not-found units are expected here. Review any additional timers,
   tunnels or jobs introduced by custom modules separately. Preserve working SSH
   and management addressing while reviewing NIC/disk replacements.
3. On the replacement host, obtain restic credentials from **independent** storage
   and restore the chosen off-host snapshot to a root-only directory. Locate its
   complete `generations/GENERATION` directory containing `inventory.json` and
   configuration, secret, instance and custom-volume archives. `restic check`
   alone is not a restore. Do not put decryption credentials only inside the
   repository they unlock. From a root shell with repository/password credentials
   loaded through protected runtime files, replace `SNAPSHOT` with the reviewed ID:

   ```sh
   restic snapshots
   restic check
   install -d -m 0700 /root/offhost
   restic restore SNAPSHOT --target /root/offhost
   ```

   Restic preserves original paths below the target; use the located generation's
   full path in the commands below. Keep the restored material root-owned and its
   generation directory mode 0700.
4. Select an existing local Incus pool on reviewed replacement storage. Do not
   point at an unmounted disk path, erase a device or reuse production storage.
   Write a root-owned mapping file, substituting actual discovered identifiers:

   ```json
   {"pool":"replacement","interfaces":{"old-uplink":"eno1"},"disks":{"OLD-UUID":"NEW-UUID"}}
   ```

   The pool receives recovered data; it must already exist. Supported backends
   accepted by the planner are dir, ZFS, Btrfs and LVM with portable Incus exports;
   only dir has automated restore evidence. NIC/disk mappings must
   refer to existing replacement hardware. They are review records, not network,
   filesystem or boot mutations; adapt old source against the replacement's own
   configuration manually. Empty mappings are allowed when no hardware remap is
   needed. The initial increment maps all recovered objects to one selected pool.
5. Plan, inspect and explicitly confirm the imports:

   ```sh
   sudo nixus-admin recovery plan /root/offhost/generations/GENERATION --mappings /root/recovery-mappings.json
   sudo nixus-admin recovery status
   sudo nixus-admin recovery resume --confirm
   ```

   Planning hashes every archive, checks both recovery kits and records source
   identity and destination pool configuration. No Incus resource is changed by
   planning. The new journal is `/var/lib/nixus-admin/replacement-recovery.json`;
   source and credentials are staged under its reported recovery ID at
   `/var/lib/nixus-admin/recovery-ID/{config,secrets}`. These files stay root-only.
   Compare source files and restore reviewed credentials individually, with their
   required owners/modes; never copy old hardware configuration or secrets over
   the replacement wholesale. Metadata/trust/network definitions remain available
   in the original inventory for review; old listening addresses are not applied.
6. Resume using the same command after a controller interruption or reboot.
   Changed checksums, pool configuration or recovered objects stop execution.
   An interruption after volume import but before ownership was recorded leaves
   an **uncertain import**, not permission to overwrite it. Inspect that stopped
   target, verify it against the archive, and only then explicitly set its
   `user.nixus.recovery-id` to the journal ID using native Incus before resuming.
   If it cannot be verified, retain it and investigate; do not delete user data to
   make retry pass. No existing unmarked object is automatically adopted.
7. Validate restored data using Incus exec/console on the isolated targets.
   Guests have no NICs/profiles, autostart or snapshot schedule. Their imported
   root disks and separate recovered custom volumes remain attached. Start and
   stop selected guests explicitly for the drill, check application records
   and data, then stop them again.
   Runtime jobs inside a guest still need review before any connectivity is added.
   Archived snapshots retain their original configuration; review isolation before
   restoring one. Do not claim success merely because imports succeeded.
8. Review and perform cutover through **native Incus**. Recreate only reviewed
   projects, profiles and networks from the inventory. Keep the replacement's
   own pool source, NIC names, addresses and disk UUIDs. Move verified custom
   volumes to their reviewed original namespaces, and move stopped guests to
   their original project/name. Detach/re-attach custom volumes as required for
   cross-project moves; never attach a surviving production writer's volume.
   Check installed `incus move --help` and `incus storage volume move --help` for
   backend restrictions. Preserve the recovery ID and imported instance UUID.
   Review desired declarations against these restored objects, including explicit
   ownership adoption if managing them through Nixus. Do not enable onboarding
   against unreviewed credentials or an old guest OS target.
9. Release the automation guard only after the application-data drill and reviewed
   source inventory match the restored identities:

   ```sh
   sudo nixus-admin recovery release --confirm --data-verified
   ```

   Every desired guest that could be created must be among the recovered original
   identities, present and stopped with its recorded UUID/recovery ID. Legacy or
   partial coverage additionally requires `--acknowledge-exclusions` and is recorded
   as selected-data evidence. Release records an **operator attestation**, backup
   time and recovery duration; it never starts guests or changes networking.
   Only then remove the recovery-mode module through a reviewed host activation.
   An unfinished/corrupt journal continues to block reconciliation, deployment,
   backups and portal guest mutations even if the mode module is removed early.

   For release evidence, export the redacted result rather than the operational
   status (which intentionally includes private workload/hardware mappings):

   ```sh
   sudo nixus-admin recovery export-report > recovery.json
   ```

   Inspect it before sharing. It contains source/input identity, coverage,
   attestation time and measured duration, with no guest names, disk UUIDs,
   addresses, credentials or mapping paths. Incomplete recovery stays unverified.

If interrupted, rollback means retaining the quarantine and original backup while
returning to the known replacement host configuration. There is no automatic
delete/overwrite cleanup. The CLI does not claim arbitrary backend, device,
custom-module secret or application-consistency coverage. Its two-node CI drill
uses synthetic configuration kits; an independently supplied real off-host
generation, mapped hardware and application checks are still mandatory for #5
and release qualification.

The instance manifest assists reconstruction; it is not an automatic restore of every possible
Incus server object. UI-created non-default networks/profiles, remote storage and external account
resources need their own exported definitions/IaC. Back up the configuration Git repository and
secret recovery material independently; do not rely on a file copied into the failed disk.
The provided backup does not raw-copy a live Incus database.

## Security upkeep

Review pinned Nixpkgs/sops inputs, incus-compose release notes and Compose base image digests regularly.
Use a branch/PR and `nix flake update`, build/evaluate, then deploy during a maintenance window.
No unattended flake update or reboot changes the hypervisor behind your back. Kernel updates
require a planned reboot. Incus database/API upgrades may make an old daemon generation
incompatible; consult release notes before downgrading. NixOS rollback is not a database backup.

Trusted Incus socket/certificates, passwordless sudo and Nixus administrator accounts are all
privileged control planes. Keep them private, use distinct identities, revoke lost keys, and
protect backups because they include guest secrets. The default firewall restricts management
by interface/source; it is not a substitute for authentication or physical network security.

## Current local layout

New backups use `.incomplete/` for unpublished work and `generations/<id>/` for
complete archives, recovery kits and their inventory/checksums. `latest.json`
selects the latest published generation. Restic excludes `.incomplete/` and
preserves the complete generation directories. A later failed export cannot
replace members of the previous complete set. Two complete local generations are
kept; legacy flat archives remain readable until explicitly retired.

Stopped guests remain stopped; running guests recover after their own group,
including after cancellation/failure. Shared writable volumes require their
consumers to stop together. Excluded groups are explicitly omitted and do not
advance the full-host success timestamp. Exports do not protect external host
writers or devices; apply workload-specific maintenance policies.

## Coverage and staging preflight

Before stopping guests, scheduled backup checks required configured recovery
credentials and estimates the **new** generation in addition to retained files.
Observed Incus usage and previous archive sizes are estimates, with 25% headroom
and 16 MiB per archive; unavailable current usage is listed as unknown even if a
previous archive size exists. Recovery kits add their bounded maximum. Known
insufficient capacity refuses before guest shutdown. Estimates do not guarantee
snapshot size, compression ratio or space under concurrent writes.

Guest disks and separately exported custom volumes are distinguished from host
bind mounts, raw attached disks and other external sources. A read-only attachment
still needs its source data to be recoverable. Uncovered or excluded data keeps
coverage partial and does not refresh the full-host success timestamp. The root-only
`inventory.json` retains `coverageDetails`, `capacity` and actual `archiveBytes`;
`/var/lib/nixus/backup-status.json` retains the most recent preflight/result.
Existing version-2 inventories remain readable. Older inventories without these
fields have no evidence for this additional coverage assessment.

```sh
sudo nixus-admin recovery coverage
sudo cat /var/lib/nixus/backup-status.json
```

The credential check reports identifiers, never secret contents. Configured SOPS
symlinks are resolved to checked regular root-owned targets before archiving;
missing or writable-by-others required targets refuse scheduled backup. Keep
restic decryption/access credentials independently available: a copy **inside**
the repository cannot unlock that repository after total host loss.

A completed export is not an off-host transfer, `restic check` is not an application
restore, and these new records initially say `restore: unverified`. Prove actual
project source, Compose volumes and any external data through an isolated restore drill. Incus server identity/administrator enrollment,
external writers, arbitrary custom module secrets and application-specific
consistency still require review; this change alone does not close #6 or qualify
a whole-host release. No new application integration or retention policy is added.

## Project backups (declarative)

Project backups are configured once in the reviewed project workspace, in
`/srv/nixus/projects/backups.nix`. Policy edits go through the normal project
review and publication, so they never need a host rebuild.

```nix
{ ... }: {
  nixus.backups = {
    enable = true;
    includeProjects = "all";          # new projects are picked up automatically
    schedule = "daily";               # hourly, daily or weekly
    data = true;                      # also export Incus instances and volumes
    verification = "metadata";        # none, metadata or full
    restic = {
      repository = "rclone:gdrive:nixus-backups";       # Google Drive through rclone
      rcloneConfigFile = "/var/lib/nixus-secrets/rclone.conf";
      initialize = true;              # only for a brand new repository
    };
    github.repository = "git@github.com:you/nixus-config.git";  # optional, private
  };
}
```

The stable `nixus-project-backup.timer` checks every 15 minutes and runs the
published policy when it is due. Each run records a separate status for every
phase:

| Phase | What it does |
|---|---|
| `config` | Copies the workspace Nix, `flake.lock`, `.sops.yaml`, SOPS ciphertext and each project's exact published Dockerfile/Compose source, with a SHA-256 manifest and per-project coverage |
| `data` | Exports Incus instances and custom volumes through the existing grouped exporter (local staging only) |
| `offHost` | Uploads both to the encrypted restic repository and applies the retention policy |
| `verification` | Runs `restic check` (metadata or full read); this is not an application restore test |
| `github` | Mirrors the non-secret configuration snapshot to a private repository |

Credentials never appear in the policy. Create them as root-only runtime files:

- **Restic password:** `/var/lib/nixus-secrets/project-restic-password`.
- **Google Drive:** create an rclone remote named `gdrive` with `rclone config`,
  and keep its config file at the path set in `rcloneConfigFile`.
- **GitHub mirror:** run `sudo nixus-admin project-backup github-key`. It
  prints only the public key; add it to your private repository as a deploy key
  with write access. GitHub's SSH host key is pinned.

Useful commands:

```sh
sudo nixus-admin project-backup status             # per-phase results and coverage
sudo nixus-admin project-backup run                # run now, ignoring the schedule
sudo nixus-admin project-backup check-destination  # confirm restic can unlock the repository
```

Coverage is honest. A Compose project without a published source, or host bind
mounts outside Incus volumes, is listed under `unknowns`. Keep the
passphrase-encrypted recovery kit separately: without it, the restic password
and age identity are lost with the host.

### Set up and restore from the console

**Backups → Set up backups**: choose Google Drive/rclone (paste the config from
`rclone config show`), S3, Backblaze B2 or a local disk, then **Save**. On first setup Nixus
generates the repository password and shows it **once**; keep it in your password manager.
**Back up now** runs immediately; snapshots are listed on the same page.

On a fresh install with no apps, **Backups → Restore this server from a backup** takes the
same destination fields and the repository password, and runs the restore described below.
Apps, their data, their secrets and the age identity come back together.

### Restore onto an empty host

On a freshly installed Nixus host (no `/srv/nixus/projects` yet), with the
restic password copied into a root-only file:

```sh
sudo nixus-admin project-backup restore \
  --repository rclone:gdrive:nixus-backups \
  --rclone-config /var/lib/nixus-secrets/rclone.conf \
  --password-file /var/lib/nixus-secrets/project-restic-password
# --snapshot ID selects an older snapshot; the default is the latest Nixus one.
```

The restore:

1. Downloads one snapshot and checks every file against the backup's SHA-256
   manifest and every Incus export against its recorded checksum.
2. Recreates the reviewed workspace, including `backups.nix`.
3. Publishes each project's Dockerfile/Compose source again and confirms it
   reproduces the exact recorded revision.
4. Recreates the Incus projects, imports custom volumes and then instances, and
   starts those that were running.

Any existing workspace, published source, volume or instance with the same
name stops the restore before Incus is changed. The report is written to
`/var/lib/nixus-admin/project-restore-report.json`.

Afterwards, restore the host age identity from the recovery kit before
deploying projects that use encrypted secrets. Rebuild each Compose revision so
its images regain build provenance, and check the application data itself.
The CI VM test performs this restore on a second, empty VM and checks the
workspace, the source bytes and a running restored container.


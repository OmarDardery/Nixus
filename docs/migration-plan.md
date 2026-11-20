# NixLab → Nixus migration plan

Tracker: [#1](https://github.com/OmarDardery/Nixus/issues/1).

## Sources

| Source | Ref | Role |
|---|---|---|
| `nixlab@incus-native` | `0242743` | Code baseline, ported without history |
| `nixlab@archive/pre-incus-native-main-2026-11-17` | `c12dcd8` | Previous Docker/Arcane project; reference only |
| [Rebuild execution plan](incus-native-plan.md) | — | Phase checklist; issue references are remapped to Nixus |

## Rules

- Each change gets one Nixus issue and one PR into `main`.
- Clean slate: no Arcane, Portainer, Docker applications VM or legacy-data migration path.
- NixLab is renamed to Nixus everywhere: options (`nixus.*`), CLI (`nixus-admin`), paths (`/srv/nixus`), units and flake outputs.
- A check counts only if it actually ran. VM, nested-KVM, physical-host and USB evidence is reported separately.
- `OmarDardery/nixlab#N` links point to closed issues or PRs in the original repository.

## Issue map

Open NixLab issues were copied as Nixus #3–#47 (nixlab #8 → #3 … nixlab #139 → #47).
Each copy links back to its original, which holds the full specification.

## Phases

### M0: Repository
- [x] Seed `main`.
- [x] Copy the 45 open NixLab issues with back-links.

### M1: Port and rename (#2)
- [x] Import the incus-native tree.
- [x] Retire Arcane, Portainer and the apps VM (#40).
- [x] Rename NixLab to Nixus.
- [x] Host baseline: all `validation-*` configurations, all `checks.x86_64-linux` derivations and the boolean check sets evaluate; unit and Node UI tests pass; the website builds with link checking.
- [ ] Rewrite the remaining docs that still describe the Arcane apps VM (#48).

### M1.5: One command, then the browser
- [x] `#install` installs Incus and its UI, Cockpit, console and portal non-interactively, then opens console-approved browser enrollment (#50).
- [x] Guided Setup walkthrough derived from host state; resumes after refresh or reboot (#51).
- [x] Host credentials are SOPS/age ciphertext by default, edited in the portal (#52).
- [x] Optimized Bash with a startup budget (#53).
- [x] First-run VM test: claim, setup progress, host SOPS, reboot (#54; VM runs in CI).

### M2: Feature parity (incus-native plan, phases 1–3)
- [ ] Projects: reviewed publication, deploy, logs and revisions (#41, #45).
- [ ] Isolated OCI builder and Compose preflight (#47): NixLab PR OmarDardery/nixlab#152 is ported with its sandbox fixed. Digest-verified Incus import and `incus-compose up` are still open.
- [ ] SOPS/age delivery and rotation (#46): NixLab PRs OmarDardery/nixlab#153 and OmarDardery/nixlab#154 are ported. Production runtime delivery into Incus Compose is still open.
- [ ] Zero-secret output and credential work: #26, #27, #28, #29.

### M3: Qualification (phase 4)
- [ ] Encrypted off-host backups (#42, #43).
- [ ] Independent host-replacement test, including USB guests (#44, #34).
- [ ] VM qualification on nested KVM (#14).
- [ ] Installer, Web UI, CLI, Incus, OCI and recovery CI all green; first release (#3, #21).

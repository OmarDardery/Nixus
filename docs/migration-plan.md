# NixLab → Nixus migration plan

## Sources
| Source | Ref | Role |
|---|---|---|
| `nixlab@incus-native` | `0242743` | Code baseline (ported without history) |
| `nixlab@archive/pre-incus-native-main-2026-11-17` | `c12dcd8` | Previous Docker/Arcane project; reference only |
| `nixlab/docs/incus-native-plan.md` | — | Phase checklist carried over below |

## Rules
- Each change: one Nixus issue → one PR into `main`.
- Clean slate: no Arcane, Portainer, Docker applications VM or legacy-data migration paths.
- Renamed from NixLab to Nixus. Identifiers, paths (`/srv/nixus`), CLI (`nixus-admin`) and options (`nixus.*`) change too.
- A check counts as passing only when it actually ran. VM, KVM, physical-host and USB evidence is listed separately.
- References like `nixlab#N` point to the original repository.

## Phases
### M0 — Repository
- [x] Seed `main`.
- [ ] Copy open NixLab issues with back-links.

### M1 — Port and rebrand
- [ ] Import the incus-native tree, renamed to Nixus.
- [ ] Retire Arcane, Portainer and the apps VM (nixlab#126).
- [ ] Host baseline: flake evaluation, unit tests and browser tests pass.
- [ ] CI workflows adapted.

### M2 — Feature parity (from the incus-native plan, phases 1–3)
- [ ] Projects: reviewed publication, deploy, logs and revisions (nixlab#128, nixlab#133).
- [ ] Isolated OCI builder and Compose preflight (nixlab#139; NixLab PRs nixlab#152 and nixlab#154 are pending).
- [ ] SOPS/age delivery and rotation (nixlab#134; NixLab PR nixlab#153 is a draft).
- [ ] Zero-secret output and credential work: nixlab#61, nixlab#62, nixlab#67, nixlab#68.

### M3 — Qualification (phase 4)
- [ ] Encrypted off-host backups (nixlab#129, nixlab#130).
- [ ] Independent host-replacement test, including USB guests (nixlab#131).
- [ ] Installer, Web UI, CLI, Incus, OCI and recovery CI all green; first release.

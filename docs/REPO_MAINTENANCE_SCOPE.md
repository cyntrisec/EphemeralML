# Repository Maintenance Scope

This repo contains more surface than Cyntrisec needs to actively evolve every week. The goal is not to shrink it immediately. The goal is to keep the maintained surface small and intentional while preserving working evidence, pilots, and cross-cloud deployment paths.

## Active Now

These paths are the current product and pilot-critical surface. Changes here should stay high-confidence and well-tested.

| Path | Why it is active now |
|------|----------------------|
| `common/` | AIR receipt format, verifier logic, manifests, and shared trust primitives |
| `client/` | Secure client, receipt verification, GCP attestation bridge, pilot UX |
| `enclave/` | Core confidential inference path, model loading, receipt emission |
| `verifier-api/` | Public verifier surface and trust-verification story |
| `pilot/` | Reusable pilot kits and buyer-facing technical proof paths |
| `docs/` | Public product architecture, benchmark methodology, and technical diligence that still belongs with the open-source repo |
| `spec/v1/` | AIR v1 public standard surface; frozen unless explicitly revised |

## Maintained But Usually Stable

These areas matter, but they should change only when a real pilot, platform bug, or proof requirement forces it.

| Path | Guidance |
|------|----------|
| `gateway-api/` | Keep compatible and healthy; avoid speculative product work until there is real operator demand |
| `host/` | Maintain for AWS Nitro paths and demos; do not add production scaffolding without a concrete need |
| `manifests/` | Keep aligned with active deployment paths; avoid broad rework |
| `tests/` | Add regression coverage when trust, receipt, or pilot behavior changes |
| `scripts/gcp/`, `scripts/security/` | Keep only actively used workflows sharp; leave the rest alone unless broken |

## Frozen Unless Needed

These paths are part of the repo, but they are not the default place to spend founder time right now.

| Path | Why to freeze by default |
|------|--------------------------|
| `compliance/` | Useful support surface, but not the current moat or near-term buying trigger |
| `infra/` | Preserve working deployment scaffolding, but avoid broad Terraform churn without live infra pressure |
| one-off scripts in `scripts/` | Keep runnable if still referenced; otherwise do not polish for its own sake |
| `artifacts/`, `demo-artifacts/`, `evidence/` | Preserve evidence; add new material only when it supports a current proof point |

## Local Disk Hygiene

Large local directories are mostly workspace state, not repository weight:

- `target/` is disposable Rust build output
- `test_assets/` is local model/data cache; most large files are ignored and can be re-downloaded
- `infra/**/.terraform/` is local provider/plugin cache

Recommended local habit:

```bash
bash scripts/cargo-local.sh test --features mock
```

That keeps local build output in `/tmp/ephemeralml-target` instead of growing `./target`.

## Working Rule

If a change does not improve one of these directly, it is probably not a priority right now:

- trust verification
- AIR receipt correctness
- verifier UX
- pilot evidence
- buyer-facing technical clarity

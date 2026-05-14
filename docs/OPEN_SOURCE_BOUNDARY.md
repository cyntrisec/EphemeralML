# Open-Source Boundary

Last updated: 2026-05-14

This repository is intentionally public for the verification ecosystem, developer UX, and reproducible product artifacts around EphemeralML and AIR v1.

## Keep Public

- AIR v1 specification and verification logic
- Verifier / trust-center code and public API surface
- CLI tooling and generic developer documentation
- Sample receipts, vectors, and generic demo scripts
- Signed public release templates, public deploy runbooks, and reproducible customer launch instructions
- Public benchmark summaries and publication-ready evidence bundles, preferably redacted or packaged as stable release assets
- High-level architecture and security-model documentation

## Keep Private

- Live account inventories, IAM mappings, DNS inventories, and certificate inventories
- Live production deployment runbooks tied to current cloud accounts, private routing topology, or customer accounts
- Raw ad-hoc cloud run artifacts with live project IDs, bucket names, instance IDs, IAM names, or account-specific logs
- Customer-specific artifacts, pilot data, and operator/admin workflows
- Billing, tenancy, abuse tooling, and managed-service operational code
- Internal security ownership logs, review cadence, and exception handling notes
- Proprietary roadmap details for composite/pipeline receipts, managed verification workflows, and compliance packaging before their public interface is stable

## Rule of Thumb

If a document primarily describes a reproducible product behavior, public verification flow, or standards-facing artifact, it likely belongs in the public repo.

If a document primarily describes current live infrastructure, internal operations, customer data, or account-specific security posture, it should live outside the public repo.

If a roadmap item reveals where product moat is forming before the public standard or verifier surface is ready, track it privately and publish only the stable interface later.

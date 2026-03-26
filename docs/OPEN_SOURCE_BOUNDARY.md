# Open-Source Boundary

Last updated: 2026-03-26

This repository is intentionally public for the verification ecosystem, developer UX, and reproducible product artifacts around EphemeralML and AIR v1.

## Keep Public

- AIR v1 specification and verification logic
- Verifier / trust-center code and public API surface
- CLI tooling and generic developer documentation
- Sample receipts, vectors, and generic demo scripts
- Public benchmark summaries and publication-ready evidence bundles
- High-level architecture and security-model documentation

## Keep Private

- Live account inventories, IAM mappings, DNS inventories, and certificate inventories
- Production deployment runbooks tied to current cloud accounts or routing topology
- Customer-specific artifacts, pilot data, and operator/admin workflows
- Billing, tenancy, abuse tooling, and managed-service operational code
- Internal security ownership logs, review cadence, and exception handling notes

## Rule of Thumb

If a document primarily describes a reproducible product behavior, public verification flow, or standards-facing artifact, it likely belongs in the public repo.

If a document primarily describes current live infrastructure, internal operations, customer data, or account-specific security posture, it should live outside the public repo.

# Evidence Layout

This directory contains public reproducibility artifacts for EphemeralML and AIR v1.

## What belongs here

- publication-grade evidence bundles tied to a public claim
- hardening evidence bundles that demonstrate a shipped behavior or regression test
- verification artifacts that an external reviewer can inspect without access to internal infrastructure

## What should not be added here

- customer or pilot data
- live account inventories or environment-specific operator notes
- transient local runs that are not part of a public claim

## Current structure

- `publication-*` — evidence bundles tied to public release or standards/publication claims
- `hardening-*` — evidence captured for shipped hardening or validation work

For the public/private rule set, see [`../docs/OPEN_SOURCE_BOUNDARY.md`](../docs/OPEN_SOURCE_BOUNDARY.md).

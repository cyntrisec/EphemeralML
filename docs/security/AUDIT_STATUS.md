# Security Audit Status (Public Summary)

Last updated: 2026-03-26

This document provides a public-facing view of the repository's current dependency and baseline security status. Detailed internal audit workflow and operational tracking are maintained privately.

## Current Public Status

- **One active dependency advisory under mitigation:** `rsa 0.9.10` / RUSTSEC-2023-0071 / CVE-2023-49092. Current call sites use blinded RSA decryption while upstream constant-time work remains pending.
- **Two informational unmaintained dependencies:** `paste 1.0.15` and `serde_cbor 0.11.2`. Both are currently tracked as low practical risk in the present dependency graph.
- **System OpenSSL baseline:** current supported baseline environments include the OpenSSL fix for CVE-2025-15467, but new hosts and base images still require normal patch verification before deploy.

## Notes

- Public documentation should focus on externally meaningful security posture and mitigations.
- Internal ownership, exception handling, and review cadence are intentionally not published here.

## Related Docs

- [`RISK_REGISTER.md`](RISK_REGISTER.md)
- [`../SECURITY_MODEL.md`](../SECURITY_MODEL.md)

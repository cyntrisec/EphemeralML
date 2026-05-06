# Security Audit Status (Public Summary)

Last updated: 2026-05-06

This document provides a public-facing view of the repository's current dependency and baseline security status. Detailed internal audit workflow and operational tracking are maintained privately.

## Current Public Status

- **Closed in code:** `rsa 0.9.10` / RUSTSEC-2023-0071 / CVE-2023-49092 was removed from the enclave dependency graph; Nitro KMS recipient decryption now uses OpenSSL OAEP-SHA256.
- **Closed in code (2026-05-06):** RUSTSEC-2026-0098 / RUSTSEC-2026-0099 / RUSTSEC-2026-0104 (`rustls-webpki 0.101.7`) closed by disabling AWS SDK service-crate default features and re-enabling only the modern `default-https-client` path. The legacy `rustls` compatibility feature (which mapped to Rustls 0.21 / `rustls-webpki 0.101.7`) is no longer compiled into the workspace.
- **Active transitive advisories:** None at this time.
- **Informational / upstream warnings:** `paste 1.0.15`, `serde_cbor 0.11.2`, and `rand` RustSec warnings remain transitive or ecosystem-wide and are tracked in the risk register.
- **System OpenSSL baseline:** current supported baseline environments include the OpenSSL fix for CVE-2025-15467, but new hosts and base images still require normal patch verification before deploy.

## Notes

- Public documentation should focus on externally meaningful security posture and mitigations.
- Internal ownership, exception handling, and review cadence are intentionally not published here.

## Related Docs

- [`RISK_REGISTER.md`](RISK_REGISTER.md)
- [`../SECURITY_MODEL.md`](../SECURITY_MODEL.md)

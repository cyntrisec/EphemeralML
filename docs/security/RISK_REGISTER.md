# Security Risk Register (Public Summary)

Last updated: 2026-04-24

This public summary tracks known third-party advisories relevant to the repository. Internal ownership, review cadence, and operational follow-up are maintained outside the public repo.

## Recently Closed

### RUSTSEC-2023-0071 / CVE-2023-49092 — `rsa 0.9.10`

- **Severity:** Medium (CVSS 5.9)
- **Affected path:** previously `ephemeral-ml-enclave` → `rsa`
- **Issue:** Non-constant-time RSA decryption can leak timing information.
- **Resolution:** Removed the RustCrypto `rsa` dependency from the enclave. Nitro KMS recipient decryption now uses OpenSSL `PKey` + `Decrypter` with RSAES-OAEP-SHA256.
- **Upstream tracking:** <https://github.com/RustCrypto/RSA/issues/19>
- **Public status:** Closed for this repository's direct dependency graph.

## Active Transitive Advisories

### RUSTSEC-2026-0098 / RUSTSEC-2026-0099 / RUSTSEC-2026-0104 — `rustls-webpki 0.101.7`

- **Affected path:** AWS SDK runtime → `aws-smithy-http-client` → Rustls 0.21 → `rustls-webpki 0.101.7`
- **Issue:** Certificate validation and CRL parsing advisories in older `rustls-webpki`.
- **Current mitigation:** Updated the independent Rustls 0.23 path to `rustls-webpki 0.103.13`. The remaining 0.101.7 copy is retained by the current AWS SDK HTTP client stack and needs upstream AWS SDK/Rustls migration or a future transport-feature change.
- **Public status:** Active upstream/transitive dependency risk.

## Informational / Unmaintained Dependencies

### RUSTSEC-2024-0436 — `paste 1.0.15`

- **Type:** Unmaintained
- **Impact in this repo:** Transitive compile-time macro only; no known runtime security impact.
- **Public status:** Monitored until upstream dependencies migrate.

### RUSTSEC-2021-0127 — `serde_cbor 0.11.2`

- **Type:** Unmaintained
- **Impact in this repo:** Transitive dependency through `aws-nitro-enclaves-nsm-api`; EphemeralML uses `ciborium` directly for its own CBOR handling.
- **Public status:** Monitored until upstream dependency chain changes.

### RUSTSEC-2026-0097 — `rand 0.8.5` / `rand 0.9.2`

- **Type:** Unsound advisory for applications using a custom logger with `rand::rng()`.
- **Impact in this repo:** Present through direct workspace dependencies and transitive ML/networking dependencies. No code path has been identified that combines `rand::rng()` with a custom logger in the vulnerable pattern, but the advisory is still denied by `cargo audit --deny warnings`.
- **Public status:** Monitored pending upstream crate migrations and targeted local dependency updates.

## Operationally Closed

### CVE-2025-15467 — System OpenSSL issue

- **Severity:** Critical upstream issue
- **Public status:** Closed for the current baseline environment as of 2026-02-21; new deployment images still need standard distro-level patch verification.

## References

- RustSec advisory database: <https://rustsec.org/advisories/>
- RustCrypto RSA tracking issue: <https://github.com/RustCrypto/RSA/issues/19>
- Ubuntu security tracker: <https://ubuntu.com/security/cves>

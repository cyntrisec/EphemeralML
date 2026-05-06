# Security Risk Register (Public Summary)

Last updated: 2026-05-06

This public summary tracks known third-party advisories relevant to the repository. Internal ownership, review cadence, and operational follow-up are maintained outside the public repo.

## Recently Closed

### RUSTSEC-2026-0098 / RUSTSEC-2026-0099 / RUSTSEC-2026-0104 — `rustls-webpki 0.101.7`

- **Affected path (previously):** AWS SDK runtime → `aws-smithy-http-client` → Rustls 0.21 → `rustls-webpki 0.101.7`
- **Issue:** Certificate validation (URI / wildcard name constraints) and CRL parsing advisories in older `rustls-webpki`.
- **Resolution:** AWS SDK service-crate default features include both the modern `default-https-client` path (Rustls 0.23 + `rustls-webpki 0.103.13`) and a deprecated `rustls` compatibility feature that maps to `aws-smithy-runtime/tls-rustls` → `aws-smithy-http-client/legacy-rustls-ring` → Rustls 0.21 → `rustls-webpki 0.101.7`. The fix sets `default-features = false` on `aws-config`, `aws-sdk-kms`, `aws-sdk-s3`, and `aws-sdk-ssm` in `host`, `enclave` (production-feature deps), `ephemeralml-doctor`, and `ephemeralml-smoke-test`, and explicitly enables only `behavior-version-latest`, `rt-tokio`, `default-https-client` (plus `credentials-process` + `sso` for `aws-config` and `http-1x` + `sigv4a` for `aws-sdk-s3`). The legacy `rustls` feature is no longer enabled, so Rustls 0.21 / `rustls-webpki 0.101.7` are removed from the build graph.
- **Upstream tracking:** <https://rustsec.org/advisories/RUSTSEC-2026-0098>, <https://rustsec.org/advisories/RUSTSEC-2026-0099>, <https://rustsec.org/advisories/RUSTSEC-2026-0104>
- **Public status:** Closed for this repository's dependency graph (verified via `cargo audit`, `cargo tree -i rustls-webpki@0.101.7 --workspace`, and `cargo tree -i rustls@0.21.12 --workspace`).

### RUSTSEC-2023-0071 / CVE-2023-49092 — `rsa 0.9.10`

- **Severity:** Medium (CVSS 5.9)
- **Affected path:** previously `ephemeral-ml-enclave` → `rsa`
- **Issue:** Non-constant-time RSA decryption can leak timing information.
- **Resolution:** Removed the RustCrypto `rsa` dependency from the enclave. Nitro KMS recipient decryption now uses OpenSSL `PKey` + `Decrypter` with RSAES-OAEP-SHA256.
- **Upstream tracking:** <https://github.com/RustCrypto/RSA/issues/19>
- **Public status:** Closed for this repository's direct dependency graph.

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

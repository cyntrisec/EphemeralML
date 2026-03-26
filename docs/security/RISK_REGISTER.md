# Security Risk Register (Public Summary)

Last updated: 2026-03-26

This public summary tracks known third-party advisories relevant to the repository. Internal ownership, review cadence, and operational follow-up are maintained outside the public repo.

## Active Advisory Under Mitigation

### RUSTSEC-2023-0071 / CVE-2023-49092 — `rsa 0.9.10`

- **Severity:** Medium (CVSS 5.9)
- **Affected path:** `ephemeral-ml-enclave` → `rsa`
- **Issue:** Non-constant-time RSA decryption can leak timing information.
- **Current mitigation:** EphemeralML uses `decrypt_blinded()` with RNG at all current RSA decryption call sites.
- **Upstream tracking:** <https://github.com/RustCrypto/RSA/issues/19>
- **Public status:** Accepted under mitigation while waiting for an upstream constant-time release path.

## Informational / Unmaintained Dependencies

### RUSTSEC-2024-0436 — `paste 1.0.15`

- **Type:** Unmaintained
- **Impact in this repo:** Transitive compile-time macro only; no known runtime security impact.
- **Public status:** Monitored until upstream dependencies migrate.

### RUSTSEC-2021-0127 — `serde_cbor 0.11.2`

- **Type:** Unmaintained
- **Impact in this repo:** Transitive dependency through `aws-nitro-enclaves-nsm-api`; EphemeralML uses `ciborium` directly for its own CBOR handling.
- **Public status:** Monitored until upstream dependency chain changes.

## Operationally Closed

### CVE-2025-15467 — System OpenSSL issue

- **Severity:** Critical upstream issue
- **Public status:** Closed for the current baseline environment as of 2026-02-21; new deployment images still need standard distro-level patch verification.

## References

- RustSec advisory database: <https://rustsec.org/advisories/>
- RustCrypto RSA tracking issue: <https://github.com/RustCrypto/RSA/issues/19>
- Ubuntu security tracker: <https://ubuntu.com/security/cves>

# Security Risk Register

Last updated: 2026-02-21

## Open Risks

### R-001: RSA timing side-channel (Marvin Attack)

| Field | Value |
|-------|-------|
| **Advisory** | RUSTSEC-2023-0071 / CVE-2023-49092 |
| **Severity** | Medium (CVSS 5.9) |
| **Affected crate** | `rsa 0.9.10` |
| **Affected path** | `ephemeral-ml-enclave` → `rsa` |
| **Description** | Non-constant-time RSA decryption leaks timing information observable over the network. |
| **Current mitigation** | All call sites use `decrypt_blinded()` with RNG to mask timing. |
| **Upstream tracking** | <https://github.com/RustCrypto/RSA/issues/19> |
| **Owner** | _TBD_ |
| **Review cadence** | Quarterly (next: 2026-05-21) |
| **Resolution plan** | Upgrade to `rsa` 0.10+ when constant-time release ships. |

### R-002: paste crate unmaintained

| Field | Value |
|-------|-------|
| **Advisory** | RUSTSEC-2024-0436 |
| **Severity** | Low (informational) |
| **Affected crate** | `paste 1.0.15` |
| **Affected path** | `tokenizers` / `pulp` / `gemm-common` → `candle-core` (transitive) |
| **Description** | Author archived the repository. No security vulnerability, compile-time macro only. |
| **Current mitigation** | None required — no runtime impact. |
| **Upstream tracking** | Drop-in fork available: `pastey` crate. |
| **Owner** | _TBD_ |
| **Review cadence** | Semi-annual (next: 2026-08-21) |
| **Resolution plan** | Wait for `tokenizers`/`gemm` upstream to migrate. |

### R-003: serde_cbor unmaintained

| Field | Value |
|-------|-------|
| **Advisory** | RUSTSEC-2021-0127 |
| **Severity** | Low (informational) |
| **Affected crate** | `serde_cbor 0.11.2` |
| **Affected path** | `aws-nitro-enclaves-nsm-api 0.4.0` → `serde_cbor` (transitive) |
| **Description** | Author archived the repository. CBOR parsing in trusted enclave context. |
| **Current mitigation** | EphemeralML uses `ciborium` for its own CBOR. Cannot remove `serde_cbor` without upstream nsm-api update. |
| **Upstream tracking** | <https://github.com/aws/aws-nitro-enclaves-nsm-api> |
| **Owner** | _TBD_ |
| **Review cadence** | Semi-annual (next: 2026-08-21) |
| **Resolution plan** | Upgrade `aws-nitro-enclaves-nsm-api` when a release drops `serde_cbor`. |

## Closed / Resolved

### R-004: System OpenSSL CVE-2025-15467

| Field | Value |
|-------|-------|
| **Advisory** | CVE-2025-15467 |
| **Severity** | Critical (CVSS 9.8) — upstream |
| **Affected component** | System `libssl3` linked by `openssl` Rust crate (0.10.75) |
| **Closed date** | 2026-02-21 |
| **Resolution** | Patched in current baseline (Ubuntu Jammy `libssl3 3.0.2-0ubuntu1.21`). |
| **Ongoing requirement** | New hosts/images must be validated against <https://ubuntu.com/security/CVE-2025-15467> before deploy. |

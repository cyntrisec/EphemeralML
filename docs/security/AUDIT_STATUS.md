# Security Audit Status

Last updated: 2026-02-21

## Active Vulnerability

### RUSTSEC-2023-0071 — rsa 0.9.10 (Marvin Attack)

- **Severity:** Medium (CVSS 5.9)
- **CVE:** CVE-2023-49092
- **Advisory:** <https://rustsec.org/advisories/RUSTSEC-2023-0071.html>
- **Upstream status:** No patched release. Constant-time rewrite tracked at
  <https://github.com/RustCrypto/RSA/issues/19>.
- **Our mitigation:** All RSA decrypt call sites use `decrypt_blinded()` with an
  RNG to mask timing signals:
  - `enclave/src/attestation.rs` (production path)
  - `enclave/src/mock.rs` (test path)
- **CI handling:** Ignored in `cargo audit` via `rustsec/audit-check` `ignore`
  parameter. Rationale and review date tracked in `.github/workflows/ci.yml`.

## Informational / Unmaintained

### RUSTSEC-2024-0436 — paste 1.0.15

- **Advisory:** <https://rustsec.org/advisories/RUSTSEC-2024-0436.html>
- **Type:** Unmaintained (author archived repo)
- **Dep chain:** `tokenizers 0.22.2` / `pulp` / `gemm-common` → `candle-core`
- **Runtime risk:** None — compile-time proc macro only.
- **Alternatives:** `pastey` (drop-in fork). Waiting for upstream tokenizers/gemm
  to migrate.

### RUSTSEC-2021-0127 — serde_cbor 0.11.2

- **Advisory:** <https://rustsec.org/advisories/RUSTSEC-2021-0127.html>
- **Type:** Unmaintained (author archived repo)
- **Dep chain:** `aws-nitro-enclaves-nsm-api 0.4.0` → `serde_cbor`
- **Runtime risk:** Low — CBOR parsing of attestation documents inside trusted
  enclave context only.
- **Alternatives:** `ciborium` (already used directly in EphemeralML).
  Cannot remove serde_cbor without an upstream nsm-api release.

## System-Level: OpenSSL CVE-2025-15467 (Operationally Closed)

- **CVE:** CVE-2025-15467
- **Severity:** Critical (CVSS 9.8) — stack buffer overflow in CMS
  AuthEnvelopedData parsing.
- **Upstream fix:** OpenSSL 3.0.19, 3.3.6, 3.4.4, 3.5.5, 3.6.1.
  - Source: <https://www.openssl.org/news/vulnerabilities.html>
- **Status:** Operationally closed for current baseline environments as of
  2026-02-21. Ubuntu Jammy `libssl3 3.0.2-0ubuntu1.21` includes the backported
  fix.
- **Ongoing requirement:** New deployment hosts or container base images must
  still be validated against the distro security tracker before deploy:
  <https://ubuntu.com/security/CVE-2025-15467>.

## Sources

- RustSec Advisory Database: <https://rustsec.org/advisories/>
- cargo-audit JSON report: `evidence/security/audit-2026-02-21/cargo-audit.json`
- OpenSSL security advisories: <https://www.openssl.org/news/vulnerabilities.html>
- Ubuntu CVE tracker: <https://ubuntu.com/security/cves>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2023-49092>
- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-15467>

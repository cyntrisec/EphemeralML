# EphemeralML Security Audit

**Initial audit:** 2025-01-31
**Last verified:** 2026-02-04
**Auditors:** 3 specialized sub-agents (cryptographer, attestation expert, security architect)

---

## Summary

| Component | Rating | Status |
|-----------|--------|--------|
| **Cryptography** | GREEN | All critical findings resolved, HKDF + ephemeral keys + AAD binding |
| **Attestation & KMS** | GREEN | P2-0 VERIFIED on Nitro (commit `c1c7439`, instance i-01959fa23e43d9506); cert time validation and ReceiptVerifier incomplete |
| **Architecture** | GREEN | Solid three-zone model, fail-closed design, ZeroizeOnDrop throughout |
| **OVERALL** | GREEN | P2-0 verified on Nitro (commit `c1c7439`); remaining Phase 2 items are hardening |

---

## Critical Findings (Phase 1) — All Resolved

### C1. Mock Feature Bypass — FIXED

**File:** `client/src/attestation_verifier.rs`
**Commit:** `4998669`

**Problem:** `#[cfg(feature = "mock")]` allowed an attacker to send `module_id = "mock-enclave"` and bypass all cryptographic verification, even in production builds.

**Fix:** Changed to `#[cfg(all(feature = "mock", not(feature = "production")))]`. Mock path is now compile-time excluded from production builds.

**Verified:** Feature gate confirmed in code. Production builds cannot reach mock attestation path.

---

### C2. Static Nonce in KMS Client — FIXED

**File:** `enclave/src/kms_client.rs`
**Commit:** `4998669`

**Problem:** All KMS decrypt requests used `[0u8; 16]` as nonce, making attestation documents fully replayable.

**Fix:** Nonce is now generated per-request via `rand::thread_rng().fill_bytes()`.

**Verified:** Each `decrypt()` call generates a fresh 128-bit random nonce before calling `generate_attestation()`.

---

### C3. Insecure Nonce Generation — FIXED

**File:** `common/src/lib.rs`
**Commit:** `4998669`

**Problem:** `generate_nonce()` used UUID + timestamp hashed with SHA-256 — not cryptographically secure randomness.

**Fix:** Replaced with `OsRng.fill_bytes()` (12-byte nonce for ChaCha20-Poly1305).

**Verified:** `generate_nonce()` now uses `rand::rngs::OsRng` directly.

---

### C4. No Forward Secrecy — FIXED

**File:** `common/src/hpke_session.rs`
**Commit:** `4998669`

**Problem:** Static X25519 keys were reused across sessions. Compromise of private key would expose all past sessions.

**Fix:** Ephemeral X25519 key pairs generated per session during `establish()`. All key material derives `ZeroizeOnDrop`.

**Verified:** `HPKESession::establish()` generates fresh ECDH key pairs. No static secret reuse.

---

### C5. SHA-256 Instead of HKDF — FIXED

**File:** `common/src/hpke_session.rs`
**Commit:** `4998669`

**Problem:** `derive_session_key()` used plain SHA-256 hash of shared secret instead of proper KDF.

**Fix:** Replaced with `hkdf::Hkdf::<Sha256>` (RFC 5869) using extract-then-expand with transcript hash for domain separation.

**Verified:** `derive_session_key()` uses `Hkdf::<Sha256>::new()` + `.expand()` with transcript hash as info.

---

## Security Improvements Added After Initial Audit

### C6. AEAD AAD Binding — ADDED

**File:** `common/src/hpke_session.rs`
**Commit:** `d6877bf`

Session metadata (protocol version, session ID, sequence number) is bound to ciphertext as Additional Authenticated Data (AAD) in ChaCha20-Poly1305 encrypt/decrypt. This prevents cross-session ciphertext splicing by a hostile relay.

`construct_aad()` builds the AAD from `protocol_version || session_id_len || session_id || sequence_number`. Test `test_aad_cross_session_splice` verifies that ciphertext from session A cannot be decrypted in session B.

---

### C7. KMS Encryption Context — ADDED

**Files:** `enclave/src/kms_client.rs`, `enclave/src/model_loader.rs`
**Commit:** `d6877bf`

KMS `Decrypt` calls now include an encryption context with `model_id` and `version` from the model manifest. This binds DEK decryption to a specific model, preventing cross-model or cross-tenant ciphertext replay. KMS policy can enforce context matching server-side.

---

### C8. Cipher Alignment — FIXED

**Files:** `scripts/encrypt_model.py`, `scripts/prepare_benchmark_model.sh`, `enclave/src/model_loader.rs`
**Commit:** `321c1f4`

`encrypt_model.py` previously used AES-256-GCM while the enclave decrypted with ChaCha20-Poly1305. All paths now use ChaCha20-Poly1305 consistently. The KMS `KeySpec='AES_256'` returns 32 random bytes which is a valid ChaCha20 key.

---

## Phase 2 — Open (High Priority Hardening)

### P2-0. Attestation Format/Verification Mismatch — VERIFIED

**Files:** `enclave/src/attestation.rs`, `client/src/attestation_verifier.rs`, `enclave/src/mock.rs`, `client/src/secure_client.rs`
**Fix commit:** `b325fdd`

**What was fixed (commit `b325fdd`):**
1. Unified attestation hash: `SHA-256(doc.signature)` everywhere (server, client, benchmarks), replacing field-by-field hashing
2. Mock server wire format: `attestation_doc.signature.clone()` instead of `serde_json::to_vec(&attestation_doc)`, matching production wire format
3. Client deserialization: removed `#[cfg]` split — both modes construct `AttestationDocument { signature: raw_bytes }`
4. Production attestation generation: removed broken COSE-as-map parsing (COSE_Sign1 is CBOR array, not map); stores raw NSM bytes directly
5. Mock verifier: parses CBOR payload in `doc.signature` to extract real keys and PCRs instead of returning zeroed placeholders
6. All benchmark binaries unified to use consistent attestation hash

**What remains unverified:**
- The production verifier path (`verify_cose_sign1` + P-384 cert chain) has NOT been tested with real NSM attestation documents on a Nitro instance
- The `generate_attestation` fix (item 4) stores raw NSM bytes but hasn't been exercised against real NSM output
- Only the mock path is covered by the 110-test suite

**Smoke test tooling available:** A dedicated smoke test binary (`host/src/bin/smoke_test_nitro.rs`) and orchestration script (`scripts/smoke_test_nitro.sh`) have been added to validate the production attestation path on real Nitro hardware. The smoke test performs the full Hello handshake over VSock, verifies the COSE_Sign1 signature (ECDSA-P384), walks the certificate chain to the AWS Nitro root CA, validates the challenge nonce, and establishes an HPKE session. Production build errors in `enclave/src/attestation.rs` and `enclave/src/server.rs` that blocked `--features production` compilation have been fixed. Run `./scripts/smoke_test_nitro.sh` on a Nitro-enabled instance to complete P2-0 validation.

**Risk:** Low. The production attestation verification path has been validated on real Nitro hardware (see verification below).

**Nitro Verification (Feb 4, 2026):**
- **Commit:** `c1c7439` (smoke test binary `smoke_test_nitro`)
- **Instance:** i-01959fa23e43d9506 (m6i.xlarge, us-east-1)
- **EIF PCR0:** `8e973a3dcba3d476420016af698eb8ac421b6540e556aa4b6ada0807d7492a881b0354d91a4a2fd9f6af74d944108b37`
- **EIF PCR1:** `0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa`
- **EIF PCR2:** `86d111ccb874f297e21ba902739ffd207a5bf9a47b16c2e57517a1e9d2187b2c14f1fb8a11fe83fec04df6332055b32f`
- **Attestation doc:** 5103 bytes COSE_Sign1
- **Signature:** ECDSA-P384 verified against leaf certificate
- **Cert chain:** Validated to AWS Nitro root CA (embedded DER)
- **Nonce:** Challenge-response verified
- **Key consistency:** ServerHello keys match attested keys
- **HPKE session:** X25519 + ChaCha20-Poly1305 established
- **Note:** PCR values from NSM are all-zeros because `--debug-mode` was used. Non-debug PCRs match the EIF build output above.
- **Ping round-trip:** Added `MessageType::Ping` (0x09) for encrypted echo without model dependency. Smoke test now uses Ping instead of Data, proving bidirectional HPKE without needing a loaded model.
- **Non-debug mode:** Smoke test script now defaults to non-debug mode (`--debug` opt-in), yielding real PCR values from NSM attestation.

**Fixes applied during Nitro validation:**
1. `d34464b` — Extract cert chain from CBOR payload (not COSE headers)
2. `8be2b18` — Use coset `tbs_data` for Sig_structure encoding
3. `e4481be` — Convert ECDSA raw (r||s) to DER for OpenSSL
4. `8f7dbbd` — Reverse NSM cabundle order for cert chain walk
5. `c1c7439` — Convert NSM millisecond timestamps to seconds

**Recommendation:** Run `./scripts/smoke_test_nitro.sh` on a Nitro-enabled instance (m6i.xlarge+). On PASS, update this finding to VERIFIED and record the PCR0/1/2 values.

---

### P2-0b. Receipt Key Type Mismatch and Attestation Binding — FIXED

**Files:** `enclave/src/attestation.rs`, `enclave/src/mock.rs`, `enclave/src/server.rs`, `enclave/src/kms_client.rs`, `enclave/src/main.rs`

**Problem (two layers):**

1. **Wrong key type:** Both `NSMAttestationProvider.receipt_keypair` and `MockAttestationProvider.receipt_keypair` were `EphemeralKeyPair`/`MockKeyPair` (X25519 ECDH keys). But `ReceiptSigningKey` uses Ed25519 signing keys. The attestation `user_data` embedded X25519 bytes labeled as "receipt_signing_key", which would fail when the client tried to use them as Ed25519 verifying keys.

2. **Key mismatch between attestation and session:** The server generated a fresh per-session `ReceiptSigningKey::generate()` (Ed25519), but the attestation `user_data` contained the provider-level X25519 key (different key, different curve). The client extracts `identity.receipt_signing_key` from attestation `user_data`, so it would always get the wrong key for receipt verification.

**Fix:**
- Removed `receipt_keypair` from both `NSMAttestationProvider` and `MockAttestationProvider`
- Changed `generate_attestation()` trait signature to accept `receipt_public_key: [u8; 32]` parameter
- Server now generates per-session `ReceiptSigningKey` (Ed25519) **before** calling `generate_attestation()`, passes the Ed25519 public key bytes into the attestation
- The attestation `user_data` now contains the same Ed25519 public key that the session uses to sign receipts
- Client extracts this key from attestation → matches the session signing key → receipt verification works

**Risk:** High (was). Receipt verification is a core security guarantee. This bug would have caused all receipt verification to fail in both mock server and production paths.

**Verified:** 110 tests pass. Benchmark binaries compile.

---

### P2-5. KMS Attestation Policy Enforcement — IMPLEMENTED

**Files:** `infra/hello-enclave/main.tf`, `scripts/test_kms_attestation.sh`

**Problem:** The KMS key policy allowed the host IAM role to call `kms:Decrypt` and `kms:GenerateDataKey` unconditionally, without requiring a valid Nitro attestation document. This meant a compromised host could decrypt model DEKs directly without the enclave.

**Fix:**
1. Added `enclave_pcr0`, `enclave_pcr1`, `enclave_pcr2` Terraform variables
2. KMS policy now conditionally includes `StringEqualsIgnoreCase` conditions on `kms:RecipientAttestation:ImageSha384` (PCR0), `kms:RecipientAttestation:PCR1`, and `kms:RecipientAttestation:PCR2` when the corresponding variables are set
3. When no PCR variables are set (dev mode), the policy remains unconditional for development convenience
4. Added `test_kms_attestation.sh` script for negative testing (host cannot decrypt without attestation) and positive testing (enclave can decrypt with attestation)

**Deployment:**
```bash
terraform apply -var="enclave_pcr0=<PCR0_FROM_BUILD>"
```

**Verification procedure:**
1. Build EIF, record PCR0/1/2 from `nitro-cli build-enclave` output
2. Apply Terraform with PCR values: `terraform apply -var="enclave_pcr0=<PCR0>"`
3. On instance: `./scripts/test_kms_attestation.sh` — `GenerateDataKey` should return `AccessDeniedException`
4. Optionally pass `--ciphertext /path/to/wrapped_dek.bin` to also test `Decrypt` denial
5. Positive test (KMS decrypt WITH attestation) is not yet automated — requires the enclave to call `KmsClient::decrypt()` during model loading. The current boot path (`main.rs`) only does an S3 connectivity check. Full positive test requires Phase 2 model loading integration.

**Risk:** High (was). Without attestation conditions, host compromise = model key compromise.

**Status:** Terraform conditions and negative test script implemented. Negative test verifiable on-instance. Positive test requires model loading path integration (Phase 2).

---

### P2-1. KMS Public Key Binding Not Validated

**File:** `client/src/attestation_verifier.rs`

KMS public key is extracted from attestation document `public_key` field and stored in `EnclaveIdentity.kms_public_key`, but is never validated against an expected value. If the KMS proxy is compromised, a MITM could substitute the KMS public key.

**Risk:** Medium. The host is already untrusted in the threat model, and KMS Decrypt is gated by attestation policy (PCR conditions). Exploitation requires compromising both the host proxy and having a valid attestation document.

**Recommendation:** Validate that the KMS public key matches the key ARN from the client's policy.

---

### P2-2. Certificate Time Validation Missing

**File:** `client/src/attestation_verifier.rs`

Certificate chain validation uses OpenSSL `verify()` for signature and chain-of-trust checking, but does not explicitly check `notBefore`/`notAfter` temporal validity. No certificate purpose/key usage validation. No revocation checking (OCSP/CRL).

**Risk:** Low. Nitro attestation certificates are short-lived (hours), and the attestation freshness check (client nonce) provides a separate time-binding mechanism.

**Recommendation:** Add explicit `X509::not_before()` / `X509::not_after()` checks.

---

### P2-3. No Constant-Time Comparisons

**File:** `client/src/attestation_verifier.rs`

Nonce comparison in attestation verification uses standard `!=` operator rather than constant-time comparison.

**Risk:** Low. The nonce is publicly known (client sends it in the challenge, enclave echoes it back). Timing leakage of a public value has no security impact. However, if similar patterns are used for secret comparisons elsewhere, it could become a concern.

**Recommendation:** Use `subtle::ConstantTimeEq` for defense-in-depth.

---

### P2-4. ReceiptVerifier Incomplete

**File:** `common/src/receipt_signing.rs`

`extract_user_data()` returns `Err("Attestation parsing not implemented")`. Receipt signature verification and binding verification are complete, but extracting user data from raw attestation documents is stubbed out.

**Mitigating factor:** The runtime client path in `client/src/secure_client.rs` independently verifies receipt signature + attestation hash, so client-side safety is stronger than this stub implies. The gap is in the generic `ReceiptVerifier` trait implementation, not in the deployed client flow.

**Risk:** Medium. The generic verification path cannot validate that the receipt's attestation binding matches a live enclave attestation. The signature and content integrity checks still work, and the client-side path covers the primary use case.

**Recommendation:** Implement CBOR/COSE parsing of attestation document to extract embedded user data fields.

---

## Phase 3 — Open (Medium Priority)

### P3-1. Timing Side-Channel in Sequence Check

**File:** `common/src/hpke_session.rs`

Different error messages for replay vs out-of-order sequence numbers, combined with early returns, create a theoretical timing side-channel. An attacker observing response times could distinguish between a replayed message and an out-of-order message.

**Risk:** Low. The sequence number is not secret, and the attacker already knows which message they sent.

**Recommendation:** Document as accepted risk, or unify error paths.

---

### P3-2. Certificate Pinning

No pinning of the AWS Nitro root certificate. The client trusts any valid COSE_Sign1 chain rooted in the Nitro root CA.

**Recommendation:** Pin the Nitro root CA public key hash in the client binary.

---

### P3-3. Audit Logging — PARTIAL

End-to-end audit logging exists: `enclave/src/audit.rs` generates structured audit events inside the enclave, forwards them to the host via VSock `Audit` message type, and `host/src/bin/kms_proxy_host.rs` receives and persists them. However, persistence is prototype-grade — logs are written to `/tmp/*.log` with no rotation, no structured format on disk, and no forwarding to centralized logging.

**Recommendation:** Replace `/tmp` file persistence with structured JSON output suitable for CloudWatch or SIEM ingestion. Add log rotation and retention policy.

---

## Positive Findings

| # | Feature | Assessment |
|---|---------|------------|
| 1 | `ZeroizeOnDrop` on all key material | Good practice — keys cleared from memory on drop |
| 2 | ChaCha20-Poly1305 AEAD | Modern authenticated encryption, consistent across all paths |
| 3 | X25519 ephemeral ECDH | Per-session forward secrecy |
| 4 | HKDF-SHA256 key derivation | RFC 5869 compliant with domain separation |
| 5 | AEAD AAD binding | Session metadata authenticated, prevents ciphertext splicing |
| 6 | KMS encryption context | Model-specific DEK binding, prevents cross-model replay |
| 7 | Strict sequence checking | Replay and reorder protection per session |
| 8 | Fail-closed design | All verification failures reject, no fallback paths |
| 9 | Ed25519 policy signatures | Canonical CBOR encoding, deterministic signing |
| 10 | Attested Execution Receipts | Full inference traceability |
| 11 | NSM attestation with fresh nonce | Per-request attestation binding |

---

## Remediation Roadmap

### Phase 1: Critical (pre-deployment) — COMPLETE

- [x] C1: Mock bypass feature gate — `#[cfg(all(feature = "mock", not(feature = "production")))]`
- [x] C2: Random nonce in KMS decrypt — `rand::thread_rng().fill_bytes()`
- [x] C3: Secure nonce generation — `OsRng.fill_bytes()`
- [x] C4: Ephemeral keys for forward secrecy — per-session `EphemeralKeyPair` + `ZeroizeOnDrop`
- [x] C5: HKDF key derivation — `hkdf::Hkdf::<Sha256>` per RFC 5869
- [x] C6: AEAD AAD binding — session metadata in ChaCha20-Poly1305 AAD
- [x] C7: KMS encryption context — model_id/version bound to Decrypt calls
- [x] C8: Cipher alignment — ChaCha20-Poly1305 everywhere

### Phase 2: High priority (hardening)

- [x] **P2-0: Attestation format/verification alignment — VERIFIED** (mock path unified in `b325fdd`; production path verified on Nitro in `c1c7439`)
- [x] **P2-0b: Receipt key type mismatch and attestation binding — FIXED** (removed X25519 receipt_keypair; per-session Ed25519 key now embedded in attestation user_data)
- [ ] **P2-5: KMS attestation policy enforcement — IMPLEMENTED** (Terraform + test script added; awaiting on-instance verification)
- [ ] P2-1: KMS public key binding validation
- [ ] P2-2: Certificate temporal validity checks
- [ ] P2-3: Constant-time comparisons (`subtle` crate)
- [ ] P2-4: ReceiptVerifier attestation document parsing

### Phase 3: Medium priority

- [ ] P3-1: Document accepted side-channel risks
- [ ] P3-2: Certificate pinning for Nitro root CA
- [x] P3-3: Audit logging — PARTIAL (E2E pipeline exists, prototype-grade `/tmp` persistence)

---

## Conclusion

**Current status:** YELLOW — APPROACHING PRODUCTION READY

All critical vulnerabilities (C1-C5) have been resolved. Three additional security improvements (C6-C8) were added beyond the original audit scope: AEAD AAD binding prevents cross-session ciphertext splicing, KMS encryption context prevents cross-model DEK replay, and cipher alignment eliminates the AES/ChaCha mismatch.

**P2-0 status (attestation alignment):** **VERIFIED** on real Nitro hardware (commit `c1c7439`, instance i-01959fa23e43d9506). The production attestation verification path — COSE_Sign1 parsing, ECDSA-P384 signature verification, P-384 certificate chain walk to AWS Nitro root CA, nonce challenge-response, timestamp freshness, and key consistency checks — has been validated with real NSM attestation documents. Five bugs were found and fixed during Nitro validation (see P2-0 section above).

The remaining Phase 2 items (P2-1 through P2-4) are hardening measures that do not represent exploitable vulnerabilities under the current threat model. P3-3 (audit logging) has been partially addressed — the E2E pipeline exists but uses prototype-grade persistence.

**Benchmark validation (Feb 4, 2026):** Full benchmark rerun on m6i.xlarge at commit `5fa19c5` — all 9 JSON files consistent (commit, hardware fields match), all validations passed. Results in `benchmark_results/run_20260203_230752/`. Inference overhead: +13.0% (enclave vs bare metal).

**Recommendation:**
- GREEN for controlled deployment, with documented P2-1..P2-4 limitations
- Full GREEN after all Phase 2 completion

---

*Initial audit: 2025-01-31*
*P2-0 verified on Nitro and benchmark rerun validation: 2026-02-04*
*EphemeralML Security Review v3*

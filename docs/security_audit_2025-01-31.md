# EphemeralML Security Audit

**Initial audit:** 2025-01-31
**Last verified:** 2026-02-03
**Auditors:** 3 specialized sub-agents (cryptographer, attestation expert, security architect)

---

## Summary

| Component | Rating | Status |
|-----------|--------|--------|
| **Cryptography** | GREEN | All critical findings resolved, HKDF + ephemeral keys + AAD binding |
| **Attestation & KMS** | YELLOW | Attestation format/verification mismatch blocks production; cert time validation and ReceiptVerifier incomplete |
| **Architecture** | GREEN | Solid three-zone model, fail-closed design, ZeroizeOnDrop throughout |
| **OVERALL** | YELLOW | P2-0 attestation mismatch blocks production; remaining Phase 2 items are hardening |

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

### P2-0. Attestation Format/Verification Mismatch — PRODUCTION BLOCKER

**Files:** `enclave/src/attestation.rs`, `client/src/attestation_verifier.rs`

The enclave generates attestation documents in one format, but the client verifier expects a different structure. The mock path papers over this because it skips real COSE/CBOR parsing entirely. In a production deployment with real NSM attestation documents, the verification pipeline would fail or silently accept malformed documents.

**Risk:** High. This is the highest-priority production gap. The system cannot be considered production-ready until the attestation generation and verification paths are aligned on the same COSE_Sign1 + CBOR structure with real NSM document parsing.

**Recommendation:** Align attestation document format between enclave generation and client verification. Test with real NSM attestation documents on a Nitro instance to confirm the full pipeline works end-to-end.

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

- [ ] **P2-0: Attestation format/verification alignment — PRODUCTION BLOCKER**
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

**Current status:** YELLOW — NOT PRODUCTION READY (one blocker remains)

All critical vulnerabilities (C1-C5) have been resolved. Three additional security improvements (C6-C8) were added beyond the original audit scope: AEAD AAD binding prevents cross-session ciphertext splicing, KMS encryption context prevents cross-model DEK replay, and cipher alignment eliminates the AES/ChaCha mismatch.

**Production blocker:** The attestation format/verification mismatch (P2-0) must be resolved before production deployment. The enclave attestation generation and client verification paths are not aligned on the same COSE_Sign1 + CBOR structure when using real NSM documents. The mock path masks this gap.

The remaining Phase 2 items (P2-1 through P2-4) are hardening measures that do not represent exploitable vulnerabilities under the current threat model. P3-3 (audit logging) has been partially addressed — the E2E pipeline exists but uses prototype-grade persistence.

**Recommendation:**
- YELLOW until P2-0 (attestation alignment) is resolved
- GREEN for controlled deployment after P2-0 fix, with documented P2-1..P2-4 limitations
- Full GREEN after all Phase 2 completion

---

*Initial audit: 2025-01-31*
*Verification and update: 2026-02-03*
*EphemeralML Security Review v2*

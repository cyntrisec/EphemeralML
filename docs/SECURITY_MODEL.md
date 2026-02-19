# EphemeralML Security Model

## Trust Model

### What We Trust

| Component | Trust Basis |
|-----------|-------------|
| Intel TDX hardware | Physical security of the CPU, correct implementation of memory encryption and attestation |
| Google Confidential Space image | dm-verity, measured boot, operator lockout — maintained by Google |
| Google Cloud Attestation | Issues OIDC tokens based on TDX quotes; trusted to verify hardware attestation correctly |
| Cloud KMS | Trusted to enforce key release policy (WIP binding) and not release keys to unauthorized workloads |
| Ed25519 cryptography | Trusted for receipt signing and manifest verification (standard, well-audited) |

### What We Reduce Trust In

| Component | Constraint |
|-----------|------------|
| Cloud operator | Cannot access workload memory (TDX), cannot modify the CS image (dm-verity), constrained by CS trust model |
| Host OS | TDX provides hardware memory encryption; the host OS cannot read CVM memory |
| Network | End-to-end encrypted channel (HPKE + ChaCha20-Poly1305) between client and enclave |
| Model supply chain | Manifest signature + SHA-256 hash pins the exact model loaded |

## Complete Evidence Chain

Starting in v0.2.8, the server returns all evidence artifacts needed for a complete
compliance bundle. The evidence chain is:

```
Receipt (signed, per-inference)
  ├── attestation_doc_hash → SHA-256 of boot attestation bytes
  ├── model_id / model_version → matches model manifest
  └── destroy_evidence → 5 cleanup actions documented
Boot Attestation (raw TDX quote, captured at boot)
  └── Binding: signing-key-attestation (receipt → attestation)
Model Manifest (JSON, from GCS/local)
  └── Binding: model-manifest-receipt (receipt → manifest)
```

The client receives all three artifacts:
- `receipt.json` — signed attestation receipt
- `ephemeralml-attestation.bin` — raw boot attestation bytes
- `ephemeralml-manifest.json` — model manifest JSON

The `compliance collect --strict` command verifies all evidence types are present
before building the bundle.

## Data Lifecycle

1. **Client sends request** over SecureChannel (HPKE key exchange + ChaCha20-Poly1305)
2. **Enclave processes** request in TDX-protected memory
3. **Inference runs** on the loaded model (pre-verified hash)
4. **Response + receipt + evidence sidecars** returned to client over the same encrypted channel
5. **Session keys** are zeroized after the connection closes
6. **CVM teardown** terminates the instance; TDX memory encryption keys are destroyed

### Data Destruction: Guaranteed vs Best-Effort

EphemeralML provides layered data destruction. Some guarantees are enforced by
hardware and cryptographic mechanisms; others are best-effort software measures.

#### Guaranteed (hardware/crypto-enforced)

| What | Mechanism | Evidence |
|------|-----------|----------|
| Session key destruction | `zeroize` crate (`ZeroizeOnDrop`) on `SymmetricKey`, `SealingContext`, `OpeningContext` | Source: `confidential-ml-transport/src/crypto/` |
| Receipt signing key destruction | `ZeroizeOnDrop` on `ReceiptSigningKey` | Source: `common/src/receipt_signing.rs` |
| Ephemeral HPKE key pair destruction | `ZeroizeOnDrop` on `EphemeralKeyPair` | Source: `enclave/src/attestation.rs` |
| CVM memory encryption key destruction | Intel TDX: VM termination destroys the hardware memory encryption key | Hardware guarantee — no software evidence possible |
| CVM non-restart | `tee-restart-policy=Never` in instance metadata; CS Launcher enforces | Verifiable via instance metadata |
| DEK zeroization | `Zeroizing<Vec<u8>>` wrapper on decrypted DEK bytes | Source: `enclave/src/model_loader.rs` |
| Inference buffer zeroization | `zeroize()` on request input, output tensor, and response buffers | Source: `enclave/src/server.rs` |

#### Best-effort (software, not independently verifiable)

| What | Limitation | Why |
|------|-----------|-----|
| Model weights in memory | Weights are loaded into `candle` tensor storage; no `zeroize` on candle's internal buffers | candle does not expose memory management hooks |
| GPU memory (H100 CC-mode) | NVIDIA CC-mode clears GPU memory on context destroy, but we cannot independently verify this | Depends on NVIDIA firmware correctness |
| Plaintext in transport buffers | `BytesMut`/`Bytes` from the `bytes` crate use ref-counted allocations that do not implement `Zeroize` | Transport-layer tensors use `Bytes`; wiped where ownership allows |
| OS page cache / swap | TDX encrypts memory, but the guest OS may page data to encrypted swap | No swap is configured in the CS image, but this is not enforced by EphemeralML |
| Cloud Logging | CS debug images write container stdout/stderr to Cloud Logging; production images do not | Use `confidential-space` (not `-debug`) image for production |
| GCS model artifacts | Encrypted model + wrapped DEK persist in GCS after inference | Caller must delete GCS objects if post-inference cleanup is required |
| Receipt persistence | Receipts are saved to the client filesystem and are not auto-deleted | Receipts are designed to persist — they are the audit trail |

#### What we do NOT claim

- **Cryptographic proof of data deletion**: Proving that data no longer exists anywhere is
  not possible with current technology. We provide *evidence of cleanup actions taken*
  (destroy evidence event in the receipt), not proof of data non-existence.
- **GPU memory scrubbing**: NVIDIA H100 CC-mode provides memory isolation and encryption,
  but EphemeralML cannot independently verify that GPU memory is scrubbed on release.
- **Compiler/allocator residuals**: The Rust allocator (`jemalloc` or system) may retain
  freed memory in thread-local caches. `zeroize` overwrites the buffer before free, but
  the allocator may still hold the freed page.

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Malicious cloud operator | TDX memory encryption, CS operator lockout, attestation-bound key release |
| Network attacker (MITM) | HPKE-based SecureChannel with attestation binding |
| Model supply chain attack | Manifest signature verification + SHA-256 hash pinning |
| Unauthorized model access | Cloud KMS key release gated on WIP attestation condition |
| Tampered workload | CS measured boot (dm-verity), attestation token reflects actual workload identity |

### Out of Scope

| Threat | Reason |
|--------|--------|
| Hardware backdoors | Assumes Intel CPU is correctly implemented |
| TDX side channels | Active research area; not mitigated by software |
| Denial of service | Cloud infrastructure availability is the provider's responsibility |
| Client-side security | Receipt verification is the client's responsibility |
| Key extraction from running CVM | TDX protects memory; we assume no firmware-level attacks |

## HIPAA Evidence Mapping

EphemeralML's proof bundle maps to HIPAA Security Rule controls:

| HIPAA Control | Section | EphemeralML Evidence |
|---------------|---------|---------------------|
| Access control | 164.312(a) | TDX enclave isolation proof — only the attested workload can access the model and data |
| Audit controls | 164.312(b) | The receipt itself — cryptographically signed record of what happened |
| Integrity | 164.312(c) | Model hash in manifest + attestation signature chain |
| Transmission security | 164.312(e) | HPKE + ChaCha20-Poly1305 AEAD encryption proof (SecureChannel) |

**Disclaimer**: EphemeralML provides *evidence support* for HIPAA compliance. It is NOT
HIPAA-certified. Organizations must conduct their own compliance assessment.

## Attestation Chain

```
Boot
 │
 ▼
MRTD / RTMR measurements (Intel TDX)
 │
 ▼
Confidential Space attestation token (OIDC JWT)
  - Issued by Google Cloud Attestation
  - Contains: image hash, eat_nonce, swname, swversion
 │
 ▼
Workload Identity Pool (WIP)
  - Validates attestation token claims
  - Maps to IAM service account
 │
 ▼
Cloud KMS
  - Key release gated on WIP identity
  - Returns decrypted DEK
 │
 ▼
Model decryption + hash verification
  - DEK decrypts model weights
  - SHA-256 verified against manifest + --expected-model-hash
 │
 ▼
Inference + Receipt
  - Receipt contains: model_hash, input_hash, output_hash, attestation_hash, ed25519_signature
```

## Receipt Anatomy

Each inference produces a signed receipt containing:

| Field | Description |
|-------|-------------|
| `model_hash` | SHA-256 of the loaded model weights |
| `request_hash` | SHA-256 of the input request |
| `response_hash` | SHA-256 of the inference output |
| `attestation_hash` | SHA-256 of the boot TDX quote (chains to hardware attestation) |
| `sequence_number` | Monotonically increasing counter (prevents replay) |
| `timestamp` | Unix timestamp of the inference |
| `signature` | Ed25519 signature over all above fields |
| `signing_key` | Public key for verification (embedded in attestation user_data) |

### Verification

```bash
cargo run -p ephemeral-ml-client --bin ephemeralml_verify -- receipt.json
```

The verifier checks:
1. Ed25519 signature is valid
2. Signing key matches the one in the attestation document
3. Sequence number is monotonically increasing
4. All hashes are present and well-formed

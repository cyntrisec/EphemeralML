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

## Data Lifecycle

1. **Client sends request** over SecureChannel (HPKE key exchange + ChaCha20-Poly1305)
2. **Enclave processes** request in TDX-protected memory
3. **Inference runs** on the loaded model (pre-verified hash)
4. **Response + receipt** returned to client over the same encrypted channel
5. **Session keys** are zeroized after the connection closes
6. **CVM teardown** terminates the instance; TDX memory encryption keys are destroyed

### Ephemeral Guarantees

- **Session TTL**: Each connection has a bounded lifetime
- **Key zeroization**: Session keys and DEK are zeroized (using the `zeroize` crate) after use
- **CVM termination**: `tee-restart-policy=Never` ensures the VM is not restarted after the workload exits

**Note**: We claim key/session zeroization and short-lived processing. We do NOT claim
cryptographic proof that data is irrecoverably gone — that would require proving negative
(data non-existence), which is not possible with current technology.

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

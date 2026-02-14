# Phase B: GCP Confidential Space — Direct Mode E2E with Receipt Verification

**Date:** 2026-02-14
**Instance:** ephemeralml-cvm (c3-standard-4, TDX, us-central1-a)
**CS Image:** confidential-space-debug-251200
**Container Image:** us-docker.pkg.dev/project-d3c20737-eec2-453d-8e5/ephemeralml/enclave:direct-fix3
**Mode:** --direct (TCP 9000, HPKE handshake, Ed25519 receipts)

## Results

| Check | Status | Detail |
|-------|--------|--------|
| CVM Boot | PASS | c3-standard-4 TDX, Confidential Space debug, RUNNING |
| Container Start | PASS | CS Launcher pulled and started container (251ms model load) |
| CS Launcher JWT | PASS | Token from `confidentialcomputing.googleapis.com`, `eat_nonce` parsed |
| Trust Evidence Bundle | PASS | Platform: tdx, model hash, HPKE key, receipt signing key emitted |
| Secure Channel | PASS | HPKE-X25519-ChaCha20Poly1305 handshake from external client |
| Inference | PASS | MiniLM-L6-v2 (384-dim embeddings), 71ms |
| Receipt Saved | PASS | JSON receipt written to disk with Ed25519 signature |
| Receipt Verified | PASS | `ephemeralml-verify` — signature PASS, measurements PASS |

## Overall: FULL PASS

All steps of the direct-mode E2E completed successfully, including receipt persistence and offline verification.

## Trust Evidence Bundle (from boot logs)

```
Platform:           tdx
Model ID:           stage-0
Quote Hash:         a8927a1295de5f7e31477b4f1949d374815d561fbe6e9a59c7a4e0632330ac48
HPKE Public Key:    249d781330aa1a209abc1fde5898fdcc
Receipt Sign Key:   310fe01e914189f2d7459b07db6232cd
Model Hash:         53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db
```

## Confidential Space Identity

```
issuer:   https://confidentialcomputing.googleapis.com
subject:  https://www.googleapis.com/compute/v1/projects/project-d3c20737-eec2-453d-8e5/zones/us-central1-a/instances/ephemeralml-cvm
swname:   CONFIDENTIAL_SPACE
eat_nonce: 310fe01e914189f2d7459b07db6232cd
```

## Receipt Verification

```
Receipt:   f54cf044-7371-4569-bd91-7c449f4ca0fc
Model:     stage-0 v1.0
Platform:  tdx-mrtd-rtmr
Sequence:  #0

Signature (Ed25519)       [PASS]
Measurements present      [PASS]
VERIFIED

Execution time:    71ms
Request hash:      1ce62d3c58b0fb827a671d88...
Response hash:     baac9798d5b94282d5a97ef2...
Public Key:        310fe01e914189f2d7459b07db6232cd6195d3fe7dfa644e9874df4daa94a874
```

## Evidence Files

| File | Content |
|------|---------|
| `receipt.json` | Signed inference receipt (Ed25519, JSON) |
| `receipt-signing-key.hex` | Server's Ed25519 public key (hex) |
| `verify-output.txt` | `ephemeralml-verify` output |
| `boot-logs.txt` | Full CVM journalctl output (1308 lines) |
| `instance-metadata.yaml` | GCE instance description |
| `RESULTS.md` | This file |

## Inference Output

```
384 floats returned (MiniLM-L6-v2 sentence embedding)
First 5: [0.3414222, 0.75955707, 0.071208954, 0.2389017, -0.15010944]
```

## Server Logs (direct mode)

```
[direct] Listening on 0.0.0.0:9000
[direct] Secure channel established with 77.137.64.85:34059
[direct] Ready for inference requests
[direct] Inference request: model_id=stage-0, input_len=384
[direct] Response sent: 384 floats, 71ms, seq=0
[direct] Channel closed: session closed
```

## What Changed (Fix)

The client's `execute_inference()` previously returned only `Vec<f32>`, discarding the validated receipt. Fixed to return `InferenceResult { output_tensor, receipt }` and save the receipt + public key to disk. The server was unchanged.

## Known Limitations

- **Measurements are placeholder** (0xAA/0xBB/0xCC): CS containers can't access configfs-tsm; real MRTD/RTMR requires CS-native quote retrieval
- **Attestation hash is [0; 32]**: Direct mode can't self-hash its own attestation; identity proven by receipt signature bound to CS JWT eat_nonce
- **Single connection**: Server exits after one client session (accept loop improvement pending)

## Build & Deployment Identifiers

| Item | Value |
|------|-------|
| **Git commit** | `4b1188a6f4aad2a6c314df86eac14b6ae9579633` |
| **Git tag** | `v1.0.0-85-g4b1188a` (85 commits past v1.0.0) |
| **Container image** | `us-docker.pkg.dev/project-d3c20737-eec2-453d-8e5/ephemeralml/enclave:direct-fix3` |
| **Container digest** | `sha256:2e2b1f1455e7465c7a1b8d92b60a0d09bc9ddbeab429c768f353415142dc85f0` |
| **Instance** | `ephemeralml-cvm` |
| **Zone** | `us-central1-a` |
| **Machine type** | `c3-standard-4` (Intel Sapphire Rapids) |
| **TEE type** | TDX |
| **CS image** | `confidential-space-debug-251200` |
| **Restart policy** | Never |
| **Instance terminated** | 2026-02-14 after evidence capture |

## Cost

- c3-standard-4: ~$0.21/hr x ~0.5hr = ~$0.10
- **Total: ~$0.10** (container image already built from Phase A)

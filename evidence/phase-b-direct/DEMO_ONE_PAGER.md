# EphemeralML: Confidential AI Inference with Cryptographic Receipts

## Architecture — Direct Mode on GCP Confidential Space

```
                          Internet (TLS + HPKE)
                                │
┌─────────────────┐             │            ┌──────────────────────────────────────────┐
│  Client Machine │             │            │  GCP c3-standard-4 (Intel TDX)           │
│                 │             │            │  Confidential Space debug image           │
│  ephemeral-ml   │─── TCP 9000 ───────────▶│  ┌──────────────────────────────────────┐ │
│   -client       │             │            │  │  CS Launcher (Google-maintained)      │ │
│                 │◀── receipt ──────────────│  │  dm-verity · operator lockout         │ │
│  ephemeralml    │             │            │  │  attestation JWT via Launcher socket  │ │
│   -verify       │             │            │  │  ┌──────────────────────────────────┐ │ │
│  ✓ VERIFIED     │             │            │  │  │  EphemeralML Container           │ │ │
└─────────────────┘             │            │  │  │  MiniLM-L6-v2 (86.7 MB)         │ │ │
                                │            │  │  │  HPKE-X25519-ChaCha20Poly1305    │ │ │
                                             │  │  │  Ed25519 receipt signing          │ │ │
                                             │  │  └──────────────────────────────────┘ │ │
                                             │  └──────────────────────────────────────┘ │
                                             └──────────────────────────────────────────┘
```

**Flow:** Client opens HPKE-encrypted channel to enclave container on a TDX-backed Confidential Space VM. Server runs inference, signs a receipt binding the model hash, input/output hashes, and TEE measurements, and returns it alongside the result. Client saves and verifies the receipt offline.

## Run Commands

```bash
# 1. Launch Confidential Space VM (one-time)
gcloud compute instances create ephemeralml-cvm \
  --zone=us-central1-a --machine-type=c3-standard-4 \
  --confidential-compute-type=TDX \
  --min-cpu-platform="Intel Sapphire Rapids" \
  --maintenance-policy=TERMINATE --shielded-secure-boot \
  --image-project=confidential-space-images \
  --image-family=confidential-space-debug \
  --metadata="tee-image-reference=us-docker.pkg.dev/PROJECT/ephemeralml/enclave:direct-fix3,tee-restart-policy=Never,tee-container-log-redirect=true"

# 2. Run client (from local machine)
EPHEMERALML_ENCLAVE_ADDR="<VM_IP>:9000" \
  cargo run --release --no-default-features --features gcp \
  -p ephemeral-ml-client --bin ephemeral-ml-client

# 3. Verify receipt offline
ephemeralml-verify /tmp/ephemeralml-receipt.json \
  --public-key $(cat /tmp/ephemeralml-receipt.json.pubkey) \
  --verbose
```

## Key Metrics

| Metric | Value |
|--------|-------|
| CVM boot (kernel + userspace) | 23.1s |
| Container start + model load | 1.3s (model: 251ms) |
| HPKE handshake | <1s |
| Inference (MiniLM-L6-v2, 384-dim) | 71ms |
| **Total cold-start to first result** | **~25s** |
| Receipt signature verification | <1ms |

## Verification Proof

```
  ==============================================================
  EphemeralML Receipt Verification
  ==============================================================

  Receipt:   f54cf044-7371-4569-bd91-7c449f4ca0fc
  Model:     stage-0 v1.0
  Platform:  tdx-mrtd-rtmr
  Sequence:  #0

  Signature (Ed25519)       [PASS]
  Measurements present      [PASS]

  VERIFIED
  ==============================================================
```

Receipt includes: model hash (`53aa5117...`), request/response SHA-256 hashes, TEE measurement type, Ed25519 signature, execution timestamp, and sequence number for replay detection.

## Limitation

Measurements are currently placeholder values — Confidential Space containers cannot access `configfs-tsm` directly, so real MRTD/RTMR values require the CS-native attestation path (Launcher JWT with WIP-gated key release through Cloud KMS).

## Next Milestone: Phase C — Full Attestation Flow

Integrate GCP Workload Identity Pool (WIP) key release so the receipt signing key is KMS-derived and bound to a real TDX quote. This closes the trust loop: the receipt's Ed25519 key is provably generated inside an attested TDX workload, verified by Google Cloud Attestation.

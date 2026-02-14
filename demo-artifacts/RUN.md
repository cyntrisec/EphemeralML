# EphemeralML Demo Recording

## Prerequisites

- GCP `c3-standard-4` TDX VM (or local mock mode)
- Rust toolchain installed
- Model files in `test_assets/minilm/`

## Local Mock Mode

```bash
# Terminal 1: Start server
cargo run --release --features mock --bin ephemeral-ml-enclave -- \
  --direct --model-dir test_assets/minilm --model-id stage-0

# Terminal 2: Infer
cargo run --release --features mock --bin ephemeralml -- infer \
  --addr 127.0.0.1:9000 \
  --file client/demo/radiology-report.txt

# Terminal 2: Verify
cargo run --release --features mock --bin ephemeralml -- verify \
  receipt.json --public-key-file receipt.json.pubkey
```

## GCP TDX Mode

```bash
# Terminal 1: Start server (on VM)
cargo run --release --no-default-features --features gcp --bin ephemeral-ml-enclave -- \
  --gcp --direct --model-source local \
  --model-dir test_assets/minilm --model-id stage-0 --synthetic

# Terminal 2: Infer (on VM)
cargo run --release --no-default-features --features gcp --bin ephemeralml -- infer \
  --addr 127.0.0.1:9000 \
  --file client/demo/radiology-report.txt

# Terminal 2: Verify
cargo run --release --no-default-features --features gcp --bin ephemeralml -- verify \
  receipt.json --public-key-file receipt.json.pubkey
```

## Demo Recording Sequence

### Scene 1: Connect + Infer (30s)

Run the `infer` command. Key output lines:
- Attestation: TDX verified (Confidential Space)
- Encryption: HPKE-X25519-ChaCha20Poly1305
- 384-dim embedding result
- Signature: VERIFIED (Ed25519)

### Scene 2: Verify Receipt (10s)

Run the `verify` command. Key output:
- Signature (Ed25519) [PASS]
- Timestamp freshness [PASS]
- Measurements present [PASS]
- VERIFIED

### Scene 3: Tamper -> Verify FAIL (15s)

```bash
# Tamper with the receipt
cp receipt.json receipt-tampered.json
sed -i 's/"model_id": "stage-0"/"model_id": "stage-TAMPERED"/' receipt-tampered.json

# Verify tampered receipt -> FAIL
cargo run --release --features mock --bin ephemeralml -- verify \
  receipt-tampered.json --public-key-file receipt.json.pubkey
```

Expected: `Signature (Ed25519) [FAIL]` and `INVALID`.

## Artifacts

| File | Description |
|------|-------------|
| `receipt-local.json` | Receipt from local mock inference |
| `receipt-local.json.pubkey` | Ed25519 public key (32 bytes) |
| `receipt-gcp.json` | Receipt from GCP TDX inference |
| `receipt-gcp.json.pubkey` | Ed25519 public key (GCP run) |
| `infer-output-gcp.txt` | Terminal output from GCP infer |
| `verify-output-gcp.txt` | Terminal output from GCP verify |
| `tamper-verify-output-gcp.txt` | Terminal output from tamper -> verify FAIL |

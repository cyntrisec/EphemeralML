# EphemeralML Build Matrix

## Deployment Modes

| Mode | Platform | Feature Flags | Network | KMS Path | Attestation |
|------|----------|---------------|---------|----------|-------------|
| **Mock** | Any (dev/CI) | `--features mock` | TCP localhost | KMS proxy (mock) | Mock COSE_Sign1 |
| **AWS Production** | Nitro Enclave | `--no-default-features --features production` | VSock (host ↔ enclave) | Enclave → VSock → Host Proxy → AWS KMS | NSM device → COSE_Sign1 |
| **GCP Production** | TDX CVM (c3-standard-4) | `--no-default-features --features gcp` | Direct TCP | Local, GCS, or GCS-KMS (`GcpKmsClient` → attestation-bound Cloud KMS) | configfs-tsm → TDX quote |
| **GCP GPU** | TDX CVM + H100 CC (a3-highgpu-1g) | `--no-default-features --features gcp,cuda` | Direct TCP | GCS (GGUF, ≤16GB) | CS Launcher attestation (TDX + `nvidia_gpu.cc_mode: ON`) |

**Mutually exclusive:** `mock`, `production`, and `gcp` cannot be combined (`compile_error!` in all crates).

## Binaries per Crate

### enclave (`ephemeral-ml-enclave`)

| Binary | Purpose | Mock | AWS Prod | GCP Prod |
|--------|---------|------|----------|----------|
| `ephemeral-ml-enclave` | Stage worker (main) | `--features mock` | `--features production` | `--features gcp` |
| `benchmark_baseline` | Inference latency | `--features mock` | `--features production` | `--features gcp` |
| `vsock_echo` | VSock debug tool | N/A | `--features production` | N/A |

### host (`ephemeral-ml-host`)

| Binary | Purpose | Mock | AWS Prod | GCP Prod |
|--------|---------|------|----------|----------|
| `ephemeral-ml-host` | Pipeline orchestrator | `--features mock` | `--features production` | N/A (no host needed) |
| `kms_proxy_host` | KMS proxy server | `--features mock` | `--features production` | N/A (direct KMS) |
| `spy_host` | Debug/monitoring | `--features mock` | `--features production` | N/A |

### client (`ephemeral-ml-client`)

| Binary | Purpose | Mock | AWS Prod | GCP Prod |
|--------|---------|------|----------|----------|
| `ephemeral-ml-client` | Inference client | `--features mock` | `--features production` | `--features gcp` |
| `commander` | Stage control CLI | `--features mock` | `--features production` | `--features gcp` |
| `verify_receipt` | Receipt verifier | `--features mock` | `--features production` | `--features gcp` |
| `benchmark_cose` | COSE benchmarks | `--features mock` | `--features mock` | N/A |
| `generate_compliance_report` | Compliance reports | `--features mock` | `--features mock` | N/A |

## Build Commands

### Development / CI (default)

```bash
cargo build --workspace                    # mock mode, all crates
cargo test --workspace                     # all mock-mode tests
cargo clippy --workspace -- -D warnings    # zero warnings
```

### GCP (real c3-standard-4 TDX CVM)

```bash
# Build enclave binary for GCP
cargo build --release --no-default-features --features gcp \
  -p ephemeral-ml-enclave

# Build client binary for GCP
cargo build --release --no-default-features --features gcp \
  -p ephemeral-ml-client

# Run on CVM (--gcp flag required to enter GCP code path)
./target/release/ephemeral-ml-enclave \
  --gcp --model-dir /app/model --model-id stage-0

# Verify GCP build compiles
cargo check --no-default-features --features gcp -p ephemeral-ml-enclave
cargo check --no-default-features --features gcp -p ephemeral-ml-client
```

### AWS Nitro (real enclave)

```bash
# Build enclave binary (production mode, local model path)
cargo build --release --no-default-features --features production \
  -p ephemeral-ml-enclave

# Build host orchestrator binary
cargo build --release --no-default-features --features production \
  -p ephemeral-ml-host

# Build EIF and launch (on EC2 with enclave support)
# Model files must be bundled in the Docker image at --model-dir path
nitro-cli build-enclave --docker-uri ... --output-file enclave.eif
nitro-cli run-enclave --eif-path enclave.eif --memory 3072 --cpu-count 2

# Run host orchestrator (connects to enclave via VSock)
./target/release/ephemeral-ml-host \
  --enclave-cid 16 \
  --text "Hello world"
```

## AWS Nitro Production Architecture

### Pipeline Mode (supported)

The host orchestrator connects to the enclave over VSock for single-stage pipeline inference:

```
Host (EC2 instance)                    Enclave (CID 16)
┌──────────────────────┐               ┌──────────────────────┐
│  ephemeral-ml-host   │  VSock 5000   │  ephemeral-ml-enclave│
│  (orchestrator)      │──────────────→│  control listener    │
│                      │  VSock 5001   │                      │
│                      │──────────────→│  data_in listener    │
│                      │  VSock 5002   │                      │
│  data_out listener   │←──────────────│  data_out connect    │
│                      │               │                      │
│  kms_proxy_host      │  VSock 8082   │  kms_proxy_client    │
│  (KMS/S3 proxy)      │←──────────────│  (model/key fetch)   │
└──────────────────────┘               └──────────────────────┘
```

- **Attestation model:** One-way. Enclave attests to host via NSM COSE_Sign1 (NitroProvider); host uses MockProvider because it is not inside a TEE. The host verifies the enclave's Nitro attestation (NitroVerifier with PCR pinning); the enclave accepts the host without attestation (MockVerifier). This is by design — the host runs on the same EC2 instance, not in a separate TEE.
- **Model loading:** Bundled in EIF Docker image via `--model-dir`. KMS/S3 model fetch is available but requires separate `kms_proxy_host`.
- **PCR pinning:** Set `EPHEMERALML_EXPECTED_PCR0/1/2` env vars on the host to pin enclave measurements.

### Direct Mode (not yet supported in production)

`--direct` mode is available in mock and GCP modes but not yet in Nitro production.
The production enclave rejects `--direct` with a clear error message.
A VSock-based direct server would be needed (tracked as future work).

### Known Limitations

- **KMS/S3 model loading:** Not yet integrated into the production pipeline path. Use `--model-dir` with model files bundled in the Docker image.
- **Multi-stage pipelines:** VSock infrastructure supports it, but only single-stage has been tested on real Nitro hardware.
- **tokio-vsock 0.7:** Workspace upgraded from 0.4 to 0.7 for pipeline compatibility.

## Feature Flag Compatibility

| Feature | Enclave | Host | Client | Common |
|---------|---------|------|--------|--------|
| `mock` | Default, mock attestation | Default, mock transport | Default, `MockVerifierBridge` | N/A |
| `production` | AWS Nitro deps (NSM, VSock) | VSock + NitroVerifier + MockProvider (one-way attestation: host is not in TEE) | `CoseVerifierBridge` | N/A |
| `gcp` | `tdx` + reqwest + base64, TDX attestation | N/A | `TdxEnvelopeVerifierBridge` | N/A |
| `tdx` | OpenSSL + TDX attestation | N/A | N/A | N/A |
| `cuda` | CUDA candle backends | N/A | N/A | N/A |
| `benchmark` | N/A | N/A | ML deps for benchmarks | N/A |

**Mutually exclusive:** `mock`, `production`, and `gcp` cannot be combined (`compile_error!` in all crates).

### Client Verifier Dispatch

The client uses a 3-way compile-time dispatch for attestation verification:

| Feature | Verifier | Attestation Format |
|---------|----------|--------------------|
| `mock` | `MockVerifierBridge` | Mock COSE_Sign1 |
| `gcp` | `TdxEnvelopeVerifierBridge` | TDX quote in CBOR envelope |
| `production` (default) | `CoseVerifierBridge` | Nitro NSM COSE_Sign1 |

The GCP verifier decodes a `TeeAttestationEnvelope` (CBOR: `{platform, tdx_wire, user_data}`) — verifies the inner TDX document and extracts the receipt signing key from `user_data`.

## Architecture Differences

| Aspect | AWS Nitro | GCP TDX CVM | GCP GPU (a3-highgpu-1g) |
|--------|-----------|-------------|-------------------------|
| Binaries needed | enclave + host + client | enclave + client | enclave + client (via Dockerfile.gpu) |
| Host process | Required (orchestrator + KMS proxy) | Not needed (direct access) | Not needed (direct access) |
| Network from enclave | None (VSock only) | Full (TCP, HTTPS) | Full (TCP, HTTPS) |
| Pipeline transport | VSock (host ↔ enclave) | TCP (0.0.0.0) | TCP (0.0.0.0) |
| KMS auth | NSM attestation → AWS KMS Recipient | `GcpKmsClient` (Attestation API → WIP/WIF → Cloud KMS) | Same as GCP TDX |
| Model loading | Local (--model-dir, bundled in EIF) | Local / GCS / GCS-KMS | GCS runtime fetch (GGUF, ≤16GB) |
| Model format | safetensors (BF16/F32) or GGUF | safetensors (BF16/F32) or GGUF | GGUF (Q4_K_M, Q8_0, etc.) |
| Compute | CPU only (2 vCPU) | CPU only (4 vCPU) | NVIDIA H100 CC-mode (CUDA 12.2) |
| Bind address | VSock (VMADDR_CID_ANY) | 0.0.0.0 (real network) | 0.0.0.0 (real network) |
| `--direct` mode | Not supported (pipeline only) | Supported | Supported |

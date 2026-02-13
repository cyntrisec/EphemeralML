# EphemeralML Build Matrix

## Deployment Modes

| Mode | Platform | Feature Flags | Network | KMS Path | Attestation |
|------|----------|---------------|---------|----------|-------------|
| **Mock** | Any (dev/CI) | `--features mock` | TCP localhost | KMS proxy (mock) | Mock COSE_Sign1 |
| **AWS Production** | Nitro Enclave | `--no-default-features --features production` | VSock (CID 3) | Enclave → VSock → Host Proxy → AWS KMS | NSM device → COSE_Sign1 |
| **GCP Production** | TDX CVM (c3-standard-4) | `--no-default-features --features gcp` | Direct TCP | Local files or GCS direct (KMS via `GcpKmsClient` not yet wired) | configfs-tsm → TDX quote |

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
| `ephemeral-ml-host` | Orchestrator | `--features mock` | `--features production` | N/A (no host needed) |
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
# Build enclave binary
cargo build --release --no-default-features --features production \
  -p ephemeral-ml-enclave

# Build host binary
cargo build --release --no-default-features --features production \
  -p ephemeral-ml-host

# Build EIF and launch (on EC2 with enclave support)
nitro-cli build-enclave --docker-uri ... --output-file enclave.eif
nitro-cli run-enclave --eif-path enclave.eif --memory 3072 --cpu-count 2
```

## Feature Flag Compatibility

| Feature | Enclave | Host | Client | Common |
|---------|---------|------|--------|--------|
| `mock` | Default, mock attestation | Default, mock transport | Default, `MockVerifierBridge` | N/A |
| `production` | AWS Nitro deps (NSM, VSock) | VSock deps | `CoseVerifierBridge` | N/A |
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

| Aspect | AWS Nitro | GCP TDX CVM |
|--------|-----------|-------------|
| Binaries needed | enclave + host + client | enclave + client |
| Host process | Required (KMS proxy, model relay) | Not needed (direct access) |
| Network from enclave | None (VSock only) | Full (TCP, HTTPS) |
| KMS auth | NSM attestation → AWS KMS Recipient | `GcpKmsClient` exists (Attestation API → WIF → Cloud KMS), not yet wired into runtime |
| Model loading | Host fetches S3 → VSock → enclave | Enclave fetches GCS directly |
| Bind address | 127.0.0.1 (VSock loopback) | 0.0.0.0 (real network) |

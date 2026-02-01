# CLAUDE.md - Project Intelligence for Claude Code

## Important: Attribution Policy

- Do NOT add "Co-Authored-By: Claude" or any Claude/Anthropic attribution to git commits.
- Do NOT add Claude as a contributor, co-author, or mention AI assistance in commit messages, PR descriptions, changelogs, or any project files.
- Commit messages should read as if written entirely by the human developer.

## Repository

- **Canonical repo**: `cyntrisec/EphemeralML` on GitHub (Cyntrisec organization)
- **Single remote**: `origin` → `https://github.com/cyntrisec/EphemeralML.git`
- **Main branch**: `main` (only branch)
- The old personal repo `tsyrulb/EphemeralML` is archived — do not push there.

## Project Overview

EphemeralML is a confidential AI inference system that runs ML models inside AWS Nitro Enclaves with end-to-end encryption. The host acts as a blind relay - it cannot decrypt or inspect sensitive data. v1.0 is complete (104/104 tasks, 91 tests passing, 13k+ LOC Rust).

Target sectors: Defense, GovCloud, Finance, Healthcare.

## Architecture

Three-zone security model:
- **Client Zone** (trusted): attestation verification, policy management, HPKE session negotiation
- **Host Zone** (untrusted relay): VSock/KMS/S3 proxy forwarding only encrypted bytes
- **Enclave Zone** (trusted TEE): NSM attestation, model decryption, Candle inference, AER generation

Key security layers: Nitro TEE isolation, COSE/CBOR attestation, HPKE (X25519 + ChaCha20-Poly1305) E2E encryption, attestation-gated KMS key release, Ed25519-signed model manifests, Attested Execution Receipts.

## Workspace Structure

```
Cargo workspace with 4 crates + 1 utility:
  common/    - Shared crypto, protocol, types (hpke_session, receipt_signing, vsock, validation, policy)
  client/    - Client library (secure_client, attestation_verifier, policy, model_validation, freshness)
  host/      - Host relay proxy (aws_proxy, kms_proxy, storage, circuit_breaker, metrics, otel)
  enclave/   - Nitro Enclave app (server, attestation, candle_engine, kms_client, model_loader, audit)
  enclaves/vsock-pingpong/ - VSock latency tool
```

Infrastructure: `infra/hello-enclave/` (Terraform), scripts in `scripts/`.

## Build & Test

```bash
# Local dev (mock mode - default)
cargo build
cargo test

# Production (Nitro Enclaves)
cargo build --release --features production --no-default-features

# EIF build
docker build -f enclave/Dockerfile.enclave -t ephemeral-ml-enclave .
nitro-cli build-enclave --docker-uri ephemeral-ml-enclave:latest --output-file enclave.eif
```

Feature flags: `mock` (default, local dev), `production` (real NSM + VSock), `cuda` (GPU via Candle).

## Key Conventions

- **Rust 2021 edition**, stable toolchain (no nightly), no unsafe except minimal FFI/libc
- **Feature-gated dual mode**: same codebase compiles for mock (local) or production (Nitro)
- **Error handling**: hierarchical typed errors (`EphemeralError`, `HostError`, `EnclaveError`), `?` propagation
- **Security**: `#[derive(ZeroizeOnDrop)]` on all key material, constant-time comparisons, input validation at boundaries
- **Naming**: `snake_case` functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` constants
- **Testing**: inline `#[cfg(test)]` for unit tests, `tests/` dirs for integration tests, descriptive test names
- **Dependencies**: all from crates.io, workspace-level pinning, minimal external deps
- **Commit style**: lowercase prefix (`chore:`, `fix:`, `feat:`, `docs:`), concise message

## Deployment

- AWS Nitro Enclaves on EC2 m6i.xlarge+ (us-east-1)
- Access via SSM Session Manager (no SSH)
- Terraform in `infra/hello-enclave/`
- Enclave: 2 CPUs, 4096MB RAM (1024MB insufficient for model loading via VSock)

## Common Pitfalls

- m6i.large and c6a family do NOT support Enclaves (need xlarge+)
- `nitro-cli console` requires `--debug-mode` flag
- Enclave needs 4096MB+ RAM for MiniLM-L6-v2 (VSock message decode buffers + model + inference)
- For larger models, quantize to int4/int8 GGUF format
- Cargo.lock IS committed (application, not library)
- `.tfstate` files are gitignored - never commit them

## Git Hygiene

- History was rewritten (Feb 2026) to remove large files and sensitive data:
  - Removed: `test_assets/minilm/model.safetensors` (87MB), `docs/aws-reference/` PDFs, `docs/investors/` PDFs
  - Scrubbed: real AWS account ID, EC2 instance ID, KMS key IDs (replaced with `REDACTED_*`)
- Do NOT commit: `.safetensors` files, `.tfstate`, `.env`, credentials, investor PDFs, AWS reference docs
- Do NOT commit large binary files — use `.gitignore` or Git LFS
- Clean up merged branches after PRs are merged — do not leave stale branches
- Test model artifacts are generated locally via `scripts/prepare_benchmark_model.sh`, not stored in git

## Benchmarking

### Running Benchmarks

The benchmark compares inference on bare-metal EC2 vs inside a Nitro Enclave using MiniLM-L6-v2 (22.7M params).

```bash
# Full suite on a Nitro-enabled instance:
./scripts/run_benchmark.sh

# Or remotely via SSM:
aws ssm send-command --instance-ids i-XXXX \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["bash /path/to/ssm_benchmark.sh"]'
```

### AWS Prerequisites (before starting instance)

1. **Terraform applied**: `cd infra/hello-enclave && terraform apply`
   - Creates KMS key with alias `alias/ephemeral-ml-test`
   - Creates IAM role with S3 + KMS permissions
   - Creates EC2 instance with Nitro Enclaves enabled
2. **S3 bucket**: `ephemeral-ml-models-demo` must exist with model artifacts:
   ```bash
   ./scripts/prepare_benchmark_model.sh --upload
   ```
3. **Instance type**: m6i.xlarge or larger (c6a does NOT support Enclaves)
4. **Docker + nitro-cli**: Must be installed on the instance

### Benchmark Architecture

- **Baseline**: `enclave/src/bin/benchmark_baseline.rs` — runs on host, outputs JSON to stdout
- **Enclave**: `enclaves/vsock-pingpong` with `--mode benchmark` — runs inside Nitro Enclave, outputs JSON via `nitro-cli console`
- **Crypto**: `enclave/src/bin/benchmark_crypto.rs` — Tier 4 crypto primitives (HPKE, Ed25519, receipts), runs on host
- **E2E**: `client/src/bin/benchmark_e2e.rs` — full HPKE encrypt→decrypt→receipt→encrypt pipeline + TCP handshake, runs on host
- **COSE**: `client/src/bin/benchmark_cose.rs` — COSE_Sign1 verification + P-384 cert chain walk, runs on host
- **Concurrent**: `enclave/src/bin/benchmark_concurrent.rs` — N-thread (1/2/4/8) inference scaling, runs on host
- **Orchestration**: `scripts/run_benchmark.sh` — builds, runs, captures, compares
- **Report**: `scripts/benchmark_report.py` — generates markdown comparison (`--baseline`, `--enclave`, optional `--crypto`)
- **Model prep**: `scripts/prepare_benchmark_model.sh` — downloads MiniLM, encrypts, optionally uploads to S3
- DEK for benchmarking is hardcoded (`0123456789abcdef...`) in all three places (prep script, baseline, enclave). Keep in sync.

### What's Measured

- Inference latency: p50/p95/p99 over 100 iterations (3 warmup)
- Cold start breakdown: attestation, KMS key release, S3 fetch, decrypt, model load
- VSock RTT: 64B, 1KB, 64KB, 1MB payload sizes (upload direction)
- Memory: peak RSS from /proc/self/status
- Throughput: inferences/sec derived from mean latency
- Crypto primitives: HPKE session setup, encrypt/decrypt (64B–1MB), Ed25519 keygen, receipt sign/verify

### Benchmark Results (Feb 2026, m6i.xlarge)

Raw results in `benchmark_results/`. The v3 results are the definitive run (v1/v2 had VSock measurement issues).

| Metric | Bare Metal | Enclave | Overhead |
|--------|-----------|---------|----------|
| Inference Mean | 81.32ms | 93.08ms | +14.5% |
| Inference P95 | 83.12ms | 94.95ms | +14.2% |
| Throughput | 12.3 inf/s | 10.7 inf/s | -12.7% |
| Cold Start | 211ms | 7,132ms | Dominated by S3→VSock fetch |
| Peak RSS | 535 MB | 1,064 MB | +99% |
| Attestation | N/A | 277ms | One-time per session |
| KMS Key Release | N/A | 79ms | One-time per session |
| Tokenizer Setup | 19ms | 25ms | +34% |

**VSock RTT (v3, using Audit messages):**
| Payload | RTT |
|---------|-----|
| 64B | 0.17ms |
| 1KB | 0.14ms |
| 64KB | 0.41ms |
| 1MB | 4.56ms |
| Upload throughput | 219.4 MB/s |

**Output Quality:** Cosine similarity = 1.000000 (embeddings are bit-identical between bare-metal and enclave).

**E2E Encrypted Request (bare metal m6i.xlarge):**
| Component | Mean |
|-----------|------|
| Per-request crypto | 0.162ms |
| Session setup | 0.137ms |
| TCP handshake | 0.176ms |

**Concurrency Scaling (bare metal m6i.xlarge, 50 iter/thread):**
| Threads | Throughput | Mean Latency | Efficiency |
|---------|-----------|-------------|-----------|
| 1 | 12.43 inf/s | 80.4ms | 100% |
| 2 | 14.32 inf/s | 139.7ms | 57.6% |
| 4 | 14.23 inf/s | 277.0ms | 28.6% |
| 8 | 14.20 inf/s | 558.7ms | 14.3% |

**Cost Analysis (m6i.xlarge @ $0.192/hr):**
| Metric | Bare Metal | Enclave |
|--------|-----------|---------|
| Cost/1M inferences | $4.34 | $4.97 |
| Cost multiplier | — | 1.15x |

**Crypto Primitives (Tier 4, bare metal m6i.xlarge):**
| Operation | Mean | P99 |
|-----------|------|-----|
| HPKE session setup (both sides) | 0.10ms | 0.13ms |
| X25519 keypair gen | 0.017ms | 0.025ms |
| HPKE encrypt 1KB | 0.003ms | 0.003ms |
| HPKE decrypt 1KB | 0.003ms | 0.003ms |
| HPKE encrypt 1MB | 0.92ms | 0.95ms |
| HPKE decrypt 1MB | 0.97ms | 1.00ms |
| Ed25519 keypair gen | 0.017ms | 0.019ms |
| Receipt sign (CBOR+Ed25519) | 0.022ms | 0.023ms |
| Receipt verify | 0.046ms | 0.054ms |
| **Per-inference crypto budget (1KB)** | **0.027ms** | — |

**COSE Attestation Verification (client-side, bare metal m6i.xlarge):**
| Operation | Mean | P99 |
|-----------|------|-----|
| COSE_Sign1 signature verify (ECDSA-P384) | 0.737ms | 0.762ms |
| Certificate chain walk (3 certs) | 2.224ms | 2.259ms |
| CBOR payload parse | 0.001ms | 0.002ms |
| **Full verification pipeline** | **2.998ms** | **3.038ms** |

Reproducibility (4 runs total, v1/v2 inference variance <1%):
- Baseline: mean 80.87ms / 81.0ms / 81.32ms
- Enclave: mean 92.81ms / 93.58ms / 93.08ms
- Attestation varies: 219-356ms across runs (NSM timing variance is expected)

Key takeaways:
- **~14.5% inference overhead** — within "Acceptable" range per BENCHMARK_SPEC.md (10-15% matches AMD SEV-SNP BERT numbers)
- **Cold start dominated by model fetch** (6.6s over VSock from S3) — could be optimized with EIF-embedded weights or pre-warming
- **Attestation + KMS total: ~356ms** one-time cost, acceptable for session-based workloads
- **Memory ~2x** due to enclave kernel overhead and VSock message buffers
- Decrypt and model load times are comparable (no significant overhead)
- **Embedding quality preserved perfectly** — no numerical divergence from TEE execution
- **Results are highly reproducible** — inference variance <1% across runs

### Known Limitations & Future Work

- Enclave `hardware` field shows "unknown" (IMDS not accessible from inside enclave)
- `commit` shows "unknown" (Docker build arg not propagated into Rust binary at compile time)
- **Missing Tier 2 metrics**: Instance type comparison (c6i.xlarge, c6i.2xlarge)
- **Missing Tier 3 metrics**: Full embedding cosine similarity (all 384 dims), output determinism across sessions
- **Missing Tier 5 metrics**: Max concurrent sessions, throughput at saturation, memory under load

## EC2 Instance Setup & Troubleshooting

### Initial Instance Configuration

The Terraform-provisioned AMI (Amazon Linux 2023) does NOT come with git, Rust, or C compilers pre-installed. After `terraform apply`, the instance requires manual setup:

```bash
# Connect via SSM (no SSH)
aws ssm start-session --target i-XXXX

# Install prerequisites
export HOME=/root
yum install -y git
yum groupinstall -y "Development Tools"
yum install -y gcc openssl-devel pkg-config perl-IPC-Cmd

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

# Clone repo and prepare
cd /tmp
git clone https://github.com/cyntrisec/EphemeralML.git ephemeral-ml-bench-src
cd ephemeral-ml-bench-src
./scripts/prepare_benchmark_model.sh  # generates test_artifacts/
```

### Services That Must Be Running

```bash
systemctl start docker && systemctl enable docker
systemctl start nitro-enclaves-allocator && systemctl enable nitro-enclaves-allocator
```

### Nitro Enclave Memory Configuration

Edit `/etc/nitro_enclaves/allocator.yaml`:
```yaml
---
cpu_count: 2
memory_mib: 4096   # Default is 1024, too small for MiniLM benchmark
```
Then `systemctl restart nitro-enclaves-allocator`.

The instance has 16GB RAM (m6i.xlarge). With 4096MB for enclaves, the host retains ~12GB.

### Common Errors & Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `failed to find a workspace root` in Docker build | Dockerfile missing root `Cargo.toml` | COPY root Cargo.toml and strip unused workspace members with sed |
| `failed to find tool "c++"` in Docker build | `esaxx-rs` (tokenizers dep) needs C++ compiler | Add `g++ perl make` to Alpine packages: `apk add --no-cache musl-dev g++ perl make` |
| `COPY --from=build` path wrong | Workspace builds put artifacts in workspace root `target/`, not member's `target/` | Use `/app/target/x86_64-unknown-linux-musl/release/vsock-pingpong` |
| `E44 Enclave console connection failure` | Enclave not started with debug mode | Add `--debug-mode` to `nitro-cli run-enclave` |
| `memory allocation of 324MB bytes failed` | Enclave has insufficient RAM for VSock message buffers | Increase enclave memory to 4096MB in allocator.yaml |
| `UnexpectedEof` in VSock RTT measurement | Proxy closes connection on large/malformed model_id | RTT payloads capped at 64KB; errors handled gracefully |
| `$HOME not set` in SSM commands | SSM shell doesn't source profiles | Always `export HOME=/root` at start of SSM scripts |
| `bash: git: command not found` | AL2023 AMI has no git | `yum install -y git` |
| Docker not running | Docker installed but not started | `systemctl start docker` |

### Docker Build Notes

The `enclaves/vsock-pingpong/Dockerfile`:
- Uses `rust:alpine` base (musl static linking for minimal enclave image)
- Copies workspace root `Cargo.toml` and strips unused members (client, host, enclave) via sed
- Needs `g++ perl make` for tokenizers/esaxx-rs C++ compilation
- Final binary at `/app/target/x86_64-unknown-linux-musl/release/vsock-pingpong` (workspace root target dir)
- Final image is busybox:1.36 (~2MB) + static binary (~9MB)
- Build arg `MODE=benchmark` sets `VSOCK_PINGPONG_MODE` env var

### SSM Command Patterns

For long-running commands, use base64-encoded scripts to avoid shell escaping issues:
```bash
SCRIPT_B64=$(base64 -w0 script.sh)
aws ssm send-command \
  --instance-ids i-XXXX \
  --document-name "AWS-RunShellScript" \
  --timeout-seconds 600 \
  --parameters "commands=[\"echo $SCRIPT_B64 | base64 -d > /tmp/script.sh\",\"bash /tmp/script.sh\"]"
```

Avoid inline Python with quotes/parens in SSM `--parameters` — SSM's JSON parsing mangles them.

### kms_proxy_host

- Binary: `host/src/bin/kms_proxy_host.rs`
- Build: `cargo build --release --bin kms_proxy_host --features production`
- Listens on VSock port 8082 (CID 3 = host)
- Handles: KmsProxy (attestation-gated key release), Storage (S3 model fetch), Audit (log forwarding)
- S3 bucket hardcoded: `ephemeral-ml-models-demo`
- Must be running before enclave starts (enclave connects to host CID 3, port 8082)

### Benchmark Run Sequence

1. Build baseline: `cargo build --release --bin benchmark_baseline`
2. Run baseline: `target/release/benchmark_baseline --model-dir test_artifacts --instance-type m6i.xlarge > baseline_results.json`
3. Build Docker: `docker build -f enclaves/vsock-pingpong/Dockerfile --build-arg MODE=benchmark -t vsock-pingpong-benchmark:latest .`
4. Build EIF: `nitro-cli build-enclave --docker-uri vsock-pingpong-benchmark:latest --output-file benchmark.eif`
5. Start proxy: `target/release/kms_proxy_host &`
6. Run enclave: `nitro-cli run-enclave --eif-path benchmark.eif --memory 4096 --cpu-count 2 --enclave-cid 16 --debug-mode`
7. Capture: `nitro-cli console --enclave-id $ID > console.log &`
8. Wait for `BENCHMARK_RESULTS_JSON_END` marker in console log
9. Extract JSON between `BENCHMARK_RESULTS_JSON_BEGIN` and `BENCHMARK_RESULTS_JSON_END` markers
10. Run crypto benchmark: `target/release/benchmark_crypto --instance-type m6i.xlarge > crypto_v1.json`
11. Run E2E benchmark: `target/release/benchmark_e2e --model-dir test_artifacts --instance-type m6i.xlarge > e2e_v1.json`
12. Run concurrency benchmark: `target/release/benchmark_concurrent --model-dir test_artifacts --instance-type m6i.xlarge > concurrent_v1.json`
13. Run COSE benchmark: `target/release/benchmark_cose --instance-type m6i.xlarge > cose_v1.json`
14. Generate report: `python3 scripts/benchmark_report.py --baseline baseline.json --enclave enclave.json --crypto crypto.json --output report.md`
15. Cleanup: terminate enclave, kill proxy

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

EphemeralML is a confidential AI inference system that runs ML models inside AWS Nitro Enclaves with end-to-end encryption. The host acts as a blind relay — it cannot decrypt or inspect sensitive data.

**Current status**: v1.0 crypto core and enclave runtime complete (110 tests, 13k+ LOC Rust, benchmarked at 14.5% overhead). Not yet user-deployable — see **Product Roadmap** below for the path from prototype to product.

Target sectors: Defense, GovCloud, Finance, Healthcare.

## Product Roadmap

### Where we are

v1.0 is a working prototype: the crypto protocol is solid (HPKE + AAD + attestation-gated KMS + execution receipts), the enclave runs inference, benchmarks are published, and CI is green. But an external user cannot deploy it with their own model without modifying source code and recompiling. The gap is operational tooling, not architecture.

**Important constraints to keep in mind:**
- The enclave only supports **BERT/embedding models** today. `CandleInferenceEngine` implements `register_model` for BERT (SafeTensors) and has `QuantizedLlama` scaffolding, but only BERT inference is wired end-to-end. LLM auto-regressive generation is not implemented.
- **Nitro Enclaves have no runtime configuration.** No env vars, no files, no network access. Everything inside the enclave must be baked into the EIF image at build time, or received from the host over VSock after boot. This means changing model config = rebuild EIF = new PCR0 = update KMS policy. This is intentional (attestation binds to the specific code+config), but it means there's no such thing as "runtime configuration" for the enclave.
- **Model weights are NOT in the EIF.** The enclave fetches encrypted weights from S3 via the host proxy at boot (`kms_proxy_client.fetch_model()`). Only the tokenizer JSON and config JSON are baked into the Dockerfile. This is correct — weights can be large (GBs) and shouldn't bloat the EIF.
- A working interactive client CLI already exists at `client/src/bin/commander.rs`. It handles HPKE session establishment, attestation verification, encrypted inference, and receipt verification.

### Current hardcoded values that block user deployment

| Value | Location | What it should be |
|-------|----------|-------------------|
| ~~S3 bucket `ephemeral-ml-models-demo`~~ | ~~`host/src/bin/kms_proxy_host.rs`~~ | ~~Env var `EPHEMERALML_S3_BUCKET`~~ **DONE** (`b325fdd`) |
| ~~VSock port 8082 (host proxy)~~ | ~~`host/src/bin/kms_proxy_host.rs`~~ | ~~Env var `EPHEMERALML_VSOCK_PORT`~~ **DONE** (`b325fdd`) |
| Test model ID `test-model-001` | `enclave/src/main.rs:98` | Baked into EIF via Dockerfile ARG |
| Test artifact hash `542c469d...` | `enclave/src/main.rs:93` | Baked into EIF or removed (boot check is optional) |
| Signing key `[0u8; 32]` | `enclave/src/main.rs:87` | Baked into EIF via Dockerfile ARG |
| Tokenizer paths `test_assets/minilm/` | `enclave/Dockerfile.enclave:19-20` | Dockerfile ARG for tokenizer dir |
| Test DEK `0123456789abcdef...` | All `scripts/*.py`, benchmark binaries | Generated via KMS per-model |
| Max sessions = 100 | `enclave/src/server.rs:36` | Compile-time constant or baked config |

### Phase 1: Runtime Configuration (make it deployable)

Goal: a user can `terraform apply` + build EIF with their tokenizer + upload their encrypted model + run inference, without editing Rust source.

1. ~~**Env-var configuration for host proxy**~~ — **DONE** (commit `b325fdd`). `kms_proxy_host.rs` reads `EPHEMERALML_S3_BUCKET` and `EPHEMERALML_VSOCK_PORT` from env, falling back to `ephemeral-ml-models-demo` and `8082` respectively. Startup log shows configured values.

2. **Boot config via VSock handshake** — the enclave cannot read env vars at runtime (Nitro Enclaves have no runtime environment injection; `nitro-cli run-enclave` does not support passing env vars or args). Instead, on boot the enclave should request a config message from the host over VSock (new `MessageType::BootConfig`). The host reads its own env vars or a config file and sends: model_id, S3 artifact key, manifest path, wrapped DEK path. This replaces the hardcoded `test-model-001` and SHA-256 hash in `main.rs`. Note: this config is not security-sensitive (the host is untrusted anyway) — the enclave verifies model integrity via the signed manifest and KMS-gated decryption.

3. **Parameterized enclave Dockerfile** — accept build args for tokenizer directory and config directory. Model weights are already fetched from S3 at runtime, so they don't go in the Dockerfile. The Dockerfile change is small: replace `COPY test_assets/minilm/` with `ARG TOKENIZER_DIR=test_assets/minilm` + `COPY ${TOKENIZER_DIR}/ /app/tokenizer/`. Changing the Dockerfile changes PCR0, which is correct — the attestation should bind to the specific tokenizer/config being used.

4. **Terraform outputs for host config** — `infra/modules/enclave_host/` already outputs S3 bucket name and KMS key ARN. Add a generated `host.env` file that the host binary sources at startup, so users don't have to manually wire Terraform outputs to env vars.

5. **PCR extraction script** — new `scripts/extract_pcrs.sh` that runs `nitro-cli build-enclave`, parses the JSON output, and:
   - Prints PCR0/1/2 values
   - Generates a KMS key policy JSON fragment with the correct PCR conditions
   - Optionally applies the policy via `aws kms put-key-policy`

   This is the most error-prone manual step today. The workflow is: build EIF → extract PCRs → update KMS policy → start enclave. If any step is wrong, KMS silently refuses to release the DEK and the enclave fails to load the model.

### Phase 2: Model Onboarding CLI (bring your own model)

Goal: `ephemeralml model upload --model ./my-model.safetensors --kms-key arn:aws:kms:...` just works.

6. **`ephemeralml` CLI binary** — new `cli/` crate in the workspace. Subcommands:
   - `ephemeralml model encrypt` — generate DEK via KMS `GenerateDataKey`, encrypt SafeTensors with ChaCha20-Poly1305, output `model.enc` + `model.dek.wrapped`
   - `ephemeralml model upload` — encrypt + upload to S3 + generate signed manifest
   - `ephemeralml model sign` — generate Ed25519-signed `ModelManifest` JSON (model_id, version, hash, key_id, signature)
   - `ephemeralml model verify` — verify a manifest signature locally
   - `ephemeralml deploy` — orchestrates Terraform apply + EIF build + PCR extraction + KMS policy update (stretch goal)

7. **Manifest-driven model loading** — enclave receives the manifest path from the host via the boot config handshake (Phase 1 item 2), fetches it from S3, verifies the signature, then uses it to fetch and decrypt the model. `ModelLoader.load_model()` already accepts `ModelManifest` — the gap is wiring the boot sequence to fetch the manifest dynamically instead of using test fixtures.

8. ~~**Fix cipher mismatch between encryption and decryption**~~ — **DONE** (commit `321c1f4`). `scripts/encrypt_model.py` now uses ChaCha20-Poly1305, matching `model_loader.rs` and `prepare_benchmark_model.sh`. Option (a) was implemented (standardize on ChaCha20-Poly1305 everywhere). The KMS `KeySpec='AES_256'` returns 32 random bytes, which is a valid ChaCha20 key.

### Phase 3: Client Access (make it accessible beyond Rust)

Goal: users who don't write Rust can call inference.

**Critical design constraint:** the threat model requires E2E encryption between client and enclave. The host is untrusted. An HTTP gateway running on the host CANNOT decrypt responses — that would break the blind relay model. There are two tiers:

- **Tier 1 (full E2E):** Client handles HPKE session establishment, attestation verification, encryption, decryption, and receipt verification locally. The host is a dumb byte relay. This preserves the threat model.
- **Tier 2 (gateway-terminated):** An HTTP gateway on the host handles HPKE on behalf of the client. The client trusts the host for transport security (HTTPS) but not for data-at-rest. Weaker security, but much simpler integration. Appropriate when the user operates the host themselves.

Both tiers should be supported, with Tier 1 as the default.

9. **HTTP transport bridge** (Tier 1) — a lightweight HTTP server on the host that bridges `POST /v1/session` and `POST /v1/inference` to VSock, passing encrypted bytes through without inspection. The client SDK handles all crypto locally. Endpoints carry opaque encrypted payloads, not plaintext JSON.

10. **Python SDK with local HPKE** (Tier 1) — `pip install ephemeralml`. Implements the full client protocol in Python: attestation verification (COSE_Sign1 + P-384 cert chain), HPKE session establishment (X25519 + ChaCha20-Poly1305), request encryption, response decryption, receipt verification. Talks to the HTTP bridge from item 9. This is substantial crypto work — consider wrapping the existing Rust `client/` crate via PyO3 instead of reimplementing.

11. **Gateway mode** (Tier 2, optional) — an HTTP gateway on the host that terminates HPKE and exposes a plaintext REST API. Useful for users who trust their own host. Must be explicitly opt-in, with clear documentation that it weakens the threat model. Endpoints:
   - `POST /v1/inference` — accepts plaintext JSON, encrypts, forwards, decrypts, returns plaintext
   - `GET /v1/attestation` — returns the enclave attestation document
   - `GET /v1/health` — enclave liveness check
   - `POST /v1/embeddings` (stretch) — OpenAI-compatible embedding API for drop-in replacement

### Phase 4: Production Hardening

12. **Reproducible EIF builds** — pin Dockerfile base images to digest (`rust:1.XX-alpine@sha256:...`), eliminate non-deterministic build steps. CI job that builds EIF and publishes PCR0/1/2 so users can verify independently.

13. **Transparency log for Attested Execution Receipts** — publish AERs to an append-only log (e.g., Sigstore Rekor or custom) for third-party auditability. Relevant for regulated sectors.

14. **Multi-model enclave** — load multiple models per enclave (manifest lists N models), route inference requests by model_id. Note: all models share the same attestation identity (same PCR0), so a multi-model enclave can access DEKs for all its configured models. This changes the isolation boundary from per-model to per-enclave.

15. **Request queuing and batching** — enclave currently processes one request at a time per session. Add a bounded queue and optional batching for throughput-sensitive workloads.

16. **LLM inference support** — extend `CandleInferenceEngine` beyond embedding models. `QuantizedLlama` is imported and `LoadedQuantizedLlamaModel` struct exists in `candle_engine.rs`, but inference dispatch (`run_inference`) only handles BERT. Needs: auto-regressive generation loop, streaming token output over VSock, KV-cache management within enclave memory constraints (4096MB default). Given that Schnabl et al. report 2.2x overhead for 8B-param models on Nitro, quantization (INT4/INT8) is likely required for LLMs.

### Implementation order

Phases 1–2 are prerequisites for any user deployment. Phase 3 widens the user base. Phase 4 is for production scale.

Within Phase 1, item 1 (S3 bucket env var) is done (`b325fdd`). Remaining priority: item 3 (Dockerfile ARGs) → item 5 (PCR script) → item 2 (boot config) → item 4 (Terraform env).

Within Phase 2, item 8 (cipher mismatch) is done. The remaining items (CLI binary, manifest-driven loading) are the next priorities.

Within Phase 3, the PyO3 wrapper approach for the Python SDK (wrapping the Rust `client/` crate) is strongly preferred over reimplementing HPKE + COSE + Ed25519 in Python. The Rust client already works end-to-end.

### What NOT to build yet

- **Multi-cloud** (Azure CVM, GCP Confidential VMs) — Nitro-specific for now, expand later
- **Web dashboard** — CLI-first, dashboard is a distraction
- **Model marketplace / registry** — users bring their own models, period
- **Billing / metering** — open-source, self-hosted; billing is a SaaS concern
- **Custom model architectures** — BERT embedding models only for now; LLM support is Phase 4

## Website

- **URL**: `https://ephemeralml.cyntrisec.com`
- **Hosting**: GitHub Pages from `main` branch, root `/` of `cyntrisec/EphemeralML`
- **Custom domain**: Verified under the `cyntrisec` GitHub org (DNS TXT record on Route 53)
- **CNAME file**: `CNAME` in repo root maps to `ephemeralml.cyntrisec.com`
- **Design**: Dark professional theme (Inter + JetBrains Mono, Vercel-inspired)
- The old `tsyrulb/EphemeralML` repo had Pages — now disabled and archived

## CI Pipeline

- **GitHub Actions** on push/PR to `main`: Format, Clippy, Test, Security Audit
- **Config**: `.github/workflows/ci.yml`
- **Security audit**: `rustsec/audit-check@v2.0.0` with `RUSTSEC-2023-0071` ignored (rsa Marvin Attack, no patch available)
- **Audit job permissions**: `checks: write`, `contents: read`
- All dependencies are stable releases (no RC/pre-release crates)

## Architecture

Three-zone security model:
- **Client Zone** (trusted): attestation verification, policy management, HPKE session negotiation
- **Host Zone** (untrusted relay): VSock/KMS/S3 proxy forwarding only encrypted bytes
- **Enclave Zone** (trusted TEE): NSM attestation, model decryption, Candle inference, AER generation

Key security layers: Nitro TEE isolation, COSE/CBOR attestation, HPKE (X25519 + ChaCha20-Poly1305) E2E encryption with AEAD AAD binding session metadata to ciphertext, attestation-gated KMS key release with per-model encryption context, Ed25519-signed model manifests, Attested Execution Receipts.

## Workspace Structure

```
Cargo workspace with 4 crates + 1 utility (+ planned additions):
  common/    - Shared crypto, protocol, types, metrics, inference helpers
               (hpke_session, receipt_signing, vsock, validation, policy, metrics, inference[feature-gated])
  client/    - Client library (secure_client, attestation_verifier, policy, model_validation, freshness)
  host/      - Host relay proxy (aws_proxy, kms_proxy, storage, circuit_breaker, metrics, otel)
  enclave/   - Nitro Enclave app (server, attestation, candle_engine, kms_client, model_loader, audit)
  enclaves/vsock-pingpong/ - VSock latency tool + enclave benchmark mode
  cli/       - [PLANNED] User-facing CLI (model encrypt/upload/sign, deploy orchestration)
  gateway/   - [PLANNED] HTTP transport bridge (encrypted byte relay) + optional gateway mode
```

Infrastructure: `infra/hello-enclave/` (Terraform), scripts in `scripts/`.

### Cipher Alignment

All encryption/decryption paths now use **ChaCha20-Poly1305**: `scripts/encrypt_model.py`, `scripts/prepare_benchmark_model.sh`, `enclave/src/model_loader.rs`, and benchmark binaries. The cipher mismatch (formerly AES-256-GCM in `encrypt_model.py`) was fixed in commit `321c1f4`.

### Attestation Hash Alignment

As of commit `b325fdd`, `attestation_hash = SHA-256(attestation.signature)` everywhere — server (`server.rs`, `mock.rs`), client (`attestation_verifier.rs`, `secure_client.rs`), and all benchmark binaries. Previously the server hashed `attestation.signature` while the client hashed individual struct fields (module_id, digest, timestamp, pcrs, certificate), causing a silent mismatch masked by the mock verifier bypass.

The mock attestation wire format was also unified: `ServerHello.attestation_document` now contains raw CBOR bytes (matching production), not JSON-serialized `AttestationDocument`. The mock verifier parses the CBOR to extract real HPKE/receipt keys instead of returning zeroed placeholders.

The production `generate_attestation` in `attestation.rs` no longer attempts to parse COSE_Sign1 as a CBOR map (it's a CBOR array); raw NSM bytes are stored directly. **Note:** the production client verifier (`verify_cose_signature`) has not been tested on real Nitro hardware — only the mock path is exercised by the test suite.

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
- **Dependencies**: all stable releases from crates.io, workspace-level pinning, no RC/pre-release crates
- **Commit style**: lowercase prefix (`chore:`, `fix:`, `feat:`, `docs:`), concise message

## Deployment

- AWS Nitro Enclaves on EC2 m6i.xlarge+ (us-east-1)
- Access via SSM Session Manager (no SSH)
- Terraform in `infra/hello-enclave/`
- Enclave: 2 CPUs, 4096MB RAM (1024MB insufficient for model loading via VSock)
- MSRV: Rust 1.75+ (set in `[workspace.package]`)

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
- **Input Scaling**: `enclave/src/bin/benchmark_input_scaling.rs` — latency vs token count (32/64/128/256), disables tokenizer padding, computes linear fit
- **True E2E**: `client/src/bin/benchmark_true_e2e.rs` — full crypto + real BERT inference pipeline (HPKE encrypt→decrypt→inference→receipt→encrypt), behind `benchmark` feature
- **Enclave Concurrency**: `client/src/bin/benchmark_enclave_concurrency.rs` — N=1/2/4 concurrent E2E sessions with independent HPKE channels, behind `benchmark` feature
- **Orchestration**: `scripts/run_benchmark.sh` — builds, runs, captures all benchmarks; uses `--debug-mode` for enclave console; IMDSv2 for instance type
- **Report**: `scripts/benchmark_report.py` — generates markdown comparison (`--baseline`, `--enclave`, `--crypto`, `--input-scaling`, `--true-e2e`, `--enclave-concurrency`, `--quality-determinism`)
- **Paper tables**: `scripts/generate_paper_tables.py` — generates 9 LaTeX tables from all benchmark JSON (`--baseline`, `--enclave`, `--crypto`, `--cose`, `--e2e`, `--concurrent`, `--input-scaling`, `--true-e2e`, `--enclave-concurrency`)
- **Quality determinism**: `scripts/analyze_quality_determinism.py` — compares embedding SHA-256 and cosine similarity across runs/environments
- **Reproducibility**: `scripts/run_benchmark_repro.sh` + `scripts/analyze_repro.py` — N runs with variance analysis (mean/stddev/CV%)
- **Model prep**: `scripts/prepare_benchmark_model.sh` — downloads MiniLM, encrypts, optionally uploads to S3
- **Shared helpers**: `common/src/metrics.rs` (peak RSS via VmHWM, SHA-256 embedding hash, percentile calculation), `common/src/inference.rs` (BERT inference + mean pooling, feature-gated)
- DEK for benchmarking is hardcoded (`0123456789abcdef...`) in all three places (prep script, baseline, enclave). Keep in sync.
- Client benchmark binaries require `--features benchmark` (adds candle, tokenizers, chacha20poly1305 deps).

### What's Measured

- Inference latency: p50/p95/p99 over 100 iterations (3 warmup)
- Cold start breakdown: attestation, KMS key release, S3 fetch, decrypt, model load
- VSock RTT: 64B, 1KB, 64KB, 1MB payload sizes (upload direction)
- Memory: peak RSS from /proc/self/status (VmHWM with fallback to VmRSS), peak virtual memory (VmPeak)
- Throughput: inferences/sec derived from mean latency
- Crypto primitives: HPKE session setup, encrypt/decrypt (64B–1MB), Ed25519 keygen, receipt sign/verify
- Input scaling: latency vs token count (32/64/128/256) with linear fit (ms/token)
- True E2E: crypto + inference combined (session setup, per-request E2E, inference-only, crypto overhead)
- Enclave concurrency: N=1/2/4 concurrent E2E sessions with throughput scaling efficiency
- Quality determinism: embedding SHA-256 comparison within and across environments, cosine similarity

### Benchmark Results (Feb 2026, m6i.xlarge)

Raw results in `benchmark_results/run_20260203_v2/`. Definitive run with VmHWM memory, full-embedding SHA-256, and all new benchmarks. Commit `3e7b676`.

| Metric | Bare Metal | Enclave | Overhead |
|--------|-----------|---------|----------|
| Inference Mean | 80.02ms | 89.49ms | +11.8% |
| Inference P95 | 81.45ms | 90.64ms | +11.3% |
| Throughput | 12.5 inf/s | 11.2 inf/s | -10.6% |
| Cold Start | 214ms | 7,490ms | Dominated by S3→VSock fetch |
| Peak RSS (VmHWM) | 266 MB | 1,018 MB | +283% |
| Attestation | N/A | 314ms | One-time per session |
| KMS Key Release | N/A | 96ms | One-time per session |
| Tokenizer Setup | 17ms | 25ms | +44% |

**VSock RTT (enclave, using Audit messages):**
| Payload | RTT |
|---------|-----|
| 64B | 0.19ms |
| 1KB | 0.19ms |
| 64KB | 0.44ms |
| 1MB | 4.69ms |
| Upload throughput | 213.4 MB/s |

**Output Quality:** Cosine similarity = 1.0000000000 (full 384-dim embedding comparison). SHA-256 differs across environments (expected f32 precision variance). Max abs diff = 5.8e-7. Verdict: near-identical.

**Input Scaling (bare metal, padding disabled):**
| Tokens | Mean | P95 |
|--------|------|-----|
| 32 | 22.14ms | 22.86ms |
| 63 | 39.13ms | 40.70ms |
| 128 | 86.94ms | 87.79ms |
| 256 | 235.45ms | 238.06ms |
| **Linear fit** | **-20.11ms + 0.969ms/token** | |

**True E2E (crypto + real inference, bare metal):**
| Component | Mean | P95 |
|-----------|------|-----|
| Session setup | 0.143ms | 0.150ms |
| Per-request E2E | 80.54ms | 82.43ms |
| Inference only | 80.23ms | 82.12ms |
| **Crypto overhead** | **0.307ms** (0.38% of E2E) | |

**E2E Encrypted Request (bare metal, crypto-only):**
| Component | Mean |
|-----------|------|
| Per-request crypto | 0.164ms |
| Session setup | 0.138ms |
| TCP handshake | 0.174ms |

**Concurrency Scaling (bare metal, 50 iter/thread):**
| Threads | Throughput | Mean Latency | Efficiency |
|---------|-----------|-------------|-----------|
| 1 | 12.45 inf/s | 80.3ms | 100% |
| 2 | 14.36 inf/s | 139.3ms | 57.7% |
| 4 | 14.31 inf/s | 277.9ms | 28.7% |
| 8 | 14.22 inf/s | 557.5ms | 14.3% |

**Enclave Concurrency (E2E crypto + inference, bare metal):**
| Clients | Throughput | Mean Latency | Efficiency |
|---------|-----------|-------------|-----------|
| 1 | 12.36 inf/s | 80.9ms | 100% |
| 2 | 14.27 inf/s | 139.9ms | 57.7% |
| 4 | 14.23 inf/s | 277.2ms | 28.8% |

**Cost Analysis (m6i.xlarge @ $0.192/hr):**
| Metric | Bare Metal | Enclave |
|--------|-----------|---------|
| Cost/1M inferences | $4.27 | $4.76 |
| Cost multiplier | — | 1.12x |

**Crypto Primitives (Tier 4, bare metal m6i.xlarge):**
| Operation | Mean | P99 |
|-----------|------|-----|
| HPKE session setup (both sides) | 0.10ms | 0.13ms |
| X25519 keypair gen | 0.017ms | 0.020ms |
| HPKE encrypt 1KB | 0.003ms | 0.003ms |
| HPKE decrypt 1KB | 0.003ms | 0.003ms |
| HPKE encrypt 1MB | 1.41ms | 1.82ms |
| HPKE decrypt 1MB | 1.36ms | 1.68ms |
| Ed25519 keypair gen | 0.017ms | 0.018ms |
| Receipt sign (CBOR+Ed25519) | 0.022ms | 0.030ms |
| Receipt verify | 0.042ms | 0.050ms |
| **Per-inference crypto budget (1KB)** | **0.028ms** | — |

**COSE Attestation Verification (client-side, bare metal m6i.xlarge):**
| Operation | Mean | P99 |
|-----------|------|-----|
| COSE_Sign1 signature verify (ECDSA-P384) | 0.739ms | 0.760ms |
| Certificate chain walk (3 certs) | 2.226ms | 2.273ms |
| CBOR payload parse | 0.001ms | 0.001ms |
| **Full verification pipeline** | **2.998ms** | **3.046ms** |

Key takeaways:
- **~11.8% inference overhead** — within "Acceptable" range per BENCHMARK_SPEC.md (10-15% matches AMD SEV-SNP BERT numbers)
- **Cold start dominated by model fetch** (6.9s over VSock from S3) — could be optimized with EIF-embedded weights or pre-warming
- **Attestation + KMS total: ~410ms** one-time cost, acceptable for session-based workloads
- **Memory ~3.8x RSS** (VmHWM: 266→1018 MB) due to enclave kernel overhead and VSock message buffers
- Decrypt and model load times are comparable (no significant overhead)
- **Embedding quality near-identical** — cosine=1.0, max_abs_diff=5.8e-7 within f32 precision
- **Crypto overhead negligible** — 0.307ms per request = 0.38% of inference time
- **Input scaling near-linear** — 0.97ms/token, BERT computational complexity dominates
- **Throughput plateaus at ~14.3 inf/s** — CPU-bound on m6i.xlarge (4 vCPUs)

### Shared Inference Module

Benchmark inference logic (`run_single_inference`: tokenize → BERT forward → mean pooling) is shared via `common/src/inference.rs`, gated behind the `inference` feature flag. Both `benchmark_baseline` and `vsock-pingpong` import from `ephemeral_ml_common::inference`. The production `CandleInferenceEngine` in `enclave/src/candle_engine.rs` has additional model registry logic and is intentionally separate.

### Benchmark Re-Run Status

The last benchmark run was completed on Feb 3, 2026 (commit `3e7b676`). Results in `benchmark_results/run_20260203_v2/`. This run has known issues: mixed commit/hardware fields across JSONs, `commit` shows "unknown" in enclave output, not a clean single-commit snapshot. **A fresh rerun is needed for publication-quality results.**

As of commit `b325fdd`, the benchmark runner (`run_benchmark.sh`) includes:
- `--clean` flag to force `cargo clean` before building (ensures `GIT_COMMIT` is baked in via `option_env!()`)
- Step 8 post-run validation: checks all JSONs agree on `commit` + `hardware`, validates `VmHWM` and `quality.embedding_sha256`
- `run_metadata.json` written per run with timestamp, git commit, instance type, enclave config

**Rerun procedure:**
1. Push latest commit, SSH into m6i.xlarge
2. `git pull && cargo clean` (one-time after checkout)
3. `./scripts/run_benchmark.sh --clean --output-dir benchmark_results/run_$(date +%Y%m%d_%H%M%S)/`
4. Repeat 3–5 times for reproducibility data
5. Step 8 validates each run; all JSONs must agree on commit + instance type

### Known Limitations & Future Work

- **Production attestation verifier VERIFIED on Nitro** (commit `c1c7439`) — COSE_Sign1 signature (ECDSA-P384), cert chain to AWS Nitro root CA, nonce, timestamps, and key consistency all validated with real NSM attestation documents. Five production-only bugs were found and fixed during validation.
- Enclave `hardware` field: should now work via Docker build arg `INSTANCE_TYPE` → `option_env!()`, but not yet verified on Nitro
- Enclave `commit` field: should now work via Docker build arg `GIT_COMMIT` → `option_env!()`, but not yet verified on Nitro
- **Missing Tier 2 metrics**: Instance type comparison (c6i.xlarge, c6i.2xlarge)
- **Missing Tier 3 metrics**: Output determinism across enclave restarts (need multiple enclave runs to compare SHA-256)
- **Missing Tier 5 metrics**: Max concurrent sessions, throughput at saturation, memory under load
- **Reproducibility suite**: `run_benchmark_repro.sh` exists but not yet run on Nitro (requires N full runs)

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
- Listens on VSock port (default 8082, configurable via `EPHEMERALML_VSOCK_PORT`, CID 3 = host)
- Handles: KmsProxy (attestation-gated key release), Storage (S3 model fetch), Audit (log forwarding)
- S3 bucket configurable via `EPHEMERALML_S3_BUCKET` env var (default: `ephemeral-ml-models-demo`)
- Must be running before enclave starts (enclave connects to host CID 3, port 8082)

### Benchmark Run Sequence

The full suite is automated via `./scripts/run_benchmark.sh --output-dir DIR`. Manual steps for reference:

1. Build baseline: `cargo build --release --bin benchmark_baseline`
2. Run baseline: `target/release/benchmark_baseline --model-dir test_artifacts --instance-type m6i.xlarge > baseline_results.json`
3. Build Docker: `docker build -f enclaves/vsock-pingpong/Dockerfile --build-arg MODE=benchmark -t vsock-pingpong-benchmark:latest .`
4. Build EIF: `nitro-cli build-enclave --docker-uri vsock-pingpong-benchmark:latest --output-file benchmark.eif`
5. Start proxy: `cargo build --release --bin kms_proxy_host --features production && target/release/kms_proxy_host &`
6. Run enclave: `nitro-cli run-enclave --eif-path benchmark.eif --memory 4096 --cpu-count 2 --enclave-cid 16 --debug-mode`
7. Capture: `nitro-cli console --enclave-id $ID > console.log &`
8. Wait for `BENCHMARK_RESULTS_JSON_END` marker in console log
9. Extract JSON between `BENCHMARK_RESULTS_JSON_BEGIN` and `BENCHMARK_RESULTS_JSON_END` markers
10. Run crypto: `target/release/benchmark_crypto --instance-type m6i.xlarge > crypto.json`
11. Run E2E: `target/release/benchmark_e2e --model-dir test_artifacts --instance-type m6i.xlarge > e2e.json`
12. Run COSE: `target/release/benchmark_cose --instance-type m6i.xlarge > cose.json`
13. Run concurrent: `target/release/benchmark_concurrent --model-dir test_artifacts --instance-type m6i.xlarge > concurrent.json`
14. Run input scaling: `target/release/benchmark_input_scaling --model-dir test_artifacts --instance-type m6i.xlarge > input_scaling.json`
15. Run true E2E: `cargo build --release -p ephemeral-ml-client --features benchmark && target/release/benchmark_true_e2e --model-dir test_artifacts --instance-type m6i.xlarge > true_e2e.json`
16. Run enclave concurrency: `target/release/benchmark_enclave_concurrency --model-dir test_artifacts --instance-type m6i.xlarge > enclave_concurrency.json`
17. Run quality determinism: `python3 scripts/analyze_quality_determinism.py --baseline-files baseline.json --enclave-files enclave.json --output quality_determinism.json`
18. Generate report: `python3 scripts/benchmark_report.py --baseline baseline.json --enclave enclave.json --crypto crypto.json --input-scaling input_scaling.json --true-e2e true_e2e.json --enclave-concurrency enclave_concurrency.json --quality-determinism quality_determinism.json --output report.md`
19. Generate paper tables: `python3 scripts/generate_paper_tables.py --baseline baseline.json --enclave enclave.json --crypto crypto.json --cose cose.json --e2e e2e.json --concurrent concurrent.json --input-scaling input_scaling.json --true-e2e true_e2e.json --enclave-concurrency enclave_concurrency.json > paper_tables.tex`
20. Cleanup: terminate enclave, kill proxy

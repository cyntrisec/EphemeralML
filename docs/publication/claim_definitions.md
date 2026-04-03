# AIR v1 Publication Claim Definitions

**Status:** Active
**Date:** 2026-02-28
**Purpose:** Canonical definitions for every public-facing claim. Every number cited in README, papers, or external communications MUST trace back to a definition in this file.

## 1. Claim Registry

### C-1: Nitro Inference Overhead (Fully Instrumented)

| Field | Value |
|-------|-------|
| **Canonical value** | +12.6% mean |
| **Formula** | `(enclave_mean - baseline_mean) / baseline_mean * 100` |
| **Scope** | Host-observed inference latency including VSock transport. Baseline runs on host OS with identical CPU allocation (RAYON_NUM_THREADS=2). Enclave runs inside Nitro Enclave with VSock pipeline (3 channels: control/data_in/data_out). |
| **Model** | MiniLM-L6-v2 (22.7M params, sentence-transformers/all-MiniLM-L6-v2, safetensors) |
| **Instance** | AWS EC2 m6i.xlarge (4 vCPU Intel Xeon 8375C, 16 GiB RAM) |
| **Enclave config** | 2 vCPU, 4096 MiB RAM, CID 16 |
| **Measurement** | 100 iterations, 3 warmup discarded, per-iteration wall-clock timing |
| **Bare metal mean** | 78.55ms |
| **Enclave mean** | 88.45ms |
| **Range (3 runs)** | +12.4% to +12.8% (runs 2-3); cold-cache run 1 at +17.6% |
| **Commit** | `b00bab1` |
| **Date** | 2026-02-04 |
| **Script** | Legacy `scripts/run_benchmark.sh` (9-benchmark suite with `benchmark_enclave_inference` binary) |
| **Reproducibility** | NOT reproducible on current `main` (`f1ba30d`+). Legacy benchmark pipeline removed. Historical artifact only. |
| **Caveats** | Includes VSock RTT (~40ms round-trip overhead baked into measurement). Run 1 cold-cache outlier excluded from headline. m6i.xlarge only. |

### C-2: Nitro Enclave Execution Overhead (Modern Fallback)

| Field | Value |
|-------|-------|
| **Canonical value** | +3.2% mean |
| **Formula** | `(receipt_execution_time_ms_mean - baseline_mean) / baseline_mean * 100` |
| **Scope** | Enclave-side inference execution time only. Baseline measured by `benchmark_baseline` binary on host. Enclave time from receipt `execution_time_ms` field. Does NOT include VSock transport, client crypto, or receipt overhead. |
| **Model** | MiniLM-L6-v2 (22.7M params) |
| **Instance** | AWS EC2 m6i.xlarge |
| **Enclave config** | 2 vCPU, 4096 MiB RAM |
| **Measurement** | Baseline: 100 iterations, 3 warmup. Enclave: 10 iterations via repeated `nitro_e2e.sh`, 2 warmup discarded. |
| **Bare metal mean** | 74.61ms |
| **Enclave execution mean** | 77.00ms |
| **P50/P95/P99** | 77.00/78.00/78.00ms (enclave), 74.58/76.80/77.80ms (baseline) |
| **Commit** | `f1ba30d` |
| **Date** | 2026-02-25 |
| **Script** | `scripts/run_benchmark_modern.sh` |
| **Reproducibility** | Reproducible on current `main`. Run `scripts/run_benchmark.sh` on a Nitro-enabled m6i.xlarge. |
| **Caveats** | Enclave memory RSS not reported (memory_peak_mb=0 in current host path). VSock RTT and cold-start stage breakdown unavailable. Lower iteration count than C-1. |

### C-3: Nitro Host E2E Latency

| Field | Value |
|-------|-------|
| **Canonical value** | 113ms (latest single run) / 117ms (10-run mean) |
| **Formula** | Client-observed wall-clock from `scripts/nitro_e2e.sh` execution (timing.json.e2e_client_ms) |
| **Scope** | Full client round-trip: encrypt request → VSock send → enclave inference → receipt sign → VSock recv → client verify. |
| **Model** | MiniLM-L6-v2 |
| **Instance** | AWS EC2 m6i.xlarge |
| **10-run stats** | Mean 117.1ms, P50 114ms, P95 130ms, P99 130ms |
| **Commit** | `f1ba30d` (10-run), single run at `a33dc8b` (113ms) |
| **Date** | 2026-02-25 (10-run), 2026-02-27 (single) |
| **Caveats** | Includes enclave execution + VSock + client crypto + receipt. Not comparable to C-1/C-2 bare-metal baselines. |

### C-4: Multi-Model Weighted Overhead

| Field | Value |
|-------|-------|
| **Canonical value** | +12.9% weighted mean |
| **Models** | MiniLM-L6-v2 (+14.0%), MiniLM-L12-v2 (+12.9%), BERT-base-uncased (+11.9%) |
| **Instance** | AWS EC2 m6i.xlarge |
| **Measurement** | 3 runs per model, 100 iterations each |
| **Commit** | `b00bab1` |
| **Date** | 2026-02-05 |
| **Reproducibility** | NOT reproducible on current `main`. Legacy pipeline. |
| **Caveats** | Same measurement scope as C-1 (host-observed, includes VSock). |

### C-5: Cross-Cloud E2E PASS (Functional + Security)

| Field | Value |
|-------|-------|
| **Canonical value** | 3/3 platforms PASS (AWS Nitro + GCP CPU TDX + GCP GPU H100 CC) |
| **Formula** | Binary PASS/FAIL per platform. PASS = positive path verified + negative tests pass + AIR v1 strict verification pass. |
| **Scope** | Functional and security correctness. NOT cross-provider overhead comparison. |
| **Evidence date** | 2026-02-27 |
| **Commit (evidence)** | Between `f1ba30d` (image build) and `a33dc8b` (HEAD at collection) |
| **Caveats** | GCP GPU MiniLM inference time (12.3s) is not representative of GPU performance — dominated by CUDA JIT warmup. MiniLM is too small for GPU benefit. |

### C-6: AIR v1 Verification Pass

| Field | Value |
|-------|-------|
| **Canonical value** | 11/11 mandatory checks PASS on all platforms |
| **Checks** | COSE_DECODE, ALG, CONTENT_TYPE, PAYLOAD, EAT_PROFILE, SIG, CTI, MHASH_PRESENT, MEAS, MTYPE, MHASH_SCHEME |
| **Scope** | AIR v1 4-layer verification (T1_PARSE → T2_CRYPTO → T3_CHAIN → T4_POLICY mandatory checks). Policy-optional checks (FRESH, MHASH, MODEL, PLATFORM, NONCE, REPLAY) skipped when no policy constraints set. |
| **Evidence** | `receipt_air_v1_verify_log.txt` in each evidence folder |

### C-7: Compliance Baseline Pass

| Field | Value |
|-------|-------|
| **Canonical value** | 16/16 compliance rules pass (baseline profile) |
| **Rules** | SIG-001, SIG-002, ATT-001, ATT-002, MEAS-001, MEAS-002, FRESH-001, FRESH-002, MODEL-001, MODEL-002, CHAIN-001, CBOR-001, KEY-001, POLICY-001, SEQ-001, DESTROY-001 |
| **Scope** | `ephemeralml-compliance verify --profile baseline` against receipt + compliance bundle |
| **Evidence** | `compliance_verify_log.txt` in MVP evidence folders |

### C-8: Negative Test Coverage

| Field | Value |
|-------|-------|
| **Canonical value** | 2/2 negative tests pass per GCP platform |
| **Tests** | (1) Wrong model hash → deployment rejection. (2) Wrong KMS key → key release failure. |
| **Scope** | GCP Confidential Space deployments only. Nitro negative tests run via separate PCR mismatch scenarios. |
| **Evidence** | `negative_wrong_hash_{deploy,verify}.txt`, `negative_wrong_key_{deploy,verify}.txt` |

### C-9: Test Suite Coverage

| Field | Value |
|-------|-------|
| **Canonical value** | 574 tests passing, zero failures |
| **Breakdown** | 240 in ephemeral-ml-common (224 unit + 16 conformance), 334 across other crates |
| **Command** | `cargo test -q` |
| **Commit** | `a33dc8b` |
| **Date** | 2026-02-28 |

### C-10: Per-Inference Crypto Overhead

| Field | Value |
|-------|-------|
| **Canonical value** | 0.028ms per inference (0.03% of inference time) |
| **Components** | HPKE encrypt/decrypt (0.006ms) + receipt sign CBOR+Ed25519 (0.022ms) |
| **Scope** | Client-side and enclave-side crypto operations per inference request. Excludes session setup. |
| **Commit** | `b00bab1` |
| **Caveats** | Measured in legacy pipeline. Magnitude is correct — crypto is not the bottleneck. |

---

## 2. Mandatory Evidence Metadata

Every claim in this registry MUST be accompanied by:

| Field | Description | Example |
|-------|-------------|---------|
| `commit` | Git commit hash at time of measurement | `f1ba30d` |
| `instance_type` | Cloud instance type | `m6i.xlarge` |
| `model` | Model name + parameter count | `MiniLM-L6-v2 (22.7M)` |
| `iterations` | Number of measured iterations | `100` |
| `warmup` | Number of warmup iterations discarded | `3` |
| `script` | Script or binary that produced the measurement | `scripts/run_benchmark_modern.sh` |
| `timestamp` | UTC ISO 8601 timestamp of measurement | `2026-02-25T11:02:00Z` |
| `evidence_path` | Relative path to evidence artifacts | `artifacts/benchmarks/aws-nitro-modern-20260225-clean/` |

---

## 3. Canonical Headline Selection

For external communication (papers, website, slide decks), use:

| Context | Claim | Rationale |
|---------|-------|-----------|
| **Headline inference overhead** | "+3–13% depending on measurement boundary" | Honest range covering C-2 (enclave execution only) through C-1 (full pipeline). |
| **Conservative single number** | "+12.6% (MiniLM-L6-v2, 100 iterations, m6i.xlarge)" | C-1, fully instrumented, highest rigor. |
| **Reproducible on main** | "+3.2% enclave execution overhead" | C-2, with caveat: excludes VSock transport. |
| **Multi-model** | "+12.9% weighted mean (3 models)" | C-4, broadest model coverage. |
| **Cross-cloud** | "3/3 platforms PASS" | C-5, functional correctness only. Do NOT cite cross-provider latency comparisons. |
| **Per-inference crypto** | "< 0.03ms per request" | C-10, negligible. |

### What NOT to claim

- Do NOT present C-2 (+3.2%) without noting it excludes transport overhead.
- Do NOT present C-1 (+12.6%) as reproducible on current main.
- Do NOT compare GCP TDX inference time to AWS Nitro inference time as overhead — different CPUs, different TEE architectures.
- Do NOT use GCP GPU MiniLM inference time (12.3s) as GPU performance — it's CUDA JIT warmup on a trivially small model.
- Do NOT claim "zero overhead" based on the +0.2–0.3% P99 figures — those are within noise.

---

## 4. Overhead Disambiguation

The +12.6% and +3.2% figures are **both correct** but measure different things:

```
Client ──► [encrypt] ──► VSock ──► Enclave ──► [inference] ──► VSock ──► [receipt] ──► Client
           ├───────────── C-3: 113-117ms (host E2E) ──────────────────────────────────┤
                                     ├──── C-2: 77ms (enclave execution) ────┤
           ├───── C-1: 88.45ms (host-observed via benchmark binary) ─────────┤
```

| Metric | Bare Metal | Measured | Overhead | What's included |
|--------|-----------|----------|----------|----------------|
| C-1 (fully instrumented) | 78.55ms | 88.45ms | +12.6% | Inference + VSock RTT + host marshaling |
| C-2 (enclave execution) | 74.61ms | 77.00ms | +3.2% | Inference only (from receipt field) |
| C-3 (host E2E) | — | 113-117ms | — | Everything client-observable |

The ~10ms gap between C-1 and C-2 is the VSock transport layer. The ~40ms gap between C-2 and C-3 is client-side crypto, network, and receipt handling.

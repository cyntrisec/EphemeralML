# Benchmark JSON Schema

`schema_version` identifies the exact result shape for a benchmark family.
Local AIR microbenchmarks currently emit `schema_version: 1`; GCP warm-path
records with transport timing hooks emit `schema_version: 2`. The goal is
reproducibility: a benchmark result must explain what was measured, where it
ran, which code produced it, and what boundary the timing covers.

## Required Top-Level Fields

```json
{
  "schema_version": 1,
  "benchmark_id": "air_receipt_microbench",
  "generated_at_unix": 1778340000,
  "binary": "benchmark_air_receipt",
  "git_sha": "84b058e",
  "environment": {},
  "workload": {},
  "measurement": {},
  "metrics": {},
  "caveats": []
}
```

## Environment

`environment` must include enough host and software metadata to explain future
drift:

```json
{
  "host": {
    "cpu_model": "Intel(R) Xeon(R) ...",
    "logical_cpus": 4,
    "kernel": "Linux 6.1...",
    "mem_total_kb": 16000000,
    "cpu_frequency": {
      "scaling_governors": ["performance"],
      "scaling_drivers": ["intel_pstate"],
      "intel_pstate_no_turbo": "0",
      "cpufreq_boost": null
    },
    "process_affinity": {
      "cpus_allowed_list": "2",
      "taskset_hint": "For quoteable runs, pin the process explicitly, e.g. taskset -c 2 target/release/benchmark_air_receipt ..."
    }
  },
  "software": {
    "rustc": "rustc 1.87.0 ...",
    "crate_versions": {
      "ephemeral-ml-client": "0.2.9",
      "ephemeral-ml-common": "0.2.9",
      "confidential-ml-transport": "0.6.1"
    }
  }
}
```

Benchmark binaries should populate `git_sha` from the local Git checkout. For
remote runner VMs that receive only a compiled binary, set
`EPHEMERALML_BENCHMARK_GIT_SHA=<commit>` explicitly.

Cloud benchmarks should extend `host` with provider-specific fields such as
`provider`, `region`, `zone`, `instance_type`, `tee`, and `image_digest` when
available.

## Workload

`workload` describes the thing being measured, not just the benchmark binary:

```json
{
  "receipt_format": "AIR v1 COSE_Sign1",
  "signature_algorithm": "Ed25519",
  "hash_algorithm": "SHA-256",
  "payload_bytes": 1024,
  "receipt_bytes": 604,
  "batch_receipts": 1000
}
```

Warm path cloud benchmarks should also include:

- `model_id`
- `model_family` (`embedding`, `causal_generation`, `classifier`)
- `model_parameters`
- `input_tokens` or `input_bytes`
- `output_tokens` where applicable
- `concurrency`
- `session_mode` (`independent_sessions` or `single_session_inflight`)

## Measurement

`measurement` defines run control:

```json
{
  "warmup_iterations": 1000,
  "measured_iterations": 10000,
  "batch_verify_passes": 5,
  "timer": "std::time::Instant",
  "unit": "microseconds"
}
```

## Metrics

Each metric is a statistics object:

```json
{
  "total_us": 1205000.0,
  "mean_us": 120.5,
  "p50_us": 119.0,
  "p95_us": 135.0,
  "p99_us": 151.0,
  "min_us": 110.0,
  "max_us": 220.0,
  "n": 10000
}
```

`total_us` is the sum of measured iterations after warmup discard. It is
included so auditors can recompute the mean and reason about total wall-clock
measurement time.

Use explicit names that encode the timing boundary, for example:

- `air_build_full_us`
- `air_build_timed_total_us`
- `air_ed25519_sign_us`
- `air_cose_serialize_us`
- `air_verify_full_policy_us`
- `air_parse_only_us`
- `ed25519_verify_strict_us`
- `sha256_request_hash_us`
- `chacha20_poly1305_seal_us`
- `warm_path_gateway_to_receipt_us`

## GCP Warm Path Timing Record

The GCP direct backend can emit one development-only timing record per response
when both sides explicitly opt in:

- Backend deployment: `bash scripts/gcp/deploy.sh --benchmark ...`
- Direct matrix run: `bash scripts/gcp/warm_path_benchmark.sh ...`
- Gateway smoke run: `bash scripts/gcp/openai_gateway_e2e.sh --benchmark ...`

The request sets `benchmark_mode: "development"` in the enclave plaintext
request. The enclave only honors it when `EPHEMERALML_BENCHMARK_MODE=development`
is present inside the Confidential Space workload. Production responses do not
include this field.

The embedded response record is intentionally smaller than a full benchmark run
record:

```json
{
  "schema_version": 2,
  "benchmark_id": "gcp_warm_path_request",
  "mode": "development",
  "timings_us": {
    "request_decrypt": 5,
    "request_hash": 8,
    "inference": 2070000,
    "response_canonicalize": 11,
    "response_hash": 7,
    "legacy_receipt_build": 120,
    "legacy_receipt_sign": 40,
    "air_claims_from_legacy": 15,
    "air_build": 35,
    "air_sign": 38,
    "air_serialize": 9,
    "response_encrypt": null
  },
  "caveats": []
}
```

Important boundary: `request_decrypt` is server-side `SecureChannel` AEAD open
time for the inbound request frame. `response_encrypt` remains `null` in the
embedded response record because exact same-response server-side AEAD seal
happens after the response JSON is serialized. The matrix runner augments each
top-level request record with client-side `client_request_encrypt` and
`client_response_decrypt` timings from `SecureChannel` timing hooks; those are
useful for transport crypto decomposition but are not enclave-side measurements.
This client-side transport timing augmentation is the schema v2 addition.

For enterprise reports, aggregate these per-request records into the top-level
schema described above. `scripts/gcp/warm_path_benchmark.sh` writes JSONL under
`evidence/benchmarks/gcp-cs-tdx-warm-path-<timestamp>/` with one `request`
record per measured request and one `summary` record per matrix point. Use 10
warmup requests per independent session, discard post-handshake cache/page-fault
outliers, and measure at least 100 requests per
`(concurrency, prompt_size, model_shape)` point. Concurrency 16 should mean 16
independent client sessions unless explicitly labeled as single-session
in-flight concurrency.

For audit throughput, report both total pass time and derived throughput:

```json
{
  "verify_cached_batch_total_us": {},
  "verify_cached_batch_receipts_per_sec": {}
}
```

The batch corpus must be generated before the timed verify pass. File I/O and
receipt creation are not part of the verify throughput metric unless explicitly
named as separate metrics.

## Caveats

Every benchmark must include a `caveats` list. Examples:

- `air_build_full_us includes claim validation, deterministic CBOR payload encoding, COSE_Sign1 Sig_structure construction, Ed25519 signing, and tagged CBOR serialization`
- `air_verify_full_policy_us measures wall-clock around verify_air_v1_receipt including COSE/CBOR parse, Ed25519 verify_strict, claim validation, and policy checks`
- `verify_cached_batch loads pre-generated receipts into memory before timing; disk I/O is excluded`
- `ChaCha20-Poly1305 measurements are AEAD seal/open timings, not raw ChaCha20 stream-cipher timings`
- `CPU governor, turbo/boost status, and process affinity are recorded; quoteable runs should pin the process with taskset and run on an otherwise idle host`

## Quoteable Run Controls

For enterprise-facing AIR microbenchmarks, use at least:

```bash
cargo build --release -p ephemeral-ml-client --bin benchmark_air_receipt
taskset -c 2 target/release/benchmark_air_receipt \
  --warmup 1000 \
  --iterations 10000 \
  --batch-receipts 1000 \
  --batch-passes 5 \
  > artifacts/benchmarks/air-receipt-$(date -u +%Y%m%dT%H%M%SZ).json
```

Before running, prefer an idle host and `performance` CPU governor:

```bash
# Optional; requires host permissions and cpupower availability.
sudo cpupower frequency-set -g performance
```

Do not hide frequency behavior. If turbo is enabled, leave the recorded
`intel_pstate_no_turbo` / `cpufreq_boost` fields in the result and mention it in
the report caveats. Run the same command on both a developer box and one
production-like cloud VM; use the cloud VM as the headline number and the dev
box as a range check.

## Versioning

Bump `schema_version` on incompatible JSON shape changes. Add optional fields
without bumping the version.

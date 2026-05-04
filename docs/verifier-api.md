# Verifier API Reference

## Overview

The EphemeralML Verifier API is a hosted HTTP service for verifying attested execution receipts. It wraps the same `verify_receipt()` logic as the CLI verifier in a REST API.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | No | Landing page (HTML form) |
| `GET` | `/health` | No | Liveness probe |
| `GET` | `/api/v1/samples/valid` | No | Fresh AIR v1 sample receipt |
| `GET` | `/api/v1/samples/legacy` | No | Fresh legacy sample receipt |
| `POST` | `/api/v1/verify` | Depends on mode | Verify receipt (JSON body) |
| `POST` | `/api/v1/verify/upload` | Depends on mode | Verify receipt (multipart upload) |

## Authentication

The verify endpoints require an API key only in `secured-api` mode. In `public-trust-center` mode, verification is intentionally public and protected by basic in-process abuse throttling.

**Supported headers** (either one):
- `Authorization: Bearer <API_KEY>`
- `X-API-Key: <API_KEY>`

**Configuration:**

| Flag / Env Var | Default | Description |
|----------------|---------|-------------|
| `--mode` / `EPHEMERALML_VERIFIER_MODE` | (none) | `public-trust-center` or `secured-api` |
| `--api-key` / `EPHEMERALML_VERIFIER_API_KEY` | (none) | API key (required for `secured-api` mode) |
| `--insecure-no-auth` / `EPHEMERALML_VERIFIER_NO_AUTH=true` | `false` | Deprecated; maps to `public-trust-center` |

**Service modes:**
- `--mode public-trust-center`: No API key. Basic in-process abuse throttling enforced. Designed for public internet-facing receipt verification.
- `--mode secured-api --api-key <KEY>`: API key required. For internal or enterprise use.
- If neither mode nor `--insecure-no-auth`: **startup fails** with instructions (fail-closed).

Health (`/health`), landing page (`/`), and sample endpoints (`/api/v1/samples/*`) never require auth.

## Rate Limiting

Per-IP sliding window limiter. Returns `429 Too Many Requests` when exceeded.

| Flag / Env Var | Default | Description |
|----------------|---------|-------------|
| `--rate-limit` / `EPHEMERALML_VERIFIER_RATE_LIMIT` | `60` | Max requests per minute per IP |

Set to `0` to disable in `secured-api` mode. `public-trust-center` mode requires a positive rate limit and will reject `0`. Health endpoint is exempt.

This limiter is a local guardrail, not a replacement for edge abuse controls. Public Cloud Run deployments should use a single instance for this service or place the verifier behind an external load balancer with Cloud Armor before relying on it for high-volume public exposure.

## CORS

| Flag | Default | Description |
|------|---------|-------------|
| `--cors-origin <URL>` | (none) | Allowed origin (repeatable) |
| `--allow-permissive-cors` | `false` | Override CORS fail-closed with auth |

**Behavior:**
- With `--cors-origin`: explicit allowlist
- Without `--cors-origin` + no auth: permissive (with warning)
- Without `--cors-origin` + auth: **startup fails** unless `--allow-permissive-cors`

## JSON Endpoint

### `POST /api/v1/verify`

**Request body:**

```json
{
  "receipt": { ... },
  "public_key": "64-char-hex-ed25519-public-key",
  "expected_model": "minilm-l6-v2",
  "expected_model_hash_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expected_request_hash_hex": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "expected_response_hash_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "expected_security_mode": "production",
  "max_age_secs": 3600,
  "measurement_type": "any",
  "expected_attestation_source": "cs-tdx",
  "expected_image_digest": "sha256:068c3cdf..."
}
```

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `receipt` | object/string | Yes | — | JSON receipt or base64 CBOR |
| `public_key` | string | Yes | — | 64-char hex Ed25519 public key |
| `expected_model` | string | No | skip | Expected model ID |
| `expected_model_hash_hex` | string | No | skip | Expected AIR `model_hash` (32-byte hex) |
| `expected_request_hash_hex` | string | No | skip | Expected AIR `request_hash` (32-byte hex) |
| `expected_response_hash_hex` | string | No | skip | Expected AIR `response_hash` (32-byte hex) |
| `expected_security_mode` | string | No | skip | Expected AIR `security_mode`; this production verifier accepts only `production` |
| `max_age_secs` | u64 | No | `0` (skip) | Max receipt age |
| `measurement_type` | string | No | `"any"` | Expected measurement type |
| `expected_attestation_source` | string | No | skip | e.g. `"cs-tdx"`, `"nitro"` |
| `expected_image_digest` | string | No | skip | e.g. `"sha256:abc123"` |
| `expected_pcr0_hex` / `expected_pcr1_hex` / `expected_pcr2_hex` | string | No | skip | Expected Nitro runtime measurements; must be supplied together |

**Response (200) — Trust Center response:**

```json
{
  "verdict": "verified",
  "verified": true,
  "format": "legacy",
  "assurance_level": "legacy_local",
  "tee_provenance_verified": false,
  "api_version": "v1",
  "verified_at": 1708000100,
  "receipt": {
    "receipt_id": "98aee3e7-...",
    "model_id": "minilm-l6-v2",
    "model_version": "v1.0",
    "platform": "nitro-pcr",
    "sequence_number": 1,
    "issued_at": 1708000000
  },
  "checks": [
    { "id": "signature", "label": "Signature (Ed25519)", "status": "pass", "layer": "crypto" },
    { "id": "model_match", "label": "Model ID match", "status": "pass", "layer": "policy" },
    { "id": "measurement_type", "label": "Measurement type", "status": "skip", "layer": "policy" },
    { "id": "timestamp_fresh", "label": "Timestamp freshness", "status": "skip", "layer": "policy" },
    { "id": "measurements_present", "label": "Measurements present", "status": "pass", "layer": "claim" },
    { "id": "attestation_source", "label": "Attestation source", "status": "skip", "layer": "policy" },
    { "id": "image_digest", "label": "Image digest", "status": "skip", "layer": "policy" },
    { "id": "destroy_evidence", "label": "Destroy evidence", "status": "skip", "layer": "policy" }
  ]
}
```

**Format values:** `"legacy"` (EphemeralML JSON/CBOR receipt) or `"air_v1"` (AIR v1 COSE_Sign1).

AIR v1 receipts submitted as base64 strings or uploaded as `.cbor` files are automatically detected and verified through the AIR v1 4-layer verification pipeline. The response shape is the same for both formats.

For AIR v1, `verified=true` means the receipt-local signature, structure, and configured policy checks passed.

Assurance levels are intentionally separated:

- `air_local`: receipt-local signature, structure, and configured policy checks only.
- `platform_attested`: `air_local` plus an authentic platform attestation sidecar, matching `attestation_doc_hash`, and signing-key binding.
- `tee_provenance`: `platform_attested` plus caller-supplied runtime measurement policy (`expected_pcr0_hex`, `expected_pcr1_hex`, and `expected_pcr2_hex`) that matches the attested PCRs.

When no attestation is supplied, the response reports `assurance_level: "air_local"`, `tee_provenance_verified: false`, and skipped `tee_provenance` checks. When an attestation is supplied without PCR policy, the response can report `assurance_level: "platform_attested"`, but `tee_provenance_verified` remains `false`.

## Multipart Endpoint

### `POST /api/v1/verify/upload`

**Form fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `receipt_file` | file | Yes | Receipt (JSON or CBOR) |
| `public_key` | text | Yes* | 64-char hex Ed25519 key |
| `public_key_file` | file | Yes* | 32-byte binary Ed25519 key |
| `attestation_file` | file | Yes* | Attestation document used to derive the receipt signing key |
| `expected_model` | text | No | Expected model ID |
| `expected_model_hash_hex` | text | No | Expected AIR `model_hash` |
| `expected_request_hash_hex` | text | No | Expected AIR `request_hash` |
| `expected_response_hash_hex` | text | No | Expected AIR `response_hash` |
| `expected_security_mode` | text | No | Expected AIR `security_mode`; this production verifier accepts only `production` |
| `expected_pcr0_hex` | text | No | Expected Nitro PCR0 measurement, 96 hex chars; must be supplied with PCR1/PCR2 |
| `expected_pcr1_hex` | text | No | Expected Nitro PCR1 measurement, 96 hex chars; must be supplied with PCR0/PCR2 |
| `expected_pcr2_hex` | text | No | Expected Nitro PCR2 measurement, 96 hex chars; must be supplied with PCR0/PCR1 |
| `measurement_type` | text | No | Expected measurement type |
| `max_age_secs` | text | No | Max receipt age (integer) |
| `expected_attestation_source` | text | No | Expected attestation source |
| `expected_image_digest` | text | No | Expected image digest |

\* Provide one of `public_key`, `public_key_file`, or `attestation_file`.

## curl Examples

### JSON endpoint with Bearer auth

```bash
curl -X POST https://verifier.example.com/api/v1/verify \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "receipt": '"$(cat receipt.json)"',
    "public_key": "aabbccdd...",
    "expected_attestation_source": "cs-tdx"
  }'
```

### Multipart upload with X-API-Key

```bash
curl -X POST https://verifier.example.com/api/v1/verify/upload \
  -H "X-API-Key: YOUR_API_KEY" \
  -F "receipt_file=@receipt.json" \
  -F "public_key=aabbccdd..." \
  -F "expected_model=minilm-l6-v2" \
  -F "expected_image_digest=sha256:068c3cdf..."
```

### Multipart upload using attestation instead of a raw public key

```bash
curl -X POST https://verifier.example.com/api/v1/verify/upload \
  -H "X-API-Key: YOUR_API_KEY" \
  -F "receipt_file=@receipt.cbor;type=application/octet-stream" \
  -F "attestation_file=@attestation.cbor;type=application/octet-stream" \
  -F "measurement_type=nitro-pcr" \
  -F "expected_pcr0_hex=<96-char-hex>" \
  -F "expected_pcr1_hex=<96-char-hex>" \
  -F "expected_pcr2_hex=<96-char-hex>"
```

In this flow the verifier derives the receipt signing key from the supplied attestation document. That proves key provenance. The PCR fields are what turn a valid platform attestation into an approved-runtime claim.

For AIR v1 uploads, the verifier also compares `SHA-256(attestation_file)` to the receipt's `attestation_doc_hash` and rejects the verdict if the attestation hash, platform authenticity, or signing-key binding checks fail.

### Local dev (public trust center)

```bash
ephemeralml-verifier --mode public-trust-center --port 8080

curl -X POST http://localhost:8080/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"receipt": ..., "public_key": "..."}'
```

## Error Responses

| Status | Meaning |
|--------|---------|
| `200` | Verification complete (check `verified` field) |
| `400` | Bad request (invalid key, malformed receipt) |
| `401` | Unauthorized (missing or invalid API key) |
| `413` | Payload too large (>2 MB) |
| `429` | Rate limit exceeded |

## Production Deployment

### Public trust center

```bash
export EPHEMERALML_VERIFIER_RATE_LIMIT=60

ephemeralml-verifier \
  --mode public-trust-center \
  --port 8080
```

### Secured API

```bash
export EPHEMERALML_VERIFIER_API_KEY="$(openssl rand -hex 32)"
export EPHEMERALML_VERIFIER_RATE_LIMIT=60

ephemeralml-verifier \
  --mode secured-api \
  --api-key "$EPHEMERALML_VERIFIER_API_KEY" \
  --cors-origin https://your-app.example.com \
  --port 8080
```

### Cloud Run public deployment guardrails

For `verify.cyntrisec.com`, deploy through a no-traffic candidate first, smoke-test the tagged URL, shift traffic only after a clean smoke test, then clear the tag.

Recommended public posture until an external load balancer and Cloud Armor are added:

- Use a dedicated runtime service account with no project-level IAM roles.
- Disable the default `run.app` URL after the custom domain is verified.
- Keep `max-instances=1` if relying on the in-process rate limiter.
- Keep low concurrency and timeout values, for example `concurrency=20` and `timeout=30`.
- Treat Cloud Run platform request logs as operational metadata that may include client IP, path, status, and trace fields.

Example hardening commands:

```bash
gcloud run services update trust-center \
  --region us-central1 \
  --no-default-url \
  --max-instances 1 \
  --concurrency 20 \
  --timeout 30

gcloud run services update-traffic trust-center \
  --region us-central1 \
  --clear-tags \
  --to-revisions <ready-revision>=100
```

## Security Defaults Summary

| Feature | Default | Override |
|---------|---------|---------|
| Mode selection | Explicit (startup fails if omitted) | `--mode public-trust-center` or `--mode secured-api` |
| Auth | Required in `secured-api`, disabled in `public-trust-center` | `--mode public-trust-center` |
| Rate limit | 60 req/min/IP | `--rate-limit N` (0=off) |
| CORS | Explicit origins with auth | `--allow-permissive-cors` |
| Body limit | 2 MB | Not configurable |

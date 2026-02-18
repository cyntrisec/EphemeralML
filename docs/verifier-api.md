# Verifier API Reference

## Overview

The EphemeralML Verifier API is a hosted HTTP service for verifying attested execution receipts. It wraps the same `verify_receipt()` logic as the CLI verifier in a REST API.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/` | No | Landing page (HTML form) |
| `GET` | `/health` | No | Liveness probe |
| `POST` | `/api/v1/verify` | Yes | Verify receipt (JSON body) |
| `POST` | `/api/v1/verify/upload` | Yes | Verify receipt (multipart upload) |

## Authentication

The verify endpoints require an API key when auth is enabled (default for production).

**Supported headers** (either one):
- `Authorization: Bearer <API_KEY>`
- `X-API-Key: <API_KEY>`

**Configuration:**

| Flag / Env Var | Default | Description |
|----------------|---------|-------------|
| `--api-key` / `EPHEMERALML_VERIFIER_API_KEY` | (none) | API key for verify endpoints |
| `--insecure-no-auth` / `EPHEMERALML_VERIFIER_NO_AUTH=true` | `false` | Disable auth (dev only) |

**Startup behavior:**
- If `--api-key` is set: auth enabled, verify endpoints require the key
- If `--insecure-no-auth`: auth disabled, loud warning logged
- If neither: **startup fails** with instructions (fail-closed)

Health (`/health`) and landing page (`/`) never require auth.

## Rate Limiting

Per-IP sliding window rate limiter. Returns `429 Too Many Requests` when exceeded.

| Flag / Env Var | Default | Description |
|----------------|---------|-------------|
| `--rate-limit` / `EPHEMERALML_VERIFIER_RATE_LIMIT` | `60` | Max requests per minute per IP |

Set to `0` to disable (with warning). Health endpoint is exempt.

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
| `max_age_secs` | u64 | No | `0` (skip) | Max receipt age |
| `measurement_type` | string | No | `"any"` | Expected measurement type |
| `expected_attestation_source` | string | No | skip | e.g. `"cs-tdx"`, `"aws-nitro"` |
| `expected_image_digest` | string | No | skip | e.g. `"sha256:abc123"` |

**Response (200):**

```json
{
  "verified": true,
  "receipt_id": "98aee3e7-...",
  "model_id": "minilm-l6-v2",
  "model_version": "v1.0",
  "checks": {
    "signature": "pass",
    "model_match": "pass",
    "measurement_type": "skip",
    "timestamp_fresh": "skip",
    "measurements_present": "pass",
    "attestation_source": "skip",
    "image_digest": "skip"
  },
  "errors": [],
  "warnings": [],
  "api_version": "v1",
  "verified_at": 1708000100
}
```

## Multipart Endpoint

### `POST /api/v1/verify/upload`

**Form fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `receipt_file` | file | Yes | Receipt (JSON or CBOR) |
| `public_key` | text | Yes* | 64-char hex Ed25519 key |
| `public_key_file` | file | Yes* | 32-byte binary Ed25519 key |
| `expected_model` | text | No | Expected model ID |
| `measurement_type` | text | No | Expected measurement type |
| `max_age_secs` | text | No | Max receipt age (integer) |
| `expected_attestation_source` | text | No | Expected attestation source |
| `expected_image_digest` | text | No | Expected image digest |

\* Provide either `public_key` or `public_key_file`, not both.

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

### Local dev (no auth)

```bash
ephemeralml-verifier --insecure-no-auth --rate-limit 0

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

```bash
export EPHEMERALML_VERIFIER_API_KEY="$(openssl rand -hex 32)"
export EPHEMERALML_VERIFIER_RATE_LIMIT=60

ephemeralml-verifier \
  --cors-origin https://your-app.example.com \
  --port 8080
```

## Security Defaults Summary

| Feature | Default | Override |
|---------|---------|---------|
| Auth | Required (fail-closed) | `--insecure-no-auth` |
| Rate limit | 60 req/min/IP | `--rate-limit N` (0=off) |
| CORS | Explicit origins with auth | `--allow-permissive-cors` |
| Body limit | 2 MB | Not configurable |

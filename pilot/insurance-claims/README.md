# Insurance Claims Triage Pilot

End-to-end pilot demonstrating EphemeralML for insurance claims processing.

This pilot has **two modes**:

| Mode | What it proves | AIR v1 receipts? |
|------|---------------|-----------------|
| **Local mock** | API flow, error handling, output structure | No — mock attestation only |
| **GCP TDX** | Full evidence path with hardware attestation | Yes — Ed25519-signed COSE_Sign1 |

## Scenario

An insurance company uses a language model to triage incoming claims. For each claim, the model classifies the claim type, extracts risk flags, produces a recommendation, and generates an explanation for the adjuster.

**On GCP TDX**, every inference produces a signed AIR v1 receipt that cryptographically binds the model identity, input/output hashes, and TEE attestation evidence.

**In local mock mode**, every inference returns receipt metadata (receipt_id, attestation_mode) but does not produce cryptographic AIR v1 receipts. Mock mode is a rehearsal path for validating API integration before a real deployment.

## What GCP TDX Mode Proves

| For compliance/legal | Evidence |
|---------------------|----------|
| Which model processed the claim | `model_id` + `model_hash` in receipt |
| That the input was not altered | `request_hash` in receipt |
| That the output was not altered | `response_hash` in receipt |
| Where it ran | `enclave_measurements` + `attestation_doc_hash` |
| When it ran | `iat` (issued-at) timestamp |
| Independent verification | Offline receipt verification with `verify-receipts.sh` |

## Dataset

8 synthetic insurance claims covering:

| # | Claim | Type | Key Risk Factors |
|---|-------|------|-----------------|
| CLM-2026-0001 | Rear-end collision, uninsured driver | Auto | High severity, uninsured motorist |
| CLM-2026-0002 | Burst pipe, basement water damage | Property | Straightforward, well-documented |
| CLM-2026-0003 | Slip-and-fall at catered event | Liability | Litigation risk, $175K demand |
| CLM-2026-0004 | Knee replacement pre-auth | Health | Pre-authorization, conservative treatment documented |
| CLM-2026-0005 | Deer strike on rural highway | Auto | Low severity, straightforward comprehensive |
| CLM-2026-0006 | Roof damage, late filing (72 days) | Property | Late filing flag, coverage dispute potential |
| CLM-2026-0007 | Vehicle theft — fraud indicators | Auto | SIU referral, multiple red flags |
| CLM-2026-0008 | Warehouse back injury, employer dispute | Workers Comp | Employer dispute, modified duty available |

No real personal data is used.

## Prerequisites

**Local mock mode:**
- Docker with `docker compose` (v2+)
- curl
- python3 (for request building and receipt verification)
- Optional: `pip install cbor2` (for deep receipt inspection)

**GCP deployment:**
- GCP project with billing and Confidential Computing enabled
- `gcloud` CLI authenticated
- Model uploaded to GCS bucket
- `.env.gcp` configured (run `bash scripts/init_gcp.sh` from repo root)

## Quick Start (Local Mock — Rehearsal)

Local mock mode validates the API flow, error handling, and output structure. It does **not** produce AIR v1 receipts or run inside a TEE.

```bash
# From this directory:
cd pilot/insurance-claims

# 1. Build and start the mock stack (TinyLlama, no TEE)
bash scripts/setup.sh

# 2. Run all scenarios (cold-start, warm batch, failure paths)
bash scripts/run-pilot.sh

# 3. Bundle artifacts for review
bash scripts/collect-artifacts.sh

# 4. Generate a sanitized customer-facing report from the latest run
bash scripts/generate-report.sh

# 5. Tear down
docker compose down
```

Note: `verify-receipts.sh` is only useful after a GCP TDX run that produces real `.cbor` receipts.

## Quick Start (GCP)

```bash
# From repo root:

# 1. Deploy to GCP Confidential Space (TDX)
bash pilot/deploy.sh

# 2. Run the GCP TDX pilot against the deployed CVM
bash pilot/insurance-claims/scripts/run-gcp-pilot.sh --ip <CVM_IP>

# 3. Verify receipts
bash pilot/insurance-claims/scripts/verify-receipts.sh

# 4. Generate a sanitized customer-facing report
bash pilot/insurance-claims/scripts/generate-report.sh

# 5. Tear down
bash scripts/gcp/teardown.sh
```

## Test Scenarios

### A. Cold-Start (2 claims)
First inferences after gateway start. Measures cold-path latency including model loading and connection establishment.

### B. Warm Batch (8 claims)
All 8 claims processed sequentially. Validates:
- Repeated receipt generation
- Stable output structure
- Consistent latency under warm conditions

### C. Failure Paths (5 tests)
- **Wrong API key** — should reject with 401
- **Empty messages** — should reject with 400
- **Unsupported tool_choice** — should reject with 400
- **Embeddings on chat-only model** — should reject with 400
- **Tampered receipt** — should fail verification

## Output Structure

```
artifacts/
  run-<timestamp>/
    responses/              # Request/response JSON for each claim
    receipts/               # Binary CBOR receipts (COSE_Sign1)
    timing/                 # Per-request latency measurements
    verification/           # Receipt verification results
    results.csv             # Machine-readable test results
    summary.json            # Run metadata
  gcp-run-<timestamp>/
    receipts/               # Real AIR v1 receipts from GCP TDX runs
    verification/           # Receipt verification results
  pilot-bundle-<date>/      # Distributable artifact bundle
    SUMMARY.md              # Business-readable results table
```

`artifacts/` is intentionally local-only and ignored by Git. Keep reusable pilot assets in this directory, and keep per-run evidence under `artifacts/`.

## What Success Looks Like

**Local mock:**
1. All 8 claims produce responses with model output and receipt metadata
2. All negative tests produce expected error responses
3. No crashes or connection drops across the full run

**GCP TDX:**
1. All of the above, plus:
2. Every response includes an AIR v1 receipt (COSE_Sign1 + Ed25519)
3. All receipts pass structural and signature verification
4. Tampered receipt is detected as invalid
5. `attestation_mode` is `cs-tdx` (not `mock`)

## Files

| Path | Purpose |
|------|---------|
| `data/claims.json` | 8 synthetic insurance claim cases |
| `requests/system-prompt.txt` | Claims triage system prompt |
| `requests/response-schema.json` | Expected output JSON schema |
| `requests/request-template.json` | OpenAI chat completion template |
| `scripts/setup.sh` | Build and start the stack |
| `scripts/run-pilot.sh` | Run all test scenarios |
| `scripts/run-gcp-pilot.sh` | Run the real GCP TDX scenario |
| `scripts/verify-receipts.sh` | Verify collected receipts |
| `scripts/collect-artifacts.sh` | Bundle artifacts for distribution |
| `scripts/generate-report.sh` | Generate a sanitized `REPORT.md` from the latest run |
| `REPORT.template.md` | Sanitized template for a customer-facing run report |
| `compose.yaml` | Docker Compose for local mock mode |

# Insurance Claims Pilot — Technical Report Template

Use this template after a pilot run to produce a customer-facing report without committing local run artifacts, project IDs, or machine-specific paths.

Fill placeholders from the latest run under `artifacts/`.

---

## Executive Summary

- **Date:** `<YYYY-MM-DD>`
- **Platforms exercised:** `<local mock / GCP TDX / other>`
- **Model(s):** `<model names and formats>`
- **Stack version:** `<EphemeralML version + key component versions>`

### Outcome Summary

- `<N>/<N>` inferences succeeded
- `<N>/<N>` negative tests passed
- `<N>/<N>` AIR v1 receipts collected and verified
- Average inference latency: `<X ms>`

---

## Pilot Modes

### Local Mock

- Purpose: API flow, error handling, response shape, operational rehearsal
- AIR v1 receipts: `No`
- Notes: `<brief notes>`

### Confidential Computing Run

- Platform: `<GCP TDX / AWS Nitro / H100 CC>`
- Purpose: full evidence path with hardware attestation
- AIR v1 receipts: `Yes`
- Notes: `<brief notes>`

---

## Environment

- **Instance / machine type:** `<machine type>`
- **Region / zone:** `<region/zone>`
- **Image / deployment ref:** `<sanitized image or release ref>`
- **Model packaging:** `<bundled in image / fetched remotely / manifest-backed>`

---

## Results

| Claim | Latency | Receipt Size | Receipt SHA-256 | Result |
|-------|---------|-------------|-----------------|--------|
| `<claim-1>` | `<ms>` | `<bytes>` | `<sha-prefix>` | `<PASS/FAIL>` |
| `<claim-2>` | `<ms>` | `<bytes>` | `<sha-prefix>` | `<PASS/FAIL>` |
| `<claim-3>` | `<ms>` | `<bytes>` | `<sha-prefix>` | `<PASS/FAIL>` |

### Receipt Contents

| Field | Value |
|-------|-------|
| Format | `COSE_Sign1` |
| Signature | `Ed25519` |
| Claims count | `<count>` |
| `iss` | `<issuer>` |
| `eat_profile` | `https://spec.cyntrisec.com/air/v1` |
| `model_id` | `<model id>` |
| `model_hash` | `<how bound>` |
| `request_hash` | `SHA-256 of input` |
| `response_hash` | `SHA-256 of output` |
| `attestation_doc_hash` | `SHA-256 of attestation evidence` |
| `enclave_measurements` | `<measurement type>` |
| `security_mode` | `<mode>` |

---

## What Passed

1. `<real AIR v1 receipts / attestation path>`
2. `<OpenAI-compatible API behavior>`
3. `<receipt metadata or verifier behavior>`
4. `<error handling>`
5. `<output stability>`
6. `<model identity binding story>`

---

## Known Limitations

1. **Mock mode limitation**  
   `<explain what mock mode does not prove>`

2. **Model quality limitation**  
   `<explain if local model quality is only for rehearsal>`

3. **Connection / lifecycle limitation**  
   `<direct mode / restart / single-session notes>`

4. **Out-of-scope items**  
   `<pipeline / multi-stage / GPU / production auth>`

---

## Latency Summary

| Metric | Local Mock | Confidential Run |
|--------|------------|------------------|
| Cold-start | `<value>` | `<value>` |
| Warm inference | `<value>` | `<value>` |
| Negative test | `<value>` | `<value or N/A>` |
| Handshake + attestation | `<value or N/A>` | `<value>` |

---

## What This Proves

### For the application team

- `<drop-in API statement>`
- `<SDK compatibility statement>`
- `<capability / output-shape statement>`

### For the security/compliance team

- `<per-inference receipt statement>`
- `<what the receipt binds>`
- `<offline verification statement>`
- `<measurement / attestation statement>`

### For the operations team

- `<deployment path>`
- `<time-to-ready>`
- `<typical latency>`

---

## Artifact References

Use relative paths only. Do not include local absolute filesystem paths.

| Path | Description |
|------|-------------|
| `artifacts/<run-id>/summary.json` | Run metadata |
| `artifacts/<run-id>/results.csv` | Machine-readable results |
| `artifacts/<run-id>/receipts/*.cbor` | AIR v1 receipts |
| `artifacts/<run-id>/receipts/*.pubkey` | Verification keys |
| `artifacts/<run-id>/verification/*.json` | Verification results |

---

## Recommendations

1. `<design-partner demo recommendation>`
2. `<production pilot recommendation>`
3. `<compliance review recommendation>`

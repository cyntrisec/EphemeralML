# End-to-End Audience Pin Test Results

**Date:** 2026-02-19
**Version:** v0.2.5 + 2 bug fixes (STS scope, chunked encoding)
**Project:** project-d3c20737-eec2-453d-8e5
**Zone:** us-central1-a
**Machine:** c3-standard-4 (Intel Sapphire Rapids, TDX)
**CS Image:** confidential-space-debug

## WIP Configuration

- **Pool:** ephemeralml-pool
- **Provider:** ephemeralml-tdx
- **Issuer:** https://confidentialcomputing.googleapis.com
- **WIP Audience:** `//iam.googleapis.com/projects/324130315768/locations/global/workloadIdentityPools/ephemeralml-pool/providers/ephemeralml-tdx`
- **KMS Key:** `projects/project-d3c20737-eec2-453d-8e5/locations/us-central1/keyRings/ephemeralml/cryptoKeys/model-dek`
- **Model Hash:** `53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db`

## Test Results

### Test 1: Positive -- Correct Audience Pin (PASS)

Client set `EPHEMERALML_EXPECTED_AUDIENCE` to the real WIP audience URI. The client's `jwt_validation()` at `attestation_bridge.rs:348` called `v.set_audience(&[aud])`, and `jsonwebtoken` verified the JWT's `aud` claim matched.

```
EphemeralML Client (GCP Mode)
Secure channel established with GCP enclave
Inference succeeded: 384 floats returned
First 5 values: [0.3414222, 0.75955707, 0.071208954, 0.2389017, -0.15010944]
Receipt saved to /tmp/ephemeralml-receipt.json
Receipt ID: c79f4339-db48-4760-a5b0-1c2190fd526d
```

### Test 2: Receipt Verification (PASS)

```
Signature (Ed25519)         [PASS]
Measurements present        [PASS]
VERIFIED
```

### Test 3: Negative -- Wrong Audience (PASS)

Client set `EPHEMERALML_EXPECTED_AUDIENCE` to a fake WIP audience (`projects/999999/.../fake/providers/fake`). The client correctly rejected the JWT during handshake.

```
Failed to establish channel: Client error: Transport error:
  Handshake failed: handshake failed: attestation verification failed
Exit code: 1
```

### Test 4: Baseline -- No Audience Pin (PASS)

Client did not set `EPHEMERALML_EXPECTED_AUDIENCE`. At `attestation_bridge.rs:351`, `v.validate_aud = false` skipped audience validation. Inference succeeded.

```
EphemeralML Client (GCP Mode)
Secure channel established with GCP enclave
Inference succeeded: 384 floats returned
Receipt ID: e61b396f-aa24-4293-ade7-7314056bf1c3
```

## Bugs Found and Fixed During Testing

### Bug 1: STS Token Exchange Missing `scope` Parameter

**File:** `enclave/src/cs_kms_client.rs:100-112`
**Error:** `STS returned 400 Bad Request: {"error":"invalid_request","error_description":"Scope(s) must be provided."}`
**Cause:** The STS token exchange form body omitted the required `scope` parameter.
**Fix:** Added `("scope", "https://www.googleapis.com/auth/cloud-platform")` to the STS exchange body.

### Bug 2: Launcher Token Response Uses Chunked Transfer-Encoding

**File:** `enclave/src/cs_token_client.rs:198`
**Error:** `STS returned 400 Bad Request: {"error":"invalid_grant","error_description":"Unable to parse the ID Token."}`
**Cause:** The Confidential Space Launcher returns OIDC tokens with `Transfer-Encoding: chunked`. The token parser expected a Content-Length response and extracted the raw body including chunk size markers (`1350\r\neyJ...`) instead of the decoded JWT.
**Fix:** Added `decode_chunked()` function that handles HTTP chunked transfer encoding. When the response headers contain `Transfer-Encoding: chunked`, the body is decoded before extracting the JWT.

## Trust Chain Verified

The full trust chain works end-to-end:

1. **Hardware:** GCP c3-standard-4, Intel Sapphire Rapids, TDX enabled
2. **Measured boot:** Confidential Space image (dm-verity, Launcher measures container)
3. **Attestation:** Launcher obtains TDX quote, issues OIDC JWT via /v1/token socket
4. **Key release:** WIP provider validates JWT issuer/audience, STS exchanges for access token, KMS decrypts model DEK
5. **Model integrity:** SHA-256 hash verified, Ed25519 manifest signature verified
6. **Client validation:** RS256 JWT verified via Google JWKS, audience pin enforced
7. **Receipt:** Ed25519-signed per-inference proof bundle with request/response hashes

## Approximate Cost

- 4 CVM instances launched (3 debug, 1 non-debug), each ~2-10 minutes
- Estimated total: ~$0.15 (c3-standard-4 at $0.209/hr)

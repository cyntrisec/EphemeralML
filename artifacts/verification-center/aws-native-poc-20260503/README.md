# AWS Native PoC Verification Center Evidence

Generated from the AWS Nitro smoke-test bundle uploaded on 2026-05-03.

The public artifact uses a redacted evidence URI:

`s3://redacted-customer-evidence-bucket/smoke-tests/20260503T142806Z/`

Included files:

- `runtime-passport.json`
- `runtime-passport.md`
- `runtime-passport.html`
- `execution-report/verification-report.json`
- `execution-report/verification-report.md`
- `execution-report/verification-report.html`
- `execution-report/SHA256SUMS`
- `SHA256SUMS`

Result:

- Runtime Passport: `overall_status=pass`
- Runtime Passport SHA-256: `20b69eec5fec2b905878c865c613ed31005fcb2835d22a91c5564394a99b55f9`
- Execution Report: `overall_status=pass`
- Execution Report assurance level: `tee_provenance`
- Execution Report SHA-256: `d84be7201028379afcae6fe2c5d22523046829bfe815c10041725d7ffcf6be48`
- Doctor: `6/6`
- Smoke test: bundle-derived pass from `manifest.json`, 12 required files, and 3/3 negative tests
- Runtime: AWS Nitro on `m7i.xlarge`
- EIF PCR0: `184b2a72e7bbe6d84dfddc586d3ce7ecc49085c044f31594e67042b6a5ff4e010f7a2052e430190b6bb54762059c4b21`

What this proves:

- The v3 bundle includes `attestation.cbor` as a hashed file.
- The AIR receipt verifies offline.
- The AIR receipt's attestation-document hash binds to the supplied Nitro attestation sidecar.
- The receipt signing key matches the public key carried by the attestation sidecar.
- The report records `attestation_provenance=bundle`, so the attestation sidecar is part of the hashed evidence bundle rather than an unaudited loose sidecar.
- The Runtime Passport links the execution evidence to AWS region/runtime metadata and a redacted S3 evidence URI.

Important limitation:

This is internal PoC evidence. The doctor EIF check is rendered as `Skip`, not
`Pass`, because the host does not currently have an adjacent
`ephemeralml-pilot.eif.cosign.bundle` and the explicit internal-PoC override was
enabled. The passport and linked execution report both preserve that fact in a
top-level warning and in `limitations[]`.

Production buyer evidence requires the release pipeline to attach and verify the
EIF cosign bundle, then rerun this flow without
`CYNTRISEC_DOCTOR_ALLOW_UNSIGNED_EIF_FOR_POC`.

Operational note:

The v3 rerun temporarily added a narrow KMS key-policy statement so the deployer
could upload the smoke-test binary through the evidence bucket's mandatory
SSE-KMS policy. The statement was removed after the run and the Nitro host was
stopped.

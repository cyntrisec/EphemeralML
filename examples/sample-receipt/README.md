# Sample Receipt Verification

This example lets a reviewer exercise the Cyntrisec verifier without deploying AWS.

The sample uses the AIR v1 Nitro golden vector in [`../../spec/v1/vectors/valid/v1-nitro-no-nonce.json`](../../spec/v1/vectors/valid/v1-nitro-no-nonce.json). It is a conformance vector, not a live customer inference bundle. A full Cluster A bundle sample will be published from the real-AWS smoke run.

Requires `jq` and `xxd`.

From the repository root:

```bash
VECTOR=spec/v1/vectors/valid/v1-nitro-no-nonce.json
jq -r .receipt_hex "$VECTOR" | xxd -r -p > /tmp/cyntrisec-air-v1.cbor
PUBLIC_KEY="$(jq -r .public_key_hex "$VECTOR")"

cargo run -p ephemeral-ml-client --bin cyntrisec-verify -- \
  /tmp/cyntrisec-air-v1.cbor \
  --public-key "$PUBLIC_KEY" \
  --expected-model minilm-l6-v2 \
  --expected-security-mode production \
  --max-age 0
```

Expected outcome: verifier exits `0` and prints a verified AIR receipt result.

What this proves:

- the receipt parses as AIR v1
- the Ed25519 receipt signature verifies
- caller-supplied model and security-mode expectations are enforced

What this does not prove:

- live AWS Nitro attestation
- the Cluster A S3 bundle layout
- customer model deployment

Use [`../../docs/pilot-deployment-runbook.md`](../../docs/pilot-deployment-runbook.md) for the full AWS BYOC pilot path.

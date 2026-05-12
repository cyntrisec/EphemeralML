# Cyntrisec Egress Protocol v1

## Status

v1.0 FROZEN. Future incompatible changes require a new schema version.

## Purpose

This protocol defines the enclave-to-host egress messages used when an attested worker needs a parent-side helper to call AWS services.

The v1 operations are:

- `kms_decrypt` — request KMS decryption of an encrypted model key or data key.
- `s3_put_object` — write an already-built receipt bundle object to customer S3.

The byte relay for inference traffic is intentionally separate. This protocol is for low-volume AWS egress helper calls and carries binary payloads directly.

## Wire Format

Requests and responses are deterministic CBOR arrays with schema version first:

```text
request  = [1, op_tag, payload]
response = [1, result_tag, payload]
```

Request `op_tag` values:

- `"kms_decrypt"`
- `"s3_put_object"`

Response `result_tag` values:

- `"ok"`
- `"err"`

Payloads are CBOR maps encoded according to [cddl/egress-protocol-v1.cddl](cddl/egress-protocol-v1.cddl).

## Operations

### KMS Decrypt

Request fields:

- `ciphertext`: KMS ciphertext blob bytes.
- `key_arn`: KMS key ARN.
- `encryption_context`: optional string map passed to KMS.

Successful response:

- `plaintext`: decrypted plaintext bytes.

### S3 PutObject

Request fields:

- `bucket`: destination bucket name.
- `key`: destination object key.
- `body`: object bytes, usually a receipt bundle tarball.
- `content_type`: optional object content type.
- `kms_key_arn`: optional SSE-KMS key ARN for evidence object encryption.
- `metadata`: optional S3 metadata map.

Successful response:

- `etag`: S3 ETag returned by PutObject.
- `version_id`: optional S3 object version ID.

## Errors

Errors use stable dotted code strings and human-readable messages:

```text
{
  code: tstr,
  message: tstr,
  ? aws_request_id: tstr
}
```

Example codes include:

- `kms.access_denied`
- `kms.invalid_ciphertext`
- `kms.attestation_mismatch`
- `s3.access_denied`
- `s3.no_such_bucket`
- `s3.kms_key_disabled`

## Connection Model

v1 uses one vsock connection per request. The enclave opens a connection, sends one request CBOR value, reads one response CBOR value, and closes the connection.

No multiplexing, streaming, or persistent sessions are defined in v1.

## Golden Vectors

CBOR hex vectors live in [vectors/egress/](vectors/egress/):

| File | Decoded Shape |
|------|---------------|
| `kms-decrypt-request.cbor.hex` | `[1, "kms_decrypt", {"ciphertext": h'c0ffee', "key_arn": "arn:aws:kms:us-east-1:111122223333:key/model", "encryption_context": {"model": "llama-3.1-8b"}}]` |
| `s3-put-object-request.cbor.hex` | `[1, "s3_put_object", {"bucket": "cyntrisec-evidence", "key": "bundles/receipt.tar.gz", "body": h'1f8b08', "content_type": "application/gzip", "kms_key_arn": "arn:aws:kms:us-east-1:111122223333:key/evidence", "metadata": {"air-receipt-sha256": "abc123"}}]` |
| `kms-decrypt-ok-response.cbor.hex` | `[1, "ok", {"op": "kms_decrypt", "data": {"plaintext": h'deadbeef'}}]` |
| `s3-put-object-ok-response.cbor.hex` | `[1, "ok", {"op": "s3_put_object", "data": {"etag": "\"abc123\"", "version_id": "3Lg..."}}]` |
| `error-response.cbor.hex` | `[1, "err", {"code": "s3.access_denied", "message": "put object denied", "aws_request_id": "REQ123"}]` |

## Verification Rules

- Decoders MUST reject any `schema_version` other than `1`.
- Decoders MUST reject unknown request operation tags.
- Decoders MUST reject unknown response result tags.
- Decoders MUST reject unknown `ok` operation variants.
- Binary payloads MUST be encoded as CBOR byte strings, not base64 text.

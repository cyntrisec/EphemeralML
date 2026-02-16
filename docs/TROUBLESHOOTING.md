# Troubleshooting Guide

## Error Code Reference

All EphemeralML errors follow the format `E{code}: {message}`.

### Model / Decomposition (1000-1099)

| Code | Variant | Redacted Message |
|------|---------|------------------|
| E1001 | DecompositionError | Model decomposition failed |
| E1002 | ValidationError | Model validation failed |
| E1003 | Validation | Input validation failed |
| E1004 | UnsupportedOperatorError | Unsupported model operator |

### Security (1100-1199)

| Code | Variant | Redacted Message |
|------|---------|------------------|
| E1100 | AttestationError | Attestation verification failed |
| E1101 | EncryptionError | Encryption operation failed |
| E1102 | DecryptionError | Decryption operation failed |
| E1103 | KmsError | Key management service error |

### Communication (1200-1299)

| Code | Variant | Redacted Message |
|------|---------|------------------|
| E1200 | CommunicationError | Communication error |
| E1201 | VSockError | Internal communication error |
| E1202 | NetworkError | Network error |

### Inference (1300-1399)

| Code | Variant | Redacted Message |
|------|---------|------------------|
| E1300 | AssemblyError | Model assembly failed |
| E1301 | InferenceError | Inference execution failed |
| E1302 | MemorySecurityError | Security boundary violation |

### System (1400-1499)

| Code | Variant | Redacted Message |
|------|---------|------------------|
| E1400 | StorageError | Storage operation failed |
| E1401 | ProxyError | Proxy operation failed |
| E1402 | IoError | I/O error |
| E1403 | SerializationError | Data format error |
| E1404 | ConfigurationError | Configuration error |

### Client (1500-1599)

| Code | Variant | Redacted Message |
|------|---------|------------------|
| E1500 | InvalidInput | Invalid input provided |
| E1501 | ResourceExhausted | Resource limit exceeded |
| E1502 | Timeout | Operation timed out |
| E1503 | ProtocolError | Protocol violation |

### Internal (1900-1999)

| Code | Variant | Redacted Message |
|------|---------|------------------|
| E1900 | Internal | Internal server error |
| E1901 | TransportError | Transport error |

## Common Failures

### KMS Permission Denied (E1103)

**Symptom**: `E1103: Key management service error` in logs.

**Causes**:
1. WIP binding mismatch — the Workload Identity Pool provider condition doesn't match the workload
2. Service account missing `roles/cloudkms.cryptoKeyDecrypter`
3. Wrong `--gcp-wip-audience` value

**Fix**:
```bash
# Check WIP provider conditions
gcloud iam workload-identity-pools providers describe PROVIDER \
    --location=global --workload-identity-pool=POOL --project=PROJECT

# Verify SA has KMS role
gcloud kms keys get-iam-policy KEY_NAME --project=PROJECT
```

### Model Hash Mismatch (E1003)

**Symptom**: `Model hash mismatch` in logs, container exits.

**Causes**:
1. `--expected-model-hash` doesn't match the actual model uploaded to GCS
2. Model was re-encrypted but hash was not updated

**Fix**:
```bash
# Re-run package_model.sh and use the printed hash
bash scripts/gcp/package_model.sh test_assets/minilm models/minilm
# Use the new hash in deploy.sh --model-hash
```

### Attestation Failure

**Symptom**: Container fails to start, no inference endpoint available.

**Causes**:
1. Machine type is not TDX-capable (must be `c3-standard-*`)
2. `--maintenance-policy=TERMINATE` not set
3. Wrong zone (TDX not available in all zones)

**Fix**:
```bash
# Verify machine type
gcloud compute instances describe ephemeralml-cvm --zone=us-central1-a \
    --format='value(machineType)'

# Should contain: c3-standard-4
```

### Container Not Starting

**Symptom**: VM is RUNNING but no response on port 9000.

**Causes**:
1. Container still pulling (takes ~30-60s)
2. Image build failed (check Artifact Registry)
3. Workload crashed on startup

**Diagnostic**:
```bash
# Check serial console output
gcloud compute instances get-serial-port-output ephemeralml-cvm \
    --zone=us-central1-a --project=PROJECT 2>&1 | tail -50

# SSH into debug image
gcloud compute ssh ephemeralml-cvm --zone=us-central1-a --project=PROJECT

# Inside the VM:
sudo journalctl -u tee-container-runner -f
sudo docker ps -a
sudo docker logs $(sudo docker ps -aq | head -1)
```

### Manifest Signature Failed

**Symptom**: `Manifest signature verification failed` in logs.

**Causes**:
1. Wrong env var: `EPHEMERALML_MODEL_SIGNING_KEY` is the private key (for `package_model.sh`).
   The enclave needs `EPHEMERALML_MODEL_SIGNING_PUBKEY` (public key, 64 hex chars).
2. Key mismatch between packaging and enclave
3. Manifest was modified after signing
4. Manifest missing from GCS when `EPHEMERALML_MODEL_SIGNING_PUBKEY` is set

**Fix**: Ensure the enclave has `EPHEMERALML_MODEL_SIGNING_PUBKEY` set to the **public key** hex
(printed by `package_model.sh` as `EPHEMERALML_MODEL_SIGNING_PUBKEY: <hex>`).
The private key (`EPHEMERALML_MODEL_SIGNING_KEY`) is only used by `package_model.sh`.

## Structured Logging

### Enable JSON Logs

```bash
EPHEMERALML_LOG_FORMAT=json
```

### Log Fields

Trust-critical log entries include structured fields:

| Field | Description |
|-------|-------------|
| `step` | Pipeline step (model_load, kms_decrypt, attestation, hash_verify, boot_evidence, manifest) |
| `source` | Model source (local, gcs, gcs-kms) |
| `hash` | Model hash (hex) |
| `model_id` | Model identifier |
| `elapsed_ms` | Operation duration in milliseconds |

### Parse JSON Logs

```bash
# Extract all model_load events
gcloud compute ssh ephemeralml-cvm --command='sudo journalctl -u tee-container-runner --no-pager' \
    | grep '"step":"model_load"' | jq .

# Get boot evidence
... | grep '"step":"boot_evidence"' | jq .
```

## Diagnostic Commands

```bash
# Check instance status
gcloud compute instances describe ephemeralml-cvm --zone=us-central1-a

# View container logs (debug image only)
gcloud compute ssh ephemeralml-cvm --zone=us-central1-a \
    --command='sudo journalctl -u tee-container-runner -n 100'

# Check firewall rules
gcloud compute firewall-rules list --filter="name=allow-ephemeralml"

# Test connectivity
nc -zv EXTERNAL_IP 9000

# Check Cloud KMS key access
gcloud kms keys list --location=global --keyring=ephemeralml --project=PROJECT
```

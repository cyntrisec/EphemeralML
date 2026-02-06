# Public Artifact Publication (No AWS Access Needed)

This guide publishes benchmark evidence so readers can verify paper claims without any AWS credentials.

## Why

- `s3://...` links usually require IAM access
- Public release assets are easier for reviewers and readers
- Checksums make integrity verifiable

## 1) Prepare a safe public bundle

```bash
./scripts/prepare_public_artifact.sh \
  --input-dir benchmark_results_final/kms_validation_20260205_234917 \
  --name kms_validation_20260205_234917.tar.gz
```

Outputs in `artifacts/public/`:

- `kms_validation_20260205_234917.tar.gz`
- `kms_validation_20260205_234917.tar.gz.sha256`
- `kms_validation_20260205_234917.tar.gz.manifest.txt`

The script scans for common sensitive markers (ARNs, instance IDs, access keys, IPv4, account-ID contexts) and fails by default if found.

## 2) Upload to GitHub Release

Authenticate once:

```bash
gh auth login -h github.com
```

Upload to an existing tag (example `v1.0.0`):

```bash
./scripts/publish_public_artifact.sh \
  --tag v1.0.0 \
  --artifact artifacts/public/kms_validation_20260205_234917.tar.gz
```

## 3) What to place in the paper

- Release page URL (stable):
  `https://github.com/cyntrisec/EphemeralML/releases/tag/v1.0.0`
- Artifact file name:
  `kms_validation_20260205_234917.tar.gz`
- SHA-256 checksum:
  `20309ab610e7321de5e29d019f0d4b15fee6a7cdafe919686ec1cbd4fabe5937`

## 4) Reader verification

After download:

```bash
sha256sum -c kms_validation_20260205_234917.tar.gz.sha256
```

Expected output:

- `...: OK`

## Optional: Zenodo DOI

If you need archival citation quality:

1. Connect the GitHub repo to Zenodo.
2. Archive the release containing the artifact.
3. Add DOI to paper provenance and README.

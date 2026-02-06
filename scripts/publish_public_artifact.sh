#!/usr/bin/env bash
# publish_public_artifact.sh
# Upload prepared benchmark artifact files to an existing GitHub Release.
#
# Example:
#   ./scripts/publish_public_artifact.sh \
#     --tag v1.0.0 \
#     --artifact artifacts/public/kms_validation_20260205_234917.tar.gz

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: publish_public_artifact.sh --tag TAG --artifact FILE [options]

Required:
  --tag TAG             Existing release tag (example: v1.0.0)
  --artifact FILE       Path to .tar.gz created by prepare_public_artifact.sh

Optional:
  --repo OWNER/REPO     GitHub repo (default: cyntrisec/EphemeralML)
  -h, --help            Show this help

Uploads:
  - <artifact>.tar.gz
  - <artifact>.tar.gz.sha256
  - <artifact>.tar.gz.manifest.txt
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $1" >&2
        exit 1
    fi
}

TAG=""
ARTIFACT=""
REPO="cyntrisec/EphemeralML"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)
            TAG="${2:-}"
            shift 2
            ;;
        --artifact)
            ARTIFACT="${2:-}"
            shift 2
            ;;
        --repo)
            REPO="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if [[ -z "$TAG" || -z "$ARTIFACT" ]]; then
    echo "ERROR: --tag and --artifact are required" >&2
    usage
    exit 1
fi

require_cmd gh

if ! gh auth status -h github.com >/dev/null 2>&1; then
    echo "ERROR: gh is not authenticated. Run: gh auth login -h github.com" >&2
    exit 1
fi

if [[ ! -f "$ARTIFACT" ]]; then
    echo "ERROR: artifact not found: $ARTIFACT" >&2
    exit 1
fi

SHA_FILE="${ARTIFACT}.sha256"
MANIFEST_FILE="${ARTIFACT}.manifest.txt"
for f in "$SHA_FILE" "$MANIFEST_FILE"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: companion file missing: $f" >&2
        exit 1
    fi
done

echo "Uploading files to release $TAG in $REPO..."
gh release upload "$TAG" \
    "$ARTIFACT" \
    "$SHA_FILE" \
    "$MANIFEST_FILE" \
    --clobber \
    --repo "$REPO"

ASSET_NAME="$(basename "$ARTIFACT")"
echo
echo "Published."
echo "Release page: https://github.com/$REPO/releases/tag/$TAG"
echo "Direct asset: https://github.com/$REPO/releases/download/$TAG/$ASSET_NAME"
echo "Checksum file: https://github.com/$REPO/releases/download/$TAG/$(basename "$SHA_FILE")"

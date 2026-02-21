#!/usr/bin/env bash
# Deploy cyntrisec.com marketing site to AWS S3
set -euo pipefail

BUCKET="${CYNTRISEC_S3_BUCKET:?Set CYNTRISEC_S3_BUCKET to your S3 bucket name}"
DISTRIBUTION_ID="${CYNTRISEC_CF_DISTRIBUTION:-}"

echo "Deploying marketing site to s3://${BUCKET}/ ..."

aws s3 sync site/marketing/ "s3://${BUCKET}/" \
  --delete \
  --exclude "shared/*" \
  --cache-control "max-age=3600"

# Shared assets (brand.css) referenced by the marketing site via ../shared/
aws s3 sync site/shared/ "s3://${BUCKET}/shared/" \
  --cache-control "max-age=3600"

echo "Upload complete."

if [ -n "${DISTRIBUTION_ID}" ]; then
  echo "Invalidating CloudFront distribution ${DISTRIBUTION_ID} ..."
  aws cloudfront create-invalidation \
    --distribution-id "${DISTRIBUTION_ID}" \
    --paths "/*"
  echo "Invalidation created."
fi

echo "Done."

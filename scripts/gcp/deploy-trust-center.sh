#!/usr/bin/env bash
# Build, scan, deploy, test, and promote the public Verification Center.
# The existing serving revision remains available for immediate rollback.

set -euo pipefail

PROJECT_ID="${1:?usage: $0 PROJECT_ID [REGION]}"
REGION="${2:-us-central1}"
SERVICE="${TRUST_CENTER_SERVICE:-trust-center}"
RUNTIME_SERVICE_ACCOUNT="${TRUST_CENTER_RUNTIME_SERVICE_ACCOUNT:-trust-center-runner@${PROJECT_ID}.iam.gserviceaccount.com}"
LIVE_URL="${TRUST_CENTER_LIVE_URL:-https://verify.cyntrisec.com}"
PROXY_PORT="${TRUST_CENTER_PROXY_PORT:-18081}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

for command_name in curl gcloud git jq; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "ERROR: required command not found: $command_name" >&2
        exit 2
    fi
done

if [[ -n "$(git -C "$REPO_DIR" status --porcelain)" ]]; then
    echo "ERROR: refusing to deploy from a dirty worktree" >&2
    exit 2
fi

git_sha="$(git -C "$REPO_DIR" rev-parse HEAD)"
upstream_sha="$(git -C "$REPO_DIR" rev-parse '@{upstream}' 2>/dev/null || true)"
if [[ -z "$upstream_sha" || "$git_sha" != "$upstream_sha" ]]; then
    echo "ERROR: refusing to deploy a commit that is not the current upstream tip" >&2
    echo "Local:    $git_sha" >&2
    echo "Upstream: ${upstream_sha:-not configured}" >&2
    exit 2
fi

short_sha="${git_sha:0:12}"
image_tag="${REGION}-docker.pkg.dev/${PROJECT_ID}/cloud-run-source-deploy/trust-center:verify-${short_sha}"
candidate_tag="candidate-${short_sha}"

previous_revision="$(gcloud run services describe "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" --format=json \
    | jq -r '[.status.traffic[] | select(.percent == 100)][0].revisionName')"

echo "Building and scanning $image_tag from $git_sha"
gcloud builds submit "$REPO_DIR" \
    --project "$PROJECT_ID" \
    --config "$REPO_DIR/cloudbuild-verifier.yaml" \
    --substitutions "_GIT_SHA=${git_sha},_IMAGE=${image_tag}"

image_digest="$(gcloud artifacts docker images describe "$image_tag" \
    --project "$PROJECT_ID" --format='value(image_summary.fully_qualified_digest)')"
if [[ -z "$image_digest" || "$image_digest" != *@sha256:* ]]; then
    echo "ERROR: failed to resolve immutable image digest for $image_tag" >&2
    exit 2
fi

echo "Deploying candidate from $image_digest"
gcloud run deploy "$SERVICE" \
    --project "$PROJECT_ID" \
    --region "$REGION" \
    --image "$image_digest" \
    --service-account "$RUNTIME_SERVICE_ACCOUNT" \
    --set-env-vars EPHEMERALML_VERIFIER_MODE=public-trust-center,EPHEMERALML_VERIFIER_RATE_LIMIT=60 \
    --cpu 1 \
    --memory 256Mi \
    --concurrency 20 \
    --timeout 30 \
    --min-instances 0 \
    --max-instances 1 \
    --ingress all \
    --allow-unauthenticated \
    --no-default-url \
    --startup-probe 'httpGet.path=/health,httpGet.port=8080,timeoutSeconds=5,periodSeconds=10,failureThreshold=12' \
    --liveness-probe 'httpGet.path=/health,httpGet.port=8080,initialDelaySeconds=5,timeoutSeconds=5,periodSeconds=30,failureThreshold=3' \
    --revision-suffix "git-${short_sha}" \
    --tag "$candidate_tag" \
    --no-traffic

candidate_revision="$(gcloud run services describe "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" \
    --format='value(status.latestCreatedRevisionName)')"
if [[ -z "$candidate_revision" ]]; then
    echo "ERROR: Cloud Run did not report a candidate revision" >&2
    exit 2
fi

proxy_log="$(mktemp /tmp/trust-center-proxy.XXXXXX)"
proxy_pid=""
cleanup() {
    if [[ -n "$proxy_pid" ]] && kill -0 "$proxy_pid" 2>/dev/null; then
        kill "$proxy_pid" 2>/dev/null || true
        wait "$proxy_pid" 2>/dev/null || true
    fi
    rm -f "$proxy_log"
}
trap cleanup EXIT

gcloud run services proxy "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" \
    --tag "$candidate_tag" --port "$PROXY_PORT" >"$proxy_log" 2>&1 &
proxy_pid=$!

candidate_url="http://127.0.0.1:${PROXY_PORT}"
ready=false
for _ in $(seq 1 30); do
    if curl -fsS --max-time 3 "$candidate_url/health" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 2
done
if [[ "$ready" != true ]]; then
    echo "ERROR: candidate proxy did not become healthy" >&2
    sed -n '1,120p' "$proxy_log" >&2
    exit 1
fi

bash "$REPO_DIR/scripts/smoke-test.sh" "$candidate_url"
bash "$REPO_DIR/scripts/trust-center-conformance.sh" "$candidate_url"
EXPECTED_BUILD_SHA="$git_sha" bash "$REPO_DIR/scripts/trust-center-drift-check.sh" "$candidate_url"

cleanup
proxy_pid=""
trap - EXIT

# Candidate and live gates together exceed the production 60 rpm ceiling when
# Cloud Run presents the same proxy peer IP to the in-process limiter. Let the
# candidate window expire before exercising the promoted revision.
echo "Waiting for the candidate rate-limit window to expire"
sleep 30
echo "Rate-limit reset: 31 seconds remaining"
sleep 31

echo "Promoting $candidate_revision to 100% traffic"
gcloud run services update-traffic "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" \
    --to-revisions "${candidate_revision}=100"

if ! bash "$REPO_DIR/scripts/smoke-test.sh" "$LIVE_URL" \
    || ! bash "$REPO_DIR/scripts/trust-center-conformance.sh" "$LIVE_URL" \
    || ! EXPECTED_BUILD_SHA="$git_sha" bash "$REPO_DIR/scripts/trust-center-drift-check.sh" "$LIVE_URL"; then
    echo "ERROR: post-promotion checks failed; rolling traffic back to $previous_revision" >&2
    gcloud run services update-traffic "$SERVICE" \
        --project "$PROJECT_ID" --region "$REGION" \
        --to-revisions "${previous_revision}=100"
    exit 1
fi

gcloud run services update-traffic "$SERVICE" \
    --project "$PROJECT_ID" --region "$REGION" --clear-tags

echo "PASS: $candidate_revision serves 100% of traffic; rollback target is $previous_revision"

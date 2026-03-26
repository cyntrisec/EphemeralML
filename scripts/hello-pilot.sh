#!/usr/bin/env bash
# EphemeralML — "Hello Pilot in 15 Minutes"
#
# A self-contained onboarding script for pilot customers. Uses only Docker
# and curl — no Rust toolchain, no Python required (optional Python step).
#
# Usage:
#   bash scripts/hello-pilot.sh          # Run from repo root
#   bash scripts/hello-pilot.sh --skip-cleanup   # Leave stack running after demo
#
# Prerequisites:
#   - Docker with "docker compose" (v2+)
#   - curl
#   - (Optional) python3 + openai package for SDK demo step
#
# What this script does:
#   1. Builds & starts the EphemeralML gateway + mock backend via Docker Compose
#   2. Runs 5 narrated demo steps (health, models, embeddings, chat error, metadata)
#   3. (Optional) Runs a 6th step using the OpenAI Python SDK
#   4. Prints a summary with elapsed time and receipt count
#   5. Tears down the Docker stack on exit (unless --skip-cleanup)
set -euo pipefail

# ---------------------------------------------------------------------------
# Constants & paths
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_DIR="$PROJECT_DIR/gateway-api"
COMPOSE_FILE="$COMPOSE_DIR/compose.yaml"
GATEWAY_URL="http://localhost:8090"
RECEIPT_COUNT=0
SKIP_CLEANUP=false
START_TIME=""

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------

for arg in "$@"; do
    case "$arg" in
        --skip-cleanup) SKIP_CLEANUP=true ;;
        --help|-h)
            echo "Usage: bash scripts/hello-pilot.sh [--skip-cleanup]"
            echo ""
            echo "  --skip-cleanup   Leave Docker stack running after demo"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: bash scripts/hello-pilot.sh [--skip-cleanup]"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Source UI helpers (if available)
# ---------------------------------------------------------------------------

if [ -f "$SCRIPT_DIR/lib/ui.sh" ]; then
    source "$SCRIPT_DIR/lib/ui.sh"
else
    # Minimal fallback
    _UI_BOLD=""; _UI_GREEN=""; _UI_RED=""; _UI_YELLOW=""; _UI_DIM=""; _UI_RESET=""
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
        _UI_BOLD="\033[1m"; _UI_GREEN="\033[32m"; _UI_RED="\033[31m"
        _UI_YELLOW="\033[33m"; _UI_DIM="\033[2m"; _UI_RESET="\033[0m"
    fi
    ui_header() { echo -e "\n  ${_UI_BOLD}$1${_UI_RESET}\n"; }
    ui_ok() { echo -e "  ${_UI_GREEN}${_UI_BOLD}$1${_UI_RESET}"; }
    ui_fail() { echo -e "  ${_UI_RED}${_UI_BOLD}$1${_UI_RESET}"; }
    ui_warn() { echo -e "  ${_UI_YELLOW}$1${_UI_RESET}"; }
    ui_info() { echo "  $1"; }
    ui_blank() { echo; }
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

elapsed_since_start() {
    local now
    now=$(date +%s)
    local diff=$(( now - START_TIME ))
    local min=$(( diff / 60 ))
    local sec=$(( diff % 60 ))
    if [ "$min" -gt 0 ]; then
        echo "${min}m ${sec}s"
    else
        echo "${sec}s"
    fi
}

step_header() {
    local step_num="$1"
    local total="$2"
    local title="$3"
    echo ""
    echo -e "  ${_UI_BOLD}[Step ${step_num}/${total}] ${title}${_UI_RESET}"
    echo -e "  ${_UI_DIM}$(printf -- '-%.0s' {1..58})${_UI_RESET}"
}

step_pass() {
    local msg="$1"
    echo -e "  ${_UI_GREEN}[PASS]${_UI_RESET} ${msg}"
}

step_fail() {
    local msg="$1"
    echo -e "  ${_UI_RED}[FAIL]${_UI_RESET} ${msg}"
}

step_skip() {
    local msg="$1"
    echo -e "  ${_UI_YELLOW}[SKIP]${_UI_RESET} ${msg}"
}

check_receipt_headers() {
    local headers="$1"
    local has_receipt=false
    if echo "$headers" | grep -qi "x-ephemeralml-receipt-present: true"; then
        has_receipt=true
        RECEIPT_COUNT=$((RECEIPT_COUNT + 1))
    fi
    if echo "$headers" | grep -qi "x-ephemeralml-attestation-mode"; then
        local mode
        mode=$(echo "$headers" | grep -i "x-ephemeralml-attestation-mode" | head -1 | sed 's/.*: //' | tr -d '\r')
        ui_info "  Attestation mode:  $mode"
    fi
    if echo "$headers" | grep -qi "x-ephemeralml-receipt-sha256"; then
        local sha
        sha=$(echo "$headers" | grep -i "x-ephemeralml-receipt-sha256" | head -1 | sed 's/.*: //' | tr -d '\r')
        ui_info "  Receipt SHA-256:   ${sha:0:16}..."
    fi
    if echo "$headers" | grep -qi "x-request-id"; then
        local rid
        rid=$(echo "$headers" | grep -i "x-request-id" | head -1 | sed 's/.*: //' | tr -d '\r')
        ui_info "  Request ID:        $rid"
    fi
    $has_receipt
}

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------

check_prerequisites() {
    ui_header "Checking prerequisites"
    local ok=true

    # Docker
    if command -v docker &>/dev/null; then
        local docker_version
        docker_version=$(docker --version 2>/dev/null || echo "unknown")
        ui_info "Docker:          $docker_version"
    else
        ui_fail "Docker not found. Install: https://docs.docker.com/get-docker/"
        ok=false
    fi

    # Docker Compose v2
    if docker compose version &>/dev/null 2>&1; then
        local compose_version
        compose_version=$(docker compose version --short 2>/dev/null || echo "unknown")
        ui_info "Docker Compose:  v${compose_version}"
    else
        ui_fail "docker compose (v2) not found. Update Docker or install compose plugin."
        ok=false
    fi

    # Docker daemon running
    if ! docker info &>/dev/null 2>&1; then
        ui_fail "Docker daemon not running. Start Docker and try again."
        ok=false
    fi

    # curl
    if command -v curl &>/dev/null; then
        ui_info "curl:            $(curl --version 2>/dev/null | head -1)"
    else
        ui_fail "curl not found. Install curl and try again."
        ok=false
    fi

    # jq (optional but helpful)
    if command -v jq &>/dev/null; then
        ui_info "jq:              $(jq --version 2>/dev/null)"
    else
        ui_warn "jq not found (optional — JSON output will not be pretty-printed)"
    fi

    # Python + openai (optional for step 6)
    if command -v python3 &>/dev/null; then
        if python3 -c "import openai" 2>/dev/null; then
            ui_info "Python + OpenAI: available (step 6 will run)"
        else
            ui_warn "Python found but 'openai' package missing (step 6 skipped)"
            ui_warn "  Install: pip install openai"
        fi
    else
        ui_warn "python3 not found (step 6 skipped — optional)"
    fi

    ui_blank

    if ! $ok; then
        ui_fail "Missing prerequisites. Fix the issues above and try again."
        exit 1
    fi
    ui_ok "All required prerequisites met."
}

# ---------------------------------------------------------------------------
# Docker stack management
# ---------------------------------------------------------------------------

compose_cmd() {
    docker compose -f "$COMPOSE_FILE" "$@"
}

teardown() {
    if $SKIP_CLEANUP; then
        ui_blank
        ui_warn "Stack left running (--skip-cleanup). To stop:"
        ui_info "  docker compose -f gateway-api/compose.yaml down -v"
        return 0
    fi
    ui_blank
    ui_info "Tearing down Docker stack..."
    compose_cmd down -v --remove-orphans 2>/dev/null || true
    ui_info "Cleanup complete."
}

# Trap for cleanup on exit / Ctrl+C
cleanup_on_exit() {
    local exit_code=$?
    # Only tear down if we actually started the stack
    if [ -n "$START_TIME" ]; then
        teardown
    fi
    exit $exit_code
}
trap cleanup_on_exit EXIT INT TERM

start_stack() {
    ui_header "Starting EphemeralML gateway (Docker Compose)"

    # Tear down any existing stack first (idempotent)
    ui_info "Removing any existing stack..."
    compose_cmd down -v --remove-orphans 2>/dev/null || true

    # Build and start with capabilities that match the mock backend (MiniLM = embeddings)
    # Enable metadata JSON from the start so step 5 can show in-body receipts.
    ui_info "Building and starting containers (this may take a few minutes on first run)..."
    ui_blank

    EPHEMERALML_MODEL_CAPABILITIES="chat,embeddings" \
    EPHEMERALML_INCLUDE_METADATA_JSON=true \
        compose_cmd up --build -d 2>&1 | tail -20

    ui_blank
    ui_info "Waiting for gateway to start..."

    # Wait for the health endpoint to respond (gateway HTTP server is up).
    # The backend connection is established lazily on the first real request.
    local attempts=0
    local max_attempts=60
    while [ $attempts -lt $max_attempts ]; do
        local health_code
        health_code=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/health" 2>/dev/null || echo "000")
        if [ "$health_code" = "200" ]; then
            ui_ok "Gateway is up!"
            return 0
        fi
        sleep 1
        attempts=$((attempts + 1))
        if [ $((attempts % 10)) -eq 0 ]; then
            ui_info "  Still waiting... (${attempts}s)"
        fi
    done

    ui_fail "Gateway did not start within ${max_attempts}s"
    ui_info "Checking container logs:"
    compose_cmd logs --tail=30 2>/dev/null || true
    exit 1
}

# ---------------------------------------------------------------------------
# Demo steps
# ---------------------------------------------------------------------------

TOTAL_STEPS=5

step_1_health() {
    step_header 1 "$TOTAL_STEPS" "Health Check"
    ui_info "Checking gateway health and triggering backend connection..."
    ui_blank

    # /health (always responds, even before backend connection)
    local health_body
    health_body=$(curl -s "$GATEWAY_URL/health" 2>/dev/null)
    if [ -z "$health_body" ]; then
        step_fail "No response from /health"
        return 1
    fi
    ui_info "  GET /health:"
    if command -v jq &>/dev/null; then
        echo "$health_body" | jq '.' 2>/dev/null | sed 's/^/    /'
    else
        echo "    $health_body"
    fi
    ui_blank

    # Trigger lazy backend connection with a warm-up embeddings request.
    # The first request establishes the secure channel (handshake ~100ms).
    ui_info "  Establishing secure channel to backend..."
    local warmup_code
    warmup_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$GATEWAY_URL/v1/embeddings" \
        -H "Content-Type: application/json" \
        -d '{"model":"warmup","input":"connection test"}' \
        2>/dev/null || echo "000")

    if [ "$warmup_code" = "200" ]; then
        ui_info "  Secure channel established (warmup HTTP $warmup_code)"
    else
        ui_warn "  Warmup returned HTTP $warmup_code (may need a moment)"
        # Retry once after a short wait
        sleep 3
        warmup_code=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "$GATEWAY_URL/v1/embeddings" \
            -H "Content-Type: application/json" \
            -d '{"model":"warmup","input":"connection test"}' \
            2>/dev/null || echo "000")
        if [ "$warmup_code" = "200" ]; then
            ui_info "  Secure channel established on retry (HTTP $warmup_code)"
        else
            ui_warn "  Backend connection returned HTTP $warmup_code"
        fi
    fi
    ui_blank

    # Now check readyz (should be 200 after successful connection)
    local readyz_code
    readyz_code=$(curl -s -o /dev/null -w "%{http_code}" "$GATEWAY_URL/readyz" 2>/dev/null)
    ui_info "  GET /readyz: HTTP $readyz_code"

    if [ "$readyz_code" = "200" ]; then
        step_pass "Gateway healthy, backend connected"
    else
        ui_warn "  readyz returned $readyz_code — backend may still be connecting"
        step_pass "Gateway is up (backend connection may be lazy)"
    fi
}

step_2_models() {
    step_header 2 "$TOTAL_STEPS" "List Models"
    ui_info "Discovering available models and their capabilities..."
    ui_blank

    local models_body
    models_body=$(curl -s "$GATEWAY_URL/v1/models" 2>/dev/null)
    if [ -z "$models_body" ]; then
        step_fail "No response from /v1/models"
        return 1
    fi

    if command -v jq &>/dev/null; then
        echo "$models_body" | jq '.' 2>/dev/null | sed 's/^/    /'
    else
        echo "    $models_body"
    fi
    ui_blank

    # Check for capabilities
    if echo "$models_body" | grep -q "ephemeralml"; then
        ui_info "  The _ephemeralml.capabilities field shows what each model supports."
        ui_info "  This mock backend uses MiniLM — an embedding model."
        step_pass "Models listed with capability metadata"
    else
        step_fail "Missing _ephemeralml capabilities in model response"
        return 1
    fi
}

step_3_embeddings() {
    step_header 3 "$TOTAL_STEPS" "Embeddings with Attestation Receipt"
    ui_info "Sending text to the embedding endpoint. The response includes"
    ui_info "receipt-related headers that can be verified later; in mock mode this is local demo evidence, not real TEE proof."
    ui_blank

    local hdrfile bodyfile
    hdrfile=$(mktemp /tmp/hello-pilot-hdr-XXXXXX)
    bodyfile=$(mktemp /tmp/hello-pilot-body-XXXXXX)

    local http_code
    http_code=$(curl -s -o "$bodyfile" -D "$hdrfile" -w "%{http_code}" \
        -X POST "$GATEWAY_URL/v1/embeddings" \
        -H "Content-Type: application/json" \
        -d '{"model":"text-embedding-3-small","input":"Patient presents with acute respiratory distress."}' \
        2>/dev/null)

    local headers body
    headers=$(cat "$hdrfile")
    body=$(cat "$bodyfile")
    rm -f "$hdrfile" "$bodyfile"

    ui_info "  POST /v1/embeddings  (HTTP $http_code)"
    ui_blank

    if [ "$http_code" != "200" ]; then
        step_fail "Expected HTTP 200, got $http_code"
        echo "    $body" | head -5
        return 1
    fi

    # Show embedding vector (truncated)
    if command -v jq &>/dev/null; then
        local dim
        dim=$(echo "$body" | jq '.data[0].embedding | length' 2>/dev/null || echo "?")
        local first_3
        first_3=$(echo "$body" | jq '[.data[0].embedding[:3][] | tostring] | join(", ")' 2>/dev/null || echo "?")
        ui_info "  Embedding dimension: $dim"
        ui_info "  First 3 values:      [$first_3, ...]"
    else
        echo "    ${body:0:200}..."
    fi
    ui_blank

    # Show receipt headers
    ui_info "  Receipt headers:"
    if check_receipt_headers "$headers"; then
        step_pass "Embedding + attestation receipt received"
    else
        ui_warn "  Receipt not present in headers (mock mode may vary)"
        step_pass "Embedding succeeded (receipt headers depend on backend config)"
    fi
}

step_4_chat_error() {
    step_header 4 "$TOTAL_STEPS" "Chat Completions (Error Demonstration)"
    ui_info "The mock backend is MiniLM — an embedding model, not generative."
    ui_info "Sending a chat request demonstrates graceful error handling."
    ui_blank

    local hdrfile bodyfile
    hdrfile=$(mktemp /tmp/hello-pilot-hdr-XXXXXX)
    bodyfile=$(mktemp /tmp/hello-pilot-body-XXXXXX)

    local http_code
    http_code=$(curl -s -o "$bodyfile" -D "$hdrfile" -w "%{http_code}" \
        -X POST "$GATEWAY_URL/v1/chat/completions" \
        -H "Content-Type: application/json" \
        -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}],"max_tokens":32}' \
        2>/dev/null)

    local headers body
    headers=$(cat "$hdrfile")
    body=$(cat "$bodyfile")
    rm -f "$hdrfile" "$bodyfile"

    ui_info "  POST /v1/chat/completions  (HTTP $http_code)"
    ui_blank

    if command -v jq &>/dev/null; then
        echo "$body" | jq '.' 2>/dev/null | sed 's/^/    /' | head -15
    else
        echo "    ${body:0:300}"
    fi
    ui_blank

    # Check for x-request-id (should be present even on errors)
    if echo "$headers" | grep -qi "x-request-id"; then
        local rid
        rid=$(echo "$headers" | grep -i "x-request-id" | head -1 | sed 's/.*: //' | tr -d '\r')
        ui_info "  Request ID:  $rid  (present even on errors)"
    fi

    if [ "$http_code" = "502" ]; then
        ui_info ""
        ui_info "  This is expected! In production, you would deploy a generative model"
        ui_info "  (e.g., Llama, Mistral) for chat, and an embedding model for /v1/embeddings."
        ui_info "  The gateway routes requests based on EPHEMERALML_MODEL_CAPABILITIES."
        step_pass "Error handled correctly (502 from embedding-only backend)"
    elif [ "$http_code" = "200" ]; then
        step_pass "Chat completion succeeded (generative backend detected)"
    else
        ui_warn "  Unexpected HTTP $http_code — continuing anyway"
        step_pass "Chat endpoint responded"
    fi
}

step_5_metadata() {
    step_header 5 "$TOTAL_STEPS" "Full Receipt in Response Body"
    ui_info "The gateway was started with EPHEMERALML_INCLUDE_METADATA_JSON=true."
    ui_info "The response body includes the _ephemeralml metadata object with"
    ui_info "attestation details, receipt hashes, and model execution evidence."
    ui_blank

    # Embeddings with metadata (gateway already has metadata JSON enabled)
    local body
    body=$(curl -s -X POST "$GATEWAY_URL/v1/embeddings" \
        -H "Content-Type: application/json" \
        -d '{"model":"text-embedding-3-small","input":"Confidential patient record for audit."}' \
        2>/dev/null)

    if [ -z "$body" ]; then
        step_fail "No response from /v1/embeddings"
        return 1
    fi

    # Check for _ephemeralml metadata in body
    if echo "$body" | grep -q "_ephemeralml"; then
        ui_info "  Response body now includes _ephemeralml metadata:"
        ui_blank
        if command -v jq &>/dev/null; then
            echo "$body" | jq '._ephemeralml' 2>/dev/null | sed 's/^/    /'
        else
            # Try to extract just the metadata part
            echo "    (metadata present — install jq for pretty output)"
        fi
        ui_blank
        RECEIPT_COUNT=$((RECEIPT_COUNT + 1))

        # Show what the metadata supports for later review
        ui_info "  This metadata supports later review of:"
        ui_info "    - Which model executed the inference (executed_model)"
        ui_info "    - The attestation mode (mock, nitro, tdx, sev-snp)"
        ui_info "    - A SHA-256 hash of the AIR v1 receipt for verification"
        ui_info "    - A receipt ID for audit trail correlation"
        step_pass "Full receipt metadata visible in response body"
    else
        ui_warn "  _ephemeralml metadata not found in response body"
        ui_info "  (This may happen if the mock backend doesn't produce receipts)"
        step_pass "Embeddings succeeded (metadata depends on backend)"
    fi
}

step_6_python_sdk() {
    # Optional — only runs if python3 + openai are available
    if ! command -v python3 &>/dev/null; then
        return 0
    fi
    if ! python3 -c "import openai" 2>/dev/null; then
        return 0
    fi

    local sdk_script="$SCRIPT_DIR/hello-pilot-verify.py"
    if [ ! -f "$sdk_script" ]; then
        ui_warn "SDK script not found at $sdk_script — skipping"
        return 0
    fi

    step_header 6 "6" "OpenAI Python SDK (Bonus Step)"
    ui_info "Running the OpenAI SDK to call the gateway and save evidence."
    ui_blank

    EPHEMERALML_GATEWAY_URL="$GATEWAY_URL" \
        python3 "$sdk_script" 2>&1 | sed 's/^/  /'

    local exit_code=${PIPESTATUS[0]}
    ui_blank
    if [ "$exit_code" -eq 0 ]; then
        RECEIPT_COUNT=$((RECEIPT_COUNT + 1))
        step_pass "OpenAI SDK demo completed"
    else
        step_fail "SDK demo failed (exit $exit_code)"
    fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    local total_elapsed
    total_elapsed=$(elapsed_since_start)

    ui_blank
    echo -e "  ${_UI_BOLD}$(printf '=%.0s' {1..58})${_UI_RESET}"
    echo -e "  ${_UI_BOLD}Summary${_UI_RESET}"
    echo -e "  ${_UI_BOLD}$(printf '=%.0s' {1..58})${_UI_RESET}"
    ui_blank
    ui_info "  Total elapsed time:   $total_elapsed"
    ui_info "  Receipts collected:   $RECEIPT_COUNT"
    ui_info "  Gateway URL:          $GATEWAY_URL"
    ui_blank

    if $SKIP_CLEANUP; then
        ui_info "  The stack is still running. Try these next:"
        ui_blank
        ui_info "    # Call the embeddings endpoint:"
        ui_info "    curl -s $GATEWAY_URL/v1/embeddings \\"
        ui_info "      -H 'Content-Type: application/json' \\"
        ui_info "      -d '{\"model\":\"text-embedding-3-small\",\"input\":\"Your text here\"}' | jq ."
        ui_blank
        ui_info "    # View models:"
        ui_info "    curl -s $GATEWAY_URL/v1/models | jq ."
        ui_blank
        ui_info "    # Stop the stack:"
        ui_info "    docker compose -f gateway-api/compose.yaml down -v"
    else
        ui_info "  What to do next:"
        ui_info "    1. Read the gateway docs:  gateway-api/README.md"
        ui_info "    2. Deploy with your own model and real TEE backend"
        ui_info "    3. Verify receipts:  ephemeralml-verify <receipt.json> --public-key-file <pubkey.bin>"
    fi

    ui_blank
    ui_ok "Hello Pilot complete!"
    ui_blank
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    START_TIME=$(date +%s)

    echo ""
    echo -e "  ${_UI_BOLD}EphemeralML — Hello Pilot${_UI_RESET}"
    echo -e "  ${_UI_DIM}Confidential AI inference with cryptographic receipts${_UI_RESET}"
    echo -e "  ${_UI_DIM}$(printf '=%.0s' {1..58})${_UI_RESET}"
    echo ""

    check_prerequisites
    start_stack

    local failures=0

    step_1_health || failures=$((failures + 1))
    step_2_models || failures=$((failures + 1))
    step_3_embeddings || failures=$((failures + 1))
    step_4_chat_error || failures=$((failures + 1))
    step_5_metadata || failures=$((failures + 1))
    step_6_python_sdk || true  # optional, don't count as failure

    print_summary

    if [ "$failures" -gt 0 ]; then
        ui_fail "$failures step(s) failed."
        exit 1
    fi
}

main

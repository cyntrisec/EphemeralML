#!/usr/bin/env bash
# run_kms_audit.sh — Build, deploy, and run KMS attestation enforcement tests
# on a Nitro Enclave. Produces structured JSON evidence for each test case.
#
# Prerequisites:
#   - Running on a Nitro-enabled EC2 instance (m6i.xlarge+)
#   - Docker and nitro-cli installed and running
#   - AWS credentials with KMS + S3 permissions
#   - Terraform applied with attest_test_pcr0 (or this script applies it)
#
# Usage:
#   ./scripts/run_kms_audit.sh [--output-dir DIR] [--skip-terraform] [--wrong-pcr]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/kms_audit_results/run_$(date +%Y%m%d_%H%M%S)"
SKIP_TERRAFORM=false
RUN_WRONG_PCR=false
TERRAFORM_DIR="${REPO_ROOT}/infra/hello-enclave"
ENCLAVE_MEMORY=4096
ENCLAVE_CPUS=2
ENCLAVE_CID=16
KMS_PROXY_PORT=8082

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --skip-terraform) SKIP_TERRAFORM=true; shift ;;
        --wrong-pcr) RUN_WRONG_PCR=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
echo "=== KMS Attestation Audit ==="
echo "Output dir: $OUTPUT_DIR"
echo "Timestamp:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# ── Step 1: Get instance metadata ──
echo "Step 1: Getting instance metadata..."
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || echo "")
if [ -n "$TOKEN" ]; then
    INSTANCE_TYPE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
        "http://169.254.169.254/latest/meta-data/instance-type" 2>/dev/null || echo "unknown")
    INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
        "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || echo "unknown")
else
    INSTANCE_TYPE="unknown"
    INSTANCE_ID="unknown"
fi
GIT_COMMIT=$(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
echo "  Instance: $INSTANCE_TYPE ($INSTANCE_ID)"
echo "  Commit:   $GIT_COMMIT"

# ── Step 2: Build correct EIF ──
echo ""
echo "Step 2: Building kms-audit EIF..."
docker build \
    -f "${REPO_ROOT}/enclaves/vsock-pingpong/Dockerfile" \
    --build-arg MODE=kms-audit \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    --build-arg INSTANCE_TYPE="$INSTANCE_TYPE" \
    -t vsock-pingpong-kms-audit:latest \
    "$REPO_ROOT"

echo "  Building EIF..."
BUILD_OUTPUT=$(nitro-cli build-enclave \
    --docker-uri vsock-pingpong-kms-audit:latest \
    --output-file "${OUTPUT_DIR}/kms-audit.eif" 2>&1)
echo "$BUILD_OUTPUT" > "${OUTPUT_DIR}/eif_build_output.json"

# Extract PCR0
PCR0=$(echo "$BUILD_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['Measurements']['PCR0'])" 2>/dev/null || echo "")
PCR1=$(echo "$BUILD_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['Measurements']['PCR1'])" 2>/dev/null || echo "")
PCR2=$(echo "$BUILD_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['Measurements']['PCR2'])" 2>/dev/null || echo "")

if [ -z "$PCR0" ]; then
    echo "ERROR: Failed to extract PCR0 from EIF build output"
    echo "Build output: $BUILD_OUTPUT"
    exit 1
fi
echo "  PCR0: $PCR0"
echo "  PCR1: $PCR1"
echo "  PCR2: $PCR2"

# ── Step 3: Apply Terraform with PCR0 ──
if [ "$SKIP_TERRAFORM" = false ]; then
    echo ""
    echo "Step 3: Applying Terraform with attest_test_pcr0..."
    (cd "$TERRAFORM_DIR" && terraform apply \
        -var "attest_test_pcr0=$PCR0" \
        -auto-approve \
        -target=aws_kms_key.attest_test_key \
        -target=aws_kms_alias.attest_test_key)

    ATTEST_KEY_ARN=$(cd "$TERRAFORM_DIR" && terraform output -raw attest_test_key_arn 2>/dev/null || echo "")
    echo "  Attest test key ARN: $ATTEST_KEY_ARN"
else
    echo ""
    echo "Step 3: Skipping Terraform (--skip-terraform)"
    ATTEST_KEY_ARN=$(cd "$TERRAFORM_DIR" && terraform output -raw attest_test_key_arn 2>/dev/null || echo "")
fi

# ── Step 4: Build and start kms_proxy_host ──
echo ""
echo "Step 4: Building and starting kms_proxy_host..."
(cd "$REPO_ROOT" && cargo build --release --bin kms_proxy_host --features production 2>&1) | tail -3

# Kill any existing proxy
pkill -f "kms_proxy_host" 2>/dev/null || true
sleep 1

RUST_LOG=info "${REPO_ROOT}/target/release/kms_proxy_host" > "${OUTPUT_DIR}/proxy.log" 2>&1 &
PROXY_PID=$!
echo "  Proxy PID: $PROXY_PID"
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "ERROR: kms_proxy_host died immediately. Check ${OUTPUT_DIR}/proxy.log"
    exit 1
fi

cleanup() {
    echo ""
    echo "Cleaning up..."
    # Terminate enclave
    nitro-cli terminate-enclave --all 2>/dev/null || true
    # Kill proxy
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 5: Run correct-PCR enclave ──
echo ""
echo "Step 5: Running kms-audit enclave (correct PCR0)..."
nitro-cli terminate-enclave --all 2>/dev/null || true
sleep 1

ENCLAVE_OUTPUT=$(nitro-cli run-enclave \
    --eif-path "${OUTPUT_DIR}/kms-audit.eif" \
    --memory "$ENCLAVE_MEMORY" \
    --cpu-count "$ENCLAVE_CPUS" \
    --enclave-cid "$ENCLAVE_CID" \
    --debug-mode 2>&1)
echo "$ENCLAVE_OUTPUT"

ENCLAVE_ID=$(echo "$ENCLAVE_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['EnclaveID'])" 2>/dev/null || echo "")
if [ -z "$ENCLAVE_ID" ]; then
    echo "ERROR: Failed to start enclave"
    exit 1
fi
echo "  Enclave ID: $ENCLAVE_ID"

# ── Step 6: Capture console output ──
echo ""
echo "Step 6: Capturing console output (waiting for KMS_AUDIT_JSON_END)..."
CONSOLE_LOG="${OUTPUT_DIR}/console.log"
nitro-cli console --enclave-id "$ENCLAVE_ID" > "$CONSOLE_LOG" 2>&1 &
CONSOLE_PID=$!

# Wait for the JSON markers (timeout after 120s)
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if grep -q "KMS_AUDIT_JSON_END" "$CONSOLE_LOG" 2>/dev/null; then
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ $((ELAPSED % 20)) -eq 0 ]; then
        echo "  ... waiting ($ELAPSED s)"
    fi
done

kill "$CONSOLE_PID" 2>/dev/null || true

if ! grep -q "KMS_AUDIT_JSON_END" "$CONSOLE_LOG"; then
    echo "ERROR: Timed out waiting for KMS audit results"
    echo "Console log tail:"
    tail -30 "$CONSOLE_LOG"
    exit 1
fi

# Extract JSON
sed -n '/KMS_AUDIT_JSON_BEGIN/,/KMS_AUDIT_JSON_END/p' "$CONSOLE_LOG" \
    | grep -v "KMS_AUDIT_JSON_" \
    > "${OUTPUT_DIR}/kms_audit_results.json"

echo "  Results saved to ${OUTPUT_DIR}/kms_audit_results.json"

# ── Step 6b: Wrong-PCR test (optional) ──
if [ "$RUN_WRONG_PCR" = true ]; then
    echo ""
    echo "Step 6b: Building wrong-PCR EIF..."
    nitro-cli terminate-enclave --all 2>/dev/null || true
    sleep 1

    docker build \
        -f "${REPO_ROOT}/enclaves/vsock-pingpong/Dockerfile" \
        --build-arg MODE=kms-audit \
        --build-arg GIT_COMMIT="$GIT_COMMIT" \
        --build-arg INSTANCE_TYPE="$INSTANCE_TYPE" \
        --build-arg PCR_MARKER=wrong-pcr-test \
        -t vsock-pingpong-kms-audit-wrong:latest \
        "$REPO_ROOT"

    WRONG_BUILD=$(nitro-cli build-enclave \
        --docker-uri vsock-pingpong-kms-audit-wrong:latest \
        --output-file "${OUTPUT_DIR}/kms-audit-wrong-pcr.eif" 2>&1)
    echo "$WRONG_BUILD" > "${OUTPUT_DIR}/eif_build_wrong_pcr.json"

    WRONG_PCR0=$(echo "$WRONG_BUILD" | python3 -c "import sys,json; print(json.load(sys.stdin)['Measurements']['PCR0'])" 2>/dev/null || echo "")
    echo "  Wrong PCR0: $WRONG_PCR0 (policy expects: $PCR0)"

    if [ "$WRONG_PCR0" = "$PCR0" ]; then
        echo "WARNING: Wrong-PCR EIF has same PCR0 as correct EIF. Test is invalid."
    else
        echo "  Running wrong-PCR enclave..."
        ENCLAVE_OUTPUT=$(nitro-cli run-enclave \
            --eif-path "${OUTPUT_DIR}/kms-audit-wrong-pcr.eif" \
            --memory "$ENCLAVE_MEMORY" \
            --cpu-count "$ENCLAVE_CPUS" \
            --enclave-cid "$ENCLAVE_CID" \
            --debug-mode 2>&1)
        echo "  $ENCLAVE_OUTPUT"

        WRONG_ENCLAVE_ID=$(echo "$ENCLAVE_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['EnclaveID'])" 2>/dev/null || echo "")

        WRONG_CONSOLE="${OUTPUT_DIR}/console_wrong_pcr.log"
        nitro-cli console --enclave-id "$WRONG_ENCLAVE_ID" > "$WRONG_CONSOLE" 2>&1 &
        WRONG_CONSOLE_PID=$!

        ELAPSED=0
        while [ $ELAPSED -lt $TIMEOUT ]; do
            if grep -q "KMS_AUDIT_JSON_END" "$WRONG_CONSOLE" 2>/dev/null; then
                break
            fi
            sleep 2
            ELAPSED=$((ELAPSED + 2))
        done
        kill "$WRONG_CONSOLE_PID" 2>/dev/null || true

        if grep -q "KMS_AUDIT_JSON_END" "$WRONG_CONSOLE"; then
            sed -n '/KMS_AUDIT_JSON_BEGIN/,/KMS_AUDIT_JSON_END/p' "$WRONG_CONSOLE" \
                | grep -v "KMS_AUDIT_JSON_" \
                > "${OUTPUT_DIR}/kms_audit_wrong_pcr_results.json"
            echo "  Wrong-PCR results saved"
        else
            echo "  WARNING: Wrong-PCR test timed out"
        fi
    fi
fi

# ── Step 7: Print summary ──
echo ""
echo "=== KMS Audit Summary ==="
echo ""

if [ -f "${OUTPUT_DIR}/kms_audit_results.json" ]; then
    python3 -c "
import json, sys
with open('${OUTPUT_DIR}/kms_audit_results.json') as f:
    data = json.load(f)

print(f'Key alias: {data.get(\"key_alias\", \"unknown\")}')
print(f'Timestamp: {data.get(\"timestamp\", \"unknown\")}')
print(f'Commit:    {data.get(\"commit\", \"unknown\")}')
print()
print(f'{\"#\":<4} {\"Test ID\":<35} {\"Expected\":<25} {\"Actual\":<20} {\"Latency\":>10}')
print('-' * 96)

for t in data.get('tests', []):
    num = t.get('test_num', '?')
    tid = t.get('test_id', 'unknown')
    exp = t.get('expected', '?')
    act = t.get('actual', '?')
    lat = t.get('latency_ms', 0)

    # Pass/fail indicator
    if exp == 'success' and act == 'success':
        mark = 'PASS'
    elif exp == 'error' and act == 'error':
        mark = 'PASS'
    elif 'or' in exp and act in ('success', 'error'):
        mark = 'PASS'
    else:
        mark = 'FAIL'

    print(f'{num:<4} {tid:<35} {exp:<25} {act + \" (\" + mark + \")\":<20} {lat:>8.1f}ms')

summary = data.get('summary', {})
print()
print(f'Total: {summary.get(\"total\", 0)}, Passed: {summary.get(\"passed\", 0)}, Failed: {summary.get(\"failed\", 0)}')
" 2>/dev/null || echo "(install python3 for formatted summary)"
fi

# Save run metadata
cat > "${OUTPUT_DIR}/run_metadata.json" <<METADATA
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$GIT_COMMIT",
  "instance_type": "$INSTANCE_TYPE",
  "instance_id": "$INSTANCE_ID",
  "pcr0": "$PCR0",
  "pcr1": "$PCR1",
  "pcr2": "$PCR2",
  "enclave_memory_mib": $ENCLAVE_MEMORY,
  "enclave_cpus": $ENCLAVE_CPUS,
  "wrong_pcr_test": $RUN_WRONG_PCR
}
METADATA

echo ""
echo "Results in: $OUTPUT_DIR"
echo "Done."

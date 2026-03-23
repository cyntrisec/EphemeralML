#!/usr/bin/env bash
# Record a canonical 90-second trust center demo using asciinema.
#
# Usage:
#   bash scripts/record-demo.sh
#
# Output: demo-recording.cast (asciinema v2 format)
#
# The recording can be played with: asciinema play demo-recording.cast
# Or embedded on a website via asciinema player JS.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CAST_FILE="$PROJECT_DIR/demo-recording.cast"
TC="https://trust-center-324130315768.us-central1.run.app"

# Clean up any previous recording
rm -f "$CAST_FILE"

echo
echo "  Recording 90-second Cyntrisec Trust Center demo..."
echo "  Output: $CAST_FILE"
echo

# Create the demo script that will be executed inside asciinema
DEMO_SCRIPT=$(mktemp)
cat > "$DEMO_SCRIPT" << 'DEMOSCRIPT'
#!/usr/bin/env bash
set -e

TC="https://trust-center-324130315768.us-central1.run.app"

type_and_run() {
    local cmd="$1"
    local delay="${2:-0.04}"
    # Print command character by character for typing effect
    echo -n '$ '
    for ((i=0; i<${#cmd}; i++)); do
        echo -n "${cmd:$i:1}"
        sleep "$delay"
    done
    echo
    sleep 0.3
    eval "$cmd"
    sleep 1
}

pause() { sleep "${1:-1.5}"; }

clear
echo
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  Cyntrisec Trust Center — Live Demo          ║"
echo "  ║  Per-inference cryptographic receipts for AI  ║"
echo "  ╚══════════════════════════════════════════════╝"
echo
sleep 2

echo "  Step 1: Check the live trust center"
echo "  ────────────────────────────────────"
echo
type_and_run "curl -s $TC/health | jq ."
pause

echo
echo "  Step 2: Get a signed AIR v1 receipt"
echo "  ────────────────────────────────────"
echo
type_and_run "curl -s $TC/api/v1/samples/valid | jq '{format, receipt_length: (.receipt_base64 | length), public_key}'"
pause

echo
echo "  Step 3: Verify the receipt"
echo "  ─────────────────────────"
echo
# Fetch and verify in one pipeline
type_and_run "SAMPLE=\$(curl -s $TC/api/v1/samples/valid)"
type_and_run "B64=\$(echo \$SAMPLE | jq -r '.receipt_base64')"
type_and_run "KEY=\$(echo \$SAMPLE | jq -r '.public_key')"
echo
type_and_run "curl -s -X POST $TC/api/v1/verify -H 'Content-Type: application/json' -d \"{\\\"receipt\\\": \\\"\$B64\\\", \\\"public_key\\\": \\\"\$KEY\\\"}\" | jq '{verdict, verified, format}'"
pause 2

echo
echo "  Step 4: Tamper the receipt and verify again"
echo "  ───────────────────────────────────────────"
echo
type_and_run "TAMPERED=\${B64:0:100}TAMPERED\${B64:108}"
echo
type_and_run "curl -s -X POST $TC/api/v1/verify -H 'Content-Type: application/json' -d \"{\\\"receipt\\\": \\\"\$TAMPERED\\\", \\\"public_key\\\": \\\"\$KEY\\\"}\" | jq '{verdict, verified}'"
pause 2

echo
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  One inference. One signed receipt.           ║"
echo "  ║  Independently verifiable. Tamper-evident.    ║"
echo "  ║                                              ║"
echo "  ║  Trust center: $TC"
echo "  ║  IETF draft: draft-tsyrulnikov-rats-attested-inference-receipt"
echo "  ╚══════════════════════════════════════════════╝"
echo
sleep 3
DEMOSCRIPT

chmod +x "$DEMO_SCRIPT"

# Record with asciinema
asciinema rec \
    --title "Cyntrisec Trust Center — Per-Inference Receipts for AI" \
    --idle-time-limit 2 \
    --command "bash $DEMO_SCRIPT" \
    "$CAST_FILE"

rm -f "$DEMO_SCRIPT"

echo
echo "  Recording saved: $CAST_FILE"
echo "  Play:  asciinema play $CAST_FILE"
echo "  Share: asciinema upload $CAST_FILE"
echo

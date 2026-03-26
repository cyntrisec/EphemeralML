#!/usr/bin/env bash
# Generate canonical demo asset pack for outbound, demos, and investor materials.
#
# Usage:
#   bash scripts/demo-pack.sh           # Generate full pack in demo-pack/
#   bash scripts/demo-pack.sh --skip-build  # Skip server build (use existing binaries)
#
# Output:
#   demo-pack/
#   ├── README.md                  # Pack summary + usage instructions
#   ├── receipt.json               # Real signed legacy receipt
#   ├── receipt.json.pubkey        # Matching Ed25519 public key (32 bytes)
#   ├── air-v1-receipt.cbor        # Real signed AIR v1 receipt
#   ├── air-v1-receipt.pubkey      # Matching public key hex
#   ├── verify-output.txt          # CLI verification output (VERIFIED)
#   ├── tamper-output.txt          # CLI tamper detection output (INVALID)
#   ├── healthcare-brief.md        # Healthcare vertical wrapper
#   ├── finance-brief.md           # Finance vertical wrapper
#   └── legal-brief.md             # Legal vertical wrapper
#
# Prerequisites: Rust toolchain, model assets in test_assets/minilm/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PACK_DIR="$PROJECT_DIR/demo-pack"
SKIP_BUILD="${1:-}"

echo
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  CYNTRISEC DEMO ASSET PACK GENERATOR        ║"
echo "  ╚══════════════════════════════════════════════╝"
echo

# ── Setup ────────────────────────────────────────────────

rm -rf "$PACK_DIR"
mkdir -p "$PACK_DIR"

# ── Step 1: Generate legacy receipt via demo flow ────────

echo "  [1/5] Generating legacy receipt via demo.sh..."

if [ "$SKIP_BUILD" != "--skip-build" ]; then
    bash "$SCRIPT_DIR/demo.sh" up
else
    echo "        (skipping build, using existing server)"
fi

FRESH_LEGACY=false

# Check if server is running
if [ -f "$PROJECT_DIR/.demo-server.pid" ] && kill -0 "$(cat "$PROJECT_DIR/.demo-server.pid")" 2>/dev/null; then
    bash "$SCRIPT_DIR/demo.sh" infer
    cp "$PROJECT_DIR/demo-receipt.json" "$PACK_DIR/receipt.json"
    cp "$PROJECT_DIR/demo-receipt.json.pubkey" "$PACK_DIR/receipt.json.pubkey"
    FRESH_LEGACY=true
    echo "        Legacy receipt saved (fresh, verifiable)."
else
    echo "        WARNING: Server not running. Skipping legacy receipt generation."
    echo "        Run without --skip-build to generate a fresh, verifiable legacy receipt."
fi

# ── Step 2: Generate AIR v1 receipt ──────────────────────

echo "  [2/5] Generating AIR v1 receipt..."

VERIFY_BIN="$PROJECT_DIR/target/release/ephemeralml-verify"
if [ ! -f "$VERIFY_BIN" ]; then
    VERIFY_BIN="$PROJECT_DIR/target/debug/ephemeralml-verify"
fi

# Use the verifier API sample endpoint to get a signed AIR v1 receipt.
# Start a temporary verifier instance if needed.
VERIFIER_PORT=18932
VERIFIER_PID=""

start_temp_verifier() {
    local bin="$PROJECT_DIR/target/release/ephemeralml-verifier"
    if [ ! -f "$bin" ]; then
        bin="$PROJECT_DIR/target/debug/ephemeralml-verifier"
    fi
    if [ ! -f "$bin" ]; then
        echo "        Building verifier..."
        cd "$PROJECT_DIR"
        cargo build --release -p ephemeralml-verifier-api 2>&1 | tail -2
        bin="$PROJECT_DIR/target/release/ephemeralml-verifier"
    fi
    "$bin" --mode public-trust-center --port "$VERIFIER_PORT" --rate-limit 100 \
        > /dev/null 2>&1 &
    VERIFIER_PID=$!
    local attempts=0
    while ! bash -c "echo > /dev/tcp/127.0.0.1/$VERIFIER_PORT" 2>/dev/null; do
        sleep 0.3
        attempts=$((attempts + 1))
        if [ $attempts -ge 15 ]; then
            echo "  ERROR: Verifier failed to start"
            kill "$VERIFIER_PID" 2>/dev/null || true
            exit 1
        fi
    done
}

start_temp_verifier

# Fetch AIR v1 sample
AIR_SAMPLE=$(curl -s "http://127.0.0.1:$VERIFIER_PORT/api/v1/samples/valid")
echo "$AIR_SAMPLE" | python3 -c "
import sys, json, base64
data = json.load(sys.stdin)
raw = base64.b64decode(data['receipt_base64'])
with open('$PACK_DIR/air-v1-receipt.cbor', 'wb') as f:
    f.write(raw)
with open('$PACK_DIR/air-v1-receipt.pubkey', 'w') as f:
    f.write(data['public_key'])
"
echo "        AIR v1 receipt saved."

# Stop temp verifier
kill "$VERIFIER_PID" 2>/dev/null || true
wait "$VERIFIER_PID" 2>/dev/null || true

# ── Step 3: Capture verification outputs ─────────────────

echo "  [3/5] Capturing verification outputs..."

if [ "$FRESH_LEGACY" = true ] && [ -f "$VERIFY_BIN" ] && [ -f "$PACK_DIR/receipt.json" ]; then
    "$VERIFY_BIN" "$PACK_DIR/receipt.json" \
        --public-key-file "$PACK_DIR/receipt.json.pubkey" \
        --max-age 0 --plain \
        > "$PACK_DIR/verify-output.txt" 2>&1 || true

    # Create tampered receipt
    python3 -c "
import json
r = json.load(open('$PACK_DIR/receipt.json'))
r['model_id'] = 'TAMPERED'
json.dump(r, open('$PACK_DIR/.tampered.json', 'w'), indent=2)
" 2>/dev/null

    "$VERIFY_BIN" "$PACK_DIR/.tampered.json" \
        --public-key-file "$PACK_DIR/receipt.json.pubkey" \
        --max-age 0 --plain \
        > "$PACK_DIR/tamper-output.txt" 2>&1 || true
    rm -f "$PACK_DIR/.tampered.json"
    echo "        Verification outputs captured (from fresh receipt)."
elif [ "$FRESH_LEGACY" = false ]; then
    echo "        Skipping legacy verification outputs (no fresh receipt)."
    echo "(not generated — run without --skip-build to produce a fresh verifiable receipt)" > "$PACK_DIR/verify-output.txt"
    echo "(not generated — run without --skip-build to produce a fresh verifiable receipt)" > "$PACK_DIR/tamper-output.txt"
else
    echo "        ephemeralml-verify not found; skipping output capture."
    echo "(not generated — build ephemeralml-verify first)" > "$PACK_DIR/verify-output.txt"
    echo "(not generated — build ephemeralml-verify first)" > "$PACK_DIR/tamper-output.txt"
fi

# ── Step 4: Generate vertical briefs ─────────────────────

echo "  [4/5] Generating vertical narrative briefs..."

cat > "$PACK_DIR/healthcare-brief.md" << 'BRIEF'
# Healthcare: Per-Inference Evidence for Clinical AI

## The Problem

Healthcare organizations using AI for clinical decision support, ambient
documentation, or diagnostic imaging need to answer: *which model processed
this patient's data, in what environment, and what evidence exists?*

Today the answer is usually vendor logs — unsigned, mutable, and not
independently verifiable.

## What EphemeralML Provides

Each AI inference produces a signed receipt containing:
- **Model identity** (model_id + cryptographic model_hash)
- **Input/output binding** (request_hash, response_hash)
- **Attestation linkage** (attestation_doc_hash, enclave_measurements)
- **Runtime metadata** (execution_time_ms, sequence_number)
- **Ed25519 signature** — independently verifiable

## Evidence Relevance

Receipt fields can support evidence workflows relevant to:
- **Audit trail controls** — the receipt itself is a signed audit artifact
- **Integrity controls** — model_hash + signature binding
- **Access/isolation evidence** — attestation linkage to workload measurements
- **Transmission security evidence** — attestation-bound encrypted channel

*This mapping is illustrative, not a compliance determination.*

## Pilot Scope

A typical healthcare pilot runs for 8 weeks on a single clinical AI workflow:
- Ambient documentation (AI processes physician-patient conversation)
- Diagnostic decision support (AI analyzes imaging or lab results)
- Prior authorization (AI processes clinical data for payer review)

## Included in This Pack

- `receipt.json` — real signed receipt from a mock inference run
- `receipt.json.pubkey` — Ed25519 public key for verification
- `air-v1-receipt.cbor` — AIR v1 COSE_Sign1 receipt (standard format)
- `verify-output.txt` — what independent verification looks like
- `tamper-output.txt` — what tamper detection looks like
BRIEF

cat > "$PACK_DIR/finance-brief.md" << 'BRIEF'
# Finance: Investigation-Ready Records for AI Decisions

## The Problem

Financial institutions using AI for credit decisioning, compliance checks,
customer advisory, or fraud detection need investigation-ready records showing
what model made what decision on what data.

Regulatory pressure is increasing: the Bank of Israel interministerial report
recommends explainability and human oversight for AI in financial services.
The SEC 2026 exam priorities explicitly target AI oversight at advisory firms.

## What EphemeralML Provides

Each AI inference produces a signed receipt — an investigation-ready record
containing model identity, data hashes, attestation evidence, and an Ed25519
signature that can be verified independently by auditors or regulators.

## Evidence Relevance

Receipt fields can support:
- **Forensic traceability** — model_id, model_hash, request/response hashes
- **Accountability** — signed receipt links a specific model run to specific data
- **Explainability support** — execution_time_ms, sequence_number for post-hoc review
- **Governance evidence** — attestation_doc_hash links to workload environment

*This mapping is illustrative, not a compliance determination.*

## Pilot Scope

A typical finance pilot runs for 8 weeks on a single AI workflow:
- Customer support copilot (AI processes customer financial data)
- Compliance screening (AI scans transactions or documents)
- Underwriting or credit analysis (AI evaluates applicant data)

## Included in This Pack

- `receipt.json` — real signed receipt from a mock inference run
- `air-v1-receipt.cbor` — AIR v1 COSE_Sign1 receipt (standard format)
- `verify-output.txt` — what independent verification looks like
- `tamper-output.txt` — what tamper detection looks like
BRIEF

cat > "$PACK_DIR/legal-brief.md" << 'BRIEF'
# Legal: Evidence for AI-Assisted Document Processing

## The Problem

Law firms using AI for contract review, due diligence, research, or document
drafting handle privileged client data. The Israeli Bar Association AI
guidelines (May 2024) require lawyers to critically verify AI outputs.

When AI processes privileged documents, firms need evidence of which model
ran, on what data, and whether the processing environment was isolated.

## What EphemeralML Provides

Each AI inference produces a signed receipt that links a specific model run
to specific request/response hashes. This supports later review of what
model and workload were involved in a given run.

## Evidence Relevance

Receipt fields can support:
- **Professional responsibility** — receipt links model identity to a specific run
- **Privilege review** — request/response hashes confirm which data was processed
- **Vendor accountability** — signed artifact is independently verifiable
- **Incident review** — full receipt chain supports forensic reconstruction

*This mapping is illustrative, not a compliance determination.*

## Pilot Scope

A typical legal pilot runs for 8 weeks on a single AI workflow:
- Contract review (AI processes deal documents)
- Due diligence (AI analyzes target company documents)
- Research assistance (AI processes case law or regulatory text)

## Included in This Pack

- `receipt.json` — real signed receipt from a mock inference run
- `air-v1-receipt.cbor` — AIR v1 COSE_Sign1 receipt (standard format)
- `verify-output.txt` — what independent verification looks like
- `tamper-output.txt` — what tamper detection looks like
BRIEF

echo "        Vertical briefs saved."

# ── Step 5: Generate README ──────────────────────────────

echo "  [5/5] Generating pack README..."

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

LEGACY_NOTE=""
if [ "$FRESH_LEGACY" = true ]; then
    LEGACY_NOTE="| \`receipt.json\` | Signed legacy receipt from mock inference (fresh, verifiable) |
| \`receipt.json.pubkey\` | Ed25519 public key (32 bytes) |
| \`verify-output.txt\` | CLI verification output (VERIFIED) |
| \`tamper-output.txt\` | CLI tamper detection output (INVALID) |"
else
    LEGACY_NOTE="| \`verify-output.txt\` | Not generated (run without --skip-build for verifiable outputs) |
| \`tamper-output.txt\` | Not generated (run without --skip-build for verifiable outputs) |"
fi

cat > "$PACK_DIR/README.md" << EOF
# Cyntrisec Demo Asset Pack

Generated: $TIMESTAMP

## Contents

| File | Description |
|------|-------------|
| \`air-v1-receipt.cbor\` | AIR v1 COSE_Sign1 receipt (primary format, always verifiable) |
| \`air-v1-receipt.pubkey\` | Ed25519 public key (hex) |
$LEGACY_NOTE
| \`healthcare-brief.md\` | Healthcare vertical narrative |
| \`finance-brief.md\` | Finance vertical narrative |
| \`legal-brief.md\` | Legal vertical narrative |

## Quick Verification

\`\`\`bash
# AIR v1 receipt (always included and verifiable)
ephemeralml-verify air-v1-receipt.cbor --public-key \$(cat air-v1-receipt.pubkey)
\`\`\`

## Trust Center

Upload any receipt to the Cyntrisec Trust Center for browser-based verification:
- Local: \`http://localhost:8080\` (run with \`--mode public-trust-center\`)

## Usage

- **Live demo:** Use \`air-v1-receipt.cbor\` + \`air-v1-receipt.pubkey\` in the CLI demo flow
- **Async outbound:** Attach a vertical brief + receipt to discovery messages
- **Investor deck:** Reference the AIR v1 receipt and verification output
- **Trust center:** Upload the receipt to the hosted verifier

## Regeneration

To produce a complete pack with fresh legacy receipts and verification outputs:
\`\`\`bash
bash scripts/demo-pack.sh
\`\`\`

Use \`--skip-build\` only for the AIR v1 receipt and vertical briefs (no legacy receipt or CLI outputs).
EOF

echo "        README saved."

# ── Cleanup ──────────────────────────────────────────────

bash "$SCRIPT_DIR/demo.sh" down 2>/dev/null || true

echo
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║  DEMO PACK READY: demo-pack/                ║"
echo "  ╚══════════════════════════════════════════════╝"
echo
echo "  Files:"
ls -1 "$PACK_DIR" | sed 's/^/    /'
echo

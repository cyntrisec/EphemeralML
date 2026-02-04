#!/usr/bin/env bash
# test_kms_attestation.sh — Verify KMS attestation-conditioned policy enforcement.
#
# Negative test: prove the host role CANNOT call kms:GenerateDataKey or kms:Decrypt
# without a valid Nitro attestation document (RecipientInfo). Runs on the host
# using the instance's IAM role credentials.
#
# The KMS policy conditions both kms:Decrypt and kms:GenerateDataKey on
# kms:RecipientAttestation:ImageSha384 (PCR0). Without a valid COSE_Sign1
# attestation document from the correct enclave image, both calls fail.
#
# Positive test: requires the enclave to actually call KmsClient::decrypt() with
# RecipientInfo containing a real NSM attestation document. This exercises the
# full path: enclave -> VSock -> kms_proxy_host -> KMS Decrypt(RecipientInfo) ->
# CiphertextForRecipient -> enclave RSA-OAEP unwrap. Today's boot path only does
# an S3 connectivity check (not KMS decrypt), so the positive test requires a model
# encrypted with a KMS-wrapped DEK (from scripts/encrypt_model.py).
#
# Prerequisites:
#   - Run ON the Nitro-enabled EC2 instance with the host IAM role
#   - KMS policy has attestation conditions (terraform apply with enclave_pcr0)
#
# Usage:
#   ./scripts/test_kms_attestation.sh
#   ./scripts/test_kms_attestation.sh --ciphertext /path/to/wrapped_dek.bin

set -euo pipefail

KMS_KEY_ALIAS="alias/ephemeral-ml-test"
CIPHERTEXT_PATH=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --ciphertext)
            CIPHERTEXT_PATH="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--ciphertext PATH]"
            echo ""
            echo "Options:"
            echo "  --ciphertext PATH   Path to a KMS ciphertext blob for additional Decrypt test"
            echo ""
            echo "Without --ciphertext, tests only GenerateDataKey (also attestation-conditioned)."
            echo "To get a ciphertext blob, run encrypt_model.py from a machine with kms:Encrypt."
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

echo "=== KMS Attestation Policy Enforcement Test ==="
echo ""
echo "This test verifies that the host IAM role CANNOT call KMS without"
echo "a valid Nitro attestation document matching the conditioned PCR values."
echo ""

OVERALL_PASS=true

# --- Test 1: GenerateDataKey without attestation ---
echo "--- Test 1: kms:GenerateDataKey without attestation ---"
echo "Command: aws kms generate-data-key --key-id $KMS_KEY_ALIAS --key-spec AES_256"
echo ""

GDK_EXIT=0
GDK_OUTPUT=$(aws kms generate-data-key \
    --key-id "$KMS_KEY_ALIAS" \
    --key-spec AES_256 \
    --output json 2>&1) || GDK_EXIT=$?

if [ $GDK_EXIT -ne 0 ]; then
    if echo "$GDK_OUTPUT" | grep -qi "AccessDeniedException"; then
        echo "PASS: GenerateDataKey returned AccessDeniedException"
        echo "      Host role cannot generate data keys without attestation."
    elif echo "$GDK_OUTPUT" | grep -qi "not authorized\|not found\|does not exist"; then
        echo "WARN: KMS key not found or role not authorized at all."
        echo "      This might mean the KMS key doesn't exist yet (run terraform apply)."
        echo "      Output: $GDK_OUTPUT"
        OVERALL_PASS=false
    else
        echo "UNEXPECTED: Non-AccessDenied error (exit $GDK_EXIT)"
        echo "Output: $GDK_OUTPUT"
        OVERALL_PASS=false
    fi
else
    echo "FAIL: GenerateDataKey SUCCEEDED without attestation!"
    echo "      The KMS policy does NOT enforce attestation conditions."
    echo "      Fix: terraform apply -var=\"enclave_pcr0=<PCR0>\""
    OVERALL_PASS=false
fi
echo ""

# --- Test 2: Decrypt without attestation (optional, needs ciphertext blob) ---
if [ -n "$CIPHERTEXT_PATH" ]; then
    if [ ! -f "$CIPHERTEXT_PATH" ]; then
        echo "--- Test 2: SKIPPED (file not found: $CIPHERTEXT_PATH) ---"
        echo ""
    else
        echo "--- Test 2: kms:Decrypt without attestation ---"
        echo "Ciphertext: $CIPHERTEXT_PATH ($(wc -c < "$CIPHERTEXT_PATH") bytes)"
        echo "Command: aws kms decrypt --ciphertext-blob fileb://$CIPHERTEXT_PATH --key-id $KMS_KEY_ALIAS"
        echo ""

        DECRYPT_EXIT=0
        DECRYPT_OUTPUT=$(aws kms decrypt \
            --ciphertext-blob "fileb://$CIPHERTEXT_PATH" \
            --key-id "$KMS_KEY_ALIAS" \
            --output json 2>&1) || DECRYPT_EXIT=$?

        if [ $DECRYPT_EXIT -ne 0 ]; then
            if echo "$DECRYPT_OUTPUT" | grep -qi "AccessDeniedException"; then
                echo "PASS: Decrypt returned AccessDeniedException"
                echo "      Host role cannot decrypt without attestation."
            else
                echo "UNEXPECTED: Non-AccessDenied error (exit $DECRYPT_EXIT)"
                echo "Output: $DECRYPT_OUTPUT"
                OVERALL_PASS=false
            fi
        else
            echo "FAIL: Decrypt SUCCEEDED without attestation!"
            echo "      The KMS policy does NOT enforce attestation conditions."
            OVERALL_PASS=false
        fi
        echo ""
    fi
else
    echo "--- Test 2: kms:Decrypt without attestation ---"
    echo "SKIPPED: No ciphertext blob provided."
    echo "         Use --ciphertext /path/to/wrapped_dek.bin to test Decrypt."
    echo "         Generate one with: python3 scripts/encrypt_model.py (from deployer machine)"
    echo ""
fi

# --- Positive test guidance ---
echo "--- Positive test (KMS Decrypt WITH attestation) ---"
echo "NOT automated. The positive test requires:"
echo "  1. A model encrypted with a KMS-wrapped DEK (scripts/encrypt_model.py)"
echo "  2. The wrapped DEK uploaded to S3"
echo "  3. The enclave calling KmsClient::decrypt() during model loading"
echo "  4. kms_proxy_host forwarding the request with RecipientInfo to KMS"
echo ""
echo "The enclave's current boot path (main.rs) only does an S3 connectivity"
echo "check, not a KMS decrypt. To test the full KMS path, the enclave must"
echo "load a model via ModelLoader::load_model(), which calls kms_client.decrypt()."
echo ""
echo "When the model loading path is exercised:"
echo "  - kms_proxy_host logs will show 'KMS Decrypt with RecipientInfo'"
echo "  - The enclave will successfully unwrap the DEK via RSA-OAEP"
echo "  - Model inference will work (proving DEK was correctly released)"
echo ""

# --- Summary ---
echo "=== Test Summary ==="
if [ "$OVERALL_PASS" = true ]; then
    echo "  Negative test: PASS (host cannot call KMS without attestation)"
    echo ""
    echo "  Combined with the smoke test (which verifies NSM attestation produces"
    echo "  valid COSE_Sign1 documents with correct PCR values), this proves:"
    echo "    - KMS rejects requests from the host role without attestation"
    echo "    - NSM produces valid attestation documents for this enclave image"
    echo "    - Only this specific EIF (matching PCR0) can obtain KMS key material"
    exit 0
else
    echo "  Negative test: FAIL"
    echo ""
    echo "  The KMS policy may not have attestation conditions enforced."
    echo "  Run: terraform apply -var=\"enclave_pcr0=<PCR0_FROM_BUILD>\""
    exit 1
fi

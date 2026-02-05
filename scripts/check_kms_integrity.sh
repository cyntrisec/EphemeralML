#!/usr/bin/env bash
# check_kms_integrity.sh — Audit existing benchmark result dirs for KMS integrity.
#
# Validates that every enclave_results.json in the given directories has:
#   security.kms_exercised = true
#   security.kms_bypassed  = false
#
# Also checks commit consistency, hardware consistency, and JSON parse health.
#
# Usage:
#   ./scripts/check_kms_integrity.sh <result_dir> [result_dir ...]
#   ./scripts/check_kms_integrity.sh benchmark_results_final/kms_validation_*/run_*
#   ./scripts/check_kms_integrity.sh benchmark_results_final/kms_validation_20260206_*/

set -euo pipefail

if [[ $# -eq 0 ]]; then
    cat <<EOF
Usage: $0 <result_dir> [result_dir ...]

Audits benchmark result directories for KMS integrity and consistency.

Examples:
  $0 benchmark_results_final/kms_validation_*/run_*
  $0 benchmark_results_multimodel_20260205/minilm-l6_run*
EOF
    exit 1
fi

PASS=0
FAIL=0
WARN=0
TOTAL=0
COMMITS=()
HARDWARE=()

red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }

for dir in "$@"; do
    [[ -d "$dir" ]] || { yellow "SKIP: not a directory: $dir"; continue; }

    TOTAL=$((TOTAL + 1))
    dir_name="$(basename "$dir")"
    errors=()

    # --- enclave_results.json ---
    enclave="$dir/enclave_results.json"
    if [[ ! -f "$enclave" ]]; then
        errors+=("missing enclave_results.json")
    else
        if ! python3 -c "import json; json.load(open('$enclave'))" 2>/dev/null; then
            errors+=("enclave_results.json: invalid JSON")
        else
            kms_exercised=$(python3 -c "
import json
d = json.load(open('$enclave'))
print(d.get('security', {}).get('kms_exercised', 'MISSING'))" 2>/dev/null)
            kms_bypassed=$(python3 -c "
import json
d = json.load(open('$enclave'))
print(d.get('security', {}).get('kms_bypassed', 'MISSING'))" 2>/dev/null)

            if [[ "$kms_exercised" == "MISSING" ]]; then
                errors+=("enclave_results.json: security.kms_exercised field missing")
            elif [[ "$kms_exercised" != "True" ]]; then
                errors+=("enclave_results.json: kms_exercised=$kms_exercised (expected True)")
            fi

            if [[ "$kms_bypassed" == "MISSING" ]]; then
                errors+=("enclave_results.json: security.kms_bypassed field missing")
            elif [[ "$kms_bypassed" != "False" ]]; then
                errors+=("enclave_results.json: kms_bypassed=$kms_bypassed (expected False)")
            fi

            enc_commit=$(python3 -c "import json; print(json.load(open('$enclave')).get('commit', 'MISSING'))" 2>/dev/null)
            enc_hw=$(python3 -c "import json; print(json.load(open('$enclave')).get('hardware', 'MISSING'))" 2>/dev/null)
            [[ "$enc_commit" != "MISSING" ]] && COMMITS+=("$enc_commit")
            [[ "$enc_hw" != "MISSING" ]] && HARDWARE+=("$enc_hw")
        fi
    fi

    # --- baseline_results.json ---
    baseline="$dir/baseline_results.json"
    if [[ ! -f "$baseline" ]]; then
        errors+=("missing baseline_results.json")
    else
        if ! python3 -c "import json; json.load(open('$baseline'))" 2>/dev/null; then
            errors+=("baseline_results.json: invalid JSON")
        else
            bl_commit=$(python3 -c "import json; print(json.load(open('$baseline')).get('commit', 'MISSING'))" 2>/dev/null)
            bl_hw=$(python3 -c "import json; print(json.load(open('$baseline')).get('hardware', 'MISSING'))" 2>/dev/null)
            [[ "$bl_commit" != "MISSING" ]] && COMMITS+=("$bl_commit")
            [[ "$bl_hw" != "MISSING" ]] && HARDWARE+=("$bl_hw")
        fi
    fi

    # --- run_metadata.json ---
    meta="$dir/run_metadata.json"
    if [[ -f "$meta" ]]; then
        if ! python3 -c "import json; json.load(open('$meta'))" 2>/dev/null; then
            errors+=("run_metadata.json: invalid JSON")
        else
            meta_commit=$(python3 -c "import json; print(json.load(open('$meta')).get('git_commit', 'MISSING'))" 2>/dev/null)
            meta_kms=$(python3 -c "import json; print(json.load(open('$meta')).get('require_kms', 'MISSING'))" 2>/dev/null)
            [[ "$meta_commit" != "MISSING" ]] && COMMITS+=("$meta_commit")
            if [[ "$meta_kms" == "False" ]]; then
                errors+=("run_metadata.json: require_kms=false (run was not KMS-enforced)")
            elif [[ "$meta_kms" == "MISSING" ]]; then
                WARN=$((WARN + 1))
                yellow "  WARN $dir_name: run_metadata.json missing require_kms field (older run format)"
            fi
        fi
    fi

    # --- Report ---
    if [[ ${#errors[@]} -eq 0 ]]; then
        PASS=$((PASS + 1))
        green "  PASS $dir_name (kms_exercised=$kms_exercised, kms_bypassed=$kms_bypassed)"
    else
        FAIL=$((FAIL + 1))
        red "  FAIL $dir_name:"
        for err in "${errors[@]}"; do
            red "    - $err"
        done
    fi
done

echo ""
echo "=== KMS Integrity Audit ==="
echo "Directories checked: $TOTAL"
green "Passed: $PASS"
[[ $FAIL -gt 0 ]] && red "Failed: $FAIL" || echo "Failed: 0"
[[ $WARN -gt 0 ]] && yellow "Warnings: $WARN" || echo "Warnings: 0"

# --- Cross-run consistency ---
if [[ ${#COMMITS[@]} -gt 0 ]]; then
    unique_commits=$(printf '%s\n' "${COMMITS[@]}" | sort -u | wc -l)
    if [[ $unique_commits -eq 1 ]]; then
        echo "Commit: ${COMMITS[0]} (consistent across all artifacts)"
    else
        yellow "Commit: INCONSISTENT ($(printf '%s\n' "${COMMITS[@]}" | sort -u | tr '\n' ' '))"
        FAIL=$((FAIL + 1))
    fi
fi

if [[ ${#HARDWARE[@]} -gt 0 ]]; then
    unique_hw=$(printf '%s\n' "${HARDWARE[@]}" | sort -u | wc -l)
    if [[ $unique_hw -eq 1 ]]; then
        echo "Hardware: ${HARDWARE[0]} (consistent across all artifacts)"
    else
        yellow "Hardware: INCONSISTENT ($(printf '%s\n' "${HARDWARE[@]}" | sort -u | tr '\n' ' '))"
        FAIL=$((FAIL + 1))
    fi
fi

echo ""
if [[ $TOTAL -eq 0 ]]; then
    red "Result: NO VALID DIRECTORIES AUDITED (glob matched nothing or all skipped)"
    exit 1
elif [[ $FAIL -eq 0 ]]; then
    green "Result: ALL CHECKS PASSED"
    exit 0
else
    red "Result: $FAIL CHECK(S) FAILED"
    exit 1
fi

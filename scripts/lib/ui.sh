#!/usr/bin/env bash
# EphemeralML shared shell UI helpers.
#
# Source this file in any script:
#   SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "${SCRIPT_DIR}/../lib/ui.sh"   # from scripts/gcp/
#   source "${SCRIPT_DIR}/lib/ui.sh"      # from scripts/
#
# Respects: NO_COLOR, CI, VERBOSE, EPHEMERALML_NO_MASCOT
# TTY detection: colors enabled only when stdout is a terminal.

# ---------------------------------------------------------------------------
# Color / TTY detection
# ---------------------------------------------------------------------------
_UI_COLOR=false
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ -z "${CI:-}" ]; then
    _UI_COLOR=true
fi

_UI_BOLD=""
_UI_GREEN=""
_UI_RED=""
_UI_YELLOW=""
_UI_DIM=""
_UI_RESET=""

if $_UI_COLOR; then
    _UI_BOLD="\033[1m"
    _UI_GREEN="\033[32m"
    _UI_RED="\033[31m"
    _UI_YELLOW="\033[33m"
    _UI_DIM="\033[2m"
    _UI_RESET="\033[0m"
fi

# ---------------------------------------------------------------------------
# Basic output helpers
# ---------------------------------------------------------------------------

ui_header() {
    local title="$1"
    local bar
    bar="$(printf '=%.0s' {1..62})"
    echo -e "  ${_UI_DIM}${bar}${_UI_RESET}"
    echo -e "  ${_UI_BOLD}${title}${_UI_RESET}"
    echo -e "  ${_UI_DIM}${bar}${_UI_RESET}"
}

ui_section() {
    local title="$1"
    local thin
    thin="$(printf -- '-%.0s' {1..62})"
    echo -e "  ${_UI_DIM}${thin}${_UI_RESET}"
    echo -e "  ${_UI_BOLD}${title}:${_UI_RESET}"
    echo -e "  ${_UI_DIM}${thin}${_UI_RESET}"
}

ui_kv() {
    local key="$1"
    local value="$2"
    printf "  %-13s %s\n" "${key}:" "${value}"
}

ui_ok() {
    local msg="$1"
    echo -e "  ${_UI_GREEN}${_UI_BOLD}${msg}${_UI_RESET}"
}

ui_fail() {
    local msg="$1"
    echo -e "  ${_UI_RED}${_UI_BOLD}${msg}${_UI_RESET}"
}

ui_warn() {
    local msg="$1"
    echo -e "  ${_UI_YELLOW}${msg}${_UI_RESET}"
}

ui_info() {
    local msg="$1"
    echo "  ${msg}"
}

ui_bullet() {
    local msg="$1"
    echo "    - ${msg}"
}

ui_blank() {
    echo
}

# ---------------------------------------------------------------------------
# run_step — run a command with collapsed output
# ---------------------------------------------------------------------------
# Usage: run_step STEP_NUM TOTAL LABEL COMMAND...
#
# 1. Prints "[N/M] Label..."
# 2. Runs command, captures stdout+stderr to tempfile
# 3. On success: prints "[OK] Label (Xs)"
# 4. On failure: prints "[FAIL] Label (exit N)" + last 20 lines + log path
# 5. With VERBOSE=true: streams output live instead of capturing
run_step() {
    local step_num="$1"; shift
    local step_total="$1"; shift
    local label="$1"; shift
    # Remaining args are the command

    local prefix="[${step_num}/${step_total}]"

    if [ "${VERBOSE:-false}" = "true" ]; then
        echo -e "${_UI_DIM}${prefix}${_UI_RESET} ${label}..."
        # Capture exit code without triggering set -e
        local exit_code=0
        "$@" || exit_code=$?
        if [ $exit_code -eq 0 ]; then
            echo -e "  ${_UI_GREEN}[OK]${_UI_RESET} ${label}"
        else
            echo -e "  ${_UI_RED}[FAIL]${_UI_RESET} ${label} (exit ${exit_code})"
            return $exit_code
        fi
        return 0
    fi

    echo -e -n "${_UI_DIM}${prefix}${_UI_RESET} ${label}..."

    local logfile
    logfile="$(mktemp "/tmp/ephemeralml-step-${step_num}-XXXXXX.log")"

    local start_time
    start_time=$(date +%s)

    # Capture exit code without triggering set -e
    local exit_code=0
    "$@" >"${logfile}" 2>&1 || exit_code=$?

    local end_time
    end_time=$(date +%s)
    local elapsed=$(( end_time - start_time ))

    if [ $exit_code -eq 0 ]; then
        echo -e "\r  ${_UI_GREEN}[OK]${_UI_RESET} ${label} (${elapsed}s)          "
        rm -f "${logfile}"
    else
        echo -e "\r  ${_UI_RED}[FAIL]${_UI_RESET} ${label} (exit ${exit_code}, ${elapsed}s)          "
        echo
        echo "  Last 20 lines:"
        tail -20 "${logfile}" | sed 's/^/    /'
        echo
        echo "  Full log: ${logfile}"
        return $exit_code
    fi
}

# ---------------------------------------------------------------------------
# Ghost mascot (shell version)
# ---------------------------------------------------------------------------
_UI_MASCOT=true
if [ -n "${EPHEMERALML_NO_MASCOT:-}" ] || ! $_UI_COLOR; then
    _UI_MASCOT=false
fi

ui_ghost_idle() {
    if $_UI_MASCOT; then
        echo "    .--."
        echo "   / oo \\"
        echo "   \\ -- /"
    fi
}

ui_ghost_ok() {
    if $_UI_MASCOT; then
        echo -e "    ${_UI_GREEN}.--."
        echo -e "   / ^^ \\"
        echo -e "   \\ -- /${_UI_RESET}"
    fi
}

ui_ghost_fail() {
    if $_UI_MASCOT; then
        echo -e "    ${_UI_RED}.--."
        echo -e "   / xx \\"
        echo -e "   \\ -- /${_UI_RESET}"
    fi
}

#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/ephemeralml-target}"
mkdir -p "$TARGET_DIR"

echo "Using CARGO_TARGET_DIR=$TARGET_DIR" >&2
exec env CARGO_TARGET_DIR="$TARGET_DIR" cargo "$@"

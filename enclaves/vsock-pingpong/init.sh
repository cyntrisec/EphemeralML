#!/bin/sh
# PID1 wrapper for Nitro Enclaves.
# Make sure we always emit something to the serial console, and keep PID1 alive
# even if the app crashes/exits (so we can read logs via attach-console).

exec </dev/console >/dev/console 2>&1
set -x

echo "[init] starting"
uname -a || true

# Minimal mounts (best-effort)
mkdir -p /proc /sys /dev || true
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true

echo "[init] ls -la /"
ls -la / || true

mode="${VSOCK_PINGPONG_MODE:-}"
if [ $# -ge 2 ] && [ "$1" = "--mode" ]; then
  mode="$2"
fi
if [ -z "$mode" ]; then
  mode="vsock"
fi

echo "[init] launching /vsock-pingpong --mode ${mode} (argv: $*)"
export RUST_BACKTRACE=1

# Run as a child so PID1 stays alive even if the app dies.
# Use env to propagate current environment variables
env /vsock-pingpong --mode "$mode"
rc=$?
echo "[init] /vsock-pingpong exited rc=$rc"

# Keep enclave alive for console inspection.
sleep 1000000

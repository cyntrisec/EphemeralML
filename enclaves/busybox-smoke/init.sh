#!/bin/sh
exec </dev/console >/dev/console 2>&1
set -x

echo "[busybox-smoke] alive"
uname -a || true
ls -la / || true
sleep 1000000

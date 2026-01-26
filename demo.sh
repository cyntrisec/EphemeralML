#!/bin/bash
# EphemeralML Zero-Trust Demo Script

echo "🚀 Starting EphemeralML Zero-Trust Demo..."
echo "------------------------------------------"

# 1. Kill any existing processes
pkill -f "ephemeral-ml-enclave" || true
pkill -f "spy_host" || true

# 2. Build the project
source "$HOME/.cargo/env"
# Navigate to the script's directory
cd "$(dirname "$0")"
echo "🔨 Building project components..."
cargo build --workspace --features mock -q

# 3. Start Enclave Server (Port 8082)
echo "🔒 Starting Secure Enclave (Mock) on port 8082..."
cargo run -p ephemeral-ml-enclave --features mock > /dev/null 2>&1 &
ENCLAVE_PID=$!
sleep 2

# 4. Start Spy Proxy (Port 8081 -> 8082)
echo "🕵️  Starting Spy Proxy on port 8081 (INTERCEPTION ACTIVE)..."
rm -f spy_intercept.log
cargo run -p ephemeral-ml-host --bin spy_host > /dev/null 2>&1 &
PROXY_PID=$!
sleep 2

# 5. Launch Commander CLI
echo "------------------------------------------"
echo "✅ Demo is ready!"
echo "User Interface: Port 8081 (routed through Spy Proxy)"
echo "Spy Log: projects/EphemeralML/spy_intercept.log"
echo "------------------------------------------"
echo "Now, type a secret message in the Commander."
echo "Then, we will check the Spy Log to see if anything was leaked."
echo "------------------------------------------"

cargo run -p ephemeral-ml-client --bin commander -- 8081

# Cleanup on exit
echo "🛑 Cleaning up processes..."
kill $ENCLAVE_PID
kill $PROXY_PID
echo "Done."

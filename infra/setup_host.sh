#!/bin/bash
# EphemeralML AWS Host Setup Script
set -e

echo "🚀 Starting Host Setup..."

# 1. Update and install basic dependencies
sudo apt-get update
sudo apt-get install -y docker.io curl git build-essential libssl-dev

# 2. Install AWS Nitro Enclaves CLI
# For Ubuntu 22.04 (Jammy)
echo "🔧 Installing Nitro Enclaves CLI..."
curl -s https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/main/scripts/setup-ubuntu.sh | bash

# 3. Add user to groups
sudo usermod -aG ne $USER
sudo usermod -aG docker $USER

# 4. Configure Enclave Resources
# We will allocate 2 vCPUs and 2048 MB of RAM for the enclave
echo "📏 Allocating resources for enclave..."
cat <<EOF | sudo tee /etc/nitro_enclaves/allocator.yaml
---
# Enclave resource allocator configuration
# Total CPU count to be used for enclaves
cpu_count: 2
# Total memory size in MiB to be used for enclaves
memory_mib: 2048
EOF

# 5. Restart services
sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl restart docker

echo "✅ Host Setup Complete!"
echo "⚠️ Please LOG OUT and LOG IN again for group changes to take effect."
echo "Then you can run 'nitro-cli --version' to verify."

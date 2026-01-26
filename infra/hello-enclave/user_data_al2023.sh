#!/bin/bash
set -euo pipefail

# Bootstrap for Nitro Enclaves "hello" host (Amazon Linux 2023)
# - Enables SSM connectivity
# - Installs docker + nitro tooling + allocator
# - Reserves a small enclave budget

exec > >(tee /var/log/ephemeralml-hello-bootstrap.log | logger -t user-data -s 2>/dev/console) 2>&1

echo "[ephemeralml] bootstrapping (AL2023)..."

# AL2023 uses dnf
dnf update -y

# SSM agent is typically preinstalled, but ensure it's running.
systemctl enable --now amazon-ssm-agent || true

# Core tools
# Note: package names can vary slightly across AL2023 minor releases; keep this best-effort.
dnf install -y git jq python3 || true

# Docker
# (AL2023 repos include docker + containerd)
dnf install -y docker || true
systemctl enable --now docker || true
usermod -aG docker ec2-user || true

# Nitro Enclaves tooling
# Packages are available in Amazon repos on Nitro-capable instances.
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel aws-nitro-enclaves-allocator || true
systemctl enable --now nitro-enclaves-allocator.service || true

# Reserve small resources (adjust later): 2 vCPU + 1024 MiB
mkdir -p /etc/nitro_enclaves
cat >/etc/nitro_enclaves/allocator.yaml <<'EOF'
---
cpu_count: 2
memory_mib: 1024
EOF

systemctl restart nitro-enclaves-allocator.service || true

echo "[ephemeralml] bootstrap complete. Run: nitro-cli --version"

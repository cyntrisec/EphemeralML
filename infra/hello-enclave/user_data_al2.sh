#!/bin/bash
set -euo pipefail

# Minimal bootstrap for Nitro Enclaves "hello world" host (Amazon Linux 2)
# - Enables SSM connectivity
# - Installs docker + nitro-cli + allocator
# - Reserves a small enclave budget

exec > >(tee /var/log/ephemeralml-hello-bootstrap.log | logger -t user-data -s 2>/dev/console) 2>&1

echo "[ephemeralml] bootstrapping..."

yum update -y

# SSM agent is typically preinstalled on AL2, but ensure it's running.
systemctl enable --now amazon-ssm-agent || true

# Docker
amazon-linux-extras install -y docker
systemctl enable --now docker
usermod -aG docker ec2-user || true

# Nitro Enclaves
# On AL2 these packages are available via yum repos.
yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel || true

systemctl enable --now nitro-enclaves-allocator.service || true

# Reserve small resources (adjust later): 2 vCPU + 1024 MiB
cat >/etc/nitro_enclaves/allocator.yaml <<'EOF'
---
cpu_count: 2
memory_mib: 1024
EOF

systemctl restart nitro-enclaves-allocator.service || true

echo "[ephemeralml] bootstrap complete. Run: nitro-cli --version"

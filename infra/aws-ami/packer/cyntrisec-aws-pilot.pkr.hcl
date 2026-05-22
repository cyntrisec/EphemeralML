packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.3.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ami_name" {
  type    = string
  default = "cyntrisec-aws-pilot"
}

variable "release_bundle" {
  type = string
}

variable "instance_type" {
  type    = string
  default = "m6i.xlarge"
}

variable "ssh_username" {
  type    = string
  default = "ec2-user"
}

variable "subnet_id" {
  type    = string
  default = ""
}

variable "ebs_kms_key_id" {
  type        = string
  description = "Customer-managed KMS key ID or ARN used to encrypt the AMI snapshot. Required for cross-account AMI sharing."
}

source "amazon-ebs" "al2023" {
  region        = var.region
  instance_type = var.instance_type
  ssh_username  = var.ssh_username
  ami_name      = var.ami_name
  ami_description = "Cyntrisec AWS pilot AMI with fixed EIF and host runtime"

  source_ami_filter {
    filters = {
      name                = "al2023-ami-2023.*-kernel-*-x86_64"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["amazon"]
    most_recent = true
  }

  subnet_id = var.subnet_id != "" ? var.subnet_id : null

  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 40
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = var.ebs_kms_key_id
    delete_on_termination = true
  }

  tags = {
    Name              = var.ami_name
    Product           = "cyntrisec"
    "cyntrisec:stage" = "private-pilot"
  }
}

build {
  sources = ["source.amazon-ebs.al2023"]

  provisioner "file" {
    source      = var.release_bundle
    destination = "/tmp/cyntrisec-release"
  }

  provisioner "shell" {
    inline = [
      "set -euxo pipefail",
      "BUNDLE_ROOT=/tmp/cyntrisec-release",
      "if [ ! -d $BUNDLE_ROOT/opt/cyntrisec ]; then BUNDLE_ROOT=$(find /tmp/cyntrisec-release -mindepth 1 -maxdepth 1 -type d | head -n1); fi",
      "test -d $BUNDLE_ROOT/opt/cyntrisec",
      "sudo dnf update -y",
      "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel jq awscli shadow-utils",
      "sudo usermod -aG ne ec2-user || true",
      "sudo install -d -m 0755 /opt/cyntrisec /etc/cyntrisec /var/lib/cyntrisec /var/log/cyntrisec",
      "sudo cp -a $BUNDLE_ROOT/opt/cyntrisec/. /opt/cyntrisec/",
      "sudo cp -a $BUNDLE_ROOT/etc/cyntrisec/. /etc/cyntrisec/",
      "sudo install -m 0644 /opt/cyntrisec/systemd/cyntrisec-bootstrap.service /etc/systemd/system/cyntrisec-bootstrap.service",
      "printf -- '---\\nmemory_mib: 4096\\ncpu_count: 2\\n' | sudo tee /etc/nitro_enclaves/allocator.yaml >/dev/null",
      "sudo systemctl enable nitro-enclaves-allocator.service",
      "sudo /opt/cyntrisec/bin/cyntrisec-bootstrap --help >/dev/null",
      "sudo /opt/cyntrisec/bin/ephemeralml-doctor --help >/dev/null",
      "sudo /opt/cyntrisec/bin/ephemeralml-smoke-test --help >/dev/null",
      "sudo /opt/cyntrisec/bin/ephemeralml-verify --help >/dev/null",
      "test -f /opt/cyntrisec/eif/ephemeralml-pilot.eif",
      "sudo rm -rf /tmp/cyntrisec-release /home/ec2-user/.ssh/authorized_keys /root/.ssh/authorized_keys /var/lib/cloud/instances/* /var/log/cloud-init*.log /var/log/dnf*.log",
      "sudo dnf clean all"
    ]
  }
}

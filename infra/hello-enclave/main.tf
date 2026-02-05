terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.12"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region to deploy the hello-world Nitro Enclave host"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix for resources"
  type        = string
  default     = "ephemeral-ml"
}

variable "instance_type" {
  description = "Parent EC2 instance type (must support Nitro Enclaves). Note: some AMD 'a' families (e.g., c6a) do NOT support Enclaves."
  type        = string
  default     = "m6i.xlarge"
}

variable "availability_zone" {
  description = "Availability Zone to place the subnet/instance in (some types not available in all AZs)."
  type        = string
  default     = "us-east-1a"
}

variable "ssh_public_key" {
  description = "Optional SSH public key. Leave empty to use SSM-only (recommended)."
  type        = string
  default     = ""
}

variable "enclave_pcr0" {
  description = "PCR0 (ImageSha384) from nitro-cli build-enclave. Empty = no attestation condition (dev mode)."
  type        = string
  default     = ""
}

variable "enclave_pcr1" {
  description = "PCR1 (kernel) from nitro-cli build-enclave. Empty = skip."
  type        = string
  default     = ""
}

variable "enclave_pcr2" {
  description = "PCR2 (application) from nitro-cli build-enclave. Empty = skip."
  type        = string
  default     = ""
}

locals {
  use_ssh = length(trimspace(var.ssh_public_key)) > 0

  # Build PCR conditions map only for non-empty PCR variables
  pcr_conditions = merge(
    var.enclave_pcr0 != "" ? { "kms:RecipientAttestation:ImageSha384" = var.enclave_pcr0 } : {},
    var.enclave_pcr1 != "" ? { "kms:RecipientAttestation:PCR1" = var.enclave_pcr1 } : {},
    var.enclave_pcr2 != "" ? { "kms:RecipientAttestation:PCR2" = var.enclave_pcr2 } : {},
  )
  has_pcr_conditions = length(local.pcr_conditions) > 0
}

data "aws_caller_identity" "current" {}

# Amazon Linux 2 (Nitro Enclaves packages/allocator are available out of the box in standard repos).
data "aws_ami" "al2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_vpc" "this" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-hello-vpc"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${var.project_name}-hello-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.this.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-hello-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = {
    Name = "${var.project_name}-hello-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "host" {
  name        = "${var.project_name}-hello-host-sg"
  description = "Hello-world Nitro Enclave host SG: no inbound, outbound 80/443"
  vpc_id      = aws_vpc.this.id

  egress {
    description = "HTTP outbound (AL2 yum repos can redirect via HTTP)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTPS outbound for SSM / yum / github"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Optional: if you want to SSH for bootstrap, pass ssh_public_key and add an ingress rule.
  dynamic "ingress" {
    for_each = local.use_ssh ? [1] : []
    content {
      description = "SSH (optional)"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    Name = "${var.project_name}-hello-host-sg"
  }
}

resource "aws_iam_role" "host" {
  name = "${var.project_name}-hello-host-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# S3 access for model storage bucket
resource "aws_iam_role_policy" "s3_model_access" {
  name = "${var.project_name}-s3-model-access"
  role = aws_iam_role.host.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:HeadObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::ephemeral-ml-models-*",
          "arn:aws:s3:::ephemeral-ml-models-*/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "host" {
  name = "${var.project_name}-hello-host-profile"
  role = aws_iam_role.host.name
}

# IAM resources can be eventually-consistent for EC2 RunInstances.
# A short sleep avoids transient "Invalid IAM Instance Profile name".
resource "time_sleep" "wait_iam_instance_profile" {
  depends_on      = [aws_iam_instance_profile.host]
  create_duration = "20s"
}

resource "aws_key_pair" "ssh" {
  count      = local.use_ssh ? 1 : 0
  key_name   = "${var.project_name}-hello-key"
  public_key = var.ssh_public_key
}

resource "aws_instance" "host" {
  ami           = data.aws_ami.al2.id
  instance_type = var.instance_type

  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.host.id]

  iam_instance_profile = aws_iam_instance_profile.host.name

  depends_on = [time_sleep.wait_iam_instance_profile]

  enclave_options {
    enabled = true
  }

  # Default AL2023 root volume can be tiny on some AMIs; Docker + rust image pulls need more.
  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  key_name = local.use_ssh ? aws_key_pair.ssh[0].key_name : null

  metadata_options {
    http_tokens = "required" # IMDSv2
  }

  user_data = file("${path.module}/user_data_al2.sh")

  tags = {
    Name = "${var.project_name}-hello-host"
  }
}

# KMS Key for Confidential Inference
resource "aws_kms_key" "enclave_key" {
  description             = "KMS key for EphemeralML enclave attestation-bound decryption"
  deletion_window_in_days = 7
  enable_key_rotation     = false # Not needed for hello-world

  policy = local.has_pcr_conditions ? jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EphemeralML-Deployer"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Enclave Decrypt with Attestation"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.host.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource  = "*"
        Condition = {
          StringEqualsIgnoreCase = local.pcr_conditions
        }
      }
    ]
  }) : jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EphemeralML-Deployer"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Enclave Decrypt with Attestation"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.host.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "enclave_key" {
  name          = "alias/${var.project_name}-test"
  target_key_id = aws_kms_key.enclave_key.key_id
}

# ── KMS Attestation Test Key ──
# Separate key with STRICT PCR0 enforcement — all Decrypt/GenerateDataKey
# operations REQUIRE a valid attestation document with matching PCR0.
# Used by `scripts/run_kms_audit.sh` to verify positive and negative
# attestation enforcement on real Nitro hardware.

variable "attest_test_pcr0" {
  description = "PCR0 (ImageSha384) for the kms-audit EIF. Required — no default, must be set from actual EIF build output."
  type        = string
  default     = ""
}

# IAM policy granting the host role permission to use the attest test key.
# KMS requires BOTH a key policy AND an identity-based policy when the key policy
# includes the root account statement (which enables IAM policy evaluation).
# The key policy's PCR0 condition still enforces attestation — the IAM policy just
# provides the identity-based "half" of the authorization.
resource "aws_iam_role_policy" "kms_attest_test_access" {
  count = var.attest_test_pcr0 != "" ? 1 : 0
  name  = "${var.project_name}-kms-attest-test-access"
  role  = aws_iam_role.host.id

  # NOTE: The IAM policy must NOT include kms:RecipientAttestation conditions.
  # Those condition keys are only valid in KMS key policies, not IAM policies.
  # Attestation enforcement is handled by the key policy's Condition block.
  # The IAM policy provides the identity-based "half" of authorization that KMS
  # requires when the key policy enables IAM policy evaluation (via root statement).
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [aws_kms_key.attest_test_key[0].arn]
      }
    ]
  })
}

resource "aws_kms_key" "attest_test_key" {
  count                   = var.attest_test_pcr0 != "" ? 1 : 0
  description             = "EphemeralML attestation enforcement test key (strict PCR0)"
  deletion_window_in_days = 7
  enable_key_rotation     = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EphemeralML-Deployer"
        Effect = "Allow"
        Principal = {
          AWS = data.aws_caller_identity.current.arn
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Deny Host Role Without Attestation"
        Effect = "Deny"
        Principal = {
          AWS = aws_iam_role.host.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          Null = {
            "kms:RecipientAttestation:ImageSha384" = "true"
          }
        }
      },
      {
        Sid    = "Allow Enclave with Matching PCR0 Only"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.host.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:ImageSha384" = var.attest_test_pcr0
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "attest_test_key" {
  count         = var.attest_test_pcr0 != "" ? 1 : 0
  name          = "alias/${var.project_name}-attest-test"
  target_key_id = aws_kms_key.attest_test_key[0].key_id
}

output "instance_id" {
  value = aws_instance.host.id
}

output "instance_public_ip" {
  value = aws_instance.host.public_ip
}

output "ssm_start_session" {
  value = "aws ssm start-session --target ${aws_instance.host.id}"
}

output "kms_key_arn" {
  value = aws_kms_key.enclave_key.arn
}

output "attest_test_key_arn" {
  value = var.attest_test_pcr0 != "" ? aws_kms_key.attest_test_key[0].arn : ""
}

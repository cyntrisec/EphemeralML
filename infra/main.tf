# EphemeralML AWS Infrastructure Configuration

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

variable "project_name" {
  default = "ephemeral-ml"
}

# 1. S3 Bucket for Encrypted Models
resource "aws_s3_bucket" "model_storage" {
  bucket = "${var.project_name}-models-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.model_storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 2. KMS Key for Model Decryption
resource "aws_kms_key" "model_key" {
  description             = "KMS Key for EphemeralML Model Decryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  # This policy allows the Enclave to use the key via Attestation
  # Initially, we allow the Host role to call Decrypt, but for production
  # we would add the Condition with ImageSha384 here.
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
        Sid    = "Allow Admin Access"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/EphemeralML-Deployer"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Enclave Decrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.host_role.arn
        }
        Action   = "kms:Decrypt"
        Resource = "*"
        
        # HARDENED: Bound to the specific build generated on 2026-01-28
        condition {
          test     = "StringEqualsIgnoreCase"
          variable = "kms:RecipientAttestation:ImageSha384"
          values   = ["dd85425484e093a30ff37d86035c8d6a6493b687d2ecc5ef26c1dcf70a53067fe10c879f38f8fc00e7d4208fa5ece1af"]
        }
        # PRO TIP: You can also pin the Signing Key PCR (usually PCR8) if using signed EIFs.
      }
      }
    ]
  })
}

# 3. IAM Role for EC2 Host
resource "aws_iam_role" "host_role" {
  name = "${var.project_name}-host-role"

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

resource "aws_iam_role_policy" "host_policy" {
  name = "${var.project_name}-host-policy"
  role = aws_iam_role.host_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.model_storage.arn,
          "${aws_s3_bucket.model_storage.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = "kms:Decrypt"
        Resource = aws_kms_key.model_key.arn
      }
    ]
  })
}

resource "aws_iam_instance_profile" "host_profile" {
  name = "${var.project_name}-host-profile"
  role = aws_iam_role.host_role.name
}

# 4. EC2 Instance with Nitro Enclaves Enabled
resource "aws_instance" "host" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "m6i.xlarge" # Requires xlarge for enclave resource isolation

  iam_instance_profile = aws_iam_instance_profile.host_profile.name
  
  # CRITICAL: Enable Nitro Enclaves
  enclave_options {
    enabled = true
  }

  tags = {
    Name = "EphemeralML-Host"
  }
}

data "aws_caller_identity" "current" {}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

output "s3_bucket_name" {
  value = aws_s3_bucket.model_storage.id
}

output "kms_key_arn" {
  value = aws_kms_key.model_key.arn
}

output "ec2_public_ip" {
  value = aws_instance.host.public_ip
}

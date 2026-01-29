# Module for EphemeralML Enclave Host

variable "aws_region" {
  type = string
}

variable "project_name" {
  type = string
}

variable "instance_type" {
  type = string
}

variable "enclave_image_sha384" {
  type = string
}

variable "account_id" {
  type = string
}

provider "aws" {
  region = var.aws_region
}

# 1. S3 Bucket for Encrypted Models (Region-specific)
resource "aws_s3_bucket" "model_storage" {
  bucket = "${var.project_name}-models-${var.aws_region}-${var.account_id}"
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.model_storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.model_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 2. KMS Key for Model Decryption
resource "aws_kms_key" "model_key" {
  description             = "KMS Key for EphemeralML Model Decryption in ${var.aws_region}"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
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
        
        condition {
          test     = "StringEqualsIgnoreCase"
          variable = "kms:RecipientAttestation:ImageSha384"
          values   = [var.enclave_image_sha384]
        }
      }
    ]
  })
}

resource "aws_kms_alias" "model_key_alias" {
  name          = "alias/${var.project_name}-model-key"
  target_key_id = aws_kms_key.model_key.key_id
}

# 3. IAM Role for EC2 Host
resource "aws_iam_role" "host_role" {
  name = "${var.project_name}-host-role-${var.aws_region}"

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
  name = "${var.project_name}-host-policy-${var.aws_region}"
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
  name = "${var.project_name}-host-profile-${var.aws_region}"
  role = aws_iam_role.host_role.name
}

# 4. EC2 Instance with Nitro Enclaves Enabled
resource "aws_instance" "host" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  iam_instance_profile = aws_iam_instance_profile.host_profile.name
  
  enclave_options {
    enabled = true
  }

  tags = {
    Name = "${var.project_name}-Host-${var.aws_region}"
  }
}

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

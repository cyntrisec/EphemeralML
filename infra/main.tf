# EphemeralML AWS Infrastructure Configuration

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}

# Primary Region deployment
module "host_us_east_1" {
  source = "./modules/enclave_host"
  
  aws_region           = "us-east-1"
  project_name         = var.project_name
  instance_type        = var.instance_type
  enclave_image_sha384 = var.enclave_image_sha384
  account_id           = data.aws_caller_identity.current.account_id
}

# Secondary Region deployment (Example of multi-region robustness)
# To enable, just uncomment and ensure provider is configured
/*
module "host_us_west_2" {
  source = "./modules/enclave_host"
  
  aws_region           = "us-west-2"
  project_name         = var.project_name
  instance_type        = var.instance_type
  enclave_image_sha384 = var.enclave_image_sha384
  account_id           = data.aws_caller_identity.current.account_id
}
*/

output "primary_s3_bucket" {
  value = module.host_us_east_1.s3_bucket_name
}

output "primary_kms_key_arn" {
  value = module.host_us_east_1.kms_key_arn
}

output "primary_ec2_public_ip" {
  value = module.host_us_east_1.ec2_public_ip
}

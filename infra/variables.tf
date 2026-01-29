# Variables for EphemeralML Infrastructure

variable "aws_regions" {
  description = "List of AWS regions for multi-region deployment"
  type        = list(string)
  default     = ["us-east-1", "us-west-2", "eu-central-1"]
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "ephemeral-ml"
}

variable "instance_type" {
  description = "EC2 instance type for the host"
  type        = string
  default     = "m6i.xlarge"
}

variable "enclave_image_sha384" {
  description = "SHA384 of the Enclave Image File (EIF) for KMS attestation"
  type        = string
  default     = "dd85425484e093a30ff37d86035c8d6a6493b687d2ecc5ef26c1dcf70a53067fe10c879f38f8fc00e7d4208fa5ece1af"
}

variable "enclave_cpu_count" {
  description = "Number of vCPUs to allocate to the enclave"
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  description = "Memory in MiB to allocate to the enclave"
  type        = number
  default     = 2048
}

# terraform/variables.tf

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

output "s3_bucket_name" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.application_logs.id
}

output "ec2_instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.application_server.id
}

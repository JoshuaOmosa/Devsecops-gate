# terraform/main.tf
#
# Reference infrastructure used to exercise Checkov / TFLint in CI.
# Hardened by design: private networking, encryption at rest, least-
# privilege IAM, and no public ingress beyond HTTPS from an internal CIDR.

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "application_logs" {
  bucket = "devsecops-gateway-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "Application Logs"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_public_access_block" "application_logs" {
  bucket                  = aws_s3_bucket.application_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "application_logs" {
  bucket = aws_s3_bucket.application_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support    = true

  tags = {
    Name = "devsecops-vpc"
  }
}

resource "aws_subnet" "main" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = {
    Name = "devsecops-subnet"
  }
}

resource "aws_security_group" "main" {
  name_prefix = "devsecops-"
  description = "Security group for DevSecOps gateway reference app"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internal network only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "Allow outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "devsecops-main-sg"
  }
}

resource "aws_iam_role" "ec2_role" {
  name_prefix        = "devsecops-ec2-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# Least-privilege: SSM only, no AdministratorAccess.
resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name_prefix = "devsecops-ec2-"
  role        = aws_iam_role.ec2_role.name
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "application_server" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.main.id
  associate_public_ip_address = false
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  monitoring                  = true

  root_block_device {
    encrypted             = true
    volume_size            = 20
    delete_on_termination = true
  }

  tags = {
    Name        = "DevSecOps-Gateway-Server"
    Environment = var.environment
  }

  depends_on = [aws_security_group.main]
}

I'll create enterprise-grade Terraform code for your Quidditch application infrastructure. Here's the complete implementation:

## Directory Structure
```
quidditch-infrastructure/
├── main.tf
├── variables.tf
├── outputs.tf
├── terraform.tfvars.example
├── modules/
│   ├── networking/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── compute/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── lambda/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── lambda/
    └── quidditch-app.zip
```

## Root Configuration Files

### main.tf
```hcl
# Terraform configuration block with required providers and backend
terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }

  # Configure remote state backend (uncomment and configure for production)
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "quidditch/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

# AWS Provider configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "terraform"
    }
  }
}

# Data source to get current AWS caller identity
data "aws_caller_identity" "current" {}

# Data source to get availability zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Random string for unique resource naming
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

# Local values for common configurations
locals {
  common_tags = {
    Environment = var.environment
    Project     = var.project_name
    ManagedBy   = "terraform"
    CreatedBy   = data.aws_caller_identity.current.user_id
    Timestamp   = timestamp()
  }
  
  resource_prefix = "${var.project_name}-${var.environment}"
}

# Networking module
module "networking" {
  source = "./modules/networking"

  project_name         = var.project_name
  environment         = var.environment
  vpc_cidr            = var.vpc_cidr
  availability_zones  = slice(data.aws_availability_zones.available.names, 0, 2)
  public_subnet_cidrs = var.public_subnet_cidrs
  
  tags = local.common_tags
}

# Compute module for EC2 instances
module "compute" {
  source = "./modules/compute"

  project_name           = var.project_name
  environment           = var.environment
  vpc_id                = module.networking.vpc_id
  public_subnet_id      = module.networking.public_subnet_ids[0]
  instance_type         = var.instance_type
  key_pair_name         = var.key_pair_name
  allowed_cidr_blocks   = var.allowed_cidr_blocks
  
  tags = local.common_tags
  
  depends_on = [module.networking]
}

# Lambda module for serverless functions
module "lambda" {
  source = "./modules/lambda"

  project_name    = var.project_name
  environment    = var.environment
  vpc_id         = module.networking.vpc_id
  subnet_ids     = module.networking.public_subnet_ids
  lambda_runtime = var.lambda_runtime
  
  tags = local.common_tags
  
  depends_on = [module.networking]
}
```

### variables.tf
```hcl
# Project configuration variables
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "quidditch"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# AWS configuration variables
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

# Networking variables
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
  
  validation {
    condition     = length(var.public_subnet_cidrs) >= 2
    error_message = "At least 2 public subnets are required for high availability."
  }
}

# EC2 configuration variables
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
  
  validation {
    condition     = contains(["t3.micro", "t3.small", "t3.medium", "t3.large"], var.instance_type)
    error_message = "Instance type must be a valid t3 instance type."
  }
}

variable "key_pair_name" {
  description = "Name of AWS key pair for EC2 access"
  type        = string
  default     = ""
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access EC2 instance"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# Lambda configuration variables
variable "lambda_runtime" {
  description = "Runtime for Lambda function"
  type        = string
  default     = "python3.9"
  
  validation {
    condition     = contains(["python3.8", "python3.9", "python3.10", "nodejs18.x", "nodejs16.x"], var.lambda_runtime)
    error_message = "Lambda runtime must be a supported version."
  }
}
```

### outputs.tf
```hcl
# VPC outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.networking.vpc_id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.networking.vpc_cidr_block
}

# Subnet outputs
output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = module.networking.public_subnet_ids
}

# EC2 outputs
output "ec2_instance_id" {
  description = "ID of the EC2 instance"
  value       = module.compute.instance_id
}

output "ec2_public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = module.compute.public_ip
  sensitive   = false
}

output "ec2_public_dns" {
  description = "Public DNS name of the EC2 instance"
  value       = module.compute.public_dns
}

# Lambda outputs
output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = module.lambda.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = module.lambda.function_arn
}

output "lambda_invoke_url" {
  description = "API Gateway invoke URL for Lambda function"
  value       = module.lambda.invoke_url
  sensitive   = false
}

# Security Group outputs
output "ec2_security_group_id" {
  description = "ID of the EC2 security group"
  value       = module.compute.security_group_id
}
```

### terraform.tfvars.example
```hcl
# Copy this file to terraform.tfvars and customize as needed

# Project configuration
project_name = "quidditch"
environment  = "dev"

# AWS configuration
aws_region = "us-east-1"

# Networking configuration
vpc_cidr             = "10.0.0.0/16"
public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]

# EC2 configuration
instance_type         = "t3.micro"
key_pair_name        = "your-key-pair"
allowed_cidr_blocks  = ["0.0.0.0/0"]  # Restrict this in production

# Lambda configuration
lambda_runtime = "python3.9"
```

## Module Configurations

### modules/networking/main.tf
```hcl
# VPC configuration
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-vpc"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-igw"
  })
}

# Public subnets
resource "aws_subnet" "public" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-public-subnet-${count.index + 1}"
    Type = "public"
  })
}

# Route table for public subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-public-rt"
  })
}

# Route table associations for public subnets
resource "aws_route_table_association" "public" {
  count = length(aws_subnet.public)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# VPC Flow Logs for security monitoring
resource "aws_flow_log" "vpc" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "vpc_flow_log" {
  name              = "/aws/vpc/flowlogs/${var.project_name}-${var.environment}"
  retention_in_days = 7
  kms_key_id        = aws_kms_key.logs.arn

  tags = var.tags
}

# KMS key for log encryption
resource "aws_kms_key" "logs" {
  description             = "KMS key for ${var.project_name} ${var.environment} log encryption"
  deletion_window_in_days = 7

  tags = merge(var.tags, {
    Name = "${var.project_name}-${var.environment}-logs-key"
  })
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.project_name}-${var.environment}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# IAM role for VPC Flow Logs
resource "aws_iam_role" "flow_log" {
  name = "${var.project_name}-${var.environment}-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

# IAM policy for VPC Flow Logs
resource "aws_iam_role_policy" "flow_log" {
  name = "${var.project_name}-${var.environment}-flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect = "Allow"
        Resource = "*"
      }
    ]
  })
}
```

### modules/networking/variables.tf
```hcl
variable "project_name" {
  description = "Name of the project"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
```

### modules/networking/outputs.tf
```hcl
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

output "kms_key_id" {
  description = "ID of the KMS key for encryption"
  value       = aws_kms_key.logs.id
}
```

### modules/compute/main.tf
```hcl
# Data source for latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "
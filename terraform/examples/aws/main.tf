terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Get the tripwire cloud-init configuration
module "tripwire" {
  source = "../../modules/tripwire"

  decoy_users              = var.decoy_users
  decoy_user_passwords     = var.decoy_user_passwords
  real_sudo_group          = var.real_sudo_group
  privileged_user          = var.privileged_user
  privileged_user_password = var.privileged_user_password
  inactivity_timeout       = var.inactivity_timeout
  enable_command_tracking  = var.enable_command_tracking
  wazuh_manager_ip         = var.wazuh_manager_ip
}

# Data source for latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

# Security group
resource "aws_security_group" "tripwire_sg" {
  name        = "tripwire-honeypot-sg"
  description = "Security group for tripwire honeypot instances"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "tripwire-honeypot-sg"
  }
}

# EC2 instance with tripwire pre-installed
resource "aws_instance" "tripwire_host" {
  count = var.instance_count

  ami           = var.ami_id != "" ? var.ami_id : data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.tripwire_sg.id]

  user_data = module.tripwire.cloud_init_config

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  tags = {
    Name        = "tripwire-honeypot-${count.index + 1}"
    Environment = var.environment
    Purpose     = "honeypot"
  }
}

# Outputs
output "instance_ids" {
  description = "IDs of created instances"
  value       = aws_instance.tripwire_host[*].id
}

output "instance_public_ips" {
  description = "Public IPs of created instances"
  value       = aws_instance.tripwire_host[*].public_ip
}

output "instance_private_ips" {
  description = "Private IPs of created instances"
  value       = aws_instance.tripwire_host[*].private_ip
}

output "ssh_commands" {
  description = "SSH commands to connect to instances"
  value = [
    for idx, ip in aws_instance.tripwire_host[*].public_ip :
    "ssh -i ${var.key_name}.pem ${var.decoy_users[0]}@${ip}"
  ]
}

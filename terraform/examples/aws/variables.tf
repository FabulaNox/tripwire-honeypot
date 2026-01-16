variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "VPC ID to deploy into"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID to deploy into"
  type        = string
}

variable "key_name" {
  description = "EC2 key pair name"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "instance_count" {
  description = "Number of instances to create"
  type        = number
  default     = 1
}

variable "ami_id" {
  description = "AMI ID (leave empty for latest Ubuntu 22.04)"
  type        = string
  default     = ""
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "environment" {
  description = "Environment tag"
  type        = string
  default     = "production"
}

# Tripwire configuration
variable "decoy_users" {
  description = "Decoy usernames"
  type        = list(string)
  default     = ["admin_john", "admin_jane"]
}

variable "decoy_user_passwords" {
  description = "Password hashes for decoy users"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "real_sudo_group" {
  description = "Real privileged group name"
  type        = string
  default     = "svc_mgmt"
}

variable "privileged_user" {
  description = "Privileged user to su to"
  type        = string
  default     = "ops_worker"
}

variable "privileged_user_password" {
  description = "Password hash for privileged user"
  type        = string
  default     = ""
  sensitive   = true
}

variable "inactivity_timeout" {
  description = "Seconds before alerting on inactive session"
  type        = number
  default     = 180
}

variable "enable_command_tracking" {
  description = "Enable auditd command tracking"
  type        = bool
  default     = true
}

variable "wazuh_manager_ip" {
  description = "Wazuh manager IP (optional)"
  type        = string
  default     = ""
}

variable "install_wazuh_agent" {
  description = "Automatically install Wazuh agent if not present"
  type        = bool
  default     = true
}

variable "wazuh_registration_password" {
  description = "Wazuh registration password for agent enrollment"
  type        = string
  default     = ""
  sensitive   = true
}

variable "wazuh_agent_group" {
  description = "Wazuh agent group"
  type        = string
  default     = "tripwire"
}

variable "wazuh_api_user" {
  description = "Wazuh API user for enrollment"
  type        = string
  default     = ""
}

variable "wazuh_api_password" {
  description = "Wazuh API password for enrollment"
  type        = string
  default     = ""
  sensitive   = true
}

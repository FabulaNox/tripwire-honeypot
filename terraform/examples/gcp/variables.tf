variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "tripwire"
}

variable "create_vpc" {
  description = "Create new VPC network"
  type        = bool
  default     = true
}

variable "subnet_cidr" {
  description = "Subnet CIDR range"
  type        = string
  default     = "10.0.1.0/24"
}

variable "existing_network" {
  description = "Existing VPC network name (if not creating)"
  type        = string
  default     = "default"
}

variable "existing_subnetwork" {
  description = "Existing subnetwork name (if not creating)"
  type        = string
  default     = "default"
}

variable "machine_type" {
  description = "GCE machine type"
  type        = string
  default     = "e2-micro"
}

variable "instance_count" {
  description = "Number of instances to create"
  type        = number
  default     = 1
}

variable "image" {
  description = "Boot disk image"
  type        = string
  default     = "ubuntu-os-cloud/ubuntu-2204-lts"
}

variable "disk_size_gb" {
  description = "Boot disk size in GB"
  type        = number
  default     = 20
}

variable "ssh_user" {
  description = "SSH username for metadata"
  type        = string
  default     = "ubuntu"
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "ssh_allowed_cidrs" {
  description = "CIDR blocks allowed to SSH"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "create_service_account" {
  description = "Create new service account"
  type        = bool
  default     = true
}

variable "existing_service_account_email" {
  description = "Existing service account email (if not creating)"
  type        = string
  default     = ""
}

variable "labels" {
  description = "Labels to apply to resources"
  type        = map(string)
  default = {
    environment = "production"
    managed-by  = "terraform"
  }
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

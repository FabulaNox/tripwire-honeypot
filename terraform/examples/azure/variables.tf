variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group name"
  type        = string
  default     = "tripwire-honeypot-rg"
}

variable "create_resource_group" {
  description = "Create new resource group"
  type        = bool
  default     = true
}

variable "prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "tripwire"
}

variable "create_vnet" {
  description = "Create new VNet"
  type        = bool
  default     = true
}

variable "vnet_address_space" {
  description = "VNet address space"
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_address_prefix" {
  description = "Subnet address prefix"
  type        = string
  default     = "10.0.1.0/24"
}

variable "existing_subnet_id" {
  description = "Existing subnet ID (if not creating VNet)"
  type        = string
  default     = ""
}

variable "vm_size" {
  description = "VM size"
  type        = string
  default     = "Standard_B1s"
}

variable "instance_count" {
  description = "Number of VMs to create"
  type        = number
  default     = 1
}

variable "admin_username" {
  description = "Admin username for VM"
  type        = string
  default     = "azureuser"
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

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default = {
    Environment = "production"
    ManagedBy   = "terraform"
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

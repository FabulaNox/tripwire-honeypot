variable "decoy_users" {
  description = "List of decoy usernames that appear to have sudo but don't"
  type        = list(string)
  default     = ["admin_john", "admin_jane"]
}

variable "decoy_user_passwords" {
  description = "Map of decoy username to password hash (use `mkpasswd -m sha-512`)"
  type        = map(string)
  default     = {}
  sensitive   = true
}

variable "real_sudo_group" {
  description = "Name of the real privileged group (use obscure name)"
  type        = string
  default     = "svc_mgmt"
}

variable "privileged_user" {
  description = "Username that admins switch to for actual sudo access"
  type        = string
  default     = "ops_worker"
}

variable "privileged_user_password" {
  description = "Password hash for privileged user (use `mkpasswd -m sha-512`)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "inactivity_timeout" {
  description = "Seconds before alerting on inactive decoy session"
  type        = number
  default     = 180
}

variable "enable_command_tracking" {
  description = "Enable command logging via auditd"
  type        = bool
  default     = true
}

variable "wazuh_manager_ip" {
  description = "Wazuh manager IP for agent registration (optional)"
  type        = string
  default     = ""
}

variable "wazuh_registration_password" {
  description = "Wazuh agent registration password for enrollment"
  type        = string
  default     = ""
  sensitive   = true
}

variable "wazuh_agent_group" {
  description = "Wazuh agent group for enrolled agents"
  type        = string
  default     = "tripwire"
}

variable "wazuh_api_user" {
  description = "Wazuh API user for agent enrollment (alternative to registration password)"
  type        = string
  default     = ""
}

variable "wazuh_api_password" {
  description = "Wazuh API password for agent enrollment"
  type        = string
  default     = ""
  sensitive   = true
}

variable "install_wazuh_agent" {
  description = "Automatically install and enroll Wazuh agent if not present"
  type        = bool
  default     = true
}

# Deployment method variables
variable "target_hosts" {
  description = "List of existing hosts to deploy to (for null_resource provisioner)"
  type = list(object({
    host        = string
    user        = string
    private_key = string
    port        = number
  }))
  default = []
}

variable "ssh_user" {
  description = "Default SSH user for provisioning"
  type        = string
  default     = "root"
}

variable "ssh_private_key_path" {
  description = "Path to SSH private key for provisioning"
  type        = string
  default     = "~/.ssh/id_rsa"
}

variable "ssh_port" {
  description = "SSH port for provisioning"
  type        = number
  default     = 22
}

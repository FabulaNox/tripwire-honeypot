variable "target_hosts" {
  description = "List of existing hosts to deploy tripwire to"
  type = list(object({
    host        = string
    user        = string
    private_key = string
    port        = number
  }))
}

variable "decoy_users" {
  description = "Decoy usernames that appear to have sudo"
  type        = list(string)
  default     = ["admin_john", "admin_jane"]
}

variable "real_sudo_group" {
  description = "Real privileged group name (use obscure name)"
  type        = string
  default     = "svc_mgmt"
}

variable "privileged_user" {
  description = "User that admins switch to for actual sudo"
  type        = string
  default     = "ops_worker"
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
  description = "Wazuh manager IP for agent registration"
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

terraform {
  required_version = ">= 1.0.0"
}

# Deploy tripwire to existing hosts via SSH
module "tripwire" {
  source = "../../modules/tripwire"

  decoy_users             = var.decoy_users
  real_sudo_group         = var.real_sudo_group
  privileged_user         = var.privileged_user
  inactivity_timeout      = var.inactivity_timeout
  enable_command_tracking = var.enable_command_tracking
  wazuh_manager_ip        = var.wazuh_manager_ip

  # Target hosts for deployment
  target_hosts = var.target_hosts
}

# Outputs
output "deployed_hosts" {
  description = "Hosts where tripwire was deployed"
  value       = module.tripwire.deployed_hosts
}

output "admin_workflow" {
  description = "Instructions for admins"
  value       = <<-EOT
    Admin Workflow:
    1. SSH as decoy user: ssh ${var.decoy_users[0]}@<host>
    2. Switch to privileged user: su ${var.privileged_user}
    3. Work with sudo privileges

    Attacker Indicators:
    - No 'su ${var.privileged_user}' within ${var.inactivity_timeout}s = ALERT
    - Attempting 'sudo' from decoy user = ALERT (will fail)
  EOT
}

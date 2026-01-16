terraform {
  required_version = ">= 1.0.0"
}

locals {
  decoy_users_string = join(" ", var.decoy_users)

  # Configuration file content - injected with Terraform variables
  tripwire_config = <<-EOT
    DECOY_USERS="${local.decoy_users_string}"
    REAL_SUDO_GROUP="${var.real_sudo_group}"
    PRIVILEGED_USER="${var.privileged_user}"
    INACTIVITY_TIMEOUT=${var.inactivity_timeout}
    TRACK_DIR="/var/run/tripwire_sessions"
    ENABLE_COMMAND_TRACKING=${var.enable_command_tracking}
    WAZUH_MANAGER="${var.wazuh_manager_ip}"
    WAZUH_REGISTRATION_PASSWORD="${var.wazuh_registration_password}"
    WAZUH_AGENT_GROUP="${var.wazuh_agent_group}"
    WAZUH_API_USER="${var.wazuh_api_user}"
    WAZUH_API_PASSWORD="${var.wazuh_api_password}"
    INSTALL_WAZUH_AGENT=${var.install_wazuh_agent}
  EOT

  # Path to the repository root (relative to this module)
  repo_root = "${path.module}/../../.."
}

# Deploy to existing hosts using null_resource
# This mirrors the behavior of deploy-remote.sh
resource "null_resource" "tripwire_deployment" {
  for_each = { for idx, host in var.target_hosts : host.host => host }

  triggers = {
    config_hash  = sha256(local.tripwire_config)
    install_hash = filesha256("${local.repo_root}/install.sh")
    session_hash = filesha256("${local.repo_root}/scripts/tripwire_session.sh")
    monitor_hash = filesha256("${local.repo_root}/scripts/tripwire_monitor.sh")
  }

  connection {
    type        = "ssh"
    host        = each.value.host
    user        = each.value.user
    private_key = file(each.value.private_key)
    port        = each.value.port
  }

  # Create remote directory structure
  provisioner "remote-exec" {
    inline = [
      "mkdir -p /tmp/tripwire-honeypot/config",
      "mkdir -p /tmp/tripwire-honeypot/scripts",
      "mkdir -p /tmp/tripwire-honeypot/systemd",
      "mkdir -p /tmp/tripwire-honeypot/wazuh-rules"
    ]
  }

  # Copy configuration (with Terraform-injected values)
  provisioner "file" {
    content     = local.tripwire_config
    destination = "/tmp/tripwire-honeypot/config/tripwire.conf"
  }

  # Copy install script
  provisioner "file" {
    source      = "${local.repo_root}/install.sh"
    destination = "/tmp/tripwire-honeypot/install.sh"
  }

  # Copy scripts
  provisioner "file" {
    source      = "${local.repo_root}/scripts/tripwire_session.sh"
    destination = "/tmp/tripwire-honeypot/scripts/tripwire_session.sh"
  }

  provisioner "file" {
    source      = "${local.repo_root}/scripts/tripwire_monitor.sh"
    destination = "/tmp/tripwire-honeypot/scripts/tripwire_monitor.sh"
  }

  # Copy systemd service
  provisioner "file" {
    source      = "${local.repo_root}/systemd/tripwire-monitor.service"
    destination = "/tmp/tripwire-honeypot/systemd/tripwire-monitor.service"
  }

  # Copy audit rules
  provisioner "file" {
    source      = "${local.repo_root}/config/tripwire-audit.rules"
    destination = "/tmp/tripwire-honeypot/config/tripwire-audit.rules"
  }

  # Copy Wazuh rules
  provisioner "file" {
    source      = "${local.repo_root}/wazuh-rules/tripwire_rules.xml"
    destination = "/tmp/tripwire-honeypot/wazuh-rules/tripwire_rules.xml"
  }

  # Run the install script and cleanup
  provisioner "remote-exec" {
    inline = [
      "chmod +x /tmp/tripwire-honeypot/install.sh",
      "chmod +x /tmp/tripwire-honeypot/scripts/*.sh",
      "cd /tmp/tripwire-honeypot && sudo ./install.sh",
      "rm -rf /tmp/tripwire-honeypot"
    ]
  }
}

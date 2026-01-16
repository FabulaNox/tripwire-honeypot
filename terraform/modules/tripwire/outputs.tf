locals {
  # Read script files from the repository (repo_root defined in main.tf)
  session_script = file("${local.repo_root}/scripts/tripwire_session.sh")
  monitor_script = file("${local.repo_root}/scripts/tripwire_monitor.sh")
  audit_rules    = file("${local.repo_root}/config/tripwire-audit.rules")
  wazuh_rules    = file("${local.repo_root}/wazuh-rules/tripwire_rules.xml")
  systemd_unit   = file("${local.repo_root}/systemd/tripwire-monitor.service")
}

output "cloud_init_config" {
  description = "Cloud-init configuration for deploying tripwire on new instances"
  value       = local.cloud_init_yaml
  sensitive   = true
}

output "tripwire_config" {
  description = "Tripwire configuration content"
  value       = local.tripwire_config
  sensitive   = true
}

output "deployed_hosts" {
  description = "List of hosts where tripwire was deployed"
  value       = [for host in var.target_hosts : host.host]
}

locals {
  cloud_init_yaml = <<-CLOUDINIT
#cloud-config
package_update: true
package_upgrade: false

packages:
  - auditd
  - audispd-plugins

groups:
  - ${var.real_sudo_group}

users:
%{for user in var.decoy_users~}
  - name: ${user}
    groups: [sudo]
    shell: /bin/bash
    lock_passwd: ${lookup(var.decoy_user_passwords, user, "") == "" ? "true" : "false"}
%{if lookup(var.decoy_user_passwords, user, "") != ""~}
    passwd: ${lookup(var.decoy_user_passwords, user, "")}
%{endif~}
%{endfor~}
  - name: ${var.privileged_user}
    groups: [${var.real_sudo_group}]
    shell: /bin/bash
    lock_passwd: ${var.privileged_user_password == "" ? "true" : "false"}
%{if var.privileged_user_password != ""~}
    passwd: ${var.privileged_user_password}
%{endif~}

write_files:
  - path: /etc/tripwire/tripwire.conf
    permissions: '0600'
    content: |
      ${indent(6, local.tripwire_config)}

  - path: /usr/local/bin/tripwire_session.sh
    permissions: '0755'
    content: |
      ${indent(6, local.session_script)}

  - path: /usr/local/bin/tripwire_monitor.sh
    permissions: '0755'
    content: |
      ${indent(6, local.monitor_script)}

  - path: /etc/systemd/system/tripwire-monitor.service
    content: |
      ${indent(6, local.systemd_unit)}

  - path: /etc/audit/rules.d/tripwire.rules
    permissions: '0640'
    content: |
      ${indent(6, local.audit_rules)}

  - path: /var/ossec/etc/rules/tripwire_rules.xml
    permissions: '0640'
    content: |
      ${indent(6, local.wazuh_rules)}

runcmd:
  # Disable real sudo group
  - sed -i 's/^%sudo/#%sudo  # DISABLED BY TRIPWIRE/' /etc/sudoers
  # Create real sudoers entry
  - echo '%${var.real_sudo_group} ALL=(ALL:ALL) ALL' > /etc/sudoers.d/tripwire-real-admins
  - chmod 440 /etc/sudoers.d/tripwire-real-admins
  # Configure PAM
  - echo 'session optional pam_exec.so /usr/local/bin/tripwire_session.sh' >> /etc/pam.d/common-session
  - echo 'session optional pam_exec.so /usr/local/bin/tripwire_session.sh' >> /etc/pam.d/sshd
  # Create tracking directory
  - mkdir -p /var/run/tripwire_sessions
  # Load audit rules
  - augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/tripwire.rules 2>/dev/null || true
  # Enable and start service
  - systemctl daemon-reload
  - systemctl enable tripwire-monitor
  - systemctl start tripwire-monitor
  # Restart Wazuh if present
  - systemctl restart wazuh-manager 2>/dev/null || systemctl restart wazuh-agent 2>/dev/null || true
CLOUDINIT
}

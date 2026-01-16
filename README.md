# Tripwire Honeypot

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)
[![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.0-purple.svg)](https://www.terraform.io/)
[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-orange.svg)](https://wazuh.com/)

A deception-based intrusion detection system that creates a fake "sudo" group to detect attackers.

> **Catch attackers in the act.** When adversaries compromise a Linux account and discover they're in the "sudo" group, they assume they've hit the jackpot. This honeypot exploits that assumption to detect intrusions within seconds.

## Concept

Attackers who compromise a Linux system often check group membership to identify privileged accounts. This tool exploits that behavior:

1. The real `sudo` group has **no privileges** (it's a decoy)
2. Actual sudo access is granted via an obscurely-named group
3. Admins know to `su` to a privileged user after login
4. Attackers see "sudo" membership, assume they have access, and either:
   - Try `sudo` (fails, triggers alert)
   - Do nothing (session monitored, alert after 3 min inactivity)

## Detection Scenarios

| Actor | Behavior | Detection |
|-------|----------|-----------|
| Real Admin | Login → `su ops_worker` → work | Normal (no alert) |
| Attacker | Login → tries `sudo` | **ALERT**: sudo failed |
| Attacker | Login → sits idle | **ALERT**: 3 min timeout |
| Attacker | Login → runs recon | **ALERT**: commands logged |

## Installation

### Interactive Setup Wizard (Recommended)

The easiest way to get started is the interactive setup wizard:

```bash
./setup-wizard.sh
```

The wizard will guide you through:
1. Choosing deployment target (AWS, Azure, GCP, or existing hosts)
2. Configuring decoy users and privileged accounts
3. Setting monitoring options (timeouts, command tracking, Wazuh)
4. Generating Terraform configuration
5. Running the deployment

![Setup Wizard](docs/wizard-screenshot.png)

### Local Installation

1. Edit configuration:
```bash
vim config/tripwire.conf
```

2. Run installer as root:
```bash
sudo ./install.sh
```

3. Set passwords for created users:
```bash
sudo passwd admin_john    # decoy user
sudo passwd ops_worker    # privileged user
```

### Remote Deployment (Shell Script)

Deploy to multiple hosts via SSH:

```bash
# Single host
./deploy-remote.sh -u root -k ~/.ssh/id_rsa server1.example.com

# Multiple hosts
./deploy-remote.sh -u admin 192.168.1.10 192.168.1.11 192.168.1.12

# From inventory file
./deploy-remote.sh -i hosts.txt --parallel 10
```

### Terraform Deployment

Deploy using Infrastructure as Code with Terraform.

#### Deploy to Existing Hosts

```bash
cd terraform/examples/existing-hosts
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your hosts
terraform init
terraform apply
```

```hcl
# terraform.tfvars
target_hosts = [
  {
    host        = "192.168.1.10"
    user        = "root"
    private_key = "~/.ssh/id_rsa"
    port        = 22
  },
  {
    host        = "192.168.1.11"
    user        = "root"
    private_key = "~/.ssh/id_rsa"
    port        = 22
  }
]

decoy_users     = ["admin_john", "admin_jane"]
real_sudo_group = "svc_mgmt"
privileged_user = "ops_worker"
```

#### Deploy New AWS EC2 Instances

```bash
cd terraform/examples/aws
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your AWS config
terraform init
terraform apply
```

```hcl
# terraform.tfvars
aws_region = "us-east-1"
vpc_id     = "vpc-xxxxxxxxx"
subnet_id  = "subnet-xxxxxxxxx"
key_name   = "my-key-pair"

instance_type  = "t3.micro"
instance_count = 2

decoy_users     = ["admin_john", "admin_jane"]
real_sudo_group = "svc_mgmt"
privileged_user = "ops_worker"
```

#### Deploy New Azure VMs

```bash
cd terraform/examples/azure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your Azure config
terraform init
terraform apply
```

```hcl
# terraform.tfvars
location            = "eastus"
resource_group_name = "tripwire-honeypot-rg"
prefix              = "tripwire"

vm_size             = "Standard_B1s"
instance_count      = 2
ssh_public_key_path = "~/.ssh/id_rsa.pub"

decoy_users     = ["admin_john", "admin_jane"]
real_sudo_group = "svc_mgmt"
privileged_user = "ops_worker"
```

#### Deploy New GCP Compute Instances

```bash
cd terraform/examples/gcp
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your GCP config
terraform init
terraform apply
```

```hcl
# terraform.tfvars
project_id = "my-gcp-project-id"
region     = "us-central1"
zone       = "us-central1-a"

machine_type        = "e2-micro"
instance_count      = 2
ssh_public_key_path = "~/.ssh/id_rsa.pub"

decoy_users     = ["admin_john", "admin_jane"]
real_sudo_group = "svc_mgmt"
privileged_user = "ops_worker"
```

#### Using the Module in Your Own Terraform

```hcl
module "tripwire" {
  source = "github.com/your-org/tripwire-honeypot//terraform/modules/tripwire"

  decoy_users             = ["admin_john"]
  real_sudo_group         = "svc_mgmt"
  privileged_user         = "ops_worker"
  inactivity_timeout      = 180
  enable_command_tracking = true
}

# Use cloud_init_config output for new instances
resource "aws_instance" "example" {
  # ...
  user_data = module.tripwire.cloud_init_config
}

# Or deploy to existing hosts
module "tripwire_existing" {
  source = "github.com/your-org/tripwire-honeypot//terraform/modules/tripwire"

  target_hosts = [
    {
      host        = "10.0.1.5"
      user        = "root"
      private_key = "~/.ssh/id_rsa"
      port        = 22
    }
  ]
}
```

## Configuration

Edit `config/tripwire.conf`:

```bash
# Decoy users (appear to have sudo, but don't)
DECOY_USERS="admin_john admin_jane"

# Real privileged group (obscure name)
REAL_SUDO_GROUP="svc_mgmt"

# User admins switch to for actual sudo
PRIVILEGED_USER="ops_worker"

# Alert timeout (seconds)
INACTIVITY_TIMEOUT=180

# Enable command tracking via auditd
ENABLE_COMMAND_TRACKING=true
```

## Admin Workflow

```
┌─────────────────────────────────────────────────────────┐
│  1. SSH as decoy user                                   │
│     ssh admin_john@server                               │
│                                                         │
│  2. Switch to privileged user                           │
│     su ops_worker                                       │
│                                                         │
│  3. Work with actual sudo privileges                    │
│     sudo systemctl restart nginx                        │
└─────────────────────────────────────────────────────────┘
```

## Wazuh Integration

The installer automatically deploys Wazuh rules if Wazuh is detected. Alert levels:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100110 | 8 | Decoy session started |
| 100120 | 14 | Inactive session (no su after 3 min) |
| 100121 | 14 | Failed sudo authentication |
| 100122 | 15 | User not in sudoers |
| 100130 | 10 | Command executed by decoy user |
| 100141 | 14 | Suspicious command (wget, nc, etc.) |

## Monitoring

### View real-time logs:
```bash
journalctl -t TRIPWIRE -f
```

### Check service status:
```bash
systemctl status tripwire-monitor
```

### View audit logs (command tracking):
```bash
ausearch -k tripwire_cmd
```

### Wazuh dashboard:
Filter by group `tripwire` or rule IDs `100110-100141`

## File Structure

```
tripwire-honeypot/
├── config/
│   ├── tripwire.conf           # Main configuration
│   └── tripwire-audit.rules    # Auditd rules template
├── scripts/
│   ├── tripwire_session.sh     # PAM session hook
│   └── tripwire_monitor.sh     # Inactivity monitor daemon
├── systemd/
│   └── tripwire-monitor.service
├── wazuh-rules/
│   └── tripwire_rules.xml      # Wazuh detection rules
├── terraform/
│   ├── modules/
│   │   └── tripwire/           # Reusable Terraform module
│   │       ├── main.tf
│   │       ├── variables.tf
│   │       └── outputs.tf
│   └── examples/
│       ├── aws/                # Deploy new EC2 instances
│       ├── azure/              # Deploy new Azure VMs
│       ├── gcp/                # Deploy new GCP instances
│       └── existing-hosts/     # Deploy to existing servers
├── setup-wizard.sh             # Interactive setup wizard
├── install.sh                  # Local installer
├── uninstall.sh                # Uninstaller
├── deploy-remote.sh            # SSH-based remote deployment
└── README.md
```

## Uninstallation

```bash
sudo ./uninstall.sh
```

This restores the normal sudo group and removes all tripwire components. Users are preserved for manual cleanup.

## MITRE Framework Mapping

This section maps the tripwire honeypot to MITRE ATT&CK (adversary techniques detected) and MITRE D3FEND (defensive techniques employed).

### MITRE ATT&CK - Techniques Detected

The honeypot detects the following adversary techniques:

| Tactic | Technique ID | Technique Name | How Detected |
|--------|--------------|----------------|--------------|
| **Discovery** | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Permission Groups Discovery: Local Groups | Attacker sees decoy user in "sudo" group |
| **Discovery** | [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Attacker enumerates users via `id`, `groups` |
| **Discovery** | [T1082](https://attack.mitre.org/techniques/T1082/) | System Information Discovery | Commands logged via auditd |
| **Privilege Escalation** | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control: Sudo and Sudo Caching | Failed sudo attempt triggers immediate alert |
| **Privilege Escalation** | [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | Valid Accounts: Local Accounts | Decoy account usage detected |
| **Execution** | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Command and Scripting Interpreter: Unix Shell | All commands from decoy users logged |
| **Command & Control** | [T1071](https://attack.mitre.org/techniques/T1071/) | Application Layer Protocol | Suspicious commands (wget, curl, nc) flagged |
| **Exfiltration** | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | Reverse shell patterns detected |

### MITRE ATT&CK - Attack Flow Disrupted

```
Attacker Perspective (what they expect vs reality):

┌─────────────────────────────────────────────────────────────────────────────┐
│  EXPECTED (Normal Linux)              │  REALITY (Tripwire Honeypot)        │
├───────────────────────────────────────┼─────────────────────────────────────┤
│  1. Compromise user account           │  1. Compromise decoy account        │
│  2. Run `id` → see "sudo" group       │  2. Run `id` → see "sudo" group ✓   │
│  3. Run `sudo -l` → see privileges    │  3. Run `sudo -l` → DENIED ⚠️       │
│  4. Escalate to root                  │  4. Alert triggered, SOC notified   │
│  5. Persist & exfiltrate              │  5. Session monitored, all logged   │
└───────────────────────────────────────┴─────────────────────────────────────┘
```

### MITRE D3FEND - Defensive Techniques Employed

| D3FEND ID | Technique | Implementation |
|-----------|-----------|----------------|
| [D3-DUC](https://d3fend.mitre.org/technique/d3f:DecoyUserCredential/) | **Decoy User Credential** | Decoy users (`admin_john`, `admin_jane`) appear privileged but aren't |
| [D3-DF](https://d3fend.mitre.org/technique/d3f:DecoyFile/) | **Decoy File** | Session tracking files in `/var/run/tripwire_sessions/` |
| [D3-SDA](https://d3fend.mitre.org/technique/d3f:SystemDaemonMonitoring/) | **System Daemon Monitoring** | `tripwire-monitor` daemon watches for anomalous behavior |
| [D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/) | **Process Spawn Analysis** | Monitor checks if expected `su` to privileged user occurred |
| [D3-SCA](https://d3fend.mitre.org/technique/d3f:SystemCallAnalysis/) | **System Call Analysis** | Auditd tracks execve, setuid, setgid syscalls |
| [D3-MAC](https://d3fend.mitre.org/technique/d3f:MandatoryAccessControl/) | **Mandatory Access Control** | PAM integration enforces session tracking |
| [D3-UA](https://d3fend.mitre.org/technique/d3f:UserAccountAnalysis/) | **User Account Analysis** | Legitimate admins follow known workflow; deviations flagged |
| [D3-AL](https://d3fend.mitre.org/technique/d3f:AuthenticationLog/) | **Authentication Event Logging** | All PAM session events logged via syslog |

### Detection Coverage Matrix

```
                    ┌─────────────────────────────────────────────────┐
                    │           DETECTION TIMELINE                     │
                    ├─────────────────────────────────────────────────┤
   T=0              │  Session Start                                   │
   (Login)          │  └─ PAM hook fires, tracking begins             │
                    │  └─ Wazuh Rule 100110 (Level 8)                 │
                    │                                                  │
   T=0 to T=180s    │  Command Execution Window                       │
                    │  └─ All commands logged via auditd              │
                    │  └─ Wazuh Rule 100130 (Level 10)                │
                    │  └─ Suspicious patterns → Rule 100141 (Level 14)│
                    │                                                  │
   T=anytime        │  Sudo Attempt                                    │
                    │  └─ Immediate failure (not in real sudoers)     │
                    │  └─ Wazuh Rule 100122 (Level 15) - CRITICAL     │
                    │                                                  │
   T=180s           │  Inactivity Timeout                              │
   (3 minutes)      │  └─ No su to privileged user detected           │
                    │  └─ Wazuh Rule 100120 (Level 14) - HIGH         │
                    │                                                  │
   T=any            │  Legitimate Admin                                │
                    │  └─ Completes su within timeout                 │
                    │  └─ Wazuh Rule 100112 (Level 3) - INFO          │
                    │  └─ Tracking file removed, no alert             │
                    └─────────────────────────────────────────────────┘
```

### NIST CSF Alignment

| Function | Category | How Addressed |
|----------|----------|---------------|
| **Identify** | Asset Management | Decoy accounts inventory tracked |
| **Protect** | Access Control | Real privileges hidden behind obscure group |
| **Detect** | Anomalies & Events | Behavioral deviation triggers alerts |
| **Detect** | Continuous Monitoring | 30-second polling, real-time auditd |
| **Respond** | Analysis | Comprehensive logging for forensics |

### Compliance Mapping

The Wazuh rules include tags for compliance frameworks:

- **PCI-DSS 10.2.7** - Access to audit trails
- **PCI-DSS 10.6.1** - Review logs daily
- **HIPAA** - Access monitoring for PHI systems
- **SOC 2** - Security monitoring controls

## Security Considerations

- Store the real privileged group name securely (not in easily-accessible docs)
- Ensure admins know the correct workflow before deployment
- Test thoroughly in a staging environment first
- The decoy users should have realistic-looking home directories
- Session tracking directory is mode 700 (root-only access)
- All credentials in Terraform are marked sensitive

## Requirements

**Target hosts:**
- Linux with systemd
- PAM
- auditd (for command tracking)
- Wazuh agent/manager (optional, for SIEM integration)

**For deployment:**
- SSH access (shell script deployment)
- Terraform >= 1.0.0 (Terraform deployment)
- AWS CLI configured (for AWS example)
- Azure CLI configured (for Azure example)
- gcloud CLI configured (for GCP example)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Disclaimer

This tool is intended for **authorized security testing and defensive purposes only**. Ensure you have proper authorization before deploying on any system. The authors are not responsible for misuse or damage caused by this tool.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary tactics and techniques framework
- [MITRE D3FEND](https://d3fend.mitre.org/) - Defensive techniques knowledge base
- [Wazuh](https://wazuh.com/) - Open source security monitoring platform
- The security community for deception-based defense research

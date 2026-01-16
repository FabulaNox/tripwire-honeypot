#!/bin/bash
#
# Tripwire Honeypot Installer
# Creates a deceptive sudo group to detect attackers
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config/tripwire.conf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Load config
if [ ! -f "$CONFIG_FILE" ]; then
    log_error "Config file not found: $CONFIG_FILE"
    exit 1
fi
source "$CONFIG_FILE"

log_info "Starting Tripwire Honeypot Installation"
log_info "========================================"

# ============ STEP 1: Create real privileged group ============
log_info "Step 1: Setting up privilege groups..."

if ! getent group "$REAL_SUDO_GROUP" > /dev/null 2>&1; then
    groupadd -r "$REAL_SUDO_GROUP"
    log_info "Created real privileged group: $REAL_SUDO_GROUP"
else
    log_warn "Group $REAL_SUDO_GROUP already exists"
fi

# ============ STEP 2: Create privileged user ============
log_info "Step 2: Setting up privileged user..."

if ! id "$PRIVILEGED_USER" > /dev/null 2>&1; then
    useradd -m -G "$REAL_SUDO_GROUP" -s /bin/bash "$PRIVILEGED_USER"
    log_info "Created privileged user: $PRIVILEGED_USER"
    log_warn "Set password for $PRIVILEGED_USER: passwd $PRIVILEGED_USER"
else
    log_warn "User $PRIVILEGED_USER already exists"
    usermod -aG "$REAL_SUDO_GROUP" "$PRIVILEGED_USER"
fi

# ============ STEP 3: Configure sudoers ============
log_info "Step 3: Configuring sudoers..."

SUDOERS_FILE="/etc/sudoers.d/tripwire-real-admins"
cat > "$SUDOERS_FILE" << EOF
# Tripwire Honeypot - Real admin privileges
# Group $REAL_SUDO_GROUP has actual sudo access
%$REAL_SUDO_GROUP ALL=(ALL:ALL) ALL
EOF
chmod 440 "$SUDOERS_FILE"
log_info "Created sudoers file: $SUDOERS_FILE"

# Disable default sudo group (make it a decoy)
if grep -q "^%sudo" /etc/sudoers 2>/dev/null; then
    sed -i 's/^%sudo/#%sudo  # DISABLED BY TRIPWIRE/' /etc/sudoers
    log_info "Disabled default sudo group in /etc/sudoers"
fi

# Also check sudoers.d
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    [[ "$f" == *tripwire* ]] && continue
    if grep -q "^%sudo" "$f" 2>/dev/null; then
        sed -i 's/^%sudo/#%sudo  # DISABLED BY TRIPWIRE/' "$f"
        log_info "Disabled sudo group in: $f"
    fi
done

# ============ STEP 4: Create decoy users ============
log_info "Step 4: Setting up decoy users..."

for DECOY_USER in $DECOY_USERS; do
    if ! id "$DECOY_USER" > /dev/null 2>&1; then
        useradd -m -G sudo -s /bin/bash "$DECOY_USER"
        log_info "Created decoy user: $DECOY_USER (in fake sudo group)"
        log_warn "Set password for $DECOY_USER: passwd $DECOY_USER"
    else
        log_warn "Decoy user $DECOY_USER already exists"
        usermod -aG sudo "$DECOY_USER"
        log_info "Added $DECOY_USER to decoy sudo group"
    fi
done

# ============ STEP 5: Install scripts ============
log_info "Step 5: Installing tripwire scripts..."

mkdir -p /etc/tripwire
cp "$CONFIG_FILE" /etc/tripwire/tripwire.conf
chmod 600 /etc/tripwire/tripwire.conf

cp "$SCRIPT_DIR/scripts/tripwire_session.sh" /usr/local/bin/
cp "$SCRIPT_DIR/scripts/tripwire_monitor.sh" /usr/local/bin/
chmod 755 /usr/local/bin/tripwire_session.sh
chmod 755 /usr/local/bin/tripwire_monitor.sh

log_info "Installed scripts to /usr/local/bin/"

# ============ STEP 6: Configure PAM ============
log_info "Step 6: Configuring PAM..."

PAM_LINE="session optional pam_exec.so /usr/local/bin/tripwire_session.sh"
PAM_FILES="/etc/pam.d/common-session /etc/pam.d/sshd"

for PAM_FILE in $PAM_FILES; do
    if [ -f "$PAM_FILE" ]; then
        if ! grep -q "tripwire_session.sh" "$PAM_FILE"; then
            echo "$PAM_LINE" >> "$PAM_FILE"
            log_info "Added tripwire hook to $PAM_FILE"
        else
            log_warn "Tripwire hook already in $PAM_FILE"
        fi
    fi
done

# ============ STEP 7: Configure auditd ============
if [ "$ENABLE_COMMAND_TRACKING" = "true" ]; then
    log_info "Step 7: Configuring auditd for command tracking..."

    AUDIT_RULES_FILE="/etc/audit/rules.d/tripwire.rules"

    # Start with base rules
    cp "$SCRIPT_DIR/config/tripwire-audit.rules" "$AUDIT_RULES_FILE"

    # Add user-specific command tracking
    for DECOY_USER in $DECOY_USERS; do
        DECOY_UID=$(id -u "$DECOY_USER" 2>/dev/null || echo "")
        if [ -n "$DECOY_UID" ]; then
            echo "# Track all commands from decoy user: $DECOY_USER" >> "$AUDIT_RULES_FILE"
            echo "-a always,exit -F arch=b64 -S execve -F uid=$DECOY_UID -k tripwire_cmd" >> "$AUDIT_RULES_FILE"
            echo "-a always,exit -F arch=b32 -S execve -F uid=$DECOY_UID -k tripwire_cmd" >> "$AUDIT_RULES_FILE"
        fi
    done

    chmod 640 "$AUDIT_RULES_FILE"
    log_info "Created audit rules: $AUDIT_RULES_FILE"

    # Reload audit rules
    if command -v augenrules &> /dev/null; then
        augenrules --load 2>/dev/null || log_warn "Failed to reload audit rules"
    elif command -v auditctl &> /dev/null; then
        auditctl -R "$AUDIT_RULES_FILE" 2>/dev/null || log_warn "Failed to reload audit rules"
    fi
    log_info "Audit rules loaded"
else
    log_warn "Command tracking disabled in config"
fi

# ============ STEP 8: Install systemd service ============
log_info "Step 8: Installing systemd service..."

mkdir -p /var/run/tripwire_sessions
cp "$SCRIPT_DIR/systemd/tripwire-monitor.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable tripwire-monitor
systemctl start tripwire-monitor

log_info "Tripwire monitor service started"

# ============ STEP 9: Install Wazuh rules (if applicable) ============
log_info "Step 9: Checking for Wazuh..."

WAZUH_RULES_DIR="/var/ossec/etc/rules"
if [ -d "$WAZUH_RULES_DIR" ]; then
    cp "$SCRIPT_DIR/wazuh-rules/tripwire_rules.xml" "$WAZUH_RULES_DIR/tripwire_rules.xml"
    chown root:wazuh "$WAZUH_RULES_DIR/tripwire_rules.xml" 2>/dev/null || true
    chmod 640 "$WAZUH_RULES_DIR/tripwire_rules.xml"

    # Add include to local_rules.xml if needed
    LOCAL_RULES="$WAZUH_RULES_DIR/local_rules.xml"
    if [ -f "$LOCAL_RULES" ]; then
        if ! grep -q "tripwire_rules.xml" "$LOCAL_RULES"; then
            # Insert include before closing group tag or at end
            sed -i '/<\/group>/i <!-- Tripwire Rules -->' "$LOCAL_RULES" 2>/dev/null || true
        fi
    fi

    log_info "Installed Wazuh rules to $WAZUH_RULES_DIR"

    # Restart Wazuh if running
    if systemctl is-active --quiet wazuh-manager; then
        systemctl restart wazuh-manager
        log_info "Restarted Wazuh manager"
    elif systemctl is-active --quiet wazuh-agent; then
        systemctl restart wazuh-agent
        log_info "Restarted Wazuh agent"
    fi
else
    log_warn "Wazuh not found. Copy wazuh-rules/tripwire_rules.xml manually if needed."
fi

# ============ SUMMARY ============
echo ""
log_info "========================================"
log_info "Installation Complete!"
log_info "========================================"
echo ""
echo "Summary:"
echo "  - Real privileged group: $REAL_SUDO_GROUP"
echo "  - Privileged user:       $PRIVILEGED_USER"
echo "  - Decoy users:           $DECOY_USERS"
echo "  - Decoy group:           sudo (has NO privileges)"
echo ""
echo "Admin workflow:"
echo "  1. SSH as decoy user (e.g., $DECOY_USERS)"
echo "  2. Run: su $PRIVILEGED_USER"
echo "  3. Work with actual sudo privileges"
echo ""
echo "Attacker indicators:"
echo "  - Login as decoy user without 'su $PRIVILEGED_USER' within 3 min"
echo "  - Attempting 'sudo' from decoy user (will fail)"
echo "  - All commands from decoy users are logged via auditd"
echo ""
log_warn "IMPORTANT: Set passwords for new users:"
for DECOY_USER in $DECOY_USERS; do
    echo "  passwd $DECOY_USER"
done
echo "  passwd $PRIVILEGED_USER"
echo ""
log_info "View logs: journalctl -t TRIPWIRE -f"

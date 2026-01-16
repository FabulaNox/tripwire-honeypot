#!/bin/bash
#
# Tripwire Honeypot Uninstaller
# Removes the tripwire honeypot and restores normal sudo configuration
#

set -e

CONFIG_FILE="/etc/tripwire/tripwire.conf"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    exit 1
fi

# Load config if exists
if [ -f "$CONFIG_FILE" ]; then
    source "$CONFIG_FILE"
else
    log_warn "Config file not found, using defaults"
    DECOY_USERS=""
    PRIVILEGED_USER=""
    REAL_SUDO_GROUP=""
fi

log_info "Tripwire Honeypot Uninstaller"
log_info "=============================="
echo ""

read -p "This will remove tripwire honeypot. Continue? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_warn "Aborted"
    exit 0
fi

# Stop and disable service
log_info "Stopping tripwire-monitor service..."
systemctl stop tripwire-monitor 2>/dev/null || true
systemctl disable tripwire-monitor 2>/dev/null || true
rm -f /etc/systemd/system/tripwire-monitor.service
systemctl daemon-reload

# Remove scripts
log_info "Removing scripts..."
rm -f /usr/local/bin/tripwire_session.sh
rm -f /usr/local/bin/tripwire_monitor.sh
rm -rf /etc/tripwire
rm -rf /var/run/tripwire_sessions

# Remove PAM configuration
log_info "Removing PAM configuration..."
for PAM_FILE in /etc/pam.d/common-session /etc/pam.d/sshd; do
    if [ -f "$PAM_FILE" ]; then
        sed -i '/tripwire_session.sh/d' "$PAM_FILE"
    fi
done

# Remove audit rules
log_info "Removing audit rules..."
rm -f /etc/audit/rules.d/tripwire.rules
if command -v augenrules &> /dev/null; then
    augenrules --load 2>/dev/null || true
fi

# Remove Wazuh rules
log_info "Removing Wazuh rules..."
rm -f /var/ossec/etc/rules/tripwire_rules.xml
if systemctl is-active --quiet wazuh-manager; then
    systemctl restart wazuh-manager 2>/dev/null || true
elif systemctl is-active --quiet wazuh-agent; then
    systemctl restart wazuh-agent 2>/dev/null || true
fi

# Restore sudo group (re-enable)
log_info "Restoring sudo group privileges..."
if [ -f /etc/sudoers ]; then
    sed -i 's/^#%sudo.*DISABLED BY TRIPWIRE/%sudo ALL=(ALL:ALL) ALL/' /etc/sudoers
fi
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    sed -i 's/^#%sudo.*DISABLED BY TRIPWIRE/%sudo ALL=(ALL:ALL) ALL/' "$f" 2>/dev/null || true
done

# Remove tripwire sudoers file
rm -f /etc/sudoers.d/tripwire-real-admins

echo ""
log_warn "The following items were NOT removed (manual cleanup required):"
echo "  - Decoy users: $DECOY_USERS"
echo "  - Privileged user: $PRIVILEGED_USER"
echo "  - Real sudo group: $REAL_SUDO_GROUP"
echo ""
echo "To remove users: userdel -r <username>"
echo "To remove group: groupdel <groupname>"
echo ""
log_info "Uninstall complete!"

#!/bin/bash
#
# Wazuh Agent Installation and Enrollment Script
# Automatically detects OS, installs agent, and enrolls with manager
#

set -e

# Configuration (can be overridden by environment variables)
WAZUH_MANAGER="${WAZUH_MANAGER:-}"
WAZUH_REGISTRATION_PASSWORD="${WAZUH_REGISTRATION_PASSWORD:-}"
WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP:-default}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-$(hostname)}"
WAZUH_VERSION="${WAZUH_VERSION:-4.7.0}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[WAZUH]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WAZUH]${NC} $1"; }
log_error() { echo -e "${RED}[WAZUH]${NC} $1"; }

#
# OS Detection
#

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_FAMILY=""

        case "$ID" in
            ubuntu|debian|linuxmint)
                OS_FAMILY="debian"
                ;;
            rhel|centos|fedora|rocky|almalinux|ol)
                OS_FAMILY="rhel"
                ;;
            amzn)
                OS_FAMILY="rhel"
                ;;
            sles|opensuse*)
                OS_FAMILY="suse"
                ;;
            *)
                log_error "Unsupported OS: $ID"
                return 1
                ;;
        esac
    else
        log_error "Cannot detect OS (no /etc/os-release)"
        return 1
    fi

    log_info "Detected OS: $OS_ID $OS_VERSION ($OS_FAMILY family)"
}

#
# Check if Wazuh agent is already installed
#

check_wazuh_installed() {
    if command -v /var/ossec/bin/wazuh-control &> /dev/null; then
        return 0
    fi
    if [ -d /var/ossec ]; then
        return 0
    fi
    return 1
}

check_wazuh_running() {
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        return 0
    fi
    return 1
}

check_wazuh_connected() {
    if [ -f /var/ossec/var/run/wazuh-agentd.state ]; then
        local status=$(cat /var/ossec/var/run/wazuh-agentd.state 2>/dev/null | grep "status" | cut -d'=' -f2 | tr -d "'" | tr -d ' ')
        if [ "$status" = "connected" ]; then
            return 0
        fi
    fi
    return 1
}

#
# Installation Functions
#

install_debian() {
    log_info "Installing Wazuh agent on Debian/Ubuntu..."

    # Install dependencies
    apt-get update -qq
    apt-get install -y -qq curl apt-transport-https lsb-release gnupg2

    # Add Wazuh repository
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list

    apt-get update -qq

    # Install agent with manager configuration
    WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y -qq wazuh-agent

    # Prevent automatic updates
    echo "wazuh-agent hold" | dpkg --set-selections

    log_info "Wazuh agent installed successfully"
}

install_rhel() {
    log_info "Installing Wazuh agent on RHEL/CentOS..."

    # Add Wazuh repository
    cat > /etc/yum.repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

    # Install agent
    WAZUH_MANAGER="$WAZUH_MANAGER" yum install -y -q wazuh-agent

    log_info "Wazuh agent installed successfully"
}

install_suse() {
    log_info "Installing Wazuh agent on SUSE..."

    # Add Wazuh repository
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

    cat > /etc/zypp/repos.d/wazuh.repo << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

    # Install agent
    WAZUH_MANAGER="$WAZUH_MANAGER" zypper install -y wazuh-agent

    log_info "Wazuh agent installed successfully"
}

#
# Configuration and Enrollment
#

configure_agent() {
    log_info "Configuring Wazuh agent..."

    local OSSEC_CONF="/var/ossec/etc/ossec.conf"

    # Backup original config
    [ -f "$OSSEC_CONF" ] && cp "$OSSEC_CONF" "${OSSEC_CONF}.bak"

    # Update manager address if not set during installation
    if [ -n "$WAZUH_MANAGER" ]; then
        if grep -q "<address>MANAGER_IP</address>" "$OSSEC_CONF" 2>/dev/null; then
            sed -i "s/<address>MANAGER_IP<\/address>/<address>$WAZUH_MANAGER<\/address>/" "$OSSEC_CONF"
        elif ! grep -q "<address>$WAZUH_MANAGER</address>" "$OSSEC_CONF"; then
            # Add server block if not present
            sed -i "/<client>/,/<\/client>/s|<server>|<server>\n      <address>$WAZUH_MANAGER</address>|" "$OSSEC_CONF"
        fi
    fi

    # Set agent name
    if [ -n "$WAZUH_AGENT_NAME" ]; then
        if grep -q "<agent_name>" "$OSSEC_CONF"; then
            sed -i "s|<agent_name>.*</agent_name>|<agent_name>$WAZUH_AGENT_NAME</agent_name>|" "$OSSEC_CONF"
        fi
    fi

    log_info "Agent configured with manager: $WAZUH_MANAGER"
}

enroll_agent() {
    log_info "Enrolling agent with Wazuh manager..."

    # Method 1: Using registration password (agent-auth)
    if [ -n "$WAZUH_REGISTRATION_PASSWORD" ]; then
        log_info "Using registration password for enrollment..."

        /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" -P "$WAZUH_REGISTRATION_PASSWORD" -G "$WAZUH_AGENT_GROUP" -A "$WAZUH_AGENT_NAME" || {
            log_warn "agent-auth failed, trying alternative method..."
        }
    fi

    # Method 2: Using API enrollment (Wazuh 4.x)
    if [ ! -f /var/ossec/etc/client.keys ] || [ ! -s /var/ossec/etc/client.keys ]; then
        if [ -n "$WAZUH_API_USER" ] && [ -n "$WAZUH_API_PASSWORD" ]; then
            log_info "Using API enrollment..."

            # Get JWT token
            local TOKEN=$(curl -s -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" -k "https://$WAZUH_MANAGER:55000/security/user/authenticate" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

            if [ -n "$TOKEN" ]; then
                # Register agent
                local RESPONSE=$(curl -s -k -X POST "https://$WAZUH_MANAGER:55000/agents" \
                    -H "Authorization: Bearer $TOKEN" \
                    -H "Content-Type: application/json" \
                    -d "{\"name\":\"$WAZUH_AGENT_NAME\",\"ip\":\"any\"}")

                local AGENT_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
                local AGENT_KEY=$(echo "$RESPONSE" | grep -o '"key":"[^"]*"' | cut -d'"' -f4)

                if [ -n "$AGENT_KEY" ]; then
                    echo "$AGENT_KEY" | /var/ossec/bin/manage_agents -i -
                    log_info "Agent enrolled via API (ID: $AGENT_ID)"
                fi
            fi
        fi
    fi

    # Check if enrollment succeeded
    if [ -f /var/ossec/etc/client.keys ] && [ -s /var/ossec/etc/client.keys ]; then
        log_info "Agent enrollment successful"
        return 0
    else
        log_warn "Agent enrollment may not be complete - manual enrollment may be required"
        return 1
    fi
}

start_agent() {
    log_info "Starting Wazuh agent..."

    systemctl daemon-reload
    systemctl enable wazuh-agent
    systemctl start wazuh-agent

    # Wait for connection
    local retries=10
    while [ $retries -gt 0 ]; do
        if check_wazuh_connected; then
            log_info "Agent connected to manager successfully"
            return 0
        fi
        sleep 3
        ((retries--))
    done

    log_warn "Agent started but connection status unknown"
}

#
# Main Installation Flow
#

install_wazuh_agent() {
    # Check if manager is specified
    if [ -z "$WAZUH_MANAGER" ]; then
        log_error "WAZUH_MANAGER not specified"
        echo "Usage: WAZUH_MANAGER=<ip> [WAZUH_REGISTRATION_PASSWORD=<pass>] $0"
        return 1
    fi

    # Check if already installed and connected
    if check_wazuh_installed; then
        log_info "Wazuh agent is already installed"

        if check_wazuh_running; then
            log_info "Wazuh agent is running"

            if check_wazuh_connected; then
                log_info "Wazuh agent is connected to manager"
                return 0
            else
                log_warn "Agent running but not connected - attempting reconfiguration"
                configure_agent
                enroll_agent
                systemctl restart wazuh-agent
                return 0
            fi
        else
            log_warn "Agent installed but not running - starting..."
            configure_agent
            start_agent
            return 0
        fi
    fi

    # Detect OS
    detect_os || return 1

    # Install based on OS family
    case "$OS_FAMILY" in
        debian) install_debian ;;
        rhel)   install_rhel ;;
        suse)   install_suse ;;
        *)      log_error "Unsupported OS family: $OS_FAMILY"; return 1 ;;
    esac

    # Configure agent
    configure_agent

    # Enroll with manager
    enroll_agent

    # Start agent
    start_agent

    log_info "Wazuh agent installation complete"
}

#
# Status Check Function
#

check_status() {
    echo ""
    echo "=== Wazuh Agent Status ==="
    echo ""

    if check_wazuh_installed; then
        echo "Installed: Yes"

        if [ -f /var/ossec/etc/client.keys ]; then
            echo "Enrolled:  Yes"
            local AGENT_ID=$(cut -d' ' -f1 /var/ossec/etc/client.keys 2>/dev/null)
            echo "Agent ID:  $AGENT_ID"
        else
            echo "Enrolled:  No"
        fi

        if check_wazuh_running; then
            echo "Running:   Yes"
        else
            echo "Running:   No"
        fi

        if check_wazuh_connected; then
            echo "Connected: Yes"
        else
            echo "Connected: No"
        fi

        if [ -f /var/ossec/etc/ossec.conf ]; then
            local MGR=$(grep -oP '(?<=<address>)[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null | head -1)
            echo "Manager:   $MGR"
        fi
    else
        echo "Installed: No"
    fi
    echo ""
}

#
# Script Entry Point
#

case "${1:-install}" in
    install)
        install_wazuh_agent
        ;;
    status)
        check_status
        ;;
    *)
        echo "Usage: $0 [install|status]"
        echo ""
        echo "Environment variables:"
        echo "  WAZUH_MANAGER              - Wazuh manager IP (required)"
        echo "  WAZUH_REGISTRATION_PASSWORD - Registration password"
        echo "  WAZUH_AGENT_NAME           - Agent name (default: hostname)"
        echo "  WAZUH_AGENT_GROUP          - Agent group (default: default)"
        echo "  WAZUH_API_USER             - API user for enrollment"
        echo "  WAZUH_API_PASSWORD         - API password for enrollment"
        exit 1
        ;;
esac

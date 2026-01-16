#!/bin/bash
#
# Tripwire Honeypot Remote Deployment
# Deploys the tripwire honeypot to remote hosts via SSH
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_task()  { echo -e "${CYAN}[*]${NC} $1"; }

usage() {
    cat << EOF
Tripwire Honeypot Remote Deployment

Usage: $0 [OPTIONS] <target> [target2] [target3] ...

Options:
    -u, --user USER       SSH user (default: root)
    -k, --key FILE        SSH private key file
    -p, --port PORT       SSH port (default: 22)
    -i, --inventory FILE  File with list of hosts (one per line)
    -P, --parallel NUM    Number of parallel deployments (default: 5)
    --dry-run             Show what would be done without executing
    -h, --help            Show this help message

Examples:
    $0 -u admin -k ~/.ssh/id_rsa server1.example.com
    $0 -i hosts.txt
    $0 -u root 192.168.1.10 192.168.1.11 192.168.1.12
    $0 --parallel 10 -i large_inventory.txt

EOF
    exit 1
}

# Default values
SSH_USER="root"
SSH_KEY=""
SSH_PORT="22"
INVENTORY_FILE=""
PARALLEL=5
DRY_RUN=false
TARGETS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--user)      SSH_USER="$2"; shift 2 ;;
        -k|--key)       SSH_KEY="$2"; shift 2 ;;
        -p|--port)      SSH_PORT="$2"; shift 2 ;;
        -i|--inventory) INVENTORY_FILE="$2"; shift 2 ;;
        -P|--parallel)  PARALLEL="$2"; shift 2 ;;
        --dry-run)      DRY_RUN=true; shift ;;
        -h|--help)      usage ;;
        -*)             log_error "Unknown option: $1"; usage ;;
        *)              TARGETS+=("$1"); shift ;;
    esac
done

# Load inventory file if provided
if [ -n "$INVENTORY_FILE" ]; then
    if [ ! -f "$INVENTORY_FILE" ]; then
        log_error "Inventory file not found: $INVENTORY_FILE"
        exit 1
    fi
    while IFS= read -r line; do
        [[ "$line" =~ ^#.*$ ]] && continue  # Skip comments
        [[ -z "$line" ]] && continue         # Skip empty lines
        TARGETS+=("$line")
    done < "$INVENTORY_FILE"
fi

# Validate targets
if [ ${#TARGETS[@]} -eq 0 ]; then
    log_error "No targets specified"
    usage
fi

# Build SSH options
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -p $SSH_PORT"
[ -n "$SSH_KEY" ] && SSH_OPTS="$SSH_OPTS -i $SSH_KEY"

# Create temporary directory for package
TEMP_DIR=$(mktemp -d)
PACKAGE_FILE="$TEMP_DIR/tripwire-honeypot.tar.gz"

log_info "Packaging tripwire-honeypot..."
tar -czf "$PACKAGE_FILE" -C "$SCRIPT_DIR" \
    config scripts systemd wazuh-rules install.sh

log_info "Package created: $(du -h "$PACKAGE_FILE" | cut -f1)"

# Function to deploy to single host
deploy_to_host() {
    local HOST="$1"
    local LOG_PREFIX="[$HOST]"

    echo -e "${CYAN}${LOG_PREFIX}${NC} Starting deployment..."

    if $DRY_RUN; then
        echo -e "${YELLOW}${LOG_PREFIX}${NC} [DRY-RUN] Would deploy to $HOST"
        return 0
    fi

    # Test connectivity
    if ! ssh $SSH_OPTS "$SSH_USER@$HOST" "echo 'Connection OK'" &>/dev/null; then
        echo -e "${RED}${LOG_PREFIX}${NC} Connection failed"
        return 1
    fi

    # Create remote temp directory and copy package
    REMOTE_TEMP=$(ssh $SSH_OPTS "$SSH_USER@$HOST" "mktemp -d")

    scp $SSH_OPTS "$PACKAGE_FILE" "$SSH_USER@$HOST:$REMOTE_TEMP/" &>/dev/null

    # Extract and install
    ssh $SSH_OPTS "$SSH_USER@$HOST" bash << EOF
set -e
cd "$REMOTE_TEMP"
tar -xzf tripwire-honeypot.tar.gz
chmod +x install.sh
./install.sh
rm -rf "$REMOTE_TEMP"
EOF

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}${LOG_PREFIX}${NC} Deployment successful"
        return 0
    else
        echo -e "${RED}${LOG_PREFIX}${NC} Deployment failed"
        return 1
    fi
}

export -f deploy_to_host
export SSH_OPTS SSH_USER PACKAGE_FILE DRY_RUN
export RED GREEN YELLOW CYAN NC

# Deploy to all targets
log_info "Deploying to ${#TARGETS[@]} host(s) with parallelism=$PARALLEL"
echo ""

SUCCESS=0
FAILED=0

if command -v parallel &> /dev/null && [ ${#TARGETS[@]} -gt 1 ]; then
    # Use GNU parallel if available
    printf '%s\n' "${TARGETS[@]}" | parallel -j "$PARALLEL" deploy_to_host {}
else
    # Fallback to background jobs
    RUNNING=0
    for HOST in "${TARGETS[@]}"; do
        deploy_to_host "$HOST" &
        ((RUNNING++))

        if [ $RUNNING -ge $PARALLEL ]; then
            wait -n
            ((RUNNING--))
        fi
    done
    wait
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
log_info "Deployment complete!"
log_info "To verify, SSH to a target and run: systemctl status tripwire-monitor"

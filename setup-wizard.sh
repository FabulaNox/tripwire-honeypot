#!/bin/bash
#
# Tripwire Honeypot Interactive Setup Wizard
# Guides users through configuration and deployment
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Symbols
CHECK="${GREEN}✓${NC}"
CROSS="${RED}✗${NC}"
ARROW="${CYAN}→${NC}"
BULLET="${BLUE}•${NC}"

# State variables
DEPLOY_TARGET=""
DECOY_USERS=()
REAL_SUDO_GROUP=""
PRIVILEGED_USER=""
INACTIVITY_TIMEOUT=""
ENABLE_COMMAND_TRACKING=""
WAZUH_MANAGER_IP=""
WAZUH_REGISTRATION_PASSWORD=""
WAZUH_AGENT_GROUP=""
WAZUH_API_USER=""
WAZUH_API_PASSWORD=""
INSTALL_WAZUH_AGENT=""

# Cloud-specific variables
AWS_REGION=""
AWS_VPC_ID=""
AWS_SUBNET_ID=""
AWS_KEY_NAME=""
AWS_INSTANCE_TYPE=""
AWS_INSTANCE_COUNT=""

AZURE_LOCATION=""
AZURE_RESOURCE_GROUP=""
AZURE_PREFIX=""
AZURE_VM_SIZE=""
AZURE_INSTANCE_COUNT=""
AZURE_SSH_PUB_KEY=""

GCP_PROJECT_ID=""
GCP_REGION=""
GCP_ZONE=""
GCP_PREFIX=""
GCP_MACHINE_TYPE=""
GCP_INSTANCE_COUNT=""
GCP_SSH_PUB_KEY=""

EXISTING_HOSTS=()

#
# Utility Functions
#

clear_screen() {
    printf "\033c"
}

print_header() {
    echo ""
    echo -e "${BOLD}${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}║${NC}      ${BOLD}Tripwire Honeypot Setup Wizard${NC}                        ${BOLD}${CYAN}║${NC}"
    echo -e "${BOLD}${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    local step=$1
    local total=$2
    local title=$3
    echo ""
    echo -e "${BOLD}${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Step ${step}/${total}: ${title}${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_info() {
    echo -e "  ${BULLET} ${DIM}$1${NC}"
}

print_success() {
    echo -e "  ${CHECK} $1"
}

print_warning() {
    echo -e "  ${YELLOW}!${NC} $1"
}

print_error() {
    echo -e "  ${CROSS} ${RED}$1${NC}"
}

prompt() {
    local message=$1
    local default=$2
    local var_name=$3

    if [ -n "$default" ]; then
        echo -ne "  ${ARROW} ${message} ${DIM}[${default}]${NC}: "
        read -r input
        if [ -z "$input" ]; then
            eval "$var_name=\"$default\""
        else
            eval "$var_name=\"$input\""
        fi
    else
        echo -ne "  ${ARROW} ${message}: "
        read -r input
        eval "$var_name=\"$input\""
    fi
}

prompt_password() {
    local message=$1
    local var_name=$2

    echo -ne "  ${ARROW} ${message}: "
    read -rs input
    echo ""
    eval "$var_name=\"$input\""
}

prompt_yes_no() {
    local message=$1
    local default=$2
    local var_name=$3

    local hint="y/n"
    [ "$default" = "y" ] && hint="Y/n"
    [ "$default" = "n" ] && hint="y/N"

    echo -ne "  ${ARROW} ${message} ${DIM}[${hint}]${NC}: "
    read -r input
    input=${input:-$default}

    if [[ "$input" =~ ^[Yy] ]]; then
        eval "$var_name=true"
    else
        eval "$var_name=false"
    fi
}

prompt_choice() {
    local message=$1
    shift
    local options=("$@")

    echo -e "  ${ARROW} ${message}"
    echo ""

    local i=1
    for opt in "${options[@]}"; do
        echo -e "     ${CYAN}${i})${NC} ${opt}"
        ((i++))
    done
    echo ""

    local choice
    while true; do
        echo -ne "  ${ARROW} Enter choice ${DIM}[1-${#options[@]}]${NC}: "
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#options[@]}" ]; then
            return $((choice - 1))
        fi
        print_error "Invalid choice. Please enter a number between 1 and ${#options[@]}"
    done
}

prompt_list() {
    local message=$1
    local var_name=$2
    local -a items=()

    echo -e "  ${ARROW} ${message}"
    echo -e "     ${DIM}(Enter one item per line, empty line to finish)${NC}"
    echo ""

    while true; do
        echo -ne "     ${DIM}>${NC} "
        read -r item
        [ -z "$item" ] && break
        items+=("$item")
    done

    eval "$var_name=(\"\${items[@]}\")"
}

wait_for_enter() {
    echo ""
    echo -ne "  ${DIM}Press Enter to continue...${NC}"
    read -r
}

validate_not_empty() {
    local value=$1
    local name=$2

    if [ -z "$value" ]; then
        print_error "$name cannot be empty"
        return 1
    fi
    return 0
}

#
# Step Functions
#

step_welcome() {
    clear_screen
    print_header

    echo -e "  Welcome to the Tripwire Honeypot setup wizard!"
    echo ""
    echo -e "  This wizard will guide you through:"
    echo ""
    echo -e "    ${BULLET} Choosing your deployment target (AWS, Azure, GCP, or existing hosts)"
    echo -e "    ${BULLET} Configuring decoy users and the real privileged group"
    echo -e "    ${BULLET} Setting up monitoring and alerting options"
    echo -e "    ${BULLET} Generating Terraform configuration"
    echo -e "    ${BULLET} Deploying the tripwire honeypot"
    echo ""
    echo -e "  ${BOLD}How it works:${NC}"
    echo ""
    echo -e "    ${DIM}1. Attackers see users in the 'sudo' group and think they have access${NC}"
    echo -e "    ${DIM}2. The 'sudo' group is actually a decoy with no privileges${NC}"
    echo -e "    ${DIM}3. Real admins know to 'su' to a different user for actual sudo${NC}"
    echo -e "    ${DIM}4. Attackers who don't do this are detected and alerted${NC}"
    echo ""

    wait_for_enter
}

step_deployment_target() {
    clear_screen
    print_header
    print_step 1 6 "Choose Deployment Target"

    echo -e "  Where do you want to deploy the tripwire honeypot?"
    echo ""

    prompt_choice "Select deployment target:" \
        "AWS - Create new EC2 instances" \
        "Azure - Create new Virtual Machines" \
        "GCP - Create new Compute instances" \
        "Existing Hosts - Deploy to servers you already have"

    local choice=$?
    case $choice in
        0) DEPLOY_TARGET="aws" ;;
        1) DEPLOY_TARGET="azure" ;;
        2) DEPLOY_TARGET="gcp" ;;
        3) DEPLOY_TARGET="existing" ;;
    esac

    echo ""
    print_success "Selected: ${BOLD}${DEPLOY_TARGET}${NC}"
}

step_tripwire_config() {
    clear_screen
    print_header
    print_step 2 6 "Tripwire Configuration"

    echo -e "  Configure the core tripwire honeypot settings."
    echo ""

    # Decoy users
    echo -e "  ${BOLD}Decoy Users${NC}"
    print_info "These users will appear to be in the 'sudo' group but have no actual privileges"
    print_info "Attackers who compromise these accounts will trigger alerts"
    echo ""

    prompt "Enter first decoy username" "admin_john" DECOY_USER_1
    DECOY_USERS+=("$DECOY_USER_1")

    prompt_yes_no "Add another decoy user?" "y" ADD_ANOTHER
    if [ "$ADD_ANOTHER" = "true" ]; then
        prompt "Enter second decoy username" "admin_jane" DECOY_USER_2
        DECOY_USERS+=("$DECOY_USER_2")
    fi

    echo ""
    print_success "Decoy users: ${DECOY_USERS[*]}"

    # Real sudo group
    echo ""
    echo -e "  ${BOLD}Real Privileged Group${NC}"
    print_info "This group will have actual sudo privileges"
    print_info "Use an obscure name that won't be obvious to attackers"
    echo ""

    prompt "Enter real sudo group name" "svc_mgmt" REAL_SUDO_GROUP
    print_success "Real sudo group: ${REAL_SUDO_GROUP}"

    # Privileged user
    echo ""
    echo -e "  ${BOLD}Privileged User${NC}"
    print_info "This is the user that real admins will 'su' to for sudo access"
    echo ""

    prompt "Enter privileged username" "ops_worker" PRIVILEGED_USER
    print_success "Privileged user: ${PRIVILEGED_USER}"

    wait_for_enter
}

step_monitoring_config() {
    clear_screen
    print_header
    print_step 3 6 "Monitoring Configuration"

    echo -e "  Configure detection and alerting settings."
    echo ""

    # Inactivity timeout
    echo -e "  ${BOLD}Inactivity Timeout${NC}"
    print_info "Alert if a decoy user logs in but doesn't 'su' to the privileged user"
    print_info "Real admins should switch within this time; attackers won't know to"
    echo ""

    prompt "Timeout in seconds before alerting" "180" INACTIVITY_TIMEOUT
    print_success "Timeout: ${INACTIVITY_TIMEOUT} seconds ($(( INACTIVITY_TIMEOUT / 60 )) minutes)"

    # Command tracking
    echo ""
    echo -e "  ${BOLD}Command Tracking${NC}"
    print_info "Log all commands run by decoy users via auditd"
    print_info "This captures attacker reconnaissance even if they don't trigger other alerts"
    echo ""

    prompt_yes_no "Enable command tracking?" "y" ENABLE_COMMAND_TRACKING
    print_success "Command tracking: ${ENABLE_COMMAND_TRACKING}"

    # Wazuh integration
    echo ""
    echo -e "  ${BOLD}Wazuh SIEM Integration${NC}"
    print_info "Connect to a Wazuh manager for centralized alerting"
    print_info "The wizard can automatically install and enroll Wazuh agents"
    echo ""

    prompt "Wazuh manager IP (or leave empty to skip)" "" WAZUH_MANAGER_IP

    if [ -n "$WAZUH_MANAGER_IP" ]; then
        print_success "Wazuh manager: ${WAZUH_MANAGER_IP}"

        # Auto-install agent
        echo ""
        echo -e "  ${BOLD}Wazuh Agent Installation${NC}"
        print_info "Automatically install Wazuh agent if not present on target hosts"
        echo ""

        prompt_yes_no "Auto-install Wazuh agent?" "y" INSTALL_WAZUH_AGENT
        print_success "Auto-install agent: ${INSTALL_WAZUH_AGENT}"

        if [ "$INSTALL_WAZUH_AGENT" = "true" ]; then
            # Agent enrollment
            echo ""
            echo -e "  ${BOLD}Agent Enrollment${NC}"
            print_info "Choose how to enroll agents with the Wazuh manager"
            echo ""

            prompt_choice "Enrollment method:" \
                "Registration password (authd)" \
                "API credentials" \
                "Manual enrollment (skip auto-enroll)"

            local enroll_choice=$?

            case $enroll_choice in
                0)
                    echo ""
                    prompt "Registration password" "" WAZUH_REGISTRATION_PASSWORD
                    prompt "Agent group" "tripwire" WAZUH_AGENT_GROUP
                    print_success "Will enroll using registration password"
                    ;;
                1)
                    echo ""
                    prompt "Wazuh API username" "wazuh-wui" WAZUH_API_USER
                    prompt_password "Wazuh API password" WAZUH_API_PASSWORD
                    prompt "Agent group" "tripwire" WAZUH_AGENT_GROUP
                    print_success "Will enroll using API credentials"
                    ;;
                2)
                    print_info "Agents will need manual enrollment after deployment"
                    WAZUH_AGENT_GROUP="tripwire"
                    ;;
            esac
        fi
    else
        print_info "Wazuh integration skipped"
        INSTALL_WAZUH_AGENT="false"
    fi

    wait_for_enter
}

step_cloud_config_aws() {
    clear_screen
    print_header
    print_step 4 6 "AWS Configuration"

    echo -e "  Configure AWS-specific settings for EC2 deployment."
    echo ""

    print_info "Make sure you have AWS CLI configured with appropriate credentials"
    echo ""

    # Region
    echo -e "  ${BOLD}AWS Region${NC}"
    prompt "AWS region" "us-east-1" AWS_REGION

    # VPC and Subnet
    echo ""
    echo -e "  ${BOLD}Network Configuration${NC}"
    print_info "You need an existing VPC and subnet"
    echo ""

    prompt "VPC ID" "" AWS_VPC_ID
    while ! validate_not_empty "$AWS_VPC_ID" "VPC ID"; do
        prompt "VPC ID" "" AWS_VPC_ID
    done

    prompt "Subnet ID" "" AWS_SUBNET_ID
    while ! validate_not_empty "$AWS_SUBNET_ID" "Subnet ID"; do
        prompt "Subnet ID" "" AWS_SUBNET_ID
    done

    # Key pair
    echo ""
    echo -e "  ${BOLD}SSH Access${NC}"
    prompt "EC2 Key Pair name" "" AWS_KEY_NAME
    while ! validate_not_empty "$AWS_KEY_NAME" "Key Pair name"; do
        prompt "EC2 Key Pair name" "" AWS_KEY_NAME
    done

    # Instance settings
    echo ""
    echo -e "  ${BOLD}Instance Configuration${NC}"
    prompt "Instance type" "t3.micro" AWS_INSTANCE_TYPE
    prompt "Number of instances" "1" AWS_INSTANCE_COUNT

    echo ""
    print_success "AWS configuration complete"

    wait_for_enter
}

step_cloud_config_azure() {
    clear_screen
    print_header
    print_step 4 6 "Azure Configuration"

    echo -e "  Configure Azure-specific settings for VM deployment."
    echo ""

    print_info "Make sure you have Azure CLI configured (az login)"
    echo ""

    # Location
    echo -e "  ${BOLD}Azure Location${NC}"
    prompt "Azure region" "eastus" AZURE_LOCATION

    # Resource group
    echo ""
    echo -e "  ${BOLD}Resource Group${NC}"
    prompt "Resource group name" "tripwire-honeypot-rg" AZURE_RESOURCE_GROUP

    # Prefix
    prompt "Resource name prefix" "tripwire" AZURE_PREFIX

    # SSH Key
    echo ""
    echo -e "  ${BOLD}SSH Access${NC}"
    prompt "Path to SSH public key" "~/.ssh/id_rsa.pub" AZURE_SSH_PUB_KEY

    # VM settings
    echo ""
    echo -e "  ${BOLD}VM Configuration${NC}"
    prompt "VM size" "Standard_B1s" AZURE_VM_SIZE
    prompt "Number of VMs" "1" AZURE_INSTANCE_COUNT

    echo ""
    print_success "Azure configuration complete"

    wait_for_enter
}

step_cloud_config_gcp() {
    clear_screen
    print_header
    print_step 4 6 "GCP Configuration"

    echo -e "  Configure GCP-specific settings for Compute deployment."
    echo ""

    print_info "Make sure you have gcloud CLI configured (gcloud auth login)"
    echo ""

    # Project
    echo -e "  ${BOLD}GCP Project${NC}"
    prompt "GCP Project ID" "" GCP_PROJECT_ID
    while ! validate_not_empty "$GCP_PROJECT_ID" "Project ID"; do
        prompt "GCP Project ID" "" GCP_PROJECT_ID
    done

    # Region/Zone
    echo ""
    echo -e "  ${BOLD}Location${NC}"
    prompt "GCP region" "us-central1" GCP_REGION
    prompt "GCP zone" "us-central1-a" GCP_ZONE

    # Prefix
    prompt "Resource name prefix" "tripwire" GCP_PREFIX

    # SSH Key
    echo ""
    echo -e "  ${BOLD}SSH Access${NC}"
    prompt "Path to SSH public key" "~/.ssh/id_rsa.pub" GCP_SSH_PUB_KEY

    # Instance settings
    echo ""
    echo -e "  ${BOLD}Instance Configuration${NC}"
    prompt "Machine type" "e2-micro" GCP_MACHINE_TYPE
    prompt "Number of instances" "1" GCP_INSTANCE_COUNT

    echo ""
    print_success "GCP configuration complete"

    wait_for_enter
}

step_cloud_config_existing() {
    clear_screen
    print_header
    print_step 4 6 "Existing Hosts Configuration"

    echo -e "  Configure SSH access to existing servers."
    echo ""

    print_info "Enter the hosts you want to deploy tripwire to"
    print_info "Each host needs SSH access with sudo/root privileges"
    echo ""

    local SSH_USER SSH_KEY SSH_PORT
    prompt "SSH username" "root" SSH_USER
    prompt "Path to SSH private key" "~/.ssh/id_rsa" SSH_KEY
    prompt "SSH port" "22" SSH_PORT

    echo ""
    echo -e "  ${BOLD}Add Hosts${NC}"
    print_info "Enter hostnames or IP addresses, one per line"
    print_info "Empty line to finish"
    echo ""

    while true; do
        local host
        echo -ne "     ${DIM}Host>${NC} "
        read -r host
        [ -z "$host" ] && break
        EXISTING_HOSTS+=("$host|$SSH_USER|$SSH_KEY|$SSH_PORT")
        print_success "Added: $host"
    done

    echo ""
    print_success "Configured ${#EXISTING_HOSTS[@]} host(s)"

    wait_for_enter
}

step_generate_config() {
    clear_screen
    print_header
    print_step 5 6 "Generate Configuration"

    echo -e "  Generating Terraform configuration files..."
    echo ""

    local TARGET_DIR=""

    case "$DEPLOY_TARGET" in
        aws)
            TARGET_DIR="$SCRIPT_DIR/terraform/examples/aws"
            generate_aws_tfvars
            ;;
        azure)
            TARGET_DIR="$SCRIPT_DIR/terraform/examples/azure"
            generate_azure_tfvars
            ;;
        gcp)
            TARGET_DIR="$SCRIPT_DIR/terraform/examples/gcp"
            generate_gcp_tfvars
            ;;
        existing)
            TARGET_DIR="$SCRIPT_DIR/terraform/examples/existing-hosts"
            generate_existing_tfvars
            ;;
    esac

    print_success "Configuration written to: ${TARGET_DIR}/terraform.tfvars"
    echo ""

    # Show generated file
    echo -e "  ${BOLD}Generated Configuration:${NC}"
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"
    cat "$TARGET_DIR/terraform.tfvars" | sed 's/^/  /'
    echo -e "  ${DIM}─────────────────────────────────────────────${NC}"

    wait_for_enter
}

generate_wazuh_config() {
    # Helper function to generate Wazuh configuration lines
    if [ -n "$WAZUH_MANAGER_IP" ]; then
        echo ""
        echo "# Wazuh Configuration"
        echo "wazuh_manager_ip            = \"${WAZUH_MANAGER_IP}\""
        echo "install_wazuh_agent         = ${INSTALL_WAZUH_AGENT}"
        [ -n "$WAZUH_AGENT_GROUP" ] && echo "wazuh_agent_group           = \"${WAZUH_AGENT_GROUP}\""
        [ -n "$WAZUH_REGISTRATION_PASSWORD" ] && echo "wazuh_registration_password = \"${WAZUH_REGISTRATION_PASSWORD}\""
        [ -n "$WAZUH_API_USER" ] && echo "wazuh_api_user              = \"${WAZUH_API_USER}\""
        [ -n "$WAZUH_API_PASSWORD" ] && echo "wazuh_api_password          = \"${WAZUH_API_PASSWORD}\""
    fi
}

generate_aws_tfvars() {
    local TARGET_DIR="$SCRIPT_DIR/terraform/examples/aws"

    cat > "$TARGET_DIR/terraform.tfvars" << EOF
# Generated by Tripwire Setup Wizard
# $(date)

# AWS Configuration
aws_region = "${AWS_REGION}"
vpc_id     = "${AWS_VPC_ID}"
subnet_id  = "${AWS_SUBNET_ID}"
key_name   = "${AWS_KEY_NAME}"

instance_type  = "${AWS_INSTANCE_TYPE}"
instance_count = ${AWS_INSTANCE_COUNT}

# Tripwire Configuration
decoy_users     = [$(printf '"%s", ' "${DECOY_USERS[@]}" | sed 's/, $//')]
real_sudo_group = "${REAL_SUDO_GROUP}"
privileged_user = "${PRIVILEGED_USER}"

inactivity_timeout      = ${INACTIVITY_TIMEOUT}
enable_command_tracking = ${ENABLE_COMMAND_TRACKING}
$(generate_wazuh_config)
EOF
}

generate_azure_tfvars() {
    local TARGET_DIR="$SCRIPT_DIR/terraform/examples/azure"

    cat > "$TARGET_DIR/terraform.tfvars" << EOF
# Generated by Tripwire Setup Wizard
# $(date)

# Azure Configuration
location            = "${AZURE_LOCATION}"
resource_group_name = "${AZURE_RESOURCE_GROUP}"
prefix              = "${AZURE_PREFIX}"

vm_size             = "${AZURE_VM_SIZE}"
instance_count      = ${AZURE_INSTANCE_COUNT}
ssh_public_key_path = "${AZURE_SSH_PUB_KEY}"

# Tripwire Configuration
decoy_users     = [$(printf '"%s", ' "${DECOY_USERS[@]}" | sed 's/, $//')]
real_sudo_group = "${REAL_SUDO_GROUP}"
privileged_user = "${PRIVILEGED_USER}"

inactivity_timeout      = ${INACTIVITY_TIMEOUT}
enable_command_tracking = ${ENABLE_COMMAND_TRACKING}
$(generate_wazuh_config)
EOF
}

generate_gcp_tfvars() {
    local TARGET_DIR="$SCRIPT_DIR/terraform/examples/gcp"

    cat > "$TARGET_DIR/terraform.tfvars" << EOF
# Generated by Tripwire Setup Wizard
# $(date)

# GCP Configuration
project_id = "${GCP_PROJECT_ID}"
region     = "${GCP_REGION}"
zone       = "${GCP_ZONE}"
prefix     = "${GCP_PREFIX}"

machine_type        = "${GCP_MACHINE_TYPE}"
instance_count      = ${GCP_INSTANCE_COUNT}
ssh_public_key_path = "${GCP_SSH_PUB_KEY}"

# Tripwire Configuration
decoy_users     = [$(printf '"%s", ' "${DECOY_USERS[@]}" | sed 's/, $//')]
real_sudo_group = "${REAL_SUDO_GROUP}"
privileged_user = "${PRIVILEGED_USER}"

inactivity_timeout      = ${INACTIVITY_TIMEOUT}
enable_command_tracking = ${ENABLE_COMMAND_TRACKING}
$(generate_wazuh_config)
EOF
}

generate_existing_tfvars() {
    local TARGET_DIR="$SCRIPT_DIR/terraform/examples/existing-hosts"

    cat > "$TARGET_DIR/terraform.tfvars" << EOF
# Generated by Tripwire Setup Wizard
# $(date)

# Target Hosts
target_hosts = [
EOF

    for host_entry in "${EXISTING_HOSTS[@]}"; do
        IFS='|' read -r host user key port <<< "$host_entry"
        cat >> "$TARGET_DIR/terraform.tfvars" << EOF
  {
    host        = "${host}"
    user        = "${user}"
    private_key = "${key}"
    port        = ${port}
  },
EOF
    done

    cat >> "$TARGET_DIR/terraform.tfvars" << EOF
]

# Tripwire Configuration
decoy_users     = [$(printf '"%s", ' "${DECOY_USERS[@]}" | sed 's/, $//')]
real_sudo_group = "${REAL_SUDO_GROUP}"
privileged_user = "${PRIVILEGED_USER}"

inactivity_timeout      = ${INACTIVITY_TIMEOUT}
enable_command_tracking = ${ENABLE_COMMAND_TRACKING}
$(generate_wazuh_config)
EOF
}

step_deploy() {
    clear_screen
    print_header
    print_step 6 6 "Deploy"

    local TARGET_DIR=""
    case "$DEPLOY_TARGET" in
        aws)      TARGET_DIR="$SCRIPT_DIR/terraform/examples/aws" ;;
        azure)    TARGET_DIR="$SCRIPT_DIR/terraform/examples/azure" ;;
        gcp)      TARGET_DIR="$SCRIPT_DIR/terraform/examples/gcp" ;;
        existing) TARGET_DIR="$SCRIPT_DIR/terraform/examples/existing-hosts" ;;
    esac

    echo -e "  ${BOLD}Ready to Deploy${NC}"
    echo ""
    echo -e "  ${BULLET} Target: ${BOLD}${DEPLOY_TARGET}${NC}"
    echo -e "  ${BULLET} Decoy users: ${BOLD}${DECOY_USERS[*]}${NC}"
    echo -e "  ${BULLET} Real sudo group: ${BOLD}${REAL_SUDO_GROUP}${NC}"
    echo -e "  ${BULLET} Privileged user: ${BOLD}${PRIVILEGED_USER}${NC}"
    echo -e "  ${BULLET} Inactivity timeout: ${BOLD}${INACTIVITY_TIMEOUT}s${NC}"
    echo ""

    prompt_yes_no "Run 'terraform init' now?" "y" RUN_INIT

    if [ "$RUN_INIT" = "true" ]; then
        echo ""
        echo -e "  ${ARROW} Running terraform init..."
        echo ""

        (cd "$TARGET_DIR" && terraform init)

        echo ""
        print_success "Terraform initialized"
    fi

    echo ""
    prompt_yes_no "Run 'terraform apply' now?" "y" RUN_APPLY

    if [ "$RUN_APPLY" = "true" ]; then
        echo ""
        echo -e "  ${ARROW} Running terraform apply..."
        echo ""

        (cd "$TARGET_DIR" && terraform apply)

        echo ""
        print_success "Deployment complete!"
    else
        echo ""
        echo -e "  To deploy manually, run:"
        echo ""
        echo -e "    ${CYAN}cd ${TARGET_DIR}${NC}"
        echo -e "    ${CYAN}terraform init${NC}"
        echo -e "    ${CYAN}terraform apply${NC}"
    fi

    wait_for_enter
}

step_complete() {
    clear_screen
    print_header

    echo -e "  ${GREEN}${BOLD}Setup Complete!${NC}"
    echo ""
    echo -e "  ${BOLD}Admin Workflow:${NC}"
    echo ""
    echo -e "    1. SSH as a decoy user:"
    echo -e "       ${CYAN}ssh ${DECOY_USERS[0]}@<host>${NC}"
    echo ""
    echo -e "    2. Switch to privileged user:"
    echo -e "       ${CYAN}su ${PRIVILEGED_USER}${NC}"
    echo ""
    echo -e "    3. Work with sudo:"
    echo -e "       ${CYAN}sudo <command>${NC}"
    echo ""
    echo -e "  ${BOLD}What Gets Detected:${NC}"
    echo ""
    echo -e "    ${BULLET} Decoy user login without 'su ${PRIVILEGED_USER}' within ${INACTIVITY_TIMEOUT}s"
    echo -e "    ${BULLET} Any 'sudo' attempt from decoy users (will fail)"
    echo -e "    ${BULLET} All commands run by decoy users (via auditd)"
    echo ""
    echo -e "  ${BOLD}View Logs:${NC}"
    echo ""
    echo -e "    ${CYAN}journalctl -t TRIPWIRE -f${NC}"
    echo ""

    if [ -n "$WAZUH_MANAGER_IP" ]; then
        echo -e "  ${BOLD}Wazuh:${NC}"
        echo -e "    Alerts will appear in Wazuh dashboard with group 'tripwire'"
        echo ""
    fi

    echo -e "  ${DIM}Thank you for using Tripwire Honeypot!${NC}"
    echo ""
}

#
# Main
#

main() {
    # Check for required tools
    if ! command -v terraform &> /dev/null; then
        echo -e "${RED}Error: terraform is not installed${NC}"
        echo "Please install Terraform first: https://www.terraform.io/downloads"
        exit 1
    fi

    step_welcome
    step_deployment_target
    step_tripwire_config
    step_monitoring_config

    case "$DEPLOY_TARGET" in
        aws)      step_cloud_config_aws ;;
        azure)    step_cloud_config_azure ;;
        gcp)      step_cloud_config_gcp ;;
        existing) step_cloud_config_existing ;;
    esac

    step_generate_config
    step_deploy
    step_complete
}

# Run main
main "$@"

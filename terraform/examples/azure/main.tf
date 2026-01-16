terraform {
  required_version = ">= 1.0.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Get tripwire cloud-init configuration
module "tripwire" {
  source = "../../modules/tripwire"

  decoy_users              = var.decoy_users
  decoy_user_passwords     = var.decoy_user_passwords
  real_sudo_group          = var.real_sudo_group
  privileged_user          = var.privileged_user
  privileged_user_password = var.privileged_user_password
  inactivity_timeout       = var.inactivity_timeout
  enable_command_tracking  = var.enable_command_tracking
  wazuh_manager_ip         = var.wazuh_manager_ip
}

# Resource Group
resource "azurerm_resource_group" "tripwire" {
  count    = var.create_resource_group ? 1 : 0
  name     = var.resource_group_name
  location = var.location

  tags = var.tags
}

data "azurerm_resource_group" "existing" {
  count = var.create_resource_group ? 0 : 1
  name  = var.resource_group_name
}

locals {
  resource_group_name     = var.create_resource_group ? azurerm_resource_group.tripwire[0].name : data.azurerm_resource_group.existing[0].name
  resource_group_location = var.create_resource_group ? azurerm_resource_group.tripwire[0].location : data.azurerm_resource_group.existing[0].location
}

# Virtual Network (optional)
resource "azurerm_virtual_network" "tripwire" {
  count               = var.create_vnet ? 1 : 0
  name                = "${var.prefix}-vnet"
  address_space       = [var.vnet_address_space]
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name

  tags = var.tags
}

resource "azurerm_subnet" "tripwire" {
  count                = var.create_vnet ? 1 : 0
  name                 = "${var.prefix}-subnet"
  resource_group_name  = local.resource_group_name
  virtual_network_name = azurerm_virtual_network.tripwire[0].name
  address_prefixes     = [var.subnet_address_prefix]
}

locals {
  subnet_id = var.create_vnet ? azurerm_subnet.tripwire[0].id : var.existing_subnet_id
}

# Network Security Group
resource "azurerm_network_security_group" "tripwire" {
  name                = "${var.prefix}-nsg"
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefixes    = var.ssh_allowed_cidrs
    destination_address_prefix = "*"
  }

  tags = var.tags
}

# Public IPs
resource "azurerm_public_ip" "tripwire" {
  count               = var.instance_count
  name                = "${var.prefix}-pip-${count.index + 1}"
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = var.tags
}

# Network Interfaces
resource "azurerm_network_interface" "tripwire" {
  count               = var.instance_count
  name                = "${var.prefix}-nic-${count.index + 1}"
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = local.subnet_id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.tripwire[count.index].id
  }

  tags = var.tags
}

# Associate NSG with NICs
resource "azurerm_network_interface_security_group_association" "tripwire" {
  count                     = var.instance_count
  network_interface_id      = azurerm_network_interface.tripwire[count.index].id
  network_security_group_id = azurerm_network_security_group.tripwire.id
}

# Virtual Machines
resource "azurerm_linux_virtual_machine" "tripwire" {
  count               = var.instance_count
  name                = "${var.prefix}-vm-${count.index + 1}"
  location            = local.resource_group_location
  resource_group_name = local.resource_group_name
  size                = var.vm_size
  admin_username      = var.admin_username

  network_interface_ids = [
    azurerm_network_interface.tripwire[count.index].id,
  ]

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(var.ssh_public_key_path)
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }

  custom_data = base64encode(module.tripwire.cloud_init_config)

  tags = merge(var.tags, {
    Name    = "${var.prefix}-vm-${count.index + 1}"
    Purpose = "honeypot"
  })
}

# Outputs
output "resource_group_name" {
  description = "Resource group name"
  value       = local.resource_group_name
}

output "vm_ids" {
  description = "IDs of created VMs"
  value       = azurerm_linux_virtual_machine.tripwire[*].id
}

output "public_ips" {
  description = "Public IPs of created VMs"
  value       = azurerm_public_ip.tripwire[*].ip_address
}

output "private_ips" {
  description = "Private IPs of created VMs"
  value       = azurerm_network_interface.tripwire[*].private_ip_address
}

output "ssh_commands" {
  description = "SSH commands to connect"
  value = [
    for idx, ip in azurerm_public_ip.tripwire[*].ip_address :
    "ssh ${var.decoy_users[0]}@${ip}"
  ]
}

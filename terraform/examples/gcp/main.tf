terraform {
  required_version = ">= 1.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
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

# VPC Network (optional)
resource "google_compute_network" "tripwire" {
  count                   = var.create_vpc ? 1 : 0
  name                    = "${var.prefix}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "tripwire" {
  count         = var.create_vpc ? 1 : 0
  name          = "${var.prefix}-subnet"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.tripwire[0].id
}

locals {
  network    = var.create_vpc ? google_compute_network.tripwire[0].name : var.existing_network
  subnetwork = var.create_vpc ? google_compute_subnetwork.tripwire[0].name : var.existing_subnetwork
}

# Firewall rule for SSH
resource "google_compute_firewall" "tripwire_ssh" {
  name    = "${var.prefix}-allow-ssh"
  network = local.network

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = var.ssh_allowed_cidrs
  target_tags   = ["tripwire-honeypot"]
}

# Service Account (optional)
resource "google_service_account" "tripwire" {
  count        = var.create_service_account ? 1 : 0
  account_id   = "${var.prefix}-sa"
  display_name = "Tripwire Honeypot Service Account"
}

locals {
  service_account_email = var.create_service_account ? google_service_account.tripwire[0].email : var.existing_service_account_email
}

# Compute Instances
resource "google_compute_instance" "tripwire" {
  count        = var.instance_count
  name         = "${var.prefix}-vm-${count.index + 1}"
  machine_type = var.machine_type
  zone         = var.zone

  tags = ["tripwire-honeypot"]

  boot_disk {
    initialize_params {
      image = var.image
      size  = var.disk_size_gb
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = local.network
    subnetwork = local.subnetwork

    access_config {
      // Ephemeral public IP
    }
  }

  metadata = {
    user-data = module.tripwire.cloud_init_config
    ssh-keys  = "${var.ssh_user}:${file(var.ssh_public_key_path)}"
  }

  service_account {
    email  = local.service_account_email
    scopes = ["cloud-platform"]
  }

  labels = merge(var.labels, {
    purpose = "honeypot"
  })
}

# Outputs
output "project_id" {
  description = "GCP project ID"
  value       = var.project_id
}

output "instance_names" {
  description = "Names of created instances"
  value       = google_compute_instance.tripwire[*].name
}

output "instance_ids" {
  description = "IDs of created instances"
  value       = google_compute_instance.tripwire[*].id
}

output "external_ips" {
  description = "External IPs of created instances"
  value       = google_compute_instance.tripwire[*].network_interface[0].access_config[0].nat_ip
}

output "internal_ips" {
  description = "Internal IPs of created instances"
  value       = google_compute_instance.tripwire[*].network_interface[0].network_ip
}

output "ssh_commands" {
  description = "SSH commands to connect"
  value = [
    for instance in google_compute_instance.tripwire :
    "gcloud compute ssh ${var.decoy_users[0]}@${instance.name} --zone=${var.zone}"
  ]
}

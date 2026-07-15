################################################################################
# CloudGuard — GCP Test Environment
# Toggle `misconfigured = true` to introduce GDPR violations.
################################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "GCP project ID"
}

variable "region" {
  default = "europe-west1"
}

variable "misconfigured" {
  description = "Set to true to introduce deliberate GDPR violations for evaluation."
  type        = bool
  default     = false
}

variable "prefix" {
  default = "cloudguard-test"
}

################################################################################
# KMS key ring + key (used for CMEK — C-11, C-19)
################################################################################

resource "google_kms_key_ring" "test" {
  name     = "${var.prefix}-keyring"
  location = var.region
}

resource "google_kms_crypto_key" "test" {
  name            = "${var.prefix}-key"
  key_ring        = google_kms_key_ring.test.id
  rotation_period = "7776000s"  # 90 days
}

################################################################################
# C-11 / C-12 — Cloud Storage bucket
################################################################################

resource "google_storage_bucket" "test" {
  name          = "${var.prefix}-bucket-${var.project_id}"
  location      = var.region
  force_destroy = true

  # C-11: CMEK (omit when misconfigured to simulate no CMEK)
  dynamic "encryption" {
    for_each = var.misconfigured ? [] : [1]
    content {
      default_kms_key_name = google_kms_crypto_key.test.id
    }
  }

  # C-12: Public access prevention
  public_access_prevention = var.misconfigured ? "inherited" : "enforced"
}

################################################################################
# C-13 / C-14 / C-15 — Audit log configuration
################################################################################

resource "google_project_iam_audit_config" "all_services" {
  count   = var.misconfigured ? 0 : 1
  project = var.project_id
  service = "allServices"

  audit_log_config { log_type = "DATA_READ" }   # C-13
  audit_log_config { log_type = "DATA_WRITE" }  # C-14
  audit_log_config { log_type = "ADMIN_READ" }  # C-15
}

################################################################################
# C-16 / C-17 — Cloud SQL instance
################################################################################

resource "google_sql_database_instance" "test" {
  name             = "${var.prefix}-sql"
  database_version = "MYSQL_8_0"
  region           = var.region
  deletion_protection = false

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      require_ssl = !var.misconfigured   # C-16
    }

    backup_configuration {
      enabled    = !var.misconfigured    # C-17
      start_time = "02:00"
    }
  }
}

################################################################################
# C-18 — IAM (no public bindings)
# Compliant: no public bindings at project or bucket level
# Misconfigured: grant allUsers Storage Object Viewer on the test bucket
# (bucket-level chosen because project-level allUsers is blocked by org policy)
################################################################################

resource "google_storage_bucket_iam_member" "public_viewer" {
  count  = var.misconfigured ? 1 : 0
  bucket = google_storage_bucket.test.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

################################################################################
# C-19 — Compute Engine disk with CMEK
################################################################################

resource "google_compute_disk" "test" {
  name  = "${var.prefix}-disk"
  type  = "pd-standard"
  zone  = "${var.region}-b"
  size  = 10

  dynamic "disk_encryption_key" {
    for_each = var.misconfigured ? [] : [1]
    content {
      kms_key_self_link = google_kms_crypto_key.test.id
    }
  }
}

################################################################################
# C-20 — Secret Manager secret
################################################################################

resource "google_secret_manager_secret" "test" {
  secret_id = "${var.prefix}-secret"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "test" {
  count       = var.misconfigured ? 0 : 1   # no version = unversioned secret
  secret      = google_secret_manager_secret.test.id
  secret_data = "synthetic-test-value-no-pii"
}

################################################################################
# Outputs
################################################################################

output "bucket_name"       { value = google_storage_bucket.test.name }
output "sql_instance_name" { value = google_sql_database_instance.test.name }
output "kms_key_id"        { value = google_kms_crypto_key.test.id }
output "disk_name"         { value = google_compute_disk.test.name }
output "misconfigured"     { value = var.misconfigured }

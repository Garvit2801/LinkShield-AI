terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

variable "project_id" { type = string }
variable "region" {
  type    = string
  default = "us-central1"
}
variable "image" {
  type    = string
  default = "us-docker.pkg.dev/cloudrun/container/hello"
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_project_service" "apis" {
  for_each = toset(["run.googleapis.com", "aiplatform.googleapis.com", "bigquery.googleapis.com",
  "texttospeech.googleapis.com", "webrisk.googleapis.com", "cloudbuild.googleapis.com", "artifactregistry.googleapis.com"])
  service            = each.key
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "repo" {
  repository_id = "linkshield"
  location      = var.region
  format        = "DOCKER"
  depends_on    = [google_project_service.apis]
}

resource "google_service_account" "run" {
  account_id   = "linkshield-run"
  display_name = "LinkShield AI Cloud Run"
}

resource "google_project_iam_member" "roles" {
  for_each = toset(["roles/aiplatform.user", "roles/bigquery.dataEditor", "roles/bigquery.jobUser"])
  project  = var.project_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.run.email}"
}

resource "google_bigquery_dataset" "ds" {
  dataset_id = "linkshield"
  location   = "US"
  depends_on = [google_project_service.apis]
}

resource "google_bigquery_table" "claims" {
  dataset_id          = google_bigquery_dataset.ds.dataset_id
  table_id            = "claims_log"
  deletion_protection = false
  time_partitioning {
    type  = "DAY"
    field = "ts"
  }
  schema = jsonencode([
    { name = "ts", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "claim_id", type = "STRING" },
    { name = "claim", type = "STRING" },
    { name = "language", type = "STRING" },
    { name = "verdict", type = "STRING" },
    { name = "confidence", type = "FLOAT" },
    { name = "grounded", type = "BOOLEAN" },
  ])
}

resource "google_cloud_run_v2_service" "app" {
  name                = "linkshield"
  location            = var.region
  deletion_protection = false
  template {
    service_account                  = google_service_account.run.email
    timeout                          = "120s"
    max_instance_request_concurrency = 20
    scaling {
      min_instance_count = 0
      max_instance_count = 5
    }
    containers {
      image = var.image
      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }
      env {
        name  = "BQ_TABLE"
        value = "${var.project_id}.linkshield.claims_log"
      }
    }
  }
  depends_on = [google_project_iam_member.roles, google_bigquery_table.claims]
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  name     = google_cloud_run_v2_service.app.name
  location = var.region
  role     = "roles/run.invoker"
  member   = "allUsers"
}

output "url" { value = google_cloud_run_v2_service.app.uri }

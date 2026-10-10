#!/usr/bin/env bash
# Usage: ./deploy.sh <project-id> [region]   (infra via Terraform, image via Cloud Build)
set -euo pipefail
PROJECT=${1:?usage: ./deploy.sh <project-id> [region]}
REGION=${2:-us-central1}
IMAGE="$REGION-docker.pkg.dev/$PROJECT/linkshield/app:$(date +%s)"
gcloud config set project "$PROJECT"
terraform -chdir=terraform init -input=false
terraform -chdir=terraform apply -auto-approve -var project_id="$PROJECT" -var region="$REGION"
gcloud builds submit --tag "$IMAGE" .
terraform -chdir=terraform apply -auto-approve -var project_id="$PROJECT" -var region="$REGION" -var image="$IMAGE"
echo "Live at: $(terraform -chdir=terraform output -raw url)"

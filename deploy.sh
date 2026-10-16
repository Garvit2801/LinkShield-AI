#!/usr/bin/env bash
# ./deploy.sh <project-id> [region] [extra terraform arguments...]
# Example: ./deploy.sh my-project us-central1 -var firebase_api_key=... -var virustotal_api_key=...
# For a throwaway demo without sign-in, add: -var auth_required=false
set -euo pipefail
PROJECT=${1:?Usage: ./deploy.sh <project-id> [region] [extra terraform arguments...]}
REGION=${2:-us-central1}
EXTRA=("${@:3}")
TAG=$(date +%s)
REPO="$REGION-docker.pkg.dev/$PROJECT/linkshield"
command -v gcloud >/dev/null || { echo "Install Google Cloud CLI" >&2; exit 1; }
command -v terraform >/dev/null || { echo "Install Terraform" >&2; exit 1; }
gcloud config set project "$PROJECT"
terraform -chdir=terraform init -input=false
VARS=(-var "project_id=$PROJECT" -var "region=$REGION")
# First pass: infrastructure and a placeholder image, so the image repository exists.
terraform -chdir=terraform apply "${VARS[@]}" ${EXTRA[@]+"${EXTRA[@]}"} -auto-approve
gcloud builds submit --tag "$REPO/api:$TAG" .
gcloud builds submit --config sandbox/cloudbuild.yaml --substitutions "_IMAGE=$REPO/sandbox:$TAG" .
# Second pass: the API and the sandbox worker, each as its own Cloud Run service.
terraform -chdir=terraform apply "${VARS[@]}" -var "image=$REPO/api:$TAG" -var "sandbox_image=$REPO/sandbox:$TAG" ${EXTRA[@]+"${EXTRA[@]}"} -auto-approve
URL=$(terraform -chdir=terraform output -raw url)
echo "Deployed: $URL"
echo "Sandbox worker: $(terraform -chdir=terraform output -raw sandbox_url) (private; only the API's service account can call it)"
echo "Telegram: after creating a bot with @BotFather, register the webhook with"
echo "  curl \"https://api.telegram.org/bot<TOKEN>/setWebhook\" -d url=$URL/api/v1/bots/telegram -d secret_token=\$(terraform -chdir=terraform output -raw telegram_webhook_secret)"
echo "WhatsApp: in the Meta developer console set the webhook to $URL/api/v1/bots/whatsapp with verify token"
echo "  terraform -chdir=terraform output -raw whatsapp_verify_token"

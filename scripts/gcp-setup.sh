#!/bin/bash
# GCP Setup for EVTX-Wazuh-Rules Auto-Deploy
# Run this in GCP Cloud Shell or any terminal with gcloud installed.
#
# This script:
# 1. Creates a GCP service account for GitHub Actions
# 2. Grants it Compute Engine permissions
# 3. Generates a JSON key
# 4. Tells you what GitHub secrets to set
#
# Usage: bash scripts/gcp-setup.sh <PROJECT_ID>

set -e

PROJECT_ID="${1:?Usage: $0 <GCP_PROJECT_ID>}"
SA_NAME="github-deploy"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "=== GCP Setup for EVTX-Wazuh-Rules ==="
echo "Project: $PROJECT_ID"
echo ""

# Enable required APIs
echo ">> Enabling Compute Engine API..."
gcloud services enable compute.googleapis.com --project="$PROJECT_ID"

# Create service account
if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" 2>/dev/null; then
    echo ">> Service account already exists: $SA_EMAIL"
else
    echo ">> Creating service account..."
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="GitHub Actions Deploy" \
        --project="$PROJECT_ID"
fi

# Grant permissions
echo ">> Granting Compute Engine permissions..."
for ROLE in roles/compute.admin roles/iam.serviceAccountUser; do
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="$ROLE" \
        --quiet > /dev/null
done

# Generate key
KEY_FILE="/tmp/gcp-sa-key.json"
echo ">> Generating service account key..."
gcloud iam service-accounts keys create "$KEY_FILE" \
    --iam-account="$SA_EMAIL" \
    --project="$PROJECT_ID"

echo ""
echo "========================================="
echo "  SETUP COMPLETE — Add GitHub Secrets"
echo "========================================="
echo ""
echo "Go to: https://github.com/saifbelaarbi/EVTX-Wazuh-rules/settings/secrets/actions"
echo ""
echo "Add these 3 secrets:"
echo ""
echo "1. GCP_PROJECT_ID"
echo "   Value: $PROJECT_ID"
echo ""
echo "2. GCP_SA_KEY"
echo "   Value: (paste the contents of the file below)"
echo "   File:  $KEY_FILE"
echo ""
echo "3. GH_PAT (GitHub Personal Access Token)"
echo "   Create at: https://github.com/settings/tokens?type=beta"
echo "   Scope: repo (read access to saifbelaarbi/EVTX-Wazuh-rules)"
echo ""
echo "Then trigger: Actions → Deploy to GCP → Run workflow → deploy"
echo ""
echo "To see the key contents:"
echo "  cat $KEY_FILE"
echo ""

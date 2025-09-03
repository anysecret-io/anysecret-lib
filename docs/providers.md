# Provider Setup Guide

Complete setup instructions for configuring cloud providers with the AnySecret CLI.

## 🎯 Overview

AnySecret CLI works with multiple providers for **secrets** (sensitive data) and **parameters** (configuration data). This guide shows you how to authenticate and configure each provider.

## 📋 Provider Matrix

| Provider | Secrets Storage | Parameters Storage | Cost (Monthly) | Auto-Setup |
|----------|----------------|--------------------|--------------|----|
| **Local Files** | .env files | JSON/YAML | Free | ✅ |
| **AWS** | Secrets Manager | S3 / Parameter Store | $0.40 / $0.01 | ✅ |
| **GCP** | Secret Manager | GCS Storage | $0.40 / $0.01 | ✅ |
| **Azure** | Key Vault | Blob Storage | $0.40 / $0.01 | ✅ |
| **Kubernetes** | Secrets | ConfigMaps | Free* | ⚠️ |
| **HashiCorp Vault** | KV Store | KV Store | Variable | ❌ |

*Free but requires cluster infrastructure costs

---

## 🏠 Local Files (Development)

Perfect for development and hobby projects. No cloud costs, works offline.

### Setup

```bash
# Create local profile (uses files in ~/.anysecret/)
anysecret config profile-create dev-local

# Start adding configuration
anysecret set DATABASE_PASSWORD "dev_password_123"
anysecret set DATABASE_HOST "localhost"

# Check where files are stored
anysecret info
# Shows: ~/.anysecret/profiles/dev-local/
```

### File Structure

```bash
~/.anysecret/profiles/dev-local/
├── secrets.env          # Secret values (chmod 600)
├── parameters.json      # Parameter values  
└── metadata.json        # Key metadata
```

### Advanced Local Setup

```bash
# Use custom directory
anysecret config profile-create custom-dev --storage-path ./my-config

# Use different formats
anysecret config profile-create yaml-config --parameter-format yaml
anysecret config profile-create env-only --secret-format env --parameter-format env
```

---

## ☁️ AWS Setup

### Prerequisites

1. AWS account with appropriate permissions
2. AWS CLI configured: `aws configure`
3. AnySecret installed: `pip install anysecret-io`

### Quick Setup

```bash
# Create AWS profile (auto-detects region and credentials)
anysecret config profile-create aws-prod --provider aws

# Test connection
anysecret providers health
# Output: aws-secrets-manager ✅ connected
#         aws-s3-parameters ✅ connected
```

### Authentication Methods

#### Option 1: AWS CLI Profile (Recommended)
```bash
# Configure AWS CLI first
aws configure --profile production

# Create AnySecret profile using AWS profile
anysecret config profile-create prod --provider aws --aws-profile production
```

#### Option 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID="your_key"
export AWS_SECRET_ACCESS_KEY="your_secret" 
export AWS_DEFAULT_REGION="us-east-1"

anysecret config profile-create prod --provider aws
```

#### Option 3: IAM Roles (EC2/ECS/Lambda)
```bash
# No configuration needed - auto-detected
anysecret config profile-create prod --provider aws
# Uses instance/task role automatically
```

### Required Permissions

Create an IAM policy with minimum required permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:CreateSecret", 
        "secretsmanager:UpdateSecret",
        "secretsmanager:DeleteSecret",
        "secretsmanager:ListSecrets"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject", 
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-anysecret-bucket",
        "arn:aws:s3:::your-anysecret-bucket/*"
      ]
    }
  ]
}
```

### Configuration Options

```bash
# Specify region
anysecret config profile-create prod --provider aws --region us-west-2

# Use Parameter Store instead of S3 for parameters
anysecret config profile-create prod --provider aws --parameter-store

# Custom S3 bucket for parameters
anysecret config profile-create prod --provider aws --s3-bucket my-config-bucket
```

---

## 🌐 Google Cloud Setup

### Prerequisites

1. GCP project with billing enabled
2. `gcloud` CLI configured: `gcloud init`
3. Required APIs enabled:
   ```bash
   gcloud services enable secretmanager.googleapis.com
   gcloud services enable storage.googleapis.com
   ```

### Quick Setup

```bash
# Authenticate with GCP
gcloud auth application-default login

# Create GCP profile (auto-detects project)
anysecret config profile-create gcp-prod --provider gcp

# Test connection
anysecret providers health
```

### Authentication Methods

#### Option 1: Application Default Credentials (Recommended)
```bash
gcloud auth application-default login
anysecret config profile-create prod --provider gcp
```

#### Option 2: Service Account Key
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"
anysecret config profile-create prod --provider gcp
```

#### Option 3: Specific Project
```bash
anysecret config profile-create prod --provider gcp --project my-project-id
```

### Required IAM Roles

Grant these roles to your service account or user:

```bash
# For Secret Manager
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:your-email@company.com" \
  --role="roles/secretmanager.admin"

# For Cloud Storage (parameters)  
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:your-email@company.com" \
  --role="roles/storage.objectAdmin"

# Create bucket for parameters
gsutil mb gs://my-anysecret-config-bucket
```

### Configuration Options

```bash
# Specify project and region
anysecret config profile-create prod --provider gcp \
  --project my-project \
  --region us-central1

# Custom storage bucket
anysecret config profile-create prod --provider gcp \
  --storage-bucket my-custom-bucket
```

---

## 🔷 Azure Setup

### Prerequisites

1. Azure subscription
2. Azure CLI configured: `az login`
3. Resource group and Key Vault created

### Quick Setup

```bash
# Authenticate with Azure
az login

# Create Azure profile
anysecret config profile-create azure-prod --provider azure \
  --key-vault my-keyvault \
  --resource-group my-rg

# Test connection
anysecret providers health
```

### Authentication Methods

#### Option 1: Azure CLI (Interactive)
```bash
az login
anysecret config profile-create prod --provider azure --key-vault my-vault
```

#### Option 2: Service Principal
```bash
export AZURE_CLIENT_ID="client-id"
export AZURE_CLIENT_SECRET="client-secret" 
export AZURE_TENANT_ID="tenant-id"

anysecret config profile-create prod --provider azure --key-vault my-vault
```

#### Option 3: Managed Identity (Azure VMs)
```bash
# No configuration needed in Azure environment
anysecret config profile-create prod --provider azure --key-vault my-vault
```

### Azure Resource Setup

```bash
# Create resource group
az group create --name anysecret-rg --location eastus

# Create Key Vault for secrets
az keyvault create \
  --name my-anysecret-vault \
  --resource-group anysecret-rg \
  --location eastus

# Create Storage Account for parameters
az storage account create \
  --name myanysecretstore \
  --resource-group anysecret-rg \
  --location eastus \
  --sku Standard_LRS
```

### Required Permissions

```bash
# Grant Key Vault access
az keyvault set-policy \
  --name my-anysecret-vault \
  --upn your-email@company.com \
  --secret-permissions get set delete list

# Grant Storage access
az role assignment create \
  --assignee your-email@company.com \
  --role "Storage Blob Data Contributor" \
  --scope "/subscriptions/SUBSCRIPTION_ID/resourceGroups/anysecret-rg"
```

---

## ☸️ Kubernetes Setup

### Prerequisites

1. Kubernetes cluster with `kubectl` access
2. Appropriate RBAC permissions
3. Namespace created for AnySecret

### Setup

```bash
# Check cluster access
kubectl get nodes

# Create namespace
kubectl create namespace anysecret

# Create Kubernetes profile
anysecret config profile-create k8s-prod --provider kubernetes \
  --namespace anysecret

# Test connection
anysecret providers health
```

### RBAC Configuration

```yaml
# anysecret-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: anysecret
  namespace: anysecret
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: anysecret
  name: anysecret-role
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list", "create", "update", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: anysecret-binding
  namespace: anysecret
subjects:
- kind: ServiceAccount
  name: anysecret
  namespace: anysecret
roleRef:
  kind: Role
  name: anysecret-role
  apiGroup: rbac.authorization.k8s.io
```

```bash
kubectl apply -f anysecret-rbac.yaml
```

### Configuration Options

```bash
# Use custom kubeconfig
anysecret config profile-create k8s --provider kubernetes \
  --kubeconfig ./my-cluster-config

# Different namespace
anysecret config profile-create k8s --provider kubernetes \
  --namespace my-app-namespace

# Specific secret/configmap names
anysecret config profile-create k8s --provider kubernetes \
  --secret-name app-secrets \
  --configmap-name app-config
```

---

## 🏗️ HashiCorp Vault Setup

### Prerequisites

1. Vault server running and accessible
2. Vault CLI installed: Download from vault.io
3. Appropriate authentication configured

### Setup

```bash
# Set Vault address
export VAULT_ADDR="https://vault.company.com"

# Authenticate (multiple methods available)
vault auth -method=userpass username=myuser

# Create Vault profile
anysecret config profile-create vault-prod --provider vault \
  --vault-url $VAULT_ADDR \
  --vault-path secret/

# Test connection
anysecret providers health
```

### Authentication Methods

#### Option 1: Token Authentication
```bash
export VAULT_TOKEN="your-vault-token"
anysecret config profile-create vault --provider vault
```

#### Option 2: Username/Password
```bash
anysecret config profile-create vault --provider vault \
  --vault-auth userpass \
  --vault-username myuser
# Will prompt for password
```

#### Option 3: AWS IAM Authentication
```bash
anysecret config profile-create vault --provider vault \
  --vault-auth aws \
  --vault-role my-vault-role
```

---

## 🔧 Profile Management

### List and Switch Profiles

```bash
# List all profiles
anysecret config profile-list

# Switch active profile
anysecret config profile-use production

# Show current profile info
anysecret info
```

### Profile Export/Import

```bash
# Export for CI/CD
anysecret config profile-export production --base64 > prod.txt

# Import profile
anysecret config profile-import --profile-data "$(cat prod.txt)"

# Encrypt sensitive profiles
anysecret config profile-export production --encrypt > prod.enc
```

### Profile Configuration Files

Profiles are stored in `~/.anysecret/profiles/`:

```bash
~/.anysecret/
├── config.json          # Global settings
└── profiles/
    ├── dev-local/        # Local file profile
    ├── aws-prod/         # AWS profile  
    └── gcp-staging/      # GCP profile
```

---

## 🔍 Troubleshooting

### Check Provider Health

```bash
# Test all providers
anysecret providers health

# Detailed status
anysecret status

# Debug connection issues
ANYSECRET_DEBUG=true anysecret get test-key
```

### Common Issues

#### AWS Authentication
```bash
# Check AWS credentials
aws sts get-caller-identity

# Test specific profile
aws sts get-caller-identity --profile production

# Check regions
aws ec2 describe-regions --output table
```

#### GCP Authentication  
```bash
# Check application default credentials
gcloud auth application-default print-access-token

# List active projects
gcloud projects list

# Check enabled APIs
gcloud services list --enabled
```

#### Azure Authentication
```bash
# Check current account
az account show

# List subscriptions
az account list

# Test Key Vault access
az keyvault secret list --vault-name my-vault
```

#### Kubernetes Access
```bash
# Check cluster connection
kubectl cluster-info

# Check permissions
kubectl auth can-i create secrets --namespace anysecret
kubectl auth can-i create configmaps --namespace anysecret
```

### Debug Mode

```bash
# Enable debug logging
export ANYSECRET_DEBUG=true
anysecret providers health

# Check provider-specific issues
anysecret config validate
```

---

## 🚀 Multi-Provider Setup

### Hybrid Approach

```bash
# Development: Local files
anysecret config profile-create dev

# Staging: Cloud with fallback
anysecret config profile-create staging --provider gcp

# Production: Multi-cloud redundancy
anysecret config profile-create prod-primary --provider gcp
anysecret config profile-create prod-backup --provider aws
```

### Cost Optimization

```bash
# Check provider costs
anysecret list --format json | jq '
  .summary | {
    secrets_monthly: (.secrets * 0.40),
    parameters_monthly: (.parameters * 0.01),
    total_monthly: (.secrets * 0.40 + .parameters * 0.01)
  }
'

# Compare with traditional approach
echo "Traditional cost: $(anysecret list --format json | jq -r '(.summary.secrets + .summary.parameters) * 0.40')"
```

---

## 📚 Next Steps

After setting up your providers:

- **[Quick Start](quickstart.md)** - Start using AnySecret
- **[Best Practices](best-practices.md)** - Production patterns  
- **[Migration Guide](migration.md)** - Move between providers
- **[CLI Reference](cli.md)** - Complete command documentation

---

*Provider setup is a one-time task. Once configured, AnySecret handles all the complexity for you.*
# Provider Setup Guide

Complete setup instructions for all supported cloud providers and storage backends.

## 🎯 Overview

AnySecret.io supports multiple providers for both **secrets** (sensitive data) and **parameters** (configuration data). This guide shows you how to configure each provider with authentication, permissions, and best practices.

## 📋 Provider Matrix

| Provider | Secrets Storage | Parameters Storage | Auto-Detection | Production Ready |
|----------|----------------|-------------------|----------------|------------------|
| **AWS** | Secrets Manager | Parameter Store | ✅ | ✅ |
| **Google Cloud** | Secret Manager | Config Connector | ✅ | ✅ |
| **Microsoft Azure** | Key Vault | App Configuration | ✅ | ✅ |
| **Kubernetes** | Secrets | ConfigMaps | ✅ | ✅ |
| **HashiCorp Vault** | KV Store | KV Store | ✅ | ✅ |
| **File-Based** | Encrypted Files | JSON/YAML/ENV | ✅ | ⚠️ |

---

## ☁️ AWS Setup

### Prerequisites

1. AWS Account with appropriate permissions
2. AWS CLI configured or IAM roles set up
3. Python packages: `pip install anysecret-io[aws]`

### Authentication Methods

#### Option 1: IAM Roles (Recommended for EC2/ECS/Lambda)

```python
# Auto-detected in AWS environments
from anysecret import get_config_manager

# No configuration needed - uses instance/task role
config = await get_config_manager()
```

#### Option 2: AWS Profiles

```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.AWS,
    secret_config={
        "region": "us-east-1",
        "profile": "production"  # AWS CLI profile
    },
    parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
    parameter_config={
        "region": "us-east-1",
        "profile": "production"
    }
)

manager = await get_config_manager(config=config)
```

#### Option 3: Access Keys (Development Only)

```bash
# Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

### Required IAM Permissions

#### For AWS Secrets Manager:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "secretsmanager:ListSecrets",
                "secretsmanager:DescribeSecret"
            ],
            "Resource": "*"
        }
    ]
}
```

#### For AWS Parameter Store:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:GetParameters",
                "ssm:GetParametersByPath",
                "ssm:DescribeParameters"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": "*"
        }
    ]
}
```

### Setting Up Secrets & Parameters

#### Create secrets in AWS Secrets Manager:
```bash
# Using AWS CLI
aws secretsmanager create-secret \
    --name "prod/database/password" \
    --description "Production database password" \
    --secret-string "mysecretpassword123"

aws secretsmanager create-secret \
    --name "prod/api/stripe-key" \
    --secret-string "sk_live_abc123..."
```

#### Create parameters in Parameter Store:
```bash
# Standard parameters
aws ssm put-parameter \
    --name "/prod/database/host" \
    --value "db.example.com" \
    --type "String"

# Encrypted parameters
aws ssm put-parameter \
    --name "/prod/database/connection-string" \
    --value "postgresql://user:pass@host:5432/db" \
    --type "SecureString"
```

### Configuration Examples

#### Basic AWS Setup:
```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.AWS,
    secret_config={
        "region": "us-east-1"
    },
    parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
    parameter_config={
        "region": "us-east-1",
        "path_prefix": "/prod/",  # Optional: only load parameters with this prefix
        "decrypt": True  # Decrypt SecureString parameters
    }
)

manager = await get_config_manager(config=config)

# Usage
db_password = await manager.get_secret("prod/database/password")
db_host = await manager.get_parameter("/prod/database/host")
```

#### Multi-Region Setup:
```python
config = ConfigManagerConfig(
    # Primary region
    secret_manager_type=ManagerType.AWS,
    secret_config={"region": "us-east-1"},
    
    # Fallback region
    secret_fallback_type=ManagerType.AWS,
    secret_fallback_config={"region": "us-west-2"}
)
```

---

## 🚀 Google Cloud Setup

### Prerequisites

1. Google Cloud Project with APIs enabled
2. Service account or Application Default Credentials
3. Python packages: `pip install anysecret-io[gcp]`

### Enable Required APIs

```bash
# Enable Secret Manager API
gcloud services enable secretmanager.googleapis.com

# Enable Resource Manager API (for Config Connector)
gcloud services enable cloudresourcemanager.googleapis.com
```

### Authentication Methods

#### Option 1: Service Account Key (Development)

```bash
# Create service account
gcloud iam service-accounts create anysecret-service \
    --description="AnySecret.io service account" \
    --display-name="AnySecret Service Account"

# Create and download key
gcloud iam service-accounts keys create ~/anysecret-key.json \
    --iam-account=anysecret-service@PROJECT_ID.iam.gserviceaccount.com

# Set environment variable
export GOOGLE_APPLICATION_CREDENTIALS=~/anysecret-key.json
```

#### Option 2: Application Default Credentials (Recommended)

```bash
# For local development
gcloud auth application-default login

# For production (automatically detected in GCP environments)
# No configuration needed in Cloud Run, GKE, Compute Engine
```

#### Option 3: Workload Identity (GKE)

```bash
# Create Kubernetes service account
kubectl create serviceaccount anysecret-ksa

# Bind to Google service account
gcloud iam service-accounts add-iam-policy-binding \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/anysecret-ksa]" \
    anysecret-service@PROJECT_ID.iam.gserviceaccount.com

# Annotate Kubernetes service account
kubectl annotate serviceaccount anysecret-ksa \
    iam.gke.io/gcp-service-account=anysecret-service@PROJECT_ID.iam.gserviceaccount.com
```

### Required IAM Roles

```bash
# For Secret Manager
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:anysecret-service@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

# For creating/managing secrets (optional)
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:anysecret-service@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.admin"
```

### Setting Up Secrets & Parameters

#### Create secrets in Secret Manager:
```bash
# Create secrets
echo -n "mysecretpassword123" | gcloud secrets create prod-database-password --data-file=-
echo -n "sk_live_abc123..." | gcloud secrets create prod-stripe-key --data-file=-

# Create secret with labels
gcloud secrets create prod-jwt-secret \
    --labels=env=production,app=myapp \
    --data-file=jwt-secret.txt
```

#### Create parameters using Config Connector (Kubernetes):
```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  database_host: "db.example.com"
  api_timeout: "30"
  log_level: "info"
  max_retries: "5"
```

### Configuration Examples

#### Basic GCP Setup:
```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.GCP,
    secret_config={
        "project_id": "my-project-123",
        "location": "us-central1"  # Optional: for regional secrets
    },
    parameter_manager_type=ManagerType.KUBERNETES_CONFIGMAP,
    parameter_config={
        "namespace": "default",
        "configmap_name": "app-config"
    }
)

manager = await get_config_manager(config=config)

# Usage
db_password = await manager.get_secret("prod-database-password")
db_host = await manager.get_parameter("database_host")
```

#### Custom Credentials:
```python
config = ConfigManagerConfig(
    secret_manager_type=ManagerType.GCP,
    secret_config={
        "project_id": "my-project-123",
        "credentials_path": "/path/to/service-account.json"
    }
)
```

---

## 🌐 Microsoft Azure Setup

### Prerequisites

1. Azure subscription with Key Vault and App Configuration services
2. Service principal or managed identity
3. Python packages: `pip install anysecret-io[azure]`

### Authentication Methods

#### Option 1: Service Principal (Development)

```bash
# Create service principal
az ad sp create-for-rbac --name anysecret-sp --role contributor

# Output:
# {
#   "appId": "your-client-id",
#   "password": "your-client-secret",
#   "tenant": "your-tenant-id"
# }

# Set environment variables
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-client-secret
export AZURE_TENANT_ID=your-tenant-id
```

#### Option 2: Managed Identity (Production)

```python
# Automatically detected in Azure environments
from anysecret import get_config_manager

# No configuration needed - uses system/user-assigned managed identity
config = await get_config_manager()
```

### Setting Up Key Vault

#### Create Key Vault:
```bash
# Create resource group
az group create --name anysecret-rg --location eastus

# Create Key Vault
az keyvault create \
    --name my-anysecret-vault \
    --resource-group anysecret-rg \
    --location eastus \
    --enabled-for-disk-encryption true
```

#### Grant Permissions:
```bash
# For service principal
az keyvault set-policy \
    --name my-anysecret-vault \
    --spn your-client-id \
    --secret-permissions get list

# For managed identity
az keyvault set-policy \
    --name my-anysecret-vault \
    --object-id managed-identity-object-id \
    --secret-permissions get list
```

#### Create secrets:
```bash
# Create secrets in Key Vault
az keyvault secret set \
    --vault-name my-anysecret-vault \
    --name "prod-database-password" \
    --value "mysecretpassword123"

az keyvault secret set \
    --vault-name my-anysecret-vault \
    --name "prod-stripe-key" \
    --value "sk_live_abc123..."
```

### Setting Up App Configuration

#### Create App Configuration:
```bash
# Create App Configuration store
az appconfig create \
    --name my-app-config \
    --resource-group anysecret-rg \
    --location eastus \
    --sku standard
```

#### Grant Permissions:
```bash
# Get connection string
CONNECTION_STRING=$(az appconfig credential list \
    --name my-app-config \
    --resource-group anysecret-rg \
    --query "[?name=='Primary'].connectionString" \
    --output tsv)
```

#### Create parameters:
```bash
# Set configuration values
az appconfig kv set \
    --name my-app-config \
    --key "database_host" \
    --value "db.example.com" \
    --label "Production"

az appconfig kv set \
    --name my-app-config \
    --key "api_timeout" \
    --value "30" \
    --label "Production"
```

### Configuration Examples

#### Basic Azure Setup:
```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.AZURE,
    secret_config={
        "vault_name": "my-anysecret-vault",
        "tenant_id": "your-tenant-id",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret"
    },
    parameter_manager_type=ManagerType.AZURE_APP_CONFIG,
    parameter_config={
        "connection_string": CONNECTION_STRING,
        "label": "Production",
        "key_filter": "database_*,api_*"  # Optional: filter keys
    }
)

manager = await get_config_manager(config=config)

# Usage
db_password = await manager.get_secret("prod-database-password")
db_host = await manager.get_parameter("database_host")
```

#### Managed Identity Setup:
```python
config = ConfigManagerConfig(
    secret_manager_type=ManagerType.AZURE,
    secret_config={
        "vault_name": "my-anysecret-vault"
        # No credentials needed - uses managed identity
    }
)
```

---

## ⚓ Kubernetes Setup

### Prerequisites

1. Kubernetes cluster access
2. kubectl configured
3. Python packages: `pip install anysecret-io[k8s]`

### Authentication Methods

#### Option 1: Service Account (Recommended)

```yaml
# service-account.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: anysecret-service-account
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets", "configmaps"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-secrets
  namespace: default
subjects:
- kind: ServiceAccount
  name: anysecret-service-account
  namespace: default
roleRef:
  kind: Role
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io
```

#### Option 2: External kubeconfig

```python
config = ConfigManagerConfig(
    secret_manager_type=ManagerType.KUBERNETES,
    secret_config={
        "kubeconfig_path": "~/.kube/config",
        "context": "production-cluster"
    }
)
```

### Setting Up Secrets & ConfigMaps

#### Create Kubernetes Secrets:
```bash
# Create secret from literals
kubectl create secret generic app-secrets \
    --from-literal=database-password=mysecretpassword123 \
    --from-literal=stripe-key=sk_live_abc123... \
    --namespace=default

# Create secret from files
kubectl create secret generic app-certs \
    --from-file=tls.crt=server.crt \
    --from-file=tls.key=server.key
```

#### Create ConfigMaps:
```bash
# Create configmap from literals
kubectl create configmap app-config \
    --from-literal=database-host=db.example.com \
    --from-literal=api-timeout=30 \
    --from-literal=log-level=info

# Create from file
kubectl create configmap app-config \
    --from-env-file=app.properties
```

#### Using YAML manifests:
```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: default
type: Opaque
data:
  database-password: bXlzZWNyZXRwYXNzd29yZDEyMw==  # base64 encoded
  stripe-key: c2tfbGl2ZV9hYmMxMjMuLi4=

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: default
data:
  database-host: "db.example.com"
  api-timeout: "30"
  log-level: "info"
  max-retries: "5"
```

### Configuration Examples

#### Basic Kubernetes Setup:
```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.KUBERNETES,
    secret_config={
        "namespace": "default",
        "secret_name": "app-secrets"  # Optional: specific secret name
    },
    parameter_manager_type=ManagerType.KUBERNETES_CONFIGMAP,
    parameter_config={
        "namespace": "default", 
        "configmap_name": "app-config"  # Optional: specific configmap name
    }
)

manager = await get_config_manager(config=config)

# Usage
db_password = await manager.get_secret("database-password")
db_host = await manager.get_parameter("database-host")
```

#### Multi-namespace Setup:
```python
config = ConfigManagerConfig(
    secret_manager_type=ManagerType.KUBERNETES,
    secret_config={
        "namespace": "production",
        "secret_name": "prod-secrets"
    },
    parameter_manager_type=ManagerType.KUBERNETES_CONFIGMAP,
    parameter_config={
        "namespace": "production",
        "configmap_name": "prod-config"
    }
)
```

---

## 🔐 HashiCorp Vault Setup

### Prerequisites

1. HashiCorp Vault server running
2. Authentication method configured
3. Python packages: `pip install anysecret-io[vault]`

### Authentication Methods

#### Option 1: Token Authentication

```python
import os
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

os.environ['VAULT_TOKEN'] = 'your-vault-token'

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.VAULT,
    secret_config={
        "url": "https://vault.example.com:8200",
        "mount_point": "secret",  # KV v2 mount point
        "path_prefix": "myapp/"   # Optional path prefix
    },
    parameter_manager_type=ManagerType.VAULT,
    parameter_config={
        "url": "https://vault.example.com:8200", 
        "mount_point": "config",
        "path_prefix": "myapp/"
    }
)
```

#### Option 2: AppRole Authentication

```python
config = ConfigManagerConfig(
    secret_manager_type=ManagerType.VAULT,
    secret_config={
        "url": "https://vault.example.com:8200",
        "auth_method": "approle",
        "role_id": "your-role-id",
        "secret_id": "your-secret-id",
        "mount_point": "secret"
    }
)
```

#### Option 3: Kubernetes Authentication

```python
config = ConfigManagerConfig(
    secret_manager_type=ManagerType.VAULT,
    secret_config={
        "url": "https://vault.example.com:8200",
        "auth_method": "kubernetes",
        "role": "myapp-role",
        "jwt_path": "/var/run/secrets/kubernetes.io/serviceaccount/token"
    }
)
```

### Setting Up Vault

#### Enable KV v2 secret engine:
```bash
# Enable secrets engine
vault secrets enable -path=secret kv-v2
vault secrets enable -path=config kv-v2

# Create policies
vault policy write myapp-policy - <<EOF
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}
path "config/data/myapp/*" {
  capabilities = ["read", "list"]
}
EOF
```

#### Create secrets and parameters:
```bash
# Create secrets
vault kv put secret/myapp/database password=mysecretpassword123
vault kv put secret/myapp/api stripe-key=sk_live_abc123...

# Create parameters
vault kv put config/myapp/database host=db.example.com port=5432
vault kv put config/myapp/api timeout=30 max-retries=5
```

#### Set up AppRole authentication:
```bash
# Enable AppRole auth
vault auth enable approle

# Create AppRole
vault write auth/approle/role/myapp-role \
    token_policies="myapp-policy" \
    token_ttl=1h \
    token_max_ttl=4h

# Get role ID and secret ID
vault read auth/approle/role/myapp-role/role-id
vault write -f auth/approle/role/myapp-role/secret-id
```

### Configuration Examples

#### Basic Vault Setup:
```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.VAULT,
    secret_config={
        "url": "https://vault.example.com:8200",
        "token": "your-vault-token",
        "mount_point": "secret",
        "path_prefix": "myapp/",
        "verify": True  # SSL verification
    },
    parameter_manager_type=ManagerType.VAULT,
    parameter_config={
        "url": "https://vault.example.com:8200",
        "token": "your-vault-token", 
        "mount_point": "config",
        "path_prefix": "myapp/"
    }
)

manager = await get_config_manager(config=config)

# Usage
db_password = await manager.get_secret("database/password")  # From secret/myapp/database
db_host = await manager.get_parameter("database/host")       # From config/myapp/database
```

---

## 📁 File-Based Providers

### Prerequisites

Python packages: `pip install anysecret-io` (included in base)

### Encrypted Files

#### Create encrypted secret file:
```bash
# Create secrets file
cat > secrets.json << 'EOF'
{
  "database_password": "mysecretpassword123",
  "stripe_secret_key": "sk_live_abc123...",
  "jwt_secret": "your-jwt-secret"
}
EOF

# Encrypt with AnySecret CLI
anysecret encrypt secrets.json secrets.json.enc --password mypassword

# Remove plaintext file
rm secrets.json
```

#### Configuration:
```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    secret_manager_type=ManagerType.ENCRYPTED_FILE,
    secret_config={
        "file_path": "/etc/secrets/secrets.json.enc",
        "password": "mypassword",  # Or use ANYSECRET_PASSWORD env var
        "format": "json"  # json, yaml, or env
    },
    parameter_manager_type=ManagerType.JSON_FILE,
    parameter_config={
        "file_path": "/etc/config/parameters.json"
    }
)
```

### Environment Files (.env)

#### Create .env file:
```bash
cat > .env << 'EOF'
# Secrets (auto-detected)
DATABASE_PASSWORD=mysecretpassword123
STRIPE_SECRET_KEY=sk_live_abc123...
JWT_SECRET=your-jwt-secret

# Parameters (auto-detected)
DATABASE_HOST=db.example.com
API_TIMEOUT=30
LOG_LEVEL=info
MAX_RETRIES=5
EOF
```

#### Configuration:
```python
config = ConfigManagerConfig(
    secret_manager_type=ManagerType.ENV_FILE,
    secret_config={
        "file_path": ".env"
    },
    parameter_manager_type=ManagerType.ENV_FILE,
    parameter_config={
        "file_path": ".env"
    }
)

# Or use auto-detection (will find .env automatically)
manager = await get_config_manager()
```

### JSON/YAML Files

#### JSON configuration:
```json
// parameters.json
{
  "database": {
    "host": "db.example.com",
    "port": 5432,
    "pool_size": 10
  },
  "api": {
    "timeout": 30,
    "max_retries": 5,
    "base_url": "https://api.example.com"
  },
  "features": {
    "feature_x_enabled": true,
    "feature_y_enabled": false
  }
}
```

#### YAML configuration:
```yaml
# parameters.yaml
database:
  host: db.example.com
  port: 5432
  pool_size: 10

api:
  timeout: 30
  max_retries: 5
  base_url: "https://api.example.com"

features:
  feature_x_enabled: true
  feature_y_enabled: false
```

#### Configuration:
```python
config = ConfigManagerConfig(
    parameter_manager_type=ManagerType.JSON_FILE,
    parameter_config={
        "file_path": "/etc/config/parameters.json",
        "key_separator": "."  # Access nested keys with dots: "database.host"
    }
)

# Or YAML
config = ConfigManagerConfig(
    parameter_manager_type=ManagerType.YAML_FILE,
    parameter_config={
        "file_path": "/etc/config/parameters.yaml",
        "key_separator": "."
    }
)

manager = await get_config_manager(config=config)

# Access nested values
db_host = await manager.get_parameter("database.host")
timeout = await manager.get_parameter("api.timeout")
```

---

## 🔧 Multi-Provider Examples

### Hybrid Cloud Setup

```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    # Secrets in AWS (primary)
    secret_manager_type=ManagerType.AWS,
    secret_config={"region": "us-east-1"},
    
    # Parameters in GCP (different cloud)
    parameter_manager_type=ManagerType.KUBERNETES_CONFIGMAP,
    parameter_config={
        "namespace": "default",
        "configmap_name": "app-config"
    },
    
    # Fallbacks
    secret_fallback_type=ManagerType.ENCRYPTED_FILE,
    secret_fallback_config={
        "file_path": "/etc/secrets/backup.json.enc",
        "password": "backup-password"
    },
    
    parameter_fallback_type=ManagerType.ENV_FILE,
    parameter_fallback_config={
        "file_path": "/etc/config/.env"
    }
)

manager = await get_config_manager(config=config)
```

### Development vs Production

```python
import os
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

def get_environment_config():
    if os.getenv("ENV") == "production":
        return ConfigManagerConfig(
            # Production: Cloud-native
            secret_manager_type=ManagerType.AWS,
            secret_config={"region": "us-east-1"},
            parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
            parameter_config={"region": "us-east-1"}
        )
    else:
        # Development: File-based
        return ConfigManagerConfig(
            secret_manager_type=ManagerType.ENV_FILE,
            secret_config={"file_path": ".env"},
            parameter_manager_type=ManagerType.ENV_FILE,
            parameter_config={"file_path": ".env"}
        )

config = get_environment_config()
manager = await get_config_manager(config=config)
```

### Multi-Region High Availability

```python
config = ConfigManagerConfig(
    # Primary region
    secret_manager_type=ManagerType.AWS,
    secret_config={"region": "us-east-1"},
    parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
    parameter_config={"region": "us-east-1"},
    
    # Secondary region fallback
    secret_fallback_type=ManagerType.AWS,
    secret_fallback_config={"region": "us-west-2"},
    parameter_fallback_type=ManagerType.AWS_PARAMETER_STORE,
    parameter_fallback_config={"region": "us-west-2"}
)
```

---

## 🔍 Auto-Detection Logic

AnySecret.io automatically detects your environment and configures appropriate providers:

### Detection Priority

1. **Environment Variables** - Explicit provider configuration
2. **Cloud Metadata Services** - AWS IMDS, GCP metadata, Azure IMDS
3. **Kubernetes Service Account** - Mounted tokens and config
4. **Local Configuration Files** - kubeconfig, AWS config, gcloud config
5. **File-based Fallback** - .env files, JSON/YAML configs

### Environment Variable Override

```bash
# Force specific providers
export SECRET_MANAGER_TYPE=aws
export PARAMETER_MANAGER_TYPE=aws_parameter_store
export AWS_REGION=us-west-2

# Or use unified provider
export CONFIG_MANAGER_TYPE=gcp
export GCP_PROJECT_ID=my-project

# Disable auto-detection
export ANYSECRET_DISABLE_AUTO_DETECTION=true
```

---

## 🚨 Troubleshooting

### Common Issues

#### Provider Not Found
```python
# Check what was detected
from anysecret import get_config_manager

config = await get_config_manager()
print(f"Provider: {config.provider_name}")
print(f"Region: {config.region}")
```

#### Authentication Failures
```bash
# Enable debug logging
export ANYSECRET_LOG_LEVEL=DEBUG

# Check provider-specific auth
aws sts get-caller-identity  # AWS
gcloud auth list            # GCP
az account show            # Azure
```

#### Permission Errors
```bash
# Test permissions
anysecret validate
anysecret list --secrets-only
anysecret list --parameters-only
```

### Debug Commands

```bash
# Check configuration
anysecret info

# List available secrets/parameters
anysecret list

# Test connectivity
anysecret get test-key --default "test-value"

# Validate permissions
anysecret validate
```

---

## 📞 Support

For provider-specific issues:

- **AWS**: [AWS Support](https://aws.amazon.com/support/)
- **Google Cloud**: [GCP Support](https://cloud.google.com/support)
- **Azure**: [Azure Support](https://azure.microsoft.com/support/)
- **Kubernetes**: [Kubernetes Documentation](https://kubernetes.io/docs/)
- **Vault**: [HashiCorp Support](https://support.hashicorp.com/)

For AnySecret.io issues:
- **GitHub Issues**: [anysecret-io/anysecret-lib/issues](https://github.com/anysecret-io/anysecret-lib/issues)
- **Discord**: [Join our community](https://discord.gg/anysecret)
- **Email**: support@anysecret.io

---

*This guide covers all major cloud providers and deployment scenarios. For advanced configurations and custom providers, see our [API Reference](api.md).*
# Quick Start Guide

Get AnySecret.io running in under 5 minutes. This guide walks you through installation, basic setup, and your first secret retrieval.

## 🎯 Prerequisites

- Python 3.8+ 
- Access to at least one cloud provider (AWS, GCP, Azure) or local development environment
- Basic familiarity with async/await in Python

## 📦 Installation

### Basic Installation

```bash
# Install the core library
pip install anysecret-io
```

### Provider-Specific Installation

Choose the providers you need:

```bash
# AWS (Secrets Manager + Parameter Store)
pip install anysecret-io[aws]

# Google Cloud (Secret Manager + Config)
pip install anysecret-io[gcp]

# Microsoft Azure (Key Vault + App Config)
pip install anysecret-io[azure]

# Kubernetes (Secrets + ConfigMaps)
pip install anysecret-io[k8s]

# HashiCorp Vault
pip install anysecret-io[vault]

# Everything (recommended for production)
pip install anysecret-io[all]
```

## ⚡ 5-Minute Setup

### Option 1: File-Based (Development)

Perfect for local development and testing:

```bash
# Create a .env file
cat > .env << 'EOF'
DATABASE_PASSWORD=mysecret123
DATABASE_HOST=localhost
API_TIMEOUT=30
STRIPE_SECRET_KEY=sk_test_abc123
REDIS_URL=redis://localhost:6379
EOF
```

```python
import asyncio
from anysecret import get_config_manager

async def main():
    # Auto-detects .env file
    config = await get_config_manager()
    
    # Get secrets (secure values)
    db_password = await config.get_secret("DATABASE_PASSWORD")
    stripe_key = await config.get_secret("STRIPE_SECRET_KEY")
    
    # Get parameters (config values)
    db_host = await config.get_parameter("DATABASE_HOST")
    timeout = await config.get_parameter("API_TIMEOUT", default=30)
    
    print(f"DB Host: {db_host}")
    print(f"Timeout: {timeout}")
    print("Secrets loaded successfully! 🎉")

asyncio.run(main())
```

### Option 2: Cloud-Native (AWS)

For AWS environments:

```python
import asyncio
from anysecret import get_config_manager
import os

async def main():
    # Set environment variables
    os.environ['SECRET_MANAGER_TYPE'] = 'aws'
    os.environ['AWS_REGION'] = 'us-east-1'
    
    # Auto-configures for AWS
    config = await get_config_manager()
    
    # Gets from AWS Secrets Manager
    db_password = await config.get_secret("prod/database/password")
    
    # Gets from AWS Parameter Store  
    db_host = await config.get_parameter("prod/database/host")
    
    print("AWS secrets loaded! ✅")

asyncio.run(main())
```

### Option 3: Auto-Detection (Recommended)

Let AnySecret.io detect your environment:

```python
import asyncio
from anysecret import get_config_manager

async def main():
    # Detects: AWS, GCP, Azure, K8s, or falls back to files
    config = await get_config_manager()
    
    # Works the same everywhere!
    api_key = await config.get("API_KEY")
    timeout = await config.get("TIMEOUT", default=30)
    
    print(f"Running in: {config.provider_name}")
    print("Configuration loaded! 🚀")

asyncio.run(main())
```

## 🔧 CLI Quick Start

AnySecret.io includes powerful CLI tools for DevOps workflows:

### Basic CLI Usage

```bash
# Get a secret
anysecret get DATABASE_PASSWORD

# Get with default value
anysecret get API_TIMEOUT --default 30

# List all available secrets/parameters
anysecret list

# Get multiple by prefix
anysecret get-prefix "database/"

# Export for shell
export DB_PASS=$(anysecret get DATABASE_PASSWORD)
```

### DevOps Integration

```bash
# For Docker
docker run -e DB_PASS=$(anysecret get db/password) myapp

# For Kubernetes
anysecret get database/password | base64 | kubectl create secret generic db-secret --from-literal=password=-

# For Terraform (JSON output)
anysecret get-all --format json > secrets.json

# For CI/CD pipelines
anysecret get api/key --format shell >> $GITHUB_ENV
```

## 🎭 Environment Detection

AnySecret.io automatically detects your environment:

| Environment | Auto-Detected | Configuration |
|-------------|---------------|---------------|
| **AWS EC2/ECS/Lambda** | ✅ | Uses IAM roles, detects region |
| **Google Cloud Run/GKE** | ✅ | Uses service accounts, detects project |
| **Azure App Service** | ✅ | Uses managed identity |
| **Kubernetes** | ✅ | Uses service accounts, detects namespace |
| **Local Development** | ✅ | Scans for .env files |
| **Docker** | ✅ | Checks for environment variables |

## 🔐 Smart Secret Classification

AnySecret.io automatically determines if values are secrets or parameters:

```python
# These are automatically classified as SECRETS:
DATABASE_PASSWORD=secret123     # → Secure storage
API_KEY=sk_live_abc123         # → Secure storage  
JWT_SECRET=mysecret            # → Secure storage
STRIPE_SECRET_KEY=sk_test_xyz  # → Secure storage

# These are automatically classified as PARAMETERS:
DATABASE_HOST=localhost        # → Config storage
API_TIMEOUT=30                # → Config storage
LOG_LEVEL=info                # → Config storage
FEATURE_FLAG_ENABLED=true     # → Config storage
```

Override when needed:

```python
# Force secret storage
public_token = await config.get_secret("PUBLIC_API_TOKEN", force_secret=True)

# Force parameter storage
pattern = await config.get_parameter("SECRET_PATTERN", force_parameter=True)
```

## 🏗️ Common Patterns

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from anysecret import get_config_manager, ConfigManagerInterface

app = FastAPI()

async def get_config() -> ConfigManagerInterface:
    return await get_config_manager()

@app.startup_event
async def startup():
    # Pre-load configuration
    config = await get_config_manager()
    app.state.config = config

@app.get("/health")
async def health(config: ConfigManagerInterface = Depends(get_config)):
    db_host = await config.get_parameter("DATABASE_HOST")
    return {"status": "healthy", "db_host": db_host}
```

### Django Settings

```python
# settings.py
import asyncio
from anysecret import get_config_manager

# Load configuration at startup
config = asyncio.run(get_config_manager())

# Use in Django settings
SECRET_KEY = asyncio.run(config.get_secret("DJANGO_SECRET_KEY"))
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'HOST': asyncio.run(config.get_parameter("DB_HOST")),
        'PASSWORD': asyncio.run(config.get_secret("DB_PASSWORD")),
    }
}
```

### Error Handling

```python
from anysecret import get_config_manager, SecretNotFoundError

async def robust_config():
    config = await get_config_manager()
    
    try:
        # Try to get required secret
        api_key = await config.get_secret("API_KEY")
    except SecretNotFoundError:
        # Handle missing secret gracefully
        print("API_KEY not found, using development mode")
        api_key = "dev-key"
    
    # Use default for optional parameters
    timeout = await config.get_parameter("TIMEOUT", default=30)
    return api_key, timeout
```

## 🚀 Next Steps

Now that you have AnySecret.io working:

1. **[Provider Setup](providers.md)** - Configure your cloud providers
2. **[Best Practices](best-practices.md)** - Security and performance tips  
3. **[API Reference](api.md)** - Complete API documentation
4. **[Migration Guide](migration.md)** - Switch between providers
5. **[Examples](https://github.com/anysecret-io/examples)** - Real-world use cases

## 🆘 Troubleshooting

### Common Issues

**Problem**: `ImportError: No module named 'anysecret'`
```bash
# Solution: Install the package
pip install anysecret-io
```

**Problem**: `ProviderNotFoundError: No suitable provider found`
```bash
# Solution: Install provider dependencies
pip install anysecret-io[aws]  # or [gcp], [azure], etc.
```

**Problem**: `PermissionDeniedError: Access denied to secret manager`
```bash
# Solution: Check your cloud provider permissions
# AWS: Ensure IAM role has SecretsManager access
# GCP: Ensure service account has Secret Manager access
# Azure: Ensure managed identity has Key Vault access
```

**Problem**: Secrets not found in cloud provider
```python
# Solution: Check your secret naming and location
config = await get_config_manager()
print(f"Provider: {config.provider_name}")
print(f"Region: {config.region}")

# List all available secrets
secrets = await config.list_secrets()
print(f"Available secrets: {secrets}")
```

### Debug Mode

Enable detailed logging:

```python
import logging
from anysecret import get_config_manager

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

config = await get_config_manager()
# Now you'll see detailed provider detection and configuration logs
```

### Getting Help

- 🐛 **Found a bug?** [Open an issue](https://github.com/anysecret-io/anysecret-lib/issues)
- 💬 **Need help?** [Join our Discord](https://discord.gg/anysecret)  
- 📧 **Enterprise support:** support@anysecret.io

---

**🎉 Congratulations!** You now have universal secret management set up. AnySecret.io will automatically adapt to your environment and keep your secrets secure across all cloud providers.

Ready for production? Check out our [Best Practices Guide](best-practices.md) next.
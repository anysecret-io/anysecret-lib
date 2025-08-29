# AnySecret.io

**Universal secret management for cloud-native applications** 🚀

AnySecret.io provides a unified API to securely manage secrets and configuration across all major cloud providers. Write once, deploy anywhere.

## ✨ Key Features

- **🌩️ Multi-Cloud** - AWS, GCP, Azure, Kubernetes, Vault
- **🔄 Auto-Detection** - Automatically detects your environment  
- **🛡️ Smart Classification** - Distinguishes secrets from config
- **⚡ Async-First** - Built for modern Python applications
- **🎯 Zero-Config** - Works out of the box in most environments
- **📦 Lightweight** - Minimal dependencies, maximum performance

## 🚀 Quick Start

Install AnySecret.io:

```bash
pip install anysecret-io[all]
```

Use in your code:

```python
import asyncio
from anysecret import get_config_manager

async def main():
    # Auto-detects your environment (AWS, GCP, Azure, K8s, etc.)
    config = await get_config_manager()
    
    # Get secrets and config values
    api_key = await config.get_secret("API_KEY")
    timeout = await config.get_parameter("TIMEOUT", default=30)
    
    print(f"Running in: {config.provider_name}")

asyncio.run(main())
```

## 🔧 CLI Usage

```bash
# Get secrets from anywhere
anysecret get DATABASE_PASSWORD

# Export for shell usage  
export API_KEY=$(anysecret get API_KEY)

# List all secrets/parameters
anysecret list
```

## 🏗️ Supported Providers

| Provider | Secrets | Parameters | Auto-Detection |
|----------|---------|------------|----------------|
| **AWS** | Secrets Manager | Parameter Store | ✅ |
| **GCP** | Secret Manager | Config | ✅ |
| **Azure** | Key Vault | App Config | ✅ |
| **Kubernetes** | Secrets | ConfigMaps | ✅ |
| **Vault** | KV Store | KV Store | ✅ |
| **Files** | .env files | .env files | ✅ |

## 📚 Documentation

- **[Quick Start Guide](quickstart.md)** - Get up and running in 5 minutes
- **[Provider Setup](providers.md)** - Configure cloud providers  
- **[API Reference](api.md)** - Complete API documentation
- **[Best Practices](best-practices.md)** - Security and performance tips
- **[Examples](examples.md)** - Real-world usage examples
- **[Migration Guide](migration.md)** - Switch between providers

## 🛡️ Security First

- **Automatic encryption** at rest and in transit
- **IAM integration** with all cloud providers
- **Audit logging** for compliance requirements
- **No secret exposure** in logs or error messages
- **Secure defaults** for all configurations

## 💡 Why AnySecret.io?

**Before:**
```python
# Different APIs for each provider
import boto3
from google.cloud import secretmanager
from azure.keyvault.secrets import SecretClient

# Provider-specific configuration
if environment == "aws":
    secrets_client = boto3.client('secretsmanager')
    secret = secrets_client.get_secret_value(SecretId='prod/api/key')['SecretString']
elif environment == "gcp":
    client = secretmanager.SecretManagerServiceClient()
    secret = client.access_secret_version(request={"name": "projects/123/secrets/api-key/versions/latest"}).payload.data.decode("UTF-8")
# ... more provider-specific code
```

**After:**
```python
# Universal API that works everywhere
from anysecret import get_config_manager

config = await get_config_manager()
secret = await config.get_secret("api-key")  # Works on any provider
```

## 🚀 Getting Started

Ready to simplify your secret management? Start with our [Quick Start Guide](quickstart.md) and have AnySecret.io working in under 5 minutes.

---

**Questions?** Join our [Discord community](https://discord.gg/anysecret) or [open an issue](https://github.com/anysecret-io/anysecret-lib/issues) on GitHub.
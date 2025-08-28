# AnySecret.io

[![PyPI version](https://badge.fury.io/py/anysecret-io.svg)](https://badge.fury.io/py/anysecret-io)
[![Python Support](https://img.shields.io/pypi/pyversions/anysecret-io.svg)](https://pypi.org/project/anysecret-io/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Commercial License](https://img.shields.io/badge/Commercial-License%20Available-green.svg)](mailto:licensing@anysecret.io)

Universal configuration and secret manager for Python applications with multi-cloud support. Handles both sensitive secrets and non-sensitive configuration parameters with intelligent auto-classification.

## Features

🚀 **Async-first design** - Built for FastAPI and modern Python frameworks  
🔄 **Auto-detection** - Automatically detects cloud environment and configures itself  
🛡️ **Multi-provider support** - GCP, AWS, Azure, Vault, encrypted files, env files  
📦 **Zero-config deployment** - Works out of the box in most environments  
🔐 **HIPAA-ready** - Encrypted file support for on-premises HIPAA compliance  
⚡ **Caching** - Built-in caching with configurable TTL  
🛠️ **Fallback support** - Primary + backup secret sources  
🔍 **Type hints** - Full type hint support with Pydantic validation  
🧠 **Smart classification** - Auto-detects secrets vs parameters with override support  
🔀 **Dual storage** - Secrets in secure stores, parameters in configuration management  

## Configuration vs Secrets

AnySecret.io intelligently handles both sensitive secrets and non-sensitive configuration:

### What are Secrets?
- Passwords, API keys, tokens, certificates
- Database connection strings with credentials
- OAuth client secrets, JWT signing keys
- Any data that should never appear in logs or version control

### What are Parameters?
- Feature flags, environment names, timeouts
- Public API endpoints, service discovery URLs
- Cache TTLs, retry counts, batch sizes
- Non-sensitive configuration that can be logged

### Auto-Classification
AnySecret.io automatically determines if a value is a secret based on:

```python
# Automatically classified as SECRETS (secure storage):
DATABASE_PASSWORD=secret123
API_KEY=sk-abc123
JWT_SECRET=mysecret
CLIENT_SECRET=oauth-secret
PRIVATE_KEY=-----BEGIN PRIVATE KEY-----

# Automatically classified as PARAMETERS (config storage):
DATABASE_HOST=localhost
API_TIMEOUT=30
FEATURE_FLAG_ENABLED=true
LOG_LEVEL=info
MAX_RETRIES=3
```

### Manual Override
Force classification when auto-detection is wrong:

```python
from anysecret import get_config_manager

config = await get_config_manager()

# Force as secret (even if name doesn't match pattern)
await config.get_secret("PUBLIC_API_ENDPOINT", force_secret=True)

# Force as parameter (even if name looks like secret)
await config.get_parameter("USER_PASSWORD_PATTERN", force_parameter=True)
```

## Quick Start

### Installation

```bash
# Basic installation (file-based only)
pip install anysecret-io

# With Google Cloud support
pip install anysecret-io[gcp]

# With AWS support
pip install anysecret-io[aws]

# With Azure support
pip install anysecret-io[azure]

# With Kubernetes support
pip install anysecret-io[k8s]

# With HashiCorp Vault support
pip install anysecret-io[vault]

# With all cloud providers
pip install anysecret-io[all]
```

### Basic Usage

```python
import asyncio
from anysecret import get_config_manager

async def main():
    # Auto-detects environment and configures itself
    config = await get_config_manager()
    
    # Get secrets (from secure storage)
    db_password = await config.get_secret("DATABASE_PASSWORD")
    api_key = await config.get_secret("STRIPE_SECRET_KEY")
    
    # Get parameters (from config storage)
    api_timeout = await config.get_parameter("API_TIMEOUT_SECONDS", default=30)
    feature_enabled = await config.get_parameter("FEATURE_X_ENABLED", default=False)
    
    # Get either (auto-classified)
    jwt_secret = await config.get("JWT_SECRET")  # Auto → secret storage
    log_level = await config.get("LOG_LEVEL")    # Auto → parameter storage
    
    # Get multiple by prefix
    auth_secrets = await config.get_secrets_by_prefix("auth/")
    app_params = await config.get_parameters_by_prefix("app/")

asyncio.run(main())
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from anysecret import get_config_manager, ConfigManagerInterface

app = FastAPI()

async def get_config() -> ConfigManagerInterface:
    return await get_config_manager()

@app.post("/login")
async def login(config: ConfigManagerInterface = Depends(get_config)):
    # Secrets from secure storage
    jwt_secret = await config.get_secret("JWT_SECRET")
    db_url = await config.get_secret("DATABASE_URL")
    
    # Parameters from config storage
    token_ttl = await config.get_parameter("JWT_EXPIRY_HOURS", default=24)
    max_attempts = await config.get_parameter("MAX_LOGIN_ATTEMPTS", default=5)
    
    # Your login logic here
    return {"status": "success"}
```

## Storage Backends

### Development (File-based)

```bash
# .env file - auto-classified
DATABASE_PASSWORD=secret123        # → Secret storage
DATABASE_HOST=localhost            # → Parameter storage
API_TIMEOUT=30                     # → Parameter storage
STRIPE_SECRET_KEY=sk_test_123      # → Secret storage
```

### Production (Cloud-native)

**Secrets**: Google Secret Manager, AWS Secrets Manager, Azure Key Vault  
**Parameters**: GCP Config Connector, AWS Parameter Store, Azure App Configuration

```python
from anysecret import ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    # Secrets go to secure storage
    secret_manager_type=ManagerType.GCP,
    secret_config={"project_id": "your-project"},
    
    # Parameters go to config storage  
    parameter_manager_type=ManagerType.GCP_CONFIG,
    parameter_config={"project_id": "your-project"},
)
```

## Supported Providers

### Secret Storage
- **Google Cloud Secret Manager** - Secure secret storage
- **AWS Secrets Manager** - Enterprise secret management
- **Azure Key Vault** - Microsoft cloud secrets
- **HashiCorp Vault** - Multi-cloud secret storage
- **Kubernetes Secrets** - Native Kubernetes secret storage
- **Encrypted Files** - On-premises HIPAA compliance

### Parameter Storage  
- **GCP Config Connector** - Google Cloud configuration
- **AWS Parameter Store** - AWS Systems Manager parameters
- **Azure App Configuration** - Microsoft configuration service
- **Kubernetes ConfigMaps** - Native Kubernetes configuration
- **Environment Files** - Simple .env file support
- **JSON/YAML Files** - Structured configuration files

## Auto-Classification Rules

### Secrets (→ Secure Storage)
Names containing: `secret`, `password`, `key`, `token`, `credential`, `private`  
Patterns: `*_SECRET`, `*_PASSWORD`, `*_KEY`, `*_TOKEN`, `JWT_*`, `OAUTH_*`  
Values: Starting with common prefixes (`sk_`, `-----BEGIN`, `AIza`)

### Parameters (→ Config Storage)  
Names containing: `timeout`, `limit`, `count`, `size`, `host`, `port`, `url`, `flag`  
Patterns: `*_ENABLED`, `*_TIMEOUT`, `*_LIMIT`, `*_HOST`, `*_PORT`, `LOG_*`  
Values: Numbers, booleans, public URLs, enum-like values

### Override Examples

```python
# Force secret storage for public-looking name
public_token = await config.get_secret("PUBLIC_API_TOKEN", force_secret=True)

# Force parameter storage for secret-looking name  
pattern = await config.get_parameter("SECRET_VALIDATION_PATTERN", force_parameter=True)

# Custom classification
config.add_secret_pattern("CUSTOM_*_PRIVATE")
config.add_parameter_pattern("CUSTOM_*_CONFIG")
```

## CLI Tools

```bash
# Encrypt secrets file
anysecret encrypt secrets.env secrets.json.enc --password mypassword

# List secrets vs parameters
anysecret list --secrets-only
anysecret list --parameters-only

# Get values
anysecret get-secret database/password
anysecret get-parameter app/timeout

# Test classification
anysecret classify DATABASE_PASSWORD  # → secret
anysecret classify API_TIMEOUT        # → parameter

# System information
anysecret info
```

## Configuration Examples

### Environment Variables

```bash
# Provider selection
export SECRET_MANAGER_TYPE=gcp
export PARAMETER_MANAGER_TYPE=gcp_config
export GCP_PROJECT_ID=your-project

# Or unified file-based
export CONFIG_MANAGER_TYPE=env_file
export ENV_FILE_PATH=.env
```

### Fallback Configuration

```python
from anysecret import ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    # Primary: Cloud-native
    secret_manager_type=ManagerType.GCP,
    secret_config={"project_id": "prod-project"},
    parameter_manager_type=ManagerType.GCP_CONFIG,
    parameter_config={"project_id": "prod-project"},
    
    # Fallback: Encrypted files
    secret_fallback_type=ManagerType.ENCRYPTED_FILE,
    secret_fallback_config={
        "file_path": "secrets.json.enc",
        "password": "fallback-password"
    },
    parameter_fallback_type=ManagerType.ENV_FILE,
    parameter_fallback_config={"file_path": ".env.fallback"}
)
```

### Azure Configuration

```python
from anysecret import ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    # Azure Key Vault for secrets
    secret_manager_type=ManagerType.AZURE,
    secret_config={
        "vault_name": "your-keyvault",
        "tenant_id": "your-tenant-id",
        "client_id": "your-client-id",
        "client_secret": "your-client-secret"
    },
    
    # Azure App Configuration for parameters
    parameter_manager_type=ManagerType.AZURE_APP_CONFIG,
    parameter_config={
        "connection_string": "your-app-config-connection-string",
        "label": "Production"
    }
)
```

### Kubernetes Configuration

```python
from anysecret import ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    # Kubernetes Secrets for sensitive data
    secret_manager_type=ManagerType.KUBERNETES,
    secret_config={
        "namespace": "default",
        "secret_name": "app-secrets"
    },
    
    # Kubernetes ConfigMaps for parameters
    parameter_manager_type=ManagerType.KUBERNETES_CONFIGMAP,
    parameter_config={
        "namespace": "default",
        "configmap_name": "app-config"
    }
)
```

### Multi-cloud Fallback Configuration

```python
from anysecret import ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    # Primary: Azure
    secret_manager_type=ManagerType.AZURE,
    secret_config={"vault_name": "prod-vault"},
    parameter_manager_type=ManagerType.AZURE_APP_CONFIG,
    parameter_config={"connection_string": "..."},
    
    # Fallback: AWS
    secret_fallback_type=ManagerType.AWS,
    secret_fallback_config={"region": "us-east-1"},
    parameter_fallback_type=ManagerType.AWS_PARAMETER_STORE,
    parameter_fallback_config={"region": "us-east-1"}
)
```

## Advanced Usage

### Custom Classification

```python
from anysecret import get_config_manager, SecretClassifier

# Custom classifier
classifier = SecretClassifier()
classifier.add_secret_patterns(["CUSTOM_*_PRIVATE", "INTERNAL_*_KEY"])  
classifier.add_parameter_patterns(["CUSTOM_*_CONFIG", "INTERNAL_*_SETTING"])

config = await get_config_manager(classifier=classifier)
```

### Batch Operations

```python
# Get all secrets for a service
auth_secrets = await config.get_secrets_by_prefix("auth/")
# Returns: {"auth/jwt_secret": "...", "auth/oauth_secret": "..."}

# Get all parameters for a service  
auth_params = await config.get_parameters_by_prefix("auth/")
# Returns: {"auth/timeout": "30", "auth/max_attempts": "5"}

# Mixed batch (auto-classified)
auth_config = await config.get_by_prefix("auth/")
# Returns: {"secrets": {...}, "parameters": {...}}
```

## Security Considerations

### Secret Protection
- Secrets never logged or cached in plaintext
- Automatic redaction in error messages
- Secure transport (TLS) for all cloud providers
- Optional field-level encryption for file storage

### Parameter Safety
- Parameters can be logged and cached
- Public values safe for version control
- Environment-specific parameter validation
- Type coercion with safety checks

### HIPAA Compliance
- Encrypted file providers for on-premises PHI
- Audit trails for secret access
- No cloud storage for customer PHI
- Configurable data residency controls

## Development
**Note**: This is currently a private project, being sanitized for open source release in the near future.
```bash
git clone https://github.com/starlitlog/anysecret-io.git
cd anysecret-io

# Install with development dependencies
pip install -e ".[dev,all]"

# Run tests
pytest

# Format code  
black anysecret tests
isort anysecret tests

# Type checking
mypy anysecret
```

## License

AnySecret.io is dual-licensed to balance open source benefits with sustainable development:

### Open Source License (AGPL-3.0)
✅ **Free for all users** - Use AnySecret.io in your applications at no cost  
✅ **Commercial applications welcome** - Build and sell products using AnySecret.io  
✅ **Modify and redistribute** - Fork, enhance, and share improvements  

⚠️ **Service providers**: If you offer AnySecret.io as a hosted service, you must open-source your entire service platform under AGPL-3.0

### Commercial License
🏢 **For service providers** - Offer AnySecret.io as a managed service without open-sourcing your platform  
🔒 **Proprietary integration** - Enhanced enterprise features and support  
📞 **Priority support** - Direct access to the development team  

**Need a commercial license?** Contact: licensing@anysecret.io

See [LICENSE](LICENSE) and [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) files for complete terms.

## Support

- **Documentation**: [GitHub README](https://github.com/starlitlog/anysecret-io)
- **Issues**: [GitHub Issues](https://github.com/starlitlog/anysecret-io/issues)
- **Email**: hello@anysecret.io

## Roadmap

- ✅ File-based providers (env, encrypted)
- ✅ Google Cloud Secret Manager  
- ✅ Auto-classification of secrets vs parameters
- ✅ CLI tools
- ✅ AWS Secrets Manager + Parameter Store
- ✅ Azure Key Vault + App Configuration
- ✅ HashiCorp Vault
- ✅ Kubernetes secrets + config maps
- 🚧 Secret rotation support
- 🚧 Configuration validation schemas
- 📋 Enhanced caching layer
- 📋 Monitoring and metrics
- 📋 Web UI dashboard

---

Made with care for the Python community.
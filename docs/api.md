# API Reference

Complete API documentation for AnySecret.io Python SDK.

## 📚 Table of Contents

- [Core API](#core-api)
- [Configuration Management](#configuration-management)
- [Provider Types](#provider-types)
- [Exception Handling](#exception-handling)
- [CLI Reference](#cli-reference)
- [Type Hints](#type-hints)

## 🚀 Core API

### `get_config_manager()`

The main entry point for AnySecret.io. Auto-detects environment and returns configured manager.

```python
from anysecret import get_config_manager

async def main():
    config = await get_config_manager()
```

**Parameters:**
- `config: Optional[ConfigManagerConfig]` - Custom configuration (overrides auto-detection)
- `classifier: Optional[SecretClassifier]` - Custom secret classification rules
- `cache_ttl: int = 300` - Cache TTL in seconds (default: 5 minutes)

**Returns:** `ConfigManagerInterface`

**Example:**
```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

# Auto-detection (recommended)
config = await get_config_manager()

# Custom configuration
custom_config = ConfigManagerConfig(
    secret_manager_type=ManagerType.AWS,
    secret_config={"region": "us-west-2"}
)
config = await get_config_manager(config=custom_config)
```

---

## 🔧 ConfigManagerInterface

The main interface for retrieving secrets and parameters.

### `get(key: str, default: Any = None) -> Any`

Universal getter - automatically classifies as secret or parameter.

```python
# Auto-classified retrieval
db_password = await config.get("DATABASE_PASSWORD")  # → secret
api_timeout = await config.get("API_TIMEOUT", default=30)  # → parameter
```

**Parameters:**
- `key: str` - The secret/parameter key
- `default: Any` - Default value if not found

**Returns:** `Any` - The decrypted/decoded value

**Raises:** 
- `SecretNotFoundError` - If key not found and no default provided
- `ProviderError` - If provider access fails

---

### `get_secret(key: str, default: Any = None, force_secret: bool = False) -> Any`

Explicitly retrieve from secure secret storage.

```python
# From secret storage (AWS Secrets Manager, GCP Secret Manager, etc.)
api_key = await config.get_secret("STRIPE_SECRET_KEY")
jwt_secret = await config.get_secret("JWT_SECRET")

# Force secret classification
public_token = await config.get_secret("PUBLIC_API_TOKEN", force_secret=True)
```

**Parameters:**
- `key: str` - The secret key
- `default: Any` - Default value if not found
- `force_secret: bool` - Force storage in secret manager (override auto-classification)

**Returns:** `Any` - The decrypted secret value

**Security:** Values are never logged or cached in plaintext.

---

### `get_parameter(key: str, default: Any = None, force_parameter: bool = False) -> Any`

Explicitly retrieve from configuration parameter storage.

```python
# From parameter storage (AWS Parameter Store, GCP Config, etc.)
db_host = await config.get_parameter("DATABASE_HOST")
timeout = await config.get_parameter("API_TIMEOUT", default=30)
feature_flag = await config.get_parameter("FEATURE_X_ENABLED", default=False)

# Force parameter classification  
pattern = await config.get_parameter("SECRET_PATTERN", force_parameter=True)
```

**Parameters:**
- `key: str` - The parameter key
- `default: Any` - Default value if not found
- `force_parameter: bool` - Force storage in parameter store (override auto-classification)

**Returns:** `Any` - The parameter value (with type coercion)

---

### `get_secrets_by_prefix(prefix: str) -> Dict[str, Any]`

Retrieve all secrets matching a prefix pattern.

```python
# Get all auth-related secrets
auth_secrets = await config.get_secrets_by_prefix("auth/")
# Returns: {
#   "auth/jwt_secret": "abc123...",
#   "auth/oauth_client_secret": "xyz789...",
#   "auth/api_key": "sk_live_..."
# }

# Database secrets
db_secrets = await config.get_secrets_by_prefix("database/")
```

**Parameters:**
- `prefix: str` - Key prefix to match

**Returns:** `Dict[str, Any]` - Dictionary of matching secrets

**Use Cases:**
- Service-specific secret loading
- Batch secret retrieval
- Environment-based grouping

---

### `get_parameters_by_prefix(prefix: str) -> Dict[str, Any]`

Retrieve all parameters matching a prefix pattern.

```python
# Get all app configuration
app_config = await config.get_parameters_by_prefix("app/")
# Returns: {
#   "app/timeout": "30",
#   "app/max_retries": "5", 
#   "app/log_level": "info"
# }

# Feature flags
features = await config.get_parameters_by_prefix("feature/")
```

**Parameters:**
- `prefix: str` - Key prefix to match

**Returns:** `Dict[str, Any]` - Dictionary of matching parameters

---

### `get_by_prefix(prefix: str) -> Dict[str, Dict[str, Any]]`

Retrieve both secrets and parameters by prefix, auto-classified.

```python
# Get everything for a service
auth_config = await config.get_by_prefix("auth/")
# Returns: {
#   "secrets": {
#     "auth/jwt_secret": "...",
#     "auth/api_key": "..."
#   },
#   "parameters": {
#     "auth/timeout": "30",
#     "auth/max_attempts": "5"
#   }
# }
```

**Returns:** `Dict[str, Dict[str, Any]]` with keys `secrets` and `parameters`

---

### `list_secrets() -> List[str]`

List all available secret keys.

```python
secrets = await config.list_secrets()
print(f"Available secrets: {secrets}")
```

**Returns:** `List[str]` - List of secret keys

---

### `list_parameters() -> List[str]`

List all available parameter keys.

```python
parameters = await config.list_parameters()
print(f"Available parameters: {parameters}")
```

**Returns:** `List[str]` - List of parameter keys

---

### Properties

```python
# Provider information
print(f"Provider: {config.provider_name}")        # "aws", "gcp", "azure", etc.
print(f"Region: {config.region}")                 # Current region/zone
print(f"Environment: {config.environment}")       # "production", "staging", etc.

# Configuration
print(f"Cache TTL: {config.cache_ttl}")          # Cache timeout in seconds
print(f"Fallback enabled: {config.has_fallback}") # Whether fallback is configured
```

---

## ⚙️ Configuration Management

### `ConfigManagerConfig`

Configuration object for customizing provider selection and settings.

```python
from anysecret import ConfigManagerConfig, ManagerType

config = ConfigManagerConfig(
    # Primary providers
    secret_manager_type=ManagerType.GCP,
    secret_config={
        "project_id": "my-project",
        "location": "us-central1"
    },
    
    parameter_manager_type=ManagerType.GCP_CONFIG,
    parameter_config={
        "project_id": "my-project"
    },
    
    # Fallback providers
    secret_fallback_type=ManagerType.ENCRYPTED_FILE,
    secret_fallback_config={
        "file_path": "/etc/secrets/secrets.json.enc",
        "password": "fallback-password"
    },
    
    parameter_fallback_type=ManagerType.ENV_FILE,
    parameter_fallback_config={
        "file_path": "/etc/config/.env"
    },
    
    # Global settings
    cache_ttl=300,
    environment="production",
    region="us-central1"
)

manager = await get_config_manager(config=config)
```

**Parameters:**
- `secret_manager_type: ManagerType` - Primary secret storage provider
- `secret_config: Dict[str, Any]` - Provider-specific secret configuration
- `parameter_manager_type: ManagerType` - Primary parameter storage provider  
- `parameter_config: Dict[str, Any]` - Provider-specific parameter configuration
- `secret_fallback_type: Optional[ManagerType]` - Fallback secret provider
- `secret_fallback_config: Optional[Dict[str, Any]]` - Fallback secret config
- `parameter_fallback_type: Optional[ManagerType]` - Fallback parameter provider
- `parameter_fallback_config: Optional[Dict[str, Any]]` - Fallback parameter config
- `cache_ttl: int` - Cache timeout in seconds (default: 300)
- `environment: Optional[str]` - Environment name for key prefixing
- `region: Optional[str]` - Cloud region/zone

---

### `ManagerType` Enum

Available provider types:

```python
from anysecret import ManagerType

# Cloud Providers
ManagerType.AWS                    # AWS Secrets Manager
ManagerType.AWS_PARAMETER_STORE    # AWS Systems Manager Parameter Store
ManagerType.GCP                    # Google Secret Manager
ManagerType.GCP_CONFIG             # Google Config Connector
ManagerType.AZURE                  # Azure Key Vault
ManagerType.AZURE_APP_CONFIG       # Azure App Configuration

# Container Platforms
ManagerType.KUBERNETES             # Kubernetes Secrets
ManagerType.KUBERNETES_CONFIGMAP   # Kubernetes ConfigMaps

# On-Premises
ManagerType.VAULT                  # HashiCorp Vault
ManagerType.ENCRYPTED_FILE         # AES-256 encrypted JSON/YAML
ManagerType.ENV_FILE               # Environment files (.env)
ManagerType.JSON_FILE              # Plain JSON files
ManagerType.YAML_FILE              # Plain YAML files
```

---

### Provider-Specific Configuration

#### AWS Configuration
```python
# AWS Secrets Manager
secret_config = {
    "region": "us-east-1",
    "profile": "production",  # Optional AWS profile
    "endpoint_url": "https://secretsmanager.us-east-1.amazonaws.com"  # Optional
}

# AWS Parameter Store
parameter_config = {
    "region": "us-east-1", 
    "path_prefix": "/myapp/",  # Optional path prefix
    "decrypt": True  # Decrypt SecureString parameters
}
```

#### Google Cloud Configuration
```python
# Google Secret Manager
secret_config = {
    "project_id": "my-project",
    "location": "us-central1",  # Optional for regional secrets
    "credentials_path": "/path/to/service-account.json"  # Optional
}

# Google Config Connector
parameter_config = {
    "project_id": "my-project",
    "namespace": "default"  # Kubernetes namespace if using Config Connector
}
```

#### Azure Configuration
```python
# Azure Key Vault
secret_config = {
    "vault_name": "my-keyvault",
    "tenant_id": "your-tenant-id",
    "client_id": "your-client-id",  # For service principal auth
    "client_secret": "your-client-secret"  # For service principal auth
}

# Azure App Configuration
parameter_config = {
    "connection_string": "Endpoint=https://...",
    "label": "Production",  # Configuration label
    "key_filter": "myapp:*"  # Optional key filter
}
```

#### Kubernetes Configuration
```python
# Kubernetes Secrets
secret_config = {
    "namespace": "default",
    "secret_name": "app-secrets",  # Optional: specific secret name
    "kubeconfig_path": "~/.kube/config"  # Optional: custom kubeconfig
}

# Kubernetes ConfigMaps
parameter_config = {
    "namespace": "default",
    "configmap_name": "app-config",  # Optional: specific configmap name
}
```

---

## 🎭 Secret Classification

### `SecretClassifier`

Customize how AnySecret.io classifies secrets vs parameters.

```python
from anysecret import SecretClassifier, get_config_manager

# Create custom classifier
classifier = SecretClassifier()

# Add custom secret patterns
classifier.add_secret_patterns([
    "CUSTOM_*_PRIVATE",
    "INTERNAL_*_KEY", 
    "*_CREDENTIAL",
    "OAUTH_*"
])

# Add custom parameter patterns  
classifier.add_parameter_patterns([
    "CUSTOM_*_CONFIG",
    "INTERNAL_*_SETTING",
    "*_TIMEOUT_MS",
    "FEATURE_*_ENABLED"
])

# Remove default patterns (advanced)
classifier.remove_secret_pattern("*_PASSWORD")  # Don't auto-classify passwords
classifier.remove_parameter_pattern("*_HOST")   # Don't auto-classify hosts

# Use custom classifier
config = await get_config_manager(classifier=classifier)
```

**Methods:**
- `add_secret_patterns(patterns: List[str])` - Add patterns for secret classification
- `add_parameter_patterns(patterns: List[str])` - Add patterns for parameter classification
- `remove_secret_pattern(pattern: str)` - Remove default secret pattern
- `remove_parameter_pattern(pattern: str)` - Remove default parameter pattern
- `is_secret(key: str, value: str = None) -> bool` - Check if key/value is classified as secret

**Default Secret Patterns:**
```python
# Name-based patterns
"*_SECRET", "*_PASSWORD", "*_KEY", "*_TOKEN", "*_CREDENTIAL", "*_PRIVATE"
"JWT_*", "OAUTH_*", "API_KEY*", "CLIENT_SECRET*", "PRIVATE_KEY*"

# Value-based patterns (for values starting with)
"sk_", "-----BEGIN", "AIza", "AKIA", "ghp_", "glpat-"
```

**Default Parameter Patterns:**
```python
# Name-based patterns
"*_HOST", "*_PORT", "*_URL", "*_TIMEOUT", "*_LIMIT", "*_COUNT"
"*_ENABLED", "*_FLAG", "*_SIZE", "LOG_*", "DEBUG_*", "MAX_*"
```

---

## ❗ Exception Handling

### Exception Hierarchy

```python
from anysecret import (
    AnySecretError,         # Base exception
    SecretNotFoundError,    # Secret/parameter not found
    ProviderError,          # Provider-specific error
    ConfigurationError,     # Configuration/setup error
    AuthenticationError,    # Authentication failed
    PermissionError,        # Insufficient permissions
    NetworkError           # Network/connectivity error
)

try:
    secret = await config.get_secret("API_KEY")
except SecretNotFoundError:
    print("API_KEY not found")
except PermissionError:
    print("Access denied to secret manager")
except ProviderError as e:
    print(f"Provider error: {e}")
except AnySecretError as e:
    print(f"AnySecret error: {e}")
```

### Exception Details

#### `SecretNotFoundError`
Raised when a secret or parameter is not found and no default is provided.

```python
try:
    api_key = await config.get_secret("MISSING_KEY")
except SecretNotFoundError as e:
    print(f"Key not found: {e.key}")
    print(f"Provider: {e.provider}")
    print(f"Searched in: {e.locations}")
```

#### `ProviderError`
Raised for provider-specific errors (network issues, API limits, etc.).

```python
try:
    secret = await config.get_secret("API_KEY")
except ProviderError as e:
    print(f"Provider: {e.provider}")
    print(f"Error code: {e.error_code}")
    print(f"Message: {e.message}")
    print(f"Retryable: {e.retryable}")
```

#### `AuthenticationError`
Raised when authentication fails with the cloud provider.

```python
try:
    config = await get_config_manager()
except AuthenticationError as e:
    print(f"Auth failed for {e.provider}")
    print(f"Reason: {e.reason}")
    print("Check your credentials/permissions")
```

---

## 🖥️ CLI Reference

### Installation
```bash
pip install anysecret-io
```

### Basic Commands

#### `anysecret get`
Retrieve a single secret or parameter.

```bash
# Get secret (auto-classified)
anysecret get DATABASE_PASSWORD

# Get with default value
anysecret get API_TIMEOUT --default 30

# Force secret retrieval
anysecret get PUBLIC_TOKEN --secret

# Force parameter retrieval  
anysecret get SECRET_PATTERN --parameter

# JSON output
anysecret get DATABASE_CONFIG --format json

# Base64 encoded (for Kubernetes)
anysecret get API_KEY --format base64
```

**Options:**
- `--default VALUE` - Default value if not found
- `--secret` - Force secret storage lookup
- `--parameter` - Force parameter storage lookup  
- `--format FORMAT` - Output format: `text`, `json`, `yaml`, `base64`, `shell`

#### `anysecret get-prefix`
Retrieve all secrets/parameters with a prefix.

```bash
# Get all with prefix
anysecret get-prefix "database/"

# JSON output  
anysecret get-prefix "auth/" --format json

# Only secrets
anysecret get-prefix "app/" --secrets-only

# Only parameters
anysecret get-prefix "app/" --parameters-only
```

#### `anysecret list`
List available secrets and parameters.

```bash
# List everything
anysecret list

# Only secrets
anysecret list --secrets-only

# Only parameters
anysecret list --parameters-only

# With values (be careful!)
anysecret list --show-values

# Filter by prefix
anysecret list --prefix "app/"
```

#### `anysecret info`
Show configuration and provider information.

```bash
anysecret info
# Output:
# Provider: aws
# Region: us-east-1  
# Environment: production
# Cache TTL: 300 seconds
# Fallback: enabled (encrypted-file)
```

### Advanced Commands

#### `anysecret classify`
Test secret classification.

```bash
anysecret classify DATABASE_PASSWORD
# Output: secret (matches pattern: *_PASSWORD)

anysecret classify API_TIMEOUT  
# Output: parameter (matches pattern: *_TIMEOUT)

anysecret classify CUSTOM_VALUE --value "sk_live_abc123"
# Output: secret (value starts with: sk_)
```

#### `anysecret validate`
Validate configuration and connectivity.

```bash
anysecret validate
# Output:
# ✅ Provider: aws (connected)
# ✅ Secret Manager: accessible  
# ✅ Parameter Store: accessible
# ✅ Fallback: configured
# ✅ Permissions: sufficient
```

#### `anysecret encrypt`
Encrypt files for secure storage.

```bash
# Encrypt .env file
anysecret encrypt secrets.env secrets.json.enc --password mypassword

# Encrypt JSON config
anysecret encrypt config.json config.json.enc --password-file password.txt
```

#### `anysecret sync-k8s`
Sync secrets to Kubernetes.

```bash
# Sync all secrets to K8s
anysecret sync-k8s --namespace production

# Sync specific prefix
anysecret sync-k8s --prefix "app/" --secret-name app-secrets

# Dry run
anysecret sync-k8s --dry-run
```

### Environment Variables

Configure CLI behavior:

```bash
# Provider selection
export SECRET_MANAGER_TYPE=aws
export PARAMETER_MANAGER_TYPE=aws_parameter_store

# AWS specific
export AWS_REGION=us-west-2
export AWS_PROFILE=production

# GCP specific  
export GCP_PROJECT_ID=my-project
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/creds.json

# Azure specific
export AZURE_KEY_VAULT_NAME=my-vault
export AZURE_TENANT_ID=tenant-id

# Global settings
export ANYSECRET_CACHE_TTL=600
export ANYSECRET_ENVIRONMENT=production
```

---

## 📝 Type Hints

AnySecret.io provides full type hint support:

```python
from typing import Dict, Any, Optional, List
from anysecret import (
    ConfigManagerInterface,
    ConfigManagerConfig, 
    ManagerType,
    SecretClassifier
)

# Function annotations
async def get_db_config(
    config: ConfigManagerInterface
) -> Dict[str, str]:
    password = await config.get_secret("DB_PASSWORD")
    host = await config.get_parameter("DB_HOST", default="localhost")
    return {"password": password, "host": host}

# Custom configuration with type hints
def create_config() -> ConfigManagerConfig:
    return ConfigManagerConfig(
        secret_manager_type=ManagerType.AWS,
        secret_config={"region": "us-east-1"},
        cache_ttl=300
    )

# Type-safe secret retrieval
async def typed_secrets(config: ConfigManagerInterface) -> None:
    # These will be properly typed by your IDE
    api_key: str = await config.get_secret("API_KEY")
    timeout: int = await config.get_parameter("TIMEOUT", default=30)
    enabled: bool = await config.get_parameter("ENABLED", default=False)
```

### Protocol Definition

```python
from typing import Protocol, Dict, Any, List, Optional

class ConfigManagerInterface(Protocol):
    """Type protocol for config manager interface."""
    
    @property
    def provider_name(self) -> str: ...
    
    @property  
    def region(self) -> Optional[str]: ...
    
    async def get(self, key: str, default: Any = None) -> Any: ...
    
    async def get_secret(
        self, 
        key: str, 
        default: Any = None,
        force_secret: bool = False
    ) -> Any: ...
    
    async def get_parameter(
        self,
        key: str,
        default: Any = None, 
        force_parameter: bool = False
    ) -> Any: ...
    
    async def get_secrets_by_prefix(self, prefix: str) -> Dict[str, Any]: ...
    
    async def get_parameters_by_prefix(self, prefix: str) -> Dict[str, Any]: ...
    
    async def list_secrets(self) -> List[str]: ...
    
    async def list_parameters(self) -> List[str]: ...
```

---

## 🔍 Advanced Usage Examples

### Custom Provider Configuration

```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

async def multi_region_setup():
    """Configure multi-region fallback."""
    config = ConfigManagerConfig(
        # Primary: us-east-1
        secret_manager_type=ManagerType.AWS,
        secret_config={
            "region": "us-east-1",
            "endpoint_url": "https://secretsmanager.us-east-1.amazonaws.com"
        },
        
        # Fallback: us-west-2  
        secret_fallback_type=ManagerType.AWS,
        secret_fallback_config={
            "region": "us-west-2"
        }
    )
    
    manager = await get_config_manager(config=config)
    return manager
```

### Custom Retry Logic

```python
import asyncio
from anysecret import get_config_manager, ProviderError

async def robust_secret_retrieval(key: str, max_retries: int = 3):
    """Retrieve secret with custom retry logic."""
    config = await get_config_manager()
    
    for attempt in range(max_retries):
        try:
            return await config.get_secret(key)
        except ProviderError as e:
            if not e.retryable or attempt == max_retries - 1:
                raise
            
            # Exponential backoff
            delay = 2 ** attempt
            await asyncio.sleep(delay)
    
    raise Exception("Max retries exceeded")
```

### Batch Operations

```python
async def load_service_config(service_name: str):
    """Load all configuration for a service."""
    config = await get_config_manager()
    
    # Load secrets and parameters in parallel
    secrets_task = config.get_secrets_by_prefix(f"{service_name}/")
    params_task = config.get_parameters_by_prefix(f"{service_name}/")
    
    secrets, parameters = await asyncio.gather(secrets_task, params_task)
    
    return {
        "service": service_name,
        "secrets": secrets,
        "parameters": parameters,
        "loaded_at": datetime.utcnow().isoformat()
    }
```

---

## 📞 Support

- **Documentation**: [anysecret.io/docs](https://anysecret.io/docs)
- **GitHub Issues**: [anysecret-io/anysecret-lib/issues](https://github.com/anysecret-io/anysecret-lib/issues)  
- **Discord**: [Join our community](https://discord.gg/anysecret)
- **Email**: support@anysecret.io

---

*This API reference covers AnySecret.io v1.0+. For older versions, see the [changelog](https://github.com/anysecret-io/anysecret-lib/releases).*
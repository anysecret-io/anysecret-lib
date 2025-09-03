# AnySecret Python SDK API Reference

The Python SDK for AnySecret.io provides programmatic access to secret and parameter management.

**Note:** The primary interface is the CLI. The Python SDK is currently minimal - use the CLI for full functionality.

## Installation

```bash
pip install anysecret-io
```

## Current API (What Actually Exists)

### Basic Usage

```python
from anysecret import get_secret_manager, SecretManagerType

# Get a secret manager instance
async def main():
    secret_manager = await get_secret_manager()
    
    # Basic operations
    secret = await secret_manager.get_secret("API_KEY")
    await secret_manager.create_secret("NEW_KEY", "value")
    await secret_manager.update_secret("API_KEY", "new_value")
    await secret_manager.delete_secret("OLD_KEY")
    secrets = await secret_manager.list_secrets()
```

### Available Exports

```python
from anysecret import (
    get_secret_manager,        # Factory function for secret managers
    SecretManagerType,         # Enum of provider types
    SecretManagerFactory       # Factory class for creating managers
)
```

### SecretManagerType Enum

```python
from anysecret import SecretManagerType

# Available types
SecretManagerType.AWS           # AWS Secrets Manager
SecretManagerType.GCP           # GCP Secret Manager  
SecretManagerType.AZURE         # Azure Key Vault
SecretManagerType.KUBERNETES    # Kubernetes Secrets
SecretManagerType.VAULT         # HashiCorp Vault
SecretManagerType.FILE          # Local file storage
```

### Direct Provider Usage

For advanced use cases, you can directly instantiate providers:

```python
# AWS Secrets Manager
from anysecret.providers.aws import AwsSecretManager

secret_manager = AwsSecretManager(region="us-east-1")
await secret_manager.create_secret("key", "value")

# GCP Secret Manager
from anysecret.providers.gcp import GcpSecretManager

secret_manager = GcpSecretManager(project_id="my-project")
await secret_manager.get_secret("key")

# Local File Storage
from anysecret.providers.file import EnvFileSecretManager

secret_manager = EnvFileSecretManager(file_path=".env")
await secret_manager.list_secrets()
```

### Parameter Manager Usage

```python
# Parameter managers are available but not exposed in main API
from anysecret.config import get_parameter_manager

param_manager = await get_parameter_manager()
value = await param_manager.get_parameter("CONFIG_VALUE")
await param_manager.create_parameter("NEW_CONFIG", "value")
```

## CLI Is Primary Interface

For most use cases, **use the CLI instead of the Python SDK**:

```bash
# The CLI provides full functionality
anysecret get API_KEY
anysecret set DATABASE_URL "postgresql://..."
anysecret list
anysecret bulk import .env
anysecret bulk export --output production.env
```

See [CLI Reference](cli.md) for complete documentation.

## ConfigManager (Available but Not Exported)

The `ConfigManager` class provides unified configuration management with automatic classification. While not exported in the main package, it can be imported directly:

```python
from anysecret.config_manager import ConfigManager
from anysecret.config import get_config_manager

# Get configured instance (with auto-detection)
config = await get_config_manager()

# Or create directly
config = ConfigManager(
    secret_config={"type": "gcp", "project_id": "my-project"},
    parameter_config={"type": "gcs", "bucket": "my-bucket"}
)

# Unified interface with auto-classification
value = await config.get("DATABASE_PASSWORD")  # Auto-routes to secrets
value = await config.get("API_TIMEOUT")       # Auto-routes to parameters

# Override classification
value = await config.get("PUBLIC_KEY", hint="secret")  # Force as secret

# Prefix-based operations
all_config = await config.get_config_by_prefix("app/")
all_keys = await config.list_all_keys(prefix="service/")

# CRUD operations
await config.set("NEW_KEY", "value")          # Auto-classified
await config.delete("OLD_KEY")
```

### ConfigManager Features

- **Automatic Classification**: Uses pattern matching to route between secrets and parameters
- **Unified Interface**: Single `get()`, `set()`, `delete()` methods
- **Prefix Operations**: Retrieve all values with a given prefix
- **Custom Patterns**: Add your own classification patterns
- **Metadata Support**: Get/set with metadata

## Provider Base Classes

If implementing custom providers:

```python
from anysecret.base_secret_manager import BaseSecretManager
from anysecret.base_parameter_manager import BaseParameterManager

class CustomSecretManager(BaseSecretManager):
    async def create_secret(self, key: str, value: str) -> None:
        # Implementation
        pass
    
    async def get_secret(self, key: str) -> str:
        # Implementation
        pass
    
    async def update_secret(self, key: str, value: str) -> None:
        # Implementation
        pass
    
    async def delete_secret(self, key: str) -> None:
        # Implementation
        pass
    
    async def list_secrets(self) -> List[str]:
        # Implementation
        pass
```

## Environment Variables

Configure the SDK behavior:

```bash
# Provider selection
export SECRET_MANAGER_TYPE=gcp
export PARAMETER_MANAGER_TYPE=gcs

# GCP
export GCP_PROJECT_ID=my-project
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/creds.json

# AWS
export AWS_REGION=us-east-1
export AWS_PROFILE=production

# Azure
export AZURE_KEY_VAULT_NAME=my-vault
```

## Exceptions

```python
from anysecret.exceptions import (
    SecretManagerError,      # Base exception
    SecretNotFoundError,     # Secret doesn't exist
    SecretAlreadyExistsError # Secret already exists
)

try:
    secret = await secret_manager.get_secret("MISSING")
except SecretNotFoundError:
    print("Secret not found")
```

## Examples

### Basic Secret Management

```python
import asyncio
from anysecret import get_secret_manager

async def manage_secrets():
    # Auto-detect provider based on environment
    mgr = await get_secret_manager()
    
    # CRUD operations
    await mgr.create_secret("API_KEY", "sk_live_123")
    value = await mgr.get_secret("API_KEY")
    await mgr.update_secret("API_KEY", "sk_live_456")
    await mgr.delete_secret("OLD_KEY")
    
    # List all
    all_secrets = await mgr.list_secrets()
    for key in all_secrets:
        print(f"Secret: {key}")

asyncio.run(manage_secrets())
```

### Using with FastAPI

```python
from fastapi import FastAPI, Depends
from anysecret import get_secret_manager

app = FastAPI()

async def get_db_password():
    mgr = await get_secret_manager()
    return await mgr.get_secret("DB_PASSWORD")

@app.get("/")
async def root(password: str = Depends(get_db_password)):
    # Use password
    return {"status": "connected"}
```

## What's Available vs What's Exported

### Currently Exported (in `__init__.py`):
- ✅ `get_secret_manager()` - Basic secret manager factory
- ✅ `SecretManagerType` - Provider type enum
- ✅ `SecretManagerFactory` - Factory for creating managers

### Available but Not Exported:
- ✅ `ConfigManager` - Full unified interface with auto-classification
- ✅ `get_config_manager()` - Auto-configured manager with detection
- ✅ `get_parameter_manager()` - Parameter manager factory
- ✅ Classification system with pattern matching
- ✅ Prefix-based retrieval methods

### Not Yet Implemented:
- ❌ Caching layer (config exists but not implemented)
- ❌ Fallback providers (config exists but not implemented)
- ❌ Retry logic and circuit breakers

**Note:** The full `ConfigManager` functionality exists and is used by the CLI but isn't exported in the main package. You can still import it directly if needed.

## Future SDK Enhancements

We're considering adding:
- Unified `ConfigManager` with auto-classification
- Async context managers for connection pooling
- Built-in retry logic and circuit breakers
- Streaming APIs for large secrets
- Batch operations

---

**Note:** This documentation reflects the actual current implementation. For the full-featured configuration management experience, use the [AnySecret CLI](cli.md).
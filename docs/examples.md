# Examples

Complete examples for using AnySecret.io across different environments and use cases.

## Table of Contents

- [Quick Start Examples](#quick-start-examples)
- [Provider-Specific Examples](#provider-specific-examples)
- [Framework Integration](#framework-integration)
- [DevOps Examples](#devops-examples)
- [Advanced Use Cases](#advanced-use-cases)
- [Error Handling](#error-handling)

## Quick Start Examples

### Basic Usage - Auto-Classification

```python
import asyncio
import anysecret

async def main():
    # Just use .get() - auto-classification handles the rest!
    db_password = await anysecret.get("database.password")  # → Secure storage
    api_key = await anysecret.get("stripe.api.key")        # → Secure storage
    db_host = await anysecret.get("database.host")         # → Parameter storage  
    timeout = await anysecret.get("api.timeout", default=30)  # → Parameter storage
    
    print(f"Connecting to {db_host} with timeout {timeout}s")

asyncio.run(main())
```

### Manual Classification (when needed)

```python
import asyncio
import anysecret

async def main():
    # Force specific storage type when auto-classification isn't enough
    admin_password = await anysecret.get("admin.password", hint="secret")
    debug_flag = await anysecret.get("debug.enabled", hint="parameter", default=False)
    
    # Or use the explicit methods
    config = await anysecret.get_config_manager()
    jwt_secret = await config.get_secret("jwt.secret")
    log_level = await config.get_parameter("log.level", default="INFO")

asyncio.run(main())
```

### Batch Operations with Auto-Classification

```python
import asyncio
import anysecret

async def load_all_config():
    # Batch get with auto-classification
    config_keys = [
        "database.password",  # → Auto: Secret
        "redis.password",     # → Auto: Secret
        "jwt.secret",         # → Auto: Secret
        "database.host",      # → Auto: Parameter
        "redis.host",         # → Auto: Parameter
        "log.level"          # → Auto: Parameter
    ]
    
    # Single call gets everything - auto-classified appropriately
    config_data = await anysecret.get_many(config_keys, defaults={
        "database.host": "localhost",
        "redis.host": "localhost",
        "log.level": "INFO"
    })
    
    return config_data

# Usage
config = asyncio.run(load_all_config())
print(f"DB Host: {config['database.host']}")
```

### CLI and Environment Variable Integration

```python
# Your application code stays the same regardless of how values are loaded:

import asyncio
import anysecret

async def main():
    # This works whether loaded via:
    # 1. Direct provider calls
    # 2. Environment variables: DATABASE_HOST=$(anysecret get database.host)  
    # 3. .env files populated by CLI
    # 4. Kubernetes secrets synced by AnySecret
    
    db_host = await anysecret.get("database.host")
    db_password = await anysecret.get("database.password")
    
    print(f"Connecting to {db_host}")
    # Password automatically cached, no re-reads from environment

asyncio.run(main())
```

## Provider-Specific Examples

### AWS Examples

#### Auto-Classification with AWS

```python
import asyncio
import anysecret

async def aws_example():
    # Auto-detects AWS environment and classifies automatically
    
    # These automatically go to AWS Secrets Manager (secure storage)
    db_password = await anysecret.get("prod.database.password")
    api_key = await anysecret.get("prod.stripe.api.key")
    
    # These automatically go to AWS Parameter Store (config storage)  
    db_host = await anysecret.get("prod.database.host")
    feature_flag = await anysecret.get("prod.features.new.ui", default=False)
    
    return {
        "db_password": db_password,
        "db_host": db_host,
        "api_key": api_key,
        "new_ui_enabled": feature_flag
    }

# Same code works in CLI:
# anysecret get prod.database.host
# anysecret get prod.stripe.api.key  

config = asyncio.run(aws_example())
```

#### Manual AWS Configuration

```python
from anysecret import ConfigManager
from anysecret.providers import AWSSecretsProvider, AWSParameterProvider

async def aws_manual_config():
    # Manual provider configuration
    secrets_provider = AWSSecretsProvider(
        region_name="us-west-2",
        profile_name="production"
    )
    
    params_provider = AWSParameterProvider(
        region_name="us-west-2",
        profile_name="production"
    )
    
    config = ConfigManager(
        secrets_provider=secrets_provider,
        parameter_provider=params_provider
    )
    
    # Use as normal
    password = await config.get_secret("prod/db/password")
    return password
```

#### AWS with Cross-Account Access

```python
from anysecret import get_config_manager
import os

async def cross_account_aws():
    # Set role ARN for cross-account access
    os.environ["AWS_ROLE_ARN"] = "arn:aws:iam::123456789012:role/CrossAccountSecretsRole"
    
    config = await get_config_manager()
    
    # Access secrets from different account
    cross_account_secret = await config.get_secret("shared/database/password")
    
    return cross_account_secret
```

### Google Cloud Examples

#### Using Secret Manager + Cloud Config

```python
import asyncio
from anysecret import get_config_manager

async def gcp_example():
    # Auto-detects GCP environment
    config = await get_config_manager()
    
    # Secrets go to Google Secret Manager
    db_password = await config.get_secret("database-password")
    api_key = await config.get_secret("stripe-api-key")
    
    # Parameters go to Cloud Config (or Runtime Config)
    project_id = await config.get_parameter("project-id")
    instance_type = await config.get_parameter("compute-instance-type", default="e2-medium")
    
    return {
        "project_id": project_id,
        "db_password": db_password,
        "api_key": api_key,
        "instance_type": instance_type
    }

asyncio.run(gcp_example())
```

#### Manual GCP Configuration

```python
from anysecret import ConfigManager
from anysecret.providers import GCPSecretsProvider, GCPParameterProvider

async def gcp_manual_config():
    # Manual configuration with service account
    secrets_provider = GCPSecretsProvider(
        project_id="my-production-project",
        credentials_path="/path/to/service-account.json"
    )
    
    params_provider = GCPParameterProvider(
        project_id="my-production-project",
        credentials_path="/path/to/service-account.json"
    )
    
    config = ConfigManager(
        secrets_provider=secrets_provider,
        parameter_provider=params_provider
    )
    
    password = await config.get_secret("database-password")
    return password
```

### Azure Examples

#### Using Key Vault + App Configuration

```python
import asyncio
from anysecret import get_config_manager

async def azure_example():
    # Auto-detects Azure environment
    config = await get_config_manager()
    
    # Secrets go to Azure Key Vault
    db_password = await config.get_secret("database-password")
    storage_key = await config.get_secret("storage-account-key")
    
    # Parameters go to Azure App Configuration
    app_name = await config.get_parameter("app-name")
    log_level = await config.get_parameter("log-level", default="INFO")
    
    return {
        "app_name": app_name,
        "db_password": db_password,
        "storage_key": storage_key,
        "log_level": log_level
    }

asyncio.run(azure_example())
```

#### Manual Azure Configuration

```python
from anysecret import ConfigManager
from anysecret.providers import AzureSecretsProvider, AzureParameterProvider

async def azure_manual_config():
    # Manual configuration with service principal
    secrets_provider = AzureSecretsProvider(
        key_vault_url="https://myvault.vault.azure.net/",
        client_id="your-client-id",
        client_secret="your-client-secret",
        tenant_id="your-tenant-id"
    )
    
    params_provider = AzureParameterProvider(
        app_config_url="https://myappconfig.azconfig.io",
        client_id="your-client-id",
        client_secret="your-client-secret", 
        tenant_id="your-tenant-id"
    )
    
    config = ConfigManager(
        secrets_provider=secrets_provider,
        parameter_provider=params_provider
    )
    
    password = await config.get_secret("database-password")
    return password
```

### Kubernetes Examples

#### Using Secrets + ConfigMaps

```python
import asyncio
from anysecret import get_config_manager

async def kubernetes_example():
    # Auto-detects Kubernetes environment
    config = await get_config_manager()
    
    # Secrets from Kubernetes Secrets
    db_password = await config.get_secret("database-password")
    tls_cert = await config.get_secret("tls-certificate")
    
    # Parameters from ConfigMaps
    app_version = await config.get_parameter("app-version")
    replica_count = await config.get_parameter("replica-count", default=3)
    
    return {
        "app_version": app_version,
        "replica_count": replica_count,
        "db_password": db_password[:10] + "..."  # Don't log full password
    }

asyncio.run(kubernetes_example())
```

#### Manual Kubernetes Configuration

```python
from anysecret import ConfigManager
from anysecret.providers import KubernetesSecretsProvider, KubernetesParameterProvider

async def k8s_manual_config():
    # Manual configuration with specific namespace
    secrets_provider = KubernetesSecretsProvider(
        namespace="production",
        kubeconfig_path="/path/to/kubeconfig"
    )
    
    params_provider = KubernetesParameterProvider(
        namespace="production",
        kubeconfig_path="/path/to/kubeconfig"
    )
    
    config = ConfigManager(
        secrets_provider=secrets_provider,
        parameter_provider=params_provider
    )
    
    password = await config.get_secret("database-password")
    return password
```

### HashiCorp Vault Examples

#### Basic Vault Usage

```python
import asyncio
from anysecret import get_config_manager

async def vault_example():
    # Auto-detects Vault environment
    config = await get_config_manager()
    
    # Both secrets and parameters from Vault KV
    db_password = await config.get_secret("secret/database/password")
    api_timeout = await config.get_parameter("config/api/timeout", default=30)
    
    return {
        "db_password": db_password,
        "api_timeout": api_timeout
    }

asyncio.run(vault_example())
```

#### Manual Vault Configuration

```python
from anysecret import ConfigManager
from anysecret.providers import VaultProvider

async def vault_manual_config():
    # Manual Vault configuration
    vault_provider = VaultProvider(
        url="https://vault.company.com:8200",
        token="your-vault-token",
        mount_point="secret",
        kv_version=2
    )
    
    config = ConfigManager(
        secrets_provider=vault_provider,
        parameter_provider=vault_provider  # Same provider for both
    )
    
    password = await config.get_secret("database/password")
    return password
```

### Encrypted File Examples

#### JSON File Configuration

```python
import asyncio
from anysecret import get_config_manager
import os

async def encrypted_file_example():
    # Set encryption key
    os.environ["ANYSECRET_ENCRYPTION_KEY"] = "your-32-byte-key-here-base64-encoded"
    os.environ["SECRET_MANAGER_TYPE"] = "file"
    os.environ["SECRETS_FILE_PATH"] = "/path/to/secrets.json.encrypted"
    
    config = await get_config_manager()
    
    # Reads from encrypted JSON file
    db_password = await config.get_secret("database_password")
    api_key = await config.get_secret("api_key")
    
    return {
        "db_password": db_password,
        "api_key": api_key
    }

asyncio.run(encrypted_file_example())
```

## Framework Integration

### FastAPI Integration - Simplified

```python
from fastapi import FastAPI
import anysecret

app = FastAPI()

@app.on_event("startup")
async def startup():
    # Pre-load critical configuration - auto-classified
    db_url = await anysecret.get("database.url")
    redis_url = await anysecret.get("redis.url")
    
    print(f"Starting with DB: {db_url}")
    print(f"Starting with Redis: {redis_url}")

@app.get("/health")
async def health_check():
    # Direct access - no dependency injection needed
    db_host = await anysecret.get("database.host", default="localhost")
    
    return {
        "status": "healthy", 
        "database_host": db_host,
        "cached": True  # Automatically cached after first call
    }

@app.post("/process")
async def process_data():
    # Secrets auto-classified and cached
    stripe_key = await anysecret.get("stripe.secret.key")
    
    # Use the key - same whether from cloud provider or env var
    # ... your business logic ...
    
    return {"status": "processed"}
```

### Environment Variable Hybrid Approach

```python
# Set in your deployment:
# DATABASE_HOST=$(anysecret get database.host)
# STRIPE_KEY=$(anysecret get stripe.secret.key)

from fastapi import FastAPI
import anysecret

app = FastAPI()

@app.get("/hybrid-example")
async def hybrid_example():
    # These calls work identically whether the values come from:
    # 1. Direct cloud provider calls
    # 2. Environment variables populated by CLI
    # 3. Cached previous calls
    
    db_host = await anysecret.get("database.host")
    stripe_key = await anysecret.get("stripe.secret.key")
    
    # AnySecret handles caching, no repeated env var reads
    return {"db_host": db_host, "has_stripe": bool(stripe_key)}
```

### Django Integration

```python
# settings.py
import asyncio
from anysecret import get_config_manager

# Initialize configuration
config = asyncio.run(get_config_manager())

# Load Django settings from AnySecret
SECRET_KEY = asyncio.run(config.get_secret("DJANGO_SECRET_KEY"))
DATABASE_PASSWORD = asyncio.run(config.get_secret("DATABASE_PASSWORD"))
DATABASE_HOST = asyncio.run(config.get_parameter("DATABASE_HOST", default="localhost"))

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'myapp',
        'USER': 'myuser',
        'PASSWORD': DATABASE_PASSWORD,
        'HOST': DATABASE_HOST,
        'PORT': '5432',
    }
}

# Cache timeout from configuration
CACHE_TIMEOUT = asyncio.run(config.get_parameter("CACHE_TIMEOUT", default=300))
```

### Flask Integration

```python
from flask import Flask
from anysecret import get_config_manager
import asyncio

app = Flask(__name__)

# Load configuration on app creation
config = asyncio.run(get_config_manager())

# Load Flask configuration
app.secret_key = asyncio.run(config.get_secret("FLASK_SECRET_KEY"))
database_url = asyncio.run(config.get_parameter("DATABASE_URL"))

@app.route('/api/data')
def get_data():
    # For sync frameworks, you can pre-load configuration
    # or use a background task to refresh periodically
    return {"message": "Hello from Flask with AnySecret!"}

if __name__ == '__main__':
    debug_mode = asyncio.run(config.get_parameter("DEBUG_MODE", default=False))
    app.run(debug=debug_mode)
```

## DevOps Examples

### Terraform Integration

```hcl
# main.tf
data "external" "secrets" {
  program = ["anysecret", "get-all", "--format", "json"]
}

resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "t3.micro"
  
  user_data = <<-EOF
    #!/bin/bash
    export DATABASE_PASSWORD="${data.external.secrets.result.database_password}"
    export API_KEY="${data.external.secrets.result.api_key}"
    
    # Start your application
    ./start-app.sh
  EOF
  
  tags = {
    Name = "WebServer"
  }
}
```

### Docker Integration

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

# Install AnySecret
RUN pip install anysecret-io[all]

COPY . .

# Use AnySecret to get configuration at runtime
CMD ["sh", "-c", "export DATABASE_URL=$(anysecret get database/url) && python app.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  web:
    build: .
    environment:
      # AnySecret will auto-detect the environment
      - SECRET_MANAGER_TYPE=aws
      - AWS_REGION=us-west-2
    command: |
      sh -c "
        export DB_PASSWORD=$$(anysecret get database/password) &&
        export REDIS_URL=$$(anysecret get redis/url) &&
        python app.py
      "
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Load Configuration') {
            steps {
                script {
                    // Load secrets using AnySecret CLI
                    env.DATABASE_PASSWORD = sh(
                        script: 'anysecret get database/password',
                        returnStdout: true
                    ).trim()
                    
                    env.API_KEY = sh(
                        script: 'anysecret get api/key',
                        returnStdout: true
                    ).trim()
                    
                    env.DATABASE_HOST = sh(
                        script: 'anysecret get database/host',
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Deploy') {
            steps {
                sh '''
                    echo "Deploying with host: $DATABASE_HOST"
                    # Your deployment script here
                    ./deploy.sh
                '''
            }
        }
    }
}
```

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy Application

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install AnySecret
      run: pip install anysecret-io[aws]
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
        aws-region: us-west-2
    
    - name: Load configuration
      run: |
        echo "DATABASE_PASSWORD=$(anysecret get database/password)" >> $GITHUB_ENV
        echo "API_KEY=$(anysecret get api/key)" >> $GITHUB_ENV
        echo "DATABASE_HOST=$(anysecret get database/host)" >> $GITHUB_ENV
    
    - name: Deploy
      run: |
        echo "Deploying to $DATABASE_HOST"
        # Your deployment commands
```

### Kubernetes Deployment

```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-app
  template:
    metadata:
      labels:
        app: web-app
    spec:
      initContainers:
      - name: config-loader
        image: python:3.11-slim
        command:
          - sh
          - -c
          - |
            pip install anysecret-io[k8s]
            anysecret get-all --format env > /shared/config.env
        volumeMounts:
        - name: shared-config
          mountPath: /shared
      
      containers:
      - name: web-app
        image: myapp:latest
        command:
          - sh
          - -c
          - |
            source /shared/config.env
            python app.py
        volumeMounts:
        - name: shared-config
          mountPath: /shared
      
      volumes:
      - name: shared-config
        emptyDir: {}
```

## Advanced Use Cases

### Configuration Hot Reloading

```python
import asyncio
import signal
from anysecret import get_config_manager

class ConfigurableApp:
    def __init__(self):
        self.config = None
        self.running = True
        self.reload_interval = 300  # 5 minutes
        
    async def initialize(self):
        self.config = await get_config_manager()
        await self.load_configuration()
        
    async def load_configuration(self):
        """Load all configuration values"""
        self.db_host = await self.config.get_parameter("DATABASE_HOST")
        self.api_timeout = await self.config.get_parameter("API_TIMEOUT", default=30)
        self.log_level = await self.config.get_parameter("LOG_LEVEL", default="INFO")
        
        print(f"Configuration loaded: {self.db_host}, timeout={self.api_timeout}")
        
    async def reload_config(self):
        """Periodically reload configuration"""
        while self.running:
            await asyncio.sleep(self.reload_interval)
            try:
                await self.load_configuration()
                print("Configuration reloaded")
            except Exception as e:
                print(f"Failed to reload configuration: {e}")
                
    async def run(self):
        # Start config reload task
        reload_task = asyncio.create_task(self.reload_config())
        
        # Main application loop
        while self.running:
            # Your application logic here
            print(f"App running with timeout: {self.api_timeout}")
            await asyncio.sleep(10)
            
        reload_task.cancel()

# Usage
async def main():
    app = ConfigurableApp()
    await app.initialize()
    
    # Handle graceful shutdown
    def signal_handler():
        app.running = False
        
    signal.signal(signal.SIGINT, lambda s, f: signal_handler())
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler())
    
    await app.run()

if __name__ == "__main__":
    asyncio.run(main())
```

### Multi-Environment Configuration

```python
import asyncio
from anysecret import get_config_manager
import os

class MultiEnvConfig:
    def __init__(self):
        self.environment = os.getenv("ENVIRONMENT", "development")
        self.config = None
        
    async def initialize(self):
        self.config = await get_config_manager()
        
    async def get_env_secret(self, key):
        """Get environment-specific secret"""
        env_key = f"{self.environment}/{key}"
        try:
            return await self.config.get_secret(env_key)
        except:
            # Fallback to non-environment specific
            return await self.config.get_secret(key)
            
    async def get_env_parameter(self, key, default=None):
        """Get environment-specific parameter"""
        env_key = f"{self.environment}/{key}"
        try:
            return await self.config.get_parameter(env_key, default=default)
        except:
            # Fallback to non-environment specific
            return await self.config.get_parameter(key, default=default)

# Usage
async def main():
    config = MultiEnvConfig()
    await config.initialize()
    
    # Gets production/database/password or database/password
    db_password = await config.get_env_secret("database/password")
    
    # Gets development/api/timeout or api/timeout
    api_timeout = await config.get_env_parameter("api/timeout", default=30)
    
    print(f"Environment: {config.environment}")
    print(f"API Timeout: {api_timeout}")

asyncio.run(main())
```

### Caching Configuration

```python
import asyncio
from anysecret import get_config_manager
import time
from typing import Dict, Any, Optional

class CachedConfigManager:
    def __init__(self, cache_ttl: int = 300):  # 5 minutes default
        self.config = None
        self.cache_ttl = cache_ttl
        self.cache: Dict[str, Dict[str, Any]] = {}
        
    async def initialize(self):
        self.config = await get_config_manager()
        
    def _is_cache_valid(self, key: str) -> bool:
        """Check if cached value is still valid"""
        if key not in self.cache:
            return False
        return time.time() - self.cache[key]["timestamp"] < self.cache_ttl
        
    async def get_secret_cached(self, key: str) -> str:
        """Get secret with caching (use carefully - secrets in memory)"""
        if self._is_cache_valid(key):
            return self.cache[key]["value"]
            
        value = await self.config.get_secret(key)
        self.cache[key] = {
            "value": value,
            "timestamp": time.time()
        }
        return value
        
    async def get_parameter_cached(self, key: str, default: Any = None) -> Any:
        """Get parameter with caching"""
        cache_key = f"param:{key}"
        if self._is_cache_valid(cache_key):
            return self.cache[cache_key]["value"]
            
        value = await self.config.get_parameter(key, default=default)
        self.cache[cache_key] = {
            "value": value,
            "timestamp": time.time()
        }
        return value
        
    def clear_cache(self):
        """Clear all cached values"""
        self.cache.clear()

# Usage
async def main():
    config = CachedConfigManager(cache_ttl=600)  # 10 minute cache
    await config.initialize()
    
    # First call - fetches from provider
    db_host = await config.get_parameter_cached("DATABASE_HOST")
    
    # Second call - returns cached value
    db_host = await config.get_parameter_cached("DATABASE_HOST")
    
    print(f"Database host: {db_host}")

asyncio.run(main())
```

## Error Handling

### Comprehensive Error Handling

```python
import asyncio
from anysecret import get_config_manager
from anysecret.exceptions import (
    SecretNotFoundError,
    ParameterNotFoundError, 
    AuthenticationError,
    ConfigurationError
)

async def robust_config_loading():
    try:
        config = await get_config_manager()
        
        # Handle missing secrets gracefully
        try:
            db_password = await config.get_secret("DATABASE_PASSWORD")
        except SecretNotFoundError:
            print("Database password not found, using environment variable")
            import os
            db_password = os.getenv("DATABASE_PASSWORD")
            if not db_password:
                raise ConfigurationError("DATABASE_PASSWORD must be set")
                
        # Handle missing parameters with defaults
        try:
            api_timeout = await config.get_parameter("API_TIMEOUT")
        except ParameterNotFoundError:
            api_timeout = 30  # Default value
            print(f"API_TIMEOUT not found, using default: {api_timeout}")
            
        # Handle authentication errors
        try:
            stripe_key = await config.get_secret("STRIPE_SECRET_KEY")
        except AuthenticationError as e:
            print(f"Authentication failed: {e}")
            print("Check your cloud credentials")
            stripe_key = None
            
        return {
            "db_password": db_password,
            "api_timeout": api_timeout,
            "stripe_key": stripe_key
        }
        
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise

# Usage with retry logic
async def load_config_with_retry(max_retries: int = 3):
    for attempt in range(max_retries):
        try:
            return await robust_config_loading()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            print(f"Attempt {attempt + 1} failed: {e}")
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
            
config = asyncio.run(load_config_with_retry())
```

### Fallback Configuration Strategy

```python
import asyncio
from anysecret import get_config_manager
import os

class FallbackConfigManager:
    def __init__(self):
        self.primary_config = None
        self.fallback_values = {}
        
    async def initialize(self):
        try:
            self.primary_config = await get_config_manager()
        except Exception as e:
            print(f"Primary config failed: {e}, using fallbacks only")
            
    def set_fallback(self, key: str, value: Any):
        """Set a fallback value for a configuration key"""
        self.fallback_values[key] = value
        
    async def get_secret_with_fallback(self, key: str) -> Optional[str]:
        """Get secret with environment variable fallback"""
        if self.primary_config:
            try:
                return await self.primary_config.get_secret(key)
            except Exception as e:
                print(f"Primary secret fetch failed: {e}")
                
        # Try environment variable
        env_value = os.getenv(key)
        if env_value:
            return env_value
            
        # Try fallback values
        if key in self.fallback_values:
            return self.fallback_values[key]
            
        return None
        
    async def get_parameter_with_fallback(self, key: str, default: Any = None) -> Any:
        """Get parameter with multiple fallback layers"""
        if self.primary_config:
            try:
                return await self.primary_config.get_parameter(key, default=default)
            except Exception as e:
                print(f"Primary parameter fetch failed: {e}")
                
        # Try environment variable  
        env_value = os.getenv(key)
        if env_value is not None:
            return env_value
            
        # Try fallback values
        if key in self.fallback_values:
            return self.fallback_values[key]
            
        return default

# Usage
async def main():
    config = FallbackConfigManager()
    
    # Set fallback values
    config.set_fallback("DATABASE_HOST", "localhost")
    config.set_fallback("API_TIMEOUT", 30)
    
    await config.initialize()
    
    # These will try provider -> env vars -> fallbacks
    db_host = await config.get_parameter_with_fallback("DATABASE_HOST")
    db_password = await config.get_secret_with_fallback("DATABASE_PASSWORD")
    
    print(f"Using database: {db_host}")
    if db_password:
        print("Database password loaded successfully")
    else:
        print("WARNING: No database password found!")

asyncio.run(main())
```

These examples provide comprehensive coverage of AnySecret.io usage across different environments, providers, and use cases. Each example is production-ready and includes proper error handling and best practices.
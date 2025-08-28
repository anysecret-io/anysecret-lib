# Best Practices Guide

Security, performance, and operational best practices for AnySecret.io in production environments.

## 🎯 Core Principles

### 1. Use the Unified `.get()` Interface

**✅ Do This:**
```python
import anysecret

# Simple, universal interface - auto-classification handles everything
db_password = await anysecret.get("database.password")  # → Auto: Secret Storage
db_host = await anysecret.get("database.host")          # → Auto: Parameter Storage  
api_timeout = await anysecret.get("api.timeout", default=30)
```

**❌ Avoid This:**
```python
# Unnecessary complexity
config = await get_config_manager()
db_password = await config.get_secret("DATABASE_PASSWORD")
db_host = await config.get_parameter("DATABASE_HOST")
```

### 2. Write Code Once, Deploy Anywhere

Your application code should be identical whether using:
- Direct cloud provider calls
- Environment variables: `DATABASE_HOST=$(anysecret get database.host)`
- CLI-populated `.env` files  
- Kubernetes secrets synced by AnySecret

```python
# This exact code works in ALL deployment scenarios:
db_host = await anysecret.get("database.host")
stripe_key = await anysecret.get("stripe.api.key")

# No environment variable reading, no config file parsing needed!
```

### 3. Trust Auto-Classification, Override When Needed

```python
# Auto-classification handles 95% of cases correctly
stripe_key = await anysecret.get("stripe.api.key")      # → Auto: Secret
log_level = await anysecret.get("app.log.level")        # → Auto: Parameter

# Override only when auto-classification isn't sufficient
admin_token = await anysecret.get("admin.token", hint="secret")
debug_flag = await anysecret.get("debug.flag", hint="parameter")
```

## 🔐 Security Best Practices

### Secret Management

#### 1. **Never Hardcode Secrets**

❌ **Don't do this:**
```python
# BAD: Hardcoded secrets
DATABASE_URL = "postgresql://user:password@host:5432/db"
API_KEY = "sk_live_abc123..."
JWT_SECRET = "hardcoded-secret"
```

✅ **Do this instead:**
```python
import anysecret

async def get_database_config():
    # Auto-classification routes secrets to secure storage, params to config storage
    db_password = await anysecret.get("database.password")
    api_key = await anysecret.get("stripe.api.key")
    jwt_secret = await anysecret.get("jwt.secret")
    
    db_host = await anysecret.get("database.host")
    db_port = await anysecret.get("database.port", default=5432)
    
    return {
        "database_url": f"postgresql://user:{db_password}@{db_host}:{db_port}/db",
        "api_key": api_key,
        "jwt_secret": jwt_secret
    }
```

#### 2. **Use Environment-Specific Secret Naming**

```python
# Environment-based naming convention
ENVIRONMENTS = {
    "development": "dev",
    "staging": "staging", 
    "production": "prod"
}

async def get_environment_secret(key: str):
    config = await get_config_manager()
    env_prefix = ENVIRONMENTS.get(os.getenv("ENVIRONMENT", "development"))
    
    # Use environment-specific keys
    env_key = f"{env_prefix}/{key}"
    return await config.get_secret(env_key)

# Usage
db_password = await get_environment_secret("database/password")
# Resolves to: "prod/database/password" in production
```

#### 3. **Implement Secret Rotation**

```python
from datetime import datetime, timedelta
from anysecret import get_config_manager

class RotatingSecretManager:
    def __init__(self, rotation_interval_days=90):
        self.rotation_interval = timedelta(days=rotation_interval_days)
        self.cache = {}
        self.last_rotation_check = {}
    
    async def get_secret_with_rotation(self, key: str):
        config = await get_config_manager()
        
        # Check if secret needs rotation
        if self._needs_rotation(key):
            await self._rotate_secret(key)
        
        return await config.get_secret(key)
    
    def _needs_rotation(self, key: str) -> bool:
        last_check = self.last_rotation_check.get(key)
        if not last_check:
            return True
        
        return datetime.now() - last_check > self.rotation_interval
    
    async def _rotate_secret(self, key: str):
        # Implement your rotation logic here
        # This could involve creating new API keys, passwords, etc.
        print(f"Rotating secret: {key}")
        self.last_rotation_check[key] = datetime.now()

# Usage
secret_manager = RotatingSecretManager()
api_key = await secret_manager.get_secret_with_rotation("api/stripe-key")
```

#### 4. **Validate Secret Formats**

```python
import re
from typing import Optional

class SecretValidator:
    PATTERNS = {
        "api_key": r"^sk_live_[a-zA-Z0-9]{24,}$",
        "jwt_secret": r"^[a-zA-Z0-9]{32,}$",
        "database_password": r"^.{12,}$",  # At least 12 characters
        "oauth_client_secret": r"^[a-zA-Z0-9\-_]{20,}$"
    }
    
    @classmethod
    def validate_secret(cls, secret_type: str, value: str) -> bool:
        pattern = cls.PATTERNS.get(secret_type)
        if not pattern:
            return True  # No validation pattern defined
        
        return re.match(pattern, value) is not None
    
    @classmethod
    async def get_validated_secret(cls, key: str, secret_type: str) -> str:
        config = await get_config_manager()
        secret = await config.get_secret(key)
        
        if not cls.validate_secret(secret_type, secret):
            raise ValueError(f"Invalid {secret_type} format for key: {key}")
        
        return secret

# Usage
try:
    stripe_key = await SecretValidator.get_validated_secret(
        "api/stripe-key", 
        "api_key"
    )
except ValueError as e:
    print(f"Secret validation failed: {e}")
    # Handle invalid secret (alert, fallback, etc.)
```

### Access Control

#### 1. **Principle of Least Privilege**

```yaml
# AWS IAM Policy - Minimal permissions
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:prod/myapp/*"
      ]
    },
    {
      "Effect": "Allow", 
      "Action": [
        "ssm:GetParameter",
        "ssm:GetParametersByPath"
      ],
      "Resource": [
        "arn:aws:ssm:us-east-1:ACCOUNT:parameter/prod/myapp/*"
      ]
    }
  ]
}
```

#### 2. **Service-Specific Secret Access**

```python
from anysecret import get_config_manager

class ServiceSecretManager:
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.allowed_secrets = self._get_allowed_secrets()
    
    def _get_allowed_secrets(self) -> set:
        """Define which secrets each service can access."""
        permissions = {
            "auth-service": {
                "auth/jwt-secret", 
                "auth/oauth-client-secret",
                "database/auth-user-password"
            },
            "payment-service": {
                "payment/stripe-secret-key",
                "payment/webhook-secret", 
                "database/payment-user-password"
            },
            "user-service": {
                "database/user-password",
                "email/sendgrid-api-key"
            }
        }
        return permissions.get(self.service_name, set())
    
    async def get_secret(self, key: str) -> str:
        if key not in self.allowed_secrets:
            raise PermissionError(f"Service {self.service_name} not allowed to access {key}")
        
        config = await get_config_manager()
        return await config.get_secret(key)

# Usage in each service
auth_secrets = ServiceSecretManager("auth-service")
jwt_secret = await auth_secrets.get_secret("auth/jwt-secret")
```

### Audit and Monitoring

#### 1. **Secret Access Logging**

```python
import logging
from typing import Optional
from anysecret import get_config_manager

# Configure audit logger
audit_logger = logging.getLogger("anysecret.audit")
audit_logger.setLevel(logging.INFO)

# Add handler for audit logs (send to SIEM, CloudWatch, etc.)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
    '"service": "anysecret", "event": "secret_access", '
    '"message": "%(message)s"}'
)
handler.setFormatter(formatter)
audit_logger.addHandler(handler)

class AuditedSecretManager:
    def __init__(self, service_name: str, user_id: Optional[str] = None):
        self.service_name = service_name
        self.user_id = user_id or "system"
    
    async def get_secret(self, key: str) -> str:
        config = await get_config_manager()
        
        # Log access attempt
        audit_logger.info(
            f"secret_key={key}, service={self.service_name}, "
            f"user={self.user_id}, action=access_attempt"
        )
        
        try:
            secret = await config.get_secret(key)
            
            # Log successful access (never log the actual secret)
            audit_logger.info(
                f"secret_key={key}, service={self.service_name}, "
                f"user={self.user_id}, action=access_success"
            )
            
            return secret
            
        except Exception as e:
            # Log access failure
            audit_logger.error(
                f"secret_key={key}, service={self.service_name}, "
                f"user={self.user_id}, action=access_failure, error={str(e)}"
            )
            raise

# Usage
secrets = AuditedSecretManager("payment-service", "user-123")
api_key = await secrets.get_secret("stripe-api-key")
```

## ⚡ Performance Best Practices

### Caching Strategies

#### 1. **Implement Smart Caching**

```python
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from anysecret import get_config_manager

class SmartSecretCache:
    def __init__(self, default_ttl: int = 300):  # 5 minutes
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        
        # Different TTLs for different secret types
        self.ttl_overrides = {
            "database": 3600,      # 1 hour - DB passwords change rarely
            "api": 1800,           # 30 minutes - API keys moderate frequency
            "jwt": 300,            # 5 minutes - JWT secrets change often
            "oauth": 1800,         # 30 minutes
        }
    
    def _get_ttl(self, key: str) -> int:
        """Get TTL based on secret type."""
        for secret_type, ttl in self.ttl_overrides.items():
            if secret_type in key.lower():
                return ttl
        return self.default_ttl
    
    def _is_expired(self, cache_entry: Dict[str, Any]) -> bool:
        expiry = cache_entry["expires_at"]
        return datetime.now() >= expiry
    
    async def get_secret(self, key: str) -> str:
        # Check cache first
        if key in self.cache and not self._is_expired(self.cache[key]):
            return self.cache[key]["value"]
        
        # Cache miss or expired - fetch from provider
        config = await get_config_manager()
        secret = await config.get_secret(key)
        
        # Cache the result
        ttl = self._get_ttl(key)
        self.cache[key] = {
            "value": secret,
            "expires_at": datetime.now() + timedelta(seconds=ttl),
            "cached_at": datetime.now()
        }
        
        return secret
    
    def invalidate(self, key: str):
        """Manually invalidate a cached secret."""
        if key in self.cache:
            del self.cache[key]
    
    def clear_cache(self):
        """Clear all cached secrets."""
        self.cache.clear()

# Global cache instance
secret_cache = SmartSecretCache()

# Usage
api_key = await secret_cache.get_secret("api/stripe-key")

# Invalidate when secret is rotated
secret_cache.invalidate("api/stripe-key")
```

#### 2. **Batch Secret Loading**

```python
from anysecret import get_config_manager
from typing import List, Dict

class BatchSecretLoader:
    @staticmethod
    async def load_service_secrets(service_name: str) -> Dict[str, str]:
        """Load all secrets for a service in one batch."""
        config = await get_config_manager()
        
        # Use prefix loading for efficiency
        secrets = await config.get_secrets_by_prefix(f"{service_name}/")
        parameters = await config.get_parameters_by_prefix(f"{service_name}/")
        
        return {**secrets, **parameters}
    
    @staticmethod
    async def preload_secrets(secret_keys: List[str]) -> Dict[str, str]:
        """Preload multiple secrets concurrently."""
        config = await get_config_manager()
        
        # Load secrets concurrently
        tasks = [config.get_secret(key) for key in secret_keys]
        values = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build result dict, handling exceptions
        result = {}
        for key, value in zip(secret_keys, values):
            if isinstance(value, Exception):
                print(f"Failed to load secret {key}: {value}")
            else:
                result[key] = value
        
        return result

# Usage at application startup
async def initialize_app():
    # Preload critical secrets
    critical_secrets = [
        "database/password",
        "api/stripe-key", 
        "auth/jwt-secret"
    ]
    
    secrets = await BatchSecretLoader.preload_secrets(critical_secrets)
    
    # Store in app context or global cache
    app.state.secrets = secrets
```

### Connection Pooling

#### 1. **Provider Connection Management**

```python
import asyncio
from contextlib import asynccontextmanager
from anysecret import get_config_manager

class ConnectionPoolManager:
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self.semaphore = asyncio.Semaphore(max_connections)
        self._config_manager = None
    
    async def get_config_manager(self):
        """Reuse config manager instance."""
        if self._config_manager is None:
            self._config_manager = await get_config_manager()
        return self._config_manager
    
    @asynccontextmanager
    async def get_secret_connection(self):
        """Manage connections to secret providers."""
        async with self.semaphore:
            config = await self.get_config_manager()
            try:
                yield config
            finally:
                # Cleanup if needed
                pass

# Global connection pool
connection_pool = ConnectionPoolManager(max_connections=5)

# Usage
async def get_database_credentials():
    async with connection_pool.get_secret_connection() as config:
        password = await config.get_secret("database/password")
        return password
```

## 🏗️ Architecture Best Practices

### Service Architecture

#### 1. **Centralized Secret Service Pattern**

```python
from fastapi import FastAPI, Depends
from anysecret import get_config_manager, ConfigManagerInterface

app = FastAPI()

# Centralized secret service
class SecretService:
    def __init__(self):
        self._config = None
    
    async def get_config(self) -> ConfigManagerInterface:
        if self._config is None:
            self._config = await get_config_manager()
        return self._config
    
    async def get_database_config(self):
        config = await self.get_config()
        return {
            "host": await config.get_parameter("database/host"),
            "port": await config.get_parameter("database/port", default=5432),
            "username": await config.get_parameter("database/username"),
            "password": await config.get_secret("database/password"),
            "database": await config.get_parameter("database/name")
        }
    
    async def get_api_keys(self):
        config = await self.get_config()
        return {
            "stripe": await config.get_secret("api/stripe-key"),
            "sendgrid": await config.get_secret("api/sendgrid-key"),
            "aws_access_key": await config.get_secret("api/aws-access-key")
        }

# Global service instance
secret_service = SecretService()

# Dependency injection
async def get_secret_service() -> SecretService:
    return secret_service

# Usage in endpoints
@app.get("/health")
async def health_check(secrets: SecretService = Depends(get_secret_service)):
    try:
        db_config = await secrets.get_database_config()
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
```

#### 2. **Multi-Environment Configuration**

```python
import os
from enum import Enum
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

class Environment(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class EnvironmentConfigFactory:
    @staticmethod
    def create_config(env: Environment) -> ConfigManagerConfig:
        base_config = {
            "cache_ttl": 300,
            "environment": env.value
        }
        
        if env == Environment.DEVELOPMENT:
            return ConfigManagerConfig(
                # Development: File-based for easy setup
                secret_manager_type=ManagerType.ENV_FILE,
                secret_config={"file_path": ".env.dev"},
                parameter_manager_type=ManagerType.ENV_FILE,
                parameter_config={"file_path": ".env.dev"},
                **base_config
            )
        
        elif env == Environment.STAGING:
            return ConfigManagerConfig(
                # Staging: Cloud-based with fallback
                secret_manager_type=ManagerType.AWS,
                secret_config={"region": "us-east-1"},
                parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
                parameter_config={"region": "us-east-1"},
                
                # File fallback for staging
                secret_fallback_type=ManagerType.ENV_FILE,
                secret_fallback_config={"file_path": ".env.staging"},
                **base_config
            )
        
        else:  # PRODUCTION
            return ConfigManagerConfig(
                # Production: Multi-region cloud setup
                secret_manager_type=ManagerType.AWS,
                secret_config={"region": "us-east-1"},
                parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
                parameter_config={"region": "us-east-1"},
                
                # Cross-region fallback
                secret_fallback_type=ManagerType.AWS,
                secret_fallback_config={"region": "us-west-2"},
                parameter_fallback_type=ManagerType.AWS_PARAMETER_STORE,
                parameter_fallback_config={"region": "us-west-2"},
                
                cache_ttl=600,  # Longer cache in production
                **base_config
            )

# Usage
def get_current_environment() -> Environment:
    env_name = os.getenv("ENVIRONMENT", "development").lower()
    return Environment(env_name)

async def initialize_config_manager():
    env = get_current_environment()
    config = EnvironmentConfigFactory.create_config(env)
    return await get_config_manager(config=config)
```

### Error Handling & Resilience

#### 1. **Circuit Breaker Pattern**

```python
import asyncio
from datetime import datetime, timedelta
from enum import Enum
from anysecret import get_config_manager, ProviderError

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"         # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = timedelta(seconds=recovery_timeout)
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
    
    def _should_attempt_reset(self) -> bool:
        return (
            self.state == CircuitState.OPEN and 
            self.last_failure_time and
            datetime.now() - self.last_failure_time > self.recovery_timeout
        )
    
    async def call(self, func, *args, **kwargs):
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            
            # Success - reset circuit breaker
            if self.state == CircuitState.HALF_OPEN:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
            
            return result
            
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = datetime.now()
            
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
            
            raise

class ResilientSecretManager:
    def __init__(self):
        self.circuit_breaker = CircuitBreaker()
        self.cache = {}
    
    async def get_secret(self, key: str, use_cache_on_failure: bool = True):
        async def _get_secret():
            config = await get_config_manager()
            return await config.get_secret(key)
        
        try:
            # Try to get secret through circuit breaker
            secret = await self.circuit_breaker.call(_get_secret)
            
            # Cache successful results
            self.cache[key] = secret
            return secret
            
        except Exception as e:
            # Use cached value if available and allowed
            if use_cache_on_failure and key in self.cache:
                print(f"Using cached value for {key} due to error: {e}")
                return self.cache[key]
            
            raise

# Usage
resilient_secrets = ResilientSecretManager()
api_key = await resilient_secrets.get_secret("api/stripe-key")
```

#### 2. **Retry with Exponential Backoff**

```python
import asyncio
import random
from typing import Callable, Any
from anysecret import get_config_manager, ProviderError

class RetryManager:
    @staticmethod
    async def retry_with_backoff(
        func: Callable,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter: bool = True
    ) -> Any:
        """Retry function with exponential backoff and jitter."""
        
        for attempt in range(max_retries + 1):
            try:
                return await func()
            
            except ProviderError as e:
                # Don't retry non-retryable errors
                if not getattr(e, 'retryable', True) or attempt == max_retries:
                    raise
                
                # Calculate delay with exponential backoff
                delay = min(base_delay * (2 ** attempt), max_delay)
                
                # Add jitter to prevent thundering herd
                if jitter:
                    delay = delay * (0.5 + random.random() * 0.5)
                
                print(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay:.2f}s...")
                await asyncio.sleep(delay)
            
            except Exception as e:
                # Don't retry unexpected errors
                if attempt == max_retries:
                    raise
                
                print(f"Unexpected error on attempt {attempt + 1}: {e}")
                await asyncio.sleep(base_delay)

# Usage
async def get_secret_with_retry(key: str) -> str:
    async def _get_secret():
        config = await get_config_manager()
        return await config.get_secret(key)
    
    return await RetryManager.retry_with_backoff(
        _get_secret,
        max_retries=3,
        base_delay=1.0,
        max_delay=10.0
    )

# Example usage
try:
    api_key = await get_secret_with_retry("api/stripe-key")
except Exception as e:
    print(f"Failed to get secret after retries: {e}")
```

## 🔄 CI/CD Best Practices

### Deployment Pipeline Integration

#### 1. **Secure Secret Injection in CI/CD**

```bash
# GitHub Actions Example
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
      uses: actions/setup-python@v3
      with:
        python-version: '3.9'
    
    - name: Install AnySecret
      run: pip install anysecret-io[aws]
    
    - name: Configure AWS Credentials
      uses: aws-actions/configure-aws-credentials@v1
      with:
        role-to-assume: arn:aws:iam::ACCOUNT:role/github-actions-role
        aws-region: us-east-1
    
    - name: Load Configuration
      run: |
        # Load secrets into environment for deployment
        export DB_PASSWORD=$(anysecret get prod/database/password)
        export API_KEY=$(anysecret get prod/api/stripe-key)
        
        # Deploy with environment variables
        ./deploy.sh
      env:
        SECRET_MANAGER_TYPE: aws
        AWS_REGION: us-east-1
```

```bash
# Jenkins Pipeline Example
pipeline {
    agent any
    
    environment {
        SECRET_MANAGER_TYPE = 'aws'
        AWS_REGION = 'us-east-1'
    }
    
    stages {
        stage('Load Secrets') {
            steps {
                script {
                    // Load secrets using AnySecret CLI
                    env.DB_PASSWORD = sh(
                        script: 'anysecret get prod/database/password',
                        returnStdout: true
                    ).trim()
                    
                    env.API_KEY = sh(
                        script: 'anysecret get prod/api/stripe-key',
                        returnStdout: true
                    ).trim()
                }
            }
        }
        
        stage('Deploy') {
            steps {
                sh './deploy.sh'
            }
        }
    }
    
    post {
        always {
            // Clear sensitive environment variables
            sh 'unset DB_PASSWORD API_KEY'
        }
    }
}
```

#### 2. **Environment-Specific Deployments**

```python
# deployment_config.py
import os
from anysecret import get_config_manager

class DeploymentConfig:
    @staticmethod
    async def generate_kubernetes_secrets(environment: str, namespace: str):
        """Generate Kubernetes secret manifests from AnySecret."""
        
        # Set environment-specific provider
        os.environ['SECRET_MANAGER_TYPE'] = 'aws'
        os.environ['AWS_REGION'] = 'us-east-1' if environment == 'prod' else 'us-west-2'
        
        config = await get_config_manager()
        
        # Get all secrets for the environment
        secrets = await config.get_secrets_by_prefix(f"{environment}/")
        
        # Generate Kubernetes secret YAML
        secret_data = {}
        for key, value in secrets.items():
            # Remove environment prefix for k8s secret keys
            k8s_key = key.replace(f"{environment}/", "").replace("/", "-")
            secret_data[k8s_key] = value
        
        return {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": f"app-secrets-{environment}",
                "namespace": namespace
            },
            "type": "Opaque",
            "stringData": secret_data
        }

# Usage in deployment script
import yaml

async def deploy_to_kubernetes():
    environments = ["staging", "prod"]
    
    for env in environments:
        secret_manifest = await DeploymentConfig.generate_kubernetes_secrets(
            environment=env,
            namespace=env
        )
        
        # Write to file
        with open(f"k8s-secrets-{env}.yaml", "w") as f:
            yaml.dump(secret_manifest, f)
        
        print(f"Generated secrets for {env} environment")
```

### Configuration Validation

#### 1. **Pre-Deployment Secret Validation**

```python
#!/usr/bin/env python3
"""
Pre-deployment secret validation script
Usage: python validate_secrets.py --environment prod
"""

import asyncio
import argparse
import sys
from typing import List, Dict, Any
from anysecret import get_config_manager, SecretNotFoundError

class SecretValidator:
    def __init__(self, environment: str):
        self.environment = environment
        
        # Define required secrets per environment
        self.required_secrets = {
            "prod": [
                "database/password",
                "api/stripe-key",
                "auth/jwt-secret",
                "email/sendgrid-api-key"
            ],
            "staging": [
                "database/password",
                "api/stripe-key-test",
                "auth/jwt-secret"
            ],
            "dev": [
                "database/password",
                "auth/jwt-secret"
            ]
        }
        
        # Define required parameters
        self.required_parameters = {
            "prod": [
                "database/host",
                "database/port",
                "api/timeout",
                "log/level"
            ],
            "staging": [
                "database/host", 
                "database/port",
                "api/timeout"
            ],
            "dev": [
                "database/host"
            ]
        }
    
    async def validate_all(self) -> bool:
        """Validate all required secrets and parameters."""
        config = await get_config_manager()
        
        success = True
        
        # Validate secrets
        secrets = self.required_secrets.get(self.environment, [])
        for secret_key in secrets:
            env_key = f"{self.environment}/{secret_key}"
            try:
                value = await config.get_secret(env_key)
                if not value:
                    print(f"❌ Secret {env_key} is empty")
                    success = False
                else:
                    print(f"✅ Secret {env_key} found")
            except SecretNotFoundError:
                print(f"❌ Secret {env_key} not found")
                success = False
        
        # Validate parameters
        parameters = self.required_parameters.get(self.environment, [])
        for param_key in parameters:
            env_key = f"{self.environment}/{param_key}"
            try:
                value = await config.get_parameter(env_key)
                print(f"✅ Parameter {env_key} = {value}")
            except Exception as e:
                print(f"❌ Parameter {env_key} error: {e}")
                success = False
        
        return success
    
    async def validate_secret_formats(self) -> bool:
        """Validate secret formats match expected patterns."""
        config = await get_config_manager()
        
        format_checks = {
            f"{self.environment}/api/stripe-key": r"^sk_(live|test)_[a-zA-Z0-9]{24,}$",
            f"{self.environment}/auth/jwt-secret": r"^[a-zA-Z0-9]{32,}$"
        }
        
        success = True
        for secret_key, pattern in format_checks.items():
            try:
                value = await config.get_secret(secret_key)
                import re
                if not re.match(pattern, value):
                    print(f"❌ Secret {secret_key} format invalid")
                    success = False
                else:
                    print(f"✅ Secret {secret_key} format valid")
            except Exception as e:
                print(f"❌ Cannot validate {secret_key}: {e}")
                success = False
        
        return success

async def main():
    parser = argparse.ArgumentParser(description="Validate deployment secrets")
    parser.add_argument("--environment", required=True, 
                       choices=["dev", "staging", "prod"],
                       help="Environment to validate")
    
    args = parser.parse_args()
    
    print(f"🔍 Validating secrets for {args.environment} environment...")
    
    validator = SecretValidator(args.environment)
    
    # Run all validations
    basic_validation = await validator.validate_all()
    format_validation = await validator.validate_secret_formats()
    
    if basic_validation and format_validation:
        print("✅ All validations passed!")
        sys.exit(0)
    else:
        print("❌ Validation failed!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
```

## 📊 Monitoring & Observability

### Metrics and Alerting

#### 1. **Secret Access Metrics**

```python
import time
from typing import Dict, Any
from prometheus_client import Counter, Histogram, Gauge
from anysecret import get_config_manager

# Prometheus metrics
secret_requests_total = Counter(
    'anysecret_requests_total',
    'Total number of secret requests',
    ['provider', 'environment', 'status']
)

secret_request_duration = Histogram(
    'anysecret_request_duration_seconds',
    'Secret request duration',
    ['provider', 'secret_type']
)

cached_secrets_gauge = Gauge(
    'anysecret_cached_secrets',
    'Number of cached secrets',
    ['provider']
)

class MetricsSecretManager:
    def __init__(self, environment: str):
        self.environment = environment
        self.cache_stats = {"hits": 0, "misses": 0}
    
    async def get_secret_with_metrics(self, key: str) -> str:
        config = await get_config_manager()
        provider_name = config.provider_name
        
        start_time = time.time()
        
        try:
            # Attempt to get secret
            secret = await config.get_secret(key)
            
            # Record success metrics
            secret_requests_total.labels(
                provider=provider_name,
                environment=self.environment,
                status='success'
            ).inc()
            
            secret_request_duration.labels(
                provider=provider_name,
                secret_type=self._get_secret_type(key)
            ).observe(time.time() - start_time)
            
            return secret
            
        except Exception as e:
            # Record failure metrics
            secret_requests_total.labels(
                provider=provider_name,
                environment=self.environment,
                status='error'
            ).inc()
            
            raise
    
    def _get_secret_type(self, key: str) -> str:
        """Classify secret type for metrics."""
        if 'database' in key:
            return 'database'
        elif 'api' in key:
            return 'api_key'
        elif 'auth' in key:
            return 'auth'
        else:
            return 'other'

# Usage
metrics_manager = MetricsSecretManager("production")
api_key = await metrics_manager.get_secret_with_metrics("api/stripe-key")
```

#### 2. **Health Checks**

```python
from fastapi import FastAPI, HTTPException
from anysecret import get_config_manager, ProviderError

app = FastAPI()

@app.get("/health/secrets")
async def secret_health_check():
    """Health check endpoint for secret provider connectivity."""
    
    try:
        config = await get_config_manager()
        
        # Test connectivity by trying to list secrets
        secrets = await config.list_secrets()
        
        return {
            "status": "healthy",
            "provider": config.provider_name,
            "region": config.region,
            "secret_count": len(secrets),
            "timestamp": time.time()
        }
        
    except ProviderError as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "provider": getattr(e, 'provider', 'unknown'),
            "timestamp": time.time()
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Health check failed: {str(e)}"
        )

@app.get("/health/secrets/detailed")
async def detailed_secret_health_check():
    """Detailed health check with specific secret validation."""
    
    config = await get_config_manager()
    
    # Test specific critical secrets
    critical_secrets = [
        "database/password",
        "api/stripe-key", 
        "auth/jwt-secret"
    ]
    
    results = {}
    overall_healthy = True
    
    for secret_key in critical_secrets:
        try:
            # Don't retrieve the actual value, just check if it exists
            await config.get_secret(secret_key)
            results[secret_key] = {"status": "available"}
            
        except Exception as e:
            results[secret_key] = {
                "status": "error",
                "error": str(e)
            }
            overall_healthy = False
    
    return {
        "status": "healthy" if overall_healthy else "degraded",
        "provider": config.provider_name,
        "secrets": results,
        "timestamp": time.time()
    }
```

## 🔄 Migration Best Practices

### Zero-Downtime Provider Migration

```python
import asyncio
from typing import Dict, Any, Optional
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

class MigrationManager:
    def __init__(self, 
                 source_config: ConfigManagerConfig,
                 target_config: ConfigManagerConfig):
        self.source_config = source_config
        self.target_config = target_config
    
    async def migrate_secrets(self, 
                            secret_keys: list,
                            batch_size: int = 10,
                            dry_run: bool = True) -> Dict[str, Any]:
        """Migrate secrets from source to target provider."""
        
        source_manager = await get_config_manager(self.source_config)
        target_manager = await get_config_manager(self.target_config)
        
        results = {
            "migrated": [],
            "failed": [],
            "skipped": []
        }
        
        # Process secrets in batches
        for i in range(0, len(secret_keys), batch_size):
            batch = secret_keys[i:i + batch_size]
            
            for secret_key in batch:
                try:
                    # Get secret from source
                    value = await source_manager.get_secret(secret_key)
                    
                    if not dry_run:
                        # Write to target (implement based on target provider)
                        await self._write_secret_to_target(
                            target_manager, secret_key, value
                        )
                    
                    results["migrated"].append(secret_key)
                    print(f"✅ {'[DRY RUN] ' if dry_run else ''}Migrated: {secret_key}")
                    
                except Exception as e:
                    results["failed"].append({
                        "key": secret_key,
                        "error": str(e)
                    })
                    print(f"❌ Failed to migrate {secret_key}: {e}")
            
            # Small delay between batches
            await asyncio.sleep(0.1)
        
        return results
    
    async def _write_secret_to_target(self, 
                                    target_manager,
                                    key: str, 
                                    value: str):
        """Write secret to target provider (implement per provider)."""
        # This would need provider-specific implementation
        # For now, this is a placeholder
        pass
    
    async def validate_migration(self, secret_keys: list) -> bool:
        """Validate that all secrets exist in both source and target."""
        
        source_manager = await get_config_manager(self.source_config)
        target_manager = await get_config_manager(self.target_config)
        
        all_valid = True
        
        for secret_key in secret_keys:
            try:
                source_value = await source_manager.get_secret(secret_key)
                target_value = await target_manager.get_secret(secret_key)
                
                if source_value == target_value:
                    print(f"✅ {secret_key}: Values match")
                else:
                    print(f"❌ {secret_key}: Values differ")
                    all_valid = False
                    
            except Exception as e:
                print(f"❌ {secret_key}: Validation failed: {e}")
                all_valid = False
        
        return all_valid

# Usage example: AWS -> GCP migration
async def migrate_aws_to_gcp():
    source_config = ConfigManagerConfig(
        secret_manager_type=ManagerType.AWS,
        secret_config={"region": "us-east-1"}
    )
    
    target_config = ConfigManagerConfig(
        secret_manager_type=ManagerType.GCP,
        secret_config={"project_id": "my-project"}
    )
    
    migrator = MigrationManager(source_config, target_config)
    
    secrets_to_migrate = [
        "prod/database/password",
        "prod/api/stripe-key",
        "prod/auth/jwt-secret"
    ]
    
    # Dry run first
    print("Running migration dry run...")
    results = await migrator.migrate_secrets(secrets_to_migrate, dry_run=True)
    
    if len(results["failed"]) == 0:
        print("Dry run successful! Proceeding with actual migration...")
        await migrator.migrate_secrets(secrets_to_migrate, dry_run=False)
        
        # Validate migration
        if await migrator.validate_migration(secrets_to_migrate):
            print("✅ Migration completed successfully!")
        else:
            print("❌ Migration validation failed!")
    else:
        print(f"❌ Dry run failed. Fix {len(results['failed'])} errors first.")
```

## 📚 Summary

Following these best practices will help you:

- **🔐 Secure**: Protect secrets with proper access control and validation
- **⚡ Fast**: Optimize performance with smart caching and connection pooling
- **🏗️ Scalable**: Build resilient architectures with proper error handling
- **🔄 Deployable**: Integrate smoothly with CI/CD pipelines
- **📊 Observable**: Monitor and alert on secret management operations
- **🚀 Migratable**: Seamlessly move between providers

For more specific guidance, see our other documentation:
- [Provider Setup](providers.md) - Detailed provider configurations
- [API Reference](api.md) - Complete API documentation  
- [Migration Guide](migration.md) - Provider migration strategies

---

*These practices are based on production deployments across thousands of applications. Adapt them to your specific security requirements and operational constraints.*
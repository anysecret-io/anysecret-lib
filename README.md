# AnySecret Library - Open Source Universal Secret Management

[![PyPI version](https://img.shields.io/pypi/v/anysecret-io.svg)](https://pypi.org/project/anysecret-io/)
[![Python Support](https://img.shields.io/pypi/pyversions/anysecret-io.svg)](https://pypi.org/project/anysecret-io/)
[![Tests](https://github.com/anysecret-io/anysecret-lib/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/anysecret-io/anysecret-lib/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Open source Python library for universal secret and configuration management across all major cloud providers.**

## Overview

This is the core open source library that powers AnySecret.io. It provides a unified interface for secret and configuration management across AWS, Google Cloud, Azure, Kubernetes, HashiCorp Vault, and local file systems.

## Key Features

- **🚀 Universal API** - Single interface for all providers
- **🤖 Smart Classification** - Automatic routing of secrets vs parameters  
- **🔄 Multi-Cloud** - AWS, GCP, Azure, K8s, Vault support
- **⚡ Async First** - Built for modern Python applications
- **🛡️ Security-Focused** - No logging/caching of sensitive values
- **📦 Zero Config** - Auto-detects cloud environments

## Quick Start

### Installation

```bash
# Basic installation
pip install anysecret-io

# With cloud providers
pip install anysecret-io[aws,gcp,azure,k8s,vault]
```

### Basic Usage

```python
import asyncio
import anysecret

async def main():
    # Auto-classification handles routing
    db_password = await anysecret.get("database.password")  # → Secure storage
    db_host = await anysecret.get("database.host")          # → Config storage
    
    # Get all secrets for your app
    config = await anysecret.get_config_manager()
    secrets = await config.get_secrets_by_prefix("myapp")

asyncio.run(main())
```

### CLI Usage

```bash
# Get secrets/parameters
anysecret get database.password
anysecret get api.timeout

# List all
anysecret list

# Bulk operations
anysecret bulk export --output .env
anysecret bulk import secrets.json

# Provider management
anysecret providers list
anysecret config validate
```

## Architecture

### Core Components

- **`anysecret.config_manager`** - Main configuration manager with auto-classification
- **`anysecret.secret_manager`** - Base secret manager interface
- **`anysecret.parameter_manager`** - Base parameter manager interface
- **`anysecret.providers.*`** - Cloud provider implementations
- **`anysecret.cli.*`** - Command-line interface

### Provider Support

| Provider | Secrets | Parameters | Status |
|----------|---------|------------|--------|
| AWS | Secrets Manager | Parameter Store | ✅ Production |
| GCP | Secret Manager | Config Connector | ✅ Production |
| Azure | Key Vault | App Configuration | ✅ Production |
| Kubernetes | Secrets | ConfigMaps | ✅ Production |
| HashiCorp Vault | KV v1/v2 | KV v1/v2 | ✅ Production |
| Encrypted Files | AES-256 | JSON/YAML | ✅ Production |
| Environment Files | .env | .env | ✅ Production |

## Development

### Requirements

- Python 3.10+ (3.8/3.9 support dropped for modern compatibility)
- Optional cloud provider dependencies

### Setup

```bash
# Clone repository
git clone https://github.com/anysecret-io/anysecret-lib.git
cd anysecret-lib

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -e ".[dev,all]"

# Run tests
pytest

# Run specific test suites
python run_tests.py smoke    # Quick smoke tests
python run_tests.py cli      # CLI tests only
python run_tests.py unit     # Unit tests only
```

### Test Suite

- **246 passing tests** across all providers and functionality
- **20 integration tests** skipped (require cloud credentials)
- **Comprehensive coverage** of all core features
- **CI/CD integration** with GitHub Actions

### Code Quality

```bash
# Format code
black anysecret tests
isort anysecret tests

# Type checking
mypy anysecret

# Linting
flake8 anysecret
```

## Configuration

### Environment Detection

The library automatically detects your environment and configures appropriate providers:

```python
# AWS (auto-detected from EC2/Lambda/ECS)
import anysecret
config = await anysecret.get_config_manager()  # Uses AWS Secrets Manager

# GCP (auto-detected from GCE/Cloud Run/GKE)  
config = await anysecret.get_config_manager()  # Uses GCP Secret Manager

# Local development
config = await anysecret.get_config_manager()  # Uses .env files
```

### Manual Configuration

```python
from anysecret import ConfigManager

# Explicit provider configuration
config = ConfigManager({
    'secret_manager': {
        'type': 'aws',
        'region': 'us-west-2'
    },
    'parameter_manager': {
        'type': 'aws', 
        'region': 'us-west-2'
    }
})
```

## API Reference

### Core Methods

```python
# Get values with auto-classification
value = await anysecret.get(key, default=None, hint=None)

# Explicit secret retrieval
secret = await config.get_secret(key)
secret_with_meta = await config.get_secret_with_metadata(key)

# Explicit parameter retrieval  
param = await config.get_parameter(key)
param_with_meta = await config.get_parameter_with_metadata(key)

# Bulk operations
secrets = await config.get_secrets_by_prefix(prefix)
all_keys = await config.list_all_keys()

# Health checks
healthy = await config.health_check()
```

### Provider-Specific Managers

```python
# Direct provider access
from anysecret.providers import (
    AwsSecretManager, 
    GcpSecretManager,
    AzureSecretManager,
    VaultSecretManager
)

aws_manager = AwsSecretManager({'region': 'us-west-2'})
secret = await aws_manager.get_secret_with_metadata('api-key')
```

## Security Best Practices

1. **Never log secrets** - Library never logs sensitive values
2. **Use auto-classification** - Reduces risk of misconfiguration
3. **Environment-specific configs** - Different providers per environment
4. **Encrypted local storage** - For development environments
5. **Regular rotation** - Use provider native rotation features

## Contributing

### Bug Reports

1. Check existing [issues](https://github.com/anysecret-io/anysecret-lib/issues)
2. Include Python version, provider type, and error details
3. Provide minimal reproduction case

### Feature Requests

1. Open [GitHub Discussion](https://github.com/anysecret-io/anysecret-lib/discussions)
2. Describe use case and expected behavior
3. Check if it fits with existing architecture

### Pull Requests

1. Fork the repository
2. Create feature branch from `main`
3. Add tests for new functionality
4. Ensure all tests pass: `pytest`
5. Follow existing code style
6. Update documentation if needed

## License

**MIT License**

- ✅ Free for all users and commercial use
- ✅ Modify and distribute freely
- ✅ Use in proprietary software
- ✅ No copyleft requirements
- ✅ Private use and commercial distribution allowed

AnySecret is and will always be free and open source under the MIT license.

## Links

- **Documentation**: [docs.anysecret.io](https://docs.anysecret.io/)
- **PyPI Package**: [pypi.org/project/anysecret-io](https://pypi.org/project/anysecret-io)
- **Homepage**: [anysecret.io](https://anysecret.io/)
- **LLM Chat Agent**: [chat.anysecret.io](https://chat.anysecret.io/)
- **Discord**: [discord.gg/Js9pnRuQ](https://discord.gg/Js9pnRuQ)
- **Issues**: [GitHub Issues](https://github.com/anysecret-io/anysecret-lib/issues)
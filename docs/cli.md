# AnySecret CLI Reference

## Abstract

AnySecret is a universal configuration and secret management system that intelligently routes configuration data between secrets and parameters based on naming patterns, optimizing for both security and cost.

**Core Concept:**
- **Primary Provider**: Your main configuration source (AWS, GCP, Azure, Kubernetes, local files, etc.)
- **Fallback Provider**: Optional secondary source checked when values aren't found in primary
- **Intelligent Classification**: Automatically routes sensitive data (API_KEY, PASSWORD) to secret managers and configuration data (HOST, PORT, TIMEOUT) to parameter stores
- **Environment Auto-detection**: Detects cloud environment and suggests optimal provider configuration
- **Incremental Configuration**: Starts simple with auto-detection, allows more complex setups as needed

**Our Approach to Configuration Management:**

AnySecret.io is first and foremost a **secret management system**. Configuration management is treated as a secondary concern with a pragmatic approach:

1. **Secrets First**: Core focus on secure secret management using cloud-native secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault)

2. **Cost-Effective Parameters**: For configuration parameters, we prioritize cost efficiency over complex features:
   - **Cloud Storage Backend**: Uses S3, GCS, Azure Blob for parameter storage (pennies vs dollars)
   - **File-Based Approach**: Reuses proven file formats (.json, .env, .yaml, encrypted) with cloud storage
   - **Batch Operations**: Store multiple parameters in single files for optimal performance

3. **Extensible Architecture**: Clean separation allows adding native parameter stores (Firebase Remote Config, AWS Parameter Store) as dedicated providers later

4. **No Wheel Reinvention**: Leverages existing file-based parameter management with cloud storage backends rather than building custom parameter management systems

**Benefits:**
- **Cost Optimization**: Parameters cost pennies in cloud storage vs hundreds/month in secret managers
- **Security**: Sensitive data automatically uses secure, encrypted secret managers
- **Simplicity**: Single interface across all providers with intelligent defaults
- **Performance**: Fast bulk reads for configuration (single file = hundreds of parameters)
- **Reliability**: Fallback providers ensure availability
- **Flexibility**: Works in any environment from local development to multi-cloud production

The CLI provides a unified interface for get/set operations that automatically use the right provider for the right data type, with cost-optimized parameter storage and enterprise-grade secret management.

---

## Quick Start

```bash
# 1. Setup your cloud profile
anysecret config profile-create gcp-prod

# 2. Import .env to cloud (intelligent routing)
anysecret bulk import .env
# → API_KEY goes to GCP Secret Manager (~$0.40/month)  
# → DATABASE_HOST goes to GCS Storage (~$0.01/month)

# 3. Export profile for CI/CD
anysecret config profile-export gcp-prod
# Copy base64 to GitHub Actions secrets

# 4. In CI/CD: Pull configs to .env
CI=true anysecret --profile-data "$PROFILE_DATA" \
  bulk export --output .env.production

# 5. Use in production  
docker run --env-file .env.production myapp
```

## Example Flow

Complete CI/CD workflow demonstrating the 8-step process:

### Step 1-3: Local Development Setup
```bash
# (a) Configure local profile (file-based)
anysecret config profile-create local-dev

# (b) Add secrets and parameters locally
anysecret set DATABASE_URL "postgresql://localhost/myapp"
anysecret set API_KEY "sk_dev_123"
anysecret set DATABASE_HOST "localhost"
anysecret set LOG_LEVEL "debug"

# (c) Create cloud-based profile for production
anysecret config profile-create gcp-prod
```

### Step 4: Push Configuration to Cloud
```bash
# (d) Import .env to GCP with intelligent classification
anysecret bulk import .env
# → API_KEY → GCP Secret Manager (~$0.40/month)
# → DATABASE_HOST → GCS Storage (~$0.01/month)
# → Automatic classification by naming patterns
```

### Step 5: Export Profile for CI/CD
```bash
# (e) Export profile configuration for GitHub Actions
anysecret config profile-export gcp-prod --base64
# Copy the base64 output to GitHub Actions secrets as ANYSECRET_PROFILE

# With encryption for extra security:
anysecret config profile-export gcp-prod --base64 --encrypt
# Use --decrypt flag when importing encrypted profiles
```

### Step 6-8: CI/CD and Production
```bash
# (f-g) In CI/CD: Pull profile and export to production .env
CI=true anysecret --profile-data "$ANYSECRET_PROFILE" \
  bulk export --parameters-only --output .env.production

# With encrypted profile:
CI=true anysecret --profile-data "$ENCRYPTED_PROFILE" --decrypt \
  bulk export --parameters-only --output .env.production

# (h) Use in production
docker run --env-file .env.production myapp
```

### Security Variations
```bash
# Show secrets in terminal (use with caution)
anysecret bulk export --show-secrets --output .env.local

# Export everything including secrets (CI mode auto-confirms)
CI=true anysecret bulk export --output .env.production

# Preview what would be exported (secrets masked)
anysecret bulk export --dry-run
```

## Core Commands

### Configuration
```bash
anysecret config init                    # Interactive setup wizard
anysecret config profile-create <name>  # Create new profile  
anysecret config profile-use <name>     # Switch profile
anysecret config profile-list           # List profiles
anysecret config profile-export <name>  # Export for CI/CD (base64)
anysecret config profile-export <name> --encrypt  # Export with encryption
anysecret config validate               # Check configuration
```

### Basic Operations
```bash
anysecret list                          # Show all keys with types
anysecret list --show-secrets           # Show parameter values and secrets  
anysecret get <key>                     # Get value (secrets masked)
anysecret get <key> --show-secrets      # Show actual secret value
anysecret set <key> <value>             # Set with auto-classification
anysecret set <key> <value> --hint secret  # Force as secret
```

### Bulk Operations  
```bash
# Import: .env → Cloud
anysecret bulk import .env                    # Auto-classify and upload
anysecret bulk import --format json config.json
anysecret bulk import --dry-run .env          # Preview classification
anysecret bulk import --prefix "APP_" .env    # Add prefix to keys

# Export: Cloud → .env  
anysecret bulk export --output .env           # Download all (needs confirmation)
anysecret bulk export --show-secrets -o .env  # Show secrets in terminal
anysecret bulk export --parameters-only -o params.env  # Safer option
anysecret bulk export --format json -o config.json     # JSON format
anysecret bulk export --dry-run               # Preview (secrets masked)
```

### CI/CD Integration
```bash
# Runtime profile override
anysecret --profile-data <base64> bulk export --output .env

# With encrypted profile data
anysecret --profile-data <encrypted_base64> --decrypt bulk export --output .env

# Environment variable support  
export ANYSECRET_PROFILE_DATA="<base64>"
anysecret bulk export --output .env.production

# With encryption
export ANYSECRET_PROFILE_DATA="<encrypted_base64>"
anysecret --decrypt bulk export --output .env.production
```

### System Info
```bash
anysecret info                          # System and config info
anysecret status                        # Provider health status  
anysecret version                       # Version information
anysecret patterns                      # Show classification patterns
anysecret classify <key>                # Test how a key would be classified
```

### Advanced Read Operations
```bash
# Tree view of configuration
anysecret read tree                     # Hierarchical view
anysecret read tree --prefix "app" --depth 3  # Filtered tree

# Search across keys and values
anysecret read search "database"        # Search in key names
anysecret read search "api" --content   # Search in values too
anysecret read search "prod.*" --regex  # Regex pattern search

# Batch operations
anysecret read get-batch API_KEY,DB_HOST,TOKEN  # Get multiple keys
anysecret read get-batch --file keys.txt        # From file
anysecret read get-batch --fail-fast            # Stop on first error

# Environment export
anysecret read get-env                  # Export all as env vars
anysecret read get-env --prefix "PROD_" --uppercase  # Transform keys
anysecret read get-env --output .env.prod       # Save to file

# Detailed key information
anysecret read describe <key>           # Full metadata
anysecret read describe <key> --show-value --history  # With value & versions
```

### Advanced Write Operations
```bash
# Enhanced set with options
anysecret write set <key> <value> --json        # JSON value
anysecret write set <key> <value> --base64      # Base64 decode
anysecret write set <key> <value> --description "API token"
anysecret write set <key> <value> --tags "env=prod,team=backend"
anysecret write set <key> <value> --ttl 3600    # Expires in 1 hour
anysecret write set <key> <value> --if-not-exists  # Conditional

# Delete with options
anysecret delete <key> --force          # Skip confirmation
anysecret delete <key> --backup         # Create backup first
```

### Provider Management
```bash
anysecret providers list                # Show all providers
anysecret providers health              # Check all provider health
anysecret providers status              # Current profile's providers
```

## Security Features

- **Secrets masked by default** - Terminal shows `***`, files get real values
- **File permissions** - Auto-sets 600 when secrets included  
- **CI mode** - Set `CI=true` to auto-confirm prompts
- **Profile encryption** - Use `--encrypt` for extra security
- **Gitignore warnings** - Warns if output files not ignored

## Cost Optimization  

**Intelligent Classification:**
- `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_TOKEN` → Secret Managers (~$0.40/month per 10k)
- `*_HOST`, `*_PORT`, `*_URL`, `*_TIMEOUT` → Cloud Storage (~$0.01/month per 10k)

**Result:** 40x cost savings while maintaining enterprise security.

## Supported Providers

| Provider | Secrets | Parameters | Status |
|----------|---------|------------|---------|
| **Local Files** | .env files | JSON files | ✅ Full |
| **GCP** | Secret Manager | Cloud Storage | ✅ Full | 
| **AWS** | Secrets Manager | Parameter Store | 🚧 Partial |
| **Azure** | Key Vault | App Config | 🚧 Partial |

## Alternative Flows

### Flow 1: Multi-Format Data Management
```bash
# Import from various formats
anysecret bulk import config.json --format json
anysecret bulk import settings.yaml --format yaml
anysecret bulk import .env --prefix "APP_"

# Export to different formats for different environments
anysecret bulk export --format json --output config.json
anysecret bulk export --format yaml --output k8s-configmap.yaml
anysecret read get-env --uppercase --export --output docker.env
```

### Flow 2: Advanced Search and Discovery
```bash
# Find all database-related configuration
anysecret read search "database" --content
anysecret read tree --prefix "db_"

# Audit secret usage
anysecret list --secrets-only --format json | jq '.items[].key'
anysecret read search "password|token|key" --regex

# Describe configuration for documentation
anysecret read describe DATABASE_URL --show-value > docs/db-config.md
```

### Flow 3: Batch Operations for Microservices
```bash
# Service A configuration
anysecret read get-batch --file service-a/required-keys.txt \
  --output service-a/.env

# Service B with transformation
anysecret read get-env --prefix "SVC_B_" \
  --uppercase --output service-b/.env

# Validate all services have required configs
for service in service-*; do
  anysecret read get-batch --file $service/keys.txt --fail-fast
done
```

### Flow 4: Development to Production Pipeline
```bash
# Development: Local files
anysecret config profile-use local-dev
anysecret bulk import dev.env

# Staging: Hybrid approach
anysecret config profile-use staging
anysecret bulk import staging.env --dry-run  # Preview
anysecret bulk import staging.env

# Production: Full cloud with encryption
anysecret config profile-export staging --encrypt > profile.enc
# In production:
anysecret --profile-data "$(cat profile.enc)" --decrypt \
  bulk export --parameters-only --output .env.production
```

### Flow 5: Multi-Cloud Migration
```bash
# Export from AWS
anysecret config profile-use aws-prod
anysecret bulk export --format json --output aws-config.json

# Import to GCP
anysecret config profile-use gcp-prod  
anysecret bulk import aws-config.json --format json --dry-run
anysecret bulk import aws-config.json --format json

# Verify migration
anysecret providers health
anysecret read search "." --regex | wc -l  # Count all keys
```

### Flow 6: Security and Compliance Workflow
```bash
# Classify and audit keys
anysecret list --format json > audit-$(date +%Y%m%d).json
anysecret patterns  # Review classification rules

# Find potentially misclassified items
anysecret list --parameters-only | grep -i "password\|secret\|key"

# Describe sensitive keys for security review
for key in $(anysecret list --secrets-only --format json | jq -r '.items[].key'); do
  anysecret read describe "$key" --format json >> security-audit.json
done

# Health check all providers
anysecret providers health
```

### Flow 7: Environment-Specific Configuration
```bash
# Base configuration
anysecret bulk import base.env

# Override with environment-specific values
anysecret bulk import envs/production.env --prefix "PROD_"
anysecret bulk import envs/features.env --if-not-exists

# Export merged configuration
anysecret read get-env --output final.env

# Generate docker-compose override
anysecret read get-env --format yaml > docker-compose.override.yml
```

### Flow 8: Debugging and Troubleshooting
```bash
# Check what would be classified as secrets
anysecret classify MY_NEW_CONFIG_KEY

# Search for specific values
anysecret read search "localhost" --content  # Find dev configs
anysecret read search "prod-" --regex

# Tree view to understand structure
anysecret read tree --depth 2

# Batch validate critical keys exist
echo "API_KEY
DATABASE_URL  
REDIS_HOST" | anysecret read get-batch --file - --fail-fast

# Detailed inspection
anysecret read describe API_KEY --metadata --history
```

## CI/CD Examples

### GitHub Actions
```yaml
- name: Deploy with AnySecret
  env:
    ANYSECRET_PROFILE_DATA: ${{ secrets.ANYSECRET_PROFILE }}
    CI: true
  run: |
    pip install anysecret
    anysecret --profile-data "$ANYSECRET_PROFILE_DATA" \
      bulk export --parameters-only --output .env.production
    docker run --env-file .env.production myapp
```

### Local Development  
```bash
# Setup once
anysecret config profile-create local-dev
anysecret set DATABASE_URL "postgresql://localhost/myapp"
anysecret set API_KEY "sk_dev_123"

# Daily usage
anysecret bulk export --output .env
npm run dev
```

## Provider Implementation Status

The following table shows the implementation status of each command across different providers:

**Legend:**
- ✅ Implemented and tested
- 🔄 Partially implemented
- ⏳ Planned/Upcoming
- ❌ Not supported by provider

### Core Operations

| Operation | Local Files | GCP | AWS | Azure | Kubernetes | Vault |
|-----------|------------|-----|-----|-------|------------|-------|
| **get** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **set** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **delete** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **list** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Secret Management

| Provider | create_secret | get_secret | update_secret | delete_secret | list_secrets |
|----------|--------------|------------|---------------|---------------|--------------|
| **Local (.env)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Local (encrypted)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **GCP Secret Manager** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AWS Secrets Manager** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Azure Key Vault** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Kubernetes Secrets** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **HashiCorp Vault** | ✅ | ✅ | ✅ | ✅ | ✅ |

### Parameter Management

| Provider | create_parameter | get_parameter | update_parameter | delete_parameter | list_parameters |
|----------|-----------------|---------------|------------------|------------------|-----------------|
| **Local (JSON)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Local (YAML)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **GCS Storage** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AWS S3** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AWS Parameter Store** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Azure Blob Storage** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Azure App Config** | 🔄 | 🔄 | 🔄 | 🔄 | 🔄 |
| **Kubernetes ConfigMaps** | ✅ | ✅ | ✅ | ✅ | ✅ |

### Bulk Operations

| Operation | Local Files | GCP | AWS | Azure | Kubernetes |
|-----------|------------|-----|-----|-------|------------|
| **bulk import** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **bulk export** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **--format json** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **--format yaml** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **--format env** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **--dry-run** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **--prefix** | ✅ | ✅ | ✅ | ✅ | ✅ |

### Advanced Read Operations

| Operation | Local Files | GCP | AWS | Azure | Kubernetes | Vault |
|-----------|------------|-----|-----|-------|------------|-------|
| **read list** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **read tree** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **read search** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **read get-batch** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **read get-env** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **read describe** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **--format json/yaml** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Configuration & Profiles

| Feature | Status | Notes |
|---------|--------|-------|
| **config init** | ✅ | Interactive setup wizard |
| **config profile-create** | ✅ | All providers supported |
| **config profile-use** | ✅ | Switch between profiles |
| **config profile-list** | ✅ | List all profiles |
| **config profile-export** | ✅ | Base64 export for CI/CD |
| **config profile-export --encrypt** | ✅ | Encrypted profiles |
| **--profile-data** | ✅ | Runtime profile override |
| **config validate** | ✅ | Verify configuration |

### Provider-Specific Features

| Feature | GCP | AWS | Azure | Notes |
|---------|-----|-----|-------|-------|
| **Native SDK Integration** | ✅ | ✅ | ✅ | Using official SDKs |
| **IAM/RBAC Support** | ✅ | ✅ | ✅ | Via cloud provider IAM |
| **Versioning (Secrets)** | ✅ | ✅ | ✅ | Native version support |
| **Encryption at Rest** | ✅ | ✅ | ✅ | Provider-managed |
| **Cloud Storage Parameters** | ✅ GCS | ✅ S3 | ✅ Blob | Cost-optimized |
| **Health Monitoring** | ✅ | ✅ | ✅ | Via providers health |

### File Storage Formats

| Format | Secrets | Parameters | Import | Export |
|--------|---------|------------|--------|--------|
| **.env** | ✅ | ✅ | ✅ | ✅ |
| **JSON** | ✅ | ✅ | ✅ | ✅ |
| **YAML** | ✅ | ✅ | ✅ | ✅ |
| **Encrypted** | ✅ | ❌ | ✅ | ✅ |

## Planned CLI Enhancements

A few useful commands we're considering next:

```bash
# Secret rotation
anysecret rotate <key>                  # Rotate a secret with new value
anysecret rotate --all --older-than 90d # Rotate old secrets

# Diff and sync
anysecret diff prod staging             # Compare two profiles
anysecret sync --from prod --to staging # Copy configs between profiles

# Validation
anysecret validate --schema schema.json # Validate configs against schema
anysecret lint                          # Check for common issues

# Cost analysis
anysecret cost                          # Show current month costs
anysecret cost --optimize               # Suggest parameter vs secret moves
```

Got ideas? Let us know what CLI commands would make your life easier!

---

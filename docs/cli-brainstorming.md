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

The AnySecret CLI is a comprehensive command-line interface for universal configuration and secret management across multiple cloud providers and environments. It provides intelligent routing, cost optimization, and seamless integration with CI/CD pipelines.

## Quick Start: .env to Cloud Import

The most common workflow - importing local `.env` files to cloud providers with automatic cost optimization:

```bash
# 1. Configure your cloud profile (one-time setup)
anysecret config profile-use gcp-with-fallback    # or aws, azure

# 2. Preview your import (see what gets classified where)
anysecret bulk import .env --dry-run
# Shows table: API_KEY → GCP Secret Manager (~$0.40/month)
#              DATABASE_HOST → GCS Storage (~$0.01/month)

# 3. Import to cloud (automatic intelligent routing)
anysecret bulk import .env

# 4. Verify and use
anysecret list                                    # See all imported items
anysecret get API_KEY --raw                       # Retrieve from cloud
```

## CI/CD Integration Workflow

Perfect for GitHub Actions, GitLab CI, or any CI/CD system:

### Step 1: Export Profile (One-time setup)
```bash
# 🏠 LOCAL: Export profile for CI/CD use
anysecret config profile-export gcp-with-fallback
# Copy the base64 string to your CI/CD secrets as ANYSECRET_PROFILE_DATA
```

### Step 2: Push Configs to Cloud (Development)
```bash
# 🔧 DEV: Import local .env to cloud providers
anysecret bulk import .env
# Secrets → GCP Secret Manager (~$0.40/month)
# Parameters → GCS Storage (~$0.01/month)
```

### Step 3: Pull Configs in CI/CD (Build time)
```bash
# 🚀 CI/CD: Pull from cloud and create .env for deployment
export CI=true  # Auto-confirm prompts
anysecret --profile-data "$ANYSECRET_PROFILE_DATA" \
  bulk export --output .env.production

# Safer: Export only parameters, inject secrets at runtime
anysecret --profile-data "$ANYSECRET_PROFILE_DATA" \
  bulk export --parameters-only --output .env.production
```

### Step 4: Use in Production
```bash
# 🏭 PRODUCTION: Use the generated .env file
docker run --env-file .env.production myapp
# or
source .env.production && npm start
```

### Complete GitHub Actions Example
```yaml
name: Deploy to Production
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Pull configs from GCP
        env:
          ANYSECRET_PROFILE_DATA: ${{ secrets.ANYSECRET_PROFILE }}
          CI: true  # Auto-confirm security prompts
        run: |
          # Install anysecret
          pip install anysecret
          
          # Pull all configs from GCP
          anysecret --profile-data "$ANYSECRET_PROFILE_DATA" \
            bulk export --output .env.production
          
          # Set restrictive permissions
          chmod 600 .env.production
      
      - name: Build and deploy
        run: |
          docker build -t myapp .
          docker run --env-file .env.production myapp
```

### Security Best Practices
- Use `--parameters-only` when possible to avoid secrets in files
- Always set `CI=true` in CI/CD to auto-confirm prompts
- Delete `.env` files after use: `shred -vfz .env.production`
- Use encrypted profiles for extra security with `--encrypt`

**Key Benefits:**
- 🔐 **Security**: Secrets → enterprise secret managers (GCP/AWS/Azure)  
- 💰 **Cost**: Parameters → cheap cloud storage (40x cost reduction)
- 🤖 **Intelligence**: Automatic classification based on naming patterns
- 🚀 **Simple**: Single command imports entire configurations
- 🔄 **CI/CD Ready**: Export once, use anywhere with profile data

## Table of Contents

0. [Quick Start: .env to Cloud Import](#quick-start-env-to-cloud-import)
1. [Configuration and Metadata](#configuration-and-metadata)
2. [Write Permissions and Security](#write-permissions-and-security)
3. [ReadOnly List and Bulk Operations](#readonly-list-and-bulk-operations)
4. [Read Namespace Operations](#read-namespace-operations)
5. [ReadOnly Item Operations](#readonly-item-operations)
6. [Write Item Operations](#write-item-operations)
7. [Sync Migration](#sync-migration)
8. [Bulk Write Operations](#bulk-write-operations)
9. [Environment Management](#environment-management)
10. [CI/CD Integration](#cicd-integration)
11. [Multi-Cloud Coordination](#multi-cloud-coordination)
12. [Security and Compliance](#security-and-compliance)
13. [Performance and Monitoring](#performance-and-monitoring)
14. [Export and Import](#export-and-import)

---

## Configuration and Metadata

### Environment Detection and Configuration

```bash
# Show system information and current configuration
anysecret info
anysecret status
anysecret version

# Show available providers and their status
anysecret providers list
anysecret providers status
anysecret providers health

# Configuration management
anysecret config init                    # Interactive setup wizard
anysecret config validate               # Validate current configuration
anysecret config show                   # Display current configuration
anysecret config reset                  # Reset to default configuration
anysecret config backup                 # Backup current configuration

# Profile export/import for CI/CD
anysecret config profile-export [profile]           # Export profile as base64
anysecret config profile-export --encrypt [profile] # Export encrypted profile
anysecret config profile-export --no-base64         # Export as JSON
anysecret config profile-export -o file.txt         # Export to file
anysecret --profile-data <base64>                   # Use exported profile
anysecret config restore <backup-file>  # Restore from backup

# Environment profiles
anysecret config profile-create <name>    # Create configuration profile
anysecret config profile-list            # List available profiles
anysecret config profile-use <name>      # Switch to profile
anysecret config profile-delete <name>   # Delete profile
anysecret config profile-show <name>     # Show profile details

# Provider configuration
anysecret provider configure aws        # Configure AWS provider
anysecret provider configure gcp        # Configure GCP provider
anysecret provider configure azure      # Configure Azure provider
anysecret provider test <provider>      # Test provider connectivity
```

### Classification Patterns

```bash
# Pattern management
anysecret patterns show                        # Show all classification patterns
anysecret config patterns-add-secret <pattern> # Add secret pattern
anysecret config patterns-add-param <pattern>  # Add parameter pattern
anysecret config patterns-remove <pattern>     # Remove pattern
anysecret config patterns-test <key>           # Test key classification
anysecret config patterns-export               # Export patterns to file
anysecret config patterns-import <file>        # Import patterns from file
```

### Write Permissions and Security

AnySecret is **read-only by default** to prevent accidental modifications to secrets and configuration. Write operations must be explicitly enabled per profile.

```bash
# Check write permissions across all profiles
anysecret config check-permissions

# Enable writes with security warning (current profile)
anysecret config enable-writes

# Enable writes for specific profile
anysecret config enable-writes --profile production

# Disable writes (secure default)
anysecret config disable-writes

# Skip confirmation prompt
anysecret config enable-writes --yes
```

**Security Features:**
- ✅ **Read-only by default**: All profiles start as read-only
- ⚠️ **Explicit consent**: Write permissions require user confirmation
- 🔒 **Security warnings**: Clear warnings when enabling writes
- 📝 **Audit trail**: Tracks when/how permissions were changed
- 🛡️ **Profile isolation**: Each profile has independent write permissions

**Write operations include:**
- `set`, `delete`, `update` commands
- Bulk operations and migrations
- Configuration modifications
- Secret rotation and generation

---

## ReadOnly List and Bulk Operations

### List Operations

```bash
# Basic listing
anysecret list                          # List all keys with classification
anysecret list --prefix <prefix>        # Filter by prefix
anysecret list --secrets-only           # Show only secrets
anysecret list --parameters-only        # Show only parameters
anysecret list --values                  # Show parameter values (secrets hidden)
anysecret list --format table|json|yaml # Output format (table is default)

# Advanced filtering
anysecret list --pattern <regex>        # Filter by regex pattern
anysecret list --modified-since <date>  # Filter by modification date (not yet implemented)
anysecret list --created-since <date>   # Filter by creation date (not yet implemented)
anysecret list --tags <key=value>       # Filter by tags/metadata (not yet implemented)
anysecret list --provider <provider>    # Filter by provider (not yet implemented)

# Output format examples
anysecret list --format json            # JSON output with metadata
anysecret list --format yaml            # YAML output with metadata
anysecret list --format json --values    # Include parameter values in JSON

# Hierarchical view (also available in read namespace)
anysecret tree                          # Show hierarchical tree view
anysecret tree --depth <n>              # Limit tree depth
anysecret tree --prefix <prefix>        # Tree view with prefix filter

# Search operations (also available in read namespace)
anysecret search <query>                # Search keys and descriptions
anysecret search --content <query>      # Search in values (parameters only)
anysecret search --metadata <query>     # Search in metadata
anysecret grep <pattern>                # Regex search across keys/values
```

### Bulk Read Operations

```bash
# Bulk retrieval
anysecret read get-batch <file>              # Get keys from file (one per line)
anysecret read get-batch <key1,key2,key3>    # Get specific keys (comma-separated)
anysecret read get-batch --format json       # Output as JSON object
anysecret read get-batch --format yaml       # Output as YAML object
anysecret read get-batch --format env        # Output as export statements
anysecret read get-batch --fail-fast         # Stop on first error
anysecret read get-batch --quiet             # Only show values

# Environment variable export
anysecret read get-env --prefix <prefix>     # Export as environment variables
anysecret read get-env --output .env         # Write to file
anysecret read get-env --uppercase           # Convert keys to uppercase
anysecret read get-env --no-export           # Skip 'export' keyword

# Comparison operations
anysecret diff <env1> <env2>            # Compare environments
anysecret diff --provider <p1> <p2>     # Compare providers
anysecret validate-refs <file>          # Validate references in file
```

---

## Read Namespace Operations

The `read` namespace provides advanced read operations, analysis tools, and bulk retrieval commands for comprehensive configuration management.

### Advanced List and Tree Operations

```bash
# Enhanced listing (same as top-level commands)
anysecret read list                          # List all keys with classification
anysecret read list --prefix <prefix>        # Filter by prefix
anysecret read list --secrets-only           # Show only secrets
anysecret read list --parameters-only        # Show only parameters
anysecret read list --values                 # Show parameter values (secrets hidden)
anysecret read list --format json|yaml       # JSON/YAML output
anysecret read list --pattern <regex>        # Filter by regex pattern

# Hierarchical tree view
anysecret read tree                          # Show hierarchical tree view
anysecret read tree --prefix <prefix>        # Tree view with prefix filter
anysecret read tree --depth <n>              # Limit tree depth
anysecret read tree --secrets-only           # Show only secrets in tree
anysecret read tree --parameters-only        # Show only parameters in tree
```

### Search and Analysis Operations

```bash
# Advanced search capabilities
anysecret read search <query>                # Search in key names
anysecret read search <query> --content      # Search in values
anysecret read search <query> --metadata     # Search in metadata
anysecret read search <query> --regex        # Use regex patterns
anysecret read search <query> --case-sensitive # Case sensitive search
anysecret read search <query> --secrets-only # Search only secrets
anysecret read search <query> --format json  # JSON output

# Key analysis and description
anysecret read describe <key>                # Show detailed key metadata
anysecret read describe <key> --show-value   # Include actual value
anysecret read describe <key> --history      # Include version history
anysecret read describe <key> --format json  # JSON output
anysecret read describe <key> --raw          # Raw value output only
```

### Bulk Operations and Export

```bash
# Batch retrieval
anysecret read get-batch <key1,key2,key3>    # Get multiple keys
anysecret read get-batch --file keys.txt     # Get keys from file
anysecret read get-batch --format json       # JSON output
anysecret read get-batch --format yaml       # YAML output  
anysecret read get-batch --format env        # Environment export format
anysecret read get-batch --fail-fast         # Stop on first error
anysecret read get-batch --quiet             # Only show values
anysecret read get-batch --prefix <prefix>   # Add prefix to keys

# Environment variable export
anysecret read get-env                       # Export all as env vars
anysecret read get-env --prefix <prefix>     # Export with prefix filter
anysecret read get-env --output .env         # Write to file
anysecret read get-env --uppercase           # Convert keys to uppercase
anysecret read get-env --no-export           # Skip 'export' keyword
anysecret read get-env --no-quote            # Don't quote values
anysecret read get-env --secrets-only        # Only export secrets
anysecret read get-env --parameters-only     # Only export parameters
```

### Usage Examples

```bash
# Find all API keys
anysecret read search "api" --content --case-sensitive

# Get database configuration as JSON
anysecret read get-batch DB_HOST,DB_PORT,DB_NAME --format json

# Export staging environment to file
anysecret read get-env --prefix staging/ --output staging.env

# Analyze a specific key
anysecret read describe API_KEY --show-value --history

# Tree view of application config
anysecret read tree --prefix app/ --depth 3
```

---

## Write Namespace Operations

The `anysecret write` namespace provides comprehensive write operations with intelligent routing, security controls, and rich user feedback.

### Core Write Operations

```bash
# Primary set operation with intelligent routing
anysecret write set <key> <value>           # Intelligent routing between secrets/parameters
anysecret write set <key> <value> --hint secret      # Hint as secret
anysecret write set <key> <value> --hint parameter   # Hint as parameter
anysecret write set <key> <value> --json             # Parse value as JSON
anysecret write set <key> <value> --base64           # Decode base64 value
anysecret write set <key> <value> --description "desc" # Add description
anysecret write set <key> <value> --tags "env:prod,team:backend" # Add tags
anysecret write set <key> <value> --ttl 3600         # Set TTL in seconds
anysecret write set <key> <value> --if-not-exists    # Only set if doesn't exist
anysecret write set <key> <value> --encrypt          # Force encryption for files

# Explicit secret setting
anysecret write set-secret <key> <value>    # Force secret storage
anysecret write set-secret <key> --file <path>       # Read from file
anysecret write set-secret <key> --prompt            # Read from prompt
anysecret write set-secret <key> <value> --base64    # Decode base64
anysecret write set-secret <key> <value> --tags "sensitive:true"
anysecret write set-secret <key> <value> --description "API key for service X"

# Explicit parameter setting
anysecret write set-parameter <key> <value>  # Force parameter storage
anysecret write set-parameter <key> <value> --json   # Validate as JSON
anysecret write set-parameter <key> <value> --tags "config:database"
anysecret write set-parameter <key> <value> --description "Database config"
```

### Deletion Operations

```bash
# Delete operations with backup support
anysecret write delete <key>                # Delete with confirmation
anysecret write delete <key> --force        # Skip confirmation
anysecret write delete <key> --hint secret  # Hint for routing
anysecret write delete <key> --hint parameter # Hint for routing
anysecret write delete <key> --backup       # Create backup (default: true)
anysecret write delete <key> --no-backup    # Skip backup creation

# Bulk delete operations
anysecret write delete --prefix "/app/"     # Delete by prefix
anysecret write delete --pattern "temp_.*"  # Delete by pattern
anysecret write delete --tags "env:staging" # Delete by tags
```

### Advanced Write Features

```bash
# Conditional operations
anysecret write update <key> <value>        # Update existing only
anysecret write upsert <key> <value>        # Update or create
anysecret write replace <key> <old> <new>   # Replace if current value matches

# File-based operations
anysecret write set-from-file <file>        # Set multiple from JSON/YAML
anysecret write set-env-file <file>         # Set from .env file
anysecret write set-template <template> <vars> # Apply template

# Advanced secret operations
anysecret write generate <key> --length 32  # Generate random secret
anysecret write rotate <key>                # Rotate existing secret
anysecret write expire <key> --ttl 3600     # Set expiration
```

---

## ReadOnly Item Operations

### Single Item Retrieval

```bash
# Basic get operations
anysecret get <key>                     # Get value with auto-classification
anysecret get <key> --hint secret       # Override classification as secret
anysecret get <key> --hint parameter    # Override classification as parameter
anysecret get <key> --metadata          # Include metadata (classification, storage, type)
anysecret get <key> --raw               # Raw output (reveals secret values)
anysecret get <key> --format json        # JSON output format
anysecret get <key> --format yaml        # YAML output format

# Combined options
anysecret get <key> --raw --format json # Get secret value in JSON
anysecret get <key> --metadata --format yaml # Get with metadata in YAML

# Explicit retrieval
anysecret get-secret <key>              # Explicitly get from secrets
anysecret get-parameter <key>           # Explicitly get from parameters
anysecret get-secret <key> --version <v> # Get specific version
anysecret get-secret <key> --decrypt    # Decrypt and show value

# History and versions
anysecret history <key>                 # Show version history
anysecret versions <key>                # List all versions
anysecret get-version <key> <version>   # Get specific version
anysecret diff-versions <key> <v1> <v2> # Compare versions

# Metadata operations
anysecret describe <key>                # Show detailed metadata
anysecret tags <key>                    # Show tags
anysecret references <key>              # Show what references this key
anysecret dependencies <key>            # Show key dependencies
```

### Validation and Testing

```bash
# Validation
anysecret validate <key>                # Validate key exists and accessible
anysecret test <key>                    # Test key retrieval
anysecret check-access <key>            # Check access permissions
anysecret lint                          # Lint all configuration

# Classification testing
anysecret classify <key>                # Test classification
anysecret why-secret <key>              # Explain why classified as secret
anysecret why-parameter <key>           # Explain why classified as parameter
```

---

## Write Item Operations

### Single Item Operations

```bash
# Basic set operations
anysecret set <key> <value>             # Set with auto-classification
anysecret set <key> <value> --hint secret    # Force as secret
anysecret set <key> <value> --hint parameter # Force as parameter
anysecret set <key> <value> --json      # Parse value as JSON
anysecret set <key> <value> --base64    # Decode base64 value

# Explicit operations
anysecret set-secret <key> <value>      # Explicitly set as secret
anysecret set-parameter <key> <value>   # Explicitly set as parameter
anysecret set-secret <key> --file <path> # Set secret from file
anysecret set-parameter <key> --file <path> # Set parameter from file

# Advanced set options
anysecret set <key> <value> --description <desc>  # Add description
anysecret set <key> <value> --tags <k1=v1,k2=v2>  # Add tags
anysecret set <key> <value> --ttl <seconds>        # Set TTL
anysecret set <key> <value> --encrypt              # Force encryption
anysecret set <key> <value> --if-not-exists        # Only if key doesn't exist

# Update operations
anysecret update <key> <value>          # Update existing key
anysecret append <key> <value>          # Append to existing value
anysecret replace <key> <old> <new>     # Replace substring in value
anysecret rotate <key>                  # Generate new secret value

# Deletion
anysecret delete <key>                  # Delete key
anysecret delete <key> --force          # Force delete without confirmation
anysecret delete <key> --backup         # Backup before delete
```

### Interactive Operations

```bash
# Interactive editing
anysecret edit <key>                    # Edit in default editor
anysecret edit <key> --editor <cmd>     # Use specific editor
anysecret create-interactive            # Interactive key creation wizard

# Secure input
anysecret set-secret <key> --prompt     # Prompt for secret value (hidden)
anysecret generate <key>                # Generate random secret
anysecret generate <key> --length <n>   # Generate with specific length
anysecret generate <key> --pattern <p>  # Generate with pattern
```

---

## Sync Migration

### Provider Migration

```bash
# Full migration between providers
anysecret migrate --from <source> --to <target>        # Migrate all
anysecret migrate --from <source> --to <target> --dry-run # Test migration
anysecret migrate --prefix <prefix> --from <s> --to <t> # Migrate prefix
anysecret migrate --keys-from-file <file> --to <target> # Migrate specific keys

# Sync operations
anysecret sync <source> <target>        # Sync between providers
anysecret sync <source> <target> --strategy <merge|overwrite|skip>
anysecret sync --auto                   # Auto-sync based on configuration
anysecret sync --watch                  # Continuous sync mode

# Backup and restore
anysecret backup --to <provider>        # Backup to provider
anysecret backup --file <path>          # Backup to file
anysecret restore --from <provider>     # Restore from provider
anysecret restore --file <path>         # Restore from file
anysecret snapshot <name>               # Create named snapshot
anysecret rollback <snapshot>           # Rollback to snapshot
```

### Conflict Resolution

```bash
# Conflict management
anysecret conflicts list                # List sync conflicts
anysecret conflicts resolve <key> <strategy> # Resolve specific conflict
anysecret conflicts resolve-all <strategy>   # Resolve all conflicts
anysecret conflicts show <key>          # Show conflict details

# Merge strategies
anysecret merge <key> --strategy newest # Use newest value
anysecret merge <key> --strategy manual # Manual merge
anysecret merge <key> --interactive     # Interactive merge
```

---

## Bulk Write Operations

### Bulk Import/Export

```bash
# Import operations (.env files to cloud providers)
anysecret bulk import <file>                    # Import from file with intelligent classification
anysecret bulk import <file> --format env        # Explicitly specify .env format (auto-detected)
anysecret bulk import <file> --format json       # Import from JSON file
anysecret bulk import <file> --format yaml       # Import from YAML file
anysecret bulk import <file> --format csv        # Import from CSV file
anysecret bulk import <file> --prefix <prefix>   # Add prefix to imported keys
anysecret bulk import <file> --dry-run           # Test import (shows preview table)
anysecret bulk import <file> --overwrite         # Overwrite existing keys
anysecret bulk import <file> --skip-existing     # Skip existing keys
anysecret bulk import <file> --transform <script> # Transform during import

# Examples:
anysecret bulk import .env                       # Import .env file to current profile
anysecret bulk import config.json --prefix "app_" # Import JSON with "app_" prefix
anysecret bulk import prod.env --dry-run         # Preview what would be imported

# Complete .env to Cloud Workflow:
# 1. Preview the import (see classification table)
anysecret bulk import .env --dry-run
# 2. Import to current profile (routes secrets to GCP Secret Manager, params to GCS)
anysecret bulk import .env
# 3. Verify import worked
anysecret list
# 4. Test retrieval
anysecret get DATABASE_PASSWORD --raw

# Intelligent Classification & Cost Optimization:
# The import system automatically analyzes each key and routes to optimal storage:
#
# → SECRETS (High Security, ~$0.40/month per 10k items):
#   *_PASSWORD, *_SECRET, *_KEY, *_TOKEN, *_CREDENTIAL, API_KEY, STRIPE_*, etc.
#   Stored in: GCP Secret Manager, AWS Secrets Manager, Azure Key Vault
#
# → PARAMETERS (Cost Optimized, ~$0.01/month per 10k items):
#   *_HOST, *_PORT, *_URL, *_TIMEOUT, *_ENDPOINT, FEATURE_*, DEBUG_*, etc.
#   Stored in: GCS JSON, S3 JSON, Azure Blob Storage
#
# Benefits: 40x cost savings while maintaining enterprise security for sensitive data

# Export operations (pull from cloud to files)
anysecret bulk export --output .env           # Export to .env file (secrets masked in terminal)
anysecret bulk export --format json -o config.json  # Export as JSON
anysecret bulk export --format yaml -o config.yaml  # Export as YAML
anysecret bulk export --prefix <prefix>       # Filter by prefix
anysecret bulk export --parameters-only      # Exclude secrets (safer)
anysecret bulk export --show-secrets         # Show secrets in terminal (DANGEROUS)
anysecret bulk export --dry-run              # Preview without creating file

# Security features:
# - Secrets masked by default in terminal output (***) 
# - File permissions auto-set to 600 when secrets included
# - Warning prompts when exporting secrets
# - CI mode auto-confirms with CI=true environment variable

# Templating
anysecret template render <template>    # Render configuration template
anysecret template validate <template>  # Validate template
anysecret template create <name>        # Create new template
```

### Batch Operations

```bash
# Batch modifications
anysecret batch --file <operations.json>     # Execute batch operations
anysecret batch --stdin                      # Read operations from stdin
anysecret transform <script>                 # Apply transformation script
anysecret update-tags --add <k=v>            # Add tags to multiple keys
anysecret update-tags --remove <key>         # Remove tags from keys
anysecret expire --pattern <regex> --ttl <t> # Set expiration on matching keys

# Bulk generation
anysecret generate-batch <count> --prefix <p> # Generate multiple secrets
anysecret populate --template <file>          # Populate from template
anysecret seed --environment <env>            # Seed with environment data
```

---

## Environment Management

### Environment Operations

```bash
# Environment management
anysecret env create <name>             # Create new environment
anysecret env list                      # List environments
anysecret env switch <name>             # Switch to environment
anysecret env delete <name>             # Delete environment
anysecret env clone <source> <target>   # Clone environment
anysecret env merge <source> <target>   # Merge environments

# Environment configuration
anysecret env config <name> --provider <p>    # Set provider for environment
anysecret env config <name> --prefix <prefix> # Set prefix for environment
anysecret env config <name> --tags <tags>     # Set environment tags
anysecret env promote <from> <to>              # Promote between environments

# Multi-environment operations
anysecret deploy <env>                  # Deploy to environment
anysecret rollback <env> <version>      # Rollback environment
anysecret compare <env1> <env2>         # Compare environments
anysecret validate-deployment <env>     # Validate deployment
```

---

## CI/CD Integration

### Pipeline Operations

```bash
# CI/CD helpers
anysecret ci init                       # Initialize CI/CD configuration
anysecret ci export --format <github|gitlab|jenkins> # Export for CI platform
anysecret ci validate                   # Validate CI/CD configuration
anysecret ci test-access               # Test CI/CD access permissions

# Deployment operations
anysecret deploy check                  # Pre-deployment checks
anysecret deploy apply                  # Apply deployment
anysecret deploy verify                 # Post-deployment verification
anysecret deploy status                 # Check deployment status
anysecret deploy logs                   # Show deployment logs

# Integration commands
anysecret webhook create <url>          # Create webhook for changes
anysecret webhook test <id>             # Test webhook
anysecret notify <message>              # Send notification
anysecret audit-log                     # Show audit log
```

### Secret Injection

```bash
# Runtime injection
anysecret exec -- <command>             # Execute command with secrets as env vars
anysecret exec --prefix <p> -- <cmd>    # Execute with filtered secrets
anysecret shell                         # Start shell with secrets loaded
anysecret wrapper <config> -- <cmd>     # Use wrapper configuration

# File injection
anysecret inject <template> <output>    # Inject secrets into template
anysecret substitute <file>             # Substitute references in file
anysecret render-config <template>      # Render application config
```

---

## Multi-Cloud Coordination

### Cross-Cloud Operations

```bash
# Multi-provider management
anysecret providers sync               # Sync across all providers
anysecret providers balance           # Balance load across providers
anysecret providers failover <from> <to> # Failover to different provider
anysecret providers priority <list>   # Set provider priority order

# Cross-cloud replication
anysecret replicate --to <providers>   # Replicate to multiple providers
anysecret replicate --key <key> --to <providers> # Replicate specific key
anysecret replicate --strategy <active|passive>  # Set replication strategy

# Regional operations
anysecret regions list                 # List available regions
anysecret regions sync <source> <target> # Sync between regions
anysecret regions failover <region>    # Failover to region
anysecret regions latency-test        # Test regional latency
```

### Cost Management

```bash
# Cost optimization
anysecret cost estimate               # Estimate current costs
anysecret cost optimize              # Suggest optimizations
anysecret cost report --period <p>   # Generate cost report
anysecret cost budget <amount>       # Set cost budget
anysecret cost alert                 # Check cost alerts

# Usage analytics
anysecret usage stats                # Show usage statistics
anysecret usage top                  # Show most accessed keys
anysecret usage report               # Generate usage report
anysecret usage trends               # Show usage trends
```

---

## Security and Compliance

### Security Operations

```bash
# Security scanning
anysecret security scan              # Scan for security issues
anysecret security audit             # Full security audit
anysecret security compliance <standard> # Check compliance
anysecret security rotate-all        # Rotate all secrets
anysecret security check-access      # Check access permissions

# Encryption management
anysecret crypto keys list           # List encryption keys
anysecret crypto keys rotate         # Rotate encryption keys
anysecret crypto encrypt <file>      # Encrypt file
anysecret crypto decrypt <file>      # Decrypt file
anysecret crypto verify <file>       # Verify file integrity

# Access control
anysecret acl list                   # List access control rules
anysecret acl grant <user> <permissions> # Grant permissions
anysecret acl revoke <user> <permissions> # Revoke permissions
anysecret acl audit                  # Audit access control
```

### Compliance and Auditing

```bash
# Audit operations
anysecret audit trail               # Show audit trail
anysecret audit export --format <f> # Export audit logs
anysecret audit search <query>      # Search audit logs
anysecret audit compliance <std>    # Check compliance standard

# Reporting
anysecret report security           # Security report
anysecret report compliance <std>   # Compliance report
anysecret report usage              # Usage report
anysecret report export <format>    # Export reports
```

---

## Performance and Monitoring

### Performance Operations

```bash
# Performance monitoring
anysecret perf benchmark            # Run performance benchmark
anysecret perf monitor              # Monitor real-time performance
anysecret perf profile              # Profile operations
anysecret perf cache stats          # Show cache statistics
anysecret perf cache clear          # Clear cache

# Health monitoring
anysecret health check              # Overall health check
anysecret health providers          # Check provider health
anysecret health connectivity       # Check connectivity
anysecret health alerts             # Show health alerts
anysecret health dashboard          # Show health dashboard
```

### Debugging and Troubleshooting

```bash
# Debug operations
anysecret debug info                # Show debug information
anysecret debug trace <operation>   # Trace operation execution
anysecret debug logs                # Show debug logs
anysecret debug connectivity        # Debug connectivity issues
anysecret debug permissions         # Debug permission issues

# Troubleshooting
anysecret doctor                    # Run diagnostic checks
anysecret fix <issue>               # Auto-fix common issues
anysecret test-config               # Test configuration
anysecret validate-setup            # Validate entire setup
```

---

## Export and Import

### Data Exchange

```bash
# Advanced export
anysecret export --vault            # Export in Vault format
anysecret export --terraform        # Export as Terraform variables
anysecret export --kubernetes       # Export as Kubernetes manifests
anysecret export --docker           # Export as Docker secrets
anysecret export --ansible          # Export for Ansible
anysecret export --helm              # Export as Helm values

# Advanced import  
anysecret bulk import --from-vault <addr>      # Import from Vault (planned)
anysecret bulk import --from-terraform <file>  # Import from Terraform (planned)
anysecret bulk import --from-kubernetes <ns>   # Import from Kubernetes (planned)
anysecret bulk import --from-env              # Import from environment (planned)
anysecret bulk import --from-keyring          # Import from system keyring (planned)

# Format conversion
anysecret convert <input> <output> --from <fmt> --to <fmt>
anysecret convert --list-formats     # List supported formats
anysecret validate-format <file>     # Validate file format
```

### Integration Helpers

```bash
# Tool integrations
anysecret generate-compose           # Generate docker-compose with secrets
anysecret generate-systemd           # Generate systemd service with secrets
anysecret generate-k8s-manifest      # Generate Kubernetes manifest
anysecret generate-terraform         # Generate Terraform configuration
anysecret generate-ansible-vars      # Generate Ansible variables

# API operations
anysecret api server start           # Start REST API server
anysecret api client test            # Test API client
anysecret api docs                   # Show API documentation
anysecret webhook listen             # Listen for webhooks
```

---

## Global Options

All commands support these global options:

```bash
--config <file>                     # Use specific configuration file
--profile <name>                    # Use specific profile
--provider <name>                   # Override provider
--region <name>                     # Override region
--format <json|yaml|table|raw>      # Output format
--output <file>                     # Output to file
--quiet                            # Suppress output
--verbose                          # Verbose output
--debug                            # Debug mode
--dry-run                          # Show what would be done
--force                            # Force operation
--yes                              # Auto-confirm prompts
--timeout <seconds>                # Operation timeout
--retry <count>                    # Retry count for failures
--cache/--no-cache                 # Enable/disable caching
--parallel <count>                 # Parallel operation count
```

---

## Environment Variables

Key environment variables that control CLI behavior:

```bash
ANYSECRET_CONFIG_FILE              # Configuration file path
ANYSECRET_PROFILE                  # Active profile
ANYSECRET_PROVIDER                 # Default provider
ANYSECRET_REGION                   # Default region
ANYSECRET_READ_ONLY                # Enable read-only mode
ANYSECRET_CACHE_TTL                # Cache TTL in seconds
ANYSECRET_LOG_LEVEL                # Log level (debug, info, warn, error)
ANYSECRET_OUTPUT_FORMAT            # Default output format
ANYSECRET_TIMEOUT                  # Default timeout
ANYSECRET_PARALLEL                 # Default parallelism
ANYSECRET_NO_COLOR                 # Disable colored output
ANYSECRET_API_URL                  # API server URL
ANYSECRET_WEBHOOK_URL              # Webhook URL
```

---

## Exit Codes

The CLI uses standard exit codes:

- `0` - Success
- `1` - General error
- `2` - Configuration error
- `3` - Permission/access error
- `4` - Network/connectivity error
- `5` - Not found error
- `6` - Validation error
- `7` - Conflict error
- `8` - Authentication error
- `9` - Resource limit error
- `10` - Timeout error

---

## Command Features and Implementation Details

### List Command (`anysecret list`)

**Description:** Lists all configuration keys with intelligent classification and filtering.

**Features:**
- **Automatic Classification**: Shows whether each key is a secret (🔐) or parameter (⚙️)
- **Rich UI**: Color-coded output with table formatting
- **Multiple Output Formats**: Table (default), JSON, YAML
- **Advanced Filtering**: By prefix, pattern (regex), type (secrets/parameters)
- **Value Display**: Optional display of parameter values (secrets always hidden)

**Options:**
- `--prefix <prefix>`: Filter results by key prefix
- `--pattern <regex>`: Filter using regular expressions
- `--secrets-only`: Show only secrets
- `--parameters-only`: Show only parameters
- `--values`: Display parameter values (secrets remain hidden)
- `--format table|json|yaml`: Output format (default: table)

**Examples:**
```bash
anysecret list                          # List all with table format
anysecret list --format json            # JSON output
anysecret list --pattern ".*_KEY"       # Regex filtering
anysecret list --secrets-only --values  # Secrets only (values hidden)
anysecret list --format yaml --prefix API  # YAML with prefix filter
```

### Get Command (`anysecret get`)

**Description:** Retrieves a single configuration value with intelligent routing.

**Features:**
- **Intelligent Classification**: Automatically determines if key is secret or parameter
- **Pattern-Based Routing**: Uses built-in and custom patterns for classification
- **Secure by Default**: Secrets are hidden unless explicitly revealed with --raw
- **Rich Metadata**: Shows classification method, storage backend, value type
- **Multiple Output Formats**: Rich panels (default), JSON, YAML, raw text

**Options:**
- `--hint secret|parameter`: Override automatic classification
- `--metadata`: Include detailed metadata in output
- `--raw`: Reveal actual secret values (use with caution)
- `--format json|yaml`: Structured output format

**Security Notes:**
- Secrets are always hidden in default output
- Use `--raw` only in secure environments
- JSON/YAML formats respect --raw flag for secret values

**Examples:**
```bash
anysecret get API_KEY                   # Auto-classified, secret hidden
anysecret get API_KEY --raw             # Reveals actual secret value
anysecret get config --hint parameter   # Force parameter classification
anysecret get API_KEY --format json --metadata  # JSON with metadata
anysecret get DB_PASSWORD --raw --format yaml   # Secret value in YAML
```

### Pattern Management Commands

**Description:** Manage custom classification patterns for intelligent routing.

**Commands:**
- `anysecret config patterns show`: Display all patterns (built-in and custom)
- `anysecret config patterns-add-secret <pattern>`: Add secret classification pattern
- `anysecret config patterns-add-param <pattern>`: Add parameter classification pattern

**Pattern Examples:**
```bash
# Add patterns for secrets
anysecret config patterns-add-secret '.*_credentials$'
anysecret config patterns-add-secret '.*_private_key$'

# Add patterns for parameters
anysecret config patterns-add-param '.*_config$'
anysecret config patterns-add-param '^app_.*'
```

---

## Provider Implementation Status

The following table shows the implementation status of each command across different providers:

**Legend:**
- ✅ - Implemented and tested
- ⏳ - Planned/Upcoming implementation
- ❌ - Not supported by provider
- 🔄 - Partially implemented

| Command | AWS | GCP | Azure | AWS S3 | GCS | Azure Blob | Kubernetes | Vault | GitHub Actions | Env File | Encrypted File | File JSON | File YAML |
|---------|-----|-----|-------|--------|-----|------------|------------|-------|----------------|----------|----------------|-----------|-----------|
| **Configuration & Metadata** |
| `anysecret info` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `anysecret status` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `anysecret providers list` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `anysecret providers health` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⏳ | ✅ | ✅ | ✅ | ✅ |
| `anysecret config init` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret config validate` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `anysecret config profile-create` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret config profile-list` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret config profile-use` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret patterns show` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `anysecret config patterns-add-secret` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `anysecret config patterns-add-param` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Read Operations** | 
| `anysecret list` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret tree` | ✅ | ✅ | ✅ | ⏳ | ⏳ | ⏳ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret search` | ✅ | ✅ | ✅ | ⏳ | ⏳ | ⏳ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret get` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret get-secret` | ✅ | ✅ | ⏳ | ❌ | ❌ | ❌ | ⏳ | ⏳ | ❌ | ✅ | ✅ | ❌ | ❌ |
| `anysecret get-parameter` | ✅ | ❌ | ⏳ | ✅ | ✅ | ✅ | ⏳ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| `anysecret get-prefix` | ✅ | ⏳ | ⏳ | ✅ | ✅ | ✅ | ⏳ | ⏳ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret get-batch` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret get-env` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⏳ | ✅ | ✅ | ✅ | ✅ |
| `anysecret history` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret versions` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret describe` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret classify` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Read Namespace Commands** | *(Comprehensive read operations)*
| `anysecret read list` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret read tree` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret read search` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret read get-batch` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret read get-env` | ✅ | ✅ | ✅ | ✅ | ✅ | ⏳ | ✅ | ✅ | ✅ | ✅ |
| `anysecret read describe` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret read grep` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret read get-json` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret read get-yaml` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret read history` | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret read versions` | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret read diff` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret read validate-refs` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| **Write Namespace Commands** | *(Comprehensive write operations)*
| `anysecret write set` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret write set-secret` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| `anysecret write set-parameter` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| `anysecret write delete` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret write update` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret write upsert` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret write generate` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret write rotate` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret write set-from-file` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret write set-env-file` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| **Write Operations** | *(Updated 2025-09-01)*
| `anysecret set` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret set-secret` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ |
| `anysecret set-parameter` | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| `anysecret update` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret delete` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret edit` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret generate` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret rotate` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Migration & Sync** |
| `anysecret migrate` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret sync` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret backup` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret restore` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret snapshot` | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret conflicts` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| **Bulk Operations** |
| `anysecret bulk import` | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret export` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret template` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret batch` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret transform` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| **Environment Management** |
| `anysecret env create` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret env switch` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret env promote` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret deploy` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ |
| **CI/CD Integration** |
| `anysecret ci init` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ |
| `anysecret ci export` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ |
| `anysecret exec` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret shell` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret inject` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret webhook` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ |
| **Multi-Cloud** |
| `anysecret providers sync` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret providers balance` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret replicate` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret regions sync` | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret cost estimate` | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret usage stats` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Security & Compliance** |
| `anysecret security scan` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret security audit` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret security rotate-all` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret crypto keys` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ⏳ | ❌ | ❌ |
| `anysecret acl` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret audit trail` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Performance & Monitoring** |
| `anysecret perf benchmark` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret health check` | ✅ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ✅ | ✅ | ✅ | ✅ |
| `anysecret debug` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret doctor` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ |
| **Export & Import** |
| `anysecret export --vault` | ⏳ | ⏳ | ⏳ | ⏳ | ✅ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret export --terraform` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret export --kubernetes` | ⏳ | ⏳ | ⏳ | ✅ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret bulk import --from-vault` | ⏳ | ⏳ | ⏳ | ⏳ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `anysecret generate-compose` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |
| `anysecret api server` | ⏳ | ⏳ | ⏳ | ⏳ | ⏳ | ❌ | ⏳ | ⏳ | ⏳ | ⏳ |

### Provider-Specific Notes:

**AWS Secrets Manager**: Native secret storage with automatic rotation and versioning. Full enterprise features.

**GCP Secret Manager**: Google Cloud native secrets with automatic replication and IAM integration. Version history supported.

**Azure Key Vault**: Microsoft native secret management with HSM support and comprehensive audit logging.

**AWS S3 Parameters**: Cost-effective parameter storage using S3 JSON files. Conflict resolution with ETags. Optimized for bulk reads.

**GCS Parameters**: Google Cloud Storage for parameters. Uses generation numbers for conflict resolution. Auto-bucket creation.

**Azure Blob Parameters**: Azure Blob Storage for cost-effective parameter management. ETag-based optimistic locking.

**Kubernetes**: ConfigMaps for parameters, Secrets for sensitive data. Native k8s integration but no version history support.

**Vault**: HashiCorp Vault integration for secrets only. Enterprise-grade versioning and encryption. No parameter store capability.

**GitHub Actions**: Read-only access to organization secrets. Limited write capabilities for CI/CD workflows.

**Env File**: Simple file-based storage. No versioning or encryption. Good for local development.

**Encrypted File**: File-based with encryption. Limited versioning through backups. Uses industry-standard encryption.

**File JSON/YAML**: Structured file storage for parameters. Version control through git. Human-readable formats.

---

This comprehensive CLI specification provides a complete interface for secret and configuration management that supports enterprise requirements, CI/CD integration, multi-cloud coordination, and operational excellence.
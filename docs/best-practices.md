# AnySecret CLI Best Practices

Real-world patterns and best practices for using the AnySecret CLI in production.

## 🎯 Core Principles

### 1. Secrets Stay Secret, Parameters Stay Cheap
```bash
# AnySecret automatically classifies and routes:
anysecret set DATABASE_PASSWORD "secret123"  # → GCP Secret Manager ($0.40/month)
anysecret set DATABASE_HOST "db.example.com" # → GCS Storage ($0.01/month)

# 40x cost savings while maintaining security
```

### 2. Use Profiles for Environment Separation
```bash
# Development
anysecret config profile-create dev --local
anysecret config profile-use dev
anysecret set API_KEY "test_key_123"

# Production  
anysecret config profile-create prod --provider gcp
anysecret config profile-use prod
anysecret set API_KEY "live_key_456"

# Never mix environments!
```

### 3. CI/CD Should Be Stateless
```bash
# Export profile for CI/CD
anysecret config profile-export prod --base64 > profile.txt

# In CI/CD: Use profile data, not local config
CI=true anysecret --profile-data "$PROFILE_DATA" bulk export --output .env
```

## 🔐 Security Best Practices

### Never Commit Secrets

❌ **Bad: Secrets in code**
```bash
# .env file committed to git
DATABASE_PASSWORD=secret123
API_KEY=sk_live_abc123
```

✅ **Good: Pull secrets at runtime**
```bash
# deploy.sh
anysecret bulk export --output .env.production
docker run --env-file .env.production myapp
rm .env.production  # Clean up after use
```

### Mask Secrets in CI/CD Logs

```bash
# Secrets are masked by default in terminal output
anysecret list
# Shows: API_KEY (secret) ***

# Only show actual values when writing to files
anysecret bulk export --output secrets.env
# File contains real values, terminal shows masked

# Explicitly show secrets (use with caution)
anysecret get API_KEY --show-secrets
```

### Use Encryption for Sensitive Profiles

```bash
# Export with encryption for extra security
anysecret config profile-export prod --encrypt > profile.enc

# Set passphrase in CI/CD secrets
export ANYSECRET_PROFILE_PASSPHRASE="strong-passphrase"

# Use encrypted profile
anysecret --profile-data "$(cat profile.enc)" --decrypt bulk export
```

## 📦 Development Workflow

### Local Development Setup

```bash
# 1. Create local profile
anysecret config profile-create local-dev

# 2. Import development secrets from .env
anysecret bulk import .env.local

# 3. Daily workflow: Export to .env for local use
anysecret bulk export --output .env
npm run dev
```

### Team Development

```bash
# Share configuration template (not secrets)
cat > .env.template << EOF
DATABASE_URL=
API_KEY=
REDIS_HOST=
EOF

# Each developer sets their own values
anysecret config profile-create my-dev
anysecret set DATABASE_URL "postgresql://localhost/myapp_dev"
anysecret set API_KEY "dev_key_123"

# Export for local development
anysecret bulk export --output .env
```

## 🚀 CI/CD Integration

### GitHub Actions

```yaml
name: Deploy
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install AnySecret
        run: pip install anysecret-io
      
      - name: Export Production Config
        env:
          ANYSECRET_PROFILE_DATA: ${{ secrets.ANYSECRET_PROFILE }}
          CI: true
        run: |
          # Pull only parameters (secrets stay secure)
          anysecret bulk export --parameters-only --output .env.prod
          
          # Or pull everything for containers
          anysecret bulk export --output .env.full
      
      - name: Deploy
        run: |
          docker build -t myapp .
          docker run --env-file .env.full myapp
```

### GitLab CI

```yaml
deploy:
  stage: deploy
  script:
    - pip install anysecret-io
    - export CI=true
    - anysecret --profile-data "$ANYSECRET_PROFILE" bulk export --output .env
    - docker run --env-file .env myapp
  variables:
    ANYSECRET_PROFILE: $ANYSECRET_PROFILE_BASE64
```

### Jenkins

```groovy
pipeline {
    environment {
        ANYSECRET_PROFILE = credentials('anysecret-profile')
        CI = 'true'
    }
    stages {
        stage('Deploy') {
            steps {
                sh '''
                    pip install anysecret-io
                    anysecret bulk export --output .env.production
                    docker run --env-file .env.production myapp
                '''
            }
        }
    }
}
```

## 🔄 Migration Patterns

### Migrate from .env Files to Cloud

```bash
# Step 1: Create cloud profile
anysecret config profile-create production \
  --provider gcp \
  --project my-project

# Step 2: Import existing .env
anysecret config profile-use production
anysecret bulk import production.env --dry-run  # Preview
anysecret bulk import production.env            # Execute

# Step 3: Verify
anysecret list --format json | jq '.summary'
# Output: {"total": 25, "secrets": 5, "parameters": 20}
```

### Migrate Between Cloud Providers

```bash
# Export from AWS
anysecret config profile-use aws-prod
anysecret bulk export --format json --output aws-config.json

# Import to GCP
anysecret config profile-use gcp-prod
anysecret bulk import aws-config.json --format json

# Verify migration
anysecret list | wc -l  # Count should match
```

### Progressive Migration

```bash
# Start with hybrid approach
anysecret config profile-create hybrid \
  --primary file://.env \
  --fallback gcp

# Gradually move secrets to cloud
anysecret set API_KEY "$API_KEY" --hint secret  # Force to GCP
anysecret set DB_HOST "$DB_HOST" --hint parameter  # Keep local

# Eventually switch to cloud-first
anysecret config profile-create cloud-first \
  --primary gcp \
  --fallback file://.env
```

## 🎯 Common Patterns

### Multi-Service Configuration

```bash
# Structure: service/environment/key
anysecret set auth/prod/jwt_secret "secret123"
anysecret set auth/prod/timeout "30"
anysecret set payment/prod/stripe_key "sk_live_123"
anysecret set payment/prod/webhook_secret "whsec_456"

# Export for specific service
anysecret read get-env --prefix "auth/prod/" --output auth.env
anysecret read get-env --prefix "payment/prod/" --output payment.env
```

### Feature Flags as Parameters

```bash
# Feature flags are parameters (cheap storage)
anysecret set features/new_ui "true" --hint parameter
anysecret set features/beta_api "false" --hint parameter
anysecret set features/debug_mode "false" --hint parameter

# Export just features
anysecret read get-env --prefix "features/" --output features.env
```

### Database Connection Strings

```bash
# Store components separately
anysecret set db/host "db.example.com"      # Parameter
anysecret set db/port "5432"                # Parameter  
anysecret set db/name "myapp"               # Parameter
anysecret set db/user "appuser"             # Parameter
anysecret set db/password "secret123"       # Secret (auto-classified)

# Compose in application
export $(anysecret read get-env --prefix "db/" | xargs)
DATABASE_URL="postgresql://$db_user:$db_password@$db_host:$db_port/$db_name"
```

## 🔍 Debugging and Validation

### Check Classification

```bash
# See how keys would be classified
anysecret classify MY_API_KEY
# Output: secret (matches pattern: *_KEY)

anysecret classify DATABASE_HOST  
# Output: parameter (matches pattern: *_HOST)

# View all patterns
anysecret patterns
```

### Validate Configuration

```bash
# Check what exists
anysecret list --format json | jq '.summary'

# Search for specific patterns
anysecret read search "database" --content
anysecret read search "prod.*api" --regex

# Tree view for organization
anysecret read tree --prefix "app/"
```

### Audit Secret Access

```bash
# List all secrets (without values)
anysecret list --secrets-only

# Export for security audit (secrets masked)
anysecret bulk export --dry-run > audit.log

# Check specific secret metadata
anysecret read describe API_KEY --metadata
```

## ⚡ Performance Optimization

### Bulk Operations

```bash
# Slow: Individual gets
for key in API_KEY DB_PASSWORD JWT_SECRET; do
  anysecret get $key >> .env
done

# Fast: Batch export
anysecret bulk export --output .env
```

### Selective Exports

```bash
# Export only what you need
anysecret bulk export --parameters-only --output params.env
anysecret read get-batch API_KEY,DB_PASSWORD --output secrets.env
```

### Use Prefixes for Grouping

```bash
# Organize by service/component
anysecret set api/timeout "30"
anysecret set api/retry_count "3"
anysecret set api/base_url "https://api.example.com"

# Export entire group efficiently
anysecret read get-env --prefix "api/" --output api-config.env
```

## 🚨 Common Pitfalls

### ❌ Don't hardcode provider details
```bash
# Bad: Provider-specific code
aws secretsmanager get-secret-value --secret-id myapp/api-key

# Good: Provider-agnostic
anysecret get myapp/api-key
```

### ❌ Don't mix environments in one profile
```bash
# Bad: Mixed environments
anysecret set dev_api_key "test_123"
anysecret set prod_api_key "live_456"

# Good: Separate profiles
anysecret config profile-use dev
anysecret set api_key "test_123"

anysecret config profile-use prod  
anysecret set api_key "live_456"
```

### ❌ Don't ignore cost optimization
```bash
# Bad: Everything as secrets
anysecret set LOG_LEVEL "info" --hint secret  # $0.40/month

# Good: Use auto-classification
anysecret set LOG_LEVEL "info"  # $0.01/month as parameter
```

## 📊 Monitoring and Health

### Provider Health Check

```bash
# Check all providers
anysecret providers health

# Check current profile
anysecret status

# Detailed info
anysecret info
```

### Cost Analysis

```bash
# See distribution
anysecret list --format json | jq '
  .summary | 
  {
    secrets_cost: (.secrets * 0.40),
    params_cost: (.parameters * 0.01),
    total_monthly: (.secrets * 0.40 + .parameters * 0.01)
  }
'
```

## 🎓 Quick Reference

### Essential Commands

```bash
# Profile management
anysecret config profile-create <name>    # Create profile
anysecret config profile-use <name>       # Switch profile
anysecret config profile-list             # List profiles
anysecret config profile-export <name>    # Export for CI/CD

# Basic operations
anysecret get <key>                       # Get value
anysecret set <key> <value>              # Set value
anysecret delete <key>                    # Delete value
anysecret list                           # List all keys

# Bulk operations
anysecret bulk import <file>             # Import from file
anysecret bulk export --output <file>    # Export to file

# Advanced reads
anysecret read tree                      # Tree view
anysecret read search <query>            # Search keys
anysecret read get-batch <keys>          # Get multiple
anysecret read get-env                   # Export as env vars
```

### Environment Variables

```bash
# Profile override
export ANYSECRET_PROFILE_DATA="<base64>"

# CI/CD mode (auto-confirm prompts)
export CI=true

# Debug mode
export ANYSECRET_DEBUG=true
```

## 📚 Next Steps

- [CLI Reference](cli.md) - Complete command documentation
- [Provider Setup](providers.md) - Configure cloud providers
- [Migration Guide](migration.md) - Migrate existing secrets

---

*These practices are based on real production usage. The CLI is the primary interface for AnySecret - it's battle-tested and production-ready.*
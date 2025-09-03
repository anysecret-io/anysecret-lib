# Quick Start Guide

Get up and running with AnySecret CLI in 5 minutes. From zero to managing secrets in the cloud with intelligent cost optimization.

## 🎯 Prerequisites

- Python 3.8+ 
- Command line / terminal access
- (Optional) Cloud provider account for production use

## 📦 Installation

```bash
pip install anysecret-io
```

That's it! The CLI is ready to use.

## ⚡ 5-Minute Quickstart

### Step 1: Create Your First Profile

```bash
# Start with local development
anysecret config profile-create my-first-profile

# Check it was created
anysecret config profile-list
# Output: my-first-profile (active)
```

### Step 2: Add Some Configuration

```bash
# Add secrets and parameters - auto-classification handles routing
anysecret set DATABASE_PASSWORD "super_secure_password"  # Auto: Secret
anysecret set DATABASE_HOST "localhost"                   # Auto: Parameter
anysecret set API_TIMEOUT "30"                           # Auto: Parameter
anysecret set STRIPE_SECRET_KEY "sk_test_abc123"         # Auto: Secret
anysecret set LOG_LEVEL "debug"                          # Auto: Parameter

# See what you've got
anysecret list
# Output:
# DATABASE_PASSWORD (secret) ***
# DATABASE_HOST (parameter) localhost  
# API_TIMEOUT (parameter) 30
# STRIPE_SECRET_KEY (secret) ***
# LOG_LEVEL (parameter) debug
```

### Step 3: Use Your Configuration

```bash
# Get individual values
anysecret get DATABASE_HOST
# Output: localhost

anysecret get DATABASE_PASSWORD
# Output: *** (secrets are masked in terminal)

# Export everything to a file for your app
anysecret bulk export --output .env
cat .env
# DATABASE_PASSWORD=super_secure_password
# DATABASE_HOST=localhost
# API_TIMEOUT=30
# STRIPE_SECRET_KEY=sk_test_abc123
# LOG_LEVEL=debug
```

### Step 4: Import from Existing .env File

```bash
# If you already have a .env file
anysecret bulk import .env

# Or import with preview first
anysecret bulk import .env --dry-run

# Check classification results
anysecret list --format json | jq '.summary'
# Output: {"total": 15, "secrets": 5, "parameters": 10}
```

🎉 **Congratulations!** You're now using intelligent secret management with automatic cost optimization.

## 🔄 Next Steps

### Move to Cloud (Production Ready)

When you're ready for production, upgrade to cloud storage:

```bash
# Create cloud profile (GCP example)
anysecret config profile-create production --provider gcp

# Switch to production profile
anysecret config profile-use production

# Import your local config to cloud
anysecret bulk import .env
# Secrets → GCP Secret Manager (~$0.40/month each)
# Parameters → GCS Storage (~$0.01/month each)
# Automatic 40x cost savings!

# Export production profile for CI/CD
anysecret config profile-export production --base64 > prod-profile.txt
# Store this in your CI/CD secrets
```

### Set Up CI/CD

Add to your GitHub Actions workflow:

```yaml
- name: Deploy with AnySecret
  env:
    ANYSECRET_PROFILE_DATA: ${{ secrets.ANYSECRET_PROFILE }}
    CI: true
  run: |
    pip install anysecret-io
    anysecret bulk export --output .env.production
    docker run --env-file .env.production myapp
```

### Advanced Features

```bash
# Search and explore your config
anysecret read search "database"
anysecret read tree --prefix "api/"

# Check cost optimization
anysecret list --format json | jq '
  .summary | {
    monthly_cost: (.secrets * 0.40 + .parameters * 0.01),
    traditional_cost: ((.secrets + .parameters) * 0.40),
    savings: ((.secrets + .parameters) * 0.40 - (.secrets * 0.40 + .parameters * 0.01))
  }
'

# Provider health check
anysecret providers health
anysecret status
```

## 📚 Common First Tasks

### Import from Different Formats

```bash
# From .env file
anysecret bulk import .env

# From JSON config  
anysecret bulk import config.json --format json

# From YAML
anysecret bulk import settings.yaml --format yaml

# Add prefix to avoid conflicts
anysecret bulk import legacy.env --prefix "OLD_"
```

### Export to Different Formats

```bash
# Basic .env export
anysecret bulk export --output .env

# JSON for structured config
anysecret bulk export --format json --output config.json

# Only parameters (no secrets in file)
anysecret bulk export --parameters-only --output params.env

# Everything with secrets (be careful!)
anysecret bulk export --show-secrets --output full-config.env
```

### Multi-Environment Setup

```bash
# Create profiles for each environment
anysecret config profile-create dev
anysecret config profile-create staging  
anysecret config profile-create prod

# Switch between them
anysecret config profile-use dev
anysecret set API_KEY "dev_key_123"

anysecret config profile-use prod
anysecret set API_KEY "prod_key_456"

# Check current profile
anysecret config profile-list
# Output: 
# dev
# staging
# prod (active)
```

### Classification Control

```bash
# Check how a key would be classified
anysecret classify MY_CONFIG_VALUE
# Output: parameter (no matching secret patterns)

anysecret classify API_SECRET_KEY  
# Output: secret (matches pattern: *_SECRET_KEY)

# Override classification
anysecret set PUBLIC_KEY "pk_test_123" --hint parameter  # Force as parameter
anysecret set LOG_TOKEN "token_123" --hint secret        # Force as secret

# See classification patterns
anysecret patterns
```

## 🚨 Common Issues & Solutions

### "Profile not found" error
```bash
# Check available profiles
anysecret config profile-list

# Create if missing
anysecret config profile-create default
```

### Secrets showing as *** in terminal
```bash
# This is normal security behavior
# To see actual values (use carefully):
anysecret get API_KEY --show-secrets

# Or export to file (values are real in files)
anysecret bulk export --output .env
cat .env  # Shows real values
```

### Import not working
```bash
# Check file format
anysecret bulk import myfile.env --dry-run

# Specify format explicitly
anysecret bulk import config.json --format json

# Check file permissions and path
ls -la myfile.env
```

### Cloud provider authentication
```bash
# Check provider status
anysecret providers health

# For GCP: Set up authentication
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# For AWS: Configure credentials
aws configure
# or use environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
```

## 🎓 What You've Learned

1. ✅ **Profile Management**: Created and switched between profiles
2. ✅ **Auto-Classification**: Saw how secrets and parameters are routed automatically
3. ✅ **Import/Export**: Moved config between files and AnySecret
4. ✅ **Cost Optimization**: Understanding the 40x savings from smart routing
5. ✅ **Security**: Secrets are masked in terminal but real in files

## 🚀 Ready for More?

- **[Best Practices](best-practices.md)** - Production patterns and security
- **[CLI Reference](cli.md)** - Complete command documentation  
- **[Examples](examples.md)** - Real-world use cases from solo dev to enterprise
- **[API Reference](api.md)** - Python SDK for programmatic access

## 💡 Pro Tips

```bash
# Quick commands you'll use daily
alias as='anysecret'
alias asl='anysecret list'
alias ase='anysecret bulk export --output .env'

# Show cost savings
anysecret list --format json | jq -r '
  "💰 Monthly cost: $" + ((.summary.secrets * 0.40 + .summary.parameters * 0.01) | tostring) +
  " (saved $" + (((.summary.secrets + .summary.parameters) * 0.40 - (.summary.secrets * 0.40 + .summary.parameters * 0.01)) | tostring) + "/month vs traditional)"
'

# Health check everything
anysecret status && anysecret providers health
```

---

**You're ready!** Start with local profiles, then move to cloud when you need production deployment. AnySecret grows with you from hobby project to enterprise scale.

*Questions? Check the [examples](examples.md) for your specific use case or see the [CLI reference](cli.md) for complete documentation.*
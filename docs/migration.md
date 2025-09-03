# Migration Guide

Complete guide for migrating secrets and configuration between providers using the AnySecret CLI with zero downtime.

## 🎯 The AnySecret Migration Advantage

**Your applications never change.** Whether migrating from AWS to GCP, adding multi-cloud support, or moving from .env files to production - the same CLI commands work everywhere.

The migration changes **where** your secrets are stored, not **how** your applications use them:

```bash
# Same commands work everywhere:
anysecret get DATABASE_PASSWORD    # Works with any provider
anysecret bulk export --output .env # Works with any provider
anysecret list --format json        # Works with any provider
```

AnySecret handles provider differences through:
- **Profile management** - Switch providers with one command  
- **Auto-classification** - Optimal storage routing
- **Universal export** - Same .env output regardless of provider
- **Backup/restore** - Easy rollback if needed

## 📋 Migration Scenarios

### Common Migration Paths

| From → To | Use Case | Complexity | Downtime |
|-----------|----------|------------|----------|
| **Local Files → Cloud** | Dev to production | Low | None |
| **AWS → GCP** | Cloud provider switch | Medium | None |
| **Single → Multi-Cloud** | Redundancy/DR | High | None |
| **Legacy → AnySecret** | Tool modernization | Medium | Minimal |

---

## 🚀 Quick Migration: .env to Cloud

### Scenario: Local Development to GCP Production

Most common migration - moving from .env files to cloud providers.

#### Current State (.env file)
```bash
# .env
DATABASE_PASSWORD=dev_password_123
STRIPE_SECRET_KEY=sk_test_abc123  
JWT_SECRET=jwt_dev_secret
DATABASE_HOST=localhost
API_TIMEOUT=30
LOG_LEVEL=debug
```

#### Step 1: Create AnySecret Profile
```bash
# Import current .env to local profile
anysecret config profile-create local-dev
anysecret bulk import .env

# Verify import
anysecret list
# DATABASE_PASSWORD (secret) ***
# STRIPE_SECRET_KEY (secret) ***
# JWT_SECRET (secret) ***
# DATABASE_HOST (parameter) localhost
# API_TIMEOUT (parameter) 30
# LOG_LEVEL (parameter) debug
```

#### Step 2: Create Cloud Profile  
```bash
# Create production profile
anysecret config profile-create production --provider gcp

# Switch to production profile
anysecret config profile-use production

# Import configuration (auto-routes to optimal storage)
anysecret bulk import .env
# Secrets → GCP Secret Manager (~$0.40/month each)
# Parameters → GCS Storage (~$0.01/month each)
```

#### Step 3: Verify Migration
```bash
# Test the migration
anysecret list --format json | jq '.summary'
# {"total": 6, "secrets": 3, "parameters": 3}

anysecret get DATABASE_HOST
# localhost (same value, different storage)

# Export to verify same output format
anysecret bulk export --output .env.new
diff .env .env.new
# Should be identical
```

#### Step 4: Deploy with New Profile
```bash
# Export profile for CI/CD
anysecret config profile-export production --base64 > prod-profile.txt

# In CI/CD pipeline:
export ANYSECRET_PROFILE_DATA="$(cat prod-profile.txt)"
anysecret bulk export --output .env.production
docker run --env-file .env.production myapp
```

**Result**: Same application code, 40x cost savings, secure cloud storage.

---

## 🔄 Cloud-to-Cloud Migration

### Scenario: AWS to GCP Migration

Enterprise scenario - moving from AWS to GCP while maintaining redundancy.

#### Step 1: Export from AWS
```bash
# Current AWS profile
anysecret config profile-use aws-prod

# Export everything as backup
anysecret bulk export --format json --output aws-backup.json
anysecret bulk export --output aws-backup.env

# Verify export
wc -l aws-backup.json
# 150 lines (75 config items)
```

#### Step 2: Create GCP Profile
```bash
# Create new GCP profile
anysecret config profile-create gcp-prod --provider gcp
anysecret config profile-use gcp-prod

# Import from AWS backup (dry run first)
anysecret bulk import aws-backup.json --format json --dry-run
# Shows: 25 → secrets, 50 → parameters

# Execute import
anysecret bulk import aws-backup.json --format json
```

#### Step 3: Verify Data Integrity
```bash
# Compare configurations
anysecret config profile-use aws-prod
anysecret list --format json > aws-config.json

anysecret config profile-use gcp-prod  
anysecret list --format json > gcp-config.json

# Compare counts and keys
jq '.summary' aws-config.json gcp-config.json
jq -r '.items[].key' aws-config.json | sort > aws-keys.txt
jq -r '.items[].key' gcp-config.json | sort > gcp-keys.txt
diff aws-keys.txt gcp-keys.txt
# Should show no differences
```

#### Step 4: Gradual Cutover
```bash
# Phase 1: Test with staging environment
anysecret config profile-export gcp-prod --base64 > gcp-staging-profile.txt

# Phase 2: Blue-green deployment
# Old: AWS profile in production
# New: GCP profile in staging → validate → promote

# Phase 3: Full cutover
anysecret config profile-export gcp-prod --base64 > gcp-prod-profile.txt
# Update all CI/CD systems with new profile
```

#### Step 5: Cleanup (After Validation)
```bash
# Keep AWS as backup for rollback period
# After 30 days of stable operation:
anysecret config profile-use aws-prod
anysecret bulk export --format json --output final-aws-backup.json
# Store backup, then clean up AWS resources
```

---

## 🏗️ Multi-Cloud Setup

### Scenario: Primary + Fallback Architecture  

Enterprise resilience - primary provider with automatic fallback.

#### Design Pattern
```bash
# Primary: GCP (main operations)
# Fallback: AWS (disaster recovery)
# Local: Emergency backup
```

#### Implementation
```bash
# Create primary profile
anysecret config profile-create primary --provider gcp
anysecret config profile-use primary

# Import production configuration
anysecret bulk import production.env

# Create fallback profile  
anysecret config profile-create fallback --provider aws
anysecret config profile-use fallback

# Sync from primary to fallback
anysecret config profile-use primary
anysecret bulk export --format json --output sync.json

anysecret config profile-use fallback
anysecret bulk import sync.json --format json
```

#### Operational Scripts
```bash
# sync-profiles.sh - Run daily
#!/bin/bash
echo "Syncing primary → fallback"
anysecret config profile-use primary
anysecret bulk export --format json --output /tmp/sync.json

anysecret config profile-use fallback  
anysecret bulk import /tmp/sync.json --format json

echo "Sync complete: $(date)"
rm /tmp/sync.json
```

#### Disaster Recovery
```bash
# If primary fails, switch to fallback
export ANYSECRET_PROFILE_DATA="$FALLBACK_PROFILE_DATA"

# Same commands, different provider
anysecret bulk export --output .env.recovery
docker run --env-file .env.recovery myapp
```

---

## 📊 Migration Best Practices

### Pre-Migration Checklist

```bash
# 1. Inventory current configuration
anysecret list --format json > pre-migration-inventory.json

# 2. Test classification rules
anysecret bulk import .env --dry-run

# 3. Backup everything
anysecret bulk export --format json --output full-backup.json
anysecret bulk export --output full-backup.env

# 4. Verify provider access
anysecret providers health
```

### During Migration

```bash
# 1. Use dry-run first
anysecret bulk import config.json --format json --dry-run

# 2. Import in batches for large configs
split -l 20 large-config.json batch-
for file in batch-*; do
  anysecret bulk import "$file" --format json
  sleep 1  # Rate limiting
done

# 3. Verify each step
anysecret list --format json | jq '.summary'
```

### Post-Migration Validation

```bash
# 1. Compare counts
echo "Expected: $(jq -r '.summary.total' pre-migration-inventory.json)"  
echo "Actual: $(anysecret list --format json | jq -r '.summary.total')"

# 2. Test application integration
anysecret bulk export --output .env.test
docker run --env-file .env.test myapp ./test-suite.sh

# 3. Performance baseline
time anysecret bulk export --output /dev/null
# Should be < 2 seconds for 100 items
```

---

## 🔧 Migration Tools & Scripts

### Bulk Migration Script

```bash
#!/bin/bash
# migrate-provider.sh

set -e

SOURCE_PROFILE="$1"
TARGET_PROFILE="$2"
BACKUP_DIR="./migration-backup-$(date +%Y%m%d)"

if [[ -z "$SOURCE_PROFILE" || -z "$TARGET_PROFILE" ]]; then
  echo "Usage: $0 <source-profile> <target-profile>"
  exit 1
fi

echo "🚀 Starting migration: $SOURCE_PROFILE → $TARGET_PROFILE"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Step 1: Export from source
echo "📤 Exporting from $SOURCE_PROFILE..."
anysecret config profile-use "$SOURCE_PROFILE"
anysecret bulk export --format json --output "$BACKUP_DIR/source-backup.json"
anysecret bulk export --output "$BACKUP_DIR/source-backup.env"

# Step 2: Import to target (dry-run first)
echo "🔍 Testing import to $TARGET_PROFILE..."
anysecret config profile-use "$TARGET_PROFILE"
anysecret bulk import "$BACKUP_DIR/source-backup.json" --format json --dry-run

echo "📥 Importing to $TARGET_PROFILE..."
anysecret bulk import "$BACKUP_DIR/source-backup.json" --format json

# Step 3: Verify
echo "✅ Verifying migration..."
anysecret list --format json > "$BACKUP_DIR/target-result.json"

SOURCE_COUNT=$(jq -r '.summary.total' "$BACKUP_DIR/source-backup.json")
TARGET_COUNT=$(jq -r '.summary.total' "$BACKUP_DIR/target-result.json")

if [[ "$SOURCE_COUNT" == "$TARGET_COUNT" ]]; then
  echo "✅ Migration successful: $SOURCE_COUNT items transferred"
  echo "📁 Backups saved to: $BACKUP_DIR"
else
  echo "❌ Migration failed: $SOURCE_COUNT → $TARGET_COUNT"
  exit 1
fi
```

### Rollback Script

```bash
#!/bin/bash  
# rollback-migration.sh

BACKUP_FILE="$1"
TARGET_PROFILE="$2"

if [[ -z "$BACKUP_FILE" || -z "$TARGET_PROFILE" ]]; then
  echo "Usage: $0 <backup-file> <target-profile>"
  exit 1
fi

echo "🔄 Rolling back to $TARGET_PROFILE from $BACKUP_FILE"

anysecret config profile-use "$TARGET_PROFILE"
anysecret bulk import "$BACKUP_FILE" --format json

echo "✅ Rollback complete"
```

---

## 🚨 Troubleshooting

### Common Migration Issues

#### Import Failures
```bash
# Check file format
file config.json
anysecret bulk import config.json --format json --dry-run

# Fix JSON formatting
jq '.' config.json > config-fixed.json
anysecret bulk import config-fixed.json --format json
```

#### Provider Authentication
```bash
# Check provider access
anysecret providers health

# Re-authenticate
# For GCP:
gcloud auth application-default login

# For AWS:
aws configure
```

#### Classification Issues
```bash
# Check how keys are being classified
anysecret classify DATABASE_PASSWORD
anysecret classify API_TIMEOUT

# Override if needed
anysecret set LOG_TOKEN "value" --hint secret
anysecret set PUBLIC_KEY "value" --hint parameter
```

#### Performance Issues
```bash
# Large migrations - use batching
split -l 50 large-config.json chunk-
for chunk in chunk-*; do
  anysecret bulk import "$chunk" --format json
  sleep 2  # Rate limiting
done
```

---

## 🎓 Migration Success Stories

### Startup: $0 → $200/month savings
- **Before**: 50 config values × $0.40 = $20/month
- **After**: 10 secrets × $0.40 + 40 parameters × $0.01 = $4.40/month  
- **Savings**: $15.60/month (78% reduction)

### Scale-up: Multi-cloud resilience  
- **Challenge**: AWS vendor lock-in concerns
- **Solution**: Primary GCP, fallback AWS using AnySecret profiles
- **Result**: 99.99% uptime, easy provider switching

### Enterprise: Compliance migration
- **Challenge**: Move from HashiCorp Vault to cloud-native
- **Solution**: Gradual migration with AnySecret classification  
- **Result**: 60% cost reduction, improved compliance posture

---

## 📚 Next Steps

After migration:
- **[Best Practices](best-practices.md)** - Optimize your new setup
- **[CLI Reference](cli.md)** - Master advanced commands
- **[Examples](examples.md)** - Learn from real-world patterns

Need help? Check the [Provider Setup](providers.md) guide for cloud-specific configuration.

---

*Migration with AnySecret: Change where you store secrets, not how you use them.*
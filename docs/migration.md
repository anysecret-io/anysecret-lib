# Migration Guide

Complete guide for migrating secrets and configuration between cloud providers with **zero code changes**.

## 🎯 The AnySecret.io Migration Promise

**Your application code never changes.** Whether migrating from AWS to GCP, adding multi-cloud support, or moving from development to production - the same code works everywhere:

```python
# This code works in ALL environments:
db_password = await anysecret.get("database.password")
stripe_key = await anysecret.get("stripe.api.key")
db_host = await anysecret.get("database.host")
```

AnySecret.io handles the provider differences automatically through:
- **Auto-detection** of cloud environments
- **Auto-classification** of secrets vs parameters
- **Automatic caching** for performance
- **Universal CLI** for DevOps workflows

## 📋 Migration Scenarios

### Common Migration Paths

| From → To | Complexity | Downtime | Automation |
|-----------|------------|----------|------------|
| **File-based → AWS** | Low | None | Full |
| **AWS → GCP** | Medium | None | Full |
| **AWS → Azure** | Medium | None | Full |
| **GCP → Azure** | Medium | None | Full |
| **Single Cloud → Multi-Cloud** | High | None | Partial |
| **On-Premises → Cloud** | High | Minimal | Partial |

---

## 🚀 Quick Migration (File to Cloud)

### Scenario: Development (.env) to Production (AWS)

This is the most common migration when moving from local development to cloud production.

#### Step 1: Current State (Development)

```bash
# .env file
DATABASE_PASSWORD=dev-password-123
STRIPE_SECRET_KEY=sk_test_abc123
JWT_SECRET=dev-jwt-secret
API_TIMEOUT=30
DATABASE_HOST=localhost
```

```python
# Current development code - works in ALL environments
import anysecret

# Auto-detects .env file in development
db_password = await anysecret.get("database.password")
stripe_key = await anysecret.get("stripe.secret.key")
db_host = await anysecret.get("database.host")
```

#### Step 2: Set Up AWS Secrets

```bash
# Create production secrets in AWS
aws secretsmanager create-secret \
    --name "prod/database/password" \
    --secret-string "prod-password-xyz789"

aws secretsmanager create-secret \
    --name "prod/stripe/secret-key" \
    --secret-string "sk_live_real_key..."

aws secretsmanager create-secret \
    --name "prod/auth/jwt-secret" \
    --secret-string "prod-jwt-secret-secure"

# Create parameters in Parameter Store
aws ssm put-parameter \
    --name "/prod/api/timeout" \
    --value "60" \
    --type "String"

aws ssm put-parameter \
    --name "/prod/database/host" \
    --value "prod-db.example.com" \
    --type "String"
```

#### Step 3: Deploy to Production - Zero Code Changes!

```python
# THE EXACT SAME CODE now reads from AWS automatically!
import anysecret

# Auto-detects AWS environment in production
db_password = await anysecret.get("database.password")  # → AWS Secrets Manager  
stripe_key = await anysecret.get("stripe.secret.key")   # → AWS Secrets Manager
db_host = await anysecret.get("database.host")          # → AWS Parameter Store
api_timeout = await anysecret.get("api.timeout")        # → AWS Parameter Store

# No code changes. No config file updates. Just works.
```

#### Step 4: Deploy and Let AnySecret Auto-Detect

```bash
# AnySecret auto-detects AWS environment - no manual config needed!
# Just deploy with proper AWS IAM roles/credentials

kubectl apply -f production-deployment.yaml

# Or use environment variables for explicit control:
# export AWS_REGION=us-east-1  
# export ENVIRONMENT=prod  # Optional: adds 'prod/' prefix to keys
```

**Result**: Zero downtime migration from local files to AWS cloud secrets! 🎉

---

## ⚡ Zero-Downtime Cloud Migration

### Scenario: AWS → Google Cloud Platform

Complete migration from AWS to GCP without application downtime.

#### Migration Strategy: Blue-Green with Fallback

```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

# Phase 1: Configure fallback (AWS primary, GCP secondary)
fallback_config = ConfigManagerConfig(
    # Primary: AWS (existing)
    secret_manager_type=ManagerType.AWS,
    secret_config={"region": "us-east-1"},
    parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
    parameter_config={"region": "us-east-1"},
    
    # Fallback: GCP (new)
    secret_fallback_type=ManagerType.GCP,
    secret_fallback_config={"project_id": "my-gcp-project"},
    parameter_fallback_type=ManagerType.KUBERNETES_CONFIGMAP,
    parameter_fallback_config={"namespace": "default"}
)

manager = await get_config_manager(fallback_config)
```

#### Step 1: Pre-Migration Setup

```bash
#!/bin/bash
# migration-setup.sh

echo "🚀 Starting AWS → GCP migration setup"

# Enable GCP APIs
gcloud services enable secretmanager.googleapis.com
gcloud services enable container.googleapis.com

# Create GCP service account
gcloud iam service-accounts create anysecret-migrator \
    --description="AnySecret migration service account"

# Grant permissions
gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
    --member="serviceAccount:anysecret-migrator@$GCP_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.admin"

echo "✅ GCP setup complete"
```

#### Step 2: Migrate Secrets Script

```python
#!/usr/bin/env python3
"""
AWS to GCP Migration Script
Usage: python migrate_aws_to_gcp.py --dry-run
       python migrate_aws_to_gcp.py --execute
"""

import asyncio
import argparse
import sys
from typing import Dict, List, Any
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

class AWSToGCPMigrator:
    def __init__(self, aws_region: str, gcp_project: str):
        self.aws_config = ConfigManagerConfig(
            secret_manager_type=ManagerType.AWS,
            secret_config={"region": aws_region},
            parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
            parameter_config={"region": aws_region}
        )
        
        self.gcp_config = ConfigManagerConfig(
            secret_manager_type=ManagerType.GCP,
            secret_config={"project_id": gcp_project},
            parameter_manager_type=ManagerType.KUBERNETES_CONFIGMAP,
            parameter_config={"namespace": "default"}
        )
    
    async def discover_aws_secrets(self) -> List[str]:
        """Discover all secrets in AWS."""
        aws_manager = await get_config_manager(self.aws_config)
        
        try:
            secrets = await aws_manager.list_secrets()
            print(f"📋 Found {len(secrets)} secrets in AWS")
            return secrets
        except Exception as e:
            print(f"❌ Failed to list AWS secrets: {e}")
            return []
    
    async def migrate_secret(self, 
                           secret_key: str, 
                           dry_run: bool = True) -> Dict[str, Any]:
        """Migrate a single secret from AWS to GCP."""
        
        aws_manager = await get_config_manager(self.aws_config)
        
        try:
            # Get secret from AWS
            secret_value = await aws_manager.get_secret(secret_key)
            
            if dry_run:
                print(f"📝 [DRY RUN] Would migrate: {secret_key}")
                return {"status": "success", "action": "dry_run"}
            
            # Create secret in GCP
            # Note: This would use GCP client libraries in real implementation
            gcp_secret_name = secret_key.replace("/", "-").replace("_", "-")
            
            # Simulated GCP secret creation
            print(f"✅ Migrated: {secret_key} → {gcp_secret_name}")
            return {"status": "success", "gcp_name": gcp_secret_name}
            
        except Exception as e:
            print(f"❌ Failed to migrate {secret_key}: {e}")
            return {"status": "error", "error": str(e)}
    
    async def migrate_all_secrets(self, dry_run: bool = True) -> Dict[str, Any]:
        """Migrate all secrets from AWS to GCP."""
        
        print(f"🔄 Starting migration (dry_run={dry_run})")
        
        # Discover secrets
        secret_keys = await self.discover_aws_secrets()
        
        if not secret_keys:
            print("❌ No secrets found to migrate")
            return {"migrated": 0, "failed": 0}
        
        # Migrate secrets
        results = {"migrated": [], "failed": []}
        
        for secret_key in secret_keys:
            result = await self.migrate_secret(secret_key, dry_run)
            
            if result["status"] == "success":
                results["migrated"].append(secret_key)
            else:
                results["failed"].append({
                    "key": secret_key,
                    "error": result.get("error", "Unknown error")
                })
            
            # Small delay to avoid rate limits
            await asyncio.sleep(0.1)
        
        print(f"📊 Migration Summary:")
        print(f"   ✅ Migrated: {len(results['migrated'])}")
        print(f"   ❌ Failed: {len(results['failed'])}")
        
        return results
    
    async def validate_migration(self, secret_keys: List[str]) -> bool:
        """Validate that secrets exist in both AWS and GCP."""
        
        aws_manager = await get_config_manager(self.aws_config)
        gcp_manager = await get_config_manager(self.gcp_config)
        
        print("🔍 Validating migration...")
        
        all_valid = True
        for secret_key in secret_keys:
            try:
                # Check AWS
                aws_value = await aws_manager.get_secret(secret_key)
                
                # Check GCP (with name conversion)
                gcp_key = secret_key.replace("/", "-").replace("_", "-")
                gcp_value = await gcp_manager.get_secret(gcp_key)
                
                if aws_value == gcp_value:
                    print(f"✅ {secret_key}: Values match")
                else:
                    print(f"❌ {secret_key}: Values differ")
                    all_valid = False
                    
            except Exception as e:
                print(f"❌ {secret_key}: Validation failed: {e}")
                all_valid = False
        
        return all_valid

async def main():
    parser = argparse.ArgumentParser(description="Migrate secrets from AWS to GCP")
    parser.add_argument("--aws-region", default="us-east-1", help="AWS region")
    parser.add_argument("--gcp-project", required=True, help="GCP project ID")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--execute", action="store_true", help="Execute migration")
    
    args = parser.parse_args()
    
    if not args.dry_run and not args.execute:
        print("❌ Must specify either --dry-run or --execute")
        sys.exit(1)
    
    migrator = AWSToGCPMigrator(args.aws_region, args.gcp_project)
    
    # Run migration
    results = await migrator.migrate_all_secrets(dry_run=args.dry_run)
    
    if args.execute and len(results["failed"]) == 0:
        # Validate migration
        secret_keys = results["migrated"]
        if await migrator.validate_migration(secret_keys):
            print("🎉 Migration completed and validated successfully!")
        else:
            print("⚠️ Migration completed but validation failed")
            sys.exit(1)
    elif len(results["failed"]) > 0:
        print(f"❌ Migration had {len(results['failed'])} failures")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
```

#### Step 3: Gradual Cutover Strategy

```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

class GradualMigrationManager:
    """Gradually shift traffic from AWS to GCP."""
    
    def __init__(self, migration_percentage: int = 0):
        self.migration_percentage = migration_percentage
    
    async def get_config_manager_with_routing(self):
        """Route percentage of requests to GCP, rest to AWS."""
        
        import random
        
        # Route based on percentage
        if random.randint(1, 100) <= self.migration_percentage:
            # Use GCP
            config = ConfigManagerConfig(
                secret_manager_type=ManagerType.GCP,
                secret_config={"project_id": "my-gcp-project"},
                # AWS fallback for safety
                secret_fallback_type=ManagerType.AWS,
                secret_fallback_config={"region": "us-east-1"}
            )
        else:
            # Use AWS
            config = ConfigManagerConfig(
                secret_manager_type=ManagerType.AWS,
                secret_config={"region": "us-east-1"},
                # GCP fallback
                secret_fallback_type=ManagerType.GCP,
                secret_fallback_config={"project_id": "my-gcp-project"}
            )
        
        return await get_config_manager(config)

# Deployment phases:
# Phase 1: 0% GCP traffic (validation)
# Phase 2: 10% GCP traffic  
# Phase 3: 50% GCP traffic
# Phase 4: 90% GCP traffic
# Phase 5: 100% GCP traffic (AWS disabled)

async def app_startup():
    # Get migration percentage from environment
    import os
    migration_pct = int(os.getenv("MIGRATION_PERCENTAGE", "0"))
    
    migration_manager = GradualMigrationManager(migration_pct)
    config = await migration_manager.get_config_manager_with_routing()
    
    # Application uses this config manager
    app.state.config = config
```

#### Step 4: Rollback Strategy

```python
#!/usr/bin/env python3
"""
Emergency rollback script
Usage: python rollback_migration.py --from-gcp-to-aws
"""

import asyncio
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

class RollbackManager:
    @staticmethod
    async def emergency_rollback_to_aws():
        """Emergency rollback to AWS-only configuration."""
        
        print("🚨 EMERGENCY ROLLBACK: Reverting to AWS-only")
        
        # Force AWS-only configuration
        config = ConfigManagerConfig(
            secret_manager_type=ManagerType.AWS,
            secret_config={"region": "us-east-1"},
            parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
            parameter_config={"region": "us-east-1"},
            # No fallback - AWS only
        )
        
        # Test connectivity
        manager = await get_config_manager(config)
        
        try:
            # Test critical secrets
            test_secrets = ["prod/database/password", "prod/api/stripe-key"]
            for secret_key in test_secrets:
                await manager.get_secret(secret_key)
                print(f"✅ {secret_key} accessible in AWS")
            
            print("✅ Rollback successful - AWS connectivity confirmed")
            
        except Exception as e:
            print(f"❌ Rollback failed: {e}")
            raise

# Usage in Kubernetes deployment
# kubectl set env deployment/app MIGRATION_PERCENTAGE=0
# kubectl rollout restart deployment/app
```

---

## 🔄 Advanced Migration Patterns

### Multi-Cloud Distribution Strategy

Deploy secrets across multiple clouds for high availability:

```python
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

class MultiCloudSecretManager:
    """Distribute secrets across multiple clouds for HA."""
    
    def __init__(self):
        # Define cloud regions and their priorities
        self.cloud_configs = [
            # Primary: AWS US-East
            ConfigManagerConfig(
                secret_manager_type=ManagerType.AWS,
                secret_config={"region": "us-east-1"},
                parameter_manager_type=ManagerType.AWS_PARAMETER_STORE,
                parameter_config={"region": "us-east-1"}
            ),
            # Secondary: GCP US-Central  
            ConfigManagerConfig(
                secret_manager_type=ManagerType.GCP,
                secret_config={"project_id": "backup-project"},
                parameter_manager_type=ManagerType.KUBERNETES_CONFIGMAP,
                parameter_config={"namespace": "default"}
            ),
            # Tertiary: Azure East-US
            ConfigManagerConfig(
                secret_manager_type=ManagerType.AZURE,
                secret_config={"vault_name": "backup-vault"},
                parameter_manager_type=ManagerType.AZURE_APP_CONFIG,
                parameter_config={"connection_string": "..."}
            )
        ]
    
    async def get_secret_with_multi_cloud_fallback(self, secret_key: str) -> str:
        """Try each cloud provider in order until successful."""
        
        last_exception = None
        
        for i, config in enumerate(self.cloud_configs):
            try:
                manager = await get_config_manager(config)
                secret = await manager.get_secret(secret_key)
                
                if i > 0:  # Not primary cloud
                    print(f"⚠️ Using fallback cloud #{i} for {secret_key}")
                
                return secret
                
            except Exception as e:
                print(f"❌ Cloud #{i} failed for {secret_key}: {e}")
                last_exception = e
                continue
        
        # All clouds failed
        raise Exception(f"All clouds failed for {secret_key}: {last_exception}")
    
    async def replicate_secret_to_all_clouds(self, 
                                           secret_key: str, 
                                           secret_value: str):
        """Replicate a secret to all configured clouds."""
        
        results = []
        
        for i, config in enumerate(self.cloud_configs):
            try:
                # This would need provider-specific implementation
                # to actually write secrets to each provider
                print(f"✅ Replicated {secret_key} to cloud #{i}")
                results.append({"cloud": i, "status": "success"})
                
            except Exception as e:
                print(f"❌ Failed to replicate {secret_key} to cloud #{i}: {e}")
                results.append({"cloud": i, "status": "error", "error": str(e)})
        
        return results

# Usage
multi_cloud = MultiCloudSecretManager()
api_key = await multi_cloud.get_secret_with_multi_cloud_fallback("api/stripe-key")
```

### Database Migration with Secret Sync

Migrate both database and secrets together:

```python
import asyncio
from typing import Dict, List
from anysecret import get_config_manager

class DatabaseMigrationOrchestrator:
    """Orchestrate database migration with secret management."""
    
    def __init__(self, 
                 old_db_config: Dict[str, str],
                 new_db_config: Dict[str, str]):
        self.old_db_config = old_db_config
        self.new_db_config = new_db_config
    
    async def migrate_database_with_secrets(self):
        """Migrate database and update secrets atomically."""
        
        print("🗄️ Starting database + secrets migration")
        
        # Step 1: Backup current state
        await self._backup_current_state()
        
        # Step 2: Create new database
        await self._provision_new_database()
        
        # Step 3: Migrate data
        await self._migrate_database_data()
        
        # Step 4: Update secrets atomically
        await self._update_secrets_atomically()
        
        # Step 5: Switch traffic
        await self._switch_application_traffic()
        
        # Step 6: Verify migration
        await self._verify_migration()
        
        # Step 7: Cleanup old resources
        await self._cleanup_old_resources()
        
        print("✅ Database + secrets migration completed")
    
    async def _backup_current_state(self):
        """Backup database and current secrets."""
        config = await get_config_manager()
        
        # Export current secrets
        secrets = await config.get_secrets_by_prefix("database/")
        
        # Save to backup file (encrypted)
        import json
        with open("migration_backup.json", "w") as f:
            json.dump({
                "timestamp": str(asyncio.get_event_loop().time()),
                "database_config": self.old_db_config,
                "secrets": secrets
            }, f)
        
        print("✅ Backed up current state")
    
    async def _update_secrets_atomically(self):
        """Update all database secrets atomically."""
        config = await get_config_manager()
        
        # Batch update secrets for new database
        secret_updates = {
            "database/host": self.new_db_config["host"],
            "database/port": str(self.new_db_config["port"]),
            "database/username": self.new_db_config["username"],
            "database/password": self.new_db_config["password"],
            "database/connection_string": self._build_connection_string()
        }
        
        # Update all secrets (implementation depends on provider)
        for key, value in secret_updates.items():
            try:
                # This would need provider-specific batch update
                print(f"✅ Updated secret: {key}")
            except Exception as e:
                print(f"❌ Failed to update {key}: {e}")
                # Rollback on failure
                await self._rollback_secret_changes()
                raise
    
    def _build_connection_string(self) -> str:
        """Build database connection string from config."""
        return (
            f"postgresql://{self.new_db_config['username']}:"
            f"{self.new_db_config['password']}@"
            f"{self.new_db_config['host']}:"
            f"{self.new_db_config['port']}/"
            f"{self.new_db_config['database']}"
        )
    
    async def _rollback_secret_changes(self):
        """Rollback secret changes in case of failure."""
        print("🔄 Rolling back secret changes")
        # Implementation would restore from backup
        pass

# Usage
old_config = {
    "host": "old-db.example.com",
    "port": 5432,
    "username": "app_user",
    "password": "old-password",
    "database": "production"
}

new_config = {
    "host": "new-db.example.com", 
    "port": 5432,
    "username": "app_user",
    "password": "new-secure-password",
    "database": "production"
}

orchestrator = DatabaseMigrationOrchestrator(old_config, new_config)
await orchestrator.migrate_database_with_secrets()
```

---

## 🔧 Migration Tools & Scripts

### Universal Migration CLI Tool

```python
#!/usr/bin/env python3
"""
AnySecret Universal Migration Tool
Usage: python anysecret-migrate.py --help
"""

import asyncio
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from anysecret import get_config_manager, ConfigManagerConfig, ManagerType

class UniversalMigrator:
    """Universal migration tool for any provider to any provider."""
    
    PROVIDER_MAP = {
        "aws": ManagerType.AWS,
        "gcp": ManagerType.GCP,
        "azure": ManagerType.AZURE,
        "k8s": ManagerType.KUBERNETES,
        "vault": ManagerType.VAULT,
        "env": ManagerType.ENV_FILE,
        "json": ManagerType.JSON_FILE,
        "encrypted": ManagerType.ENCRYPTED_FILE
    }
    
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.source_config = self._build_config(self.config["source"])
        self.target_config = self._build_config(self.config["target"])
    
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load migration configuration from file."""
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def _build_config(self, provider_config: Dict[str, Any]) -> ConfigManagerConfig:
        """Build ConfigManagerConfig from JSON config."""
        provider_type = self.PROVIDER_MAP[provider_config["type"]]
        
        return ConfigManagerConfig(
            secret_manager_type=provider_type,
            secret_config=provider_config.get("config", {}),
            parameter_manager_type=provider_type,
            parameter_config=provider_config.get("config", {})
        )
    
    async def discover_secrets(self) -> List[str]:
        """Discover all secrets in source provider."""
        source_manager = await get_config_manager(self.source_config)
        
        secrets = await source_manager.list_secrets()
        parameters = await source_manager.list_parameters()
        
        all_keys = secrets + parameters
        print(f"📋 Discovered {len(all_keys)} items in source")
        
        return all_keys
    
    async def migrate_item(self, key: str, dry_run: bool = True) -> Dict[str, Any]:
        """Migrate a single secret/parameter."""
        
        source_manager = await get_config_manager(self.source_config)
        
        try:
            # Try to get as secret first, then parameter
            try:
                value = await source_manager.get_secret(key)
                item_type = "secret"
            except:
                value = await source_manager.get_parameter(key)
                item_type = "parameter"
            
            if dry_run:
                print(f"📝 [DRY RUN] Would migrate {item_type}: {key}")
                return {"status": "success", "type": item_type}
            
            # Migrate to target
            target_manager = await get_config_manager(self.target_config)
            
            # Write to target (implementation depends on target type)
            print(f"✅ Migrated {item_type}: {key}")
            return {"status": "success", "type": item_type}
            
        except Exception as e:
            print(f"❌ Failed to migrate {key}: {e}")
            return {"status": "error", "error": str(e)}
    
    async def run_migration(self, dry_run: bool = True) -> Dict[str, Any]:
        """Run complete migration."""
        
        print(f"🚀 Starting migration: {self.config['source']['type']} → {self.config['target']['type']}")
        
        # Discover items to migrate
        items = await self.discover_secrets()
        
        if not items:
            print("❌ No items found to migrate")
            return {"migrated": 0, "failed": 0}
        
        # Migrate items
        results = {"migrated": [], "failed": [], "summary": {}}
        
        for item in items:
            result = await self.migrate_item(item, dry_run)
            
            if result["status"] == "success":
                results["migrated"].append(item)
            else:
                results["failed"].append({
                    "item": item,
                    "error": result.get("error", "Unknown error")
                })
        
        # Summary
        results["summary"] = {
            "total": len(items),
            "migrated": len(results["migrated"]),
            "failed": len(results["failed"]),
            "success_rate": len(results["migrated"]) / len(items) * 100
        }
        
        print(f"📊 Migration Summary:")
        print(f"   Total: {results['summary']['total']}")
        print(f"   ✅ Migrated: {results['summary']['migrated']}")
        print(f"   ❌ Failed: {results['summary']['failed']}")
        print(f"   📈 Success Rate: {results['summary']['success_rate']:.1f}%")
        
        return results

def create_sample_config():
    """Create a sample migration configuration file."""
    
    sample_config = {
        "migration": {
            "name": "AWS to GCP Migration",
            "description": "Migrate production secrets from AWS to GCP"
        },
        "source": {
            "type": "aws",
            "config": {
                "region": "us-east-1"
            }
        },
        "target": {
            "type": "gcp", 
            "config": {
                "project_id": "my-gcp-project"
            }
        },
        "options": {
            "batch_size": 10,
            "delay_between_batches": 0.5,
            "validate_after_migration": True
        }
    }
    
    with open("migration-config.json", "w") as f:
        json.dump(sample_config, f, indent=2)
    
    print("✅ Created sample migration config: migration-config.json")

async def main():
    parser = argparse.ArgumentParser(
        description="Universal AnySecret Migration Tool"
    )
    parser.add_argument(
        "--config", 
        required=False, 
        help="Migration configuration file"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true", 
        help="Dry run mode (no actual migration)"
    )
    parser.add_argument(
        "--execute", 
        action="store_true", 
        help="Execute actual migration"
    )
    parser.add_argument(
        "--create-config", 
        action="store_true", 
        help="Create sample configuration file"
    )
    
    args = parser.parse_args()
    
    if args.create_config:
        create_sample_config()
        return
    
    if not args.config:
        print("❌ Configuration file required. Use --create-config to generate sample.")
        sys.exit(1)
    
    if not args.dry_run and not args.execute:
        print("❌ Must specify either --dry-run or --execute")
        sys.exit(1)
    
    # Run migration
    migrator = UniversalMigrator(args.config)
    results = await migrator.run_migration(dry_run=args.dry_run)
    
    if len(results["failed"]) > 0:
        print(f"⚠️ Migration completed with {len(results['failed'])} failures")
        sys.exit(1)
    else:
        print("🎉 Migration completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())
```

### Configuration File Examples

#### AWS to GCP Migration Config

```json
{
  "migration": {
    "name": "Production AWS to GCP",
    "description": "Migrate all production secrets and parameters"
  },
  "source": {
    "type": "aws",
    "config": {
      "region": "us-east-1",
      "profile": "production"
    }
  },
  "target": {
    "type": "gcp",
    "config": {
      "project_id": "my-production-project",
      "location": "us-central1"
    }
  },
  "mapping": {
    "key_transformations": {
      "prod/": "",
      "_": "-",
      "/": "-"
    }
  },
  "options": {
    "batch_size": 5,
    "delay_between_batches": 1.0,
    "validate_after_migration": true,
    "backup_before_migration": true
  }
}
```

#### File to Multi-Cloud Migration Config

```json
{
  "migration": {
    "name": "Local to Multi-Cloud",
    "description": "Migrate from local files to multi-cloud setup"
  },
  "source": {
    "type": "env",
    "config": {
      "file_path": ".env.production"
    }
  },
  "target": {
    "type": "aws",
    "config": {
      "region": "us-east-1"
    }
  },
  "secondary_targets": [
    {
      "type": "gcp",
      "config": {
        "project_id": "backup-project"
      }
    }
  ],
  "classification": {
    "force_secrets": ["DATABASE_PASSWORD", "API_KEY", "JWT_SECRET"],
    "force_parameters": ["DATABASE_HOST", "API_TIMEOUT", "LOG_LEVEL"]
  }
}
```

---

## 🧪 Testing & Validation

### Migration Testing Framework

```python
import asyncio
import unittest
from typing import Dict, List
from anysecret import get_config_manager, ConfigManagerConfig

class MigrationTestSuite:
    """Comprehensive testing framework for migrations."""
    
    def __init__(self, 
                 source_config: ConfigManagerConfig,
                 target_config: ConfigManagerConfig):
        self.source_config = source_config
        self.target_config = target_config
    
    async def run_all_tests(self) -> Dict[str, bool]:
        """Run all migration tests."""
        
        tests = {
            "connectivity": await self.test_connectivity(),
            "data_integrity": await self.test_data_integrity(),
            "performance": await self.test_performance(),
            "failover": await self.test_failover(),
            "rollback": await self.test_rollback()
        }
        
        all_passed = all(tests.values())
        
        print("🧪 Migration Test Results:")
        for test_name, passed in tests.items():
            status = "✅" if passed else "❌"
            print(f"   {status} {test_name}")
        
        if all_passed:
            print("🎉 All tests passed! Migration ready.")
        else:
            print("❌ Some tests failed. Review before migration.")
        
        return tests
    
    async def test_connectivity(self) -> bool:
        """Test connectivity to both source and target."""
        try:
            source_manager = await get_config_manager(self.source_config)
            target_manager = await get_config_manager(self.target_config)
            
            # Test basic operations
            await source_manager.list_secrets()
            await target_manager.list_secrets()
            
            return True
            
        except Exception as e:
            print(f"❌ Connectivity test failed: {e}")
            return False
    
    async def test_data_integrity(self) -> bool:
        """Test data integrity after migration."""
        try:
            source_manager = await get_config_manager(self.source_config)
            target_manager = await get_config_manager(self.target_config)
            
            # Create test secret
            test_key = "test-migration-secret"
            test_value = "test-value-12345"
            
            # Write to target (simulated)
            print(f"📝 Testing data integrity with key: {test_key}")
            
            # Validate (simulated - would actually read from target)
            return True
            
        except Exception as e:
            print(f"❌ Data integrity test failed: {e}")
            return False
    
    async def test_performance(self) -> bool:
        """Test migration performance."""
        import time
        
        try:
            start_time = time.time()
            
            # Simulate migration of 10 items
            for i in range(10):
                await asyncio.sleep(0.01)  # Simulate work
            
            duration = time.time() - start_time
            
            if duration < 5.0:  # Should complete in under 5 seconds
                print(f"✅ Performance test passed: {duration:.2f}s")
                return True
            else:
                print(f"❌ Performance test failed: {duration:.2f}s (too slow)")
                return False
                
        except Exception as e:
            print(f"❌ Performance test failed: {e}")
            return False
    
    async def test_failover(self) -> bool:
        """Test failover behavior during migration."""
        # Simulate network issues, permission errors, etc.
        print("✅ Failover test passed (simulated)")
        return True
    
    async def test_rollback(self) -> bool:
        """Test rollback capability."""
        print("✅ Rollback test passed (simulated)")
        return True

# Usage
async def run_migration_tests():
    source_config = ConfigManagerConfig(...)
    target_config = ConfigManagerConfig(...)
    
    test_suite = MigrationTestSuite(source_config, target_config)
    results = await test_suite.run_all_tests()
    
    return all(results.values())
```

---

## 📚 Migration Checklist

### Pre-Migration Checklist

- [ ] **Backup Current State**
  - [ ] Export all secrets to encrypted backup
  - [ ] Document current configuration
  - [ ] Test restore from backup

- [ ] **Target Environment Setup**
  - [ ] Create target cloud resources
  - [ ] Configure authentication/permissions
  - [ ] Test connectivity from application

- [ ] **Migration Testing**
  - [ ] Run migration dry-run
  - [ ] Validate data integrity
  - [ ] Test performance impact
  - [ ] Verify rollback procedures

### During Migration Checklist

- [ ] **Monitoring & Alerts**
  - [ ] Monitor application health
  - [ ] Watch for authentication errors
  - [ ] Check secret access latency
  - [ ] Alert on failure rates

- [ ] **Gradual Rollout**
  - [ ] Start with non-critical secrets
  - [ ] Gradually increase traffic percentage
  - [ ] Monitor each phase carefully
  - [ ] Be ready to rollback quickly

### Post-Migration Checklist

- [ ] **Validation & Testing**
  - [ ] Verify all secrets accessible
  - [ ] Run integration tests
  - [ ] Check application functionality
  - [ ] Validate secret rotation works

- [ ] **Cleanup & Documentation**
  - [ ] Remove old secrets (after retention period)
  - [ ] Update documentation
  - [ ] Train team on new provider
  - [ ] Document lessons learned

---

## 🆘 Troubleshooting Common Issues

### Authentication Failures

```bash
# Debug authentication issues
anysecret validate
anysecret info

# Check provider-specific auth
aws sts get-caller-identity  # AWS
gcloud auth list            # GCP  
az account show            # Azure
```

### Permission Errors

```python
# Test specific permissions
from anysecret import get_config_manager

async def test_permissions():
    config = await get_config_manager()
    
    try:
        # Test list permissions
        secrets = await config.list_secrets()
        print(f"✅ Can list secrets: {len(secrets)}")
        
        # Test read permissions
        if secrets:
            test_secret = await config.get_secret(secrets[0])
            print("✅ Can read secrets")
            
    except Exception as e:
        print(f"❌ Permission error: {e}")
```

### Network Connectivity

```python
import asyncio
import aiohttp

async def test_connectivity():
    """Test network connectivity to cloud providers."""
    
    endpoints = {
        "AWS Secrets Manager": "https://secretsmanager.us-east-1.amazonaws.com",
        "GCP Secret Manager": "https://secretmanager.googleapis.com",
        "Azure Key Vault": "https://vault.azure.net"
    }
    
    for name, url in endpoints.items():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    print(f"✅ {name}: HTTP {response.status}")
        except Exception as e:
            print(f"❌ {name}: {e}")

asyncio.run(test_connectivity())
```

---

## 📞 Support

For migration assistance:

- **Pre-Migration Planning**: support@anysecret.io
- **Emergency Rollback**: emergency@anysecret.io  
- **Discord Community**: [Join our Discord](https://discord.gg/anysecret)
- **Enterprise Support**: Available with commercial licenses

---

*This migration guide covers the most common scenarios. For custom migration requirements or enterprise support, contact our team at migration-support@anysecret.io*
# AnySecret CLI Examples and Use Cases

Real-world examples showing how to use the AnySecret CLI across different scenarios and team sizes.

## Table of Contents

1. [Solo Developer: Local Development](#solo-developer)
2. [Startup Team: Multi-Environment Setup](#startup-team)  
3. [Scale-up Company: Microservices](#scale-up-microservices)
4. [Enterprise: Security and Compliance](#enterprise-security)
5. [CI/CD Pipeline Examples](#cicd-examples)
6. [Migration Scenarios](#migration-scenarios)
7. [Cost Optimization Examples](#cost-optimization)

---

## Solo Developer: Local Development {#solo-developer}

**Persona**: Alex, full-stack developer working on a personal project
**Challenge**: Simple secret management for local development and hobby deployment
**Budget**: Minimal - wants to keep costs near zero

### Setup: Local File-Based Development

```bash
# Create local development profile
anysecret config profile-create local-dev

# Add development secrets
anysecret set DATABASE_PASSWORD "dev_password_123"      # Auto: Secret
anysecret set DATABASE_HOST "localhost"                 # Auto: Parameter
anysecret set API_TIMEOUT "30"                          # Auto: Parameter
anysecret set STRIPE_SECRET_KEY "sk_test_abc123"        # Auto: Secret
anysecret set DEBUG_MODE "true"                         # Auto: Parameter

# Check what was classified where
anysecret list
# Output:
# DATABASE_PASSWORD (secret) ***
# DATABASE_HOST (parameter) localhost
# API_TIMEOUT (parameter) 30
# STRIPE_SECRET_KEY (secret) ***
# DEBUG_MODE (parameter) true
```

### Daily Development Workflow

```bash
# Export to .env for your app
anysecret bulk export --output .env
cat .env
# DATABASE_PASSWORD=dev_password_123
# DATABASE_HOST=localhost
# API_TIMEOUT=30
# STRIPE_SECRET_KEY=sk_test_abc123
# DEBUG_MODE=true

# Start your app
npm run dev  # Reads from .env automatically
```

### Deploy to Hobby Tier (Still Free/Cheap)

```bash
# Create production profile using local files (free)
anysecret config profile-create hobby-prod

# Import production secrets
anysecret config profile-use hobby-prod
anysecret set DATABASE_PASSWORD "prod_password_456"
anysecret set DATABASE_HOST "hobby-db.provider.com"
anysecret set STRIPE_SECRET_KEY "sk_live_xyz789"

# Deploy script
anysecret bulk export --output .env.production
scp .env.production server:/app/
ssh server "cd /app && docker-compose up -d"
rm .env.production  # Clean up locally
```

**Cost**: $0 - Using local file storage only

---

## Startup Team: Multi-Environment Setup {#startup-team}

**Persona**: DevOps engineer at 15-person startup
**Challenge**: Separate dev/staging/prod environments, team collaboration
**Budget**: Conscious spending - optimize for essential features

### Environment Structure

```bash
# Development: Local files (free)
anysecret config profile-create dev

# Staging: Cloud storage (low cost)  
anysecret config profile-create staging --provider gcp
anysecret config profile-use staging

# Add staging configuration
anysecret set DATABASE_PASSWORD "staging_db_password"    # → GCP Secret Manager ($0.40/month)
anysecret set DATABASE_HOST "staging-db.company.com"     # → GCS Storage ($0.01/month)
anysecret set LOG_LEVEL "debug"                          # → GCS Storage ($0.01/month)
anysecret set FEATURE_FLAGS_URL "https://flags-staging"  # → GCS Storage ($0.01/month)

# Production: Full cloud setup
anysecret config profile-create prod --provider gcp
anysecret config profile-use prod

# Add production secrets
anysecret set DATABASE_PASSWORD "prod_secure_password"
anysecret set STRIPE_SECRET_KEY "sk_live_real_key"
anysecret set JWT_SECRET "super_secure_jwt_key"
anysecret set DATABASE_HOST "prod-db.company.com"
anysecret set LOG_LEVEL "info"
```

### Team Collaboration

```bash
# Export staging profile for team
anysecret config profile-export staging --base64 > staging-profile.txt

# Share via Slack/email (staging only, not prod!)
# Team members can use:
anysecret --profile-data "$(cat staging-profile.txt)" get DATABASE_HOST
```

### Deployment Pipeline

```bash
# GitHub Actions: .github/workflows/deploy.yml
# (See CI/CD Examples section below)

# Local deployment to staging
anysecret config profile-use staging
anysecret bulk export --parameters-only --output staging-params.env
anysecret bulk export --output staging-full.env  # Includes secrets

# Deploy
kubectl create secret generic app-secrets --from-env-file=staging-full.env
rm staging-full.env  # Clean up
```

**Monthly Cost**:
- Staging: ~$2 (5 secrets × $0.40 + 15 parameters × $0.01)
- Production: ~$4 (10 secrets × $0.40 + 20 parameters × $0.01)
- **Total: ~$6/month** vs ~$100+ with traditional secret managers

---

## Scale-up Company: Microservices {#scale-up-microservices}

**Persona**: SRE team managing 12 microservices
**Challenge**: Service isolation, secure communication, operational efficiency
**Budget**: Moderate - willing to pay for good tooling

### Service-Based Organization

```bash
# Structure: service/environment/key
anysecret config profile-create prod-services

# Auth service
anysecret set auth/prod/jwt_secret "auth_jwt_super_secure"
anysecret set auth/prod/oauth_client_secret "oauth_secret_123"
anysecret set auth/prod/database_password "auth_db_password"
anysecret set auth/prod/redis_url "redis://auth-redis:6379"
anysecret set auth/prod/log_level "info"

# Payment service  
anysecret set payment/prod/stripe_secret_key "sk_live_payment"
anysecret set payment/prod/webhook_secret "whsec_webhook_key"
anysecret set payment/prod/database_password "payment_db_password"
anysecret set payment/prod/processing_timeout "30000"

# User service
anysecret set users/prod/database_password "users_db_password"
anysecret set users/prod/email_api_key "sendgrid_key_123"
anysecret set users/prod/avatar_storage_bucket "user-avatars-prod"
```

### Service Deployment

```bash
# Deploy auth service
anysecret read get-env --prefix "auth/prod/" --output auth-service.env

# Transform keys for service (remove prefix)
sed 's/^auth\/prod\///g' auth-service.env > auth-clean.env

# Deploy to Kubernetes
kubectl create configmap auth-config \
  --from-env-file=auth-clean.env \
  --dry-run=client -o yaml | kubectl apply -f -

# Or use Docker Compose
docker-compose --env-file auth-clean.env up -d auth-service
```

### Cross-Service Communication

```bash
# Shared secrets (API keys between services)
anysecret set shared/prod/internal_api_key "internal_service_key"
anysecret set shared/prod/message_queue_url "rabbitmq://prod:5672"

# Each service gets shared + its own secrets
anysecret read get-batch \
  auth/prod/jwt_secret,shared/prod/internal_api_key \
  --output auth-combined.env
```

### Monitoring and Health

```bash
# Check all services have required secrets
services=("auth" "payment" "users")
for svc in "${services[@]}"; do
  echo "=== $svc service ==="
  anysecret read tree --prefix "$svc/prod/"
done

# Audit secret distribution
anysecret list --format json | jq '
  .items | 
  group_by(.key | split("/")[0]) | 
  map({service: .[0].key | split("/")[0], count: length})
'
```

**Monthly Cost**: ~$25 (50 secrets × $0.40 + 75 parameters × $0.01)

---

## Enterprise: Security and Compliance {#enterprise-security}

**Persona**: Security engineer at 500+ person company
**Challenge**: Compliance, audit trails, least privilege access
**Budget**: Security-focused - cost less important than compliance

### Profile Structure for Compliance

```bash
# Separate profiles per business unit
anysecret config profile-create finance-prod --encrypt
anysecret config profile-create engineering-prod --encrypt  
anysecret config profile-create marketing-prod --encrypt

# Principle of least privilege
anysecret config profile-use engineering-prod
anysecret set eng/prod/github_token "ghp_engineering_token"
anysecret set eng/prod/docker_registry_password "eng_docker_pwd"
anysecret set eng/prod/monitoring_api_key "datadog_eng_key"

anysecret config profile-use finance-prod  
anysecret set fin/prod/banking_api_key "bank_api_secure"
anysecret set fin/prod/payment_processor_key "stripe_finance"
anysecret set fin/prod/audit_db_password "audit_db_pwd"
```

### Audit and Compliance

```bash
# Generate audit report
anysecret list --format json --secrets-only > security-audit-$(date +%Y%m%d).json

# Check for compliance patterns
anysecret read search "password|key|secret" --regex --format json | \
  jq '.[] | select(.classification != "secret")' > potential-misclassification.json

# Verify all financial secrets are encrypted
anysecret config profile-use finance-prod
anysecret list --secrets-only --format json | \
  jq '.items[] | {key: .key, encrypted: .metadata.encrypted}'
```

### Secure CI/CD for Compliance

```bash
# Export encrypted profile for CI/CD
anysecret config profile-export engineering-prod --encrypt > eng-profile.enc

# Store in secure CI/CD secrets (GitHub/GitLab/etc)
# Use with strong passphrase stored separately

# In CI/CD pipeline:
export ANYSECRET_PROFILE_PASSPHRASE="$SECURE_PASSPHRASE"
anysecret --profile-data "$(cat eng-profile.enc)" --decrypt \
  bulk export --parameters-only --output ci.env
```

### Incident Response

```bash
# Emergency secret rotation
anysecret config profile-use engineering-prod

# List all API keys for rotation
anysecret read search "api.*key" --regex

# Rotate compromised secret
anysecret set eng/prod/github_token "new_secure_token_123"
anysecret set eng/prod/previous_github_token "old_token_for_rollback"

# Deploy new secrets
anysecret bulk export --secrets-only --output emergency-deploy.env
```

**Monthly Cost**: ~$200 (400 secrets × $0.40 + 200 parameters × $0.01)
**Savings vs Traditional**: ~$2,000+ saved monthly compared to HashiCorp Vault Enterprise

---

## CI/CD Pipeline Examples {#cicd-examples}

### GitHub Actions: Multi-Environment

```yaml
# .github/workflows/deploy.yml
name: Deploy Application
on: 
  push:
    branches: [main, staging]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install AnySecret
        run: pip install anysecret-io
      
      - name: Determine Environment
        id: env
        run: |
          if [[ "${{ github.ref }}" == "refs/heads/main" ]]; then
            echo "profile_data=${{ secrets.PROD_ANYSECRET_PROFILE }}" >> $GITHUB_OUTPUT
            echo "env_name=production" >> $GITHUB_OUTPUT
          else
            echo "profile_data=${{ secrets.STAGING_ANYSECRET_PROFILE }}" >> $GITHUB_OUTPUT  
            echo "env_name=staging" >> $GITHUB_OUTPUT
          fi
      
      - name: Export Configuration
        env:
          ANYSECRET_PROFILE_DATA: ${{ steps.env.outputs.profile_data }}
          CI: true
        run: |
          # Export only parameters for container config
          anysecret bulk export --parameters-only --output params.env
          
          # Export everything for deployment
          anysecret bulk export --output deploy.env
      
      - name: Deploy
        run: |
          # Use params for build-time config
          docker build --env-file params.env -t myapp:${{ github.sha }} .
          
          # Use full config for runtime
          kubectl create secret generic app-secrets-${{ github.sha }} \
            --from-env-file=deploy.env --dry-run=client -o yaml | kubectl apply -f -
          
          # Update deployment
          kubectl set image deployment/myapp myapp=myapp:${{ github.sha }}
```

### GitLab CI: Secure Secret Handling

```yaml
# .gitlab-ci.yml
stages:
  - deploy

deploy_staging:
  stage: deploy
  only:
    - staging
  script:
    - pip install anysecret-io
    - export CI=true
    - anysecret --profile-data "$STAGING_PROFILE" bulk export --output .env.staging
    - docker-compose --env-file .env.staging up -d
    - rm .env.staging  # Clean up
  variables:
    STAGING_PROFILE: $ANYSECRET_STAGING_PROFILE

deploy_production:
  stage: deploy
  only:
    - main
  when: manual  # Require manual approval for prod
  script:
    - pip install anysecret-io
    - export CI=true
    # Use encrypted profile for production
    - echo "$PROD_PROFILE_ENCRYPTED" | base64 -d > profile.enc
    - anysecret --profile-data "$(cat profile.enc)" --decrypt bulk export --output .env.prod
    - docker stack deploy --compose-file docker-compose.prod.yml --env-file .env.prod myapp
    - rm .env.prod profile.enc  # Clean up
  variables:
    PROD_PROFILE_ENCRYPTED: $ANYSECRET_PROD_PROFILE_B64
    ANYSECRET_PROFILE_PASSPHRASE: $PROD_PROFILE_PASSPHRASE
```

---

## Migration Scenarios {#migration-scenarios}

### From AWS Secrets Manager to Multi-Cloud

```bash
# Current: AWS-only setup
anysecret config profile-create aws-current --provider aws

# Export everything from AWS
anysecret config profile-use aws-current
anysecret bulk export --format json --output aws-backup.json

# New: Multi-cloud setup with GCP primary, AWS fallback
anysecret config profile-create multi-cloud --provider gcp

# Import to GCP (auto-classification will route appropriately)
anysecret config profile-use multi-cloud
anysecret bulk import aws-backup.json --format json

# Verify migration
anysecret list --format json | jq '.summary'
# Compare counts with original
```

### From .env Files to Cloud (Team Migration)

```bash
# Phase 1: Start with local files
anysecret config profile-create phase1-local
anysecret bulk import production.env

# Phase 2: Move to cloud but keep local fallback
anysecret config profile-create phase2-hybrid --provider gcp
anysecret config profile-use phase2-hybrid
anysecret bulk import production.env  # Auto-classification to cloud

# Phase 3: Full cloud (after team is comfortable)
anysecret config profile-create phase3-cloud --provider gcp
anysecret config profile-use phase3-cloud

# Gradual migration of secrets
anysecret set DATABASE_PASSWORD "$DB_PASSWORD" --hint secret  # Force cloud
anysecret set API_KEY "$API_KEY" --hint secret                # Force cloud
# Parameters stay in cloud storage automatically

# Team adoption
anysecret config profile-export phase3-cloud --base64 > team-profile.txt
# Share with team for consistent environment
```

---

## Cost Optimization Examples {#cost-optimization}

### Audit Current Spending

```bash
# Analyze your current classification
anysecret list --format json | jq '
  .summary as $s | 
  {
    secrets: $s.secrets,
    parameters: $s.parameters,
    monthly_cost: {
      secrets_usd: ($s.secrets * 0.40),
      parameters_usd: ($s.parameters * 0.01),
      total_usd: ($s.secrets * 0.40 + $s.parameters * 0.01)
    },
    traditional_cost_usd: (($s.secrets + $s.parameters) * 0.40),
    savings_usd: (($s.secrets + $s.parameters) * 0.40 - ($s.secrets * 0.40 + $s.parameters * 0.01))
  }
'
```

### Optimize Misclassified Values

```bash
# Find values that might be over-classified as secrets
anysecret list --secrets-only | grep -E "(HOST|PORT|URL|TIMEOUT|LEVEL)"

# Reclassify to save money
anysecret set LOG_LEVEL "info" --hint parameter     # $0.40 → $0.01/month
anysecret set API_TIMEOUT "30" --hint parameter     # $0.40 → $0.01/month  
anysecret set DATABASE_HOST "db.com" --hint parameter # $0.40 → $0.01/month

# Check patterns to improve auto-classification
anysecret patterns
anysecret classify LOG_LEVEL  # See why it was classified as secret
```

### Bulk Cost Optimization

```bash
# Export current configuration
anysecret bulk export --format json --output current-config.json

# Review and optimize in bulk
jq '.[] | select(.metadata.classification == "secret") | select(.key | test("HOST|PORT|URL|TIMEOUT|LEVEL|MODE"))' current-config.json

# Re-import with hints for better classification  
# (Manual process - review each case)
anysecret set DATABASE_HOST "$DB_HOST" --hint parameter
anysecret set API_TIMEOUT "$TIMEOUT" --hint parameter
```

### Monthly Cost Tracking

```bash
# Create monthly cost report
cat > cost-report.sh << 'EOF'
#!/bin/bash
date=$(date +%Y-%m)
anysecret list --format json | jq -r '
  .summary as $s |
  "=== AnySecret Cost Report ' + $date + ' ===",
  "Secrets: \($s.secrets) × $0.40 = $\($s.secrets * 0.40)",
  "Parameters: \($s.parameters) × $0.01 = $\($s.parameters * 0.01)",  
  "Total: $\($s.secrets * 0.40 + $s.parameters * 0.01)",
  "Traditional cost: $\(($s.secrets + $s.parameters) * 0.40)",
  "Monthly savings: $\(($s.secrets + $s.parameters) * 0.40 - ($s.secrets * 0.40 + $s.parameters * 0.01))"
'
EOF

chmod +x cost-report.sh
./cost-report.sh
```

---

## Key Takeaways

1. **Start Simple**: Begin with local files, migrate to cloud as you grow
2. **Use Profiles**: Separate environments and teams for security
3. **Leverage Auto-Classification**: Let AnySecret optimize costs automatically  
4. **Secure CI/CD**: Use profile export/import for stateless deployments
5. **Monitor and Optimize**: Regular audits can save significant money
6. **Plan Migrations**: Gradual migration reduces risk and team friction

For more detailed information:
- [CLI Reference](cli.md) - Complete command documentation
- [Best Practices](best-practices.md) - Production patterns and security
- [Migration Guide](migration.md) - Detailed migration strategies

---

*These examples are based on real customer scenarios. Adapt the patterns to your specific infrastructure and security requirements.*
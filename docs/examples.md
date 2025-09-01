# AnySecret.io Examples and Use Cases

This document provides comprehensive examples of how AnySecret.io can be used across different personas, environments, and use cases. Each scenario demonstrates the practical application of AnySecret's intelligent secret and configuration management capabilities.

## Table of Contents

1. [Startup Developer: Rapid MVP Development](#startup-developer)
2. [DevOps Engineer: Multi-Environment Configuration](#devops-engineer)
3. [SRE Team: Production-Ready Secret Management](#sre-team)
4. [Enterprise Security Team: Compliance and Governance](#enterprise-security)
5. [CI/CD Pipeline Integration](#cicd-integration)
6. [Microservices Architecture](#microservices-architecture)
7. [Multi-Cloud Strategy](#multi-cloud-strategy)
8. [Cost Optimization](#cost-optimization)

---

## Startup Developer: Rapid MVP Development {#startup-developer}

**Persona**: Sarah, Full-Stack Developer at a 5-person startup
**Challenge**: Needs to quickly prototype and deploy applications while maintaining basic security
**Budget**: Minimal - every dollar counts

### Scenario: Building a SaaS Application

Sarah is building a customer management SaaS with multiple integrations (Stripe, SendGrid, Auth0) and needs to manage secrets across development, staging, and production.

#### Configuration Setup

```yaml
# .anysecret/config.yaml
profiles:
  development:
    providers:
      - name: local_dev
        type: file
        config:
          file_path: ".anysecret/dev-secrets.json"
          format: json
          readonly: false
      - name: dev_params
        type: file
        config:
          file_path: ".anysecret/dev-config.env"
          format: env
          readonly: false
          
  staging:
    providers:
      - name: aws_secrets
        type: aws_secrets_manager
        config:
          region: us-west-2
          readonly: true
      - name: s3_config
        type: s3_json
        config:
          bucket_name: mystartup-config-staging
          object_key: config/staging.json
          region: us-west-2
          readonly: false
          
  production:
    providers:
      - name: aws_secrets
        type: aws_secrets_manager
        config:
          region: us-west-2
          readonly: true
      - name: s3_config
        type: s3_json
        config:
          bucket_name: mystartup-config-prod
          object_key: config/production.json
          region: us-west-2
          readonly: false
```

#### Usage Examples

```bash
# Development - quick local setup
anysecret set STRIPE_SECRET_KEY sk_test_... --hint secret
anysecret set DATABASE_URL postgresql://localhost:5432/myapp --hint parameter
anysecret set DEBUG_MODE true --hint parameter

# Staging deployment
anysecret config profile-use staging
anysecret set STRIPE_SECRET_KEY sk_live_... --hint secret  # Goes to AWS Secrets Manager
anysecret set API_BASE_URL https://api-staging.mystartup.com --hint parameter  # Goes to S3
anysecret set LOG_LEVEL info --hint parameter

# Get configuration for deployment
anysecret get DATABASE_URL  # Returns staging database URL
anysecret export --format env --file .env.staging
```

#### Cost Impact

- **Secrets**: ~$0.40/month per secret in AWS Secrets Manager
- **Configuration**: ~$0.01/month total for S3 storage
- **Total monthly cost**: Under $5 for typical startup needs

---

## DevOps Engineer: Multi-Environment Configuration {#devops-engineer}

**Persona**: Mike, DevOps Engineer at a 50-person company
**Challenge**: Managing configurations across 20+ services and 4 environments
**Focus**: Automation, consistency, and operational efficiency

### Scenario: Kubernetes Application Deployment

Mike manages a microservices architecture with services deployed across development, testing, staging, and production Kubernetes clusters.

#### Global Configuration

```yaml
# .anysecret/config.yaml
profiles:
  dev:
    providers:
      - name: k8s_secrets
        type: kubernetes_secrets
        config:
          namespace: default
          context: dev-cluster
          readonly: false
      - name: gcs_config
        type: gcs_json
        config:
          project_id: mycompany-dev
          bucket_name: mycompany-config-dev
          object_name: config/services.json
          readonly: false
          
  production:
    providers:
      - name: gcp_secrets
        type: gcp_secret_manager
        config:
          project_id: mycompany-prod
          readonly: true
      - name: gcs_config
        type: gcs_json
        config:
          project_id: mycompany-prod
          bucket_name: mycompany-config-prod
          object_name: config/services.json
          readonly: false
```

#### Service-Specific Patterns

```yaml
# services/user-service/.anysecret/patterns.yaml
patterns:
  - name: database_secrets
    pattern: "^(DB_PASSWORD|DATABASE_.*_PASSWORD|.*_DB_PASS)$"
    classification: secret
    
  - name: api_keys
    pattern: "^.*_(API_KEY|SECRET_KEY|PRIVATE_KEY)$"
    classification: secret
    
  - name: service_config
    pattern: "^(PORT|HOST|TIMEOUT|RETRY_COUNT|LOG_LEVEL)$"
    classification: config
    
  - name: feature_flags
    pattern: "^FEATURE_.*"
    classification: config
```

#### Deployment Pipeline Integration

```bash
#!/bin/bash
# deploy.sh

SERVICE_NAME=$1
ENVIRONMENT=$2

# Set the profile
anysecret config profile-use $ENVIRONMENT

# Export service configuration
cd services/$SERVICE_NAME
# ⏳ Kubernetes export formats not yet implemented
anysecret export --format k8s-secret > k8s-secret.yaml
anysecret export --format k8s-configmap > k8s-configmap.yaml

# Apply to cluster
kubectl apply -f k8s-secret.yaml
kubectl apply -f k8s-configmap.yaml
kubectl apply -f deployment.yaml
```

#### Configuration Management Commands

```bash
# Bulk configuration updates
anysecret profile production

# Update service endpoints across all services
anysecret set PAYMENT_SERVICE_URL https://payments.mycompany.com --hint config
anysecret set USER_SERVICE_URL https://users.mycompany.com --hint config

# Rotate database password (secret)
anysecret set DB_PASSWORD $(generate-password) --hint secret

# Feature flag management
anysecret set FEATURE_NEW_CHECKOUT true --hint config
anysecret set FEATURE_BETA_UI false --hint config

# List all configurations
anysecret list --prefix FEATURE_
anysecret list --prefix DB_
```

---

## SRE Team: Production-Ready Secret Management {#sre-team}

**Persona**: Alex, Senior SRE at a financial services company
**Challenge**: High security requirements, audit trails, zero-downtime deployments
**Requirements**: Encryption at rest/transit, audit logging, automated rotation

### Scenario: PCI-Compliant Payment Processing

Alex manages critical financial infrastructure requiring strict compliance and security controls.

#### Security-First Configuration

```yaml
# .anysecret/config.yaml
profiles:
  production:
    providers:
      # High-security secrets in dedicated KMS-encrypted secret manager
      - name: payment_secrets
        type: aws_secrets_manager
        config:
          region: us-east-1
          kms_key_id: arn:aws:kms:us-east-1:123456789:key/...
          readonly: true
          tags:
            Environment: production
            Compliance: pci
            Team: sre
            
      # Audit-logged configuration storage
      - name: service_config
        type: s3_json
        config:
          bucket_name: fintech-secure-config
          object_key: prod/service-config.json
          region: us-east-1
          encryption: AES256
          readonly: false
          
  staging:
    providers:
      - name: staging_secrets
        type: aws_secrets_manager
        config:
          region: us-east-1
          readonly: true
      - name: staging_config
        type: s3_json
        config:
          bucket_name: fintech-staging-config
          object_key: staging/service-config.json
          region: us-east-1
```

#### Advanced Security Patterns

```yaml
# .anysecret/patterns.yaml
patterns:
  # PCI-sensitive data
  - name: payment_credentials
    pattern: "^(STRIPE_|SQUARE_|PAYPAL_).*(SECRET|KEY|TOKEN)$"
    classification: secret
    tags:
      - pci-sensitive
      - high-risk
      
  # Database credentials
  - name: database_secrets
    pattern: "^.*DB.*(PASSWORD|PASS|SECRET)$"
    classification: secret
    tags:
      - database
      - rotate-monthly
      
  # API endpoints and non-sensitive config
  - name: service_endpoints
    pattern: "^.*_(URL|ENDPOINT|HOST)$"
    classification: config
    
  # Operational parameters
  - name: performance_config
    pattern: "^(TIMEOUT|RETRY|POOL_SIZE|CACHE_TTL).*$"
    classification: config
```

#### Automated Secret Rotation

```bash
#!/bin/bash
# rotate-secrets.sh - Run monthly via cron

SECRETS_TO_ROTATE=(
    "DB_MASTER_PASSWORD"
    "API_SERVICE_KEY"
    "ENCRYPTION_KEY"
)

for secret in "${SECRETS_TO_ROTATE[@]}"; do
    echo "Rotating $secret..."
    
    # Generate new secret
    NEW_VALUE=$(openssl rand -base64 32)
    
    # Update in secret manager with staging first
    anysecret profile staging
    anysecret set "${secret}_NEW" "$NEW_VALUE" --hint secret
    
    # Test with new secret
    if run_integration_tests; then
        # Promote to production
        anysecret profile production
        anysecret set "$secret" "$NEW_VALUE" --hint secret
        
        # Clean up staging
        anysecret profile staging
        anysecret delete "${secret}_NEW"
        
        echo "✅ Successfully rotated $secret"
    else
        echo "❌ Failed to rotate $secret - rolling back"
        anysecret profile staging
        anysecret delete "${secret}_NEW"
    fi
done
```

#### Audit and Monitoring

```bash
# Audit commands
anysecret audit --since "7 days ago"  # View recent access
anysecret validate --profile production  # Validate configuration integrity
anysecret health-check  # Verify all providers are accessible

# Monitoring integration
# ⏳ Prometheus export format not yet implemented
anysecret export --format json | curl -X POST http://monitoring:8080/metrics
```

---

## Enterprise Security Team: Compliance and Governance {#enterprise-security}

**Persona**: Rachel, CISO at a 1000+ employee enterprise
**Challenge**: SOC2, GDPR compliance, enterprise-wide secret governance
**Requirements**: Centralized control, policy enforcement, comprehensive auditing

### Scenario: Multi-Team Secret Governance

Rachel implements enterprise-wide secret management policies across 50+ development teams with strict compliance requirements.

#### Enterprise Configuration Structure

```yaml
# .anysecret/enterprise-config.yaml
global:
  # Enterprise-wide defaults
  default_providers:
    secrets:
      type: azure_key_vault
      config:
        vault_url: https://enterprise-secrets.vault.azure.net/
        tenant_id: ${AZURE_TENANT_ID}
    config:
      type: azure_blob
      config:
        account_name: enterpriseconfig
        container_name: team-configurations
        
  # Compliance requirements
  compliance:
    require_encryption: true
    audit_all_access: true
    rotation_policy: 90d
    approval_required: true
    
teams:
  # Development teams with restricted access
  web-team:
    providers:
      - name: team_secrets
        type: azure_key_vault
        config:
          vault_url: https://web-team-secrets.vault.azure.net/
          readonly: false
          allowed_operations: ["get", "list"]
      - name: team_config
        type: azure_blob
        config:
          container_name: web-team-config
          blob_name: config/web-services.json
          readonly: false
          
  data-team:
    providers:
      - name: data_secrets
        type: azure_key_vault
        config:
          vault_url: https://data-team-secrets.vault.azure.net/
          readonly: false
          allowed_operations: ["get", "list"]
      - name: data_config
        type: azure_blob
        config:
          container_name: data-team-config
          blob_name: config/data-services.json
          readonly: false
```

#### Policy Enforcement

```yaml
# .anysecret/policies.yaml
policies:
  # Secret classification policies
  - name: pii_data_protection
    description: "PII data must be stored in enterprise vault"
    rules:
      - if: "classification == 'secret' AND tags.contains('pii')"
        then:
          provider_type: azure_key_vault
          encryption_required: true
          access_logging: true
          
  - name: financial_data_protection
    description: "Financial data requires additional approval"
    rules:
      - if: "pattern.matches('.*FINANCIAL.*') OR tags.contains('financial')"
        then:
          approval_required: true
          provider_type: azure_key_vault
          retention: 7_years
          
  # Configuration policies
  - name: environment_separation
    description: "Production configs require approval"
    rules:
      - if: "environment == 'production'"
        then:
          approval_required: true
          readonly_default: true
          change_window_required: true
```

#### Governance Workflows

```bash
#!/bin/bash
# enterprise-governance.sh

# Daily compliance check (future implementation)
anysecret config validate
anysecret status

# Generate audit report
anysecret list --format json --values > audit-$(date +%Y%m).json

# Check for patterns that might indicate policy violations
anysecret list --pattern ".*_(KEY|SECRET|PASSWORD|TOKEN).*" --secrets-only

# Manual lifecycle management for now
anysecret list --format json | jq '.[] | select(.created_date < "2024-06-01")'
```

#### Multi-Team Access Control

```bash
# ⏳ Team management commands not yet implemented
# Current approach: manual profile management per team
anysecret config profile-create web-team-prod
anysecret config profile-create web-team-staging

# ⏳ Temporary access grants not yet implemented  
# Current approach: manual profile switching
anysecret config profile-use web-team-prod

# ⏳ Automated bulk secret rotation not yet implemented
# Manual approach for now:
anysecret list --pattern ".*_DB_PASSWORD$" --secrets-only
# Then manually rotate each secret using 'anysecret set'
```

---

## CI/CD Pipeline Integration {#cicd-integration}

### GitHub Actions Integration

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
      
      - name: Setup AnySecret
        uses: anysecret/setup-action@v1
        with:
          version: latest
          
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-west-2
          
      - name: Set environment profile
        run: anysecret config profile-use production
        
      - name: Export configuration
        run: |
          anysecret export --format env --file .env.production
          # ⏳ Docker Compose export format not yet implemented
          anysecret export --format docker-compose > docker-compose.env
          
      - name: Deploy to ECS
        run: |
          # Configuration is now available as environment variables
          docker-compose -f docker-compose.yml --env-file docker-compose.env up -d
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        ANYSECRET_PROFILE = "${env.BRANCH_NAME == 'main' ? 'production' : 'staging'}"
    }
    
    stages {
        stage('Setup') {
            steps {
                script {
                    sh 'anysecret profile ${ANYSECRET_PROFILE}'
                    sh 'anysecret health-check'
                }
            }
        }
        
        stage('Build') {
            steps {
                script {
                    // Export configuration for build process
                    // ⏳ Makefile export format not yet implemented
                    sh 'anysecret export --format makefile > build.env'
                    sh 'make build'
                }
            }
        }
        
        stage('Deploy') {
            when { branch 'main' }
            steps {
                script {
                    // ⏳ Kubernetes export format not yet implemented
                    sh 'anysecret export --format k8s-secret | kubectl apply -f -'
                    sh 'kubectl rollout restart deployment/myapp'
                }
            }
        }
    }
}
```

---

## Microservices Architecture {#microservices-architecture}

### Service Mesh Configuration

```yaml
# Service A configuration
# services/user-service/.anysecret/config.yaml
profiles:
  production:
    providers:
      - name: shared_secrets
        type: gcp_secret_manager
        config:
          project_id: mycompany-prod
          readonly: true
      - name: service_config
        type: gcs_json
        config:
          project_id: mycompany-prod
          bucket_name: microservices-config
          object_name: user-service/config.json
          readonly: false
```

```yaml
# Service B configuration
# services/order-service/.anysecret/config.yaml
profiles:
  production:
    providers:
      - name: shared_secrets
        type: gcp_secret_manager
        config:
          project_id: mycompany-prod
          readonly: true
      - name: service_config
        type: gcs_json
        config:
          project_id: mycompany-prod
          bucket_name: microservices-config
          object_name: order-service/config.json
          readonly: false
```

### Cross-Service Configuration Management

```bash
#!/bin/bash
# update-all-services.sh

SERVICES=("user-service" "order-service" "payment-service" "notification-service")

# Update shared database connection string
for service in "${SERVICES[@]}"; do
    cd services/$service
    anysecret profile production
    anysecret set SHARED_DB_HOST db.production.internal --hint config
    anysecret set REDIS_CLUSTER redis.production.internal:6379 --hint config
    cd ../..
done

# Update service discovery endpoints
anysecret profile production
anysecret set USER_SERVICE_ENDPOINT https://user-service.prod.svc.cluster.local --hint config
anysecret set ORDER_SERVICE_ENDPOINT https://order-service.prod.svc.cluster.local --hint config
```

---

## Multi-Cloud Strategy {#multi-cloud-strategy}

### Hybrid AWS + GCP Deployment

```yaml
# .anysecret/config.yaml
profiles:
  aws_primary:
    providers:
      - name: aws_secrets
        type: aws_secrets_manager
        config:
          region: us-west-2
          readonly: true
      - name: s3_config
        type: s3_json
        config:
          bucket_name: myapp-primary-config
          object_key: config/production.json
          region: us-west-2
          
  gcp_secondary:
    providers:
      - name: gcp_secrets
        type: gcp_secret_manager
        config:
          project_id: myapp-backup
          readonly: true
      - name: gcs_config
        type: gcs_json
        config:
          project_id: myapp-backup
          bucket_name: myapp-secondary-config
          object_name: config/production.json
          
  multi_cloud:
    providers:
      # Primary secrets from AWS
      - name: primary_secrets
        type: aws_secrets_manager
        config:
          region: us-west-2
          readonly: true
          priority: 1
      # Fallback secrets from GCP
      - name: backup_secrets
        type: gcp_secret_manager
        config:
          project_id: myapp-backup
          readonly: true
          priority: 2
      # Configuration in S3 (primary)
      - name: primary_config
        type: s3_json
        config:
          bucket_name: myapp-primary-config
          object_key: config/production.json
          region: us-west-2
          readonly: false
```

### Disaster Recovery Scenarios

```bash
#!/bin/bash
# dr-failover.sh

# Check primary cloud availability
if anysecret health-check --profile aws_primary; then
    echo "AWS primary is healthy"
    anysecret profile aws_primary
else
    echo "AWS primary failed, switching to GCP secondary"
    anysecret profile gcp_secondary
    
    # Notify ops team
    anysecret get SLACK_WEBHOOK --hint secret | xargs -I {} \
        curl -X POST {} -d '{"text": "ALERT: Failed over to GCP secondary"}'
fi

# Export configuration for deployment
anysecret export --format env --file .env.production
```

---

## Cost Optimization {#cost-optimization}

### Intelligent Classification for Cost Savings

```yaml
# .anysecret/cost-optimization.yaml
patterns:
  # Expensive secrets (AWS Secrets Manager: $0.40/month per secret)
  - name: high_security_secrets
    pattern: "^(.*_PRIVATE_KEY|.*_SECRET_KEY|.*_PASSWORD|.*_TOKEN|DATABASE_URL)$"
    classification: secret
    justification: "Security-critical data requiring encryption and rotation"
    
  # Cheap configuration (S3: ~$0.01/month for thousands of parameters)
  - name: application_config
    pattern: "^(.*_URL|.*_ENDPOINT|.*_HOST|PORT|TIMEOUT|LOG_LEVEL|FEATURE_.*|DEBUG_.*)$"
    classification: config
    justification: "Non-sensitive configuration data"
    
  # Edge cases requiring analysis
  - name: review_required
    pattern: "^(API_.*|SERVICE_.*|EXTERNAL_.*)$"
    classification: review
    justification: "May contain sensitive API keys or just endpoints"
```

### Cost Analysis Commands

```bash
# Generate cost report
anysecret cost-analysis --profile production

# Output:
# Secret Storage Costs:
#   AWS Secrets Manager: 47 secrets × $0.40 = $18.80/month
#   Configuration Storage:
#   S3 JSON files: 312 parameters × $0.000004 = $0.001/month
#   
#   Total Monthly Cost: $18.80
#   Potential Savings: $124.80 (if all parameters were in Secrets Manager)

# Identify cost optimization opportunities
anysecret optimize --dry-run

# Output:
# Found 23 parameters classified as secrets that could be configuration:
#   - LOG_LEVEL (currently: secret, suggested: config, savings: $0.40/month)
#   - API_BASE_URL (currently: secret, suggested: config, savings: $0.40/month)
#   - FEATURE_NEW_UI (currently: secret, suggested: config, savings: $0.40/month)
```

### Bulk Reclassification

```bash
# Review and reclassify parameters
anysecret list --classification secret | grep -E "(URL|ENDPOINT|FEATURE_|LOG_)" > review.txt

# Bulk reclassify non-sensitive items
while IFS= read -r param; do
    echo "Reclassifying $param as config..."
    current_value=$(anysecret get "$param" --raw)
    anysecret delete "$param"
    anysecret set "$param" "$current_value" --hint config
done < review.txt

# Verify cost savings
anysecret cost-analysis --compare-with last-month
```

---

## Summary

These examples demonstrate AnySecret.io's flexibility across different organizational scales and requirements:

- **Startups** benefit from cost-effective secret management with minimal operational overhead
- **DevOps teams** achieve consistency and automation across complex multi-service architectures
- **SRE teams** implement production-ready security with automated rotation and monitoring
- **Enterprise security** teams enforce governance and compliance across large organizations
- **Multi-cloud strategies** provide resilience and vendor independence
- **Cost optimization** ensures efficient resource utilization through intelligent classification

Each scenario showcases AnySecret.io's core philosophy: **secrets-first security with pragmatic configuration management**, enabling teams to focus on building great products while maintaining robust security practices.


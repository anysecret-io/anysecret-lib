# AnySecret.io

**Intelligent secret management with 40x cost savings** 💰

AnySecret is a CLI-first tool that automatically routes secrets to secure managers and configuration to cheap storage, optimizing both security and cost.

## ✨ Key Features

- **🧠 Smart Classification** - Auto-routes secrets vs parameters based on naming patterns
- **💰 Cost Optimization** - 40x savings by using cheap storage for configuration 
- **🌩️ Multi-Cloud** - AWS, GCP, Azure, Kubernetes, HashiCorp Vault, local files
- **🔄 Profile Management** - Separate environments with easy CI/CD export
- **🛡️ Security by Default** - Secrets masked in terminal, real in files
- **📦 CLI-First** - Designed for real-world DevOps workflows

## 🚀 Quick Start

Install AnySecret:

```bash
pip install anysecret-io
```

Create your first profile and add configuration:

```bash
# Create local development profile
anysecret config profile-create my-app

# Add configuration (auto-classified)
anysecret set DATABASE_PASSWORD "secret123"     # → Secret Manager ($0.40/month)
anysecret set DATABASE_HOST "localhost"         # → Cheap Storage ($0.01/month)
anysecret set API_TIMEOUT "30"                  # → Cheap Storage ($0.01/month)

# Export for your application
anysecret bulk export --output .env
```

## 💡 The AnySecret Approach

### Before: Everything Expensive
```bash
# Traditional: All in secret managers
DATABASE_HOST=localhost        # $0.40/month
API_TIMEOUT=30                 # $0.40/month  
LOG_LEVEL=info                 # $0.40/month
DATABASE_PASSWORD=secret123    # $0.40/month

# Monthly cost: $1.60 for 4 values
```

### After: Smart Cost Optimization
```bash
# AnySecret: Automatic intelligent routing
anysecret set DATABASE_HOST "localhost"         # → Storage: $0.01/month
anysecret set API_TIMEOUT "30"                  # → Storage: $0.01/month
anysecret set LOG_LEVEL "info"                  # → Storage: $0.01/month
anysecret set DATABASE_PASSWORD "secret123"     # → Secrets: $0.40/month

# Monthly cost: $0.43 for 4 values (73% savings!)
```

## 🔧 CLI Usage Patterns

### Development Workflow
```bash
# Setup once
anysecret config profile-create dev
anysecret bulk import .env.local

# Daily usage
anysecret bulk export --output .env
npm run dev
```

### Production Deployment  
```bash
# Create production profile
anysecret config profile-create prod --provider gcp

# Import configuration (auto-classified to optimal storage)
anysecret bulk import .env.production

# Export for CI/CD
anysecret config profile-export prod --base64 > profile.txt
# Store in GitHub/GitLab secrets
```

### CI/CD Integration
```bash
# In your deployment pipeline
export ANYSECRET_PROFILE_DATA="$STORED_PROFILE_DATA"
export CI=true

anysecret bulk export --output .env.production
docker run --env-file .env.production myapp
```

## 🏗️ Supported Providers

### Secrets (High Security, Higher Cost)
| Provider | Status | Cost/Secret/Month |
|----------|--------|-------------------|
| **AWS Secrets Manager** | ✅ Full | ~$0.40 |
| **GCP Secret Manager** | ✅ Full | ~$0.40 |
| **Azure Key Vault** | ✅ Full | ~$0.40 |
| **Kubernetes Secrets** | ✅ Full | Free* |
| **HashiCorp Vault** | ✅ Full | Variable |
| **Local Files (.env)** | ✅ Full | Free |

### Parameters (Lower Security, Low Cost)
| Provider | Status | Cost/Parameter/Month |
|----------|--------|----------------------|
| **AWS S3** | ✅ Full | ~$0.01 |
| **GCS Storage** | ✅ Full | ~$0.01 |
| **Azure Blob Storage** | ✅ Full | ~$0.01 |
| **AWS Parameter Store** | ✅ Full | ~$0.05 |
| **Kubernetes ConfigMaps** | ✅ Full | Free* |
| **Local Files (JSON/YAML)** | ✅ Full | Free |

*Free but requires cluster infrastructure costs

## 🎯 Auto-Classification Rules

AnySecret automatically routes based on naming patterns:

### → Secrets (Secure + Expensive)
```bash
*_SECRET, *_PASSWORD, *_KEY, *_TOKEN, *_CREDENTIAL
API_KEY, CLIENT_SECRET, JWT_SECRET, DB_PASSWORD
# Plus value-based detection: sk_, pk_, -----BEGIN
```

### → Parameters (Config + Cheap)  
```bash
*_HOST, *_PORT, *_URL, *_TIMEOUT, *_LIMIT, *_COUNT
*_ENABLED, *_MODE, LOG_*, DEBUG_*, MAX_*
# Non-sensitive configuration values
```

### Override When Needed
```bash
# Force classification
anysecret set PUBLIC_KEY "pk_123" --hint parameter  # Save money
anysecret set LOG_TOKEN "token" --hint secret       # Force security
```

## 📊 Real-World Savings

### Startup (25 config values)
- **Traditional**: 25 × $0.40 = **$10/month**
- **AnySecret**: 5 secrets × $0.40 + 20 parameters × $0.01 = **$2.20/month**
- **Savings**: $7.80/month (78% reduction)

### Scale-up (100 config values)
- **Traditional**: 100 × $0.40 = **$40/month** 
- **AnySecret**: 20 secrets × $0.40 + 80 parameters × $0.01 = **$8.80/month**
- **Savings**: $31.20/month (78% reduction)

### Enterprise (500 config values)
- **Traditional**: 500 × $0.40 = **$200/month**
- **AnySecret**: 100 secrets × $0.40 + 400 parameters × $0.01 = **$44/month** 
- **Savings**: $156/month (78% reduction)

## 🛡️ Security Features

- **Secrets masked by default** - Terminal shows `***`, files get real values
- **Profile encryption** - Use `--encrypt` for sensitive profiles  
- **IAM integration** - Native cloud provider access control
- **Audit trails** - All operations logged for compliance
- **File permissions** - Auto-sets secure permissions on secret files

## 📚 Documentation

Start here based on your experience level:

### New to AnySecret
- **[Quick Start Guide](quickstart.md)** - 5-minute setup
- **[Examples](examples.md)** - Real scenarios from solo dev to enterprise

### Using in Production  
- **[Best Practices](best-practices.md)** - Security patterns and workflows
- **[CLI Reference](cli.md)** - Complete command documentation

### Advanced Topics
- **[Migration Guide](migration.md)** - Move between providers  
- **[Provider Setup](providers.md)** - Cloud provider configuration
- **[API Reference](api.md)** - Python SDK (basic functionality)

## 🤔 Why AnySecret vs Alternatives?

### vs. Cloud Provider Native Tools
- ❌ **Vendor lock-in** - Hard to switch providers
- ❌ **High costs** - Everything treated as high-security secrets  
- ❌ **Complex setup** - Different APIs for each provider

✅ **AnySecret**: Multi-cloud, cost-optimized, consistent interface

### vs. HashiCorp Vault
- ❌ **Infrastructure overhead** - Need to run and maintain Vault
- ❌ **High operational cost** - Enterprise features expensive
- ❌ **Complex networking** - Security policies, network access

✅ **AnySecret**: Serverless, leverages managed cloud services

### vs. Manual .env Management
- ❌ **Security risk** - Secrets in plain text files
- ❌ **No audit trail** - Who changed what when?
- ❌ **Hard to rotate** - Manual process across environments

✅ **AnySecret**: Secure by default, audit trails, easy rotation

## 🚀 Ready to Start?

```bash
pip install anysecret-io
anysecret config profile-create my-first-app
anysecret set DATABASE_PASSWORD "secure123"
anysecret set API_TIMEOUT "30"
anysecret bulk export --output .env
```

**[Follow the Quick Start Guide →](quickstart.md)**

---

*AnySecret.io: Smart secret management that saves you money while keeping you secure.*
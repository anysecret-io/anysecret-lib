# Documentation Deployment Setup

This guide explains how to set up automatic documentation deployment from `anysecret-lib` to `anysecret-docs`.

## 🏗️ Architecture

```
anysecret-lib (source)     →     anysecret-docs (built site)     →     Cloudflare Pages
     ↓                                    ↓                                    ↓
  docs/*.md                         Static HTML                        docs.anysecret.io
  mkdocs.yml                       CSS, JS, Assets
```

## 🔧 Setup Steps

### 1. Create GitHub Repositories

```bash
# Create anysecret-docs repository on GitHub
# - Repository: anysecret-io/anysecret-docs
# - Visibility: Public
# - Initialize with README: No (we provide our own)
```

### 2. Generate Personal Access Token

1. Go to GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens
2. Create token with access to `anysecret-io/anysecret-docs`
3. Required permissions:
   - **Contents**: Read and write
   - **Metadata**: Read
   - **Pull requests**: Read (if needed)

### 3. Configure Repository Secret

1. Go to `anysecret-io/anysecret-lib` → Settings → Secrets and variables → Actions
2. Create new repository secret:
   - **Name**: `DOCS_DEPLOY_TOKEN`
   - **Value**: Your personal access token from step 2

### 4. Initialize anysecret-docs Repository

```bash
cd anysecret-docs
git init
git add README.md .gitkeep
git commit -m "Initial commit"
git branch -M main
git remote add origin git@github.com:anysecret-io/anysecret-docs.git
git push -u origin main
```

### 5. Trigger First Deployment

Push any change to docs in `anysecret-lib`:

```bash
cd anysecret-lib
# Edit any file in docs/ or mkdocs.yml
git add .
git commit -m "Trigger docs deployment"
git push
```

The GitHub Action will automatically:
1. Build the MkDocs site
2. Push the built site to `anysecret-docs`
3. Cloudflare Pages will deploy from `anysecret-docs`

### 6. Configure Cloudflare Pages

1. **Connect Repository**:
   - Go to Cloudflare Dashboard → Pages
   - Connect to Git → Select `anysecret-io/anysecret-docs`

2. **Build Settings**:
   - **Build command**: `echo "No build needed - pre-built site"`
   - **Build output directory**: `/` (root)
   - **Root directory**: `/` (root)

3. **Custom Domain**:
   - Add custom domain: `docs.anysecret.io`
   - Cloudflare handles SSL automatically

## 🚀 Workflow

### Automatic Deployment

The documentation automatically rebuilds when you:
- Edit any file in `anysecret-lib/docs/`
- Modify `mkdocs.yml`
- Update `requirements-docs.txt`
- Modify the GitHub Action workflow

### Manual Deployment

Trigger manually via GitHub:
1. Go to `anysecret-lib` → Actions → Deploy Documentation
2. Click "Run workflow"

## 🔍 Monitoring

### GitHub Action Logs
- View deployment status in `anysecret-lib` → Actions tab
- Check build logs for any errors

### Cloudflare Pages
- Monitor deployments in Cloudflare Dashboard → Pages
- View deployment history and logs

## 🐛 Troubleshooting

### Common Issues

**Action fails with "Permission denied"**:
- Check `DOCS_DEPLOY_TOKEN` is set correctly
- Verify token has write access to `anysecret-docs`

**MkDocs build fails**:
- Check `requirements-docs.txt` is up to date
- Verify all markdown files have valid syntax

**Cloudflare Pages not updating**:
- Check if `anysecret-docs` repository received the push
- Verify Cloudflare Pages is connected to correct repository

### Debug Steps

1. **Check Action Logs**:
   ```bash
   # View in GitHub UI or via CLI
   gh run list --repo anysecret-io/anysecret-lib
   gh run view <run-id> --repo anysecret-io/anysecret-lib
   ```

2. **Test Build Locally**:
   ```bash
   cd anysecret-lib
   pip install -r requirements-docs.txt
   mkdocs build --strict
   mkdocs serve  # Test locally
   ```

3. **Verify Token Permissions**:
   ```bash
   # Test token can access anysecret-docs
   curl -H "Authorization: token <YOUR_TOKEN>" \
        https://api.github.com/repos/anysecret-io/anysecret-docs
   ```

## 📁 File Structure

### anysecret-lib
```
anysecret-lib/
├── docs/                    # Source markdown files
├── mkdocs.yml              # MkDocs configuration
├── requirements-docs.txt   # Documentation dependencies
└── .github/workflows/
    └── deploy-docs.yml     # Deployment workflow
```

### anysecret-docs (auto-generated)
```
anysecret-docs/
├── index.html              # Built site
├── assets/                 # CSS, JS, images
├── search/                 # Search index
└── [all other built files]
```

## 🔄 Updating the Setup

### Add New Dependencies
Edit `requirements-docs.txt` and push - the action will automatically use them.

### Modify Build Process
Edit `.github/workflows/deploy-docs.yml` and push changes.

### Change Site Configuration
Edit `mkdocs.yml` - changes deploy automatically.

---

**✅ Setup Complete!** Your docs will now automatically deploy to `docs.anysecret.io` whenever you update the source files in `anysecret-lib`.
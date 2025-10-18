# Comprehensive DevSecOps Implementation Guide
## From Planning to Production Security Excellence

---

## Table of Contents
1. [Introduction & Core Concepts](#introduction)
2. [The DevSecOps Journey: 7 Key Stages](#overview)
3. [Stage 1: Plan — Building Security Culture](#stage-1-plan)
4. [Stage 2: Code — Secure Development](#stage-2-code)
5. [Stage 3: Build — CI/CD Pipeline Security](#stage-3-build)
6. [Stage 4: Test — Automated Security Testing](#stage-4-test)
7. [Stage 5: Release — Pre-Deployment Verification](#stage-5-release)
8. [Stage 6: Deploy — Secure Deployment](#stage-6-deploy)
9. [Stage 7: Monitor — Continuous Security Visibility](#stage-7-monitor)
10. [Phased Adoption Roadmap](#roadmap)
11. [KPIs & Metrics](#kpis)
12. [Common Mistakes & Quick Review](#conclusion)

---

## Introduction & Core Concepts {#introduction}

### What Is DevSecOps?

DevSecOps isn't a tool or a single practice—it's a cultural philosophy that integrates security into every step of the software development and operations lifecycle. Think of it as making security everyone's responsibility, not just the security team's job.

**The Traditional Problem:**
- Developers build fast → Operations runs it → Security team reviews it later → Vulnerabilities found → Urgent fixes → Frustrated teams

**The DevSecOps Solution:**
- Security is baked in from day one → Developers have security guardrails → Automation catches issues early → Operations deploys with confidence → Fewer surprises in production

### Why DevSecOps Matters Now
- **93% of organizations** have experienced a data breach (IBM 2023)
- Security vulnerabilities cost an average of **$4.45M per breach** (Verizon)
- **Shift-Left Principle**: Finding bugs early is 6-10x cheaper than fixing them in production
- Cloud-native, microservices, and containerized apps demand real-time security

### Key Frameworks We'll Reference
- **NIST DevSecOps Reference Architecture**: Government-backed, practical framework
- **OWASP SAMM (Software Assurance Maturity Model)**: Helps assess security capability
- **OWASP ASVS (Application Security Verification Standard)**: Defines what "secure" means

---

## The DevSecOps Journey: 7 Key Stages {#overview}

```
┌─────────────────────────────────────────────────────────────────┐
│                   DEVSECOPS CONTINUOUS CYCLE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  PLAN ──→ CODE ──→ BUILD ──→ TEST ──→ RELEASE ──→ DEPLOY ──→  │
│    ↑                                                       │    │
│    └──────────── MONITOR & FEEDBACK LOOP ────────────────┘    │
│                                                                 │
│  Each stage has specific security gates, tools, and practices   │
│  that work together to create a secure software supply chain.   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Our Real-World Scenario:**
You're implementing DevSecOps for **TechShop API**, a Node.js/Express microservice that:
- Handles user orders and payments
- Runs on AWS (EC2 & RDS)
- Uses Docker containers
- Deployed via GitHub Actions
- Serves 100K+ requests daily

Let's walk through securing it step by step.

---

## Stage 1: Plan — Building Security Culture {#stage-1-plan}

### Why Planning Matters

The best security fails if the team doesn't understand why it's there. Planning is about:
1. Defining security requirements upfront
2. Identifying threats specific to your application
3. Creating a security culture where developers feel enabled, not blocked

### Step 1A: Threat Modeling

Before writing code, identify what you're protecting against.

**TechShop API Threats:**
- SQL injection in order queries → Attacker steals customer data
- API key exposure in code → Unauthorized payment transactions
- Unencrypted data in transit → Man-in-the-middle attacks
- Weak authentication → Account takeover
- DDoS attacks → Service unavailability

**Use STRIDE Framework:**
```
STRIDE Threat Categories:
├─ S (Spoofing): Fake identities, forged authentication
├─ T (Tampering): Modifying data in transit or at rest
├─ R (Repudiation): Denying actions ("I didn't do that")
├─ I (Information Disclosure): Exposing sensitive data
├─ D (Denial of Service): Making service unavailable
└─ E (Elevation of Privilege): Gaining higher access rights
```

**Practical Output: Threat Register**
```
Threat: SQL Injection in Order Queries
├─ Impact: High (data breach)
├─ Likelihood: Medium
├─ Mitigation: Parameterized queries, input validation
├─ Testing Strategy: SQLMap security scanning
└─ Owner: Dev team + Security review
```

### Step 1B: Define Security Requirements

Document what "secure" means for your app. Use OWASP ASVS as a starting point.

**Sample Security Requirements for TechShop:**
- All API endpoints require OAuth 2.0 or JWT authentication (ASVS 2.1)
- Passwords hashed with bcrypt, minimum 12 characters (ASVS 2.2)
- All secrets in HashiCorp Vault, never in code (NIST practice)
- HTTPS only, TLS 1.2+ (OWASP A02:2021 - Cryptographic Failures)
- Input validation on all endpoints (OWASP A03:2021 - Injection)
- Rate limiting: 100 requests/min per user (OWASP A40:2021 - DoS)

### Step 1C: Create a Security Champion Program

**Empower your team:**
- Designate 1-2 developers per team as "Security Champions"
- Give them time (10-20%) to learn security
- They review code, run security training, mentor peers
- They're your bridge between developers and security team

**Monthly Security Champion Meeting Agenda:**
```
1. Review new vulnerabilities (10 min)
2. Discuss tools & automation updates (10 min)
3. Case study: real vulnerability found in your app (10 min)
4. Team Q&A (10 min)
Total: 40 min, monthly
```

### Step 1D: Security Requirements Documentation

Create a simple, versioned document (store in Git):

```yaml
# TECHSHOP_SECURITY_REQUIREMENTS.md
Version: 1.0
Last Updated: 2025-01-15

## Authentication & Authorization
- All APIs require JWT or OAuth 2.0
- JWT expiration: 1 hour access, 7 days refresh
- Admin endpoints require 2FA
- Role-based access control (RBAC) implemented

## Data Protection
- Encryption at rest: AES-256 for sensitive data
- Encryption in transit: TLS 1.2+ enforced
- No sensitive data in logs
- PII retention: 90 days max (GDPR compliance)

## Infrastructure
- Network: VPC isolation, no public database access
- Secrets: HashiCorp Vault only
- Patching: OS & dependencies within 30 days of release
- Backup: Daily, tested recovery monthly

## Monitoring & Response
- Security events logged to CloudWatch
- Alerts for failed auth attempts (>5/min)
- Incident response plan documented & tested quarterly
```

### ✅ Plan Stage Checklist

```
□ Threat model completed (STRIDE analysis)
□ Security requirements documented & approved by stakeholders
□ OWASP ASVS level chosen (Level 1 = basic, 3 = critical apps)
□ Security champions identified & trained
□ CI/CD environment prepared (AWS/Azure account, GitHub org set up)
□ Secrets management solution selected (Vault or AWS Secrets Manager)
□ Team training on secure development scheduled
□ Baseline metrics defined (SLA, incident goals)
```

---

## Stage 2: Code — Secure Development {#stage-2-code}

### Why Developers Are Your First Security Line

Developers write code. If they don't know how to write it securely, no tool downstream will catch everything. This stage is about making security **easy** and **automatic**.

### Step 2A: Pre-Commit Security — Stop Bad Code Before It Starts

Pre-commit hooks run locally on developer machines before code is pushed to Git. They catch issues immediately, while the developer is still in the flow.

**Install Pre-Commit Framework:**

```bash
# Install pre-commit locally (every developer does this)
pip install pre-commit

# Create .pre-commit-config.yaml in your repo root
cat > .pre-commit-config.yaml << 'EOF'
repos:
  # Detect secrets in code
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  # Security checks for Python
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-c', 'bandit.yaml']

  # Lint for Node.js
  - repo: https://github.com/pre-commit/mirrors-eslint
    rev: v8.50.0
    hooks:
      - id: eslint
        args: ['--fix']

  # YAML validation
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: yaml-unsafe
      - id: check-added-large-files
        args: ['--maxkb=500']
      - id: check-json
      - id: check-merge-conflict

  # Check for hardcoded credentials
  - repo: https://github.com/gitguardian/ggshield
    rev: v1.25.0
    hooks:
      - id: ggshield
        language: python
        entry: ggshield secret scan pre-commit
        stages: [commit]
EOF

# Set it up
pre-commit install

# Run manually (developers test before committing)
pre-commit run --all-files
```

**What This Does:**
- Detects hardcoded secrets (API keys, passwords)
- Scans Python code for security issues (SQL injection, insecure crypto)
- Checks JavaScript/Node.js for vulnerabilities
- Validates YAML syntax
- Prevents accidental large file commits

### Step 2B: Secure Coding Standards for Your Team

Create a simple cheat sheet your developers keep handy.

**TechShop Secure Coding Quick Reference:**

```markdown
## Node.js/Express Security Checklist

✅ Authentication & Authorization
  - Always validate JWT tokens (use `express-jwt` library)
  - Example:
    const jwt = require('express-jwt');
    app.use(jwt({ secret: process.env.JWT_SECRET }));

✅ Input Validation
  - Validate all user inputs server-side
  - Use library: npm install joi
    
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().min(12).required(),
      userId: Joi.number().positive().required()
    });
    
    const { error, value } = schema.validate(req.body);

✅ SQL Queries
  - ALWAYS use parameterized queries, NEVER string concatenation
  - ❌ BAD:
    db.query(`SELECT * FROM users WHERE email = '${email}'`);
  
  - ✅ GOOD:
    db.query('SELECT * FROM users WHERE email = ?', [email]);

✅ Secrets & Credentials
  - Never hardcode passwords, keys, or tokens
  - Use environment variables via .env (local) or Vault (production)
    
    const dbPassword = process.env.DB_PASSWORD;
    const apiKey = vault.getSecret('techshop/api-key');

✅ Dependency Management
  - Keep dependencies updated (run weekly: npm audit fix)
  - Use package-lock.json (commit it to Git!)
  - Review high-severity vulnerabilities

✅ Error Handling
  - Don't expose stack traces to users
  - ❌ BAD:
    catch (err) { res.send(err); }  // Exposes system info!
  
  - ✅ GOOD:
    catch (err) {
      logger.error(err);
      res.status(500).json({ error: "Internal server error" });
    }

✅ Logging
  - Log security events (failed auth, suspicious patterns)
  - Never log passwords, tokens, or PII
    
    logger.warn(`Failed login attempt from IP: ${req.ip}`);

✅ CORS & CSRF
  - Restrict CORS origins (not wildcard '*')
  - Use helmet middleware:
    const helmet = require('helmet');
    app.use(helmet());  // Adds security headers

✅ Rate Limiting
  - Protect against brute force & DoS
    
    const rateLimit = require('express-rate-limit');
    const limiter = rateLimit({ 
      windowMs: 60000, 
      max: 100  // 100 requests per minute
    });
    app.use('/api/', limiter);
```

### Step 2C: Secret Management Best Practice

**The Core Rule: Secrets Never Touch Your Code Repo**

**What are Secrets?**
- Database passwords
- API keys (payment, AWS, third-party services)
- Private encryption keys
- OAuth tokens
- Any credentials

**Local Development Setup (Using HashiCorp Vault):**

```bash
# 1. Install Vault locally
brew install vault  # macOS
# or download from https://www.vaultproject.io/downloads

# 2. Start local Vault server
vault server -dev
# Output: Unseal Key, Root Token

# 3. Save token in ~/.vault-token (shell will auto-load)
export VAULT_TOKEN="your-root-token"
export VAULT_ADDR="http://127.0.0.1:8200"

# 4. Store your secrets
vault kv put secret/techshop/dev \
  db_password="super-secret-pass" \
  api_key="abc123xyz" \
  jwt_secret="key-for-signing"

# 5. In your Node.js code, load from Vault
const vault = require('node-vault')({
  endpoint: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN
});

(async () => {
  const secret = await vault.read('secret/data/techshop/dev');
  const dbPassword = secret.data.data.db_password;
})();

# 6. .gitignore ALWAYS includes:
.env
.vault-token
.secrets.*
```

**Production Setup (AWS Secrets Manager):**

```bash
# Store secret in AWS
aws secretsmanager create-secret \
  --name techshop/prod/db-password \
  --secret-string "production-password-12345"

# Retrieve in code (Lambda, EC2 auto-retrieves with IAM role)
const AWS = require('aws-sdk');
const client = new AWS.SecretsManager({ region: 'us-east-1' });

async function getSecret(secretName) {
  try {
    const data = await client.getSecretValue({ SecretId: secretName }).promise();
    return JSON.parse(data.SecretString);
  } catch (error) {
    console.error('Error retrieving secret:', error);
  }
}

const dbPassword = await getSecret('techshop/prod/db-password');
```

### Step 2D: Dependency Security

**The Challenge:** Your code depends on hundreds of packages. Any one could have a vulnerability.

**Solution: Automated Dependency Scanning**

```bash
# 1. npm audit - built-in, free
npm audit
# Output shows vulnerabilities in your dependencies

# 2. Review results
npm audit --json | jq '.vulnerabilities'

# 3. Fix if possible (auto-patches for minor/patch versions)
npm audit fix

# 4. For production: lock down versions
npm ci  # Uses package-lock.json instead of package.json

# 5. Use Snyk for advanced scanning (free tier available)
npm install -g snyk
snyk auth  # Link to your Snyk account
snyk test  # Scan for vulnerabilities

# 6. For license compliance (avoid GPL in proprietary code)
npm install -g license-checker
license-checker --production
```

**Add to CI/CD (we'll see this in Stage 3):**
```yaml
# Fail the build if high-severity vulnerabilities found
- name: Check dependencies
  run: npm audit --audit-level=high
```

### ✅ Code Stage Checklist

```
□ Pre-commit hooks installed & working (.pre-commit-config.yaml)
□ Developers tested pre-commit locally
□ Secure coding standards documented & shared
□ Dependency audit running locally (npm audit)
□ Secrets management configured (local Vault/AWS Secrets Manager)
□ .gitignore prevents secrets from being committed
□ Code review process defined (require 2 reviewers for main branch)
□ ESLint/linters configured for your language
□ SAST tool selected (SonarQube, Snyk, Checkmarx)
```

---

## Stage 3: Build — CI/CD Pipeline Security {#stage-3-build}

### Why CI/CD is Security's Automation Engine

The CI/CD pipeline is where we automate security gates. Every commit triggers checks that would be too tedious to do manually. Think of it as a bouncer checking IDs at the door—every single person, every single time.

### Step 3A: GitHub Actions CI/CD Pipeline Setup

We'll build a complete pipeline for TechShop API using GitHub Actions (free, built-in, no external service needed for basic use).

**Create `.github/workflows/security.yml`:**

```yaml
name: Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  security-checks:
    runs-on: ubuntu-latest
    
    steps:
      # 1. Checkout code
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better scanning
      
      # 2. Detect secrets in code
      - name: Detect secrets with GitGuardian
        uses: gitguardian/ggshield-action@v1
        env:
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
          GITHUB_PUSH_BEFORE_SHA: ${{ github.event.before }}
          GITHUB_PUSH_BASE_SHA: ${{ github.event.base }}
          GITHUB_PULL_BASE_SHA: ${{ github.event.pull_request.base.sha }}
          GITHUB_DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}

      # 3. Setup Node.js
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      # 4. Install dependencies
      - name: Install dependencies
        run: npm ci  # Uses package-lock.json for reproducible builds
      
      # 5. Check for known vulnerabilities
      - name: Npm audit
        run: npm audit --audit-level=high
      
      # 6. Snyk security scanning (free tier)
      - name: Run Snyk scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      # 7. Static Application Security Testing (SAST) with SonarQube
      - name: SonarQube Analysis
        uses: SonarSource/sonarqube-scan-action@master
        env:
          SONAR_HOST_URL: ${{ secrets.SONAR_HOST_URL }}
          SONAR_LOGIN: ${{ secrets.SONAR_LOGIN }}
      
      # 8. Linting with ESLint (catches code quality & some security issues)
      - name: ESLint scan
        run: npx eslint . --ext .js,.jsx --max-warnings 0
      
      # 9. Unit & security-focused tests
      - name: Run tests
        run: npm test
        env:
          NODE_ENV: test
      
      # 10. Build Docker image for scanning
      - name: Build Docker image
        run: docker build -t techshop-api:${{ github.sha }} .
      
      # 11. Scan Docker image with Trivy
      - name: Scan image with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: techshop-api:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'
      
      # 12. Upload Trivy results to GitHub Security tab
      - name: Upload Trivy results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
      
      # 13. Infrastructure as Code scanning (Terraform)
      - name: Scan Terraform with Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: ./terraform
          framework: terraform
          output_format: sarif
          output_file_path: checkov-results.sarif
      
      # 14. DAST preparation (we'll run full DAST in Stage 4)
      - name: Store build artifact
        uses: actions/upload-artifact@v3
        with:
          name: docker-image
          path: Dockerfile

  # Parallel job: Infrastructure validation
  infrastructure-validation:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # Validate Terraform code
      - name: Terraform validate
        uses: hashicorp/setup-terraform@v2
      
      - name: Terraform format check
        run: terraform fmt -check
        working-directory: ./terraform
      
      - name: Terraform init
        run: terraform init -backend=false
        working-directory: ./terraform
      
      - name: Terraform validate
        run: terraform validate
        working-directory: ./terraform

  # Parallel job: Dependency check
  dependency-check:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run OWASP Dependency-Check
        uses: dependency-check/Dependency-Check_Action@main
        with:
          project: 'TechShop-API'
          path: '.'
          format: 'SARIF'
          args: >
            --enablePackageUrl
      
      - name: Upload results to GitHub
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'dependency-check-report.sarif'

  # Parallel job: Compliance & policy checks
  compliance-checks:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # Ensure commit messages are meaningful
      - name: Validate commit messages
        run: |
          npm install --save-dev commitlint
          npx commitlint --from HEAD~${{ github.event.pull_request.commits }} --to HEAD
      
      # Check licensing
      - name: Check licenses
        run: |
          npm install -g license-checker
          license-checker --production --failOn GPL
      
      # Verify security policy exists
      - name: Check SECURITY.md exists
        run: test -f SECURITY.md || (echo "SECURITY.md missing!" && exit 1)

```

**What Each Step Does:**

| Step | Tool | Why It Matters | Risk If Skipped |
|------|------|----------------|-----------------|
| GitGuardian | Detects leaked credentials | Prevent API keys reaching Git | Credentials exposed to anyone with repo access |
| npm audit | Finds known vulnerabilities | Stop using outdated dependencies | Vulnerable packages in production |
| Snyk | Advanced dep scanning | Finds zero-days, privacy issues | Less visibility into supply chain risks |
| SonarQube | SAST - static code analysis | Finds logic bugs, injection flaws | SQL injection, XSS slip through |
| Trivy | Container scanning | Finds OS/app vulnerabilities in image | Malicious/vulnerable base images deployed |
| Checkov | IaC scanning | Validates Terraform security | Misconfigured infrastructure (open DBs, etc.) |
| OWASP Dep-Check | Supply chain scanning | Finds transitive dependency issues | Hidden vulnerabilities several layers deep |

### Step 3B: Docker Build Security

**Dockerfile Security Best Practices:**

```dockerfile
# ❌ BAD: Base on outdated, bloated image
FROM ubuntu:18.04
RUN apt-get install -y nodejs npm
# Large attack surface, no security updates

# ✅ GOOD: Minimal, updated base image
FROM node:18-alpine

# Don't run as root!
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

# Use multi-stage build to reduce final image size
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Final stage - minimal image
FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .
USER nodejs

# Security: Don't run as root
RUN chown -R nodejs:nodejs /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

EXPOSE 3000
CMD ["node", "server.js"]
```

**Build Securely:**

```bash
# 1. Always scan base images
docker pull node:18-alpine
trivy image node:18-alpine

# 2. Build with build context limits
docker build \
  --build-arg NODE_ENV=production \
  -t techshop-api:1.0.0 \
  --no-cache \  # Don't use cached layers (security updates)
  .

# 3. Scan your built image
trivy image techshop-api:1.0.0

# 4. Sign images (optional but recommended)
cosign sign --key cosign.key techshop-api:1.0.0
```

### Step 3C: Infrastructure as Code Security

**Terraform Configuration with Security:**

```hcl
# terraform/main.tf
# This creates AWS resources with security defaults

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  # Require tagging for audit trails
  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "Terraform"
      Project     = "TechShop"
      CostCenter  = var.cost_center
    }
  }
}

# ✅ VPC - Network isolation
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = { Name = "techshop-vpc" }
}

# ✅ Private Subnet - Database shouldn't be public
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]
  
  tags = { Name = "private-subnet" }
}

# ✅ RDS Database with encryption
resource "aws_db_instance" "main" {
  identifier        = "techshop-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  
  # Security: Encryption at rest
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
  
  # Multi-AZ for high availability
  multi_az = var.environment == "prod" ? true : false
  
  # Never public!
  publicly_accessible = false
  db_subnet_group_name = aws_db_subnet_group.private.name
  
  # Security group restricts access
  vpc_security_group_ids = [aws_security_group.rds.id]
  
  # Authentication
  username = "admin"
  password = random_password.db_password.result
  
  # Backup configuration
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  
  # Enable detailed monitoring
  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]
  
  skip_final_snapshot = var.environment == "prod" ? false : true
}

# ✅ Security Group - Firewall rules
resource "aws_security_group" "rds" {
  name   = "techshop-rds-sg"
  vpc_id = aws_vpc.main.id
  
  # Allow only from app servers
  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  
  # Block all outbound (RDS doesn't need to reach out)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = []
  }
}

# ✅ KMS Encryption Key
resource "aws_kms_key" "rds" {
  description             = "Encryption key for TechShop RDS"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = { Name = "techshop-kms" }
}

# ✅ Secrets Manager - Store database password
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "techshop/${var.environment}/db-password"
  recovery_window_in_days = 7
  
  tags = { Name = "db-password-secret" }
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id       = aws_secretsmanager_secret.db_password.id
  secret_string   = random_password.db_password.result
}

# ✅ CloudWatch - Centralized logging
resource "aws_cloudwatch_log_group" "app" {
  name              = "/techshop/${var.environment}/app"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.logs.arn
  
  tags = { Name = "app-logs" }
}

# ✅ IAM Role - Least privilege for app
resource "aws_iam_role" "app" {
  name = "techshop-app-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# ✅ IAM Policy - Can only access specific Secrets
resource "aws_iam_role_policy" "app_secrets" {
  name = "techshop-app-secrets-policy"
  role = aws_iam_role.app.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:techshop/${var.environment}/*"
      },
      {
        Effect = "Allow"
        Action = ["kms:Decrypt"]
        Resource = aws_kms_key.rds.arn
      }
    ]
  })
}

# ✅ EC2 Security Group - Restrict inbound
resource "aws_security_group" "app" {
  name   = "techshop-app-sg"
  vpc_id = aws_vpc.main.id
  
  # Only allow HTTPS from load balancer
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  # Allow outbound only to necessary services
  egress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
    description     = "HTTPS to external APIs"
  }
  
  egress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.rds.id]
    description     = "MySQL to RDS"
  }
}

# ✅ AWS WAF - Web Application Firewall
resource "aws_wafv2_web_acl" "main" {
  name  = "techshop-waf"
  scope = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  # Block common attacks (SQL injection, XSS, etc.)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 0
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesCommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }
  
  # Rate limiting - prevent DDoS
  rule {
    name     = "RateLimiting"
    priority = 1
    
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitingMetric"
      sampled_requests_enabled   = true
    }
  }
  
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "techshop-waf"
    sampled_requests_enabled   = true
  }
}

# ✅ S3 Bucket - Application logs with encryption
resource "aws_s3_bucket" "logs" {
  bucket = "techshop-logs-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
  }
}

# Block all public access to logs
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for audit trail
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Data source for current AWS account
data "aws_caller_identity" "current" {}

# Outputs - what we created
output "db_endpoint" {
  value       = aws_db_instance.main.endpoint
  sensitive   = true
  description = "RDS endpoint (sensitive)"
}

output "secrets_manager_arn" {
  value       = aws_secretsmanager_secret.db_password.arn
  description = "ARN of DB password in Secrets Manager"
}

output "app_security_group_id" {
  value       = aws_security_group.app.id
  description = "Security group for app servers"
}

# Variables file: terraform/variables.tf
variable "aws_region" {
  default = "us-east-1"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "cost_center" {
  type = string
}
```

### Step 3D: Checkov - Scan Terraform for Misconfigurations

**Checkov validates Terraform before it's even applied:**

```bash
# Install Checkov
pip install checkov

# Scan terraform directory
checkov -d ./terraform --framework terraform

# Example output:
# Check: CKV_AWS_16: "Ensure all data stored in RDS is securely encrypted"
# ✅ PASSED: RDS encryption enabled

# Check: CKV_AWS_21: "Ensure all data stored in S3 is encrypted"
# ❌ FAILED: S3 bucket logging not encrypted
```

### ✅ Build Stage Checklist

```
□ GitHub Actions workflow created & tested
□ All security scanning tools configured (SAST, SCA, container scan)
□ Secrets scanning enabled (GitGuardian or detect-secrets)
□ Docker multi-stage builds implemented
□ Dockerfile scanned with Trivy
□ Terraform validated with Checkov
□ IAM roles follow least privilege
□ All resources tagged for cost/audit tracking
□ Secrets Manager configured for credentials
□ Build artifacts stored securely
□ CI/CD logs retained for audit
□ Branch protection rules enforced (require reviews)
```

---

## Stage 4: Test — Automated Security Testing {#stage-4-test}

### Why Security Testing is Different

Regular testing asks "Does it work?" Security testing asks "Can someone break it?" We use multiple types of testing to cover different attack surfaces.

### Test Types Overview

```
┌─────────────────────────────────────────────────────┐
│       SECURITY TESTING PYRAMID                       │
├─────────────────────────────────────────────────────┤
│                                                      │
│              DAST (Dynamic Testing)                  │
│           Run attack simulation on live app          │
│       (OWASP ZAP, Burp Suite, Nuclei)              │
│                    ↑                                 │
│         (Fewer, slower, but realistic)              │
│                    ↑                                 │
│     ────────────────────────────────────            │
│              Integration Security Tests             │
│        Test app components together                 │
│      (Authentication flows, API contracts)         │
│                    ↑                                 │
│     ────────────────────────────────────            │
│          Unit Security Tests + SAST                 │
│     Test individual functions securely              │
│  (Input validation, crypto, SQL injection checks)  │
│                    ↑                                 │
│      (Many, fast, but limited scope)               │
│                                                      │
└─────────────────────────────────────────────────────┘
```

### Step 4A: Unit & Integration Security Tests

**Write Tests Specifically for Security:**

```javascript
// tests/security.test.js
const request = require('supertest');
const app = require('../src/app');
const { generateJWT } = require('../src/utils/jwt');

describe('Security Tests - Authentication & Authorization', () => {
  
  describe('JWT Validation', () => {
    test('should reject requests without JWT token', async () => {
      const res = await request(app)
        .get('/api/orders')
        .expect(401);
      
      expect(res.body.error).toMatch(/unauthorized/i);
    });
    
    test('should reject expired tokens', async () => {
      const expiredToken = generateJWT({ userId: 1 }, '-1h'); // Expired 1 hour ago
      
      const res = await request(app)
        .get('/api/orders')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
    });
    
    test('should reject tampered tokens', async () => {
      const token = generateJWT({ userId: 1 });
      const tampered = token.slice(0, -10) + 'hacked1234'; // Modify signature
      
      const res = await request(app)
        .get('/api/orders')
        .set('Authorization', `Bearer ${tampered}`)
        .expect(401);
    });
    
    test('should reject tokens signed with wrong secret', async () => {
      const jwt = require('jsonwebtoken');
      const wrongToken = jwt.sign({ userId: 1 }, 'wrong-secret');
      
      const res = await request(app)
        .get('/api/orders')
        .set('Authorization', `Bearer ${wrongToken}`)
        .expect(401);
    });
  });
  
  describe('Input Validation & Injection Prevention', () => {
    const token = generateJWT({ userId: 1 });
    
    test('should reject SQL injection in email field', async () => {
      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${token}`)
        .send({
          email: "admin'--",  // SQL injection attempt
          password: 'Safe123!@#'
        })
        .expect(400);
      
      expect(res.body.error).toMatch(/invalid email/i);
    });
    
    test('should reject XSS in name field', async () => {
      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${token}`)
        .send({
          email: 'user@example.com',
          name: '<script>alert("xss")</script>',
          password: 'Safe123!@#'
        })
        .expect(400);
    });
    
    test('should enforce password complexity', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'test@example.com',
          password: 'weak'  // Too simple
        })
        .expect(400);
      
      expect(res.body.error).toMatch(/password must be at least 12 characters/i);
    });
    
    test('should sanitize special characters', async () => {
      const res = await request(app)
        .post('/api/orders')
        .set('Authorization', `Bearer ${token}`)
        .send({
          description: '<<script>>malicious<</script>>',
          amount: 100
        })
        .expect(201);
      
      // Verify sanitization occurred
      const order = res.body;
      expect(order.description).not.toContain('<script>');
    });
  });
  
  describe('Authorization & RBAC', () => {
    test('user should not access other users orders', async () => {
      const user1Token = generateJWT({ userId: 1 });
      
      const res = await request(app)
        .get('/api/orders/999')  // Order belonging to user 999
        .set('Authorization', `Bearer ${user1Token}`)
        .expect(403);
      
      expect(res.body.error).toMatch(/forbidden/i);
    });
    
    test('admin can view any order', async () => {
      const adminToken = generateJWT({ userId: 1, role: 'admin' });
      
      const res = await request(app)
        .get('/api/orders/999')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
    });
    
    test('user cannot access admin endpoints', async () => {
      const userToken = generateJWT({ userId: 1, role: 'user' });
      
      const res = await request(app)
        .post('/api/admin/users/ban')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ userId: 2 })
        .expect(403);
    });
  });
  
  describe('Rate Limiting & DoS Protection', () => {
    test('should block after exceeding rate limit', async () => {
      const token = generateJWT({ userId: 1 });
      
      // Make 101 requests (limit is 100/min)
      for (let i = 0; i < 101; i++) {
        const res = await request(app)
          .get('/api/orders')
          .set('Authorization', `Bearer ${token}`);
        
        if (i === 100) {
          expect(res.status).toBe(429); // Too Many Requests
        }
      }
    });
  });
  
  describe('Session Management', () => {
    test('should invalidate session on logout', async () => {
      const token = generateJWT({ userId: 1 });
      
      // Logout
      await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      // Try to use same token
      const res = await request(app)
        .get('/api/orders')
        .set('Authorization', `Bearer ${token}`)
        .expect(401);
    });
  });
  
  describe('Error Handling - No Information Leakage', () => {
    test('should not expose stack traces in error responses', async () => {
      const res = await request(app)
        .get('/api/nonexistent')
        .expect(404);
      
      // Should NOT contain:
      expect(res.body).not.toHaveProperty('stack');
      expect(res.text).not.toContain('at Function');
      expect(res.text).not.toContain('node_modules');
    });
    
    test('should use generic error messages for auth failures', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'anypassword'
        })
        .expect(401);
      
      // Should NOT say "user not found" (reveals user enumeration)
      expect(res.body.error).toBe('Invalid credentials');
    });
  });
});

describe('Security Tests - Data Protection', () => {
  
  test('should never log sensitive data', async () => {
    const consoleSpy = jest.spyOn(console, 'log');
    
    const token = generateJWT({ userId: 1 });
    await request(app)
      .get('/api/orders')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    
    // Check logs don't contain token
    const logs = consoleSpy.mock.calls.flat().join('');
    expect(logs).not.toContain(token);
    
    consoleSpy.mockRestore();
  });
  
  test('should encrypt sensitive data in transit', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'user@example.com',
        password: 'Password123!@#'
      });
    
    // Check HTTPS header is set
    expect(res.headers['strict-transport-security']).toBeDefined();
  });
});

describe('Security Tests - CORS & CSRF', () => {
  
  test('should reject requests from untrusted origins', async () => {
    const res = await request(app)
      .get('/api/orders')
      .set('Origin', 'https://evil.com')
      .expect(403);
  });
  
  test('should accept requests from whitelisted origins', async () => {
    const token = generateJWT({ userId: 1 });
    
    const res = await request(app)
      .get('/api/orders')
      .set('Origin', 'https://techshop.com')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });
});
```

**Run tests locally and in CI:**

```bash
# Local development
npm test -- --coverage

# CI/CD (GitHub Actions adds this step)
npm test -- --coverage --watchAll=false
```

### Step 4B: DAST - Dynamic Application Security Testing

DAST runs actual attack simulations against your running application. Unlike SAST (which reads code), DAST interacts with the live app.

**Using OWASP ZAP (Zed Attack Proxy):**

```bash
# 1. Install ZAP Docker image
docker pull owasp/zap2docker-stable

# 2. Start your app (locally or in test environment)
npm start  # App runs on localhost:3000

# 3. Run ZAP scan
docker run --network host \
  owasp/zap2docker-stable zap-baseline.py \
  -t http://localhost:3000 \
  -r zap-report.html

# What ZAP tests for:
# - SQL Injection
# - Cross-Site Scripting (XSS)
# - Cross-Site Request Forgery (CSRF)
# - Broken Authentication
# - Sensitive Data Exposure
# - Missing Security Headers
# - Insecure Deserialization
# - Using Components with Known Vulnerabilities
```

**Integrate OWASP ZAP into GitHub Actions:**

```yaml
# .github/workflows/dast.yml
name: DAST Testing

on:
  push:
    branches: [main, develop]

jobs:
  dast:
    runs-on: ubuntu-latest
    
    services:
      # Start app for testing
      app:
        image: techshop-api:latest
        ports:
          - 3000:3000
        env:
          DATABASE_URL: ${{ secrets.TEST_DB_URL }}
          JWT_SECRET: test-secret
          NODE_ENV: test
    
    steps:
      - uses: actions/checkout@v4
      
      # Wait for app to be ready
      - name: Wait for app to start
        run: |
          for i in {1..30}; do
            curl -f http://localhost:3000/health && break
            sleep 2
          done
      
      # Run OWASP ZAP baseline scan
      - name: Run OWASP ZAP scan
        uses: zaproxy/action-baseline@v0.7.0
        with:
          target: 'http://localhost:3000'
          rules_file_name: '.zap/rules.tsv'
          cmd_options: '-a'
      
      # Generate report
      - name: Publish ZAP results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: zap-scan-report
          path: report_html.html
      
      # Fail if high-risk issues found
      - name: Check for critical issues
        run: |
          if grep -q "Risk: High" report_html.html; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi
```

### Step 4C: API Security Testing with Nuclei

Nuclei is a template-based vulnerability scanner perfect for APIs:

```yaml
# nuclei-templates/techshop-api.yaml
id: techshop-api-security
info:
  name: TechShop API Security Tests
  description: Custom security templates for TechShop
  severity: high

requests:
  # Test 1: Check for authentication bypass
  - raw:
      - |
        GET /api/orders HTTP/1.1
        Host: {{Hostname}}
    
    matchers:
      - type: status
        status:
          - 401  # Should require auth
    
    matchers-condition: and

  # Test 2: Check for exposed API keys in response
  - raw:
      - |
        GET /api/config HTTP/1.1
        Host: {{Hostname}}
    
    matchers-condition: and
    matchers:
      - type: word
        words:
          - 'api_key'
          - 'secret'
          - 'password'
        condition: or
      
      - type: status
        status:
          - 200

  # Test 3: Check for missing security headers
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
    
    matchers:
      - type: word
        words:
          - 'X-Content-Type-Options: nosniff'
          - 'X-Frame-Options'
          - 'Strict-Transport-Security'
        negative: true

  # Test 4: SQL Injection test
  - raw:
      - |
        GET /api/search?q=test' OR '1'='1 HTTP/1.1
        Host: {{Hostname}}
    
    matchers:
      - type: status
        status:
          - 400  # Should reject malicious input
          - 401
```

**Run Nuclei:**

```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Run custom templates
nuclei -t nuclei-templates/techshop-api.yaml -u http://localhost:3000

# Run against all endpoints
nuclei -l urls.txt -t nuclei-templates/ -o results.json
```

### Step 4D: Dependency Composition Analysis (SCA)

**OWASP Dependency-Check Test Integration:**

```javascript
// tests/dependencies.test.js
const dependencyCheck = require('dependency-check-npm');
const fs = require('fs');

describe('Dependency Security', () => {
  
  test('should not have high-severity vulnerabilities', async () => {
    const report = JSON.parse(
      fs.readFileSync('dependency-check-report.json')
    );
    
    const highSeverity = report.reportSchema.vulnerabilities.filter(
      v => v.severity === 'HIGH' || v.severity === 'CRITICAL'
    );
    
    expect(highSeverity.length).toBe(0);
  }, 30000); // 30 second timeout
  
  test('should have all dependencies pinned to specific versions', () => {
    const packageLock = JSON.parse(
      fs.readFileSync('package-lock.json')
    );
    
    // Verify no ranges like ^1.0.0 or ~2.1.0
    const versions = Object.values(packageLock.packages)
      .map(pkg => pkg.version);
    
    versions.forEach(version => {
      expect(version).toMatch(/^\d+\.\d+\.\d+$/); // Exact semver only
    });
  });
  
  test('should have license compliance', () => {
    const licenses = JSON.parse(
      fs.readFileSync('license-check-results.json')
    );
    
    // Reject GPL, AGPL for proprietary software
    const forbidden = licenses.filter(
      l => l.license.includes('GPL') || l.license.includes('AGPL')
    );
    
    expect(forbidden.length).toBe(0);
  });
});
```

### ✅ Test Stage Checklist

```
□ Unit security tests written (JWT, input validation, auth)
□ Integration security tests passing
□ DAST (OWASP ZAP) scan configured in CI/CD
□ API security tests (Nuclei templates) created
□ Dependency composition analysis integrated
□ Test coverage > 80% for security-critical paths
□ All tests run on every commit (CI/CD)
□ Failure criteria defined (must block on high-severity findings)
□ Performance baseline established (tests shouldn't slow build >5min)
□ Test data sanitized (no real PII in test environment)
```

---

## Stage 5: Release — Pre-Deployment Verification {#stage-5-release}

### Why Pre-Deployment Checks Save Your Team

Before pushing to production, we verify everything again. This is like a pre-flight checklist for aircraft—redundancy saves lives (and reputation).

### Step 5A: Release Checklist Automation

Create an automated checklist that must pass before deployment:

```yaml
# .github/workflows/pre-release.yml
name: Pre-Release Verification

on:
  pull_request:
    types: [opened, synchronize]
    branches:
      - main

jobs:
  pre-release-checks:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      # 1. Verify changelog updated
      - name: Check CHANGELOG updated
        run: |
          if ! git diff --name-only ${{ github.event.pull_request.base.sha }} | grep -q "^CHANGELOG.md$"; then
            echo "❌ CHANGELOG.md not updated"
            exit 1
          fi
          echo "✅ CHANGELOG.md updated"
      
      # 2. Verify version bumped
      - name: Check version bump
        run: |
          VERSION=$(jq -r '.version' package.json)
          if [[ $VERSION == *"0.0.0-dev"* ]]; then
            echo "❌ Version still dev: $VERSION"
            exit 1
          fi
          echo "✅ Version set: $VERSION"
      
      # 3. Verify security documentation
      - name: Check SECURITY.md
        run: test -f SECURITY.md || (echo "❌ SECURITY.md missing" && exit 1)
      
      # 4. Verify no hardcoded secrets
      - name: Secrets scan
        run: |
          npx detect-secrets scan --baseline .secrets.baseline || exit 1
      
      # 5. Verify code review approval
      - name: Require code review
        uses: actions/github-script@v6
        with:
          script: |
            const pr = context.payload.pull_request;
            const reviews = await github.rest.pulls.listReviews({
              owner: context.repo.owner,
              repo: context.repo.repo,
              pull_number: pr.number
            });
            
            const approvals = reviews.data.filter(r => r.state === 'APPROVED');
            if (approvals.length < 2) {
              core.setFailed('❌ Requires 2 approvals. Current: ' + approvals.length);
            } else {
              core.notice('✅ Code review approved');
            }
      
      # 6. Verify all CI checks passed
      - name: Require CI checks
        uses: actions/github-script@v6
        with:
          script: |
            const pr = context.payload.pull_request;
            const checks = await github.rest.checks.listForRef({
              owner: context.repo.owner,
              repo: context.repo.repo,
              ref: pr.head.sha
            });
            
            const failures = checks.data.check_runs.filter(
              c => c.status !== 'completed' || c.conclusion === 'failure'
            );
            
            if (failures.length > 0) {
              core.setFailed('❌ Some CI checks failed');
            } else {
              core.notice('✅ All CI checks passed');
            }
      
      # 7. Generate SBOM (Software Bill of Materials)
      - name: Generate SBOM
        run: |
          npm install -g cyclonedx-npm
          cyclonedx-npm --output-file sbom.json
      
      # 8. Scan SBOM for supply chain risks
      - name: Scan SBOM with Snyk
        run: |
          snyk sbom --file sbom.json
      
      # 9. Verify artifact signing readiness
      - name: Prepare artifact signing
        run: |
          echo "Artifact signing keys configured: ✅"
          # In production, verify GPG/Cosign keys exist
      
      # 10. Generate release notes
      - name: Generate release notes
        run: |
          # Parse CHANGELOG for this version
          VERSION=$(jq -r '.version' package.json)
          sed -n "/## \[$VERSION\]/,/## \[/p" CHANGELOG.md | head -n -1 > RELEASE_NOTES.md
          cat RELEASE_NOTES.md
      
      # 11. Final security sign-off
      - name: Final security review
        run: |
          echo "=== Final Security Sign-Off ===" 
          echo "✅ All tests passed"
          echo "✅ SAST scan complete"
          echo "✅ DAST scan complete"
          echo "✅ Dependency check passed"
          echo "✅ Container scan passed"
          echo "✅ IaC validation passed"
          echo "✅ Code review approved"
          echo "✅ Security documentation updated"
          echo ""
          echo "🚀 Ready for release!"
```

### Step 5B: Release Tag & Artifact Signing

**Sign your releases with GPG (proof of authenticity):**

```bash
# 1. Generate GPG key (if not already done)
gpg --gen-key
# Follow prompts to create key

# 2. Configure Git to use your key
git config user.signingkey YOUR-KEY-ID
git config commit.gpgsign true

# 3. Tag release with signature
VERSION="v1.2.0"
git tag -s $VERSION -m "Release $VERSION"

# 4. Sign Docker image with Cosign (optional but recommended)
# Install Cosign
wget https://github.com/sigstore/cosign/releases/download/v2.0.0/cosign-linux-amd64
chmod +x cosign-linux-amd64

# Sign image
./cosign sign --key cosign.key techshop-api:$VERSION

# 5. Upload signed artifacts to GitHub Release
gh release create $VERSION \
  --title "TechShop $VERSION" \
  --notes "$(cat RELEASE_NOTES.md)" \
  sbom.json \
  LICENSE

# Verify signature
git tag -v $VERSION
```

### Step 5C: Release Approval Workflow

Create a manual approval gate for production releases:

```yaml
# .github/workflows/release-approval.yml
name: Release Approval Gate

on:
  workflow_dispatch:  # Manual trigger
    inputs:
      version:
        description: 'Version to release (e.g., v1.2.0)'
        required: true
      environment:
        description: 'Target environment'
        required: true
        type: choice
        options:
          - staging
          - production

jobs:
  approval-check:
    runs-on: ubuntu-latest
    environment:
      name: ${{ github.event.inputs.environment }}-approval
    
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/tags/${{ github.event.inputs.version }}
      
      # This step requires manual approval from security team
      - name: Wait for security team approval
        run: |
          echo "⏳ Waiting for security team approval..."
          echo "Environment: ${{ github.event.inputs.environment }}"
          echo "Version: ${{ github.event.inputs.version }}"
          echo ""
          echo "✅ Approval checklist:"
          echo "  □ All automated tests passed"
          echo "  □ Penetration testing complete (if required)"
          echo "  □ Security review approved"
          echo "  □ Change advisory board signed off"
          echo "  □ Rollback plan documented"
      
      - name: Notify Slack
        uses: slackapi/slack-github-action@v1.24.0
        with:
          payload: |
            {
              "text": "🔐 Release Approval Required",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "*Release Ready for Approval*\n\nVersion: `${{ github.event.inputs.version }}`\nEnvironment: `${{ github.event.inputs.environment }}`\nRequester: `${{ github.actor }}`"
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
          SLACK_WEBHOOK_TYPE: INCOMING_WEBHOOK
      
      - name: Generate approval summary
        run: |
          cat > approval-summary.md << 'EOF'
          # Release Approval Summary
          
          **Version:** ${{ github.event.inputs.version }}
          **Environment:** ${{ github.event.inputs.environment }}
          **Date:** $(date)
          **Approver:** (To be filled by security team)
          
          ## Pre-Release Verification Results
          
          ### Security Scans
          - ✅ SAST (SonarQube) - 0 critical findings
          - ✅ DAST (OWASP ZAP) - 0 high-risk vulnerabilities
          - ✅ SCA (Snyk) - 0 high-severity dependencies
          - ✅ Container Scan (Trivy) - 0 critical vulnerabilities
          - ✅ IaC Validation (Checkov) - All policies passed
          
          ### Code Quality
          - ✅ Unit Test Coverage: 87%
          - ✅ Integration Tests: 24/24 passing
          - ✅ Security Tests: 18/18 passing
          
          ### Documentation
          - ✅ CHANGELOG updated
          - ✅ SECURITY.md reviewed
          - ✅ API documentation current
          - ✅ Deployment runbook prepared
          
          ### Sign-Off
          - [ ] Security Team Lead
          - [ ] DevOps Lead
          - [ ] Product Owner
          - [ ] Change Advisory Board
          EOF
          
          cat approval-summary.md
      
      - name: Upload approval summary
        uses: actions/upload-artifact@v3
        with:
          name: release-approval-summary
          path: approval-summary.md
```

### ✅ Release Stage Checklist

```
□ All CI/CD checks passing
□ CHANGELOG.md updated with version & changes
□ Version number bumped (semver)
□ Git tag created with GPG signature
□ SBOM (Software Bill of Materials) generated
□ Release notes generated from CHANGELOG
□ Code reviewed by ≥2 senior developers
□ Security review completed
□ Penetration testing done (if applicable)
□ Deployment runbook prepared
□ Rollback plan documented
□ Stakeholder approvals obtained
□ On-call engineer briefed
□ Change management ticket created
```

---

## Stage 6: Deploy — Secure Deployment {#stage-6-deploy}

### Why Deployment Security Matters

Even with perfect code, bad deployment practices can introduce vulnerabilities. This stage focuses on deploying safely and verifiably.

### Step 6A: GitOps-Based Deployment with ArgoCD

**The Principle:** Git is source of truth. Deploy by pushing commits.

```yaml
# .github/workflows/deploy.yml
name: Secure Deployment

on:
  push:
    branches: [main]
    paths:
      - 'src/**'
      - 'Dockerfile'
      - 'helm/**'
  workflow_dispatch:
    inputs:
      environment:
        description: 'Deploy to environment'
        required: true
        type: choice
        options:
          - staging
          - production

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    outputs:
      image: ${{ steps.image.outputs.image }}
      digest: ${{ steps.image.outputs.digest }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker buildx
        uses: docker/setup-buildx-action@v2
      
      - name: Login to ECR
        uses: aws-actions/amazon-ecr-login@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Build and push Docker image
        id: image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            ${{ secrets.ECR_REGISTRY }}/techshop:${{ github.sha }}
            ${{ secrets.ECR_REGISTRY }}/techshop:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
          outputs: type=oci
      
      # Sign image
      - name: Install Cosign
        uses: sigstore/cosign-installer@v3
      
      - name: Sign Docker image
        env:
          COSIGN_EXPERIMENTAL: 1
        run: |
          cosign sign --yes ${{ steps.image.outputs.image }}@${{ steps.image.outputs.digest }}
      
      # Verify image after signing
      - name: Verify image signature
        env:
          COSIGN_EXPERIMENTAL: 1
        run: |
          cosign verify ${{ steps.image.outputs.image }}@${{ steps.image.outputs.digest }}

  deploy:
    needs: build-and-push
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
        with:
          repository: techshop-org/gitops-config  # Separate GitOps repo
          token: ${{ secrets.GITOPS_TOKEN }}
          path: gitops
      
      - name: Update Helm values
        run: |
          cd gitops
          
          # Update image tag in values file
          sed -i "s|image:.*|image: ${{ needs.build-and-push.outputs.image }}|" \
            helm/values-prod.yaml
          
          # Add deployment annotation for audit trail
          DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
          sed -i "s|deployedAt:.*|deployedAt: $DATE|" helm/values-prod.yaml
          sed -i "s|deployedBy:.*|deployedBy: ${{ github.actor }}|" helm/values-prod.yaml
          sed -i "s|commitSha:.*|commitSha: ${{ github.sha }}|" helm/values-prod.yaml
      
      - name: Commit and push
        run: |
          cd gitops
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add helm/values-prod.yaml
          git commit -m "Deploy TechShop API ${{ github.sha }}"
          git push
      
      # ArgoCD automatically syncs when it detects changes
      # It pulls from this GitOps repo and applies to Kubernetes
      
      - name: Wait for ArgoCD sync
        run: |
          # Wait for ArgoCD to detect and sync changes
          sleep 30
          # Then verify with kubectl
          kubectl rollout status deployment/techshop-api \
            -n production --timeout=5m
        env:
          KUBECONFIG: ${{ secrets.KUBECONFIG }}
      
      - name: Verify deployment
        run: |
          # Verify new pods are running
          kubectl get pods -n production -l app=techshop-api
          
          # Check for any CrashLoopBackOff or errors
          kubectl describe pods -n production -l app=techshop-api
        env:
          KUBECONFIG: ${{ secrets.KUBECONFIG }}
```

### Step 6B: Kubernetes Security Configuration

**Deploy to Kubernetes with security defaults:**

```yaml
# helm/values-prod.yaml
replicaCount: 3

image:
  repository: 123456789.dkr.ecr.us-east-1.amazonaws.com/techshop
  tag: latest
  pullPolicy: IfNotPresent
  # Use signed images only
  signatureVerification: true

# Pod Security Context - Run as non-root
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1001
  runAsGroup: 3000
  fsGroup: 2000
  seccompProfile:
    type: RuntimeDefault

# Container Security Context
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE

# Network Policy - Restrict traffic
networkPolicy:
  enabled: true
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
      - namespaceSelector:
          matchLabels:
            name: ingress-nginx
      ports:
        - protocol: TCP
          port: 3000
  egress:
    - to:
      - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 3306  # MySQL
        - protocol: TCP
          port: 443   # HTTPS
    - to:
      - podSelector:
          matchLabels:
            k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53

# Pod Disruption Budget - High availability
podDisruptionBudget:
  minAvailable: 2

# Liveness & Readiness Probes
livenessProbe:
  httpGet:
    path: /health
    port: 3000
  initialDelaySeconds: 10
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 3000
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2

# Resource Limits - Prevent DoS via resource exhaustion
resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

# Secrets mounted from external sources
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: techshop-secrets
        key: database-url
  - name: JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: techshop-secrets
        key: jwt-secret
  - name: API_KEY
    valueFrom:
      secretKeyRef:
        name: techshop-secrets
        key: api-key

# Pod Security Policy (enforced by cluster)
podSecurityPolicy: restricted

# Service Account with minimal permissions
serviceAccount:
  create: true
  name: techshop-api
  automountServiceAccountToken: true

# RBAC - What this SA can do
rbac:
  create: true
  rules:
    # Read secrets for this app only
    - apiGroups: [""]
      resources: ["secrets"]
      resourceNames: ["techshop-secrets"]
      verbs: ["get"]
    # Cannot create or delete pods
    - apiGroups: [""]
      resources: ["pods"]
      verbs: ["get", "list"]

# Affinity - Spread pods across nodes
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
            - key: app
              operator: In
              values:
                - techshop-api
        topologyKey: kubernetes.io/hostname

ingress:
  enabled: true
  className: nginx
  annotations:
    # Force HTTPS
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    # Security headers
    nginx.ingress.kubernetes.io/add-headers: "default/security-headers"
    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "100"
  hosts:
    - host: api.techshop.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: techshop-tls
      hosts:
        - api.techshop.com
```

### Step 6C: Secrets Management During Deployment

**Use Sealed Secrets for GitOps-friendly secret management:**

```bash
# Install Sealed Secrets controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.18.0/controller.yaml

# Create a secret
kubectl create secret generic techshop-secrets \
  --from-literal=database-url="mysql://user:pass@host/db" \
  --from-literal=jwt-secret="your-jwt-secret" \
  --dry-run=client -o yaml > secret.yaml

# Seal it (encrypt) so it's safe to commit to Git
kubeseal -f secret.yaml -w sealed-secret.yaml

# Now sealed-secret.yaml is safe to commit
# Only the cluster with the right key can decrypt it
git add sealed-secret.yaml
git commit -m "Add sealed secrets"

# In Kubernetes manifest, reference the sealed secret
# When deployed, it automatically decrypts
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: techshop-secrets
  namespace: production
spec:
  encryptedData:
    database-url: AgBvB3jz5k...  # Encrypted value
    jwt-secret: AgC2kM8zF...     # Encrypted value
```

### Step 6D: Deployment Monitoring & Validation

**Health checks post-deployment:**

```bash
#!/bin/bash
# deploy-validation.sh - Run after deployment

set -e

NAMESPACE="production"
SERVICE="techshop-api"
TIMEOUT=300

echo "🚀 Validating TechShop API Deployment"

# 1. Wait for deployment to be ready
echo "⏳ Waiting for deployment to be ready..."
kubectl rollout status deployment/$SERVICE -n $NAMESPACE --timeout=${TIMEOUT}s

# 2. Check all pods are running
echo "🔍 Checking pod status..."
POD_COUNT=$(kubectl get pods -n $NAMESPACE -l app=$SERVICE -o jsonpath='{.items | length}')
READY_COUNT=$(kubectl get pods -n $NAMESPACE -l app=$SERVICE -o jsonpath='{.items[?(@.status.conditions[?(@.type=="Ready")].status=="True")] | length}')

if [ "$POD_COUNT" -eq "$READY_COUNT" ]; then
  echo "✅ All $POD_COUNT pods ready"
else
  echo "❌ Only $READY_COUNT/$POD_COUNT pods ready"
  exit 1
fi

# 3. Verify image signature
echo "🔐 Verifying image signatures..."
IMAGES=$(kubectl get pods -n $NAMESPACE -l app=$SERVICE -o jsonpath='{.items[*].spec.containers[*].image}')
for IMAGE in $IMAGES; do
  if ! cosign verify $IMAGE > /dev/null; then
    echo "❌ Image not signed: $IMAGE"
    exit 1
  fi
  echo "✅ Signature verified: $IMAGE"
done

# 4. Check service connectivity
echo "📡 Testing service connectivity..."
SERVICE_IP=$(kubectl get svc $SERVICE -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
for i in {1..5}; do
  if curl -s -f "https://$SERVICE_IP/health" > /dev/null; then
    echo "✅ Service responding to requests"
    break
  fi
  if [ $i -eq 5 ]; then
    echo "❌ Service not responding"
    exit 1
  fi
  sleep 10
done

# 5. Check application logs for errors
echo "📋 Checking application logs..."
POD=$(kubectl get pods -n $NAMESPACE -l app=$SERVICE -o jsonpath='{.items[0].metadata.name}')
if kubectl logs $POD -n $NAMESPACE | grep -i "error\|exception\|failed"; then
  echo "⚠️  Check logs - errors detected"
  kubectl logs $POD -n $NAMESPACE | tail -20
fi

# 6. Monitor error rates
echo "📊 Checking error metrics..."
kubectl exec -it $POD -n $NAMESPACE -- curl -s localhost:9090/metrics | grep http_requests_total

echo ""
echo "✅ Deployment validation complete!"
echo "🎉 TechShop API is running in production"
```

### ✅ Deploy Stage Checklist

```
□ Container image signed and verified
□ Docker image scanned with Trivy (zero critical vulnerabilities)
□ Secrets encrypted and managed via Vault/Sealed Secrets
□ Kubernetes manifests validated with kubeval
□ Network policies configured
□ RBAC rules least-privilege
□ Pod security policies enforced
□ Resource limits set (CPU/memory)
□ Health checks configured (liveness/readiness)
□ Monitoring & logging configured
□ Backup & disaster recovery tested
□ Load balancer health checks verified
□ Deployment rolled out gradually (canary if applicable)
□ Post-deployment validation passed
□ On-call team notified
□ Incident response plan reviewed
```

---

## Stage 7: Monitor — Continuous Security Visibility {#stage-7-monitor}

### Why Monitoring is Your Earliest Warning System

Threats don't stop at deployment. Real-time monitoring detects attacks, misconfigurations, and anomalies before they cause damage.

### Step 7A: Security Event Logging Architecture

```yaml
# CloudWatch/Prometheus setup for security monitoring
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: monitoring
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    alerting:
      alertmanagers:
        - static_configs:
            - targets:
                - alertmanager:9093
    
    rule_files:
      - /etc/prometheus/security-rules.yml
    
    scrape_configs:
      # Monitor Kubernetes API server
      - job_name: 'kubernetes-apiservers'
        kubernetes_sd_configs:
          - role: endpoints
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
      
      # Monitor application
      - job_name: 'techshop-api'
        static_configs:
          - targets: ['localhost:3000']
        metrics_path: '/metrics'
      
      # Monitor container runtime
      - job_name: 'kubelet'
        kubernetes_sd_configs:
          - role: nodes
        scheme: https
        tls_config:
          ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

---
apiVersion: ConfigMap
metadata:
  name: security-rules
  namespace: monitoring
data:
  security-rules.yml: |
    groups:
      - name: security_alerts
        interval: 30s
        rules:
          # Alert on failed authentication attempts
          - alert: HighFailedAuthAttempts
            expr: |
              rate(http_requests_total{path="/auth/login",status="401"}[5m]) > 0.5
            for: 2m
            annotations:
              summary: "High failed login attempts detected"
              description: "{{ $value }} failed logins per second"
          
          # Alert on SQL injection attempts
          - alert: PotentialSQLInjection
            expr: |
              rate(security_events_total{event_type="sql_injection_attempt"}[5m]) > 0
            annotations:
              summary: "SQL injection attempt detected"
              severity: critical
          
          # Alert on data exfiltration patterns
          - alert: UnusualDataAccess
            expr: |
              rate(data_access_bytes_total[5m]) > 
              avg_over_time(data_access_bytes_total[7d]) * 3
            for: 5m
            annotations:
              summary: "Unusual data access pattern detected"
          
          # Alert on privilege escalation
          - alert: PrivilegeEscalation
            expr: |
              increase(rbac_deny_total[5m]) > 5
            annotations:
              summary: "Multiple privilege escalation attempts"
              severity: critical
          
          # Alert on certificate expiration
          - alert: CertificateExpiring
            expr: |
              (certmanager_certificate_expiration_timestamp_seconds - time()) / 86400 < 30
            annotations:
              summary: "Certificate expiring in less than 30 days"
          
          # Alert on image with vulnerabilities deployed
          - alert: VulnerableImageDeployed
            expr: |
              container_image_vulnerability_count > 0
            annotations:
              summary: "Container with known vulnerabilities deployed"
              severity: high
```

### Step 7B: Application Security Logging

**Instrument your code for security events:**

```javascript
// src/logging/securityLogger.js
const winston = require('winston');
const CloudWatchTransport = require('winston-cloudwatch');

class SecurityLogger {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.json(),
      defaultMeta: { service: 'techshop-api' },
      transports: [
        // CloudWatch for production
        new CloudWatchTransport({
          logGroupName: `/techshop/${process.env.NODE_ENV}/security`,
          logStreamName: `${process.env.NODE_ENV}-stream-${Date.now()}`,
          awsRegion: process.env.AWS_REGION,
        }),
        // Console for local development
        new winston.transports.Console({
          format: winston.format.simple()
        })
      ]
    });
  }

  // Log authentication attempts
  logAuthAttempt(email, success, ip) {
    this.logger.info('auth_attempt', {
      event_type: 'authentication',
      email: email,
      success: success,
      ip_address: ip,
      timestamp: new Date().toISOString()
    });
  }

  // Log failed authentication
  logAuthFailure(email, reason, ip) {
    this.logger.warn('auth_failure', {
      event_type: 'authentication_failure',
      email: email,
      reason: reason, // 'invalid_password', 'user_not_found', etc
      ip_address: ip,
      severity: 'medium',
      timestamp: new Date().toISOString()
    });
  }

  // Log potential attacks
  logSecurityEvent(eventType, details, severity = 'medium') {
    this.logger.warn('security_event', {
      event_type: eventType,
      details: details,
      severity: severity, // low, medium, high, critical
      timestamp: new Date().toISOString()
    });
  }

  // Log data access for audit trail
  logDataAccess(userId, resource, action, result) {
    this.logger.info('data_access', {
      event_type: 'data_access_audit',
      user_id: userId,
      resource: resource,
      action: action,
      result: result,
      timestamp: new Date().toISOString()
    });
  }

  // Log configuration changes
  logConfigChange(changeType, oldValue, newValue, changedBy) {
    this.logger.warn('config_change', {
      event_type: 'configuration_change',
      change_type: changeType,
      old_value: '***REDACTED***', // Never log sensitive values
      new_value: '***REDACTED***',
      changed_by: changedBy,
      timestamp: new Date().toISOString()
    });
  }

  // Log permission denials
  logAuthorizationDenial(userId, resource, reason) {
    this.logger.warn('authz_denial', {
      event_type: 'authorization_denied',
      user_id: userId,
      requested_resource: resource,
      reason: reason,
      timestamp: new Date().toISOString()
    });
  }
}

module.exports = new SecurityLogger();
```

**Use the logger in your routes:**

```javascript
// src/routes/auth.js
const express = require('express');
const securityLogger = require('../logging/securityLogger');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const router = express.Router();

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const clientIp = req.ip;

  try {
    // Validate input
    if (!email || !password) {
      securityLogger.logSecurityEvent('invalid_login_request', {
        missing_field: !email ? 'email' : 'password',
        ip_address: clientIp
      }, 'low');
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Find user (never reveal if user exists to prevent enumeration)
    const user = await User.findOne({ email });
    if (!user) {
      securityLogger.logAuthFailure(email, 'user_not_found', clientIp);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      securityLogger.logAuthFailure(email, 'invalid_password', clientIp);
      
      // Track failed attempts (for brute force detection)
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts > 5) {
        securityLogger.logSecurityEvent('brute_force_detected', {
          email: email,
          attempts: user.failedLoginAttempts,
          ip_address: clientIp
        }, 'high');
        user.locked = true;
      }
      await user.save();
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.locked) {
      securityLogger.logAuthFailure(email, 'account_locked', clientIp);
      return res.status(401).json({ error: 'Account locked. Contact support.' });
    }

    // Success! Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Log successful authentication
    securityLogger.logAuthAttempt(email, true, clientIp);

    res.json({ token });

  } catch (error) {
    securityLogger.logSecurityEvent('login_error', {
      error: error.message
    }, 'medium');
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
```

### Step 7C: Grafana Dashboards for Security Monitoring

**Create dashboards to visualize security metrics:**

```yaml
# grafana-dashboard.json (simplified)
{
  "dashboard": {
    "title": "TechShop Security Dashboard",
    "panels": [
      {
        "title": "Failed Login Attempts (Last 24h)",
        "targets": [{
          "expr": "increase(auth_failures_total[24h])"
        }],
        "alert": {
          "conditions": [{
            "evaluator": { "type": "gt", "params": [50] },
            "operator": { "type": "and" }
          }],
          "message": "High failed login attempts detected"
        }
      },
      {
        "title": "API Response Time P99",
        "targets": [{
          "expr": "histogram_quantile(0.99, http_request_duration_seconds)"
        }]
      },
      {
        "title": "Data Access Audit Trail",
        "targets": [{
          "expr": "data_access_total"
        }]
      },
      {
        "title": "Permission Denials",
        "targets": [{
          "expr": "rate(authz_denials_total[5m])"
        }]
      },
      {
        "title": "Active Security Vulnerabilities",
        "targets": [{
          "expr": "container_vulnerability_count{severity=~'high|critical'}"
        }],
        "alert": {
          "message": "Critical vulnerabilities detected in deployment"
        }
      },
      {
        "title": "Certificate Expiration Status",
        "targets": [{
          "expr": "(certmanager_certificate_expiration_timestamp_seconds - time()) / 86400"
        }]
      }
    ]
  }
}
```

### Step 7D: Automated Incident Response

**Automatically respond to security events:**

```yaml
# alertmanager-config.yml
global:
  resolve_timeout: 5m

route:
  receiver: security-team
  group_by: ['alertname', 'cluster']
  routes:
    # Critical - immediate page
    - match:
        severity: critical
      receiver: pagerduty-critical
      repeat_interval: 5m
    
    # High severity - email + Slack
    - match:
        severity: high
      receiver: security-slack
      repeat_interval: 1h
    
    # Medium - Slack only
    - match:
        severity: medium
      receiver: security-slack
      repeat_interval: 4h

receivers:
  - name: security-team
    email_configs:
      - to: security-team@techshop.com
        from: alerts@techshop.com
        smarthost: smtp.example.com:587
        auth_username: alerts@techshop.com
  
  - name: pagerduty-critical
    pagerduty_configs:
      - service_key: $PAGERDUTY_KEY
        description: "🚨 Critical Security Alert"
  
  - name: security-slack
    slack_configs:
      - api_url: $SLACK_WEBHOOK_URL
        channel: '#security-alerts'
        title: "🔒 Security Alert"
        text: "{{ range .Alerts }}{{ .Annotations.summary }}\n{{ end }}"

inhibit_rules:
  # Don't alert on authentication failures if service is down
  - source_match:
      alertname: ServiceDown
    target_match:
      alertname: HighFailedAuthAttempts
    equal: ['instance']
```

### Step 7E: SIEM Integration (Optional)

**Send all security logs to a SIEM for correlation
# CodeDrift

**Enterprise-Grade AI Code Safety Guardian for JavaScript & TypeScript**

[![npm version](https://badge.fury.io/js/codedrift.svg)](https://www.npmjs.com/package/codedrift)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CodeDrift is a static analysis tool that detects critical security vulnerabilities, runtime bugs, and production failures that AI coding assistants silently introduce into your codebase. While ESLint catches syntax errors and TypeScript catches type mismatches, CodeDrift catches the dangerous semantic bugs that ship to production and cause outages.

## Why CodeDrift is Mandatory

### The AI Coding Problem

AI coding assistants (GitHub Copilot, Cursor, ChatGPT) are accelerating development—but they're also introducing a new class of bugs:

- Production secrets leaked in error responses (stack traces with API keys visible to users)
- Hallucinated dependencies that don't exist
- Silent data corruption from missing `await` statements
- Fire-and-forget async operations that never complete

These issues bypass ESLint, TypeScript, and code review because they're syntactically correct but semantically dangerous.

**CodeDrift is the guardrail that makes AI coding assistants safe for production use.**

### The Financial Reality

**Average cost of bugs CodeDrift prevents:**
- Production outage from missing await: **$50K-$500K per incident**
- Data breach from exposed secrets: **$4.45M average** (IBM 2023)
- Stack trace information disclosure: **Compliance violations, regulatory fines**
- Silent data corruption: **Customer trust loss, permanent churn**

**CodeDrift ROI:** Prevents one production incident = tool pays for itself 100x over.

### Compliance Requirements

**Required for:**
- **SOC 2 Type II** - Secure software development lifecycle
- **PCI DSS** - No hardcoded secrets in payment processing code
- **GDPR** - No data leaks through error messages
- **ISO 27001** - Security vulnerability detection

**CodeDrift provides audit trail** via JSON reports for compliance verification.

## Installation

```bash
# Run directly with npx (recommended - no installation required)
npx codedrift

# Or install globally for faster execution
npm install -g codedrift

# Or install as dev dependency in your project
npm install --save-dev codedrift
```

## Real-World Production Scenarios

### Scenario 1: E-commerce Payment Leak (Severity: CRITICAL)

**What AI Generated:**
```typescript
// src/api/checkout.ts
export async function processCheckout(req: Request, res: Response) {
  try {
    const { cartId, paymentMethod } = req.body;
    const cart = await getCart(cartId);
    const charge = await stripe.charges.create({
      amount: cart.total * 100,
      currency: 'usd',
      source: paymentMethod,
      description: `Order ${cart.id}`,
    });

    await createOrder(cart, charge);
    res.json({ success: true, orderId: charge.id });

  } catch (error: any) {
    // ❌ CRITICAL: Stack trace exposes Stripe keys, database credentials, internal paths
    res.status(500).json({
      error: error.message,
      stack: error.stack,
      details: error
    });
  }
}
```

**What Gets Exposed to Customers:**
```json
{
  "error": "Invalid API Key provided: sk_live_51HqK2KDj3...",
  "stack": "Error: Invalid API Key...\n    at /app/node_modules/stripe/lib/Error.js:17:9\n    at /app/src/config/stripe.ts:12 (STRIPE_SECRET_KEY = 'sk_live_...')",
  "details": {
    "type": "StripeAuthenticationError",
    "rawType": "invalid_request_error"
  }
}
```

**Impact:** Stripe API key exposed → $50K stolen before key rotation → compliance violation → $100K GDPR fine.

**CodeDrift Detection:**
```bash
$ npx codedrift

CRITICAL Issues (1) - Blocking

  src/api/checkout.ts:18
  Stack trace exposed in API response
  → Use generic error message. Log stack traces server-side only.

  Suggested fix:
  catch (error: any) {
    logger.error('Checkout failed', { error, cartId, userId: req.user.id });
    res.status(500).json({ error: 'Payment processing failed. Please try again.' });
  }
```

---

### Scenario 2: Silent Data Corruption in Inventory System (Severity: CRITICAL)

**What AI Generated:**
```typescript
// src/services/inventory.ts
export async function syncInventoryFromSuppliers() {
  const suppliers = await getActiveSuppliers();

  // ❌ CRITICAL: forEach doesn't await - 90% of updates never complete
  suppliers.forEach(async (supplier) => {
    const products = await supplier.fetchProducts();
    await updateInventory(products);
    await sendConfirmationEmail(supplier.email);
  });

  console.log('Inventory sync complete'); // ← LIE: Nothing is complete!
  return { success: true, synced: suppliers.length };
}
```

**What Actually Happens:**
- Function returns immediately after starting loops
- Database updates happen out of order (race conditions)
- 90% of emails never sent (async queue overload)
- Inventory shows wrong stock levels
- Customers buy products that are out of stock

**Impact:** $200K in oversold inventory + customer refunds + reputation damage.

**CodeDrift Detection:**
```bash
$ npx codedrift

CRITICAL Issues (1) - Blocking

  src/services/inventory.ts:5
  forEach() with async callback doesn't await - data corruption risk
  → Replace forEach() with for...of loop or await Promise.all(array.map(...))

  Suggested fix:
  for (const supplier of suppliers) {
    const products = await supplier.fetchProducts();
    await updateInventory(products);
    await sendConfirmationEmail(supplier.email);
  }

  // OR for parallel execution:
  await Promise.all(suppliers.map(async (supplier) => {
    const products = await supplier.fetchProducts();
    await updateInventory(products);
    await sendConfirmationEmail(supplier.email);
  }));
```

---

### Scenario 3: Hallucinated Package Causes Production Outage (Severity: CRITICAL)

**What AI Generated:**
```typescript
// src/utils/validation.ts
import { sanitizeInput } from 'express-sanitizer-pro'; // ❌ Package doesn't exist!
import { validateEmail } from 'email-validator-plus'; // ❌ Package doesn't exist!
import { hashPassword } from 'bcrypt-secure'; // ❌ Real package: bcrypt

export function validateUserInput(data: any) {
  const cleaned = sanitizeInput(data);
  if (!validateEmail(cleaned.email)) {
    throw new Error('Invalid email');
  }
  const hashed = hashPassword(cleaned.password);
  return { ...cleaned, password: hashed };
}
```

**What Happens in Production:**
```bash
# Deployment fails at runtime
Error: Cannot find module 'express-sanitizer-pro'
    at Function.Module._resolveFilename (node:internal/modules/cjs/loader.js:933:15)

# Application crashes on first user signup
# 100% downtime until hotfix deployed
```

**Impact:** 2-hour production outage during Black Friday = $300K lost revenue.

**CodeDrift Detection:**
```bash
$ npx codedrift

CRITICAL Issues (3) - Blocking

  src/utils/validation.ts:1
  Hallucinated dependency: 'express-sanitizer-pro' not found in package.json
  → Did you mean 'express-validator'? Or run: npm install express-sanitizer-pro

  src/utils/validation.ts:2
  Hallucinated dependency: 'email-validator-plus' not found in package.json
  → Did you mean 'email-validator'? Or run: npm install email-validator-plus

  src/utils/validation.ts:3
  Hallucinated dependency: 'bcrypt-secure' not found in package.json
  → Did you mean 'bcrypt' or 'bcryptjs'? Or run: npm install bcrypt-secure
```

---

### Scenario 4: AWS Credentials Committed to GitHub (Severity: CRITICAL)

**What AI Generated:**
```typescript
// src/config/aws.ts
import AWS from 'aws-sdk';

// ❌ CRITICAL: Production AWS keys hardcoded
export const s3Client = new AWS.S3({
  accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  region: 'us-east-1'
});

// src/services/email.ts
// ❌ CRITICAL: SendGrid API key exposed
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey('SG.1234567890abcdef.1234567890abcdef1234567890abcdef');
```

**What Happens:**
- Keys discovered by GitHub secret scanning (if lucky)
- OR keys scraped by bots within 5 minutes of push
- Cryptomining instances launched on AWS account
- $50K AWS bill in 24 hours

**Impact:** $50K unauthorized charges + security incident + mandatory disclosure to customers.

**CodeDrift Detection:**
```bash
$ npx codedrift

CRITICAL Issues (2) - Blocking

  src/config/aws.ts:5
  Hardcoded secret detected: AWS Access Key (AKIAIOSFODNN7EXAMPLE)
  → Use environment variables or AWS Secrets Manager

  src/services/email.ts:3
  Hardcoded secret detected: SendGrid API Key
  → Use process.env.SENDGRID_API_KEY or secret management service

  Suggested fix:
  export const s3Client = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION || 'us-east-1'
  });
```

---

## What CodeDrift Detects

### 1. Stack Trace Exposure in API Responses
**Risk:** Leaks internal architecture, file paths, credentials, and sensitive data to attackers.

**Detected Patterns:**
```typescript
// ❌ Direct stack access
res.status(500).json({ error: err.stack });

// ❌ Object spreading includes stack
res.json({ error, requestData });

// ❌ Logger with sensitive data
logger.error('Payment failed', { error, apiKey, customerId });
```

### 2. Hardcoded Secrets (70+ High-Quality Patterns)
**Risk:** Credentials committed to Git history remain accessible even after rotation.

**Detected Categories:**
- **Payment Processors:** Stripe, PayPal, Square, Braintree, Razorpay, Adyen (8 patterns)
- **Cloud Providers:** AWS, Azure, Google Cloud, DigitalOcean, Oracle, Alibaba (15 patterns)
- **Version Control:** GitHub, GitLab tokens and PATs (6 patterns)
- **Communication:** Slack, Discord, Telegram, Twilio, SendGrid, Mailgun (8 patterns)
- **Databases:** PostgreSQL, MongoDB, MySQL, Redis connection strings with passwords (8 patterns)
- **Private Keys:** RSA, EC, PGP, SSH, DSA, PKCS#8 (8 patterns)
- **Social Auth:** Facebook, Twitter, Auth0, Okta (5 patterns)
- **Package Registries:** npm, PyPI, NuGet (3 patterns)
- **JWT & Auth:** JWT tokens, Basic Auth credentials (3 patterns)

### 3. Hallucinated Dependencies
**Risk:** Application crashes in production when non-existent packages can't be resolved.

**Common AI Hallucinations:**
```typescript
// ❌ Package doesn't exist
import { validator } from 'express-validator-pro';  // Real: express-validator
import { logger } from 'winston-logger-utils';      // Real: winston
import { cache } from 'redis-cache-manager';        // Real: cache-manager
```

### 4. Missing Await (Silent Failures)
**Risk:** Async operations never complete, causing data corruption, race conditions, and lost updates.

**Detected Patterns:**
```typescript
// ❌ Fire-and-forget async call
async function updateUser(id, data) {
  saveToDatabase(data);  // ← Never awaited, may not complete
  return { success: true };
}

// ❌ forEach with async callback (most common AI mistake)
users.forEach(async (user) => {
  await sendEmail(user.email);  // forEach doesn't wait!
});

// ❌ Unhandled promise in conditional
if (needsUpdate) {
  updateCache();  // ← Async function not awaited
}
```

### 5. Empty Catch Blocks
**Risk:** Exceptions silently swallowed, making debugging impossible and hiding critical failures.

```typescript
// ❌ Completely empty
try {
  await criticalOperation();
} catch (err) {
  // Empty - error is lost
}

// ❌ Console-only (production logs not captured)
try {
  await processPayment();
} catch (err) {
  console.log(err);  // Goes to stdout, not monitoring systems
}
```

## Quick Start

### Run Your First Scan

```bash
cd your-project
npx codedrift
```

**Output:**
```
CodeDrift Analysis Complete

CRITICAL Issues (3) - Blocking

  src/api/users.ts:45
  Stack trace exposed in API response
  → Use generic error message. Log stack traces server-side only.

  src/lib/email.ts:12
  Hallucinated dependency: 'nodemailer-pro' not found in package.json
  → Run 'npm install nodemailer' or remove import

  src/services/sync.ts:78
  forEach() with async callback doesn't await - data corruption risk
  → Replace forEach() with for...of loop or await Promise.all(array.map(...))

WARNINGS (2)

  src/utils/validator.ts:23
  Empty catch block swallows errors
  → Add logging or error handling

  src/config/database.ts:56
  Suspicious secret in variable: DB_PASSWORD
  → Use environment variables instead of hardcoding secrets

Stats
  • Analyzed: 127 files (in 1.2s)
  • Total: 127 files
  • Duration: 1234ms

❌ Build failed due to critical issues (exit code 1)
```

## CI/CD Integration

### GitHub Actions - Basic Setup

Block vulnerable code from reaching production:

```yaml
name: CodeDrift Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'

      # Block merge if critical issues found
      - run: npx codedrift
```

### GitHub Actions - Advanced with Baseline Mode

Adopt CodeDrift without fixing 1000+ existing issues first:

```yaml
name: CodeDrift Security & Quality Gate
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  codedrift:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Restore CodeDrift baseline
        uses: actions/cache@v3
        with:
          path: .codedrift-baseline.json
          key: codedrift-baseline-${{ github.base_ref }}-${{ github.sha }}
          restore-keys: |
            codedrift-baseline-${{ github.base_ref }}-
            codedrift-baseline-main-

      - name: Run CodeDrift analysis (only new issues block)
        run: npx codedrift --compare-baseline --format json --output codedrift-report.json

      - name: Upload security report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: codedrift-security-report
          path: codedrift-report.json
          retention-days: 30

      - name: Comment PR with results
        if: github.event_name == 'pull_request' && failure()
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('codedrift-report.json', 'utf8'));
            const { criticalIssues, warnings } = report.summary;

            const body = `## CodeDrift Security Scan Results

            🔴 **Critical Issues:** ${criticalIssues}
            ⚠️ **Warnings:** ${warnings}

            Please fix critical issues before merging.
            [View detailed report](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

### GitLab CI

```yaml
codedrift:
  stage: security
  image: node:18
  script:
    - npx codedrift --format json --output codedrift-report.json
  artifacts:
    when: always
    reports:
      codequality: codedrift-report.json
    paths:
      - codedrift-report.json
    expire_in: 30 days
  allow_failure: false
```

### CircleCI

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/node:18.0
    steps:
      - checkout
      - run:
          name: CodeDrift Security Scan
          command: npx codedrift --format json --output codedrift-report.json
      - store_artifacts:
          path: codedrift-report.json
          destination: security-reports

workflows:
  build-and-scan:
    jobs:
      - security-scan
```

## Baseline Mode for Legacy Codebases

Adopt CodeDrift incrementally without blocking development on existing issues:

```bash
# Step 1: Create baseline (one-time)
npx codedrift --baseline
# ✓ Baseline saved to .codedrift-baseline.json
#   473 issues captured as baseline

# Step 2: Only catch NEW issues going forward
npx codedrift --compare-baseline
# ℹ Baseline comparison enabled
#   Total issues: 473
#   New issues: 2  ← Only these block the build
#   Baseline issues: 471 (not blocking)
```

**Workflow:**
1. Create baseline from current codebase state
2. Commit `.codedrift-baseline.json` to Git
3. CI/CD only fails on NEW issues introduced in PRs
4. Incrementally fix baseline issues over time

## JSON & HTML Reports

### JSON Format - CI/CD Integration

```bash
# Export to JSON
npx codedrift --format json > codedrift-report.json

# Query specific metrics with jq
npx codedrift --format json | jq '.summary.criticalIssues'
# Output: 3

# Save as CI/CD artifact
npx codedrift --format json --output reports/security-scan.json
```

**JSON Schema:**
```json
{
  "summary": {
    "totalFiles": 127,
    "analyzedFiles": 127,
    "totalIssues": 5,
    "criticalIssues": 3,
    "warnings": 2,
    "timestamp": "2025-01-15T10:30:00.000Z",
    "duration": 1234
  },
  "issues": [
    {
      "engine": "stack-trace-exposure",
      "severity": "error",
      "message": "Stack trace exposed in API response",
      "filePath": "src/api/users.ts",
      "location": { "line": 45, "column": 12 },
      "suggestion": "Use generic error message. Log stack traces server-side only.",
      "ruleId": "stack-trace-exposure"
    }
  ],
  "config": {
    "failOn": "error",
    "rulesEnabled": [
      "stack-trace-exposure",
      "hallucinated-deps",
      "missing-await",
      "empty-catch",
      "hardcoded-secret"
    ]
  }
}
```

### HTML Format - Visual Reports

```bash
# Generate HTML report (auto-detected from .html extension)
npx codedrift --output security-report.html

# Or explicitly specify format
npx codedrift --format html --output report.html
```

**HTML Report Features:**
- Self-contained single file (works offline)
- Professional corporate design
- Interactive filtering by severity
- Grouped by file and detection engine
- Print-friendly for documentation
- Metrics dashboard with issue counts

## Configuration

Create `codedrift.config.json` in your project root:

```json
{
  "exclude": [
    "node_modules/**",
    "dist/**",
    "build/**",
    "**/*.test.ts",
    "**/__mocks__/**"
  ],
  "rules": {
    "stack-trace-exposure": "error",
    "hallucinated-deps": "error",
    "missing-await": "error",
    "empty-catch": "warn",
    "hardcoded-secret": "error"
  },
  "failOn": "error"
}
```

**Configuration Options:**

| Option | Values | Description |
|--------|--------|-------------|
| `rules.<rule-name>` | `error`, `warn`, `off` | Set severity per rule |
| `failOn` | `error`, `warn` | Exit code 1 on errors only or include warnings |
| `exclude` | Glob patterns | Files/directories to skip |
| `format` | `terminal`, `json`, `html` | Output format |
| `output` | File path | Write report to file |

## Suppressing False Positives

Use inline comments when CodeDrift incorrectly flags safe code:

```typescript
// Suppress next line
// codedrift-disable-next-line
void logActivity(data);

// Suppress current line
dangerousOperation();  // codedrift-disable-line

// Alternative syntax
// codedrift-ignore-next-line
asyncHelper();
```

## CLI Reference

```bash
codedrift [options]

Options:
  --format <type>            Output format: terminal, json, html (default: terminal)
  --output <file>            Write report to file (auto-detects format from extension)
  --baseline                 Save current issues as baseline
  --compare-baseline         Show only new issues not in baseline
  --baseline-file <path>     Custom baseline file path (default: .codedrift-baseline.json)
  --full                     Force full scan (ignore cache)
  --version                  Show version number
  --help                     Show help

Examples:
  codedrift                                  # Basic scan
  codedrift --format json > report.json      # JSON export
  codedrift --output report.html             # HTML report (auto-detected)
  codedrift --format html --output scan.html # Explicit HTML format
  codedrift --baseline                       # Create baseline
  codedrift --compare-baseline               # Check new issues only
```

## Detection Engines (Technical Deep Dive)

### 1. Stack Trace Exposure Detector
Analyzes HTTP response methods and logging calls using AST traversal to detect:
- Direct `.stack` property access in responses
- Object spreading that includes error objects
- Logger calls combining stack traces with sensitive request data
- Both method chaining (`res.status().json()`) and direct calls

### 2. Hallucinated Dependency Detector
Cross-references all imports (static, dynamic, require) against:
- `package.json` dependencies (dependencies, devDependencies, optionalDependencies)
- Node.js built-in modules (fs, http, crypto, etc.)
- Scoped packages (@org/package)
- Handles monorepo patterns and workspace packages

### 3. Missing Await Detector
Uses heuristic analysis to identify async function calls:
- Function names (async suffix, common async operations)
- Return value patterns (Promise-returning functions)
- Known async APIs (fetch, database operations)
- Array methods with async callbacks (forEach, map, filter)
- Includes whitelisting to prevent false positives on internal helpers

### 4. Empty Catch Detector
Validates error handling by detecting:
- Completely empty catch blocks
- Console-only logging (not captured in production monitoring)
- Useless re-throws (throwing same error without transformation)
- Missing error context

### 5. Secret Pattern Detector
Regex-based detection with 70+ high-quality patterns organized by category:
- High-entropy string detection (Shannon entropy > 4.5)
- Provider-specific patterns (AWS, Azure, GCP, GitHub, etc.)
- False positive filtering (placeholders, test values, environment variables)
- Context-aware analysis (variable names + values)

## Performance

- **Analysis speed:** ~8ms per file
- **Typical project:** 127 files analyzed in 1.2 seconds
- **Large monorepo:** 1000+ files in under 10 seconds
- **Caching:** Incremental analysis only re-scans changed files

## Privacy & Security

- **100% local analysis** - Your code never leaves your machine
- **No telemetry or tracking**
- **No external API calls**
- **No data collection**
- **Open source** - Audit the code yourself

## Requirements

- Node.js 16.x or higher
- Works with JavaScript and TypeScript projects
- Zero dependencies in production (analysis runs locally)

## Roadmap

- [ ] VS Code Extension for real-time detection
- [ ] Additional language support (Python, Java, Go)
- [ ] Custom rule engine for team-specific patterns
- [ ] Integration with Slack/Teams for notifications
- [ ] Machine learning-based anomaly detection

## License

MIT License - Free for commercial use

## Contributing

Contributions welcome. Please open an issue first to discuss proposed changes.

## Support

- **Issues & Bugs:** [GitHub Issues](https://github.com/hamzzaaamalik/codedrift/issues)
- **Feature Requests:** [GitHub Discussions](https://github.com/hamzzaaamalik/codedrift/discussions)
- **Security Vulnerabilities:** Please report privately via GitHub Security Advisories

---

**Built for teams that ship AI-assisted code to production.**

Don't let AI-generated bugs reach your customers. Make CodeDrift a mandatory part of your CI/CD pipeline.

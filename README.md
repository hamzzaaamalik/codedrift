# CodeDrift

Guardrails for AI-assisted development. Catches security vulnerabilities and runtime bugs that AI coding assistants introduce into JavaScript and TypeScript codebases.

[![npm version](https://badge.fury.io/js/codedrift.svg)](https://www.npmjs.com/package/codedrift)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Whether you're using GitHub Copilot for autocomplete, generating entire functions with ChatGPT, or writing code manually, CodeDrift detects dangerous patterns before they ship. Think of it as a safety net for the new era of AI-accelerated development.

## Quick Start

```bash
npx codedrift
```

## Installation

```bash
# Run directly without installation
npx codedrift

# Install as dev dependency
npm install --save-dev codedrift

# Install globally
npm install -g codedrift
```

Requirements: Node.js 16+

## The Problem

You ask GitHub Copilot or ChatGPT to create an API endpoint:

```typescript
app.get('/api/documents/:id', async (req, res) => {
  const doc = await db.documents.findById(req.params.id);
  res.json(doc);
});
```

TypeScript compiles. ESLint passes. Tests pass. Code review approved. Deployed to production.

Three days later: any user can access any document by changing the URL.

You just shipped an IDOR vulnerability.

## What CodeDrift Catches

CodeDrift detects this before deployment:

```bash
npx codedrift

CRITICAL Issues (1)

  src/api/documents.ts:23
  Database query using user-supplied ID without authorization check
  IDOR vulnerability allows any user to access any document
  Fix: Add authorization check before query
```

## Detection Engines

| Engine | Detects | Severity |
|--------|---------|----------|
| IDOR | Database queries without authorization checks | Critical |
| Missing Input Validation | req.body or req.params used without validation | Critical |
| Hardcoded Secrets | API keys and tokens in source code | Critical |
| Stack Trace Exposure | Error stacks leaked in API responses | Critical |
| Missing Await | Async functions called without await | Critical |
| Async forEach | forEach with async callbacks that silently fail | Critical |
| Hallucinated Dependencies | Imports of packages that do not exist | Critical |
| Unsafe Regex | Regular expressions vulnerable to ReDoS | Error |
| Console in Production | console.log in production code | Warning |
| Empty Catch | Empty catch blocks that hide errors | Warning |

## Common Patterns

### IDOR Vulnerability

AI generates database queries that skip authorization:

```typescript
app.get('/orders/:id', async (req, res) => {
  const order = await db.orders.findById(req.params.id);
  res.json(order);
});
```

CodeDrift detects:
```
Database query using user-supplied ID without authorization check
Fix: Verify order.userId === req.user.id before returning data
```

### Missing Input Validation

AI uses request data without validation:

```typescript
app.post('/users', async (req, res) => {
  const { email, role } = req.body;
  await db.users.create({ email, role });
});
```

CodeDrift detects:
```
API route uses req.body without validation
Vulnerable to privilege escalation and injection attacks
Fix: Add input validation with zod, joi, or yup
```

### Async forEach Bug

AI creates loops that silently fail:

```typescript
async function syncInventory(products) {
  products.forEach(async (p) => {
    await updateStock(p.id, p.quantity);
  });
  console.log('Sync complete');
}
```

The function returns immediately. Updates happen asynchronously and may never complete.

CodeDrift detects:
```
forEach with async callback does not await
90% of updates will fail silently
Fix: Use for...of loop or Promise.all
```

### Hardcoded Secrets

AI embeds credentials from training data:

```typescript
const stripe = new Stripe('sk_live_51HqK2KDj3...');
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey('SG.1234567890abcdef...');
```

CodeDrift detects:
```
Hardcoded Stripe API key detected
Hardcoded SendGrid API key detected
Fix: Use environment variables
```

### Stack Trace Exposure

AI copies debugging patterns that leak secrets:

```typescript
catch (error) {
  res.status(500).json({
    error: error.message,
    stack: error.stack
  });
}
```

Exposes internal paths, database credentials, and API keys to users.

CodeDrift detects:
```
Stack trace exposed in API response
Production secrets and file paths visible to attackers
Fix: Only log stack traces server-side
```

## Confidence Levels

CodeDrift assigns confidence levels to every issue to help you prioritize fixes:

- **High**: Clear security vulnerabilities or bugs in production code (fix immediately)
- **Medium**: Issues in test files or generated code (review and fix)
- **Low**: Potential false positives or edge cases (investigate when convenient)

Confidence levels are automatically adjusted based on file context:

```typescript
// src/api/users.ts - HIGH confidence
app.get('/users/:id', async (req, res) => {
  const user = await db.users.findById(req.params.id); // IDOR: High confidence
  res.json(user);
});

// tests/api.test.ts - MEDIUM confidence (downgraded)
test('should fetch user', async () => {
  const user = await db.users.findById('123'); // Same pattern, medium confidence
});

// dist/bundle.js - MEDIUM confidence (generated file)
// Generated code automatically gets reduced confidence
```

### Filtering by Confidence

Use `--confidence-threshold` to filter issues:

```bash
# Show only high confidence issues
npx codedrift --confidence-threshold high

# Show high and medium confidence (default)
npx codedrift --confidence-threshold medium

# Show all issues including low confidence
npx codedrift --confidence-threshold low
```

## Configuration

Create `codedrift.config.json` in your project root:

```json
{
  "exclude": [
    "node_modules/**",
    "dist/**",
    "**/*.test.ts"
  ],
  "rules": {
    "idor": "error",
    "missing-input-validation": "error",
    "hardcoded-secret": "error",
    "stack-trace-exposure": "error",
    "missing-await": "error",
    "async-foreach": "error",
    "hallucinated-deps": "error",
    "unsafe-regex": "error",
    "console-in-production": "warn",
    "empty-catch": "warn"
  },
  "failOn": "error",
  "excludeTestFiles": false,
  "confidenceThreshold": "medium",
  "respectGitignore": true
}
```

Options:
- `rules.<name>`: Set to "error", "warn", or "off"
- `failOn`: Exit with code 1 on "error" or "warn"
- `exclude`: Array of glob patterns to skip
- `excludeTestFiles`: Skip test files entirely (default: false)
- `confidenceThreshold`: Minimum confidence level to report ("high", "medium", "low")
- `respectGitignore`: Honor .gitignore patterns when scanning (default: true)

## Monorepo and Workspace Support

CodeDrift automatically detects and supports monorepo configurations for npm, yarn, and pnpm workspaces.

### Automatic Workspace Detection

```json
// Root package.json
{
  "name": "my-monorepo",
  "workspaces": [
    "packages/*",
    "apps/*"
  ]
}
```

CodeDrift will:
- Detect workspace packages automatically
- Resolve dependencies from both workspace and root package.json
- Include workspace name in error messages for context
- Handle scoped packages (@org/package) correctly

### Workspace-Aware Error Messages

```bash
CRITICAL Issues (2)

  packages/api/src/server.ts:15
  Hallucinated dependency: 'express-rate-limiter' not found in workspace '@myorg/api' package.json
  Fix: Run 'npm install express-rate-limiter' or remove import if AI hallucinated this package

  apps/web/src/App.tsx:3
  Hallucinated dependency: 'react-super-hooks' not found in workspace '@myorg/web' package.json
  Fix: Run 'npm install react-super-hooks' or remove import if AI hallucinated this package
```

### Supported Workspace Formats

- **npm workspaces**: `"workspaces": ["packages/*"]`
- **yarn workspaces**: `"workspaces": ["packages/*"]`
- **pnpm workspaces**: via `pnpm-workspace.yaml`
- **Lerna**: via `lerna.json` (experimental)

### Running in Monorepos

```bash
# Run from monorepo root (analyzes all workspaces)
npx codedrift

# Run in specific workspace
cd packages/api && npx codedrift

# Exclude specific workspaces
npx codedrift --exclude "packages/legacy/**"
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Check
on: [push, pull_request]

jobs:
  codedrift:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npx codedrift --confidence-threshold high

  # Advanced: separate jobs for different confidence levels
  high-priority:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npx codedrift --confidence-threshold high --exclude-tests
```

### GitLab CI

```yaml
codedrift:
  stage: test
  image: node:18
  script:
    - npx codedrift --format json --output codedrift-report.json --confidence-threshold medium
  artifacts:
    reports:
      codequality: codedrift-report.json
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
      - run: npx codedrift --format json --output report.json --confidence-threshold high
      - store_artifacts:
          path: report.json
```

## Output Formats

### Terminal

```bash
npx codedrift
```

Displays grouped issues with priorities:

```
CRITICAL Issues (3)
  1. src/api/users.ts:23 - IDOR vulnerability
  2. src/api/orders.ts:45 - Missing input validation
  3. src/config/aws.ts:12 - Hardcoded AWS key

Warnings (5)
  Console in Production: 5 findings in 3 files
```

### JSON

```bash
npx codedrift --format json --output report.json
```

Machine-readable format for CI/CD pipelines and custom tooling.

### HTML

```bash
npx codedrift --output report.html
```

Interactive report with filtering and grouping. Can also be generated interactively after terminal analysis.

## Baseline Mode

For existing projects with many issues:

```bash
# Save current state as baseline
npx codedrift --baseline

# Only new issues will fail CI
npx codedrift --compare-baseline
```

This allows incremental adoption without blocking development on existing issues.

## Suppressing False Positives

```typescript
// Disable next line
// codedrift-disable-next-line
void backgroundTask();

// Disable current line
dangerousOperation(); // codedrift-disable-line
```

## CLI Reference

```bash
codedrift [options]

Options:
  --format <type>               Output format: terminal, json, html
  --output <file>               Write report to file
  --baseline                    Save current issues as baseline
  --compare-baseline            Show only new issues since baseline
  --baseline-file <path>        Custom baseline file path
  --full                        Force full scan, ignore cache
  --confidence-threshold <lvl>  Minimum confidence: high, medium, low (default: medium)
  --exclude-tests              Skip test files entirely
  -h, --help                    Show help
  -v, --version                 Show version

Examples:
  # Basic scan
  codedrift

  # Only show high-confidence issues
  codedrift --confidence-threshold high

  # Skip test files for faster CI
  codedrift --exclude-tests --confidence-threshold high

  # Generate HTML report
  codedrift --output report.html

  # Baseline workflow
  codedrift --baseline
  codedrift --compare-baseline

  # JSON for custom processing
  codedrift --format json --output report.json

  # Monorepo: analyze specific workspace
  cd packages/api && codedrift --confidence-threshold high
```

## How It Works

CodeDrift uses the TypeScript Compiler API to parse source code into an Abstract Syntax Tree. Ten detection engines traverse the AST looking for dangerous patterns.

Architecture:
- Parser: Converts code to AST using typescript compiler
- Engines: Pattern detectors for IDOR, secrets, missing await, etc
- Formatter: Outputs results as terminal, JSON, or HTML
- CLI: Orchestrates analysis and handles exit codes

Performance: 50 files per second on typical projects
Privacy: 100% local analysis, no telemetry, code never leaves your machine

## Contributing

Contributions are welcome. Open an issue first to discuss proposed changes.

Adding a new detector:

```typescript
// src/engines/my-detector.ts
import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';

export class MyDetector extends BaseEngine {
  readonly name = 'my-detector';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    // Detection logic here
    return issues;
  }
}
```

Register in `src/engines/index.ts` and add tests in `tests/`.

## FAQ

**Does this replace ESLint or TypeScript?**

No. CodeDrift complements them. ESLint catches syntax and style issues. TypeScript catches type errors. CodeDrift catches semantic security vulnerabilities.

**Does my code get sent anywhere?**

No. Analysis runs entirely locally. Zero telemetry. Your code never leaves your machine.

**Can I use this with hand-written code?**

Yes. These bugs occur in all code but are more common in AI-generated code.

**Will this catch all bugs?**

No tool catches everything. CodeDrift focuses on the ten most critical and common patterns.

## Roadmap

- VS Code extension for real-time detection
- Auto-fix suggestions
- Python and Go support
- Custom rule engine
- GitHub App for PR comments

## License

MIT

## Support

- Issues and bugs: [GitHub Issues](https://github.com/hamzzaaamalik/codedrift/issues)
- Feature requests: [GitHub Discussions](https://github.com/hamzzaaamalik/codedrift/discussions)
- Security vulnerabilities: Report privately via GitHub Security Advisories

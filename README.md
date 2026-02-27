# CodeDrift

**AI Refactoring Guardrail for JavaScript and TypeScript**

CodeDrift is a static analysis tool that detects AI-induced bugs, security vulnerabilities, and anti-patterns that traditional linters miss. Designed for development teams using AI coding assistants like GitHub Copilot, Cursor, and ChatGPT.

## Installation

```bash
# Run directly with npx (recommended)
npx codedrift

# Or install globally
npm install -g codedrift
codedrift
```

## What CodeDrift Detects

### Critical Issues

**Stack Trace Exposure**
Prevents leaking internal error details and stack traces in HTTP responses, a common security vulnerability introduced by AI assistants.

**Hallucinated Dependencies**
Detects imports from non-existent npm packages. AI models frequently suggest packages that don't exist (observed in ~20% of AI-generated code).

**Missing Await**
Identifies fire-and-forget async function calls that should be awaited, including the common `.forEach()` with async callback mistake.

**Hardcoded Secrets**
Finds API keys, tokens, passwords, and credentials hardcoded in source files. Detects 19+ secret patterns including Stripe, AWS, GitHub, JWT, and more.

### Warnings

**Empty Catch Blocks**
Flags error handling blocks that silently swallow exceptions without logging or recovery.

**Async forEach**
Detects `.forEach()`, `.map()`, and `.filter()` called with async callbacks, which don't properly await execution.

## Configuration

Create a `codedrift.config.json` file in your project root:

```json
{
  "exclude": [
    "node_modules/**",
    "dist/**",
    "**/*.test.ts"
  ],
  "rules": {
    "stack-trace-exposure": "error",
    "hallucinated-deps": "error",
    "missing-await": "warn",
    "empty-catch": "warn",
    "hardcoded-secret": "error"
  },
  "failOn": "error"
}
```

### Configuration Options

**Rule Levels**
- `error` - Critical issue, blocks build with exit code 1
- `warn` - Warning, reported but doesn't block build
- `off` - Rule disabled

**Fail Behavior**
- `failOn: "error"` - Exit code 1 only on critical errors (default)
- `failOn: "warn"` - Exit code 1 on warnings and errors

**Exclude Patterns**
Glob patterns for files and directories to skip during analysis.

## Suppressing False Positives

Use inline comments to suppress specific detections:

```typescript
// Disable detection for the next line
// codedrift-disable-next-line
void logActivity(data);

// Disable detection for the current line
dangerousOperation();  // codedrift-disable-line
```

## Example Output

```
CodeDrift Analysis Complete

CRITICAL Issues (2) - Blocking

  src/api/users.ts:45
  Stack trace exposed in API response
  → Use generic error message. Log stack traces server-side only.

  src/lib/email.ts:12
  Hallucinated dependency: 'nodemailer-pro' not found in package.json
  → Run 'npm install nodemailer-pro' or remove import

Stats
  • Analyzed: 127 files
  • Total: 127 files

Build failed due to critical issues (exit code 1)
```

## Why CodeDrift?

Traditional static analysis tools (ESLint, TypeScript, SonarJS) excel at catching syntax errors, type mismatches, and code style issues. However, they cannot detect semantic bugs and anti-patterns commonly introduced by AI code generation:

- ESLint validates syntax and style, not runtime behavior
- TypeScript checks types, not logical correctness
- SonarJS detects general code smells, not AI-specific patterns

CodeDrift fills this gap by focusing specifically on patterns that AI assistants frequently introduce:

- Security vulnerabilities (exposed stack traces, hardcoded secrets)
- Runtime bugs (missing await, fire-and-forget async)
- Hallucinated dependencies and imports
- Error handling anti-patterns

**Privacy-First Design**
All analysis runs locally. Your code never leaves your machine.

**Performance**
Analyzes approximately 8ms per file. Typical projects complete in under 2 seconds.

**Zero Configuration**
Works out of the box with sensible defaults. Configuration optional.

## CI/CD Integration

### GitHub Actions

```yaml
name: CodeDrift Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npx codedrift
```

### GitLab CI

```yaml
codedrift:
  image: node:18
  script:
    - npx codedrift
```

CodeDrift exits with code 1 when critical issues are detected, automatically failing CI/CD pipelines.

## Detection Engines

1. **Stack Trace Exposure Detector**
   Analyzes HTTP response methods (`res.json()`, `res.send()`) and logging calls to prevent stack trace leaks. Detects both direct `.stack` access and object spreading patterns.

2. **Hallucinated Dependency Detector**
   Cross-references all import statements with `package.json` dependencies and Node.js built-in modules. Handles scoped packages and dynamic imports.

3. **Missing Await Detector**
   Uses heuristic analysis to identify async function calls without proper awaiting. Includes special detection for array methods with async callbacks.

4. **Empty Catch Detector**
   Identifies try-catch blocks with empty bodies, console-only logging, or useless re-throws. Validates proper error handling patterns.

5. **Secret Pattern Detector**
   Regex-based detection of hardcoded credentials. Recognizes API keys, tokens, private keys, and connection strings. Filters out placeholders and test values.

## Development

```bash
# Install dependencies
npm install

# Build from source
npm run build

# Run tests
npm test

# Run in development mode
npm run dev
```

## Requirements

- Node.js 16.x or higher
- TypeScript 5.x or higher (for TypeScript projects)

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting pull requests.

## Support

Report bugs and request features at: https://github.com/hamzzaaamalik/codedrift/issues

---

Built for development teams using AI coding assistants.

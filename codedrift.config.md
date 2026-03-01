# CodeDrift Configuration Guide

This document explains all available configuration options for `codedrift.config.json`.

## Complete Configuration Example

```json
{
  "$schema": "https://json-schema.org/draft-07/schema#",

  "exclude": [
    "node_modules/**",
    "dist/**",
    "build/**",
    "coverage/**",
    "**/*.test.ts",
    "**/*.spec.ts",
    "__tests__/**",
    ".next/**",
    "__generated__/**"
  ],

  "rules": {
    "stack-trace-exposure": "error",
    "hallucinated-deps": "error",
    "missing-await": "error",
    "async-foreach": "error",
    "empty-catch": "warn",
    "hardcoded-secret": "error",
    "unsafe-regex": "error",
    "console-in-production": "warn",
    "missing-input-validation": "error",
    "idor": "error"
  },

  "failOn": "error",
  "excludeTestFiles": false,
  "confidenceThreshold": "medium",
  "respectGitignore": true,

  "cache": {
    "enabled": true,
    "ttl": 86400000
  },

  "format": "terminal",
  "output": null
}
```

## Configuration Options

### `exclude` (array of strings)

Glob patterns to exclude from analysis. Common patterns:

- `node_modules/**` - Dependencies
- `dist/**`, `build/**` - Build output
- `**/*.test.ts` - Test files
- `coverage/**` - Coverage reports
- `.next/**`, `out/**` - Framework build directories
- `__generated__/**` - Auto-generated code

**Default**: `[]`

### `rules` (object)

Enable or disable specific detection engines:

#### Rule Levels
- `"error"` - Fail CI/CD on this rule
- `"warn"` - Report but don't fail
- `"off"` - Disable detection

#### Available Rules

| Rule | Default | Description |
|------|---------|-------------|
| `idor` | `error` | Insecure Direct Object Reference vulnerabilities |
| `missing-input-validation` | `error` | API endpoints without input validation |
| `hardcoded-secret` | `error` | API keys and tokens in source code |
| `stack-trace-exposure` | `error` | Error stacks leaked in responses |
| `missing-await` | `error` | Async calls without await |
| `async-foreach` | `error` | forEach with async callbacks |
| `hallucinated-deps` | `error` | Imports of non-existent packages |
| `unsafe-regex` | `error` | ReDoS-vulnerable regular expressions |
| `console-in-production` | `warn` | console.log in production code |
| `empty-catch` | `warn` | Empty catch blocks |

### `failOn` (string)

Exit with code 1 when issues of this severity or higher are found.

**Options**: `"error"`, `"warn"`

**Default**: `"error"`

**Examples**:
- `"error"` - Fail only on error-level issues
- `"warn"` - Fail on both warnings and errors

### `excludeTestFiles` (boolean)

Skip test files entirely from analysis.

**Default**: `false`

**Use case**: Speed up CI by only analyzing production code

**Example**:
```json
{
  "excludeTestFiles": true
}
```

Test file patterns detected:
- `*.test.ts`, `*.spec.ts`
- `__tests__/**`
- `tests/**`, `test/**`
- `*.e2e.ts`, `*.integration.test.ts`

### `confidenceThreshold` (string)

Minimum confidence level to report.

**Options**: `"high"`, `"medium"`, `"low"`

**Default**: `"medium"`

**Confidence Levels**:
- `high` - Only show definite bugs (production code)
- `medium` - Include test files and generated code
- `low` - Show all findings including edge cases

**Example for CI**:
```json
{
  "confidenceThreshold": "high"
}
```

### `respectGitignore` (boolean)

Honor `.gitignore` patterns when scanning files.

**Default**: `true`

**Use case**: Automatically exclude files already ignored by git

**Example**:
```json
{
  "respectGitignore": true
}
```

### `cache` (object)

Control caching behavior for faster subsequent scans.

**Options**:
- `enabled` (boolean) - Enable/disable caching (default: `true`)
- `ttl` (number) - Cache time-to-live in milliseconds (default: `86400000` = 24 hours)

**Example**:
```json
{
  "cache": {
    "enabled": true,
    "ttl": 3600000
  }
}
```

Set `enabled: false` to force fresh analysis every time.

### `format` (string)

Output format.

**Options**: `"terminal"`, `"json"`, `"html"`

**Default**: `"terminal"`

**Use cases**:
- `terminal` - Human-readable CLI output
- `json` - Machine-readable for CI/CD
- `html` - Interactive browser report

### `output` (string | null)

Write report to a file instead of stdout.

**Default**: `null`

**Examples**:
```json
{
  "format": "html",
  "output": "codedrift-report.html"
}
```

```json
{
  "format": "json",
  "output": "reports/codedrift.json"
}
```

## Use Case Examples

### Strict CI Configuration

```json
{
  "failOn": "error",
  "confidenceThreshold": "high",
  "excludeTestFiles": true,
  "cache": {
    "enabled": false
  }
}
```

### Development Configuration

```json
{
  "failOn": "warn",
  "confidenceThreshold": "medium",
  "excludeTestFiles": false
}
```

### Monorepo Configuration

```json
{
  "exclude": [
    "node_modules/**",
    "packages/legacy/**",
    "apps/deprecated/**"
  ],
  "respectGitignore": true
}
```

### Performance-Optimized Configuration

```json
{
  "excludeTestFiles": true,
  "exclude": [
    "node_modules/**",
    "dist/**",
    "**/*.d.ts"
  ],
  "cache": {
    "enabled": true,
    "ttl": 86400000
  }
}
```

## Environment-Specific Configuration

You can use different configs for different environments:

```bash
# CI
npx codedrift --config codedrift.ci.json

# Development
npx codedrift --config codedrift.dev.json
```

## Schema Validation

Add `$schema` field for IDE autocomplete and validation:

```json
{
  "$schema": "https://json-schema.org/draft-07/schema#"
}
```

This enables IntelliSense in VS Code and other editors.

/**
 * Example outputs for each formatter mode
 *
 * These examples demonstrate the different output formats available in CodeDrift.
 */

/**
 * SUMMARY FORMAT (Default)
 * Concise, actionable output with top 5 issues
 *
 * Example:
 *
 * 🔍 Analyzing 1,234 files...
 *
 * 📊 Analysis Complete
 *
 *   🔴 Critical Issues:        89    ← Fix these first!
 *   🟠 High Severity:         456
 *   🟡 Medium Severity:     1,234
 *   🔵 Low Severity:        2,341
 *   ────────────────────────────
 *   Total:                 4,120 (high confidence only)
 *
 * 🎯 Top 5 Issues to Fix:
 *
 *   1.  🔴 Hardcoded Secrets (src/config/aws.ts:42)
 *       AWS access key detected in source code
 *   2.  🔴 Insecure Direct Object Reference (src/api/users.ts:156)
 *       User ID parameter not validated against authenticated user
 *   3.  🟠 Missing Await (src/db/queries.ts:234)
 *       Promise not awaited, may cause race condition
 *   4.  🟠 Stack Trace Exposure (src/errors/handler.ts:67)
 *       Stack trace sent in production error response
 *   5.  🟡 Console in Production (src/index.ts:12)
 *       console.log may leak sensitive data
 *
 * 💡 Run with --details to see all issues
 * 📄 HTML report: codedrift-report.html
 *
 * Analyzed 1,234 files in 2.45s (503 files/sec)
 */

/**
 * DETAILED FORMAT (--details or --verbose)
 * Full issue details with code context
 *
 * Example:
 *
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *   CodeDrift Analysis - Detailed Report
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Summary:
 *   Total Issues: 4,120
 *   Critical: 89  Warnings: 4,031
 *   Files Analyzed: 1,234/1,250
 *
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * 🔴 CRITICAL • Hardcoded AWS Secret Key
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 *   File:       src/config/aws.ts:42:15
 *   Engine:     hardcoded-secret
 *   Confidence: ⭐⭐⭐ High
 *
 *   AWS access key pattern detected in source code
 *
 *      39 |
 *      40 | export const awsConfig = {
 *      41 |   region: 'us-east-1',
 *      42 |   accessKeyId: "AKIAIOSFODNN7EXAMPLE",
 *                         ^^^^^^^^^^^^^^^^^^^^^^^
 *      43 |   secretAccessKey: process.env.AWS_SECRET,
 *      44 | };
 *
 *   💡 Suggestion:
 *      Move to environment variable:
 *      accessKeyId: process.env.AWS_ACCESS_KEY
 *
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 */

/**
 * COMPACT FORMAT (--format compact or default in CI)
 * One line per issue, CI-friendly
 *
 * Example:
 *
 * src/config/aws.ts:42:15 - [hardcoded-secret] error: AWS access key pattern detected in source code
 * src/api/users.ts:156:23 - [idor] error: User ID parameter not validated against authenticated user
 * src/db/queries.ts:234:12 - [missing-await] warning: Promise not awaited, may cause race condition
 * src/errors/handler.ts:67:5 - [stack-trace-exposure] warning: Stack trace sent in production error response
 * src/index.ts:12:1 - [console-in-production] warning: console.log may leak sensitive data in production
 */

/**
 * GROUPED BY FILE (--group-by file)
 * Issues grouped by file path
 *
 * Example:
 *
 * ═══════════════════════════════════════════════════════════════════
 *   CodeDrift Analysis - Grouped by File
 * ═══════════════════════════════════════════════════════════════════
 *
 *   Total Issues: 4,120  Critical: 89  Warnings: 4,031
 *   Files Analyzed: 1,234/1,250
 *
 * ───────────────────────────────────────────────────────────────────
 * 📄 src/config/aws.ts
 *   3 critical, 1 warning, 4 total
 * ───────────────────────────────────────────────────────────────────
 *
 *   🔴 Line 42: Hardcoded Secrets
 *      AWS access key pattern detected in source code
 *
 *   🔴 Line 44: Hardcoded Secrets
 *      AWS secret access key pattern detected
 *
 *   🔴 Line 56: Missing Input Validation
 *      Configuration parameter not validated
 *
 * ───────────────────────────────────────────────────────────────────
 */

/**
 * GROUPED BY ENGINE (--group-by engine)
 * Issues grouped by detection engine
 *
 * Example:
 *
 * ═══════════════════════════════════════════════════════════════════
 *   CodeDrift Analysis - Grouped by Engine
 * ═══════════════════════════════════════════════════════════════════
 *
 * ───────────────────────────────────────────────────────────────────
 * 🔧 Hardcoded Secrets
 *   42 critical, 12 total
 * ───────────────────────────────────────────────────────────────────
 *
 *   🔴 src/config/aws.ts:42
 *      AWS access key pattern detected in source code
 *
 *   🔴 src/config/database.ts:23
 *      Database password hardcoded
 *
 * ───────────────────────────────────────────────────────────────────
 */

/**
 * GROUPED BY SEVERITY (--group-by severity)
 * Issues grouped by severity level (default grouping)
 *
 * Example:
 *
 * ═══════════════════════════════════════════════════════════════════
 *   CodeDrift Analysis - Grouped by Severity
 * ═══════════════════════════════════════════════════════════════════
 *
 * ───────────────────────────────────────────────────────────────────
 * 🔴 Error Severity
 *   89 critical, 89 total
 * ───────────────────────────────────────────────────────────────────
 *
 *   Hardcoded Secrets: src/config/aws.ts:42
 *      AWS access key pattern detected in source code
 *
 *   Insecure Direct Object Reference: src/api/users.ts:156
 *      User ID parameter not validated against authenticated user
 *
 * ───────────────────────────────────────────────────────────────────
 */

/**
 * QUIET MODE (--quiet)
 * Shows only critical and high severity issues
 *
 * Filters to:
 * - All error severity issues
 * - Warning severity with high confidence
 *
 * Removes noise while focusing on actionable items
 */

/**
 * CI MODE (auto-detected)
 * Automatically enabled when:
 * - process.env.CI === 'true'
 * - !process.stdout.isTTY
 *
 * Behavior:
 * - No colors or emoji
 * - No spinners or progress bars
 * - Defaults to compact format
 * - Proper exit codes:
 *   - 0 = No critical/high issues
 *   - 1 = Critical/high issues found
 *   - 2 = Analysis error
 */

export {};

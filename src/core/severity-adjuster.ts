/**
 * Smart Severity Adjustment System
 * Adjusts issue severity based on context and confidence
 */

import type { Issue } from '../types/index.js';

/**
 * Adjust severity based on context
 *
 * This function applies intelligent severity adjustments based on:
 * - Confidence level (downgrade low-confidence errors)
 * - File context (test files, generated files)
 * - Engine-specific rules (console in dev vs prod)
 *
 * @param issue - Issue to adjust
 * @returns Adjusted issue, or null if it should be filtered out
 */
export function adjustSeverity(issue: Issue): Issue | null {
  let { severity } = issue;
  const confidence = issue.confidence || 'high';

  // Downgrade low-confidence errors to warnings
  if (severity === 'error' && confidence === 'low') {
    severity = 'warning';
  }

  // Test files (except secrets) are lower priority
  if (issue.metadata?.isTestFile) {
    // Security issues in tests are still important (hardcoded secrets, etc.)
    const securityEngines = [
      'secret-detector',
      'hardcoded-secret',
      'sql-injection-detector',
      'xss-detector',
    ];

    if (!securityEngines.includes(issue.engine)) {
      if (severity === 'error') {
        severity = 'warning';
      } else if (severity === 'warning') {
        severity = 'info';
      }
    }
  }

  // Generated files should be skipped entirely
  if (issue.metadata?.isGeneratedFile) {
    return null; // Signal to filter out
  }

  // Console statements: context-aware severity
  if (issue.engine === 'console-detector' || issue.engine === 'console-in-production') {
    const filePath = issue.filePath.toLowerCase();

    // Console in dev/debug/scripts is just info
    if (
      filePath.includes('/dev/') ||
      filePath.includes('/debug/') ||
      filePath.includes('/scripts/') ||
      filePath.includes('/tools/')
    ) {
      severity = 'info';
    }
    // Console in test files is info
    else if (issue.metadata?.isTestFile) {
      severity = 'info';
    }
    // Console in production code remains warning/error
  }

  // Empty catch blocks: less severe in test files
  if (issue.engine === 'empty-catch' && issue.metadata?.isTestFile) {
    if (severity === 'error') {
      severity = 'warning';
    }
  }

  // Missing await: high severity in production, medium in tests
  if (issue.engine === 'missing-await' && issue.metadata?.isTestFile) {
    if (severity === 'error') {
      severity = 'warning';
    }
  }

  return { ...issue, severity };
}

/**
 * Batch adjust severities for multiple issues
 *
 * @param issues - Array of issues to adjust
 * @returns Filtered and adjusted issues (null issues removed)
 */
export function adjustSeverities(issues: Issue[]): Issue[] {
  return issues
    .map(adjustSeverity)
    .filter((issue): issue is Issue => issue !== null);
}

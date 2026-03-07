/**
 * Risk Scoring System
 * Calculates risk scores (0-100) and assigns priority levels to issues
 */

import type { Issue } from '../types/index.js';

/**
 * Calculate risk score for an issue (0-100)
 *
 * Risk score is calculated based on:
 * - Base severity (error=40, warning=20, info=5)
 * - Confidence multiplier (high=2x, medium=1.2x, low=0.8x)
 * - Context adjustments (test files, generated files)
 * - Engine weight (security > quality > style)
 * - File type weight (config/auth files are higher risk)
 *
 * @param issue - The issue to calculate risk for
 * @returns Risk score between 0 and 100
 */
export function calculateRiskScore(issue: Issue): number {
  let score = 0;

  // Base score from severity
  if (issue.severity === 'error') {
    score += 40;
  } else if (issue.severity === 'warning') {
    score += 20;
  } else {
    score += 5;
  }

  // Confidence multiplier
  const confidence = issue.confidence || 'high';
  if (confidence === 'high') {
    score *= 2;
  } else if (confidence === 'medium') {
    score *= 1.2;
  } else {
    score *= 0.8;
  }

  // Context adjustments
  if (issue.metadata?.isTestFile) {
    // Test files are less critical (except for secrets)
    if (issue.engine !== 'hardcoded-secret') {
      score *= 0.3;
    }
  }

  if (issue.metadata?.isGeneratedFile) {
    // Generated files should have minimal score
    score = 0;
  }

  // Engine weight (security issues are critical)
  const securityEngines = [
    'hardcoded-secret',
    'idor',
    'missing-input-validation',
    'stack-trace-exposure',
    'unsafe-regex',
  ];

  if (securityEngines.includes(issue.engine)) {
    score *= 1.5; // Security issues are 50% more critical
  }

  // File type weight
  const filePath = issue.filePath.toLowerCase();
  if (
    filePath.includes('/config/') ||
    filePath.includes('/auth/') ||
    filePath.includes('/security/') ||
    filePath.endsWith('.env') ||
    filePath.includes('credentials')
  ) {
    score *= 1.3; // Config and auth files are 30% higher risk
  }

  // Production code is higher priority than development utilities
  if (
    filePath.includes('/dev/') ||
    filePath.includes('/debug/') ||
    filePath.includes('/scripts/')
  ) {
    score *= 0.7;
  }

  // Cap at 100 and ensure it's an integer
  return Math.min(Math.round(score), 100);
}

/**
 * Assign priority level based on risk score
 *
 * Priority levels:
 * - critical: >= 80 (requires immediate action)
 * - high: >= 50 (should be fixed soon)
 * - medium: >= 20 (should be addressed)
 * - low: < 20 (nice to fix)
 *
 * @param riskScore - Risk score (0-100)
 * @returns Priority level
 */
export function assignPriority(riskScore: number): 'critical' | 'high' | 'medium' | 'low' {
  if (riskScore >= 80) return 'critical';
  if (riskScore >= 50) return 'high';
  if (riskScore >= 20) return 'medium';
  return 'low';
}

/**
 * Enrich an issue with risk score and priority
 *
 * This is the main function to use for adding risk metadata to issues.
 * It calculates the risk score and assigns a priority level.
 *
 * @param issue - Issue to enrich
 * @returns Issue with riskScore and priority fields populated
 */
export function enrichIssueWithRisk(issue: Issue): Issue {
  const riskScore = calculateRiskScore(issue);
  return {
    ...issue,
    riskScore,
    priority: assignPriority(riskScore),
  };
}

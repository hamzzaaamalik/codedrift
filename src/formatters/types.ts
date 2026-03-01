/**
 * Formatter type definitions and utilities
 */

import type { Issue } from '../types/index.js';

export type GroupByType = 'severity' | 'file' | 'engine';
export type FormatType = 'summary' | 'detailed' | 'compact' | 'json';

export interface FormatterOptions {
  /** Format type for output */
  format: FormatType;
  /** Group issues by this criteria */
  groupBy?: GroupByType;
  /** Show only critical issues */
  quiet?: boolean;
  /** Disable colors */
  noColor?: boolean;
  /** Running in CI environment */
  ci?: boolean;
}

export interface IssueGroup {
  name: string;
  issues: Issue[];
  criticalCount: number;
  warningCount: number;
  infoCount: number;
}

/**
 * Calculate risk score for issue prioritization
 */
export function calculateRiskScore(issue: Issue): number {
  // Severity weight (error > warning > info)
  const severityScore = issue.severity === 'error' ? 100 :
                       issue.severity === 'warning' ? 50 : 10;

  // Confidence weight (high > medium > low)
  const confidence = issue.confidence || 'high';
  const confidenceScore = confidence === 'high' ? 3 :
                         confidence === 'medium' ? 2 : 1;

  // Engine priority (critical security issues first)
  const enginePriority: Record<string, number> = {
    'idor': 10,
    'missing-input-validation': 9,
    'hardcoded-secret': 8,
    'stack-trace-exposure': 7,
    'missing-await': 6,
    'async-foreach': 5,
    'hallucinated-deps': 4,
    'unsafe-regex': 3,
    'console-in-production': 2,
    'empty-catch': 1,
  };
  const engineScore = enginePriority[issue.engine] || 0;

  return (severityScore * confidenceScore) + engineScore;
}

/**
 * Group issues by specified criteria
 */
export function groupIssues(issues: Issue[], groupBy: GroupByType): IssueGroup[] {
  const groups: Map<string, Issue[]> = new Map();

  for (const issue of issues) {
    let key: string;
    switch (groupBy) {
      case 'severity':
        key = issue.severity;
        break;
      case 'file':
        key = issue.filePath;
        break;
      case 'engine':
        key = issue.engine;
        break;
      default:
        key = issue.severity;
    }

    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(issue);
  }

  // Convert to IssueGroup array
  const result: IssueGroup[] = [];
  for (const [name, groupIssues] of groups.entries()) {
    result.push({
      name,
      issues: groupIssues,
      criticalCount: groupIssues.filter(i => i.severity === 'error').length,
      warningCount: groupIssues.filter(i => i.severity === 'warning').length,
      infoCount: groupIssues.filter(i => i.severity === 'info').length,
    });
  }

  // Sort groups
  if (groupBy === 'severity') {
    const severityOrder = { 'error': 0, 'warning': 1, 'info': 2 };
    result.sort((a, b) => {
      const aOrder = severityOrder[a.name as keyof typeof severityOrder] ?? 999;
      const bOrder = severityOrder[b.name as keyof typeof severityOrder] ?? 999;
      return aOrder - bOrder;
    });
  } else {
    // Sort by critical count desc, then total count desc
    result.sort((a, b) => {
      if (a.criticalCount !== b.criticalCount) {
        return b.criticalCount - a.criticalCount;
      }
      return b.issues.length - a.issues.length;
    });
  }

  return result;
}

/**
 * Get human-readable engine name
 */
export function getEngineName(engine: string): string {
  const names: Record<string, string> = {
    'idor': 'Insecure Direct Object Reference',
    'missing-input-validation': 'Missing Input Validation',
    'hardcoded-secret': 'Hardcoded Secrets',
    'stack-trace-exposure': 'Stack Trace Exposure',
    'missing-await': 'Missing Await',
    'async-foreach': 'Async forEach/map',
    'hallucinated-deps': 'Hallucinated Dependencies',
    'unsafe-regex': 'Unsafe Regex (ReDoS)',
    'console-in-production': 'Console in Production',
    'empty-catch': 'Empty Catch Blocks',
  };
  return names[engine] || engine;
}

/**
 * Get severity emoji/icon
 */
export function getSeverityIcon(severity: string, useEmoji: boolean = true): string {
  if (!useEmoji) {
    return severity === 'error' ? '[ERROR]' :
           severity === 'warning' ? '[WARN]' : '[INFO]';
  }

  return severity === 'error' ? '🔴' :
         severity === 'warning' ? '🟠' : '🔵';
}

/**
 * Get confidence stars
 */
export function getConfidenceStars(confidence: string): string {
  switch (confidence) {
    case 'high':
      return '⭐⭐⭐';
    case 'medium':
      return '⭐⭐';
    case 'low':
      return '⭐';
    default:
      return '⭐⭐⭐';
  }
}

/**
 * Truncate file path for display
 */
export function truncatePath(filePath: string, maxLength: number = 60): string {
  if (filePath.length <= maxLength) {
    return filePath;
  }

  const parts = filePath.split(/[/\\]/);
  if (parts.length <= 2) {
    return '...' + filePath.slice(-(maxLength - 3));
  }

  // Keep first and last parts, truncate middle
  const first = parts[0];
  const last = parts[parts.length - 1];
  const remaining = maxLength - first.length - last.length - 6; // ".../"

  if (remaining <= 0) {
    return '...' + filePath.slice(-(maxLength - 3));
  }

  return first + '/.../' + last;
}

/**
 * Issue Deduplication System
 * Groups identical issues that appear in multiple locations
 */

import { createHash } from 'crypto';
import type { Issue, IssueGroup } from '../types/index.js';

/**
 * Create a fingerprint for an issue
 *
 * The fingerprint is used to identify duplicate issues across different files.
 * Multiple fingerprinting strategies:
 * 1. Exact match: engine + message + code pattern
 * 2. Message match: engine + message (for grouping similar issues)
 *
 * @param issue - Issue to fingerprint
 * @param mode - 'exact' for exact code match, 'message' for message-only grouping
 * @returns Unique fingerprint hash (16 characters)
 */
export function createFingerprint(issue: Issue, mode: 'exact' | 'message' = 'exact'): string {
  if (mode === 'message') {
    // Message-level fingerprint: Groups all "Missing await" issues together
    // regardless of which function is missing await
    const key = `${issue.engine}:${issue.message}`;
    return createHash('sha256').update(key).digest('hex').substring(0, 16);
  }

  // Exact fingerprint: Groups same issue with same code pattern
  const contextSnippet = issue.metadata?.contextSnippet || '';

  // Normalize the context snippet to ignore whitespace differences
  const normalizedContext = contextSnippet.trim().replace(/\s+/g, ' ');

  const key = `${issue.engine}:${issue.message}:${normalizedContext}`;
  return createHash('sha256').update(key).digest('hex').substring(0, 16);
}

/**
 * Deduplicate issues by grouping identical issues together
 *
 * Groups issues with the same fingerprint together, showing:
 * - A primary issue (first occurrence)
 * - All occurrences (including the primary)
 * - Total count
 *
 * This helps reduce noise when the same issue appears in multiple files.
 *
 * @param issues - Array of issues to deduplicate
 * @returns Array of issue groups, sorted by frequency (most frequent first)
 */
export function deduplicateIssues(issues: Issue[]): IssueGroup[] {
  const groups = new Map<string, IssueGroup>();

  for (const issue of issues) {
    const fingerprint = createFingerprint(issue);

    if (groups.has(fingerprint)) {
      const group = groups.get(fingerprint)!;
      group.occurrences.push(issue);
      group.count++;
    } else {
      groups.set(fingerprint, {
        fingerprint,
        primaryIssue: issue,
        occurrences: [issue],
        count: 1,
      });
    }
  }

  return Array.from(groups.values())
    .sort((a, b) => b.count - a.count); // Most frequent first
}

/**
 * Get statistics about issue duplication
 *
 * @param issueGroups - Array of issue groups
 * @returns Statistics about duplication
 */
export function getDeduplicationStats(issueGroups: IssueGroup[]): {
  totalIssues: number;
  uniqueIssues: number;
  duplicateGroups: number;
  reductionPercentage: number;
} {
  const totalIssues = issueGroups.reduce((sum, group) => sum + group.count, 0);
  const uniqueIssues = issueGroups.length;
  const duplicateGroups = issueGroups.filter(g => g.count > 1).length;
  const reductionPercentage = totalIssues > 0
    ? Math.round(((totalIssues - uniqueIssues) / totalIssues) * 100)
    : 0;

  return {
    totalIssues,
    uniqueIssues,
    duplicateGroups,
    reductionPercentage,
  };
}

/**
 * Deduplicate issues by message pattern (looser grouping)
 * Groups all issues with the same engine + message together,
 * regardless of code differences
 *
 * Example: All "console.log() in production code" issues group together
 *
 * @param issues - Array of issues to deduplicate
 * @returns Array of issue groups, sorted by frequency
 */
export function deduplicateByMessage(issues: Issue[]): IssueGroup[] {
  const groups = new Map<string, IssueGroup>();

  for (const issue of issues) {
    const fingerprint = createFingerprint(issue, 'message');

    if (groups.has(fingerprint)) {
      const group = groups.get(fingerprint)!;
      group.occurrences.push(issue);
      group.count++;
    } else {
      groups.set(fingerprint, {
        fingerprint,
        primaryIssue: issue,
        occurrences: [issue],
        count: 1,
      });
    }
  }

  return Array.from(groups.values())
    .sort((a, b) => b.count - a.count); // Most frequent first
}

/**
 * Get top N most frequent issues
 * Useful for showing "Top 10 issues to fix"
 *
 * @param issueGroups - Array of issue groups
 * @param topN - Number of top issues to return
 * @returns Top N issue groups sorted by frequency
 */
export function getTopIssues(issueGroups: IssueGroup[], topN: number = 10): IssueGroup[] {
  return [...issueGroups]
    .sort((a, b) => b.count - a.count)
    .slice(0, topN);
}

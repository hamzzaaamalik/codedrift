/**
 * Baseline mode implementation
 * Allows tracking only new issues by comparing against a baseline
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import type { Issue } from '../types/index.js';

export interface BaselineData {
  version: string;
  timestamp: string;
  fingerprints: Set<string>;
}

export interface BaselineFile {
  version: string;
  timestamp: string;
  fingerprints: string[];
}

/**
 * Generate a unique fingerprint for an issue
 * Based on: filePath + line + ruleId + message snippet
 */
export function generateFingerprint(issue: Issue): string {
  const messageSnippet = issue.message.substring(0, 100); // First 100 chars
  const data = `${issue.filePath}:${issue.location.line}:${issue.engine}:${messageSnippet}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Load baseline from file
 */
export function loadBaseline(baselineFile: string): BaselineData | null {
  try {
    if (!fs.existsSync(baselineFile)) {
      return null;
    }

    const content = fs.readFileSync(baselineFile, 'utf-8');
    const data: BaselineFile = JSON.parse(content);

    return {
      version: data.version,
      timestamp: data.timestamp,
      fingerprints: new Set(data.fingerprints),
    };
  } catch (error) {
    console.warn(`Warning: Failed to load baseline from ${baselineFile}`);
    return null;
  }
}

/**
 * Save baseline to file
 */
export function saveBaseline(issues: Issue[], baselineFile: string, version: string): void {
  const fingerprints = issues.map(generateFingerprint);

  const data: BaselineFile = {
    version,
    timestamp: new Date().toISOString(),
    fingerprints,
  };

  // Create directory if it doesn't exist
  const dir = path.dirname(baselineFile);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(baselineFile, JSON.stringify(data, null, 2), 'utf-8');
}

/**
 * Filter issues to only include new ones (not in baseline)
 */
export function filterNewIssues(issues: Issue[], baseline: BaselineData): Issue[] {
  return issues.filter(issue => {
    const fingerprint = generateFingerprint(issue);
    return !baseline.fingerprints.has(fingerprint);
  });
}

/**
 * Get default baseline file path
 */
export function getDefaultBaselinePath(): string {
  return path.join(process.cwd(), '.codedrift-baseline.json');
}

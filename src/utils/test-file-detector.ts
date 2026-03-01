/**
 * Test file detection utility
 * Identifies test files by name patterns
 */

import * as path from 'path';

const TEST_FILE_PATTERNS = [
  /\.test\.(ts|js|tsx|jsx)$/,
  /\.spec\.(ts|js|tsx|jsx)$/,
  /__tests__\//,
  /__mocks__\//,
  /\.test-d\.ts$/,
];

const TEST_DIRECTORY_PATTERNS = [
  'test',
  'tests',
  '__tests__',
  '__mocks__',
  'spec',
  'specs',
];

/**
 * Check if a file path represents a test file
 */
export function isTestFile(filePath: string): boolean {
  const normalized = filePath.split(path.sep).join('/');

  // Check file name patterns
  for (const pattern of TEST_FILE_PATTERNS) {
    if (pattern.test(normalized)) {
      return true;
    }
  }

  // Check if file is in a test directory
  const parts = normalized.split('/');
  for (const part of parts) {
    if (TEST_DIRECTORY_PATTERNS.includes(part.toLowerCase())) {
      return true;
    }
  }

  return false;
}

/**
 * Detect workspace name from file path
 */
export function detectWorkspaceName(filePath: string): string | undefined {
  const normalized = filePath.split(path.sep).join('/');

  // Look for common monorepo patterns
  const monorepoPatterns = [
    /\/packages\/([^\/]+)\//,
    /\/apps\/([^\/]+)\//,
    /\/services\/([^\/]+)\//,
    /\/modules\/([^\/]+)\//,
  ];

  for (const pattern of monorepoPatterns) {
    const match = normalized.match(pattern);
    if (match) {
      return match[1];
    }
  }

  return undefined;
}

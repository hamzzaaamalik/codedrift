/**
 * Configuration loader for CodeDrift
 * Loads and validates codedrift.config.json
 */

import * as fs from 'fs';
import * as path from 'path';
import { CodeDriftConfig, Confidence, Issue } from '../types/index.js';

const DEFAULT_CONFIG: CodeDriftConfig = {
  exclude: [
    'node_modules/**',
    'dist/**',
    'build/**',
    'coverage/**',
    '.next/**',
    '.nuxt/**',
    '**/*.min.js',
    '**/*.bundle.js',
    '**/__samples__/**',
    '**/__tests__/**',
    '**/__mocks__/**',
  ],
  rules: {
    // Security issues - keep as errors (high priority)
    'stack-trace-exposure': 'error',
    'hardcoded-secret': 'error',
    'sql-injection': 'error',
    'xss-detector': 'error',
    'idor': 'error',

    // Code quality - downgrade to warnings to reduce noise
    'missing-await': 'warn', // ✅ CHANGED: Too noisy as error
    'empty-catch': 'warn',
    'console-in-production': 'warn', // ✅ CHANGED: Common in CLI tools
    'hallucinated-deps': 'warn', // ✅ CHANGED: Workspace resolution can be complex
  },
  failOn: 'error',
  cache: {
    enabled: true,
    ttl: 86400000, // 24 hours
  },
  respectGitignore: true,
  excludeTestFiles: true, // ✅ CHANGED: Skip test files by default to reduce noise
  confidenceThreshold: 'high', // ✅ CHANGED: Only show high-confidence issues by default (maximum noise reduction)
};

/**
 * Load configuration from project root
 */
export function loadConfig(): CodeDriftConfig {
  const configPath = findConfigFile();

  if (!configPath) {
    return DEFAULT_CONFIG;
  }

  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    const userConfig = JSON.parse(content) as Partial<CodeDriftConfig>;

    // Merge with defaults
    return mergeConfig(DEFAULT_CONFIG, userConfig);
  } catch (error) {
    console.warn(`Warning: Failed to load config from ${configPath}:`, error instanceof Error ? error.message : error);
    return DEFAULT_CONFIG;
  }
}

/**
 * Find config file in current directory or parents
 */
function findConfigFile(): string | null {
  const configNames = [
    'codedrift.config.json',
    '.codedriftrc.json',
    '.codedriftrc',
  ];

  let currentDir = process.cwd();
  const root = path.parse(currentDir).root;

  while (currentDir !== root) {
    for (const name of configNames) {
      const configPath = path.join(currentDir, name);
      if (fs.existsSync(configPath)) {
        return configPath;
      }
    }

    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }

  return null;
}

/**
 * Merge user config with defaults
 */
function mergeConfig(defaults: CodeDriftConfig, user: Partial<CodeDriftConfig>): CodeDriftConfig {
  return {
    exclude: user.exclude ?? defaults.exclude,
    rules: {
      ...defaults.rules,
      ...user.rules,
    },
    failOn: user.failOn ?? defaults.failOn,
    cache: {
      ...defaults.cache,
      ...user.cache,
    },
    respectGitignore: user.respectGitignore ?? defaults.respectGitignore,
    excludeTestFiles: user.excludeTestFiles ?? defaults.excludeTestFiles,
    confidenceThreshold: user.confidenceThreshold ?? defaults.confidenceThreshold,
    workspaceRoot: user.workspaceRoot ?? defaults.workspaceRoot,
    format: user.format ?? defaults.format,
    output: user.output ?? defaults.output,
  };
}

/**
 * Get default configuration
 */
export function getDefaultConfig(): CodeDriftConfig {
  return { ...DEFAULT_CONFIG };
}

/**
 * Check if a rule is enabled
 */
export function isRuleEnabled(config: CodeDriftConfig, ruleName: string): boolean {
  const level = config.rules?.[ruleName as keyof typeof config.rules];
  return level !== 'off';
}

/**
 * Get effective severity for a rule
 */
export function getRuleSeverity(config: CodeDriftConfig, ruleName: string): 'error' | 'warning' | null {
  const level = config.rules?.[ruleName as keyof typeof config.rules];

  if (level === 'off') return null;
  if (level === 'error') return 'error';
  if (level === 'warn') return 'warning';

  return null;
}

/**
 * Check if an issue meets the confidence threshold
 */
export function meetsConfidenceThreshold(issue: Issue, threshold: Confidence): boolean {
  // If issue has no confidence, assume high confidence
  const issueConfidence = issue.confidence || 'high';

  const confidenceLevels: Record<Confidence, number> = {
    'high': 3,
    'medium': 2,
    'low': 1,
  };

  const issueLevel = confidenceLevels[issueConfidence];
  const thresholdLevel = confidenceLevels[threshold];

  // Issue passes if its confidence is >= threshold
  return issueLevel >= thresholdLevel;
}

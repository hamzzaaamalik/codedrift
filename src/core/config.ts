/**
 * Configuration loader for CodeDrift
 * Loads and validates codedrift.config.json
 */

import * as fs from 'fs';
import * as path from 'path';
import { CodeDriftConfig } from '../types/index.js';

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
    'stack-trace-exposure': 'error',
    'hallucinated-deps': 'error',
    'missing-await': 'error',
    'empty-catch': 'warn',
    'hardcoded-secret': 'error',
  },
  failOn: 'error',
  cache: {
    enabled: true,
    ttl: 86400000, // 24 hours
  },
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

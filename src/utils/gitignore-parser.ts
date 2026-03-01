/**
 * GitIgnore Parser
 * Parses .gitignore files and determines if files should be ignored
 * Supports standard gitignore patterns including negation and wildcards
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * Compiled gitignore rule
 */
interface IgnoreRule {
  pattern: RegExp;
  negation: boolean;
  directoryOnly: boolean;
}

/**
 * GitIgnoreParser class
 * Parses .gitignore patterns and provides file filtering
 */
export class GitIgnoreParser {
  private rules: IgnoreRule[] = [];
  private rootDir: string;

  /**
   * Create a new GitIgnoreParser
   * @param rootDir - Root directory containing .gitignore
   */
  constructor(rootDir: string) {
    this.rootDir = path.resolve(rootDir);
    this.loadGitignore();
  }

  /**
   * Load and parse .gitignore file
   */
  private loadGitignore(): void {
    const gitignorePath = path.join(this.rootDir, '.gitignore');

    if (!fs.existsSync(gitignorePath)) {
      return;
    }

    try {
      const content = fs.readFileSync(gitignorePath, 'utf-8');
      this.parseGitignore(content);
    } catch (error) {
      console.warn(`Warning: Failed to load .gitignore: ${error instanceof Error ? error.message : error}`);
    }
  }

  /**
   * Parse gitignore content and convert to rules
   * @param content - Content of .gitignore file
   */
  private parseGitignore(content: string): void {
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Parse the pattern
      const rule = this.parsePattern(trimmed);
      if (rule) {
        this.rules.push(rule);
      }
    }
  }

  /**
   * Parse a single gitignore pattern
   * @param pattern - Pattern string
   * @returns Compiled rule or null if invalid
   */
  private parsePattern(pattern: string): IgnoreRule | null {
    let isNegation = false;
    let isDirectoryOnly = false;
    let workPattern = pattern;

    // Handle negation patterns (!)
    if (workPattern.startsWith('!')) {
      isNegation = true;
      workPattern = workPattern.slice(1);
    }

    // Handle directory-only patterns (/)
    if (workPattern.endsWith('/')) {
      isDirectoryOnly = true;
      workPattern = workPattern.slice(0, -1);
    }

    // Convert gitignore pattern to regex
    const regex = this.patternToRegex(workPattern, isDirectoryOnly);

    if (!regex) {
      return null;
    }

    return {
      pattern: regex,
      negation: isNegation,
      directoryOnly: isDirectoryOnly,
    };
  }

  /**
   * Convert gitignore pattern to regular expression
   * Supports *, **, and other gitignore wildcards
   *
   * @param pattern - Gitignore pattern
   * @param isDirectoryOnly - Whether this pattern is for directories only
   * @returns RegExp or null if invalid
   */
  private patternToRegex(pattern: string, isDirectoryOnly: boolean = false): RegExp | null {
    try {
      let regexPattern = '';
      let isRooted = false;

      // Check if pattern is rooted (starts with /)
      if (pattern.startsWith('/')) {
        isRooted = true;
        pattern = pattern.slice(1);
      }

      // Check if pattern should match in any directory
      const hasSlash = pattern.includes('/');

      if (!hasSlash && !isRooted) {
        // Pattern like "*.log" should match in any directory
        regexPattern = '(?:^|/)';
      } else if (isRooted) {
        // Pattern like "/foo" should only match at root
        regexPattern = '^';
      }

      // Convert pattern to regex
      let i = 0;
      while (i < pattern.length) {
        const char = pattern[i];

        if (char === '*') {
          // Check for **
          if (pattern[i + 1] === '*') {
            // ** matches any number of directories
            if (pattern[i + 2] === '/') {
              regexPattern += '(?:.*/)';
              i += 3;
            } else if (i + 2 === pattern.length) {
              regexPattern += '.*';
              i += 2;
            } else {
              regexPattern += '[^/]*';
              i += 1;
            }
          } else {
            // * matches anything except /
            regexPattern += '[^/]*';
            i += 1;
          }
        } else if (char === '?') {
          // ? matches any single character except /
          regexPattern += '[^/]';
          i += 1;
        } else if (char === '[') {
          // Character class
          const closeBracket = pattern.indexOf(']', i);
          if (closeBracket === -1) {
            // Invalid pattern
            return null;
          }
          const charClass = pattern.slice(i, closeBracket + 1);
          regexPattern += charClass;
          i = closeBracket + 1;
        } else if (/[.+^${}()|\\]/.test(char)) {
          // Escape regex special characters
          regexPattern += '\\' + char;
          i += 1;
        } else {
          // Regular character
          regexPattern += char;
          i += 1;
        }
      }

      // For directory patterns, match the directory and everything inside
      if (isDirectoryOnly) {
        regexPattern += '(?:$|/.*)';
      } else {
        regexPattern += '$';
      }

      return new RegExp(regexPattern);
    } catch (error) {
      console.warn(`Warning: Invalid gitignore pattern: ${pattern}`);
      return null;
    }
  }

  /**
   * Add additional patterns to the ignore list
   * Useful for adding patterns from config
   *
   * @param patterns - Array of gitignore-style patterns
   */
  public addPatterns(patterns: string[]): void {
    for (const pattern of patterns) {
      const rule = this.parsePattern(pattern);
      if (rule) {
        this.rules.push(rule);
      }
    }
  }

  /**
   * Check if a file path should be ignored
   *
   * @param filePath - Absolute or relative file path
   * @param isDirectory - Whether the path is a directory (optional)
   * @returns true if the file should be ignored
   */
  public ignores(filePath: string, isDirectory?: boolean): boolean {
    // Make path relative to root
    let relativePath = path.isAbsolute(filePath)
      ? path.relative(this.rootDir, filePath)
      : filePath;

    // Normalize path separators for cross-platform compatibility
    relativePath = relativePath.split(path.sep).join('/');

    // Remove leading ./
    if (relativePath.startsWith('./')) {
      relativePath = relativePath.slice(2);
    }

    let ignored = false;

    // Process rules in order (later rules override earlier ones)
    for (const rule of this.rules) {
      // Skip directory-only rules for files
      if (rule.directoryOnly && isDirectory === false) {
        continue;
      }

      // Test the pattern
      if (rule.pattern.test(relativePath)) {
        ignored = !rule.negation;
      }
    }

    return ignored;
  }

  /**
   * Alias for ignores() for backward compatibility
   * @param filePath - File path to check
   * @returns true if the file should be ignored
   */
  public shouldIgnore(filePath: string): boolean {
    return this.ignores(filePath);
  }

  /**
   * Get all rules (for debugging)
   * @returns Array of rules
   */
  public getRules(): IgnoreRule[] {
    return this.rules;
  }

  /**
   * Clear all rules
   */
  public clearRules(): void {
    this.rules = [];
  }

  /**
   * Reload .gitignore file
   */
  public reload(): void {
    this.clearRules();
    this.loadGitignore();
  }
}

/**
 * Create a GitIgnoreParser instance
 * @param rootDir - Root directory
 * @returns GitIgnoreParser instance
 */
export function createGitIgnoreParser(rootDir: string): GitIgnoreParser {
  return new GitIgnoreParser(rootDir);
}

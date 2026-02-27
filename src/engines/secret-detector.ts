/**
 * Secret Pattern Detector
 * Detects hardcoded secrets, API keys, passwords, and tokens
 * Priority: CRITICAL (security vulnerability)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: 'error' | 'warning';
}

export class SecretDetector extends BaseEngine {
  readonly name = 'hardcoded-secret';

  // Secret patterns to detect
  private readonly patterns: SecretPattern[] = [
    // API Keys - Stripe
    { name: 'Stripe API Key', pattern: /sk_(live|test)_[0-9a-zA-Z]{24,}/, severity: 'error' },
    { name: 'Stripe Webhook Secret', pattern: /whsec_[0-9a-zA-Z]{32,}/, severity: 'error' },

    // GitHub
    { name: 'GitHub Token', pattern: /gh[ps]_[0-9a-zA-Z]{36,}/, severity: 'error' },
    { name: 'GitHub PAT', pattern: /github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}/, severity: 'error' },
    { name: 'GitHub OAuth', pattern: /gho_[0-9a-zA-Z]{36}/, severity: 'error' },

    // AWS
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'error' },

    // Google
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\\-_]{35}/, severity: 'error' },

    // Private Keys
    { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/, severity: 'error' },
    { name: 'Private Key', pattern: /-----BEGIN PRIVATE KEY-----/, severity: 'error' },
    { name: 'EC Private Key', pattern: /-----BEGIN EC PRIVATE KEY-----/, severity: 'error' },
    { name: 'OpenSSH Private Key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, severity: 'error' },

    // Database URLs with passwords
    { name: 'PostgreSQL URL', pattern: /postgresql:\/\/[^:]+:[^@\s]+@/, severity: 'error' },
    { name: 'MongoDB URL', pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@\s]+@/, severity: 'error' },
    { name: 'MySQL URL', pattern: /mysql:\/\/[^:]+:[^@\s]+@/, severity: 'error' },

    // Slack
    { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, severity: 'error' },
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}/, severity: 'error' },

    // SendGrid
    { name: 'SendGrid API Key', pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/, severity: 'error' },

    // Generic JWT
    { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'error' },

    // npm tokens
    { name: 'npm Access Token', pattern: /npm_[A-Za-z0-9]{36}/, severity: 'error' },
  ];

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      // Check string literals for secret patterns
      if (ts.isStringLiteral(node)) {
        const stringIssue = this.checkStringLiteral(node, context);
        if (stringIssue) {
          issues.push(stringIssue);
        }
      }

      // Check variable declarations for suspicious names with non-env values
      if (ts.isVariableDeclaration(node)) {
        const varIssue = this.checkVariableDeclaration(node, context);
        if (varIssue) {
          issues.push(varIssue);
        }
      }
    });

    return issues;
  }

  /**
   * Check string literal for secret patterns
   */
  private checkStringLiteral(node: ts.StringLiteral, context: AnalysisContext): Issue | null {
    const value = node.text;

    // Skip empty strings
    if (value.length === 0) {
      return null;
    }

    // Skip placeholder values
    if (this.isPlaceholder(value)) {
      return null;
    }

    // Skip test/dev values
    if (this.isTestValue(value)) {
      return null;
    }

    // Check against known patterns
    for (const { name, pattern, severity } of this.patterns) {
      if (pattern.test(value)) {
        return this.createIssue(context, node, `Hardcoded secret detected: ${name}`, {
          severity,
          suggestion: 'Use environment variables or secret management service',
        });
      }
    }

    return null;
  }

  /**
   * Check variable declaration for suspicious secret-like names
   */
  private checkVariableDeclaration(node: ts.VariableDeclaration, context: AnalysisContext): Issue | null {
    if (!ts.isIdentifier(node.name)) {
      return null;
    }

    const varName = node.name.text;

    // Check if variable name suggests it's a secret
    if (!this.isSuspiciousVariableName(varName)) {
      return null;
    }

    // Check if it's using process.env (safe)
    if (node.initializer && this.isEnvVariable(node.initializer)) {
      return null;
    }

    // Check if it's a placeholder
    if (node.initializer && ts.isStringLiteral(node.initializer) && this.isPlaceholder(node.initializer.text)) {
      return null;
    }

    // Check if it's empty/null
    if (node.initializer && this.isEmptyValue(node.initializer)) {
      return null;
    }

    // Check if it's a hardcoded string value
    if (node.initializer && ts.isStringLiteral(node.initializer)) {
      const value = node.initializer.text;

      // Skip test values
      if (this.isTestValue(value)) {
        return null;
      }

      // Has suspicious name and hardcoded value
      if (value.length > 8) {  // Only flag if value looks substantial
        return this.createIssue(context, node, `Suspicious secret in variable: ${varName}`, {
          severity: 'warning',
          suggestion: 'Use environment variables instead of hardcoding secrets',
        });
      }
    }

    return null;
  }

  /**
   * Check if variable name suggests it contains a secret
   */
  private isSuspiciousVariableName(name: string): boolean {
    const lowerName = name.toLowerCase();
    const suspiciousWords = [
      'secret', 'password', 'passwd', 'pwd', 'token', 'key',
      'apikey', 'api_key', 'private', 'credential', 'auth',
    ];

    return suspiciousWords.some(word => lowerName.includes(word));
  }

  /**
   * Check if initializer is process.env access
   */
  private isEnvVariable(node: ts.Expression): boolean {
    // process.env.VAR_NAME
    if (ts.isPropertyAccessExpression(node)) {
      const { expression } = node;
      if (ts.isPropertyAccessExpression(expression)) {
        return (
          ts.isIdentifier(expression.expression) &&
          expression.expression.text === 'process' &&
          ts.isIdentifier(expression.name) &&
          expression.name.text === 'env'
        );
      }
    }

    // process.env['VAR_NAME']
    if (ts.isElementAccessExpression(node)) {
      const { expression } = node;
      if (ts.isPropertyAccessExpression(expression)) {
        return (
          ts.isIdentifier(expression.expression) &&
          expression.expression.text === 'process' &&
          ts.isIdentifier(expression.name) &&
          expression.name.text === 'env'
        );
      }
    }

    return false;
  }

  /**
   * Check if value is a placeholder
   */
  private isPlaceholder(value: string): boolean {
    const placeholderPatterns = [
      /YOUR_.*_HERE/i,
      /REPLACE.*WITH/i,
      /CHANGE.*THIS/i,
      /EXAMPLE/i,
      /PLACEHOLDER/i,
      /TODO/i,
      /XXX/i,
    ];

    return placeholderPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if value is for test/dev environment
   */
  private isTestValue(value: string): boolean {
    const lowerValue = value.toLowerCase();
    const testIndicators = ['test', 'dev', 'local', 'demo', 'example', 'sample', 'mock'];

    return testIndicators.some(indicator => lowerValue.includes(indicator));
  }

  /**
   * Check if initializer is empty/null/undefined
   */
  private isEmptyValue(node: ts.Expression): boolean {
    // Empty string
    if (ts.isStringLiteral(node) && node.text === '') {
      return true;
    }

    // null
    if (node.kind === ts.SyntaxKind.NullKeyword) {
      return true;
    }

    // undefined
    if (ts.isIdentifier(node) && node.text === 'undefined') {
      return true;
    }

    return false;
  }

  /**
   * Calculate Shannon entropy of a string
   * High entropy (>4.5) suggests randomness (possible secret)
   *
   * Future enhancement: Use this for adaptive secret detection
   * Example: Check if high-entropy strings (>4.5) are assigned to secret-named variables
   */
  // private calculateEntropy(str: string): number {
  //   if (str.length === 0) return 0;
  //   const freq = new Map<string, number>();
  //   for (const char of str) freq.set(char, (freq.get(char) || 0) + 1);
  //   let entropy = 0;
  //   for (const count of freq.values()) {
  //     const p = count / str.length;
  //     entropy -= p * Math.log2(p);
  //   }
  //   return entropy;
  // }
}

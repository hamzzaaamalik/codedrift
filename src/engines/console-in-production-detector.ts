/**
 * Console in Production Detector
 * Detects console.log/warn/error/info in production code
 * Priority: HIGH (PCI/GDPR violations, production noise, sensitive data logging)
 *
 * AI coding assistants LOVE console.log for "debugging":
 * - Logs sensitive data (passwords, tokens, PII)
 * - PCI DSS violation if logging payment data
 * - GDPR violation if logging personal data
 * - Creates production noise and performance issues
 * - Never removed before shipping
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import { isCLIFile, isMigrationFile } from '../utils/file-utils.js';
import * as ts from 'typescript';

export class ConsoleInProductionDetector extends BaseEngine {
  readonly name = 'console-in-production';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    // Skip test files - console.log is fine in tests
    if (this.isTestFile(context.filePath)) {
      return issues;
    }

    // Skip files that are explicitly development/debug utilities
    if (this.isDevelopmentFile(context.filePath)) {
      return issues;
    }

    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const issue = this.checkConsoleCall(node, context);
        if (issue) {
          issues.push(issue);
        }
      }
    });

    return issues;
  }

  /**
   * Check if this is a console method call
   *
   * Confidence levels:
   * - High: Console.log with sensitive data (password, token, etc.)
   * - High: Console in production route handlers
   * - Medium: Console in regular production code
   * - Low: Console.error (may be intentional error logging)
   */
  private checkConsoleCall(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    const { expression } = node;

    // Must be console.method()
    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const objectName = this.getObjectName(expression.expression);
    const methodName = expression.name.text;

    // Check if it's a console call
    if (objectName !== 'console') {
      return null;
    }

    // Check if it's a logging method
    const loggingMethods = ['log', 'warn', 'error', 'info', 'debug', 'trace', 'dir', 'table'];
    if (!loggingMethods.includes(methodName)) {
      return null;
    }

    // Check if it's in a development-only block
    if (this.isInDevelopmentBlock(node)) {
      return null;
    }

    // Analyze what's being logged - is it sensitive?
    const sensitivity = this.analyzeSensitivity(node);

    let message = `console.${methodName}() in production code`;
    let severity: 'error' | 'warning' = 'warning';
    let confidence: 'high' | 'medium' | 'low' = 'medium';

    if (sensitivity.isSensitive) {
      message = `console.${methodName}() logging potentially sensitive data: ${sensitivity.reason}`;
      severity = 'error';
      confidence = 'high'; // High confidence for sensitive data
    } else if (methodName === 'error') {
      // console.error might be intentional for error logging
      confidence = 'low';
    } else if (this.isInRouteHandler(node)) {
      // Console in route handlers is more likely a bug
      confidence = 'high';
    }

    return this.createIssue(context, node, message, {
      severity,
      suggestion: `Use proper logger (winston, pino, bunyan) with log levels and redaction. Remove console.${methodName}() from production code.`,
      confidence,
    });
  }

  /**
   * Check if console call is within a route handler
   */
  private isInRouteHandler(node: ts.Node): boolean {
    let current = node.parent;

    while (current) {
      // Check for Express/Fastify style: app.get('/path', (req, res) => {})
      if (ts.isCallExpression(current)) {
        const { expression } = current;
        if (ts.isPropertyAccessExpression(expression)) {
          const methodName = expression.name.text;
          const routeMethods = ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'];
          if (routeMethods.includes(methodName)) {
            return true;
          }
        }
      }

      current = current.parent;
    }

    return false;
  }

  /**
   * Get object name from expression
   */
  private getObjectName(expr: ts.Expression): string | null {
    if (ts.isIdentifier(expr)) {
      return expr.text;
    }
    if (ts.isPropertyAccessExpression(expr)) {
      return this.getObjectName(expr.expression);
    }
    return null;
  }

  /**
   * Check if file is a test file
   */
  private isTestFile(filePath: string): boolean {
    const testPatterns = [
      /\.test\.(ts|tsx|js|jsx)$/,
      /\.spec\.(ts|tsx|js|jsx)$/,
      /\/__tests__\//,
      /\/tests?\//,
      /\/test\//,
      /\/spec\//,
      /\.e2e\.(ts|tsx|js|jsx)$/,
      /\.integration\.(ts|tsx|js|jsx)$/,
    ];

    return testPatterns.some(pattern => pattern.test(filePath));
  }

  /**
   * Check if file is a development/debug utility
   * Enhanced with context-aware detection
   */
  private isDevelopmentFile(filePath: string): boolean {
    // Use utility functions for CLI and migration detection
    if (isCLIFile(filePath)) {
      return true; // CLI files are expected to use console for output
    }

    if (isMigrationFile(filePath)) {
      return true; // Migration files often use console for progress/logging
    }

    const devPatterns = [
      /\/dev\//,
      /\/debug\//,
      /\/scripts\//,
      /\/tools\//,
      /\/cli\./,
      /debug\.ts$/,
      /logger\.ts$/,  // Logger implementations are allowed to use console
      /log\.ts$/,
      /\/seed\//,     // Seed scripts
      /\/setup\//,    // Setup scripts
    ];

    return devPatterns.some(pattern => pattern.test(filePath));
  }

  /**
   * Check if console call is in a development-only block
   */
  private isInDevelopmentBlock(node: ts.Node): boolean {
    let current = node.parent;

    while (current) {
      // Check if inside: if (process.env.NODE_ENV === 'development') { ... }
      if (ts.isIfStatement(current)) {
        const condition = current.expression;

        // Look for NODE_ENV checks
        if (this.isDevelopmentCondition(condition)) {
          return true;
        }
      }

      current = current.parent;
    }

    return false;
  }

  /**
   * Check if condition is checking for development environment
   */
  private isDevelopmentCondition(node: ts.Expression): boolean {
    // Simple check: process.env.NODE_ENV === 'development'
    if (ts.isBinaryExpression(node)) {
      const text = node.getText();
      const devPatterns = [
        /NODE_ENV.*===.*['"]development['"]/,
        /NODE_ENV.*===.*['"]dev['"]/,
        /isDevelopment/,
        /isDebug/,
        /__DEV__/,
      ];

      return devPatterns.some(pattern => pattern.test(text));
    }

    // Check for direct flag: if (isDevelopment) { ... }
    if (ts.isIdentifier(node)) {
      const name = node.text.toLowerCase();
      return ['isdevelopment', 'isdev', 'isdebug', '__dev__'].includes(name);
    }

    return false;
  }

  /**
   * Analyze what's being logged to detect sensitive data
   */
  private analyzeSensitivity(node: ts.CallExpression): { isSensitive: boolean; reason?: string } {
    if (!node.arguments || node.arguments.length === 0) {
      return { isSensitive: false };
    }

    // Check all arguments for sensitive variable names or patterns
    for (const arg of node.arguments) {
      const argText = arg.getText().toLowerCase();

      // Sensitive keywords in variable names
      const sensitiveKeywords = [
        // Authentication & Authorization
        'password', 'passwd', 'pwd', 'token', 'jwt', 'apikey', 'api_key',
        'secret', 'private', 'credential', 'auth',

        // Payment Data (PCI)
        'card', 'cvv', 'cvc', 'pin', 'payment', 'billing', 'creditcard',
        'account_number', 'routing', 'iban', 'swift',

        // Personal Data (GDPR/PII)
        'ssn', 'social_security', 'passport', 'license', 'dob', 'birthdate',
        'email', 'phone', 'address', 'medical', 'health',

        // Session & Security
        'session', 'cookie', 'csrf', 'nonce', 'salt', 'hash',

        // Database
        'connection_string', 'db_password', 'database_url',
      ];

      for (const keyword of sensitiveKeywords) {
        if (argText.includes(keyword)) {
          return {
            isSensitive: true,
            reason: `variable name contains '${keyword}'`
          };
        }
      }

      // Check for object spreading that might include sensitive fields
      if (ts.isIdentifier(arg)) {
        const varName = arg.text.toLowerCase();
        const sensitiveObjectNames = ['user', 'req', 'request', 'body', 'params', 'query', 'headers'];

        if (sensitiveObjectNames.includes(varName)) {
          return {
            isSensitive: true,
            reason: `logging entire '${arg.text}' object which may contain sensitive data`
          };
        }
      }

      // Check for req.body, req.params, etc.
      if (ts.isPropertyAccessExpression(arg)) {
        const text = arg.getText();
        if (text.match(/req\.(body|params|query|headers)/)) {
          return {
            isSensitive: true,
            reason: 'logging request data which may contain sensitive information'
          };
        }
      }
    }

    return { isSensitive: false };
  }
}

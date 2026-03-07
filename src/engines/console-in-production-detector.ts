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
import { traverse, getImports } from '../core/parser.js';
import { isCLIFile, isMigrationFile, isConfigFile } from '../utils/file-utils.js';
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

    // Check if this file imports an established logging library
    const hasLoggerImport = this.fileUsesLoggerLibrary(context);

    // Check if this file imports the 'debug' npm package
    const hasDebugImport = this.fileImportsDebugPackage(context);

    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        // Skip debug() calls if the file imports the 'debug' package —
        // 'debug' is a controlled logging solution, not console pollution.
        if (hasDebugImport && this.isDebugPackageCall(node)) {
          return;
        }

        const issue = this.checkConsoleCall(node, context);
        if (issue) {
          // If the file uses a proper logger, suppress only LOW-confidence findings.
          // HIGH: sensitive data logging — always report.
          // MEDIUM: console in route handlers — still worth flagging even with a logger.
          // LOW: generic console.log in regular code — likely intentional alongside logger.
          if (hasLoggerImport && issue.confidence === 'low') {
            return;
          }
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

    // Debug utility methods get lower severity — they're debug instrumentation, not logging
    const debugMethods = ['table', 'time', 'timeEnd', 'timeLog', 'count', 'countReset', 'group', 'groupEnd'];
    if (debugMethods.includes(methodName)) {
      // Still check if in development block
      if (this.isInDevelopmentBlock(node)) {
        return null;
      }
      if (this.isInsideLoggerClass(node)) {
        return null;
      }
      return this.createIssue(context, node, `console.${methodName}() is a debug utility left in production code`, {
        severity: 'info',
        suggestion: `Remove console.${methodName}() — it's debug instrumentation, not logging.`,
        confidence: 'medium',
      });
    }

    // Check if it's a logging method (after debug methods are handled above)
    const loggingMethods = ['log', 'warn', 'error', 'info', 'debug', 'trace', 'dir'];
    if (!loggingMethods.includes(methodName)) {
      return null;
    }

    // Check if it's in a development-only block
    if (this.isInDevelopmentBlock(node)) {
      return null;
    }

    // Check if this console call is inside a logger/transport class implementation
    if (this.isInsideLoggerClass(node)) {
      return null;
    }

    // Respect eslint-disable comments — if the developer explicitly disabled no-console,
    // they've made a conscious decision to keep this console call
    if (this.hasEslintDisableComment(node, context)) {
      return null;
    }

    // Analyze what's being logged - is it sensitive?
    const sensitivity = this.analyzeSensitivity(node);

    let message = `console.${methodName}() in production code`;
    let severity: 'error' | 'warning' = 'warning';
    let confidence: 'high' | 'medium' | 'low' = 'low';

    if (sensitivity.isSensitive) {
      message = `console.${methodName}() logging potentially sensitive data: ${sensitivity.reason}`;
      severity = 'error';
      confidence = 'high'; // High confidence for sensitive data
    } else if (this.isInRouteHandler(node)) {
      // Console in route handlers is more likely a bug
      confidence = 'high';
    }

    // Catch block context: console in error handlers is commonly intentional
    if (this.isInCatchBlock(node)) {
      confidence = 'low';
    }

    // Structured logging: JSON.stringify() suggests intentional, controlled output
    if (this.hasStructuredLoggingArg(node)) {
      confidence = 'low';
    }

    // Anonymization: arguments passing through masking/redacting functions
    // indicate the developer is being careful about what's logged
    if (this.hasAnonymizationArg(node)) {
      confidence = 'low';
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
   * Check if the file imports an established logging library.
   * When true, non-sensitive console calls are suppressed (likely intentional alongside the logger).
   * Sensitive-data console calls are still reported regardless.
   */
  private fileUsesLoggerLibrary(context: AnalysisContext): boolean {
    // Only the established production-grade loggers from the spec.
    // General-purpose utilities like `debug` are intentionally excluded —
    // they're too commonly imported for one-off use to reliably signal "proper logging".
    const loggerPackages = new Set([
      'winston', 'pino', 'bunyan', 'log4js', 'loglevel',
      'signale', 'tslog', 'roarr',
    ]);

    const imports = getImports(context.sourceFile);
    return imports.some(imp => {
      // Handle scoped packages like @org/pino → still extract 'pino' if needed,
      // but these loggers are not scoped so a simple split is sufficient.
      const pkg = imp.moduleName.startsWith('@')
        ? imp.moduleName          // keep full scoped name for future entries
        : imp.moduleName.split('/')[0];
      return loggerPackages.has(pkg);
    });
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

    if (isConfigFile(filePath)) {
      return true; // Config/build files legitimately use console for output
    }

    // Normalize to forward slashes for cross-platform regex matching
    const normalPath = filePath.replace(/\\/g, '/');

    const devPatterns = [
      /\/dev\//,
      /\/debug\//,
      /\/scripts\//,
      /\/tools\//,
      /\/bin\//,
      /\/cli[./]/,
      /debug\.ts$/,
      /logger\.ts$/,  // Logger implementations are allowed to use console
      /log\.ts$/,
      /\/seed\//,     // Seed scripts
      /\/setup\//,    // Setup scripts
      /\/evals?\//,   // Eval / benchmark / nightly test scripts — never production
      /\/bench(?:marks?)?\//,
      /\/fixtures?\//,
    ];

    return devPatterns.some(pattern => pattern.test(normalPath));
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
    const text = node.getText();

    // Check for debug/development keywords in the full condition text.
    // Catches: process.env.NODE_ENV === 'development', process.env.DEBUG,
    // isTruthyEnvValue(process.env.OPENCLAW_DEBUG_HEALTH), isDebug, __DEV__, etc.
    const devPatterns = [
      /NODE_ENV.*===.*['"]development['"]/,
      /NODE_ENV.*===.*['"]dev['"]/,
      /isDevelopment/,
      /isDebug/,
      /__DEV__/,
      /process\.env\.[A-Z_]*DEBUG/,
      /process\.env\.[A-Z_]*VERBOSE/,
    ];

    if (devPatterns.some(pattern => pattern.test(text))) {
      return true;
    }

    // Check for direct flag: if (isDevelopment) { ... } or if (DEBUG) { ... }
    if (ts.isIdentifier(node)) {
      const name = node.text.toLowerCase();
      return ['isdevelopment', 'isdev', 'isdebug', '__dev__', 'debug', 'verbose'].includes(name);
    }

    return false;
  }

  /**
   * Check if the console call is inside a logger/transport class implementation.
   * Logger classes (winston transports, custom loggers, etc.) legitimately wrap console.
   */
  private isInsideLoggerClass(node: ts.Node): boolean {
    let current: ts.Node | undefined = node.parent;

    while (current) {
      // Check if inside a class declaration or expression
      if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) {
        // Check if the class name or containing variable looks like a logger
        let className: string | null = null;

        if (ts.isClassDeclaration(current) && current.name) {
          className = current.name.text;
        } else if (ts.isClassExpression(current) && current.name) {
          className = current.name.text;
        } else if (ts.isVariableDeclaration(current.parent as ts.Node)) {
          const decl = current.parent as ts.VariableDeclaration;
          if (ts.isIdentifier(decl.name)) {
            className = decl.name.text;
          }
        }

        if (className) {
          const loggerClassPatterns = /logger|logging|transport|winston|pino|bunyan|log4|appender|handler|stream|writer|sink|reporter/i;
          if (loggerClassPatterns.test(className)) {
            return true;
          }
        }

        // Also check: class with 1+ log-level method AND the class name doesn't suggest a service/controller
        const classMembers = (current as ts.ClassDeclaration | ts.ClassExpression).members;
        const logLevelNames = ['log', 'warn', 'error', 'info', 'debug', 'trace', 'fatal', 'verbose', 'write'];
        const logMethodCount = classMembers.filter((m: ts.ClassElement) =>
          ts.isMethodDeclaration(m) && ts.isIdentifier(m.name) &&
          logLevelNames.includes(m.name.text.toLowerCase())
        ).length;
        // Single log method is enough if the class name suggests it's a logger/transport
        if (logMethodCount >= 1 && className && /transport|appender|sink|writer|stream|handler/i.test(className)) {
          return true;
        }
      }

      // Check if inside a method whose name is a standard log level
      if (ts.isMethodDeclaration(current) && ts.isIdentifier(current.name)) {
        const methodName = current.name.text.toLowerCase();
        const logLevelMethods = ['log', 'warn', 'error', 'info', 'debug', 'trace', 'fatal', 'verbose', 'write'];

        if (logLevelMethods.includes(methodName)) {
          // Only skip if it's inside a class that has multiple log methods (logger pattern)
          const parentClass = current.parent;
          if (ts.isClassDeclaration(parentClass) || ts.isClassExpression(parentClass)) {
            const logMethods = parentClass.members.filter((m: ts.ClassElement) =>
              ts.isMethodDeclaration(m) &&
              ts.isIdentifier(m.name) &&
              logLevelMethods.includes(m.name.text.toLowerCase())
            );
            // If the class has 2+ log-level methods, it's a logger implementation
            if (logMethods.length >= 2) {
              return true;
            }
          }
        }
      }

      current = current.parent;
    }

    return false;
  }

  /**
   * Check if a console call has an eslint-disable comment for no-console.
   * If developers explicitly suppressed the lint rule, they've acknowledged this console usage.
   */
  private hasEslintDisableComment(node: ts.Node, context: AnalysisContext): boolean {
    const sourceFile = context.sourceFile;
    const nodeStart = node.getStart(sourceFile);
    const lineNumber = sourceFile.getLineAndCharacterOfPosition(nodeStart).line;

    // Check the line above for eslint-disable-next-line
    if (lineNumber > 0) {
      const prevLineStart = sourceFile.getLineStarts()[lineNumber - 1];
      const prevLineEnd = sourceFile.getLineStarts()[lineNumber] || sourceFile.getEnd();
      const prevLineText = sourceFile.text.substring(prevLineStart, prevLineEnd);
      if (/eslint-disable(?:-next-line)?.*no-console/.test(prevLineText)) {
        return true;
      }
    }

    // Check same line for inline eslint-disable
    const lineStart = sourceFile.getLineStarts()[lineNumber];
    const lineEnd = sourceFile.getLineStarts()[lineNumber + 1] || sourceFile.getEnd();
    const lineText = sourceFile.text.substring(lineStart, lineEnd);
    if (/eslint-disable(?:-line)?.*no-console/.test(lineText)) {
      return true;
    }

    return false;
  }

  /**
   * Check if the file imports the 'debug' npm package.
   * The debug package is a controlled logging solution, not console pollution.
   */
  private fileImportsDebugPackage(context: AnalysisContext): boolean {
    const imports = getImports(context.sourceFile);
    return imports.some(imp => imp.moduleName === 'debug');
  }

  /**
   * Check if a call expression is a debug() call from the debug package.
   * Matches: debug('namespace')(...), createDebug(...), or a variable bound from debug.
   * Since we cannot do full binding analysis, we match calls to identifiers named 'debug'
   * or common patterns like debug('app:server').
   */
  private isDebugPackageCall(node: ts.CallExpression): boolean {
    const { expression } = node;
    // Direct call: debug(...)
    if (ts.isIdentifier(expression) && expression.text === 'debug') {
      return true;
    }
    // Curried call: debug('namespace')(...) — the outer call's expression is itself a call to debug
    if (ts.isCallExpression(expression)) {
      const inner = expression.expression;
      if (ts.isIdentifier(inner) && inner.text === 'debug') {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if the console call is inside a catch block.
   * Console in error handlers is commonly intentional for debugging production issues.
   */
  private isInCatchBlock(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      if (ts.isCatchClause(current)) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Check if any argument to the console call is a JSON.stringify() call.
   * Structured logging suggests intentional, controlled output.
   */
  private hasStructuredLoggingArg(node: ts.CallExpression): boolean {
    if (!node.arguments) return false;
    for (const arg of node.arguments) {
      if (
        ts.isCallExpression(arg) &&
        ts.isPropertyAccessExpression(arg.expression) &&
        ts.isIdentifier(arg.expression.expression) &&
        arg.expression.expression.text === 'JSON' &&
        arg.expression.name.text === 'stringify'
      ) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if any argument passes through a known anonymization/masking function.
   * These functions indicate the developer is being careful about what's logged.
   */
  private hasAnonymizationArg(node: ts.CallExpression): boolean {
    if (!node.arguments) return false;

    const anonymizationPattern = /hash|mask|redact|anonymize|sanitize|obfuscate|censor|scrub|encrypt/i;

    for (const arg of node.arguments) {
      if (ts.isCallExpression(arg)) {
        const callee = arg.expression;
        let funcName: string | null = null;

        if (ts.isIdentifier(callee)) {
          funcName = callee.text;
        } else if (ts.isPropertyAccessExpression(callee)) {
          funcName = callee.name.text;
        }

        if (funcName && anonymizationPattern.test(funcName)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Check if a keyword appears at a logical identifier boundary in text.
   * Uses the original (non-lowercased) text to correctly detect camelCase transitions.
   *
   * Matches: password, user_password, getPassword, this.password, PASSWORD_HASH
   * Does NOT match: pin in typing, health in unhealthy
   */
  private hasKeywordAtBoundary(text: string, keyword: string): boolean {
    const lower = keyword.toLowerCase();
    const capitalized = keyword.charAt(0).toUpperCase() + keyword.slice(1).toLowerCase();
    const upper = keyword.toUpperCase();

    // Pattern 1: lowercase keyword preceded by non-letter or start, followed by non-lowercase or end
    // Handles: password, user_password, .password, (password), password_hash, "password"
    if (new RegExp(`(?:^|[^a-zA-Z])${lower}(?:[^a-z]|$)`).test(text)) return true;

    // Pattern 2: capitalized keyword preceded by a lowercase letter (camelCase transition)
    // Handles: getPassword, checkHealth, mySession
    if (new RegExp(`[a-z]${capitalized}`).test(text)) return true;

    // Pattern 3: SCREAMING_SNAKE_CASE
    // Handles: DB_PASSWORD, API_TOKEN
    if (new RegExp(`(?:^|[^a-zA-Z])${upper}(?:[^a-zA-Z]|$)`).test(text)) return true;

    return false;
  }

  /**
   * Returns true if the sensitive keyword appears only as a functional modifier prefix
   * in an identifier, rather than being the primary data concept itself.
   *
   * Splits the identifier into camelCase / snake_case words. If the keyword is NOT the
   * final word AND every subsequent word is an "operational qualifier" (manager, service,
   * check, etc.), the identifier describes functionality AROUND the concept — not the
   * sensitive data value itself — so it should not be flagged.
   *
   * Examples:
   *   sessionManager → ['session', 'manager'] → 'session' prefix, 'manager' operational → non-sensitive
   *   healthCheck    → ['health',  'check']   → 'health'  prefix, 'check'   operational → non-sensitive
   *   authService    → ['auth',    'service'] → 'auth'    prefix, 'service' operational → non-sensitive
   *   userPassword   → ['user',    'password']→ 'password' is LAST word                → sensitive
   *   sessionToken   → ['session', 'token']   → 'token' is LAST word                   → sensitive
   */
  private isKeywordInNonSensitiveContext(identifier: string, keyword: string): boolean {
    // Normalise the identifier into lowercase words by splitting at camelCase and
    // underscore / hyphen / dot boundaries.
    const words = identifier
      .replace(/([a-z])([A-Z])/g, '$1_$2')  // camelCase → snake_case
      .toLowerCase()
      .split(/[_\-.\s]+/)
      .filter(w => w.length > 0);

    const keywordLower = keyword.toLowerCase();

    // Require an exact word match (not a sub-string of a longer word).
    const keywordIndex = words.indexOf(keywordLower);
    if (keywordIndex === -1) return false;

    // If the keyword IS the last word, the identifier represents the data itself.
    if (keywordIndex === words.length - 1) return false;

    // Keyword is a non-final word. Every subsequent word must be a purely operational
    // qualifier that signals infrastructure / functionality rather than a data value.
    const operationalQualifiers = new Set([
      // Architecture / DI
      'manager', 'service', 'handler', 'middleware', 'provider', 'factory',
      'builder', 'resolver', 'registry', 'repository', 'controller', 'adapter',
      // Configuration
      'config', 'options', 'settings', 'policy', 'rules',
      // Behavioural type descriptors (not data values)
      'type', 'kind', 'scheme', 'method', 'mode', 'strategy',
      // Monitoring / health
      'check', 'status', 'monitor', 'ping', 'metric', 'endpoint',
      // Counting / sizing
      'count', 'index', 'size', 'length', 'limit',
      // Async infrastructure
      'store', 'cache', 'queue', 'worker', 'job', 'sender', 'template',
      // Validation
      'validator', 'verifier', 'parser',
    ]);

    const followingWords = words.slice(keywordIndex + 1);
    return followingWords.every(w => operationalQualifiers.has(w));
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
      // Skip plain string literals — they are message text, not data.
      // e.g., console.error('Error changing password:', err) — 'password' is in the
      // message string, not in a variable being logged. Only identifiers and
      // expressions contain data values worth checking.
      if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
        continue;
      }

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

      // Use original text (not lowercased) for boundary detection that respects camelCase
      const argTextOriginal = arg.getText();

      for (const keyword of sensitiveKeywords) {
        // Check if keyword appears at a logical identifier boundary in the original text.
        // Matches: password, user_password, getPassword, this.password, PASSWORD
        // Does NOT match: pin in typing, health in unhealthy
        if (!this.hasKeywordAtBoundary(argTextOriginal, keyword)) {
          continue;
        }

        // Keyword found at boundary — check for non-sensitive context dynamically.
        // Extract individual identifier tokens from the arg expression and check if
        // any token contains the keyword only as a functional modifier prefix
        // (e.g., sessionManager, healthCheck, authService).
        const identifierTokens = argTextOriginal
          .split(/[.[\](),'"\s]+/)
          .filter(p => /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(p));

        if (identifierTokens.some(token => this.isKeywordInNonSensitiveContext(token, keyword))) {
          continue; // Keyword is a functional modifier, not the data itself
        }

        return {
          isSensitive: true,
          reason: `variable name contains '${keyword}'`
        };
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

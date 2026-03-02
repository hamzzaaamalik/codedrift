/**
 * Unsafe Regex Detector
 * Detects regex patterns vulnerable to ReDoS (Regular Expression Denial of Service)
 * AND dynamic RegExp construction from user-controlled input (regex injection)
 * Priority: HIGH → CRITICAL (security/availability issue)
 *
 * AI often generates functionally correct but unsafe regex patterns:
 * - Nested quantifiers: (a+)+, (a*)*
 * - Catastrophic backtracking
 * - Exponential time complexity on certain inputs
 * - new RegExp(req.query.search) — direct regex injection from user input
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';
import safeRegex from 'safe-regex2';

export class UnsafeRegexDetector extends BaseEngine {
  readonly name = 'unsafe-regex';

  /** Sources of user-controlled input */
  private static readonly USER_INPUT_PATTERNS = [
    /^req(uest)?\.(query|params|body)/,
    /^ctx\.(query|params|request\.body)/,
  ];

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      // Check regex literals: /pattern/flags
      if (ts.isRegularExpressionLiteral(node)) {
        const issue = this.checkRegexLiteral(node, context);
        if (issue) {
          issues.push(issue);
        }
      }

      // Check RegExp constructor: new RegExp('pattern')
      if (ts.isNewExpression(node)) {
        const issue = this.checkRegExpConstructor(node, context);
        if (issue) {
          issues.push(issue);
        }
        // Also check for dynamic user input: new RegExp(req.query.search)
        const dynamicIssue = this.checkDynamicRegExp(node, context);
        if (dynamicIssue) {
          issues.push(dynamicIssue);
        }
      }

      // Check RegExp() without new keyword
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'RegExp') {
        // Check for ReDoS in static string patterns: RegExp('(a+)+')
        const redosIssue = this.checkRegExpCallPattern(node, context);
        if (redosIssue) {
          issues.push(redosIssue);
        }
        // Check for dynamic user input: RegExp(req.query.search)
        const dynamicIssue = this.checkDynamicRegExp(node, context);
        if (dynamicIssue) {
          issues.push(dynamicIssue);
        }
      }
    });

    return issues;
  }

  /**
   * Check regex literal for unsafe patterns
   */
  private checkRegexLiteral(node: ts.RegularExpressionLiteral, context: AnalysisContext): Issue | null {
    const regexText = node.text;

    // Extract pattern from /pattern/flags format
    const match = regexText.match(/^\/(.+)\/([gimsuvy]*)$/);
    if (!match) {
      return null;
    }

    const [, pattern] = match;

    return this.checkPattern(pattern, node, context);
  }

  /**
   * Check RegExp constructor for unsafe patterns
   */
  private checkRegExpConstructor(node: ts.NewExpression, context: AnalysisContext): Issue | null {
    // Check if it's new RegExp(...)
    if (!ts.isIdentifier(node.expression) || node.expression.text !== 'RegExp') {
      return null;
    }

    // Get first argument (the pattern)
    if (!node.arguments || node.arguments.length === 0) {
      return null;
    }

    const patternArg = node.arguments[0];

    // Only check string literals (dynamic patterns can't be analyzed)
    if (!ts.isStringLiteral(patternArg)) {
      return null;
    }

    const pattern = patternArg.text;

    return this.checkPattern(pattern, node, context);
  }

  /**
   * Check RegExp() call (without new) for unsafe static patterns.
   * Mirrors checkRegExpConstructor but for CallExpression instead of NewExpression.
   */
  private checkRegExpCallPattern(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    if (!node.arguments || node.arguments.length === 0) {
      return null;
    }

    const patternArg = node.arguments[0];

    // Only check string literals (dynamic patterns handled by checkDynamicRegExp)
    if (!ts.isStringLiteral(patternArg)) {
      return null;
    }

    const pattern = patternArg.text;
    return this.checkPattern(pattern, node, context);
  }

  /**
   * Check if regex pattern is unsafe
   *
   * Confidence: High - safe-regex2 uses static analysis to detect known ReDoS patterns
   * The library has high accuracy for detecting exponential time complexity in regex
   */
  private checkPattern(pattern: string, node: ts.Node, context: AnalysisContext): Issue | null {
    // Skip empty patterns
    if (!pattern || pattern.length === 0) {
      return null;
    }

    // Check with safe-regex2
    const result = safeRegex(pattern);

    if (!result) {
      // Pattern is unsafe - downgraded to warning (was error)
      // ReDoS is often low-risk in practice (error parsing, markdown, sanitization)
      // Only genuinely user-facing regex on untrusted input is critical
      return this.createIssue(
        context,
        node,
        'Unsafe regex pattern - vulnerable to ReDoS (Regular Expression Denial of Service)',
        {
          severity: 'warning',
          suggestion: 'Simplify regex pattern. Avoid nested quantifiers like (a+)+, (a*)*, or (a+)*. If this regex processes untrusted user input, this is a critical security issue.',
          confidence: 'high',
        }
      );
    }

    return null;
  }

  /**
   * Check if new RegExp() / RegExp() uses user-controlled input
   * Flags as CRITICAL — user-controlled regex enables ReDoS and regex injection
   */
  private checkDynamicRegExp(node: ts.NewExpression | ts.CallExpression, context: AnalysisContext): Issue | null {
    if (!node.arguments || node.arguments.length === 0) {
      return null;
    }

    const patternArg = node.arguments[0];

    // Skip string literals — already handled by checkRegExpConstructor / checkPattern
    if (ts.isStringLiteral(patternArg) || ts.isNoSubstitutionTemplateLiteral(patternArg)) {
      return null;
    }

    // Check if the argument is directly user input
    if (this.isUserInputExpression(patternArg)) {
      return this.createIssue(
        context,
        node,
        'User-controlled input passed to RegExp constructor — regex injection and ReDoS vulnerability',
        {
          severity: 'error',
          suggestion: `User-controlled input passed to new RegExp() enables ReDoS attacks and regex injection. Sanitize input with a function that escapes regex special characters, or use a fixed pattern with string matching instead.`,
          confidence: 'high',
        }
      );
    }

    // Check if it traces back to user input via variable
    if (ts.isIdentifier(patternArg)) {
      if (this.tracesBackToUserInput(patternArg, node)) {
        return this.createIssue(
          context,
          node,
          'User-controlled input passed to RegExp constructor — regex injection and ReDoS vulnerability',
          {
            severity: 'error',
            suggestion: `User-controlled input passed to new RegExp() enables ReDoS attacks and regex injection. Sanitize input with a function that escapes regex special characters, or use a fixed pattern with string matching instead.`,
            confidence: 'high',
          }
        );
      }
    }

    // Check template literals that embed user input: new RegExp(`${req.query.search}`)
    if (ts.isTemplateExpression(patternArg)) {
      for (const span of patternArg.templateSpans) {
        if (this.isUserInputExpression(span.expression)) {
          return this.createIssue(
            context,
            node,
            'User-controlled input embedded in RegExp template — regex injection and ReDoS vulnerability',
            {
              severity: 'error',
              suggestion: `User-controlled input interpolated into new RegExp() enables ReDoS attacks and regex injection. Sanitize input with a function that escapes regex special characters, or use a fixed pattern.`,
              confidence: 'high',
            }
          );
        }
        if (ts.isIdentifier(span.expression) && this.tracesBackToUserInput(span.expression, node)) {
          return this.createIssue(
            context,
            node,
            'User-controlled input embedded in RegExp template — regex injection and ReDoS vulnerability',
            {
              severity: 'error',
              suggestion: `User-controlled input interpolated into new RegExp() enables ReDoS attacks and regex injection. Sanitize input with a function that escapes regex special characters, or use a fixed pattern.`,
              confidence: 'high',
            }
          );
        }
      }
    }

    // Check binary expressions (concatenation): new RegExp(req.query.search + ".*")
    if (ts.isBinaryExpression(patternArg) && patternArg.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      if (this.containsUserInput(patternArg)) {
        return this.createIssue(
          context,
          node,
          'User-controlled input concatenated into RegExp — regex injection and ReDoS vulnerability',
          {
            severity: 'error',
            suggestion: `User-controlled input concatenated into new RegExp() enables ReDoS attacks and regex injection. Sanitize input with a function that escapes regex special characters, or use a fixed pattern.`,
            confidence: 'high',
          }
        );
      }
    }

    return null;
  }

  /**
   * Check if an expression directly references user input (req.query, req.params, req.body, etc.)
   */
  private isUserInputExpression(node: ts.Node): boolean {
    const text = node.getText();
    return UnsafeRegexDetector.USER_INPUT_PATTERNS.some(pattern => pattern.test(text));
  }

  /**
   * Check if a binary expression tree contains any user input references
   */
  private containsUserInput(node: ts.Node): boolean {
    if (this.isUserInputExpression(node)) {
      return true;
    }
    if (ts.isIdentifier(node)) {
      // We can't easily trace here without scope, but check common names
      return false;
    }
    if (ts.isBinaryExpression(node)) {
      return this.containsUserInput(node.left) || this.containsUserInput(node.right);
    }
    if (ts.isParenthesizedExpression(node)) {
      return this.containsUserInput(node.expression);
    }
    return false;
  }

  /**
   * Trace an identifier back to its declaration to see if it originates from user input
   */
  private tracesBackToUserInput(identifier: ts.Identifier, searchScope: ts.Node): boolean {
    const varName = identifier.text;
    let comesFromUserInput = false;

    // Walk up to the enclosing function scope
    let currentScope = searchScope.parent;
    while (currentScope && !ts.isSourceFile(currentScope)) {
      if (this.isFunctionLike(currentScope)) {
        break;
      }
      currentScope = currentScope.parent;
    }

    if (!currentScope) {
      return false;
    }

    traverse(currentScope, (node) => {
      if (comesFromUserInput) return; // short-circuit

      // const pattern = req.query.search
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === varName) {
        if (node.initializer && this.isUserInputExpression(node.initializer)) {
          comesFromUserInput = true;
        }
      }

      // const { search } = req.query
      if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) {
          if (ts.isBindingElement(element) && ts.isIdentifier(element.name) && element.name.text === varName) {
            if (node.initializer && this.isUserInputExpression(node.initializer)) {
              comesFromUserInput = true;
            }
          }
          // Renamed binding: const { search: s } = req.query
          if (ts.isBindingElement(element) && element.propertyName && ts.isIdentifier(element.propertyName)) {
            if (ts.isIdentifier(element.name) && element.name.text === varName) {
              if (node.initializer && this.isUserInputExpression(node.initializer)) {
                comesFromUserInput = true;
              }
            }
          }
        }
      }
    });

    return comesFromUserInput;
  }

  /**
   * Check if node is function-like
   */
  private isFunctionLike(node: ts.Node): boolean {
    return (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    );
  }
}

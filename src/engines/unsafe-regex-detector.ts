/**
 * Unsafe Regex Detector
 * Detects regex patterns vulnerable to ReDoS (Regular Expression Denial of Service)
 * Priority: HIGH (security/availability issue)
 *
 * AI often generates functionally correct but unsafe regex patterns:
 * - Nested quantifiers: (a+)+, (a*)*
 * - Catastrophic backtracking
 * - Exponential time complexity on certain inputs
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';
import safeRegex from 'safe-regex2';

export class UnsafeRegexDetector extends BaseEngine {
  readonly name = 'unsafe-regex';

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
   * Check if regex pattern is unsafe
   */
  private checkPattern(pattern: string, node: ts.Node, context: AnalysisContext): Issue | null {
    // Skip empty patterns
    if (!pattern || pattern.length === 0) {
      return null;
    }

    // Check with safe-regex2
    const result = safeRegex(pattern);

    if (!result) {
      // Pattern is unsafe
      return this.createIssue(
        context,
        node,
        'Unsafe regex pattern - vulnerable to ReDoS (Regular Expression Denial of Service)',
        {
          severity: 'error',
          suggestion: 'Simplify regex pattern. Avoid nested quantifiers like (a+)+, (a*)*, or (a+)*',
        }
      );
    }

    return null;
  }
}

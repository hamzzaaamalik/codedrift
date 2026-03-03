/**
 * Unsafe Regex Detector
 * Two separate detection paths:
 *   Path A: Static ReDoS — regex literals with catastrophic backtracking
 *   Path B: Dynamic Regex Injection — user input passed to RegExp() constructor
 *
 * AI often generates functionally correct but unsafe regex patterns:
 * - Nested quantifiers: (a+)+, (a*)*
 * - Overlapping alternation: (\s|[ \t])+
 * - Quantified overlap before anchor: \w+\d+$
 * - new RegExp(req.query.search) — direct regex injection from user input
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';
import safeRegex from 'safe-regex2';

export class UnsafeRegexDetector extends BaseEngine {
  readonly name = 'unsafe-regex';

  // ──────────────────────── Data Structures ────────────────────────

  /** Sources of user-controlled input */
  private static readonly USER_INPUT_PATTERNS = [
    /^req(uest)?\.(query|params|body)/,
    /^ctx\.(query|params|request\.body)/,
    /^request\.(params|query|payload)/,      // Hapi
    /^req(uest)?\.headers/,                  // Headers
    /^ctx\.headers/,                         // Koa headers
    /^message\.data/,                        // WebSocket
    /^socket\.data/,                         // Socket
  ];

  /** Functions that properly escape regex special characters → input is safe */
  private static readonly ESCAPE_FUNCTION_NAMES = new Set([
    'escaperegexp', 'escaperegex', 'escapestringregexp', 'escapestringregex',
    'regexescape', 'regexpescape', 'quotemeta',
  ]);

  /** Trusted (non-attacker-controlled) data sources */
  private static readonly TRUSTED_SOURCE_PATTERNS = [
    /^process\.env\./,
    /^config\./,
    /^settings\./,
    /^constants?\./i,
    /^options\./,
    /^ENV\./,
  ];

  /** Methods that produce bounded-length output — regex on their result is lower risk */
  private static readonly BOUNDED_INPUT_METHODS = new Set([
    'charat', 'substring', 'substr', 'slice', 'trim',
    'trimstart', 'trimend', 'padstart', 'padend', 'split',
  ]);

  /** Character class subset relationships for overlap detection */
  private static readonly SUBSET_PAIRS: [RegExp, RegExp][] = [
    [/\\w/, /\\d/],          // \w ⊃ \d
    [/\\s/, /\\t/],          // \s ⊃ \t
    [/\\s/, / /],            // \s ⊃ space
    [/\./, /\\w/],           // . ⊃ \w
    [/\./, /\\d/],           // . ⊃ \d
    [/\./, /\\s/],           // . ⊃ \s
    [/\./, /\[/],            // . ⊃ any char class
  ];

  // ──────────────────────── Main Analyze ────────────────────────

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];
    const flaggedLines = new Set<number>();

    traverse(context.sourceFile, (node) => {
      let issue: Issue | null = null;

      // Path A: Regex literals → static ReDoS check
      if (ts.isRegularExpressionLiteral(node)) {
        issue = this.checkRegexLiteral(node, context);
      }

      // Path A+B: new RegExp(...)
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'RegExp') {
        // Path A: static string pattern
        issue = issue || this.checkRegExpStaticPattern(node, context);
        // Path B: dynamic user input
        issue = issue || this.checkDynamicRegExp(node, context);
      }

      // Path A+B: RegExp(...) without new
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'RegExp') {
        issue = issue || this.checkRegExpStaticPattern(node, context);
        issue = issue || this.checkDynamicRegExp(node, context);
      }

      if (issue && !flaggedLines.has(issue.location.line)) {
        flaggedLines.add(issue.location.line);
        issues.push(issue);
      }
    });

    return issues;
  }

  // ──────────────────── Path A: Static ReDoS ────────────────────

  /**
   * Check regex literal for unsafe patterns: /pattern/flags
   */
  private checkRegexLiteral(node: ts.RegularExpressionLiteral, context: AnalysisContext): Issue | null {
    const regexText = node.text;
    const match = regexText.match(/^\/(.+)\/([gimsuvy]*)$/);
    if (!match) return null;
    const [, pattern] = match;
    return this.checkPattern(pattern, node, context);
  }

  /**
   * Check new RegExp('pattern') or RegExp('pattern') with a string literal arg
   */
  private checkRegExpStaticPattern(node: ts.NewExpression | ts.CallExpression, context: AnalysisContext): Issue | null {
    if (!node.arguments || node.arguments.length === 0) return null;
    const patternArg = node.arguments[0];

    // Only check string literals / no-substitution templates
    if (ts.isStringLiteral(patternArg)) {
      return this.checkPattern(patternArg.text, node, context);
    }
    if (ts.isNoSubstitutionTemplateLiteral(patternArg)) {
      return this.checkPattern(patternArg.text, node, context);
    }
    return null;
  }

  /**
   * Core static pattern analysis.
   * Uses safe-regex2 as primary detector, supplements with overlapping alternation
   * and quantified overlap checks. Context-aware severity adjustment.
   */
  private checkPattern(pattern: string, node: ts.Node, context: AnalysisContext): Issue | null {
    if (!pattern || pattern.length === 0) return null;

    // Primary: safe-regex2 check
    const isSafe = safeRegex(pattern);

    if (!isSafe) {
      const severity = this.getStaticReDoSSeverity(node, context);
      return this.createIssue(
        context,
        node,
        'Unsafe regex pattern — vulnerable to ReDoS (Regular Expression Denial of Service)',
        {
          severity,
          suggestion: `Rewrite this regex to avoid nested quantifiers like (a+)+, (a*)*, or (a+)*. ${severity === 'error' ? 'This regex is used in a context that processes user input — fix immediately.' : 'If this regex processes untrusted user input, this is a critical security issue.'}`,
          confidence: 'high',
        }
      );
    }

    // Supplementary: overlapping alternation with quantifier
    if (this.hasOverlappingAlternation(pattern)) {
      const severity = this.getStaticReDoSSeverity(node, context);
      return this.createIssue(
        context,
        node,
        'Regex has overlapping alternation with quantifier — potential ReDoS vulnerability',
        {
          severity: severity === 'error' ? 'error' : 'warning',
          suggestion: 'Alternation branches can match the same characters, causing exponential backtracking. Simplify by merging overlapping branches into a single character class.',
          confidence: 'medium',
        }
      );
    }

    // Supplementary: quantified overlap before anchor
    if (this.hasQuantifiedOverlap(pattern)) {
      const severity = this.getStaticReDoSSeverity(node, context);
      return this.createIssue(
        context,
        node,
        'Regex has overlapping quantified groups before anchor — potential ReDoS vulnerability',
        {
          severity: severity === 'error' ? 'error' : 'warning',
          suggestion: 'Adjacent quantified groups match overlapping characters before an anchor ($, \\b), causing backtracking on non-matching input. Rewrite to use non-overlapping character classes.',
          confidence: 'medium',
        }
      );
    }

    return null;
  }

  /**
   * Determine severity for static ReDoS based on context.
   * 'error' if the regex processes user input or is in a route handler.
   * 'warning' otherwise.
   */
  private getStaticReDoSSeverity(node: ts.Node, _context: AnalysisContext): 'error' | 'warning' {
    // Bounded input demotes severity — regex on split lines, charAt, substring is lower risk
    if (this.isBoundedInput(node)) return 'warning';
    // Check if regex is used on user input (.match/.test on req.body etc.)
    if (this.regexAppliesToUserInput(node)) return 'error';
    // Check if we're in a route handler
    if (this.isInRouteHandler(node)) return 'error';
    // Check if we're in a validator function
    if (this.isInValidatorFunction(node)) return 'error';
    return 'warning';
  }

  /**
   * Check if the regex node is used on user-controlled input.
   * Looks for patterns like: userInput.match(regex), regex.test(userInput)
   */
  private regexAppliesToUserInput(node: ts.Node): boolean {
    // Case 1: regex is argument to .match/.search/.split: userInput.match(/pattern/)
    if (node.parent && ts.isCallExpression(node.parent)) {
      const call = node.parent;
      if (ts.isPropertyAccessExpression(call.expression)) {
        const methodName = call.expression.name.text;
        if (['match', 'search', 'split', 'replace', 'replaceAll'].includes(methodName)) {
          const objText = call.expression.expression.getText();
          if (UnsafeRegexDetector.USER_INPUT_PATTERNS.some(p => p.test(objText))) return true;
        }
      }
    }

    // Case 2: regex.test(userInput) — regex is the object, user input is argument
    // Check if the regex is stored in a variable used in .test()
    // This is harder to detect statically — check the enclosing function for .test() on user input
    let funcScope = node.parent;
    while (funcScope && !this.isFunctionLike(funcScope) && !ts.isSourceFile(funcScope)) {
      funcScope = funcScope.parent;
    }
    if (funcScope && !ts.isSourceFile(funcScope)) {
      const funcText = funcScope.getText();
      if (UnsafeRegexDetector.USER_INPUT_PATTERNS.some(p => p.test(funcText))) {
        // Function references user input — likely the regex processes it
        return true;
      }
    }

    return false;
  }

  /**
   * Check if the node is inside a route handler (Express, Koa, Hapi, Fastify).
   */
  private isInRouteHandler(node: ts.Node): boolean {
    let current: ts.Node | undefined = node.parent;

    while (current && !ts.isSourceFile(current)) {
      if (this.isFunctionLike(current)) {
        const funcNode = current as ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;
        if (funcNode.parameters && funcNode.parameters.length >= 1) {
          const firstParam = funcNode.parameters[0];
          if (ts.isIdentifier(firstParam.name)) {
            const firstName = firstParam.name.text.toLowerCase();
            if (firstName === 'ctx') return true;
            if (funcNode.parameters.length >= 2) {
              const secondParam = funcNode.parameters[1];
              if (ts.isIdentifier(secondParam.name)) {
                const secondName = secondParam.name.text.toLowerCase();
                if ((firstName === 'req' || firstName === 'request') &&
                    (secondName === 'res' || secondName === 'response' || secondName === 'reply' || secondName === 'h')) {
                  return true;
                }
              }
            }
          }
        }
      }

      if (ts.isCallExpression(current)) {
        const expr = current.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const methodName = expr.name.text.toLowerCase();
          const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'all'];
          if (httpMethods.includes(methodName)) {
            const objText = expr.expression.getText().toLowerCase();
            if (/^(app|router|route|server|api|fastify|instance)$/.test(objText)) {
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
   * Check if the node is inside a validator/sanitizer function.
   */
  private isInValidatorFunction(node: ts.Node): boolean {
    let current: ts.Node | undefined = node.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isFunctionDeclaration(current) && current.name) {
        if (/validat|sanitiz|check|verify|parse/i.test(current.name.text)) return true;
      }
      if (ts.isVariableDeclaration(current) && ts.isIdentifier(current.name)) {
        if (/validat|sanitiz|check|verify|parse/i.test(current.name.text)) return true;
      }
      if (ts.isMethodDeclaration(current) && ts.isIdentifier(current.name)) {
        if (/validat|sanitiz|check|verify|parse/i.test(current.name.text)) return true;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Check if the regex operates on bounded-length data.
   * e.g., line from .split('\n'), str.charAt(0), str.substring(0, 50)
   * Bounded input makes ReDoS less exploitable — demote severity.
   */
  private isBoundedInput(node: ts.Node): boolean {
    // Case 1: regex is argument to .match/.test/.search on a bounded expression
    // e.g., line.match(/pattern/) where line comes from .split()
    if (node.parent && ts.isCallExpression(node.parent)) {
      const call = node.parent;
      if (ts.isPropertyAccessExpression(call.expression)) {
        const methodName = call.expression.name.text;
        if (['match', 'search', 'test', 'replace', 'replaceAll'].includes(methodName)) {
          const obj = call.expression.expression;
          // Direct: str.charAt(0).match(regex)
          if (ts.isCallExpression(obj) && ts.isPropertyAccessExpression(obj.expression)) {
            const innerMethod = obj.expression.name.text.toLowerCase();
            if (UnsafeRegexDetector.BOUNDED_INPUT_METHODS.has(innerMethod)) return true;
          }
          // Variable: check if the variable was assigned from a bounded method
          if (ts.isIdentifier(obj)) {
            if (this.variableComesFromBoundedMethod(obj)) return true;
          }
        }
      }
    }

    // Case 2: Check enclosing iteration over split results
    // e.g., .split('\n').map(line => line.match(regex)), lines.map(line => ...)
    // Walk up past arrow function callbacks to find .map/.forEach on split source
    let current: ts.Node | undefined = node.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)) {
        const method = current.expression.name.text;
        if (['map', 'foreach', 'filter', 'find', 'some', 'every', 'flatmap', 'reduce'].includes(method.toLowerCase())) {
          const iterObj = current.expression.expression;
          // Direct: str.split('\n').map(...)
          if (ts.isCallExpression(iterObj) && ts.isPropertyAccessExpression(iterObj.expression)) {
            if (iterObj.expression.name.text.toLowerCase() === 'split') return true;
          }
          // Variable: lines = str.split('\n'); lines.map(...)
          if (ts.isIdentifier(iterObj) && this.variableComesFromBoundedMethod(iterObj)) return true;
        }
      }
      // Stop at enclosing non-callback function (route handler, named function, etc.)
      // But allow walking through arrow functions that are arguments to .map/.forEach etc.
      if (this.isFunctionLike(current) && current !== node.parent) {
        // We're at a function boundary — only continue if this function is a callback arg
        if (current.parent && ts.isCallExpression(current.parent)) {
          // This is a callback — keep walking
        } else {
          break;
        }
      }
      current = current.parent;
    }

    return false;
  }

  /**
   * Check if an identifier was assigned from a bounded method call (.split, .charAt, etc.)
   */
  private variableComesFromBoundedMethod(identifier: ts.Identifier): boolean {
    const varName = identifier.text;
    let scope: ts.Node | undefined = identifier.parent;
    while (scope && !this.isFunctionLike(scope) && !ts.isSourceFile(scope)) {
      scope = scope.parent;
    }
    if (!scope) return false;

    let found = false;
    traverse(scope, (node) => {
      if (found) return;
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === varName && node.initializer) {
        // const line = str.charAt(0)  or  const lines = str.split('\n')
        if (ts.isCallExpression(node.initializer) && ts.isPropertyAccessExpression(node.initializer.expression)) {
          const method = node.initializer.expression.name.text.toLowerCase();
          if (UnsafeRegexDetector.BOUNDED_INPUT_METHODS.has(method)) {
            found = true;
          }
        }
      }
      // for (const line of str.split('\n')) — ForOfStatement
      if (ts.isForOfStatement(node)) {
        const decl = node.initializer;
        if (ts.isVariableDeclarationList(decl) && decl.declarations.length > 0) {
          const d = decl.declarations[0];
          if (ts.isIdentifier(d.name) && d.name.text === varName) {
            const expr = node.expression;
            if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression)) {
              if (expr.expression.name.text.toLowerCase() === 'split') {
                found = true;
              }
            }
          }
        }
      }
    });
    return found;
  }

  // ──────────── Supplementary ReDoS Detection ────────────

  /**
   * Detect overlapping alternation with quantifier.
   * Catches: (a|ab)+, (\s|[ \t])+, (\w|\d)+, (a?)+
   */
  private hasOverlappingAlternation(pattern: string): boolean {
    // Match groups with alternation followed by a quantifier: (alt1|alt2)+/*/{n,}
    const groupWithQuantifier = /\(([^()]+)\)[+*]\$?/g;
    let m;
    while ((m = groupWithQuantifier.exec(pattern)) !== null) {
      const groupContent = m[1];
      const alternatives = groupContent.split('|');
      if (alternatives.length < 2) continue;

      // Check if any pair of alternatives overlaps
      for (let i = 0; i < alternatives.length; i++) {
        for (let j = i + 1; j < alternatives.length; j++) {
          if (this.alternativesOverlap(alternatives[i], alternatives[j])) {
            return true;
          }
        }
      }
    }

    // Check (a?)+ pattern — optional in quantified group
    if (/\([^()]*\?\)[+*]/.test(pattern)) {
      return true;
    }

    return false;
  }

  /**
   * Check if two alternation branches overlap in the characters they can match.
   */
  private alternativesOverlap(a: string, b: string): boolean {
    // Direct prefix overlap: 'a' and 'ab' — 'a' matches start of 'ab'
    if (a.length > 0 && b.length > 0 && (b.startsWith(a) || a.startsWith(b))) {
      return true;
    }

    // Character class subset overlaps
    for (const [superset, subset] of UnsafeRegexDetector.SUBSET_PAIRS) {
      if ((superset.test(a) && subset.test(b)) || (superset.test(b) && subset.test(a))) {
        return true;
      }
    }

    // Identical patterns
    if (a === b) return true;

    return false;
  }

  /**
   * Detect quantified overlap before anchor.
   * Catches: \w+\d+$, .*[a-z]+$, .*\w+$
   */
  private hasQuantifiedOverlap(pattern: string): boolean {
    // Pattern: quantified_class quantified_class $ (end anchor)
    // Where the classes overlap
    const endAnchorPatterns = [
      // \w+\d+$ — \d is subset of \w
      /\\w[+*].*\\d[+*].*\$/,
      // .*[a-z]+$ — . includes [a-z]
      /\.\*.*\[[a-z]/i,
      // .*\w+$
      /\.\*.*\\w[+*].*\$/,
      // \w+[a-z]+$ or similar overlapping
      /\\w[+*].*\[a-z[^\]]*\][+*].*\$/i,
    ];

    for (const p of endAnchorPatterns) {
      if (p.test(pattern)) return true;
    }

    return false;
  }

  // ──────────── Path B: Dynamic Regex Injection ────────────

  /**
   * Check if new RegExp() / RegExp() uses user-controlled input.
   * Handles: direct input, variable tracing, template literals, concatenation,
   * function parameters. Skips escaped input and trusted sources.
   */
  private checkDynamicRegExp(node: ts.NewExpression | ts.CallExpression, context: AnalysisContext): Issue | null {
    if (!node.arguments || node.arguments.length === 0) return null;
    const patternArg = node.arguments[0];

    // Skip string literals and no-substitution templates — handled by Path A
    if (ts.isStringLiteral(patternArg) || ts.isNoSubstitutionTemplateLiteral(patternArg)) {
      return null;
    }

    // Check if the argument is directly user input
    if (this.isUserInputExpression(patternArg)) {
      // Check for escaping on the expression (e.g., escapeRegExp(req.query.s))
      if (this.isEscapedExpression(patternArg)) return null;

      return this.createIssue(
        context, node,
        'User-controlled input passed to RegExp constructor — regex injection and ReDoS vulnerability',
        {
          severity: 'error',
          suggestion: 'Escape user input with string.replace(/[.*+?^${}()|[\\]\\\\]/g, \'\\\\$&\') before passing to RegExp, or use string methods (includes, startsWith, indexOf) instead.',
          confidence: 'high',
        }
      );
    }

    // Check if it's an identifier that traces to user input
    if (ts.isIdentifier(patternArg)) {
      // Check escaping
      if (this.isEscapedVariable(patternArg, node)) return null;
      // Check trusted source
      if (this.tracesToTrustedSource(patternArg, node)) return null;

      // Trace to user input (multi-hop)
      const traceResult = this.traceVariable(patternArg, node);
      if (traceResult.isUserInput) {
        if (traceResult.isEscaped) return null;
        return this.createIssue(
          context, node,
          'User-controlled input passed to RegExp constructor — regex injection and ReDoS vulnerability',
          {
            severity: 'error',
            suggestion: 'Escape user input with string.replace(/[.*+?^${}()|[\\]\\\\]/g, \'\\\\$&\') before passing to RegExp, or use string methods (includes, startsWith, indexOf) instead.',
            confidence: traceResult.depth > 2 ? 'medium' : 'high',
          }
        );
      }

      // Check if it's a function parameter (could be user input)
      if (this.isFunctionParameter(patternArg)) {
        return this.createIssue(
          context, node,
          'Function parameter used in RegExp constructor — potential regex injection if parameter contains user input',
          {
            severity: 'warning',
            suggestion: 'If this parameter can contain user input, escape it with string.replace(/[.*+?^${}()|[\\]\\\\]/g, \'\\\\$&\') before passing to RegExp, or use string matching methods instead.',
            confidence: 'medium',
          }
        );
      }
    }

    // Check template literals with user input: new RegExp(`^${req.query.search}`)
    if (ts.isTemplateExpression(patternArg)) {
      for (const span of patternArg.templateSpans) {
        const expr = span.expression;
        if (this.isUserInputExpression(expr) && !this.isEscapedExpression(expr)) {
          return this.createIssue(
            context, node,
            'User-controlled input embedded in RegExp template — regex injection and ReDoS vulnerability',
            {
              severity: 'error',
              suggestion: 'Escape user input before interpolating into RegExp template. Use string.replace(/[.*+?^${}()|[\\]\\\\]/g, \'\\\\$&\') or a dedicated escapeRegExp function.',
              confidence: 'high',
            }
          );
        }
        if (ts.isIdentifier(expr)) {
          if (this.isEscapedVariable(expr, node)) continue;
          const traceResult = this.traceVariable(expr, node);
          if (traceResult.isUserInput && !traceResult.isEscaped) {
            return this.createIssue(
              context, node,
              'User-controlled input embedded in RegExp template — regex injection and ReDoS vulnerability',
              {
                severity: 'error',
                suggestion: 'Escape user input before interpolating into RegExp template. Use string.replace(/[.*+?^${}()|[\\]\\\\]/g, \'\\\\$&\') or a dedicated escapeRegExp function.',
                confidence: traceResult.depth > 2 ? 'medium' : 'high',
              }
            );
          }
        }
      }
    }

    // Check binary expressions (concatenation): new RegExp(req.query.search + ".*")
    if (ts.isBinaryExpression(patternArg) && patternArg.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      if (this.containsUserInput(patternArg, node)) {
        return this.createIssue(
          context, node,
          'User-controlled input concatenated into RegExp — regex injection and ReDoS vulnerability',
          {
            severity: 'error',
            suggestion: 'Escape user input before concatenating into RegExp. Use string.replace(/[.*+?^${}()|[\\]\\\\]/g, \'\\\\$&\') or a dedicated escapeRegExp function.',
            confidence: 'high',
          }
        );
      }
    }

    return null;
  }

  // ──────────── Input Detection ────────────

  /**
   * Check if an expression directly references user input
   */
  private isUserInputExpression(node: ts.Node): boolean {
    const text = node.getText();
    return UnsafeRegexDetector.USER_INPUT_PATTERNS.some(p => p.test(text));
  }

  /**
   * Check if a binary expression tree contains any user input references
   */
  private containsUserInput(node: ts.Node, scope: ts.Node): boolean {
    if (this.isUserInputExpression(node)) return true;
    if (ts.isIdentifier(node)) {
      const traceResult = this.traceVariable(node, scope);
      return traceResult.isUserInput && !traceResult.isEscaped;
    }
    if (ts.isBinaryExpression(node)) {
      return this.containsUserInput(node.left, scope) || this.containsUserInput(node.right, scope);
    }
    if (ts.isParenthesizedExpression(node)) {
      return this.containsUserInput(node.expression, scope);
    }
    return false;
  }

  // ──────────── Variable Tracing (Multi-Hop) ────────────

  /**
   * Trace an identifier back to its source with multi-hop support.
   * Returns structured info about what was found.
   */
  private traceVariable(identifier: ts.Identifier, searchScope: ts.Node, depth: number = 0): { isUserInput: boolean; isEscaped: boolean; isTrustedSource: boolean; depth: number } {
    if (depth > 3) return { isUserInput: false, isEscaped: false, isTrustedSource: false, depth };

    const varName = identifier.text;
    let result = { isUserInput: false, isEscaped: false, isTrustedSource: false, depth };

    // Find enclosing function scope
    let currentScope = searchScope.parent;
    while (currentScope && !ts.isSourceFile(currentScope)) {
      if (this.isFunctionLike(currentScope)) break;
      currentScope = currentScope.parent;
    }
    if (!currentScope) return result;

    traverse(currentScope, (node) => {
      if (result.isUserInput || result.isTrustedSource) return;

      // Simple declaration: const pattern = ...
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === varName) {
        if (!node.initializer) return;

        const initText = node.initializer.getText();

        // Check direct user input
        if (this.isUserInputExpression(node.initializer)) {
          result = { isUserInput: true, isEscaped: false, isTrustedSource: false, depth };
          return;
        }

        // Check trusted source
        if (UnsafeRegexDetector.TRUSTED_SOURCE_PATTERNS.some(p => p.test(initText))) {
          result = { isUserInput: false, isEscaped: false, isTrustedSource: true, depth };
          return;
        }

        // Check if initializer is an escape function call
        if (ts.isCallExpression(node.initializer)) {
          if (this.isEscapeCall(node.initializer)) {
            result = { isUserInput: true, isEscaped: true, isTrustedSource: false, depth };
            return;
          }

          // Check if initializer is a method call on another variable (e.g., q.toLowerCase())
          if (ts.isPropertyAccessExpression(node.initializer.expression)) {
            const obj = node.initializer.expression.expression;
            if (ts.isIdentifier(obj)) {
              const inner = this.traceVariable(obj, searchScope, depth + 1);
              if (inner.isUserInput) {
                // Check if the method is an escape (.replace with regex escape pattern)
                const methodName = node.initializer.expression.name.text;
                if (methodName === 'replace' && this.isInlineEscapeReplace(node.initializer)) {
                  result = { isUserInput: true, isEscaped: true, isTrustedSource: false, depth: inner.depth };
                } else {
                  result = { ...inner, depth: inner.depth };
                }
                return;
              }
            }
          }

          // Check if initializer is a function call wrapping another variable
          // e.g., const cleaned = sanitize(q)
          if (node.initializer.arguments.length > 0) {
            const firstArg = node.initializer.arguments[0];
            if (ts.isIdentifier(firstArg)) {
              const inner = this.traceVariable(firstArg, searchScope, depth + 1);
              if (inner.isUserInput) {
                result = { ...inner, depth: inner.depth };
                return;
              }
            }
          }
        }

        // Multi-hop: initializer is another identifier
        if (ts.isIdentifier(node.initializer)) {
          const inner = this.traceVariable(node.initializer, searchScope, depth + 1);
          result = inner;
          return;
        }

        // Template expression: const p = `^${q}`
        if (ts.isTemplateExpression(node.initializer)) {
          for (const span of node.initializer.templateSpans) {
            if (ts.isIdentifier(span.expression)) {
              const inner = this.traceVariable(span.expression, searchScope, depth + 1);
              if (inner.isUserInput) {
                result = inner;
                return;
              }
            }
            if (this.isUserInputExpression(span.expression)) {
              result = { isUserInput: true, isEscaped: false, isTrustedSource: false, depth };
              return;
            }
          }
        }
      }

      // Destructuring: const { search } = req.query
      if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name)) {
        for (const element of node.name.elements) {
          const elementName = ts.isBindingElement(element) && ts.isIdentifier(element.name) ? element.name.text : null;
          // Handle renamed: const { search: s } = req.query
          const renamedName = ts.isBindingElement(element) && element.propertyName && ts.isIdentifier(element.name) ? element.name.text : null;

          if ((elementName === varName || renamedName === varName) && node.initializer) {
            if (this.isUserInputExpression(node.initializer)) {
              result = { isUserInput: true, isEscaped: false, isTrustedSource: false, depth };
              return;
            }
            const initText = node.initializer.getText();
            if (UnsafeRegexDetector.TRUSTED_SOURCE_PATTERNS.some(p => p.test(initText))) {
              result = { isUserInput: false, isEscaped: false, isTrustedSource: true, depth };
              return;
            }
          }
        }
      }
    });

    return result;
  }

  // ──────────── Escaping Detection ────────────

  /**
   * Check if an expression is wrapped in an escaping function call.
   * e.g., escapeRegExp(req.query.search) or _.escapeRegExp(input)
   */
  private isEscapedExpression(node: ts.Node): boolean {
    // Check parent: is the expression an argument to an escape function?
    if (node.parent && ts.isCallExpression(node.parent)) {
      return this.isEscapeCall(node.parent);
    }
    return false;
  }

  /**
   * Check if an identifier variable was escaped before use.
   */
  private isEscapedVariable(identifier: ts.Identifier, searchScope: ts.Node): boolean {
    const traceResult = this.traceVariable(identifier, searchScope);
    return traceResult.isEscaped;
  }

  /**
   * Check if a CallExpression is a regex escaping function.
   */
  private isEscapeCall(call: ts.CallExpression): boolean {
    const expr = call.expression;
    let funcName: string | null = null;

    if (ts.isIdentifier(expr)) {
      funcName = expr.text;
    } else if (ts.isPropertyAccessExpression(expr)) {
      funcName = expr.name.text;
      // Also check full text for lodash patterns: _.escapeRegExp
      const fullText = expr.getText();
      if (/[_.]escapeRegExp$/i.test(fullText) || /escapeStringRegexp$/i.test(fullText)) {
        return true;
      }
    }

    if (funcName && UnsafeRegexDetector.ESCAPE_FUNCTION_NAMES.has(funcName.toLowerCase())) {
      return true;
    }

    // Check for names containing "escape" + "regex"
    if (funcName && /escape.*reg/i.test(funcName)) return true;

    return false;
  }

  /**
   * Check if a .replace() call is the inline regex escaping pattern.
   * Pattern: s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
   */
  private isInlineEscapeReplace(call: ts.CallExpression): boolean {
    if (call.arguments.length < 2) return false;
    const firstArg = call.arguments[0];
    const firstArgText = firstArg.getText();
    // Check if the first arg is a regex containing the standard escape character class
    return /\[.*\*.*\+.*\?.*\^.*\$.*\{.*\}/.test(firstArgText) || /\.\*\+\?\^/.test(firstArgText);
  }

  // ──────────── Trusted Source Detection ────────────

  /**
   * Check if an identifier traces to a trusted (non-user) source.
   */
  private tracesToTrustedSource(identifier: ts.Identifier, searchScope: ts.Node): boolean {
    const traceResult = this.traceVariable(identifier, searchScope);
    return traceResult.isTrustedSource;
  }

  // ──────────── Function Parameter Detection ────────────

  /**
   * Check if an identifier is a parameter of the enclosing function.
   */
  private isFunctionParameter(identifier: ts.Identifier): boolean {
    const varName = identifier.text;
    let current: ts.Node | undefined = identifier.parent;

    while (current && !ts.isSourceFile(current)) {
      if (this.isFunctionLike(current)) {
        const funcNode = current as ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;
        if (funcNode.parameters) {
          for (const param of funcNode.parameters) {
            if (ts.isIdentifier(param.name) && param.name.text === varName) {
              return true;
            }
          }
        }
        return false; // Found enclosing function but param not in it
      }
      current = current.parent;
    }
    return false;
  }

  // ──────────── Utility ────────────

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

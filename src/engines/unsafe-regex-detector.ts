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
    'sanitizeregex', 'sanitizeregexp', 'sanitizepattern',
    'escapestr', 'escapestring', 'escapespecialchars', 'escapespecial',
    'regexpquote', 'quotere', 'quoteregex',
  ]);

  /** Trusted (non-attacker-controlled) data sources */
  private static readonly TRUSTED_SOURCE_PATTERNS = [
    /^process\.env\./,
    /^config(?:Manager)?\./,
    /^settings\./,
    /^constants?\./i,
    /^options\./,
    /^ENV\./,
    /^APP\./,
    /\.(?:constants?|PATTERNS?|REGEXES?|SCHEMAS?)\b/i,
    /^this\.(?:config|options|settings|pattern)/i,
    /^(?:DEFAULT|STATIC|GLOBAL)_/,
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
      // safe-regex2 is conservative — it flags any star-height > 1, even safe
      // patterns like (\d+)? (optional group with inner quantifier).
      // Apply structural analysis to filter false positives.

      // Guard 1: If all nested quantifiers use ? or {n} as outer quantifier,
      // the pattern is safe. (X+)? matches 0 or 1 times — no exponential backtracking.
      // (X+){3} is bounded — at most 3 iterations.
      if (this.allNestedQuantifiersAreBounded(pattern)) {
        // Safe — skip
      }
      // Guard 2: Disjoint-delimiter guard — patterns like \d+(\.\d+)+ are safe
      // because the delimiter (\.) prevents catastrophic backtracking.
      else if (this.hasDisjointDelimiters(pattern)) {
        // Safe — skip
      }
      // Guard 3: Literal-anchor-in-group guard — groups containing a mandatory
      // literal character (like \r?\n, /, :) that cannot match the repeating body.
      // e.g., (?:[ \t]*\r?\n)+ — each iteration MUST consume a newline, preventing
      // catastrophic backtracking even though category-level analysis is too coarse.
      else if (this.hasLiteralAnchorInGroups(pattern)) {
        // Safe — skip
      }
      // Guard 4: Fully-anchored pattern — patterns with both ^ and $ anchors are safe
      // because the engine can only start matching at position 0, eliminating the
      // exponential backtracking that arises from trying multiple start positions.
      // e.g., /^~?(\/[^\s]+)+$/ — safe because no alternative starting positions.
      else if (this.isFullyAnchored(pattern)) {
        // Safe — skip
      }
      else {
        let severity = this.getStaticReDoSSeverity(node, context);
        // Complexity-based demotion: simple patterns with shallow quantifier
        // nesting (< 2 levels) pose minimal real-world ReDoS risk. Demote to
        // 'warning' unless they're on user input (which stays 'error').
        if (severity === 'error' && this.isSimplePattern(pattern) && !this.regexAppliesToUserInput(node)) {
          severity = 'warning';
        }
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
          // Skip middleware functions (3+ params with 'next' as last) — they're helpers, not endpoints
          const hasNextParam = funcNode.parameters.length >= 3 &&
            funcNode.parameters.some(p => ts.isIdentifier(p.name) && p.name.text.toLowerCase() === 'next');
          if (hasNextParam) return false;

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

    // Check (a?)+ pattern — fully-optional content in quantified group.
    // Only flag when ALL elements in the group are optional (can match empty).
    // e.g., (a?)+ is dangerous, but (\r?\n)+ is safe because \n is mandatory.
    if (/\([^()]*\?\)[+*]/.test(pattern)) {
      const optGroupRegex = /\(([^()]*\?)\)[+*]/g;
      let gm;
      while ((gm = optGroupRegex.exec(pattern)) !== null) {
        const groupContent = gm[1];
        // Strip non-capturing prefix
        const content = groupContent.startsWith('?:') ? groupContent.slice(2) : groupContent;
        // Check if every element in the group is optional (has ? quantifier)
        // Remove escape sequences and check if there are mandatory elements
        const stripped = content.replace(/\\./g, 'X'); // normalize escapes
        // If after removing all X? patterns, nothing mandatory remains → dangerous
        const withoutOptional = stripped.replace(/X\?/g, '').replace(/.\?/g, '').replace(/\[[^\]]*\]\?/g, '');
        const mandatory = withoutOptional.replace(/[+*?|]/g, '').trim();
        if (mandatory.length === 0) {
          return true; // All elements optional → can match empty → dangerous
        }
      }
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
    // Where the classes overlap AND no literal delimiter separates them.
    const endAnchorPatterns: Array<{ regex: RegExp; gapGroup: number }> = [
      // \w+\d+$ — \d is subset of \w. Capture gap between quantifiers.
      { regex: /\\w[+*]((?:[^\\$]|\\.)*)\\d[+*].*\$/, gapGroup: 1 },
      // .*[a-z]+$ — . includes [a-z]
      { regex: /\.\*((?:[^\\$[\]]|\\.)*)\[[a-z][^\]]*\][+*].*\$/i, gapGroup: 1 },
      // .*\w+$
      { regex: /\.\*((?:[^\\$]|\\.)*)\\w[+*].*\$/, gapGroup: 1 },
      // \w+[a-z]+$ or similar overlapping
      { regex: /\\w[+*]((?:[^\\$[]|\\.)*)\[a-z[^\]]*\][+*].*\$/i, gapGroup: 1 },
    ];

    for (const { regex, gapGroup } of endAnchorPatterns) {
      const m = regex.exec(pattern);
      if (m) {
        const gap = m[gapGroup] || '';
        // If there's a literal string between the quantified groups, it acts as a
        // delimiter preventing catastrophic backtracking (e.g., \w+end\d+$)
        if (this.hasLiteralDelimiterInGap(gap)) continue;
        return true;
      }
    }

    return false;
  }

  /**
   * Check if a gap string between quantified groups contains a literal delimiter.
   * Literal characters (not escape classes like \w, \d) prevent backtracking overlap.
   */
  private hasLiteralDelimiterInGap(gap: string): boolean {
    if (!gap || gap.length === 0) return false;
    // Strip escape sequences to find literal characters
    const withoutEscapes = gap.replace(/\\[dDwWsS.bB]/g, '');
    // If any literal characters remain (not just escape classes), it's a delimiter
    const literals = withoutEscapes.replace(/\\/g, '');
    return literals.length > 0;
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
        // Check if the expression is an inline .replace() escape call
        if (ts.isCallExpression(expr) && ts.isPropertyAccessExpression(expr.expression) &&
            expr.expression.name.text === 'replace' && this.isInlineEscapeReplace(expr)) {
          continue; // Safe — escaped inline
        }
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

    // Check for names containing "escape" + "regex" or "sanitize" + "regex/pattern"
    if (funcName && (/escape.*reg/i.test(funcName) || /sanitize.*(?:reg|pattern)/i.test(funcName) ||
        /(?:regex|regexp).*(?:escape|sanitize|quote)/i.test(funcName))) return true;

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

  // ──────────── Disjoint-Delimiter Guard ────────────

  /**
   * Check if every quantified group in the pattern starts with a delimiter
   * character disjoint from the preceding character class. If so, safe-regex2's
   * nested-quantifier concern is a false alarm — the delimiter prevents
   * catastrophic backtracking.
   *
   * Handles literal delimiters (-, _, \.), escape-class delimiters (\s, \d),
   * and bracket-expression delimiters ([._-]).
   *
   * Examples of safe patterns:
   *   /^\d+(\.\d+)?$/           — \. disjoint from \d
   *   /^[a-z0-9]+(-[a-z0-9]+)*$/ — - disjoint from [a-z0-9]
   *   /^\w+(\s\w+)*$/           — \s disjoint from \w
   */
  private hasDisjointDelimiters(pattern: string): boolean {
    const groups = this.findQuantifiedGroups(pattern);
    if (groups.length === 0) return false;

    for (const group of groups) {
      const firstElem = this.extractFirstRegexElement(group.content);
      if (!firstElem) return false;

      const precElem = this.extractPrecedingRegexElement(pattern, group.startIndex);

      if (precElem) {
        // Normal case: check delimiter disjointness with preceding element
        if (!this.elementsAreDisjoint(firstElem, precElem)) return false;
      } else {
        // Anchor case (^ at start): no preceding matchable element.
        // Check if the group has an internal delimiter — the LAST element in the
        // group content is disjoint from the repeating body (first element).
        // e.g., (\w+\.) → last=\., first=\w → disjoint → safe (dot terminates each repetition)
        const lastElem = this.extractLastRegexElement(group.content);
        if (!lastElem || !this.elementsAreDisjoint(firstElem, lastElem)) return false;
      }
    }
    return true;
  }

  /**
   * Find all top-level quantified groups: (...)+, (...)*, (...)?
   * Returns content (without parens), start index, and outer quantifier of each.
   */
  private findQuantifiedGroups(pattern: string): Array<{ content: string; startIndex: number; outerQuantifier: string }> {
    const groups: Array<{ content: string; startIndex: number; outerQuantifier: string }> = [];
    let i = 0;

    while (i < pattern.length) {
      if (pattern[i] === '\\' && i + 1 < pattern.length) { i += 2; continue; }

      // Skip character class [...]
      if (pattern[i] === '[') {
        i = this.skipCharClass(pattern, i);
        continue;
      }

      // Found opening paren — find matching close
      if (pattern[i] === '(') {
        const start = i;
        let depth = 1;
        i++;

        while (i < pattern.length && depth > 0) {
          if (pattern[i] === '\\' && i + 1 < pattern.length) { i += 2; continue; }
          if (pattern[i] === '[') { i = this.skipCharClass(pattern, i); continue; }
          if (pattern[i] === '(') depth++;
          if (pattern[i] === ')') depth--;
          i++;
        }

        // i is past the closing ). Check if followed by quantifier (+, *, ?, {n,m}).
        const closeParenIdx = i - 1; // position of ')'
        if (i < pattern.length && /[+*?{]/.test(pattern[i])) {
          // Skip past {n,m} quantifier so 'i' ends after it
          let quantifierStr = pattern[i];
          if (pattern[i] === '{') {
            const braceStart = i;
            while (i < pattern.length && pattern[i] !== '}') i++;
            if (i < pattern.length) i++;
            quantifierStr = pattern.substring(braceStart, i);
          }
          let content = pattern.substring(start + 1, closeParenIdx);
          // Strip non-capturing/named group prefix
          if (content.startsWith('?:')) content = content.substring(2);
          else if (content.startsWith('?<') && content.includes('>')) {
            content = content.substring(content.indexOf('>') + 1);
          }
          groups.push({ content, startIndex: start, outerQuantifier: quantifierStr });
        }
        continue;
      }

      i++;
    }
    return groups;
  }

  /**
   * Check if all nested quantifier structures in the pattern are bounded.
   * (X+)? is safe (0 or 1 occurrence). (X+){3} is safe (exactly 3).
   * Only (X+)+ and (X+)* are dangerous (unbounded repetition).
   */
  private allNestedQuantifiersAreBounded(pattern: string): boolean {
    const groups = this.findQuantifiedGroups(pattern);
    if (groups.length === 0) return true; // No quantified groups at all

    // Check if any group has an inner quantifier AND an unbounded outer quantifier
    for (const group of groups) {
      const hasInnerQuantifier = /[+*]/.test(group.content.replace(/\\./g, '').replace(/\[[^\]]*\]/g, ''));
      if (!hasInnerQuantifier) continue; // No inner quantifier — not nested

      // Outer quantifier: ? is bounded, {n} is bounded, + and * are unbounded
      const outer = group.outerQuantifier;
      if (outer === '?' ) continue; // (X+)? → bounded (0 or 1)
      if (outer.startsWith('{')) {
        // {n} or {n,m} — check if m is small (bounded)
        const match = outer.match(/^\{(\d+)(?:,(\d*))?\}$/);
        if (match) {
          const max = match[2] !== undefined ? (match[2] === '' ? Infinity : parseInt(match[2], 10)) : parseInt(match[1], 10);
          if (max <= 10) continue; // Bounded repetition — safe
        }
      }
      // outer is + or * or {n,} — unbounded, check if inner is truly quantified
      return false;
    }
    return true; // All nested quantifiers are bounded
  }

  /**
   * Guard 3: Check if every quantified group with unbounded outer quantifier
   * contains a mandatory literal character that cannot be matched by adjacent
   * character classes, preventing catastrophic backtracking.
   *
   * This handles cases where the category-level disjointness check (Guard 2)
   * is too coarse. For example:
   *   (?:[ \t]*\r?\n)+ — \n is mandatory, and [ \t] can't match \n
   *   (?::[a-z0-9]+)+  — : is mandatory, and [a-z0-9] can't match :
   *   (?:\/[^\s]+)+    — / is mandatory literal at start of each iteration
   */
  /**
   * Check if the pattern is fully anchored with both ^ and $.
   * Fully-anchored patterns prevent the regex engine from trying multiple
   * starting positions, which is a prerequisite for catastrophic backtracking
   * in most ReDoS scenarios.
   */
  private isFullyAnchored(pattern: string): boolean {
    // Must start with ^ (after optional non-capturing group or flags)
    // and end with $ (before optional flags)
    const stripped = pattern.replace(/^\(\?[a-z]+\)/, ''); // strip inline flags
    return stripped.startsWith('^') && /\$(?:\)*)$/.test(stripped);
  }

  private hasLiteralAnchorInGroups(pattern: string): boolean {
    const groups = this.findQuantifiedGroups(pattern);
    if (groups.length === 0) return false;

    for (const group of groups) {
      // Only check groups with inner quantifiers (the ones safe-regex2 flags)
      const contentStripped = group.content.replace(/\\./g, '').replace(/\[[^\]]*\]/g, '');
      const hasInnerQuantifier = /[+*]/.test(contentStripped);
      if (!hasInnerQuantifier) continue;

      // Check if this group has an unbounded outer quantifier
      const outer = group.outerQuantifier;
      if (outer === '?') continue; // bounded
      if (outer.startsWith('{')) {
        const match = outer.match(/^\{(\d+)(?:,(\d*))?\}$/);
        if (match) {
          const max = match[2] !== undefined ? (match[2] === '' ? Infinity : parseInt(match[2], 10)) : parseInt(match[1], 10);
          if (max <= 10) continue;
        }
      }

      // This group has inner quantifier + unbounded outer. Check for mandatory literal.
      if (!this.groupHasMandatoryLiteralAnchor(group.content, pattern, group.startIndex)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Check if a quantified group's content contains a mandatory literal element
   * that can't be consumed by the adjacent repeating body, acting as an anchor
   * that prevents catastrophic backtracking.
   */
  private groupHasMandatoryLiteralAnchor(content: string, _fullPattern: string, _groupStart: number): boolean {
    // Parse the group content into elements, checking for mandatory literals
    // A "mandatory literal" is a non-optional element that matches a specific character
    // which cannot be matched by the quantified parts of the group.

    // Strategy: Extract all non-quantified literal/escape elements and check
    // if any of them are NOT matchable by the quantified character classes in the group.

    // Step 1: Find all character classes used with quantifiers in the group
    const quantifiedClasses = new Set<string>();
    const classRegex = /(\[[^\]]*\]|\\[dDwWsS]|\.)[+*?]|\b([+*?])/g;
    let m;
    while ((m = classRegex.exec(content)) !== null) {
      if (m[1]) quantifiedClasses.add(m[1]);
    }

    // Step 2: Find mandatory literals (not followed by ? and not inside quantified groups)
    // Simple approach: look for literal chars or escape sequences not followed by ?, +, *
    const elements: string[] = [];
    let i = 0;
    while (i < content.length) {
      if (content[i] === '\\' && i + 1 < content.length) {
        const esc = content.substring(i, i + 2);
        i += 2;
        // Skip if followed by quantifier making it optional
        if (i < content.length && content[i] === '?') { i++; continue; }
        if (i < content.length && (content[i] === '+' || content[i] === '*')) { i++; continue; }
        elements.push(esc);
        continue;
      }
      if (content[i] === '[') {
        const end = this.findClosingBracket(content, i);
        if (end !== -1) {
          const cls = content.substring(i, end + 1);
          i = end + 1;
          if (i < content.length && content[i] === '?') { i++; continue; }
          if (i < content.length && (content[i] === '+' || content[i] === '*')) { i++; continue; }
          elements.push(cls);
          continue;
        }
      }
      if (content[i] === '(' || content[i] === ')' || content[i] === '|' ||
          content[i] === '+' || content[i] === '*' || content[i] === '?' ||
          content[i] === '{' || content[i] === '}') {
        i++;
        continue;
      }
      // Literal character
      const ch = content[i];
      i++;
      if (i < content.length && (content[i] === '?' || content[i] === '+' || content[i] === '*')) { i++; continue; }
      elements.push(ch);
    }

    // Step 3: Check if any mandatory element is NOT matchable by the quantified classes
    for (const elem of elements) {
      const elemCats = this.getCharCategories(elem);
      if (!elemCats || elemCats.has('any')) continue;

      // Check against each quantified class
      let matchedByAnyQuantified = false;
      for (const qClass of quantifiedClasses) {
        const qCats = this.getCharCategories(qClass);
        if (!qCats) continue;
        if (qCats.has('any')) { matchedByAnyQuantified = true; break; }
        for (const cat of elemCats) {
          if (qCats.has(cat)) { matchedByAnyQuantified = true; break; }
        }
        if (matchedByAnyQuantified) break;
      }

      if (!matchedByAnyQuantified) {
        return true; // Found a mandatory literal that can't be consumed by quantified parts
      }
    }

    // Special case: check for \r?\n pattern (newline mandatory, \r optional)
    // \n (newline) is not in the whitespace matched by [ \t]
    if (/\\r\?\\n/.test(content) || /\\n/.test(content)) {
      // Check if any quantified class can match \n
      let newlineMatchable = false;
      for (const qClass of quantifiedClasses) {
        // \n is NOT matched by [ \t], \w, \d — only by \s, ., [^\S] etc.
        if (qClass === '.' || qClass === '\\s' || qClass === '\\S') {
          newlineMatchable = true; break;
        }
        if (qClass.startsWith('[') && qClass.endsWith(']')) {
          const inner = qClass.slice(1, -1);
          if (inner.includes('\\n') || inner.includes('\\s')) {
            newlineMatchable = true; break;
          }
          // [ \t] does NOT match \n
        }
      }
      if (!newlineMatchable) return true;
    }

    return false;
  }

  /**
   * Extract the first regex element from a group's content string.
   * Returns \d, \., [a-z], or a literal character.
   */
  private extractFirstRegexElement(content: string): string | null {
    if (!content || content.length === 0) return null;

    // Escape sequence: \d, \w, \s, \., etc.
    if (content[0] === '\\' && content.length >= 2) {
      return content.substring(0, 2);
    }

    // Character class: [...]
    if (content[0] === '[') {
      const end = this.findClosingBracket(content, 0);
      if (end === -1) return null;
      return content.substring(0, end + 1);
    }

    // Literal character
    return content[0];
  }

  /**
   * Extract the last regex element from a group's content string.
   * For (\w+\.) returns \., for (\w+[-]) returns [-], for (\w+x) returns x.
   * Strips trailing quantifiers to get the base element.
   */
  private extractLastRegexElement(content: string): string | null {
    if (!content || content.length === 0) return null;

    let p = content.length - 1;

    // Strip trailing quantifiers
    while (p >= 0) {
      if (content[p] === '+' || content[p] === '*' || content[p] === '?') {
        p--;
      } else if (content[p] === '}') {
        const braceStart = content.lastIndexOf('{', p);
        if (braceStart >= 0) { p = braceStart - 1; } else { break; }
      } else {
        break;
      }
    }
    if (p < 0) return null;

    // Character class: ]...[
    if (content[p] === ']') {
      let j = p - 1;
      while (j >= 0) {
        if (content[j] === '[' && (j === 0 || content[j - 1] !== '\\')) {
          return content.substring(j, p + 1);
        }
        if (content[j] === '\\' && j > 0) { j -= 2; continue; }
        j--;
      }
      return null;
    }

    // Escape sequence: \d, \w, \., etc.
    if (p >= 1 && content[p - 1] === '\\') {
      return content.substring(p - 1, p + 1);
    }

    // Literal character
    return content[p];
  }

  /**
   * Extract the regex element immediately before position `pos` in the pattern.
   * Strips trailing quantifiers (+, *, ?, {n,m}) to get the base element.
   */
  private extractPrecedingRegexElement(pattern: string, pos: number): string | null {
    if (pos <= 0) return null;

    let p = pos - 1;

    // Strip quantifiers and modifiers from right
    while (p >= 0) {
      if (pattern[p] === '+' || pattern[p] === '*' || pattern[p] === '?') {
        p--;
      } else if (pattern[p] === '}') {
        const braceStart = pattern.lastIndexOf('{', p);
        if (braceStart >= 0) { p = braceStart - 1; } else { break; }
      } else {
        break;
      }
    }

    if (p < 0) return null;

    // Skip anchors — not matchable characters
    if (pattern[p] === '^' || pattern[p] === '$') return null;

    // Character class: ]...[
    if (pattern[p] === ']') {
      let j = p - 1;
      while (j >= 0) {
        if (pattern[j] === '[' && (j === 0 || pattern[j - 1] !== '\\')) {
          return pattern.substring(j, p + 1);
        }
        if (pattern[j] === '\\' && j > 0) { j -= 2; continue; }
        j--;
      }
      return null;
    }

    // Closing group: ) — preceding element is a group (walk through it)
    if (pattern[p] === ')') {
      let depth = 1;
      let j = p - 1;
      while (j >= 0 && depth > 0) {
        if (pattern[j] === ')') depth++;
        else if (pattern[j] === '(') depth--;
        j--;
      }
      return (depth === 0) ? pattern.substring(j + 1, p + 1) : null;
    }

    // Escape sequence: \d, \w, etc.
    if (p >= 1 && pattern[p - 1] === '\\') {
      return pattern.substring(p - 1, p + 1);
    }

    // Literal character
    return pattern[p];
  }

  /**
   * Check if two regex elements are disjoint (cannot match any common character).
   * Uses character category classification.
   */
  private elementsAreDisjoint(a: string, b: string): boolean {
    const aCats = this.getCharCategories(a);
    const bCats = this.getCharCategories(b);
    if (!aCats || !bCats) return false;
    if (aCats.has('any') || bCats.has('any')) return false;

    for (const cat of aCats) {
      if (bCats.has(cat)) return false;
    }
    return true;
  }

  /**
   * Map a regex element to the set of character categories it can match.
   * Categories: digit, lower, upper, underscore, whitespace, punct, any
   */
  private getCharCategories(element: string): Set<string> | null {
    const cats = new Set<string>();

    // Escape classes
    if (element === '\\d') { cats.add('digit'); return cats; }
    if (element === '\\D') { ['lower', 'upper', 'underscore', 'whitespace', 'punct'].forEach(c => cats.add(c)); return cats; }
    if (element === '\\w') { ['digit', 'lower', 'upper', 'underscore'].forEach(c => cats.add(c)); return cats; }
    if (element === '\\W') { ['whitespace', 'punct'].forEach(c => cats.add(c)); return cats; }
    if (element === '\\s') { cats.add('whitespace'); return cats; }
    if (element === '\\S') { ['digit', 'lower', 'upper', 'underscore', 'punct'].forEach(c => cats.add(c)); return cats; }

    // Escaped literal: \., \-, \_, etc.
    if (element.startsWith('\\') && element.length === 2) {
      this.classifyChar(element[1], cats);
      return cats;
    }

    // Character class: [...]
    if (element.startsWith('[') && element.endsWith(']')) {
      const inner = element.slice(1, -1);
      const negated = inner.startsWith('^');
      const content = negated ? inner.slice(1) : inner;

      const positiveCats = new Set<string>();
      this.parseCharClassContent(content, positiveCats);

      if (negated) {
        const all = ['digit', 'lower', 'upper', 'underscore', 'whitespace', 'punct'];
        for (const c of all) { if (!positiveCats.has(c)) cats.add(c); }
        return cats.size > 0 ? cats : null;
      }
      return positiveCats.size > 0 ? positiveCats : null;
    }

    // Unescaped dot — matches (almost) anything
    if (element === '.') { cats.add('any'); return cats; }

    // Literal single character
    if (element.length === 1) {
      this.classifyChar(element, cats);
      return cats;
    }

    return null;
  }

  /** Classify a single character into digit/lower/upper/underscore/whitespace/punct */
  private classifyChar(ch: string, cats: Set<string>): void {
    if (/[0-9]/.test(ch)) cats.add('digit');
    else if (/[a-z]/.test(ch)) cats.add('lower');
    else if (/[A-Z]/.test(ch)) cats.add('upper');
    else if (ch === '_') cats.add('underscore');
    else if (/\s/.test(ch)) cats.add('whitespace');
    else cats.add('punct');
  }

  /** Parse the content of a character class [...] and add categories */
  private parseCharClassContent(content: string, cats: Set<string>): void {
    let i = 0;
    while (i < content.length) {
      // Escape sequence inside class
      if (content[i] === '\\' && i + 1 < content.length) {
        const esc = content[i + 1];
        if (esc === 'd') cats.add('digit');
        else if (esc === 'w') { ['digit', 'lower', 'upper', 'underscore'].forEach(c => cats.add(c)); }
        else if (esc === 's') cats.add('whitespace');
        else this.classifyChar(esc, cats);
        i += 2;
        continue;
      }

      // Range: a-z, 0-9, A-Z
      if (i + 2 < content.length && content[i + 1] === '-' && content[i + 2] !== ']') {
        const start = content[i], end = content[i + 2];
        if (/[a-z]/.test(start) && /[a-z]/.test(end)) cats.add('lower');
        else if (/[A-Z]/.test(start) && /[A-Z]/.test(end)) cats.add('upper');
        else if (/[0-9]/.test(start) && /[0-9]/.test(end)) cats.add('digit');
        i += 3;
        continue;
      }

      // Single character
      this.classifyChar(content[i], cats);
      i++;
    }
  }

  /** Skip past a character class [...], returning the index after the closing ] */
  private skipCharClass(pattern: string, start: number): number {
    let i = start + 1;
    if (i < pattern.length && pattern[i] === '^') i++;
    if (i < pattern.length && pattern[i] === ']') i++; // ] as first char is literal
    while (i < pattern.length) {
      if (pattern[i] === '\\' && i + 1 < pattern.length) { i += 2; continue; }
      if (pattern[i] === ']') return i + 1;
      i++;
    }
    return i;
  }

  /** Find the index of the closing ] for a character class starting at `start` */
  private findClosingBracket(pattern: string, start: number): number {
    let i = start + 1;
    if (i < pattern.length && pattern[i] === '^') i++;
    if (i < pattern.length && pattern[i] === ']') i++;
    while (i < pattern.length) {
      if (pattern[i] === '\\' && i + 1 < pattern.length) { i += 2; continue; }
      if (pattern[i] === ']') return i;
      i++;
    }
    return -1;
  }

  // ──────────── Complexity Analysis ────────────

  /**
   * Measure quantifier nesting depth in a regex pattern.
   * Returns the maximum depth of nested quantifiers (e.g., (a+)+ = 2, \d+ = 1).
   * Used to demote simple patterns with shallow nesting to 'warning'.
   */
  private getQuantifierNestingDepth(pattern: string): number {
    let maxDepth = 0;
    let currentGroupDepth = 0;
    let inCharClass = false;
    let i = 0;

    while (i < pattern.length) {
      const ch = pattern[i];

      // Skip escaped characters
      if (ch === '\\' && i + 1 < pattern.length) {
        i += 2;
        continue;
      }

      if (ch === '[') { inCharClass = true; i++; continue; }
      if (ch === ']') { inCharClass = false; i++; continue; }
      if (inCharClass) { i++; continue; }

      if (ch === '(') {
        currentGroupDepth++;
        i++;
        continue;
      }

      if (ch === ')') {
        // Check if this group is followed by a quantifier
        const next = i + 1 < pattern.length ? pattern[i + 1] : '';
        if (next === '+' || next === '*' || next === '{') {
          // This group has a quantifier — check if it contains quantifiers inside
          const innerDepth = this.countInnerQuantifiers(pattern, i);
          maxDepth = Math.max(maxDepth, innerDepth + 1);
        }
        currentGroupDepth = Math.max(0, currentGroupDepth - 1);
        i++;
        continue;
      }

      // Standalone quantifiers (on atoms, not groups)
      if ((ch === '+' || ch === '*') && i > 0) {
        maxDepth = Math.max(maxDepth, 1);
      }

      i++;
    }

    return maxDepth;
  }

  /**
   * Count the maximum quantifier depth inside a group ending at `closeParenIdx`.
   */
  private countInnerQuantifiers(pattern: string, closeParenIdx: number): number {
    // Walk backwards to find the matching open paren
    let depth = 0;
    let openIdx = closeParenIdx - 1;
    let inCC = false;

    while (openIdx >= 0) {
      const ch = pattern[openIdx];
      // Simple backward scan — not perfect with escapes but good enough
      if (ch === ']') { inCC = true; openIdx--; continue; }
      if (ch === '[') { inCC = false; openIdx--; continue; }
      if (inCC) { openIdx--; continue; }
      if (ch === ')') { depth++; openIdx--; continue; }
      if (ch === '(') {
        if (depth === 0) break;
        depth--;
        openIdx--;
        continue;
      }
      openIdx--;
    }

    // Now check the substring inside the group for quantifiers
    const inner = pattern.substring(openIdx + 1, closeParenIdx);
    let hasQuantifier = false;
    let innerInCC = false;
    for (let j = 0; j < inner.length; j++) {
      if (inner[j] === '\\' && j + 1 < inner.length) { j++; continue; }
      if (inner[j] === '[') { innerInCC = true; continue; }
      if (inner[j] === ']') { innerInCC = false; continue; }
      if (innerInCC) continue;
      if (inner[j] === '+' || inner[j] === '*') {
        hasQuantifier = true;
        break;
      }
    }

    return hasQuantifier ? 1 : 0;
  }

  /**
   * Check if a pattern is "simple" — shallow nesting and short length.
   * Simple patterns pose minimal real-world ReDoS risk.
   */
  private isSimplePattern(pattern: string): boolean {
    const nestingDepth = this.getQuantifierNestingDepth(pattern);
    // Patterns with < 2 levels of quantifier nesting are simple
    // e.g., \d+ (depth 1) is simple, (a+)+ (depth 2) is not
    return nestingDepth < 2 && pattern.length < 60;
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

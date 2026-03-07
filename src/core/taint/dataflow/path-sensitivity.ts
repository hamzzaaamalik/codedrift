/**
 * Path-Sensitive Branch Refinement for Taint Analysis
 *
 * When the CFG branches on a condition (if-statement, ternary, logical
 * expression), this analyzer inspects the condition and produces
 * {@link BranchRefinement} descriptors that tell the solver how to
 * update abstract taint state on each branch.
 *
 * Design: this module returns plain refinement descriptors rather than
 * mutating abstract state directly, keeping it fully decoupled from the
 * lattice / abstract-state implementation.
 */

import * as ts from 'typescript';

// ── Refinement Descriptor Types ─────────────────────────────────────

/**
 * Describes how a branch condition refines taint state for a single variable.
 */
export interface BranchRefinement {
  /** Variable name affected by the refinement */
  varName: string;
  /** Action to apply on the TRUE branch */
  trueBranch: RefinementAction;
  /** Action to apply on the FALSE branch */
  falseBranch: RefinementAction;
}

/**
 * Concrete actions the solver can apply to a variable's taint state
 * when taking a particular branch edge.
 */
export type RefinementAction =
  | { kind: 'sanitize'; sanitizerName: string }
  | { kind: 'mark-untainted' }
  | { kind: 'mark-tainted' }
  | { kind: 'narrow-type'; typeName: string }
  | { kind: 'none' };

// ── Validation Pattern ──────────────────────────────────────────────

/**
 * A pattern that matches validation / sanitizer function names and
 * describes what taint refinement they imply.
 */
export interface ValidationPattern {
  /** Function name or pattern (e.g. `'isValid'`, `/^validate/`) */
  namePattern: string | RegExp;
  /** What this validator does on the true branch */
  trueBranchAction: RefinementAction;
  /** What this validator does on the false branch */
  falseBranchAction: RefinementAction;
}

// ── Convenience constants ───────────────────────────────────────────

const NONE: RefinementAction = { kind: 'none' };
const UNTAINTED: RefinementAction = { kind: 'mark-untainted' };

/** Type names that are inherently safe from injection. */
const SAFE_TYPEOF_TYPES = new Set(['number', 'boolean', 'bigint', 'symbol']);

/** Whitelist-style method names where `.has(x)` implies x is safe. */
const WHITELIST_RECEIVERS = new Set([
  'whitelist', 'allowedSet', 'allowList', 'safeSet', 'permittedValues',
  'validValues', 'knownValues', 'trustedSet', 'approvedList',
]);

// ── PathSensitivityAnalyzer ─────────────────────────────────────────

/**
 * Analyzes branch conditions (if-guards, ternaries, logical operators)
 * and derives {@link BranchRefinement}s describing how each branch
 * constrains the taint state of in-scope variables.
 */
export class PathSensitivityAnalyzer {
  /** Registered validation / sanitizer patterns. */
  private readonly validationPatterns: ValidationPattern[];

  constructor() {
    this.validationPatterns = buildDefaultPatterns();
  }

  // ── Public API ────────────────────────────────────────────────────

  /**
   * Analyze a branch condition and return refinements for each branch.
   *
   * @param condition - The condition expression of an `if`, `?:`, etc.
   * @returns An array of refinements. Empty when nothing can be inferred.
   */
  analyzeBranch(condition: ts.Expression): BranchRefinement[] {
    return this.analyzeExpression(condition);
  }

  /**
   * Register an additional validation pattern at runtime.
   *
   * @param pattern - The pattern to add.
   */
  addValidationPattern(pattern: ValidationPattern): void {
    this.validationPatterns.push(pattern);
  }

  // ── Core recursive analysis ───────────────────────────────────────

  /**
   * Recursively analyze an expression and return all derivable refinements.
   */
  private analyzeExpression(expr: ts.Expression): BranchRefinement[] {
    // Strip parentheses
    expr = ((ts as any).skipOuterExpressions?.(expr) ?? expr) as ts.Expression;

    // 5. Negation — swap true/false branches
    if (ts.isPrefixUnaryExpression(expr) && expr.operator === ts.SyntaxKind.ExclamationToken) {
      return this.analyzeExpression(expr.operand).map(flipRefinement);
    }

    // 6. Logical AND / OR
    if (ts.isBinaryExpression(expr)) {
      if (expr.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
        return this.analyzeLogicalAnd(expr);
      }
      if (expr.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        return this.analyzeLogicalOr(expr);
      }
    }

    // 2. typeof checks — `typeof x === 'string'`
    const typeofResult = this.analyzeTypeof(expr);
    if (typeofResult) return [typeofResult];

    // 3 & 4. Equality comparisons — null/undefined/literal
    const equalityResult = this.analyzeEquality(expr);
    if (equalityResult) return [equalityResult];

    // 1. Validation / sanitizer function calls
    const callResult = this.analyzeCall(expr);
    if (callResult) return [callResult];

    // 8. Regex test — `/pattern/.test(x)` or `regex.test(x)`
    const regexResult = this.analyzeRegexTest(expr);
    if (regexResult) return [regexResult];

    // 9. Method calls that return boolean — `whitelist.has(x)`
    const methodResult = this.analyzeMethodCall(expr);
    if (methodResult) return [methodResult];

    // 7. `in` operator — `'prop' in obj`
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.InKeyword) {
      return []; // structural check — no taint refinement
    }

    // 7. instanceof — `x instanceof Foo`
    const instanceOfResult = this.analyzeInstanceOf(expr);
    if (instanceOfResult) return [instanceOfResult];

    // 3. Bare truthiness — `if (x)` — no taint refinement
    return [];
  }

  // ── Individual analysis helpers ───────────────────────────────────

  /**
   * Analyze `typeof x === 'type'` / `typeof x !== 'type'`.
   */
  private analyzeTypeof(expr: ts.Expression): BranchRefinement | null {
    if (!ts.isBinaryExpression(expr)) return null;

    const isEquality = expr.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
      || expr.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken;
    const isInequality = expr.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken
      || expr.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken;

    if (!isEquality && !isInequality) return null;

    const [typeofSide, literalSide] = extractTypeofPair(expr.left, expr.right);
    if (!typeofSide || !literalSide) return null;

    const varName = extractVarName(typeofSide.expression);
    if (!varName) return null;

    const typeName = literalSide.text;
    const isSafe = SAFE_TYPEOF_TYPES.has(typeName);

    const matchAction: RefinementAction = isSafe
      ? UNTAINTED
      : { kind: 'narrow-type', typeName };

    const refinement: BranchRefinement = {
      varName,
      trueBranch: matchAction,
      falseBranch: NONE,
    };

    // For !== / !=, swap branches
    if (isInequality) return flipRefinement(refinement);
    return refinement;
  }

  /**
   * Analyze equality / strict-equality against null, undefined, or literals.
   */
  private analyzeEquality(expr: ts.Expression): BranchRefinement | null {
    if (!ts.isBinaryExpression(expr)) return null;

    const isEquality = expr.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
      || expr.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken;
    const isInequality = expr.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken
      || expr.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken;

    if (!isEquality && !isInequality) return null;

    const [varSide, litSide] = extractVarAndLiteral(expr.left, expr.right);
    if (!varSide || litSide === undefined) return null;

    const varName = extractVarName(varSide);
    if (!varName) return null;

    // null / undefined → true branch is safe
    if (litSide === null) {
      const refinement: BranchRefinement = {
        varName,
        trueBranch: UNTAINTED,
        falseBranch: NONE,
      };
      return isInequality ? flipRefinement(refinement) : refinement;
    }

    // Literal value (string, number, boolean) → exact match is safe
    const refinement: BranchRefinement = {
      varName,
      trueBranch: UNTAINTED,
      falseBranch: NONE,
    };
    return isInequality ? flipRefinement(refinement) : refinement;
  }

  /**
   * Analyze a call expression against registered validation patterns.
   */
  private analyzeCall(expr: ts.Expression): BranchRefinement | null {
    if (!ts.isCallExpression(expr)) return null;

    const funcName = extractCallName(expr);
    if (!funcName) return null;

    const pattern = this.matchPattern(funcName);
    if (!pattern) return null;

    // Refined variable is the first argument, if any
    const firstArg = expr.arguments[0];
    if (!firstArg) return null;

    const varName = extractVarName(firstArg);
    if (!varName) return null;

    return {
      varName,
      trueBranch: pattern.trueBranchAction,
      falseBranch: pattern.falseBranchAction,
    };
  }

  /**
   * Analyze `/regex/.test(x)` or `pattern.test(x)`.
   */
  private analyzeRegexTest(expr: ts.Expression): BranchRefinement | null {
    if (!ts.isCallExpression(expr)) return null;
    if (!ts.isPropertyAccessExpression(expr.expression)) return null;

    const method = expr.expression.name.text;
    if (method !== 'test') return null;

    const arg = expr.arguments[0];
    if (!arg) return null;

    const varName = extractVarName(arg);
    if (!varName) return null;

    const receiver = expr.expression.expression;
    const sanitizerName = ts.isRegularExpressionLiteral(receiver)
      ? `regex:${receiver.text}`
      : 'regex:unknown';

    return {
      varName,
      trueBranch: { kind: 'sanitize', sanitizerName },
      falseBranch: NONE,
    };
  }

  /**
   * Analyze boolean-returning method calls such as `whitelist.has(x)`.
   */
  private analyzeMethodCall(expr: ts.Expression): BranchRefinement | null {
    if (!ts.isCallExpression(expr)) return null;
    if (!ts.isPropertyAccessExpression(expr.expression)) return null;

    const method = expr.expression.name.text;
    const receiver = expr.expression.expression;
    const receiverName = extractVarName(receiver);

    // whitelist.has(x), allowedSet.has(x), etc.
    if (method === 'has' && receiverName && WHITELIST_RECEIVERS.has(receiverName)) {
      const arg = expr.arguments[0];
      if (!arg) return null;
      const varName = extractVarName(arg);
      if (!varName) return null;

      return { varName, trueBranch: UNTAINTED, falseBranch: NONE };
    }

    return null;
  }

  /**
   * Analyze `x instanceof Foo` — narrows type on the true branch.
   */
  private analyzeInstanceOf(expr: ts.Expression): BranchRefinement | null {
    if (!ts.isBinaryExpression(expr)) return null;
    if (expr.operatorToken.kind !== ts.SyntaxKind.InstanceOfKeyword) return null;

    const varName = extractVarName(expr.left);
    if (!varName) return null;

    const typeName = extractVarName(expr.right) ?? 'unknown';

    return {
      varName,
      trueBranch: { kind: 'narrow-type', typeName },
      falseBranch: NONE,
    };
  }

  // ── Logical connective handling ───────────────────────────────────

  /**
   * `A && B` — on the true branch both hold, so return the union of
   * refinements from A and B. On the false branch at least one is false,
   * so we conservatively return nothing (no single-variable guarantee).
   */
  private analyzeLogicalAnd(expr: ts.BinaryExpression): BranchRefinement[] {
    const left = this.analyzeExpression(expr.left);
    const right = this.analyzeExpression(expr.right);
    return [...left, ...right];
  }

  /**
   * `A || B` — on the true branch at least one holds, so we can only
   * keep refinements that appear in *both* disjuncts for the same
   * variable (intersection). On the false branch both are false, so
   * both false-branch refinements apply.
   */
  private analyzeLogicalOr(expr: ts.BinaryExpression): BranchRefinement[] {
    const left = this.analyzeExpression(expr.left);
    const right = this.analyzeExpression(expr.right);

    // Intersect true-branch refinements by variable name
    const result: BranchRefinement[] = [];

    for (const l of left) {
      const match = right.find((r) => r.varName === l.varName);
      if (match) {
        result.push({
          varName: l.varName,
          trueBranch: mergeActions(l.trueBranch, match.trueBranch),
          falseBranch: l.falseBranch, // both false → both apply, pick left
        });
      }
    }

    return result;
  }

  // ── Pattern matching ──────────────────────────────────────────────

  /**
   * Find the first {@link ValidationPattern} that matches `name`.
   */
  private matchPattern(name: string): ValidationPattern | undefined {
    return this.validationPatterns.find((p) => {
      if (typeof p.namePattern === 'string') {
        return matchGlobString(name, p.namePattern);
      }
      return p.namePattern.test(name);
    });
  }
}

// ── Helper functions (module-private) ───────────────────────────────

/**
 * Build the default set of validation / sanitizer patterns.
 */
function buildDefaultPatterns(): ValidationPattern[] {
  const prefixes = [
    'isValid', 'validate', 'sanitize', 'check', 'verify',
    'isAuthorized', 'isAuthenticated', 'isAllowed', 'ensure',
  ];

  return prefixes.map((prefix) => ({
    namePattern: new RegExp(`^${prefix}`, 'i'),
    trueBranchAction: { kind: 'sanitize' as const, sanitizerName: prefix },
    falseBranchAction: NONE,
  }));
}

/**
 * Swap true/false branches of a refinement (used for negation).
 */
function flipRefinement(r: BranchRefinement): BranchRefinement {
  return {
    varName: r.varName,
    trueBranch: r.falseBranch,
    falseBranch: r.trueBranch,
  };
}

/**
 * Extract a simple variable name from an expression, or `null`.
 */
function extractVarName(expr: ts.Expression): string | null {
  expr = ((ts as any).skipOuterExpressions?.(expr) ?? expr) as ts.Expression;
  if (ts.isIdentifier(expr)) return expr.text;
  return null;
}

/**
 * Extract the callee name from a call expression.
 * Handles `foo(...)` and `obj.foo(...)`.
 */
function extractCallName(call: ts.CallExpression): string | null {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) return callee.text;
  if (ts.isPropertyAccessExpression(callee)) return callee.name.text;
  return null;
}

/**
 * Given left/right of a binary expression, identify which side is a
 * `typeof` unary and which is a string literal. Returns `[typeof, literal]`
 * or `[null, null]`.
 */
function extractTypeofPair(
  left: ts.Expression,
  right: ts.Expression,
): [ts.TypeOfExpression | null, ts.StringLiteral | null] {
  if (ts.isTypeOfExpression(left) && ts.isStringLiteral(right)) {
    return [left, right];
  }
  if (ts.isTypeOfExpression(right) && ts.isStringLiteral(left)) {
    return [right, left];
  }
  return [null, null];
}

/**
 * Given left/right of an equality expression, identify which side is a
 * variable and which is a literal (null, undefined, string, number, boolean).
 *
 * Returns `[varExpr, literalValue]` where `literalValue` is `null` for
 * null/undefined, or any other sentinel, or `undefined` when no literal
 * was found.
 */
function extractVarAndLiteral(
  left: ts.Expression,
  right: ts.Expression,
): [ts.Expression, unknown] | [null, undefined] {
  const l = asLiteralValue(left);
  const r = asLiteralValue(right);

  if (r !== undefined && l === undefined) return [left, r];
  if (l !== undefined && r === undefined) return [right, l];
  return [null, undefined];
}

/**
 * If `expr` is a null, undefined, or primitive literal, return a sentinel
 * value. Returns `undefined` (the JS value) when the expression is not
 * a recognisable literal.
 */
function asLiteralValue(expr: ts.Expression): unknown {
  expr = ((ts as any).skipOuterExpressions?.(expr) ?? expr) as ts.Expression;

  // null
  if (expr.kind === ts.SyntaxKind.NullKeyword) return null;

  // undefined (identifier)
  if (ts.isIdentifier(expr) && expr.text === 'undefined') return null;

  // void 0
  if (ts.isVoidExpression(expr)) return null;

  // string literal
  if (ts.isStringLiteral(expr)) return expr.text;

  // numeric literal
  if (ts.isNumericLiteral(expr)) return Number(expr.text);

  // true / false
  if (expr.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (expr.kind === ts.SyntaxKind.FalseKeyword) return false;

  return undefined;
}

/**
 * Simple glob-style string match supporting a trailing `*` wildcard.
 * E.g. `'validate*'` matches `'validateInput'`.
 */
function matchGlobString(name: string, pattern: string): boolean {
  if (pattern.endsWith('*')) {
    const prefix = pattern.slice(0, -1);
    return name.startsWith(prefix);
  }
  return name === pattern;
}

/**
 * Conservatively merge two refinement actions. If they agree, keep the
 * action; otherwise fall back to `none`.
 */
function mergeActions(a: RefinementAction, b: RefinementAction): RefinementAction {
  if (a.kind === b.kind) {
    // If both sanitize, keep whichever (both valid)
    if (a.kind === 'sanitize' && b.kind === 'sanitize') return a;
    if (a.kind === 'narrow-type' && b.kind === 'narrow-type') return NONE; // different types
    return a;
  }
  // Different kinds → conservative
  return NONE;
}

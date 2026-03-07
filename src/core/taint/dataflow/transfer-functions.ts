/**
 * TransferFunctions — Statement-level taint state transformers
 *
 * Defines how each TypeScript statement or expression transforms the abstract
 * taint state during data flow analysis. The fixpoint solver calls
 * `processStatement()` for every node in each basic block, collecting the
 * returned `TransferEffect` side effects to build function summaries and
 * detect sink reachability.
 *
 * Design principles:
 * - State is mutated **in place** for efficiency (the solver clones before
 *   branching).
 * - Every handler returns an array of side effects; pure state mutations
 *   produce an empty array.
 * - Expression-level taint resolution (`resolveExpressionTaint`) is a pure
 *   read-only query that never mutates state.
 */

import * as ts from 'typescript';
import {
  TaintFact,
  TaintValue,
  createUntaintedFact,
  isTainted,
  joinFacts,
} from './lattice.js';
import { AbstractState } from './abstract-state.js';
import { AccessPath } from '../heap/access-path.js';

// ── Transfer Effect ──────────────────────────────────────────────────

/**
 * Side effects produced by processing a statement.
 * Collected by the solver to build function summaries.
 */
export interface TransferEffect {
  kind: 'sink-hit' | 'call-edge' | 'taint-source' | 'return-transfer';

  /** For sink-hit: semantic category of the sink */
  sinkKind?: string;
  /** For sink-hit: fully qualified callee name (e.g. 'db.query') */
  sinkCallee?: string;
  /** For sink-hit: parameter indices whose taint reaches the sink */
  paramSources?: Set<number>;
  /** For sink-hit: whether taint was sanitized before reaching the sink */
  sanitized?: boolean;
  /** For sink-hit: sanitizer names applied along the flow */
  sanitizations?: string[];
  /** Source line number (1-based) */
  line?: number;

  /** For call-edge: unique identifier of the callee function */
  calleeId?: string;
  /** For call-edge: mapping from caller param sources to callee arg positions */
  argMapping?: { callerParamSources: Set<number>; calleeArgIndex: number }[];
  /** For call-edge: variable that receives the call return value */
  returnAssignedTo?: string;

  /** For taint-source: semantic kind of the source */
  sourceKind?: string;
  /** For taint-source: variable name receiving the tainted value */
  outputVar?: string;

  /** For return-transfer: parameter indices contributing to the return value */
  returnParamSources?: Set<number>;
  /** For return-transfer: whether the returned value was sanitized */
  returnSanitized?: boolean;
  /** For return-transfer: sanitizer names applied to the returned value */
  returnSanitizations?: string[];
}

// ── Sink / Sanitizer classification tables ───────────────────────────

/** Database query / execute sinks */
const DB_SINKS = new Set([
  'db.query', 'db.execute', 'db.raw',
  'connection.query', 'pool.query',
  'knex.raw', 'sequelize.query',
  'prisma.$queryRaw', 'prisma.$executeRaw',
  'mongoose.exec',
]);

/** Command execution sinks */
const CMD_SINKS = new Set([
  'exec', 'execSync', 'spawn', 'spawnSync', 'execFile',
  'child_process.exec', 'child_process.execSync',
  'child_process.spawn', 'child_process.spawnSync',
  'child_process.execFile',
]);

/** File system read sinks */
const FS_READ_SINKS = new Set([
  'fs.readFile', 'fs.readFileSync', 'fs.createReadStream',
]);

/** File system write / destructive sinks */
const FS_WRITE_SINKS = new Set([
  'fs.writeFile', 'fs.writeFileSync', 'fs.createWriteStream',
  'fs.unlink', 'fs.rmdir',
]);

/** HTML output sinks */
const HTML_SINKS = new Set([
  'res.send', 'res.write',
  'document.write', 'document.writeln',
]);

/** Eval / dynamic code execution sinks */
const EVAL_SINKS = new Set([
  'eval', 'Function',
  'vm.runInContext', 'vm.runInNewContext',
]);

/** URL / HTTP request sinks */
const HTTP_SINKS = new Set([
  'fetch', 'axios', 'axios.get', 'axios.post', 'axios.put', 'axios.delete',
  'http.request', 'https.request',
]);

/** Template engine rendering sinks */
const TEMPLATE_SINKS = new Set([
  'ejs.render', 'pug.render',
  'handlebars.compile', 'nunjucks.render',
]);

/** Logging sinks */
const LOG_SINKS = new Set([
  'console.log', 'console.warn', 'console.error',
  'logger.info', 'logger.warn', 'logger.error',
]);

/** Known taint source property paths */
const TAINT_SOURCE_PATHS: ReadonlyMap<string, string> = new Map([
  ['req.body', 'req-body'],
  ['req.params', 'req-params'],
  ['req.query', 'req-query'],
  ['req.headers', 'req-headers'],
  ['req.cookies', 'req-cookies'],
  ['req.files', 'req-files'],
  ['req.ip', 'req-ip'],
  ['request.body', 'req-body'],
  ['request.params', 'req-params'],
  ['request.query', 'req-query'],
  ['request.payload', 'req-payload'],
  ['ctx.request.body', 'ctx-body'],
  ['ctx.params', 'ctx-params'],
  ['ctx.query', 'ctx-query'],
  ['process.env', 'process-env'],
  ['process.argv', 'process-argv'],
]);

/** Numeric cast sanitizers */
const NUMERIC_SANITIZERS = new Set([
  'parseInt', 'parseFloat', 'Number',
]);

/** Math.* method names recognised as sanitizers */
const MATH_METHODS = new Set([
  'abs', 'ceil', 'floor', 'round', 'trunc', 'max', 'min',
  'pow', 'sqrt', 'log', 'sign', 'random',
]);

/** URL encoding sanitizers */
const URL_ENCODE_SANITIZERS = new Set([
  'encodeURIComponent', 'encodeURI',
]);

/** HTML escape / XSS sanitizers */
const HTML_ESCAPE_SANITIZERS = new Set([
  'escape', 'escapeHtml', 'DOMPurify.sanitize', 'xss', 'sanitizeHtml',
]);

/** Validation library sanitizers */
const VALIDATOR_SANITIZERS = new Set([
  'validator.escape', 'validator.trim',
]);

/** Path normalisation sanitizers */
const PATH_SANITIZERS = new Set([
  'path.basename', 'path.normalize',
]);

// ── TransferFunctions Class ──────────────────────────────────────────

export class TransferFunctions {
  private filePath: string;
  readonly paramNames: string[];

  constructor(filePath: string, paramNames: string[]) {
    this.filePath = filePath;
    this.paramNames = paramNames;
  }

  // ── Public API ───────────────────────────────────────────────────

  /**
   * Process a single AST node, updating the abstract state in place.
   *
   * Returns any side effects (sink hits, call edges, taint sources,
   * return transfers) that the solver should collect.
   *
   * @param stmt - The TypeScript AST node to process
   * @param state - The current abstract state (mutated in place)
   * @returns Array of transfer effects produced by this statement
   */
  processStatement(stmt: ts.Node, state: AbstractState): TransferEffect[] {
    // Variable declaration: const x = expr / let x = expr
    if (ts.isVariableStatement(stmt)) {
      const effects: TransferEffect[] = [];
      for (const decl of stmt.declarationList.declarations) {
        effects.push(...this.processVariableDeclaration(decl, state));
      }
      return effects;
    }

    // Single variable declaration (inside a for-in, for-of, etc.)
    if (ts.isVariableDeclaration(stmt)) {
      return this.processVariableDeclaration(stmt, state);
    }

    // Expression statement (assignments, calls, etc.)
    if (ts.isExpressionStatement(stmt)) {
      return this.processExpressionNode(stmt.expression, state);
    }

    // Return statement
    if (ts.isReturnStatement(stmt)) {
      return this.processReturnStatement(stmt, state);
    }

    // Bare expression (call, assignment inside for-header, etc.)
    if (ts.isCallExpression(stmt) || ts.isBinaryExpression(stmt)) {
      return this.processExpressionNode(stmt, state);
    }

    return [];
  }

  /**
   * Resolve the taint status of an arbitrary expression given the
   * current abstract state.
   *
   * This is a **read-only** operation — it never mutates state.
   *
   * @param expr - The TypeScript expression node
   * @param state - The current abstract state
   * @returns A TaintFact describing the combined taint status
   */
  resolveExpressionTaint(expr: ts.Expression, state: AbstractState): TaintFact {
    // Identifier — direct variable lookup
    if (ts.isIdentifier(expr)) {
      return state.getVar(expr.text);
    }

    // Property access chain (a.b.c) — try heap model, fall back to base var
    if (ts.isPropertyAccessExpression(expr)) {
      const ap = AccessPath.fromExpression(expr);
      if (ap) {
        const heapFact = state.isFieldTainted(ap);
        if (heapFact.value !== TaintValue.Untainted) {
          return heapFact;
        }
      }
      // Fall back: taint of base object propagates through field access
      return this.resolveExpressionTaint(expr.expression, state);
    }

    // Element access (a[b]) — treat like property access
    if (ts.isElementAccessExpression(expr)) {
      const ap = AccessPath.fromExpression(expr);
      if (ap) {
        const heapFact = state.isFieldTainted(ap);
        if (heapFact.value !== TaintValue.Untainted) {
          return heapFact;
        }
      }
      return this.resolveExpressionTaint(expr.expression, state);
    }

    // Call expression — sanitizer produces sanitized fact; else propagate arg taint
    if (ts.isCallExpression(expr)) {
      const sanitizerKind = this.classifyCallAsSanitizer(expr);
      if (sanitizerKind) {
        // Resolve taint of first argument to carry provenance through
        const argFact = expr.arguments.length > 0
          ? this.resolveExpressionTaint(expr.arguments[0], state)
          : createUntaintedFact();
        if (isTainted(argFact)) {
          return {
            value: TaintValue.Sanitized,
            sourceParams: new Set(argFact.sourceParams),
            sourceKinds: new Set(argFact.sourceKinds),
            sanitizations: [...argFact.sanitizations, sanitizerKind],
            isSanitized: true,
          };
        }
        return argFact;
      }
      // Non-sanitizer call: conservatively propagate argument taint
      return this.unionArgTaint(expr, state);
    }

    // Binary expression (concatenation, logical ops, etc.)
    if (ts.isBinaryExpression(expr)) {
      return this.processBinaryExpression(expr, state);
    }

    // Template literal with interpolations
    if (ts.isTemplateExpression(expr)) {
      return this.processTemplateLiteral(expr, state);
    }

    // No-substitution template literal (plain backtick string)
    if (ts.isNoSubstitutionTemplateLiteral(expr)) {
      return createUntaintedFact();
    }

    // Conditional (ternary) expression: join consequent and alternate
    if (ts.isConditionalExpression(expr)) {
      const whenTrue = this.resolveExpressionTaint(expr.whenTrue, state);
      const whenFalse = this.resolveExpressionTaint(expr.whenFalse, state);
      return joinFacts(whenTrue, whenFalse);
    }

    // Parenthesized expression — unwrap
    if (ts.isParenthesizedExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression, state);
    }

    // Type assertion / as-expression — unwrap
    if (ts.isAsExpression(expr) || ts.isTypeAssertionExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression, state);
    }

    // Non-null assertion (expr!) — unwrap
    if (ts.isNonNullExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression, state);
    }

    // Spread element — propagate inner taint
    if (ts.isSpreadElement(expr)) {
      return this.resolveExpressionTaint(expr.expression, state);
    }

    // Await expression — propagate inner taint
    if (ts.isAwaitExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression, state);
    }

    // Array literal — union all element taint
    if (ts.isArrayLiteralExpression(expr)) {
      let result: TaintFact = createUntaintedFact();
      for (const element of expr.elements) {
        if (ts.isOmittedExpression(element)) continue;
        result = joinFacts(result, this.resolveExpressionTaint(element, state));
      }
      return result;
    }

    // Object literal — union all property value taint
    if (ts.isObjectLiteralExpression(expr)) {
      let result: TaintFact = createUntaintedFact();
      for (const prop of expr.properties) {
        if (ts.isPropertyAssignment(prop)) {
          result = joinFacts(result, this.resolveExpressionTaint(prop.initializer, state));
        } else if (ts.isShorthandPropertyAssignment(prop)) {
          result = joinFacts(result, state.getVar(prop.name.text));
        } else if (ts.isSpreadAssignment(prop)) {
          result = joinFacts(result, this.resolveExpressionTaint(prop.expression, state));
        }
      }
      return result;
    }

    // Literals — always untainted
    if (
      ts.isStringLiteral(expr) ||
      ts.isNumericLiteral(expr) ||
      ts.isRegularExpressionLiteral(expr) ||
      expr.kind === ts.SyntaxKind.TrueKeyword ||
      expr.kind === ts.SyntaxKind.FalseKeyword ||
      expr.kind === ts.SyntaxKind.NullKeyword ||
      expr.kind === ts.SyntaxKind.UndefinedKeyword
    ) {
      return createUntaintedFact();
    }

    // Prefix / postfix unary — propagate operand taint
    if (ts.isPrefixUnaryExpression(expr)) {
      return this.resolveExpressionTaint(expr.operand, state);
    }
    if (ts.isPostfixUnaryExpression(expr)) {
      return this.resolveExpressionTaint(expr.operand, state);
    }

    // Default: conservative untainted (prefer false negatives over crashes)
    return createUntaintedFact();
  }

  // ── Statement Handlers ──────────────────────────────────────────

  /**
   * Process a variable declaration: `const x = expr`.
   *
   * Handles simple identifier binding, object destructuring, and
   * array destructuring patterns.
   */
  private processVariableDeclaration(
    decl: ts.VariableDeclaration,
    state: AbstractState,
  ): TransferEffect[] {
    const effects: TransferEffect[] = [];

    if (!decl.initializer) {
      // No initializer — variable is untainted
      if (ts.isIdentifier(decl.name)) {
        state.setVar(decl.name.text, createUntaintedFact());
      }
      return effects;
    }

    // Detect taint sources in the initializer
    effects.push(...this.collectTaintSources(decl.initializer, state));

    const initFact = this.resolveExpressionTaint(decl.initializer, state);

    // Simple binding: const x = expr
    if (ts.isIdentifier(decl.name)) {
      state.setVar(decl.name.text, initFact);

      // Establish alias for heap tracking
      const initPath = AccessPath.fromExpression(decl.initializer);
      if (initPath) {
        const targetPath = new AccessPath(decl.name.text, []);
        state.addAlias(targetPath, initPath);
      }

      // If this is a call expression assigned to a variable, emit call-edge
      if (ts.isCallExpression(decl.initializer)) {
        effects.push(...this.processCallExpression(decl.initializer, state, decl.name.text));
      }

      return effects;
    }

    // Object destructuring: const { a, b } = expr
    if (ts.isObjectBindingPattern(decl.name)) {
      for (const element of decl.name.elements) {
        if (ts.isIdentifier(element.name)) {
          const fieldName = element.propertyName
            ? (ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text)
            : element.name.text;

          // Each destructured field inherits taint from the source
          state.setVar(element.name.text, initFact);

          // Track heap alias for field access
          const initPath = AccessPath.fromExpression(decl.initializer);
          if (initPath) {
            const fieldPath = initPath.append(fieldName);
            const targetPath = new AccessPath(element.name.text, []);
            state.addAlias(targetPath, fieldPath);

            // Also check heap for field-specific taint
            const fieldFact = state.isFieldTainted(fieldPath);
            if (fieldFact.value !== TaintValue.Untainted) {
              state.setVar(element.name.text, fieldFact);
            }
          }
        }
      }
      return effects;
    }

    // Array destructuring: const [a, b] = expr
    if (ts.isArrayBindingPattern(decl.name)) {
      for (let i = 0; i < decl.name.elements.length; i++) {
        const element = decl.name.elements[i];
        if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
          // Each element inherits taint from the array
          state.setVar(element.name.text, initFact);

          const initPath = AccessPath.fromExpression(decl.initializer);
          if (initPath) {
            const indexPath = initPath.append(String(i));
            const targetPath = new AccessPath(element.name.text, []);
            state.addAlias(targetPath, indexPath);
          }
        }
      }
      return effects;
    }

    return effects;
  }

  /**
   * Process an assignment expression: `x = expr` or `obj.field = expr`.
   *
   * Updates the target variable or heap field with the taint of the
   * right-hand side expression.
   */
  private processAssignment(
    expr: ts.BinaryExpression,
    state: AbstractState,
  ): TransferEffect[] {
    const effects: TransferEffect[] = [];
    const rhsFact = this.resolveExpressionTaint(expr.right, state);

    // Detect taint sources on the RHS
    effects.push(...this.collectTaintSources(expr.right, state));

    // Simple identifier target: x = expr
    if (ts.isIdentifier(expr.left)) {
      state.setVar(expr.left.text, rhsFact);

      // If RHS is a call, emit call-edge with assignment target
      if (ts.isCallExpression(expr.right)) {
        effects.push(...this.processCallExpression(expr.right, state, expr.left.text));
      }

      return effects;
    }

    // Property access target: obj.field = expr
    if (ts.isPropertyAccessExpression(expr.left)) {
      const targetPath = AccessPath.fromExpression(expr.left);
      if (targetPath && isTainted(rhsFact)) {
        for (const paramIdx of rhsFact.sourceParams) {
          for (const kind of rhsFact.sourceKinds) {
            state.taintField(targetPath, paramIdx, kind);
          }
          // If no source kinds, still record the taint
          if (rhsFact.sourceKinds.size === 0) {
            state.taintField(targetPath, paramIdx, 'unknown');
          }
        }
      }

      // Check for innerHTML assignment → html-output sink
      if (expr.left.name.text === 'innerHTML' && isTainted(rhsFact)) {
        effects.push({
          kind: 'sink-hit',
          sinkKind: 'html-output',
          sinkCallee: '.innerHTML',
          paramSources: new Set(rhsFact.sourceParams),
          sanitized: rhsFact.isSanitized,
          sanitizations: [...rhsFact.sanitizations],
          line: this.getLineNumber(expr),
        });
      }

      return effects;
    }

    // Element access target: obj[key] = expr
    if (ts.isElementAccessExpression(expr.left)) {
      const targetPath = AccessPath.fromExpression(expr.left);
      if (targetPath && isTainted(rhsFact)) {
        for (const paramIdx of rhsFact.sourceParams) {
          for (const kind of rhsFact.sourceKinds) {
            state.taintField(targetPath, paramIdx, kind);
          }
          if (rhsFact.sourceKinds.size === 0) {
            state.taintField(targetPath, paramIdx, 'unknown');
          }
        }
      }
      return effects;
    }

    return effects;
  }

  /**
   * Process a call expression: `foo(args)`.
   *
   * 1. If the callee is a known **sink**, produce a `sink-hit` effect for
   *    any tainted argument.
   * 2. If the callee is a known **sanitizer**, update state to mark the
   *    result as sanitized.
   * 3. Otherwise, produce a `call-edge` effect for inter-procedural
   *    resolution by the solver.
   *
   * @param node - The call expression AST node
   * @param state - Current abstract state
   * @param assignedTo - Variable receiving the return value (if any)
   * @returns Side effects for the solver
   */
  private processCallExpression(
    node: ts.CallExpression,
    state: AbstractState,
    assignedTo?: string,
  ): TransferEffect[] {
    const effects: TransferEffect[] = [];

    // 1. Check for sink hit
    const sinkKind = this.classifyCallAsSink(node);
    if (sinkKind) {
      for (let i = 0; i < node.arguments.length; i++) {
        const argFact = this.resolveExpressionTaint(node.arguments[i], state);
        if (isTainted(argFact) || argFact.isSanitized) {
          effects.push({
            kind: 'sink-hit',
            sinkKind,
            sinkCallee: this.getCalleeName(node) ?? undefined,
            paramSources: new Set(argFact.sourceParams),
            sanitized: argFact.isSanitized,
            sanitizations: [...argFact.sanitizations],
            line: this.getLineNumber(node),
          });
        }
      }
    }

    // 2. Check for sanitizer
    const sanitizerKind = this.classifyCallAsSanitizer(node);
    if (sanitizerKind && assignedTo) {
      const argFact = node.arguments.length > 0
        ? this.resolveExpressionTaint(node.arguments[0], state)
        : createUntaintedFact();

      if (isTainted(argFact)) {
        state.setVar(assignedTo, {
          value: TaintValue.Sanitized,
          sourceParams: new Set(argFact.sourceParams),
          sourceKinds: new Set(argFact.sourceKinds),
          sanitizations: [...argFact.sanitizations, sanitizerKind],
          isSanitized: true,
        });
      } else {
        state.setVar(assignedTo, argFact);
      }
      return effects;
    }

    // 3. Emit call-edge for inter-procedural analysis
    const calleeId = this.resolveCalleeId(node);
    if (calleeId) {
      const argMapping: TransferEffect['argMapping'] = [];
      for (let i = 0; i < node.arguments.length; i++) {
        const argFact = this.resolveExpressionTaint(node.arguments[i], state);
        if (isTainted(argFact) || argFact.isSanitized) {
          argMapping.push({
            callerParamSources: new Set(argFact.sourceParams),
            calleeArgIndex: i,
          });
        }
      }

      if (argMapping.length > 0 || assignedTo) {
        effects.push({
          kind: 'call-edge',
          calleeId,
          argMapping,
          returnAssignedTo: assignedTo,
          line: this.getLineNumber(node),
        });
      }
    }

    return effects;
  }

  /**
   * Process a return statement: `return expr`.
   *
   * If the returned expression is tainted, produce a `return-transfer`
   * effect so the solver can propagate taint to callers.
   */
  private processReturnStatement(
    node: ts.ReturnStatement,
    state: AbstractState,
  ): TransferEffect[] {
    if (!node.expression) return [];

    const fact = this.resolveExpressionTaint(node.expression, state);
    if (isTainted(fact) || fact.isSanitized) {
      return [{
        kind: 'return-transfer',
        returnParamSources: new Set(fact.sourceParams),
        returnSanitized: fact.isSanitized,
        returnSanitizations: [...fact.sanitizations],
        line: this.getLineNumber(node),
      }];
    }

    return [];
  }

  /**
   * Detect known taint source patterns in property access expressions.
   *
   * Recognises `req.body`, `req.params`, `req.query`, `process.env`, etc.
   * and marks the containing variable as tainted in the abstract state.
   *
   * @returns A taint-source effect if a source was detected, else empty
   */
  private detectTaintSource(
    node: ts.PropertyAccessExpression,
    state: AbstractState,
  ): TransferEffect[] {
    const ap = AccessPath.fromExpression(node);
    if (!ap) return [];

    const pathStr = ap.toString();

    // Check each known source path (longest prefix match)
    for (const [pattern, sourceKind] of TAINT_SOURCE_PATHS) {
      if (pathStr === pattern || pathStr.startsWith(pattern + '.')) {
        // Taint the root variable in the heap
        const taintPath = new AccessPath(ap.root, pattern.split('.').slice(1));
        state.taintField(taintPath, -1, sourceKind);

        return [{
          kind: 'taint-source',
          sourceKind,
          outputVar: ap.root,
          line: this.getLineNumber(node),
        }];
      }
    }

    return [];
  }

  /**
   * Resolve taint through a template literal expression.
   *
   * Taint propagates through any interpolated span — if any `${expr}` is
   * tainted, the entire template result is tainted.
   */
  private processTemplateLiteral(
    node: ts.TemplateExpression,
    state: AbstractState,
  ): TaintFact {
    let result: TaintFact = createUntaintedFact();
    for (const span of node.templateSpans) {
      const spanFact = this.resolveExpressionTaint(span.expression, state);
      result = joinFacts(result, spanFact);
    }
    return result;
  }

  /**
   * Resolve taint through a binary expression.
   *
   * - String concatenation (`+`): union taint from both operands.
   * - Compound assignment (`+=`): union taint from both operands.
   * - Comparison operators (`===`, `!==`, `<`, `>`, etc.): result is untainted
   *   (comparisons produce booleans, not user-controlled strings).
   * - Logical operators (`&&`, `||`, `??`): conservative union of both operands.
   */
  private processBinaryExpression(
    node: ts.BinaryExpression,
    state: AbstractState,
  ): TaintFact {
    const op = node.operatorToken.kind;

    // Comparison operators produce boolean results — always untainted
    if (
      op === ts.SyntaxKind.EqualsEqualsToken ||
      op === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      op === ts.SyntaxKind.ExclamationEqualsToken ||
      op === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      op === ts.SyntaxKind.LessThanToken ||
      op === ts.SyntaxKind.LessThanEqualsToken ||
      op === ts.SyntaxKind.GreaterThanToken ||
      op === ts.SyntaxKind.GreaterThanEqualsToken ||
      op === ts.SyntaxKind.InstanceOfKeyword ||
      op === ts.SyntaxKind.InKeyword
    ) {
      return createUntaintedFact();
    }

    const leftFact = this.resolveExpressionTaint(node.left, state);
    const rightFact = this.resolveExpressionTaint(node.right, state);

    // String concatenation, addition, logical operators — union taint
    return joinFacts(leftFact, rightFact);
  }

  // ── Sink / Sanitizer Classification ─────────────────────────────

  /**
   * Classify a call expression as a known sink.
   *
   * @returns The sink kind string (e.g. 'db-query', 'command-execution')
   *          or null if the callee is not a recognised sink.
   */
  private classifyCallAsSink(node: ts.CallExpression): string | null {
    const callee = this.getCalleeName(node);
    if (!callee) return null;

    if (DB_SINKS.has(callee)) return 'db-query';
    if (CMD_SINKS.has(callee)) return 'command-execution';
    if (FS_READ_SINKS.has(callee)) return 'file-read';
    if (FS_WRITE_SINKS.has(callee)) return 'file-write';
    if (HTML_SINKS.has(callee)) return 'html-output';
    if (EVAL_SINKS.has(callee)) return 'eval';
    if (HTTP_SINKS.has(callee)) return 'http-request';
    if (TEMPLATE_SINKS.has(callee)) return 'template-render';
    if (LOG_SINKS.has(callee)) return 'log-output';

    // Redirect (res.redirect)
    if (callee === 'res.redirect') return 'redirect';

    // URL construction: new URL(...)
    if (ts.isNewExpression(node.parent) && callee === 'URL') return 'url-construction';

    return null;
  }

  /**
   * Classify a call expression as a known sanitizer.
   *
   * @returns The sanitizer kind string (e.g. 'numeric-cast', 'html-escape')
   *          or null if the callee is not a recognised sanitizer.
   */
  private classifyCallAsSanitizer(node: ts.CallExpression): string | null {
    const callee = this.getCalleeName(node);
    if (!callee) return null;

    // Numeric casts
    if (NUMERIC_SANITIZERS.has(callee)) return 'numeric-cast';

    // Math.* methods
    if (callee.startsWith('Math.')) {
      const method = callee.slice(5);
      if (MATH_METHODS.has(method)) return 'numeric-cast';
    }

    // URL encoding
    if (URL_ENCODE_SANITIZERS.has(callee)) return 'url-encode';

    // HTML escape / XSS sanitization
    if (HTML_ESCAPE_SANITIZERS.has(callee)) return 'html-escape';

    // Validation library
    if (VALIDATOR_SANITIZERS.has(callee)) return 'validation';

    // JSON.stringify
    if (callee === 'JSON.stringify') return 'serialization';

    // Path sanitizers
    if (PATH_SANITIZERS.has(callee)) return 'path-sanitize';

    // String.prototype.replace with regex — conservative heuristic
    if (ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'replace' &&
        node.arguments.length >= 1 &&
        ts.isRegularExpressionLiteral(node.arguments[0])) {
      return 'regex-replace';
    }

    return null;
  }

  // ── Callee Resolution ───────────────────────────────────────────

  /**
   * Resolve a unique callee identifier for inter-procedural call edges.
   *
   * @returns A string like `"file.ts#funcName"` or `"file.ts#obj.method"`,
   *          or null if the callee cannot be statically resolved.
   */
  private resolveCalleeId(node: ts.CallExpression): string | null {
    const callee = node.expression;

    // Simple function call: foo(...)
    if (ts.isIdentifier(callee)) {
      return `${this.filePath}#${callee.text}`;
    }

    // Method call: obj.method(...)
    if (ts.isPropertyAccessExpression(callee)) {
      const obj = callee.expression;
      if (ts.isIdentifier(obj)) {
        return `${this.filePath}#${obj.text}.${callee.name.text}`;
      }
      // this.method(...)
      if (obj.kind === ts.SyntaxKind.ThisKeyword) {
        return `${this.filePath}#this.${callee.name.text}`;
      }
    }

    return null;
  }

  // ── Helpers ─────────────────────────────────────────────────────

  /**
   * Get the human-readable callee name from a call expression.
   *
   * Produces dotted names like `"db.query"`, `"res.send"`, or simple
   * names like `"eval"`.
   */
  private getCalleeName(node: ts.CallExpression): string | null {
    const callee = node.expression;

    if (ts.isIdentifier(callee)) {
      return callee.text;
    }

    if (ts.isPropertyAccessExpression(callee)) {
      const ap = AccessPath.fromExpression(callee);
      return ap ? ap.toString() : null;
    }

    return null;
  }

  /**
   * Get the 1-based line number of an AST node.
   *
   * Walks up the tree to find the containing SourceFile, then uses
   * the TypeScript compiler API to compute the line number.
   */
  private getLineNumber(node: ts.Node): number {
    const sourceFile = node.getSourceFile();
    if (!sourceFile) return 0;
    const { line } = ts.getLineAndCharacterOfPosition(sourceFile, node.getStart(sourceFile));
    return line + 1; // Convert 0-based to 1-based
  }

  /**
   * Process a top-level expression node and dispatch to the
   * appropriate handler.
   */
  private processExpressionNode(
    expr: ts.Expression,
    state: AbstractState,
  ): TransferEffect[] {
    // Assignment: x = expr
    if (ts.isBinaryExpression(expr) && isAssignmentOperator(expr.operatorToken.kind)) {
      return this.processAssignment(expr, state);
    }

    // Standalone call expression: foo(args)
    if (ts.isCallExpression(expr)) {
      return this.processCallExpression(expr, state);
    }

    return [];
  }

  /**
   * Union the taint of all arguments in a call expression.
   *
   * Used as a conservative approximation when the callee is not a known
   * sink or sanitizer.
   */
  private unionArgTaint(
    node: ts.CallExpression,
    state: AbstractState,
  ): TaintFact {
    let result: TaintFact = createUntaintedFact();
    for (const arg of node.arguments) {
      result = joinFacts(result, this.resolveExpressionTaint(arg, state));
    }
    return result;
  }

  /**
   * Recursively walk an expression tree to detect and register taint
   * sources (e.g. `req.body`, `process.env`).
   *
   * Any detected sources are registered in the abstract state and
   * returned as `taint-source` effects.
   */
  private collectTaintSources(
    node: ts.Node,
    state: AbstractState,
  ): TransferEffect[] {
    const effects: TransferEffect[] = [];

    if (ts.isPropertyAccessExpression(node)) {
      effects.push(...this.detectTaintSource(node, state));
    }

    ts.forEachChild(node, (child) => {
      effects.push(...this.collectTaintSources(child, state));
    });

    return effects;
  }
}

// ── Module-level Helpers ─────────────────────────────────────────────

/**
 * Check whether a token kind represents an assignment operator.
 *
 * Covers `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `**=`, `<<=`, `>>=`,
 * `>>>=`, `&=`, `|=`, `^=`, `&&=`, `||=`, `??=`.
 */
function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

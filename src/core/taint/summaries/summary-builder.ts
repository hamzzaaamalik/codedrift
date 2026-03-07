/**
 * SummaryBuilder — Constructs per-function taint summaries by analyzing
 * function bodies with synthetic parameter taint.
 *
 * Each parameter is treated as tainted, and we do a forward pass to discover:
 *   - Which params flow to the return value (SummaryTransfer)
 *   - Which params reach known sinks (SummarySinkHit)
 *   - Which params are passed to other function calls (SummaryCallEdge)
 *   - Whether the function introduces new taint sources
 *   - Whether the function itself acts as a sanitizer
 */

import * as ts from 'typescript';
import * as crypto from 'crypto';
import type { TaintSourceKind, TaintSinkKind, SanitizationKind } from '../types.js';
import type {
  FunctionSummary,
  SummaryInput,
  SummaryOutput,
  SummaryTransfer,
  SummarySinkHit,
  SummaryCallEdge,
} from './summary-types.js';
import { CFGBuilder } from '../cfg/cfg-builder.js';
import { DataFlowSolver } from '../dataflow/dataflow-solver.js';
import { AbstractState } from '../dataflow/abstract-state.js';
import type { TransferEffect } from '../dataflow/transfer-functions.js';

// ---------------------------------------------------------------------------
// Sink pattern tables (mirrored from sink-detector.ts for summary context)
// ---------------------------------------------------------------------------

const DB_QUERY_METHODS = new Set([
  'findById', 'findOne', 'findUnique', 'findFirst', 'findMany',
  'query', 'where', 'select', 'findByPk', 'aggregate',
]);

const DB_MUTATION_METHODS = new Set([
  'create', 'insert', 'update', 'delete', 'destroy', 'save',
  'upsert', 'remove', 'deleteOne', 'deleteMany', 'updateOne',
  'updateMany', 'insertMany',
]);

const FILE_READ_METHODS = new Set([
  'readFile', 'readFileSync', 'createReadStream', 'access',
]);

const FILE_WRITE_METHODS = new Set([
  'writeFile', 'writeFileSync', 'createWriteStream', 'unlink', 'rename',
]);

const COMMAND_EXEC_METHODS = new Set([
  'exec', 'execSync', 'spawn', 'spawnSync',
]);

const REDIRECT_METHODS = new Set(['redirect']);

const EVAL_FUNCTIONS = new Set(['eval', 'Function']);

const SSRF_FUNCTIONS = new Set(['fetch', 'got']);

const SSRF_MODULES = new Set(['axios', 'http', 'https', 'undici']);

const SSRF_METHODS = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'request', 'fetch',
]);

const TEMPLATE_RENDER_METHODS = new Set(['render', 'compile']);
const TEMPLATE_CALLERS = new Set(['ejs', 'pug', 'handlebars']);

// ---------------------------------------------------------------------------
// Sanitizer pattern tables (mirrored from sanitizer-detector.ts)
// ---------------------------------------------------------------------------

const TYPE_COERCION_FUNCTIONS = new Set([
  'parseInt', 'parseFloat', 'Number', 'Boolean', 'String', 'BigInt',
]);

const SCHEMA_PARSE_METHODS = new Set(['parse', 'safeParse', 'validate']);
const SCHEMA_CALLERS = new Set([
  'z', 'zod', 'joi', 'yup', 'schema', 'ajv', 'vine', 'superstruct',
]);

const ESCAPE_FUNCTIONS = new Set([
  'escapeHtml', 'encodeURIComponent', 'encodeURI', 'sqlEscape', 'xss',
]);

const ESCAPE_DOTTED = new Map<string, Set<string>>([
  ['DOMPurify', new Set(['sanitize'])],
  ['validator', new Set(['escape'])],
]);

const CUSTOM_VALIDATOR_PATTERN = /^(validate|sanitize|check|verify|ensure|clean|filter|guard)/i;

// ---------------------------------------------------------------------------
// Taint source patterns (mirrored from source-detector.ts)
// ---------------------------------------------------------------------------

interface SourcePattern {
  object: string;
  property: string;
  kind: TaintSourceKind;
}

const SOURCE_PATTERNS: SourcePattern[] = [
  { object: 'req', property: 'body', kind: 'req.body' },
  { object: 'req', property: 'params', kind: 'req.params' },
  { object: 'req', property: 'query', kind: 'req.query' },
  { object: 'req', property: 'headers', kind: 'req.headers' },
  { object: 'req', property: 'cookies', kind: 'req.cookies' },
  { object: 'req', property: 'files', kind: 'req.files' },
  { object: 'req', property: 'ip', kind: 'req.ip' },
  { object: 'request', property: 'body', kind: 'req.body' },
  { object: 'request', property: 'params', kind: 'req.params' },
  { object: 'request', property: 'query', kind: 'req.query' },
  { object: 'request', property: 'headers', kind: 'req.headers' },
  { object: 'request', property: 'cookies', kind: 'req.cookies' },
  { object: 'request', property: 'files', kind: 'req.files' },
  { object: 'request', property: 'ip', kind: 'req.ip' },
  { object: 'ctx', property: 'params', kind: 'ctx.params' },
  { object: 'ctx', property: 'query', kind: 'ctx.query' },
  { object: 'request', property: 'payload', kind: 'request.payload' },
  { object: 'request', property: 'params', kind: 'request.params' },
  { object: 'request', property: 'query', kind: 'request.query' },
  { object: 'process', property: 'argv', kind: 'process.argv' },
  { object: 'process', property: 'env', kind: 'process.env' },
];

// ---------------------------------------------------------------------------
// Internal taint-tracking state
// ---------------------------------------------------------------------------

/** Per-variable tracking: which param indices flow into this variable */
interface VarTaintInfo {
  /** Set of param indices whose taint reaches this variable */
  paramSources: Set<number>;
  /** Sanitizations applied to this variable's taint */
  sanitizations: SanitizationKind[];
  /** Is this variable's taint fully sanitized? */
  isSanitized: boolean;
}

// ---------------------------------------------------------------------------
// SummaryBuilder
// ---------------------------------------------------------------------------

export class SummaryBuilder {
  /**
   * Build summaries for all functions in a source file.
   */
  buildFileSummaries(
    sourceFile: ts.SourceFile,
    filePath: string,
    exportedNames: Set<string>,
  ): FunctionSummary[] {
    const summaries: FunctionSummary[] = [];
    this.visitFileLevel(sourceFile, filePath, exportedNames, summaries, undefined);
    return summaries;
  }

  /**
   * Build a summary for a single function-like declaration.
   */
  buildFunctionSummary(
    functionNode: ts.FunctionLikeDeclaration,
    canonicalId: string,
    filePath: string,
    isExported: boolean,
  ): FunctionSummary {
    const functionName = this.extractFunctionName(functionNode);
    const paramNames = this.extractParamNames(functionNode);
    const paramCount = functionNode.parameters.length;
    const isAsync = this.isAsyncFunction(functionNode);
    const isConstructor = ts.isConstructorDeclaration(functionNode);
    const containingClass = this.getContainingClassName(functionNode);

    // Compute body hash for incremental invalidation
    const body = functionNode.body;
    const bodyText = body ? body.getText() : '';
    const bodyHash = crypto.createHash('sha256').update(bodyText).digest('hex').slice(0, 16);

    // Track sanitizations applied at specific points: variable -> sanitizations
    const transfers: SummaryTransfer[] = [];
    const sinkHits: SummarySinkHit[] = [];
    const callEdges: SummaryCallEdge[] = [];
    const taintSources: { kind: TaintSourceKind; output: SummaryOutput }[] = [];

    if (body) {
      // Primary: flat AST walk (proven, comprehensive detection)
      const taintMap = new Map<string, VarTaintInfo>();
      for (let i = 0; i < paramCount; i++) {
        const param = functionNode.parameters[i];
        this.seedParamTaint(param, i, taintMap);
      }
      this.walkBody(
        body, taintMap, paramNames, filePath,
        transfers, sinkHits, callEdges, taintSources, functionNode,
      );

      // Augment with CFG-based path-sensitive analysis for additional precision
      try {
        if (ts.isBlock(body)) {
          const cfgBuilder = new CFGBuilder();
          const cfg = cfgBuilder.build(functionNode);
          const entryState = AbstractState.createEntryState(paramCount, paramNames);
          const solver = new DataFlowSolver({ pathSensitive: true, fieldSensitive: true });
          const result = solver.solve(cfg, entryState, filePath, paramNames);

          // Merge any additional findings from CFG analysis (deduped)
          const existingSinkKeys = new Set(sinkHits.map(h => `${h.sinkKind}:${h.line}`));
          const existingEdgeKeys = new Set(callEdges.map(e => `${e.calleeCanonicalId}:${e.line}`));
          const cfgTransfers: SummaryTransfer[] = [];
          const cfgSinkHits: SummarySinkHit[] = [];
          const cfgCallEdges: SummaryCallEdge[] = [];
          const cfgTaintSources: { kind: TaintSourceKind; output: SummaryOutput }[] = [];

          this.convertEffectsToSummary(
            result.effects, paramNames, filePath, cfgTransfers, cfgSinkHits, cfgCallEdges, cfgTaintSources,
          );

          // Add only new findings not already discovered by AST walk
          for (const hit of cfgSinkHits) {
            if (!existingSinkKeys.has(`${hit.sinkKind}:${hit.line}`)) {
              sinkHits.push(hit);
            }
          }
          for (const edge of cfgCallEdges) {
            if (!existingEdgeKeys.has(`${edge.calleeCanonicalId}:${edge.line}`)) {
              callEdges.push(edge);
            }
          }
        }
      } catch {
        // CFG augmentation failed — AST walk results are sufficient
      }
    }

    // Determine if the function is itself a sanitizer
    const { isSanitizer, sanitizerKind } = this.detectSanitizerFunction(
      functionNode,
      transfers,
      sinkHits,
      paramCount,
    );

    return {
      canonicalId,
      filePath,
      functionName,
      paramCount,
      paramNames,
      isAsync,
      isExported,
      isConstructor,
      containingClass,
      transfers,
      sinkHits,
      callEdges,
      taintSources,
      isSanitizer,
      sanitizerKind,
      bodyHash,
      isComplete: true,
    };
  }

  // =========================================================================
  // File-level visitor — finds all function declarations
  // =========================================================================

  private visitFileLevel(
    node: ts.Node,
    filePath: string,
    exportedNames: Set<string>,
    summaries: FunctionSummary[],
    containingClass: string | undefined,
  ): void {
    // Function declaration
    if (ts.isFunctionDeclaration(node) && node.name) {
      const name = node.name.text;
      const canonicalId = `${filePath}#${name}`;
      const isExported = exportedNames.has(name) || this.hasExportModifier(node);
      summaries.push(this.buildFunctionSummary(node, canonicalId, filePath, isExported));
    }

    // Variable declaration with arrow / function expression
    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        if (
          decl.initializer &&
          ts.isIdentifier(decl.name) &&
          this.isFunctionLike(decl.initializer)
        ) {
          const name = decl.name.text;
          const canonicalId = `${filePath}#${name}`;
          const isExported = exportedNames.has(name) || this.hasExportModifier(node);
          summaries.push(
            this.buildFunctionSummary(
              decl.initializer as ts.FunctionLikeDeclaration,
              canonicalId,
              filePath,
              isExported,
            ),
          );
        }
      }
    }

    // Class declaration — visit methods
    if (ts.isClassDeclaration(node)) {
      const className = node.name?.text;
      for (const member of node.members) {
        if (
          (ts.isMethodDeclaration(member) ||
            ts.isConstructorDeclaration(member) ||
            ts.isGetAccessorDeclaration(member) ||
            ts.isSetAccessorDeclaration(member)) &&
          member.body
        ) {
          const methodName = ts.isConstructorDeclaration(member)
            ? 'constructor'
            : (member.name && ts.isIdentifier(member.name) ? member.name.text : '<computed>');
          const qualifiedName = className ? `${className}.${methodName}` : methodName;
          const canonicalId = `${filePath}#${qualifiedName}`;
          const isExported =
            (className !== undefined && exportedNames.has(className)) ||
            this.hasExportModifier(node);
          summaries.push(
            this.buildFunctionSummary(member, canonicalId, filePath, isExported),
          );
        }
      }
    }

    // Export default function expression
    if (ts.isExportAssignment(node) && node.expression && this.isFunctionLike(node.expression)) {
      const canonicalId = `${filePath}#default`;
      summaries.push(
        this.buildFunctionSummary(
          node.expression as ts.FunctionLikeDeclaration,
          canonicalId,
          filePath,
          true,
        ),
      );
    }

    // Recurse into module-level children (but not into function bodies)
    if (
      !ts.isFunctionDeclaration(node) &&
      !ts.isArrowFunction(node) &&
      !ts.isFunctionExpression(node) &&
      !ts.isMethodDeclaration(node)
    ) {
      ts.forEachChild(node, (child) =>
        this.visitFileLevel(child, filePath, exportedNames, summaries, containingClass),
      );
    }
  }

  // =========================================================================
  // Body walker — forward pass taint propagation
  // =========================================================================

  private walkBody(
    body: ts.Node,
    taintMap: Map<string, VarTaintInfo>,
    paramNames: string[],
    filePath: string,
    transfers: SummaryTransfer[],
    sinkHits: SummarySinkHit[],
    callEdges: SummaryCallEdge[],
    taintSources: { kind: TaintSourceKind; output: SummaryOutput }[],
    functionNode: ts.FunctionLikeDeclaration,
  ): void {
    const visit = (node: ts.Node): void => {
      // Variable declarations: propagate taint
      if (ts.isVariableStatement(node)) {
        for (const decl of node.declarationList.declarations) {
          this.processDeclaration(decl, taintMap);
        }
      }

      // Assignment expressions: x = tainted
      if (ts.isExpressionStatement(node)) {
        const expr = node.expression;
        if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
          this.processAssignment(expr, taintMap, paramNames, transfers);
        }
      }

      // Return statements: check if returning tainted value
      if (ts.isReturnStatement(node) && node.expression) {
        this.processReturn(node.expression, taintMap, paramNames, transfers, functionNode);
      }

      // Call expressions: check for sinks, sanitizers, and call edges
      if (ts.isCallExpression(node)) {
        this.processCall(node, taintMap, paramNames, filePath, sinkHits, callEdges);
        this.processSanitizer(node, taintMap);
      }

      // new Function() — eval sink
      if (ts.isNewExpression(node)) {
        this.processNewExpression(node, taintMap, paramNames, sinkHits);
      }

      // innerHTML assignment — html-output sink
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left) &&
        node.left.name.text === 'innerHTML'
      ) {
        const sources = this.resolveExprTaint(node.right, taintMap);
        if (sources.size > 0) {
          const line = this.getLineNumber(node);
          for (const paramIdx of sources) {
            sinkHits.push({
              input: this.makeParamInput(paramIdx, paramNames),
              sinkKind: 'html-output',
              sinkCallee: 'innerHTML',
              sanitized: this.isTaintSanitized(node.right, taintMap),
              sanitizations: this.collectSanitizations(node.right, taintMap),
              line,
            });
          }
        }
      }

      // Param mutation: param.x = expr
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left)
      ) {
        this.processParamMutation(node, taintMap, paramNames, transfers);
      }

      // Taint source detection: does this function access req.body etc.?
      if (ts.isPropertyAccessExpression(node)) {
        this.detectTaintSource(node, taintSources);
      }

      // Do NOT recurse into nested function bodies (they get their own summaries)
      if (
        ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isArrowFunction(node) ||
        ts.isMethodDeclaration(node)
      ) {
        // But DO check if a tainted value is passed as an arg to a callback
        // that is defined inline — we handle this via processCall on the parent
        return;
      }

      ts.forEachChild(node, visit);
    };

    // For concise arrow bodies (no block), treat the body itself as a return
    if (!ts.isBlock(body)) {
      // Concise arrow: (x) => x.field — body IS the return expression
      this.processReturn(body as ts.Expression, taintMap, paramNames, transfers, functionNode);
      // Also check for calls within the concise body
      const visitExpr = (n: ts.Node): void => {
        if (ts.isCallExpression(n)) {
          this.processCall(n, taintMap, paramNames, filePath, sinkHits, callEdges);
          this.processSanitizer(n, taintMap);
        }
        if (ts.isPropertyAccessExpression(n)) {
          this.detectTaintSource(n, taintSources);
        }
        ts.forEachChild(n, visitExpr);
      };
      visitExpr(body);
    } else {
      ts.forEachChild(body, visit);
    }
  }

  // =========================================================================
  // Declaration & assignment processing
  // =========================================================================

  private processDeclaration(
    decl: ts.VariableDeclaration,
    taintMap: Map<string, VarTaintInfo>,
  ): void {
    if (!decl.initializer) return;

    const sources = this.resolveExprTaint(decl.initializer, taintMap);
    if (sources.size === 0) return;

    const sanitizations = this.collectSanitizations(decl.initializer, taintMap);
    const isSanitized = this.isTaintSanitized(decl.initializer, taintMap);

    if (ts.isIdentifier(decl.name)) {
      taintMap.set(decl.name.text, {
        paramSources: new Set(sources),
        sanitizations,
        isSanitized,
      });
    } else if (ts.isObjectBindingPattern(decl.name)) {
      for (const element of decl.name.elements) {
        if (ts.isIdentifier(element.name)) {
          taintMap.set(element.name.text, {
            paramSources: new Set(sources),
            sanitizations: [...sanitizations],
            isSanitized,
          });
        }
      }
    } else if (ts.isArrayBindingPattern(decl.name)) {
      for (const element of decl.name.elements) {
        if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
          taintMap.set(element.name.text, {
            paramSources: new Set(sources),
            sanitizations: [...sanitizations],
            isSanitized,
          });
        }
      }
    }
  }

  private processAssignment(
    expr: ts.BinaryExpression,
    taintMap: Map<string, VarTaintInfo>,
    _paramNames: string[],
    _transfers: SummaryTransfer[],
  ): void {
    const sources = this.resolveExprTaint(expr.right, taintMap);
    if (sources.size === 0) return;

    const sanitizations = this.collectSanitizations(expr.right, taintMap);
    const isSanitized = this.isTaintSanitized(expr.right, taintMap);

    if (ts.isIdentifier(expr.left)) {
      taintMap.set(expr.left.text, {
        paramSources: new Set(sources),
        sanitizations,
        isSanitized,
      });
    }
  }

  // =========================================================================
  // Return processing
  // =========================================================================

  private processReturn(
    expr: ts.Expression,
    taintMap: Map<string, VarTaintInfo>,
    paramNames: string[],
    transfers: SummaryTransfer[],
    functionNode: ts.FunctionLikeDeclaration,
  ): void {
    const sources = this.resolveExprTaint(expr, taintMap);
    if (sources.size === 0) return;

    const isAsync = this.isAsyncFunction(functionNode);
    const outputKind: SummaryOutput['kind'] = isAsync ? 'promise-resolve' : 'return';

    for (const paramIdx of sources) {
      const sanitizations = this.collectSanitizationsForParam(paramIdx, expr, taintMap);
      const isSanitized = this.isTaintSanitizedForParam(paramIdx, expr, taintMap);

      transfers.push({
        from: this.makeParamInput(paramIdx, paramNames),
        to: {
          kind: outputKind,
          label: outputKind === 'return' ? 'return value' : 'resolved promise value',
        },
        sanitizations,
        isSanitized,
        confidence: this.inferConfidence(expr),
      });
    }
  }

  // =========================================================================
  // Param mutation processing
  // =========================================================================

  private processParamMutation(
    node: ts.BinaryExpression,
    taintMap: Map<string, VarTaintInfo>,
    paramNames: string[],
    transfers: SummaryTransfer[],
  ): void {
    const left = node.left;
    if (!ts.isPropertyAccessExpression(left)) return;

    // Check if the root of the property access is a parameter
    const root = this.getRootIdentifier(left);
    if (!root) return;

    const paramIndex = paramNames.indexOf(root.text);
    if (paramIndex < 0) return;

    // Check if the right-hand side carries taint from a different param
    const rhsSources = this.resolveExprTaint(node.right, taintMap);
    if (rhsSources.size === 0) return;

    const accessPath = this.getAccessPath(left);

    for (const sourceIdx of rhsSources) {
      if (sourceIdx === paramIndex) continue; // Self-mutation is not interesting
      const sanitizations = this.collectSanitizationsForParam(sourceIdx, node.right, taintMap);
      const isSanitized = this.isTaintSanitizedForParam(sourceIdx, node.right, taintMap);

      transfers.push({
        from: this.makeParamInput(sourceIdx, paramNames),
        to: {
          kind: 'param-mutation',
          paramIndex,
          accessPath,
          label: `param[${paramIndex}].${accessPath.join('.')}`,
        },
        sanitizations,
        isSanitized,
        confidence: 'definite',
      });
    }
  }

  // =========================================================================
  // Call expression processing — sinks, call edges, callbacks
  // =========================================================================

  private processCall(
    node: ts.CallExpression,
    taintMap: Map<string, VarTaintInfo>,
    paramNames: string[],
    filePath: string,
    sinkHits: SummarySinkHit[],
    callEdges: SummaryCallEdge[],
  ): void {
    const callee = node.expression;
    const line = this.getLineNumber(node);

    // Check each argument for taint
    const taintedArgs: { argIndex: number; paramSources: Set<number> }[] = [];
    for (let i = 0; i < node.arguments.length; i++) {
      const arg = node.arguments[i];
      const sources = this.resolveExprTaint(arg, taintMap);
      if (sources.size > 0) {
        taintedArgs.push({ argIndex: i, paramSources: sources });
      }
    }

    if (taintedArgs.length === 0) return;

    // Check if this call is a known sink
    const sinkKind = this.classifyCallAsSink(node);
    if (sinkKind) {
      const calleeText = callee.getText();
      for (const { paramSources } of taintedArgs) {
        for (const paramIdx of paramSources) {
          sinkHits.push({
            input: this.makeParamInput(paramIdx, paramNames),
            sinkKind,
            sinkCallee: calleeText,
            sanitized: this.isTaintSanitizedForParam(paramIdx, node, taintMap),
            sanitizations: this.collectSanitizationsForParam(paramIdx, node, taintMap),
            line,
          });
        }
      }
      return; // Sinks do not create call edges
    }

    // Otherwise, create a call edge for inter-procedural resolution
    const calleeId = this.resolveCalleeId(node, filePath);
    if (!calleeId) return;

    const argMapping: SummaryCallEdge['argMapping'] = [];
    for (const { argIndex, paramSources } of taintedArgs) {
      for (const paramIdx of paramSources) {
        argMapping.push({
          callerInput: this.makeParamInput(paramIdx, paramNames),
          calleeParamIndex: argIndex,
        });
      }
    }

    const returnMapping = this.resolveReturnMapping(node);

    // If there's a return mapping, propagate taint to the assigned variable
    if (returnMapping) {
      const allSources = new Set<number>();
      for (const { paramSources } of taintedArgs) {
        for (const s of paramSources) allSources.add(s);
      }
      taintMap.set(returnMapping.assignedTo, {
        paramSources: allSources,
        sanitizations: [],
        isSanitized: false,
      });
    }

    callEdges.push({
      calleeCanonicalId: calleeId,
      argMapping,
      returnMapping: returnMapping ?? undefined,
      line,
    });
  }

  private processNewExpression(
    node: ts.NewExpression,
    taintMap: Map<string, VarTaintInfo>,
    paramNames: string[],
    sinkHits: SummarySinkHit[],
  ): void {
    const expr = node.expression;
    if (!ts.isIdentifier(expr) || expr.text !== 'Function') return;

    const args = node.arguments;
    if (!args || args.length === 0) return;

    const line = this.getLineNumber(node);
    for (const arg of args) {
      const sources = this.resolveExprTaint(arg, taintMap);
      for (const paramIdx of sources) {
        sinkHits.push({
          input: this.makeParamInput(paramIdx, paramNames),
          sinkKind: 'eval',
          sinkCallee: 'new Function',
          sanitized: this.isTaintSanitizedForParam(paramIdx, arg, taintMap),
          sanitizations: this.collectSanitizationsForParam(paramIdx, arg, taintMap),
          line,
        });
      }
    }
  }

  // =========================================================================
  // Sanitizer processing
  // =========================================================================

  private processSanitizer(
    node: ts.CallExpression,
    taintMap: Map<string, VarTaintInfo>,
  ): void {
    const kind = this.classifyCallAsSanitizer(node);
    if (!kind) return;

    // The sanitizer's first argument is typically what's being sanitized.
    // The result (if assigned) should be marked as sanitized.
    const parent = node.parent;

    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      const sources = this.resolveExprTaint(node, taintMap);
      taintMap.set(parent.name.text, {
        paramSources: sources,
        sanitizations: [kind],
        isSanitized: true,
      });
      return;
    }

    if (
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(parent.left)
    ) {
      const sources = this.resolveExprTaint(node, taintMap);
      taintMap.set(parent.left.text, {
        paramSources: sources,
        sanitizations: [kind],
        isSanitized: true,
      });
    }
  }

  // =========================================================================
  // Taint source detection — does the function body access req.body etc.?
  // =========================================================================

  private detectTaintSource(
    node: ts.PropertyAccessExpression,
    taintSources: { kind: TaintSourceKind; output: SummaryOutput }[],
  ): void {
    // Check for ctx.request.body (3-level Koa pattern)
    if (
      node.name.text === 'body' &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'request' &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === 'ctx'
    ) {
      taintSources.push({
        kind: 'ctx.request.body',
        output: { kind: 'return', label: 'ctx.request.body' },
      });
      return;
    }

    // Standard 2-level patterns
    if (!ts.isIdentifier(node.expression)) return;
    const obj = node.expression.text;
    const prop = node.name.text;

    const match = SOURCE_PATTERNS.find((p) => p.object === obj && p.property === prop);
    if (match) {
      taintSources.push({
        kind: match.kind,
        output: { kind: 'return', label: `${obj}.${prop}` },
      });
    }
  }

  // =========================================================================
  // CFG-based effect conversion
  // =========================================================================

  /**
   * Convert DataFlowSolver TransferEffects into the summary format
   * (SummaryTransfer, SummarySinkHit, SummaryCallEdge, taint sources).
   */
  private convertEffectsToSummary(
    effects: TransferEffect[],
    paramNames: string[],
    _filePath: string,
    transfers: SummaryTransfer[],
    sinkHits: SummarySinkHit[],
    callEdges: SummaryCallEdge[],
    taintSources: { kind: TaintSourceKind; output: SummaryOutput }[],
  ): void {
    for (const effect of effects) {
      switch (effect.kind) {
        case 'sink-hit': {
          if (!effect.sinkKind || !effect.paramSources) break;
          for (const paramIdx of effect.paramSources) {
            sinkHits.push({
              input: this.makeParamInput(paramIdx, paramNames),
              sinkKind: effect.sinkKind as TaintSinkKind,
              sinkCallee: effect.sinkCallee ?? '<unknown>',
              sanitized: effect.sanitized ?? false,
              sanitizations: (effect.sanitizations ?? []) as SanitizationKind[],
              line: effect.line ?? 0,
            });
          }
          break;
        }
        case 'call-edge': {
          if (!effect.calleeId || !effect.argMapping) break;
          const argMapping: SummaryCallEdge['argMapping'] = [];
          for (const mapping of effect.argMapping) {
            for (const paramIdx of mapping.callerParamSources) {
              argMapping.push({
                callerInput: this.makeParamInput(paramIdx, paramNames),
                calleeParamIndex: mapping.calleeArgIndex,
              });
            }
          }
          if (argMapping.length > 0) {
            callEdges.push({
              calleeCanonicalId: effect.calleeId,
              argMapping,
              returnMapping: effect.returnAssignedTo
                ? { assignedTo: effect.returnAssignedTo }
                : undefined,
              line: effect.line ?? 0,
            });
          }
          break;
        }
        case 'return-transfer': {
          if (!effect.returnParamSources) break;
          for (const paramIdx of effect.returnParamSources) {
            transfers.push({
              from: this.makeParamInput(paramIdx, paramNames),
              to: { kind: 'return', label: 'return' },
              isSanitized: effect.returnSanitized ?? false,
              sanitizations: (effect.returnSanitizations ?? []) as SanitizationKind[],
              confidence: 'definite',
            });
          }
          break;
        }
        case 'taint-source': {
          if (!effect.sourceKind || !effect.outputVar) break;
          taintSources.push({
            kind: effect.sourceKind as TaintSourceKind,
            output: { kind: 'return', label: effect.sourceKind ?? 'source' },
          });
          break;
        }
      }
    }
  }

  // =========================================================================
  // Sanitizer function detection — is this function itself a sanitizer?
  // =========================================================================

  private detectSanitizerFunction(
    functionNode: ts.FunctionLikeDeclaration,
    transfers: SummaryTransfer[],
    sinkHits: SummarySinkHit[],
    paramCount: number,
  ): { isSanitizer: boolean; sanitizerKind?: SanitizationKind } {
    // A function is a sanitizer if:
    // 1. It has at least one parameter
    // 2. It has no unsanitized sink hits
    // 3. All transfer edges are sanitized
    // 4. It has transfer edges (it returns something)
    if (paramCount === 0) return { isSanitizer: false };
    if (sinkHits.some((s) => !s.sanitized)) return { isSanitizer: false };
    if (transfers.length === 0) return { isSanitizer: false };
    if (transfers.some((t) => !t.isSanitized)) return { isSanitizer: false };

    // Check the function name for sanitizer hints
    const funcName = this.extractFunctionName(functionNode);
    if (CUSTOM_VALIDATOR_PATTERN.test(funcName)) {
      return { isSanitizer: true, sanitizerKind: 'custom-validator' };
    }

    // If all transfers are sanitized, pick the most common sanitization kind
    const kinds = transfers.flatMap((t) => t.sanitizations);
    if (kinds.length > 0) {
      const freq = new Map<SanitizationKind, number>();
      for (const k of kinds) {
        freq.set(k, (freq.get(k) ?? 0) + 1);
      }
      let bestKind: SanitizationKind = kinds[0];
      let bestCount = 0;
      for (const [k, c] of freq) {
        if (c > bestCount) {
          bestKind = k;
          bestCount = c;
        }
      }
      return { isSanitizer: true, sanitizerKind: bestKind };
    }

    return { isSanitizer: false };
  }

  // =========================================================================
  // Taint resolution — resolve which param indices flow through an expression
  // =========================================================================

  private resolveExprTaint(
    expr: ts.Expression | ts.Node,
    taintMap: Map<string, VarTaintInfo>,
  ): Set<number> {
    if (ts.isIdentifier(expr)) {
      const info = taintMap.get(expr.text);
      return info ? new Set(info.paramSources) : new Set();
    }

    if (ts.isPropertyAccessExpression(expr)) {
      return this.resolveExprTaint(expr.expression, taintMap);
    }

    if (ts.isElementAccessExpression(expr)) {
      return this.resolveExprTaint(expr.expression, taintMap);
    }

    if (ts.isCallExpression(expr)) {
      // Check if the call result is a known sanitizer wrapping a tainted value
      for (const arg of expr.arguments) {
        const sources = this.resolveExprTaint(arg, taintMap);
        if (sources.size > 0) return sources;
      }
      return new Set();
    }

    if (ts.isTemplateExpression(expr)) {
      const result = new Set<number>();
      for (const span of expr.templateSpans) {
        for (const s of this.resolveExprTaint(span.expression, taintMap)) {
          result.add(s);
        }
      }
      return result;
    }

    if (ts.isTaggedTemplateExpression(expr)) {
      if (ts.isTemplateExpression(expr.template)) {
        return this.resolveExprTaint(expr.template, taintMap);
      }
      return new Set();
    }

    if (ts.isBinaryExpression(expr)) {
      if (
        expr.operatorToken.kind === ts.SyntaxKind.PlusToken ||
        expr.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken
      ) {
        const result = new Set<number>();
        for (const s of this.resolveExprTaint(expr.left, taintMap)) result.add(s);
        for (const s of this.resolveExprTaint(expr.right, taintMap)) result.add(s);
        return result;
      }
      return new Set();
    }

    if (ts.isAwaitExpression(expr)) {
      return this.resolveExprTaint(expr.expression, taintMap);
    }

    if (ts.isConditionalExpression(expr)) {
      const result = new Set<number>();
      for (const s of this.resolveExprTaint(expr.whenTrue, taintMap)) result.add(s);
      for (const s of this.resolveExprTaint(expr.whenFalse, taintMap)) result.add(s);
      return result;
    }

    if (ts.isSpreadElement(expr)) {
      return this.resolveExprTaint(expr.expression, taintMap);
    }

    if (ts.isObjectLiteralExpression(expr)) {
      const result = new Set<number>();
      for (const prop of expr.properties) {
        if (ts.isSpreadAssignment(prop)) {
          for (const s of this.resolveExprTaint(prop.expression, taintMap)) result.add(s);
        } else if (ts.isPropertyAssignment(prop)) {
          for (const s of this.resolveExprTaint(prop.initializer, taintMap)) result.add(s);
        } else if (ts.isShorthandPropertyAssignment(prop)) {
          const info = taintMap.get(prop.name.text);
          if (info) {
            for (const s of info.paramSources) result.add(s);
          }
        }
      }
      return result;
    }

    if (ts.isArrayLiteralExpression(expr)) {
      const result = new Set<number>();
      for (const el of expr.elements) {
        for (const s of this.resolveExprTaint(el, taintMap)) result.add(s);
      }
      return result;
    }

    if (ts.isParenthesizedExpression(expr)) {
      return this.resolveExprTaint(expr.expression, taintMap);
    }

    if (ts.isNonNullExpression(expr)) {
      return this.resolveExprTaint(expr.expression, taintMap);
    }

    if (ts.isAsExpression(expr) || ts.isTypeAssertionExpression(expr)) {
      return this.resolveExprTaint(expr.expression, taintMap);
    }

    if (ts.isPrefixUnaryExpression(expr)) {
      return this.resolveExprTaint(expr.operand, taintMap);
    }

    return new Set();
  }

  // =========================================================================
  // Sink classification
  // =========================================================================

  private classifyCallAsSink(node: ts.CallExpression): TaintSinkKind | null {
    const callee = node.expression;

    // Simple identifier calls
    if (ts.isIdentifier(callee)) {
      const name = callee.text;
      if (EVAL_FUNCTIONS.has(name)) return 'eval';
      if (COMMAND_EXEC_METHODS.has(name)) return 'command-execution';
      if (SSRF_FUNCTIONS.has(name)) return 'http-request';
      if (name === 'axios') return 'http-request';
      return null;
    }

    // Property access calls: obj.method()
    if (ts.isPropertyAccessExpression(callee)) {
      const method = callee.name.text;
      const objText = callee.expression.getText();

      if (DB_QUERY_METHODS.has(method)) return 'db-query';
      if (DB_MUTATION_METHODS.has(method)) return 'db-mutation';
      if (FILE_READ_METHODS.has(method) && this.looksLikeFsOrPath(objText)) return 'file-read';
      if (FILE_WRITE_METHODS.has(method) && this.looksLikeFsOrPath(objText)) return 'file-write';
      if (COMMAND_EXEC_METHODS.has(method) && this.looksLikeChildProcess(objText)) return 'command-execution';
      if (method === 'send' && this.looksLikeResponse(objText)) return 'html-output';
      if (method === 'write' && objText === 'document') return 'html-output';
      if (TEMPLATE_RENDER_METHODS.has(method) && (this.looksLikeResponse(objText) || TEMPLATE_CALLERS.has(objText))) return 'html-output';
      if (REDIRECT_METHODS.has(method) && this.looksLikeResponse(objText)) return 'redirect';
      if (SSRF_MODULES.has(objText) && SSRF_METHODS.has(method)) return 'http-request';

      return null;
    }

    return null;
  }

  // =========================================================================
  // Sanitizer classification
  // =========================================================================

  private classifyCallAsSanitizer(node: ts.CallExpression): SanitizationKind | null {
    const callee = node.expression;

    if (ts.isIdentifier(callee)) {
      const name = callee.text;
      if (TYPE_COERCION_FUNCTIONS.has(name)) return 'type-coercion';
      if (ESCAPE_FUNCTIONS.has(name)) return 'escape';
      if (CUSTOM_VALIDATOR_PATTERN.test(name)) return 'custom-validator';
      return null;
    }

    if (ts.isPropertyAccessExpression(callee)) {
      const method = callee.name.text;
      const objText = callee.expression.getText();

      if (SCHEMA_CALLERS.has(objText) && SCHEMA_PARSE_METHODS.has(method)) return 'schema-validation';
      if (SCHEMA_PARSE_METHODS.has(method) && this.looksLikeSchema(callee.expression)) return 'schema-validation';

      const escapeMethods = ESCAPE_DOTTED.get(objText);
      if (escapeMethods && escapeMethods.has(method)) return 'escape';

      if (CUSTOM_VALIDATOR_PATTERN.test(method)) return 'custom-validator';
      return null;
    }

    return null;
  }

  // =========================================================================
  // Callee ID resolution
  // =========================================================================

  private resolveCalleeId(node: ts.CallExpression, filePath: string): string | null {
    const callee = node.expression;

    if (ts.isIdentifier(callee)) {
      // Local or imported function — use filePath#name as a placeholder.
      // The summary store will resolve imports later.
      return `${filePath}#${callee.text}`;
    }

    if (ts.isPropertyAccessExpression(callee)) {
      const method = callee.name.text;
      const obj = callee.expression;

      // this.method() — same class
      if (ts.isIdentifier(obj) && obj.text === 'this') {
        return `${filePath}#this.${method}`;
      }

      // module.method() — could be an import
      if (ts.isIdentifier(obj)) {
        return `${filePath}#${obj.text}.${method}`;
      }
    }

    return null;
  }

  private resolveReturnMapping(
    node: ts.CallExpression,
  ): { assignedTo: string; accessPath?: string[] } | null {
    const parent = node.parent;

    // const x = fn(...)
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return { assignedTo: parent.name.text };
    }

    // x = fn(...)
    if (
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(parent.left)
    ) {
      return { assignedTo: parent.left.text };
    }

    // await fn(...) — check grandparent
    if (ts.isAwaitExpression(parent)) {
      const grandparent = parent.parent;
      if (ts.isVariableDeclaration(grandparent) && ts.isIdentifier(grandparent.name)) {
        return { assignedTo: grandparent.name.text };
      }
      if (
        ts.isBinaryExpression(grandparent) &&
        grandparent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(grandparent.left)
      ) {
        return { assignedTo: grandparent.left.text };
      }
    }

    return null;
  }

  // =========================================================================
  // Sanitization tracking helpers
  // =========================================================================

  private isTaintSanitized(
    expr: ts.Expression | ts.Node,
    taintMap: Map<string, VarTaintInfo>,
  ): boolean {
    if (ts.isIdentifier(expr)) {
      const info = taintMap.get(expr.text);
      return info?.isSanitized ?? false;
    }
    return false;
  }

  private isTaintSanitizedForParam(
    paramIdx: number,
    expr: ts.Expression | ts.Node,
    taintMap: Map<string, VarTaintInfo>,
  ): boolean {
    if (ts.isIdentifier(expr)) {
      const info = taintMap.get(expr.text);
      if (info && info.paramSources.has(paramIdx)) {
        return info.isSanitized;
      }
    }
    return false;
  }

  private collectSanitizations(
    expr: ts.Expression | ts.Node,
    taintMap: Map<string, VarTaintInfo>,
  ): SanitizationKind[] {
    if (ts.isIdentifier(expr)) {
      const info = taintMap.get(expr.text);
      return info?.sanitizations ?? [];
    }
    return [];
  }

  private collectSanitizationsForParam(
    _paramIdx: number,
    expr: ts.Expression | ts.Node,
    taintMap: Map<string, VarTaintInfo>,
  ): SanitizationKind[] {
    return this.collectSanitizations(expr, taintMap);
  }

  // =========================================================================
  // Parameter seeding
  // =========================================================================

  private seedParamTaint(
    param: ts.ParameterDeclaration,
    paramIndex: number,
    taintMap: Map<string, VarTaintInfo>,
  ): void {
    if (ts.isIdentifier(param.name)) {
      taintMap.set(param.name.text, {
        paramSources: new Set([paramIndex]),
        sanitizations: [],
        isSanitized: false,
      });
    } else if (ts.isObjectBindingPattern(param.name)) {
      // Destructured parameter: function({ a, b })
      for (const element of param.name.elements) {
        if (ts.isIdentifier(element.name)) {
          taintMap.set(element.name.text, {
            paramSources: new Set([paramIndex]),
            sanitizations: [],
            isSanitized: false,
          });
        }
      }
    } else if (ts.isArrayBindingPattern(param.name)) {
      for (const element of param.name.elements) {
        if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
          taintMap.set(element.name.text, {
            paramSources: new Set([paramIndex]),
            sanitizations: [],
            isSanitized: false,
          });
        }
      }
    }

    // Handle default parameter values — they don't introduce external taint
    // but we still mark the parameter as tainted (the caller controls the value)
  }

  // =========================================================================
  // AST utility helpers
  // =========================================================================

  private extractFunctionName(node: ts.FunctionLikeDeclaration): string {
    // Named function declaration
    if (ts.isFunctionDeclaration(node) && node.name) {
      return node.name.text;
    }

    // Method declaration
    if (ts.isMethodDeclaration(node) && node.name) {
      if (ts.isIdentifier(node.name)) return node.name.text;
      if (ts.isStringLiteral(node.name)) return node.name.text;
      return '<computed>';
    }

    // Constructor
    if (ts.isConstructorDeclaration(node)) {
      return 'constructor';
    }

    // Get/Set accessor
    if (ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) {
      if (ts.isIdentifier(node.name)) return node.name.text;
      return '<accessor>';
    }

    // Arrow or function expression assigned to variable
    const parent = node.parent;
    if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }

    // Property assignment: { handler: function() {} }
    if (parent && ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }

    // Named function expression
    if (ts.isFunctionExpression(node) && node.name) {
      return node.name.text;
    }

    return '<anonymous>';
  }

  private extractParamNames(node: ts.FunctionLikeDeclaration): string[] {
    return node.parameters.map((p) => {
      if (ts.isIdentifier(p.name)) return p.name.text;
      if (ts.isObjectBindingPattern(p.name)) return '{...}';
      if (ts.isArrayBindingPattern(p.name)) return '[...]';
      return '_';
    });
  }

  private isAsyncFunction(node: ts.FunctionLikeDeclaration): boolean {
    const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
    if (modifiers) {
      for (const mod of modifiers) {
        if (mod.kind === ts.SyntaxKind.AsyncKeyword) return true;
      }
    }
    return false;
  }

  private hasExportModifier(node: ts.Node): boolean {
    if (!ts.canHaveModifiers(node)) return false;
    const modifiers = ts.getModifiers(node);
    if (!modifiers) return false;
    return modifiers.some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
  }

  private getContainingClassName(node: ts.Node): string | undefined {
    let current = node.parent;
    while (current) {
      if (ts.isClassDeclaration(current) && current.name) {
        return current.name.text;
      }
      current = current.parent;
    }
    return undefined;
  }

  private isFunctionLike(node: ts.Node): boolean {
    return (
      ts.isArrowFunction(node) ||
      ts.isFunctionExpression(node) ||
      ts.isFunctionDeclaration(node)
    );
  }

  private getRootIdentifier(expr: ts.Expression): ts.Identifier | null {
    if (ts.isIdentifier(expr)) return expr;
    if (ts.isPropertyAccessExpression(expr)) return this.getRootIdentifier(expr.expression);
    if (ts.isElementAccessExpression(expr)) return this.getRootIdentifier(expr.expression);
    return null;
  }

  private getAccessPath(expr: ts.PropertyAccessExpression): string[] {
    const path: string[] = [];
    let current: ts.Expression = expr;
    while (ts.isPropertyAccessExpression(current)) {
      path.unshift(current.name.text);
      current = current.expression;
    }
    return path;
  }

  private getLineNumber(node: ts.Node): number {
    const sourceFile = node.getSourceFile();
    if (!sourceFile) return 0;
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
    return line + 1; // 1-based
  }

  private makeParamInput(paramIndex: number, paramNames: string[]): SummaryInput {
    return {
      kind: 'param',
      paramIndex,
      label: paramNames[paramIndex] ?? `param${paramIndex}`,
    };
  }

  private inferConfidence(expr: ts.Expression | ts.Node): 'definite' | 'possible' {
    // If the return is inside an if/else or ternary, it's only possible
    let current = expr.parent;
    while (current) {
      if (ts.isIfStatement(current) || ts.isConditionalExpression(current)) {
        return 'possible';
      }
      if (ts.isSwitchStatement(current)) {
        return 'possible';
      }
      // Stop at function boundary
      if (
        ts.isFunctionDeclaration(current) ||
        ts.isFunctionExpression(current) ||
        ts.isArrowFunction(current) ||
        ts.isMethodDeclaration(current)
      ) {
        break;
      }
      current = current.parent;
    }
    return 'definite';
  }

  // =========================================================================
  // Heuristic helpers (mirrored from sink-detector.ts)
  // =========================================================================

  private looksLikeFsOrPath(name: string): boolean {
    return /^(fs|fsp|fsPromises|path)$/.test(name);
  }

  private looksLikeChildProcess(name: string): boolean {
    return /^(child_process|cp|childProcess)$/.test(name);
  }

  private looksLikeResponse(name: string): boolean {
    return /^(res|response|ctx|reply)$/.test(name);
  }

  private looksLikeSchema(expr: ts.Expression): boolean {
    const text = expr.getText();
    return SCHEMA_CALLERS.has(text.split('.')[0]) || /schema/i.test(text);
  }
}

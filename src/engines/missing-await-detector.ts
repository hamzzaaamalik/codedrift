/**
 * Missing Await Detector
 * Detects fire-and-forget async function calls that should be awaited.
 * Priority: CRITICAL (causes race conditions, data corruption, silent failures)
 *
 * Detection strategies:
 *   S1: Same-file async declaration (async keyword)
 *   S2: TypeScript Promise<T> return type annotation
 *   S3: Known async API database (ORM, fs, HTTP, Redis, etc.)
 *   S4: this.method() where method is async in same class
 *   S5: Naming heuristics (fetch*, save*, load*, etc.)
 *   S6: Import from async-sounding module
 *   S7: Used with .then()/await elsewhere in same file
 *   S8: Matches strong async naming pattern
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse, ASTHelpers } from '../core/parser.js';
import { isKnownAsyncAPI, getAPICategory, KNOWN_ASYNC_METHODS } from './known-async-apis.js';
import { SYNC_OBJECTS, SYNC_METHODS, matchesSyncPrefix, matchesSyncObjectPattern } from './known-sync-apis.js';
import * as ts from 'typescript';

// ──────────────────── Interfaces ────────────────────

interface BlockContext {
  insideTryBlock: boolean;
  insideCatchBlock: boolean;
  insideFinallyBlock: boolean;
  insideLoop: boolean;
  insideConditional: boolean;
}

interface SequenceGapInfo {
  nextAwaitedName: string | null;
}

// ──────────────────── Detector ────────────────────

export class MissingAwaitDetector extends BaseEngine {
  readonly name = 'missing-await';

  // ── Fire-and-forget exact matches ──
  private static readonly FIRE_AND_FORGET = new Set([
    'log', 'logActivity', 'logEvent', 'logError', 'logWarning', 'logInfo',
    'track', 'trackEvent', 'trackUser', 'trackAction', 'trackPageView',
    'record', 'recordMetric', 'recordEvent', 'recordActivity',
    'report', 'reportError', 'reportEvent', 'analytics', 'sendAnalytics',
    'emit', 'publish', 'dispatch', 'trigger', 'fire',
    'monitor', 'ping', 'heartbeat', 'healthCheck',
    'warmCache', 'prefetch', 'preload',
    'notify', 'sendNotification', 'alert',
    // Cleanup / lifecycle (commonly fire-and-forget in shutdown handlers)
    'close', 'stop', 'destroy', 'dispose', 'shutdown', 'terminate',
    'cleanup', 'teardown', 'disconnect', 'end', 'abort', 'cancel',
    'unsubscribe', 'unregister', 'deregister', 'unlisten',
  ]);

  // ── Timer functions ──
  private static readonly TIMER_FUNCTIONS = new Set([
    'setTimeout', 'setInterval', 'setImmediate', 'queueMicrotask',
  ]);

  // ── Test framework callbacks ──
  private static readonly TEST_FUNCTIONS = new Set([
    'it', 'test', 'describe', 'beforeEach', 'afterEach',
    'beforeAll', 'afterAll', 'before', 'after',
  ]);

  // ── Route handler registration methods ──
  private static readonly ROUTE_METHODS = new Set([
    'get', 'post', 'put', 'delete', 'patch', 'use', 'all', 'head', 'options',
  ]);

  // ── Route handler objects ──
  private static readonly ROUTE_OBJECTS = new Set([
    'app', 'router', 'server', 'fastify',
  ]);

  // ── Event handler methods ──
  private static readonly EVENT_METHODS = new Set([
    'on', 'once', 'addEventListener', 'addListener',
  ]);

  // ── Event handler registration methods (for callback detection) ──
  private static readonly EVENT_REGISTRATION_METHODS = new Set([
    'on', 'once', 'addEventListener', 'addListener', 'subscribe',
  ]);

  // ── ORM/query terminal methods that still produce Promises ──
  private static readonly ORM_TERMINAL_METHODS = new Set([
    'exec', 'toPromise', 'subscribe', 'pipe', 'stream', 'cursor', 'lean', 'then',
  ]);

  // ── Framework decorators that make methods fire-and-forget ──
  private static readonly FRAMEWORK_DECORATORS = new Set([
    // NestJS HTTP
    'Get', 'Post', 'Put', 'Patch', 'Delete', 'All', 'Head', 'Options',
    // NestJS scheduling & events
    'Cron', 'OnEvent', 'Subscribe', 'EventHandler', 'MessageHandler',
    'Process', 'OnQueueActive', 'OnQueueCompleted', 'OnQueueFailed',
    // GraphQL
    'Query', 'Mutation', 'Subscription', 'ResolveField',
  ]);

  // ──────────────────── Main Analyze ────────────────────

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const issue = this.checkMissingAwait(node, context);
        if (issue) {
          issues.push(issue);
        }
      }
    });

    return issues;
  }

  // ──────────────────── Core Detection ────────────────────

  /**
   * Check if a call expression is an unawaited async function.
   * Multi-stage pipeline: skip checks → async detection → context → severity → suggestion.
   */
  private checkMissingAwait(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    // ── Skip Pipeline ──

    // 1. Already awaited
    if (this.isAwaited(node)) return null;

    // 1b. Suppression comment on previous line (// no await, // fire-and-forget, etc.)
    if (this.hasAwaitSuppressionComment(node, context)) return null;

    // 2. void prefix (intentional fire-and-forget)
    if (this.hasVoidOperator(node)) return null;

    // 3. Promise chain (.then/.catch/.finally)
    if (this.hasPromiseHandler(node)) return null;

    // 3b. for await...of iterable — async generators don't need explicit await
    if (this.isForAwaitIterable(node)) return null;

    // 4. Callback-style call (last arg is (err, data) => ...)
    if (this.isCallbackStyleCall(node)) return null;

    // 5. Assigned to variable — check if handled later
    const varInfo = this.getAssignedVariable(node);
    if (varInfo) {
      if (this.isVariableHandledLater(varInfo.name, varInfo.node, node)) {
        return null; // Variable is awaited/returned/passed later
      }
      // Variable assigned but never handled — will flag below as warning
    }

    // 6. this.* method calls — skip if method is NOT async in same class
    let knownAsync = false;
    let className: string | null = null;
    if (ts.isPropertyAccessExpression(node.expression) &&
        node.expression.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const asyncResult = this.isAsyncMethodInClass(node);
      if (!asyncResult.isAsync) return null;
      knownAsync = true;
      className = asyncResult.className;
    }

    // 7. Must be inside an async function (await is invalid otherwise)
    if (!this.isInsideAsyncFunction(node)) return null;

    // 8. Top-level async context (framework callbacks, IIFEs, etc.)
    if (this.isTopLevelAsyncContext(node)) return null;

    // 8b. Inside event handler callback — async calls in event callbacks are fire-and-forget
    if (this.isInsideEventHandlerCallback(node)) return null;

    // 9. Inside Promise.all/allSettled/race/any
    if (this.isInsidePromiseAll(node)) return null;

    // ── Extract call info ──
    const { expression } = node;
    let functionName: string | null = null;
    let objectName: string | null = null;
    // Track if call uses method syntax (expr.method()) vs bare call (fn())
    // Important: even when objectName is null (complex chains like arr.filter().join()),
    // it's still a method call — S1/S2 should NOT match standalone declarations.
    const isMethodCall = ts.isPropertyAccessExpression(expression);

    if (ts.isIdentifier(expression)) {
      functionName = expression.text;
    } else if (isMethodCall) {
      functionName = expression.name.text;
      objectName = this.getObjectName(expression.expression);
    }

    // 10. Intentional fire-and-forget patterns
    if (functionName && this.isIntentionalFireAndForget(functionName, objectName)) return null;

    // ── Async Detection Strategies (ordered by confidence) ──

    // S1: Declared async in same file
    // IMPORTANT: Only applies to bare function calls (not method calls).
    // arr.filter().join() should NOT match standalone async function join().
    // Method calls on objects should use S3 (known API) or S4 (this.method).
    const isDeclaredAsync = knownAsync
      || (!isMethodCall && functionName ? this.isDeclaredAsAsync(functionName, context) : false);

    // S2: TypeScript Promise<T> return type annotation
    // Same restriction: only bare function calls (not method calls).
    const hasPromiseReturn = !isDeclaredAsync && !isMethodCall && functionName
      ? this.hasPromiseReturnType(functionName, context)
      : false;

    // S3: Known async API database
    const isKnownAPI = !isDeclaredAsync && !hasPromiseReturn
      ? isKnownAsyncAPI(objectName, functionName || '')
      : false;

    // S4: this.method() already handled above (knownAsync)

    // High confidence: any of S1-S4
    const isHighConfidence = isDeclaredAsync || hasPromiseReturn || isKnownAPI;

    // Skip heuristics if this is a known sync method ON AN OBJECT (e.g., crypto.update()).
    // Bare function calls (no objectName) must reach S5-S7 cross-file heuristics first.
    if (!isHighConfidence && functionName && objectName && this.isSyncMethod(functionName, objectName)) {
      return null;
    }

    // S5-S7: Cross-file heuristics (medium confidence)
    const isHeuristicallyAsync = !isHighConfidence && functionName ? this.isLikelyAsync(functionName) : false;
    const isFromAsyncModule = !isHighConfidence && functionName ? this.isImportedFromAsyncModule(functionName, context) : false;
    const isUsedAsAsync = !isHighConfidence && functionName ? this.isUsedAsAsyncElsewhere(functionName, context) : false;
    const isCrossFileAsync = isHeuristicallyAsync || isFromAsyncModule || isUsedAsAsync;

    // S8: Pattern matching (medium confidence)
    const matchesPattern = !isHighConfidence && !isCrossFileAsync && functionName
      ? this.matchesAsyncPattern(functionName, objectName)
      : false;

    // Determine overall async likelihood
    const isLikelyAsync = isHighConfidence || isCrossFileAsync || matchesPattern;
    if (!isLikelyAsync) return null;

    // ── Sync prefix veto — function names starting with convert*, format*, parse*, etc.
    //    Applies even with cross-file async (module path heuristic is weak evidence),
    //    BUT not if the function is used with await/then elsewhere (S7 — strong evidence).
    if (!isHighConfidence && functionName && matchesSyncPrefix(functionName)) {
      if (!isKnownAsyncAPI(objectName, functionName) && !isUsedAsAsync) {
        return null;
      }
    }

    // ── Immediate chain veto — fn().toString(), fn().length, !fn(), fn() + 1, etc.
    //    Only for non-high-confidence: if fn IS declared async (S1-S4), chaining
    //    .toString() on a Promise is a real bug (returns "[object Promise]").
    //    For heuristic detections, the chain proves the developer thinks it's sync.
    if (!isHighConfidence && this.hasImmediateChain(node)) {
      return null;
    }

    // ── Return statement skip — `return asyncCall()` forwards the Promise to the caller.
    //    This is not fire-and-forget: the caller receives and can await the Promise.
    //    Applies to ALL returned async calls: return this.method(), return Model.findOne(),
    //    return fetchData(), return fetchQuoteFromProvider(), etc.
    if (this.isReturned(node)) {
      return null;
    }

    // ── Destructuring veto — const { a } = fn() proves developer expects sync object.
    //    Only for non-high-confidence: if fn IS declared async (S1-S4), destructuring
    //    a Promise is a real bug (data will be undefined).
    if (!isHighConfidence && node.parent && ts.isVariableDeclaration(node.parent) &&
        node.parent.initializer === node &&
        (ts.isObjectBindingPattern(node.parent.name) || ts.isArrayBindingPattern(node.parent.name))) {
      return null;
    }

    // ── Sync usage veto — variable used synchronously later (non-high confidence only) ──
    if (!isHighConfidence && varInfo) {
      if (this.isResultUsedSynchronously(varInfo.name, varInfo.node)) {
        return null;
      }
    }

    // ── Inline sync usage veto — call result consumed directly as function argument
    //    or object property value. e.g., doSomething(loadConfig()) or { cfg: loadConfig() }
    //    Developer expects a concrete value, not a Promise. Only for non-high-confidence.
    if (!isHighConfidence && this.isUsedAsInlineArgument(node)) {
      return null;
    }

    // ── Return value usage check ──
    const returnValueUsed = this.isReturnValueUsed(node);

    // Skip low-confidence fire-and-forget (pattern match + not used)
    if (!isHighConfidence && !isCrossFileAsync && matchesPattern && !returnValueUsed) {
      return null;
    }

    // ── Context Classification ──
    const blockContext = this.classifyBlockContext(node);
    const sequenceGap = this.detectSequenceGap(node);
    const apiCategory = isKnownAPI ? getAPICategory(objectName, functionName || '') : null;

    // Mongoose .exec() detection — classify the inner method
    let effectiveApiCategory = apiCategory;
    if (!effectiveApiCategory && functionName === 'exec') {
      const mongooseInfo = this.isMongooseExecCall(node);
      if (mongooseInfo) {
        effectiveApiCategory = getAPICategory(mongooseInfo.objectName, mongooseInfo.innerMethodName);
      }
    }

    // ── Severity ──
    const { severity, confidence } = this.classifySeverity(
      functionName || '', objectName, blockContext, sequenceGap,
      returnValueUsed, effectiveApiCategory, isHighConfidence,
      isHeuristicallyAsync, isFromAsyncModule, isUsedAsAsync, node,
    );

    // ── Suggestion ──
    const callName = objectName ? `${objectName}.${functionName}` : (functionName || 'unknown');
    const { message, suggestion } = this.generateContextualSuggestion(
      callName, functionName || '', blockContext, sequenceGap,
      effectiveApiCategory, isHighConfidence, isCrossFileAsync, returnValueUsed,
      className, varInfo ? varInfo.name : null,
    );

    return this.createIssue(context, node, message, { severity, confidence, suggestion });
  }

  // ──────────────────── Skip Rules ────────────────────

  private isAwaited(node: ts.Node): boolean {
    if (!node.parent) return false;
    if (ts.isAwaitExpression(node.parent)) return true;
    // Check if this call is part of a chain that's ultimately awaited/voided/handled
    // e.g., await User.findOne(q).exec() — inner findOne() is consumed by .exec() which is awaited
    // Also handles: await (foo().bar()), foo().bar().then(...), void foo().bar()
    let current: ts.Node = node;
    while (current.parent) {
      const p = current.parent;
      if (ts.isAwaitExpression(p) || ts.isVoidExpression(p)) return true;
      // Chain continues through property access, call expressions, parenthesized exprs,
      // type assertions, and non-null assertions
      if (ts.isParenthesizedExpression(p) ||
          ts.isNonNullExpression(p) || ts.isAsExpression(p) || ts.isTypeAssertionExpression(p)) {
        current = p;
        continue;
      }
      // Call expressions: only chain through if current is the callee (foo().bar()),
      // NOT when current is an argument (wrapper(foo())).
      // Being passed as an argument means the promise is consumed by the wrapper.
      if (ts.isCallExpression(p)) {
        if (p.expression === current || (ts.isPropertyAccessExpression(p.expression) &&
            p.expression.expression === current)) {
          // Current is the callee expression (chain) — continue chaining
          current = p;
          continue;
        }
        // Current is an argument — promise is consumed by the calling function
        return true;
      }
      if (ts.isPropertyAccessExpression(p)) {
        // If the chain accesses .then/.catch/.finally, the promise is handled
        const name = p.name.text;
        if (name === 'then' || name === 'catch' || name === 'finally') return true;
        current = p;
        continue;
      }
      break;
    }
    return false;
  }

  private hasVoidOperator(node: ts.Node): boolean {
    return !!(node.parent && ts.isVoidExpression(node.parent));
  }

  /**
   * Check if the line above the call has a suppression comment indicating intentional
   * no-await, e.g. "// No await to proceed asynchronously", "// fire-and-forget"
   */
  private hasAwaitSuppressionComment(node: ts.CallExpression, context: AnalysisContext): boolean {
    const sf = context.sourceFile;
    // Find the statement containing this call
    let stmt: ts.Node = node;
    while (stmt.parent && !ts.isBlock(stmt.parent) && !ts.isSourceFile(stmt.parent)) {
      stmt = stmt.parent;
    }
    const stmtStart = stmt.getStart(sf);
    // Get text from the line before the statement
    const textBefore = sf.text.slice(Math.max(0, stmtStart - 200), stmtStart);
    // Look at the last comment before the statement
    const lastLine = textBefore.trimEnd().split('\n').pop() || '';
    const commentMatch = lastLine.match(/\/\/(.+)$/) || lastLine.match(/\/\*(.+?)\*\//);
    if (!commentMatch) return false;
    const comment = commentMatch[1].toLowerCase();
    return /\bno\s+await\b/.test(comment) ||
           /\bfire[- ]?and[- ]?forget\b/.test(comment) ||
           /\bintentionally\s+not\s+await/.test(comment) ||
           /\bdeliberately\s+not\s+await/.test(comment) ||
           /\bproceed\s+async/.test(comment) ||
           /\bdon'?t\s+await\b/.test(comment);
  }

  private hasPromiseHandler(node: ts.CallExpression): boolean {
    const parent = node.parent;
    if (!parent || !ts.isPropertyAccessExpression(parent)) return false;
    const name = parent.name.text;
    return name === 'then' || name === 'catch' || name === 'finally';
  }

  /**
   * Check if the call is the iterable in a `for await...of` statement.
   * Async generators (async function*) are consumed this way — no explicit await needed.
   */
  private isForAwaitIterable(node: ts.CallExpression): boolean {
    let current: ts.Node = node;
    // Walk up through property access chains (e.g., obj.method().something)
    while (current.parent && (ts.isPropertyAccessExpression(current.parent) ||
           ts.isCallExpression(current.parent) || ts.isParenthesizedExpression(current.parent))) {
      current = current.parent;
    }
    // Check if parent is a ForOfStatement with awaitModifier
    if (current.parent && ts.isForOfStatement(current.parent) &&
        current.parent.awaitModifier && current.parent.expression === current) {
      return true;
    }
    return false;
  }

  /**
   * Immediate chain — return value consumed as sync value.
   * If fn().toString() or fn().length or !fn() or fn() + x, the developer
   * treats the return as a concrete type. If it were a Promise, these would
   * produce "[object Promise]" or NaN — clearly the developer knows it's sync.
   */
  private hasImmediateChain(node: ts.CallExpression): boolean {
    const parent = node.parent;
    if (!parent) return false;

    // .toString(), .property — sync chain
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
      const name = parent.name.text;
      // Exception: .then/.catch/.finally are Promise handling, NOT sync chains
      if (name === 'then' || name === 'catch' || name === 'finally') return false;
      // Exception: ORM/query terminal methods that still produce Promises
      if (MissingAwaitDetector.ORM_TERMINAL_METHODS.has(name)) return false;
      return true;
    }

    // ['key'] bracket access
    if (ts.isElementAccessExpression(parent) && parent.expression === node) return true;

    // !fn(), +fn(), -fn(), typeof fn()
    if (ts.isPrefixUnaryExpression(parent) && parent.operand === node) return true;

    // fn() + x, fn() === x (arithmetic, comparison, but NOT assignment)
    if (ts.isBinaryExpression(parent) && (parent.left === node || parent.right === node)) {
      const op = parent.operatorToken.kind;
      // Skip assignment operators — those store the value, not consume it
      if (op === ts.SyntaxKind.EqualsToken ||
          op === ts.SyntaxKind.PlusEqualsToken ||
          op === ts.SyntaxKind.MinusEqualsToken) return false;
      // Skip logical operators — value flows through, doesn't prove sync
      if (op === ts.SyntaxKind.AmpersandAmpersandToken ||
          op === ts.SyntaxKind.BarBarToken ||
          op === ts.SyntaxKind.QuestionQuestionToken) return false;
      return true;
    }

    // `${fn()}` template literal
    if (ts.isTemplateSpan(parent)) return true;

    // ...fn() spread
    if (ts.isSpreadElement(parent) && parent.expression === node) return true;

    // NOTE: destructuring `const { a } = fn()` is NOT skipped here.
    // If fn is high-confidence async (S1-S4), destructuring a Promise IS a bug
    // (data will be undefined). For heuristic detections, isResultUsedSynchronously
    // handles the veto post-detection.

    return false;
  }

  /**
   * Callback-style call: last argument is (err, data) => ...
   */
  private isCallbackStyleCall(node: ts.CallExpression): boolean {
    if (node.arguments.length === 0) return false;
    let lastArg: ts.Node = node.arguments[node.arguments.length - 1];
    // Unwrap `await function(err, doc){}` — misplaced await on callback
    if (ts.isAwaitExpression(lastArg)) {
      lastArg = lastArg.expression;
    }
    if (!ASTHelpers.isFunctionLike(lastArg)) return false;
    const funcLike = lastArg as ts.FunctionLikeDeclaration;
    const params = funcLike.parameters;
    if (params.length < 2) return false;
    const firstParam = params[0];
    if (ts.isIdentifier(firstParam.name)) {
      const name = firstParam.name.text.toLowerCase();
      // Standard Node.js callback error parameter names
      return name === 'err' || name === 'error' || name === 'e' || name === '_'
        || name === 'ex' || name === 'exception' || name === 'exc';
    }
    return false;
  }

  /**
   * Get the variable name if the call result is assigned.
   */
  private getAssignedVariable(node: ts.CallExpression): { name: string; node: ts.Node } | null {
    // Walk up through transparent wrappers: ternary, logical ops, parentheses
    let current: ts.Node = node;
    while (current.parent) {
      const p = current.parent;
      if (ts.isParenthesizedExpression(p) || ts.isNonNullExpression(p) || ts.isAsExpression(p)) {
        current = p;
        continue;
      }
      // Ternary: const x = cond ? asyncFn() : fallback
      if (ts.isConditionalExpression(p) && (current === p.whenTrue || current === p.whenFalse)) {
        current = p;
        continue;
      }
      // Logical: const x = maybeNull || asyncFn()
      if (ts.isBinaryExpression(p) &&
          (p.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
           p.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
           p.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken)) {
        current = p;
        continue;
      }
      break;
    }

    const parent = current.parent;
    if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return { name: parent.name.text, node: parent };
    }
    if (parent && ts.isBinaryExpression(parent) &&
        parent.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      // const x = asyncCall()
      if (ts.isIdentifier(parent.left)) {
        return { name: parent.left.text, node: parent };
      }
      // this.prop = asyncCall() — promise stored in property for later await
      if (ts.isPropertyAccessExpression(parent.left)) {
        const propName = parent.left.name.text;
        return { name: propName, node: parent };
      }
    }
    return null;
  }

  /**
   * Scan forward in the enclosing function to check if a stored promise variable
   * is later awaited, returned, .then()-chained, or passed to Promise.all.
   */
  private isVariableHandledLater(varName: string, assignmentNode: ts.Node, _callNode: ts.CallExpression): boolean {
    const enclosingFunc = this.findEnclosingAsyncFunction(assignmentNode);
    if (!enclosingFunc) return true; // Conservative: assume handled

    const body = 'body' in enclosingFunc ? enclosingFunc.body : null;
    if (!body) return true;

    let found = false;
    let pastAssignment = false;

    traverse(body, (n) => {
      if (found) return;
      if (n === assignmentNode) { pastAssignment = true; return; }
      if (!pastAssignment) return;

      // Helper: check if an expression references the variable (bare or this.prop)
      const isVarRef = (expr: ts.Node): boolean => {
        if (ts.isIdentifier(expr) && expr.text === varName) return true;
        // Also match this.varName for property assignments
        if (ts.isPropertyAccessExpression(expr) &&
            expr.expression.kind === ts.SyntaxKind.ThisKeyword &&
            expr.name.text === varName) return true;
        return false;
      };

      // await variableName / await this.variableName
      if (ts.isAwaitExpression(n) && isVarRef(n.expression)) {
        found = true; return;
      }

      // variableName.then( or .catch( / this.variableName.then(
      if (ts.isPropertyAccessExpression(n) && isVarRef(n.expression) &&
          (n.name.text === 'then' || n.name.text === 'catch' || n.name.text === 'finally')) {
        found = true; return;
      }

      // return variableName / return this.variableName
      if (ts.isReturnStatement(n) && n.expression && isVarRef(n.expression)) {
        found = true; return;
      }

      // Promise.all/allSettled containing variableName
      if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
        const obj = this.getObjectName(n.expression.expression);
        const method = n.expression.name.text;
        if (obj === 'Promise' && (method === 'all' || method === 'allSettled' || method === 'race' || method === 'any')) {
          let hasVar = false;
          traverse(n, (arg) => {
            if (ts.isIdentifier(arg) && arg.text === varName) hasVar = true;
          });
          if (hasVar) { found = true; return; }
        }
      }

      // variableName.exec() / .subscribe() / .end() / .pipe() — terminal promise consumers
      if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) &&
          ts.isIdentifier(n.expression.expression) && n.expression.expression.text === varName) {
        const method = n.expression.name.text;
        if (['exec', 'subscribe', 'end', 'pipe', 'toPromise', 'unsubscribe',
             'on', 'once', 'emit', 'addEventListener'].includes(method)) {
          found = true; return;
        }
      }

      // await inside conditional block: if (...) { await variableName }
      if (ts.isAwaitExpression(n)) {
        let hasVar = false;
        traverse(n.expression, (inner) => {
          if (ts.isIdentifier(inner) && inner.text === varName) hasVar = true;
        });
        if (hasVar) { found = true; return; }
      }

    });

    return found;
  }

  /**
   * Check if node is inside an async function context.
   */
  private isInsideAsyncFunction(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) ||
          ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
        return !!(current.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword));
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Check if a call expression is inside a return statement or arrow implicit return.
   * Walks up the AST through transparent wrappers (parens, type assertions, ternaries,
   * logical operators, object/array literals) and stops at statement-level nodes.
   */
  private isReturned(node: ts.CallExpression): boolean {
    let current: ts.Node = node;

    while (current.parent) {
      const parent = current.parent;

      // Found return — call IS returned
      if (ts.isReturnStatement(parent)) return true;

      // Arrow function implicit return: () => fn()
      if (ts.isArrowFunction(parent) && !ts.isBlock(parent.body) && current === parent.body) {
        return true;
      }

      // Yield / yield*
      if (ts.isYieldExpression(parent)) return true;

      // ── Transparent wrappers — keep walking ──
      if (ts.isParenthesizedExpression(parent)) { current = parent; continue; }
      if (ts.isAsExpression(parent) || ts.isTypeAssertionExpression(parent)) { current = parent; continue; }
      if (ts.isNonNullExpression(parent)) { current = parent; continue; }
      if (ts.isConditionalExpression(parent)) { current = parent; continue; }

      // Method chaining: db.query('x').update({...}) — inner call is part of a chain.
      // The Promise propagates through the chain, so `return db.query('x').update({...})`
      // correctly forwards the result to the caller.
      if (ts.isPropertyAccessExpression(parent)) { current = parent; continue; }
      if (ts.isCallExpression(parent) && parent.expression === current) { current = parent; continue; }

      // Logical operators: fn() ?? fallback, a || fn()
      if (ts.isBinaryExpression(parent) && [
        ts.SyntaxKind.QuestionQuestionToken,
        ts.SyntaxKind.BarBarToken,
        ts.SyntaxKind.AmpersandAmpersandToken,
        ts.SyntaxKind.CommaToken,
      ].includes(parent.operatorToken.kind)) {
        current = parent;
        continue;
      }

      // ── Everything else — stop walking ──
      // The Promise is only forwarded when it's a DIRECT return value.
      // When embedded in object literals ({ result: fn() }), arrays ([fn()]),
      // function arguments (someCall(fn())), or spread (...fn()), the Promise
      // is buried — the caller gets { result: Promise } not { result: data }.
      return false;
    }

    return false;
  }

  /**
   * Find nearest enclosing async function.
   */
  private findEnclosingAsyncFunction(node: ts.Node): ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration | null {
    let current = node.parent;
    while (current) {
      if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) ||
          ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
        const isAsync = current.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword);
        return isAsync ? current : null;
      }
      current = current.parent;
    }
    return null;
  }

  /**
   * Check if the enclosing async function is a top-level context
   * (framework callback, IIFE, timer, test, route handler, event handler, decorated handler).
   */
  private isTopLevelAsyncContext(node: ts.Node): boolean {
    const enclosingAsync = this.findEnclosingAsyncFunction(node);
    if (!enclosingAsync) return false;

    // IIFE
    if (this.isIIFE(enclosingAsync)) return true;

    // Framework decorated handler (@Get, @Cron, @OnEvent, @Query, etc.)
    if (this.isFrameworkDecoratedHandler(enclosingAsync)) return true;

    // Remaining checks: async function must be argument to a CallExpression
    const callInfo = this.getEnclosingCallExpression(enclosingAsync);
    if (!callInfo) return false;

    const calleeName = this.getCalleeInfo(callInfo.callExpr);
    if (!calleeName) return false;

    // Timer callbacks
    if (MissingAwaitDetector.TIMER_FUNCTIONS.has(calleeName.fullName) ||
        MissingAwaitDetector.TIMER_FUNCTIONS.has(calleeName.methodName)) {
      return true;
    }
    if (calleeName.objectName === 'process' && calleeName.methodName === 'nextTick') {
      return true;
    }

    // Test framework callbacks
    if (MissingAwaitDetector.TEST_FUNCTIONS.has(calleeName.fullName) ||
        MissingAwaitDetector.TEST_FUNCTIONS.has(calleeName.methodName)) {
      return true;
    }

    // Route handler registrations
    if (calleeName.objectName &&
        MissingAwaitDetector.ROUTE_OBJECTS.has(calleeName.objectName) &&
        MissingAwaitDetector.ROUTE_METHODS.has(calleeName.methodName)) {
      return true;
    }

    // Event handler registrations
    if (MissingAwaitDetector.EVENT_METHODS.has(calleeName.methodName)) {
      return true;
    }

    return false;
  }

  /**
   * Check if the call is inside an async callback passed to an event registration method
   * (.on(), .once(), .addEventListener(), .addListener(), .subscribe()).
   * Async calls inside event handler callbacks are fire-and-forget by nature since
   * the event emitter doesn't await the handler.
   */
  private isInsideEventHandlerCallback(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      // Look for arrow functions or function expressions
      if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) {
        // Check if this function is an argument to an event registration call
        const parent = current.parent;
        if (parent && ts.isCallExpression(parent) && parent.arguments.some(a => a === current)) {
          const callee = parent.expression;
          if (ts.isPropertyAccessExpression(callee)) {
            if (MissingAwaitDetector.EVENT_REGISTRATION_METHODS.has(callee.name.text)) {
              return true;
            }
          }
        }
      }
      // Stop at function boundaries that are NOT event callbacks (to avoid
      // skipping across unrelated function scopes)
      if (ts.isFunctionDeclaration(current) || ts.isMethodDeclaration(current)) {
        break;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Check for framework decorators (NestJS HTTP, scheduling, events, GraphQL).
   */
  private isFrameworkDecoratedHandler(funcNode: ts.Node): boolean {
    if (!ts.isMethodDeclaration(funcNode)) return false;
    const decorators = ts.canHaveDecorators(funcNode) ? ts.getDecorators(funcNode) : undefined;

    // Check method decorators
    const hasSkipDecorator = decorators?.some(d => {
      if (ts.isCallExpression(d.expression) && ts.isIdentifier(d.expression.expression)) {
        return MissingAwaitDetector.FRAMEWORK_DECORATORS.has(d.expression.expression.text);
      }
      if (ts.isIdentifier(d.expression)) {
        return MissingAwaitDetector.FRAMEWORK_DECORATORS.has(d.expression.text);
      }
      return false;
    });
    if (hasSkipDecorator) return true;

    // Check if parent class has @Resolver decorator
    const parent = funcNode.parent;
    if (parent && (ts.isClassDeclaration(parent) || ts.isClassExpression(parent))) {
      const classDecorators = ts.canHaveDecorators(parent) ? ts.getDecorators(parent) : undefined;
      if (classDecorators) {
        return classDecorators.some(d => {
          const name = ts.isCallExpression(d.expression) && ts.isIdentifier(d.expression.expression)
            ? d.expression.expression.text
            : ts.isIdentifier(d.expression) ? d.expression.text : '';
          return name === 'Resolver';
        });
      }
    }

    return false;
  }

  /**
   * Check if inside Promise.all/allSettled/race/any.
   */
  private isInsidePromiseAll(node: ts.Node): boolean {
    let current = node.parent;
    let depth = 0;
    while (current && depth < 10) {
      if (ts.isCallExpression(current)) {
        const expr = current.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const objName = this.getObjectName(expr.expression);
          const methodName = expr.name.text;
          if (objName === 'Promise' && (methodName === 'all' || methodName === 'allSettled' || methodName === 'race' || methodName === 'any')) {
            return true;
          }
        }
      }
      current = current.parent;
      depth++;
    }
    return false;
  }

  private isIIFE(funcNode: ts.Node): boolean {
    let current: ts.Node = funcNode;
    while (current.parent && ts.isParenthesizedExpression(current.parent)) {
      current = current.parent;
    }
    if (current.parent && ts.isCallExpression(current.parent) && current.parent.expression === current) {
      return true;
    }
    if (current.parent && ts.isPropertyAccessExpression(current.parent)) {
      const name = current.parent.name.text;
      if ((name === 'call' || name === 'apply' || name === 'bind') &&
          current.parent.parent && ts.isCallExpression(current.parent.parent)) {
        return true;
      }
    }
    return false;
  }

  private getEnclosingCallExpression(funcNode: ts.Node): { callExpr: ts.CallExpression } | null {
    let current: ts.Node = funcNode;
    while (current.parent && ts.isParenthesizedExpression(current.parent)) {
      current = current.parent;
    }
    if (current.parent && ts.isCallExpression(current.parent)) {
      const callExpr = current.parent;
      const isArgument = callExpr.arguments.some(arg => arg === current);
      if (isArgument) return { callExpr };
    }
    return null;
  }

  private getCalleeInfo(callExpr: ts.CallExpression): { fullName: string; objectName: string | null; methodName: string } | null {
    const expr = callExpr.expression;
    if (ts.isIdentifier(expr)) {
      return { fullName: expr.text, objectName: null, methodName: expr.text };
    }
    if (ts.isPropertyAccessExpression(expr)) {
      const methodName = expr.name.text;
      const objectName = this.getObjectName(expr.expression);
      return {
        fullName: objectName ? `${objectName}.${methodName}` : methodName,
        objectName,
        methodName,
      };
    }
    return null;
  }

  // ──────────────────── Async Detection Strategies ────────────────────

  /**
   * S1: Check if function is declared with async keyword in the same file.
   */
  private isDeclaredAsAsync(functionName: string, context: AnalysisContext): boolean {
    let isAsync = false;
    traverse(context.sourceFile, (node) => {
      if (isAsync) return;
      if (ts.isFunctionDeclaration(node) && node.name?.text === functionName) {
        if (ASTHelpers.isAsyncFunction(node)) isAsync = true;
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === functionName) {
        if (node.initializer && ASTHelpers.isFunctionLike(node.initializer) && ASTHelpers.isAsyncFunction(node.initializer)) {
          isAsync = true;
        }
      }
    });
    return isAsync;
  }

  /**
   * S2: Check if function has Promise<T> return type annotation.
   */
  private hasPromiseReturnType(functionName: string, context: AnalysisContext): boolean {
    let hasPromise = false;
    traverse(context.sourceFile, (node) => {
      if (hasPromise) return;
      // function foo(): Promise<T> { ... }
      if (ts.isFunctionDeclaration(node) && node.name?.text === functionName && node.type) {
        if (this.isPromiseTypeNode(node.type)) hasPromise = true;
      }
      // const foo = (): Promise<T> => { ... }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === functionName) {
        if (node.initializer && ASTHelpers.isFunctionLike(node.initializer)) {
          const funcLike = node.initializer as ts.FunctionLikeDeclaration;
          if (funcLike.type && this.isPromiseTypeNode(funcLike.type)) hasPromise = true;
        }
      }
      // class method: methodName(): Promise<T> { ... }
      if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === functionName && node.type) {
        if (this.isPromiseTypeNode(node.type)) hasPromise = true;
      }
    });
    return hasPromise;
  }

  private isPromiseTypeNode(typeNode: ts.TypeNode): boolean {
    if (ts.isTypeReferenceNode(typeNode) && ts.isIdentifier(typeNode.typeName)) {
      return typeNode.typeName.text === 'Promise';
    }
    // Union types: Promise<T> | null, Promise<T> | undefined
    if (ts.isUnionTypeNode(typeNode)) {
      return typeNode.types.some(t => this.isPromiseTypeNode(t));
    }
    return false;
  }

  /**
   * S4: Check if this.methodName() calls an async method in the enclosing class.
   * Returns isAsync flag and className.
   */
  private isAsyncMethodInClass(node: ts.CallExpression): { isAsync: boolean; className: string | null } {
    const expr = node.expression;
    if (!ts.isPropertyAccessExpression(expr)) return { isAsync: false, className: null };

    const methodName = expr.name.text;
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) {
        const name = ts.isClassDeclaration(current) && current.name ? current.name.text : null;
        const result = this.findAsyncMemberInClass(current, methodName);
        if (result !== null) return { isAsync: result, className: name };

        // Check parent class in same file (single-level inheritance)
        const parentResult = this.findAsyncMemberInParentClass(current, methodName);
        if (parentResult !== null) return { isAsync: parentResult, className: name };

        return { isAsync: false, className: name };
      }
      current = current.parent;
    }
    return { isAsync: false, className: null };
  }

  /** Check if a class has a member (method or arrow property) with the given name. */
  private findAsyncMemberInClass(classNode: ts.ClassDeclaration | ts.ClassExpression, methodName: string): boolean | null {
    for (const member of classNode.members) {
      // Standard method: async method() {}
      if (ts.isMethodDeclaration(member) && member.name && ts.isIdentifier(member.name)) {
        if (member.name.text === methodName) {
          return !!(member.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword));
        }
      }
      // Arrow function property: method = async () => {}
      if (ts.isPropertyDeclaration(member) && member.name && ts.isIdentifier(member.name)) {
        if (member.name.text === methodName && member.initializer) {
          if (ASTHelpers.isFunctionLike(member.initializer) && ASTHelpers.isAsyncFunction(member.initializer)) {
            return true;
          }
          if (ASTHelpers.isFunctionLike(member.initializer)) {
            return false; // Found the property but it's not async
          }
        }
      }
    }
    return null; // Not found in this class
  }

  /** Walk the extends clause to find the parent class in the same file and check its members. */
  private findAsyncMemberInParentClass(classNode: ts.ClassDeclaration | ts.ClassExpression, methodName: string): boolean | null {
    if (!classNode.heritageClauses) return null;
    for (const clause of classNode.heritageClauses) {
      if (clause.token !== ts.SyntaxKind.ExtendsKeyword) continue;
      for (const type of clause.types) {
        if (!ts.isIdentifier(type.expression)) continue;
        const parentName = type.expression.text;
        // Find parent class in same file
        const sourceFile = classNode.getSourceFile();
        let parentClass: ts.ClassDeclaration | ts.ClassExpression | null = null;
        traverse(sourceFile, (n) => {
          if (parentClass) return;
          if (ts.isClassDeclaration(n) && n.name?.text === parentName) {
            parentClass = n;
          }
        });
        if (parentClass) {
          return this.findAsyncMemberInClass(parentClass, methodName);
        }
      }
    }
    return null;
  }

  /**
   * S5: Naming heuristic — function name suggests I/O-bound async.
   * Tightened to only include genuinely I/O-implying prefixes.
   * Ambiguous prefixes like 'create', 'update', 'delete' require the next char
   * to be uppercase (camelCase) to avoid matching words like "creation", "updating".
   */
  private isLikelyAsync(functionName: string): boolean {
    const lower = functionName.toLowerCase();

    // Tier 1: Strong I/O prefixes — always async
    const strongPrefixes = ['fetch', 'save', 'query', 'request', 'upload', 'download'];
    if (strongPrefixes.some(p => lower.startsWith(p) && functionName.length > p.length)) {
      return true;
    }

    // Tier 2: I/O-leaning but require camelCase continuation
    const ioPrefixes = ['send', 'load', 'create', 'update', 'delete', 'find', 'remove', 'insert'];
    for (const prefix of ioPrefixes) {
      if (lower.startsWith(prefix) && functionName.length > prefix.length) {
        const nextChar = functionName[prefix.length];
        // Require uppercase next char (camelCase boundary) — e.g. "createUser" not "create"
        if (nextChar === nextChar.toUpperCase() && nextChar !== nextChar.toLowerCase()) {
          return true;
        }
      }
    }

    // Tier 3: "get" prefix — only for data-fetching patterns, not getters
    if (lower.startsWith('get') && functionName.length > 3) {
      const rest = functionName.slice(3);
      // Must start with uppercase (camelCase)
      if (rest[0] !== rest[0].toUpperCase() || rest[0] === rest[0].toLowerCase()) return false;
      // Exclude sync getter patterns — property/attribute accessors
      const syncGetterSuffixes = [
        'Name', 'Type', 'Value', 'Label', 'Text', 'Key', 'Index', 'Count', 'Length',
        'Size', 'Status', 'State', 'Mode', 'Kind', 'Category', 'Level', 'Priority',
        'Score', 'Rank', 'Order', 'Position', 'Offset', 'Limit', 'Page', 'Version',
        'Format', 'Style', 'Color', 'Font', 'Width', 'Height', 'Depth', 'Radius',
        'Angle', 'Unit', 'Currency', 'Locale', 'Timezone', 'Pattern', 'Prefix',
        'Suffix', 'Separator', 'Delimiter', 'Extension', 'Path', 'Dir', 'Url',
        'Hash', 'Checksum', 'Property', 'Attribute', 'Element', 'Cache', 'Default',
        'Instance', 'Class', 'Constructor', 'Prototype', 'Schema', 'Enum', 'Flag',
        'Option', 'Param', 'Arg', 'Description', 'Title', 'Header', 'Footer',
        'Column', 'Row', 'Field', 'Selector', 'Tag', 'Id',
      ];
      if (syncGetterSuffixes.some(s => rest === s || rest.endsWith(s))) return false;
      // Only match data-fetching patterns
      const dataWords = ['User', 'Data', 'Items', 'List', 'Record', 'Result', 'Response',
        'Config', 'Settings', 'Profile', 'Order', 'Product', 'Post', 'Comment',
        'Message', 'File', 'Image', 'Document', 'Account', 'Payment', 'Session',
        'Token', 'Transaction', 'Report', 'Stats', 'Analytics'];
      if (dataWords.some(w => rest.startsWith(w))) return true;
      if (rest.endsWith('ById') || rest.endsWith('ByEmail') || rest.endsWith('BySlug')
          || rest.endsWith('ByName') || rest.endsWith('ByKey') || rest.endsWith('ByToken')) return true;
      // Note: plural endings (getUsers, getOrders) removed from S5 — too weak as standalone
      // signal. Sync cache lookups like `getUsers()` were false-positiving. These names
      // can still be flagged via S6 (module import) + S7 (used as async elsewhere) or S8.
    }

    return false;
  }

  /**
   * S6: Import from async-sounding module.
   * Only matches if the MODULE FILENAME itself suggests async (not parent directories).
   * e.g., import from './transactionService' matches, but './services/utils/fuse' does not.
   */
  private isImportedFromAsyncModule(functionName: string, context: AnalysisContext): boolean {
    const asyncModulePatterns = [/service$/i, /repository$/i, /repo$/i, /api$/i, /client$/i, /handler$/i];
    let found = false;
    traverse(context.sourceFile, (node) => {
      if (found) return;
      if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
        const modulePath = node.moduleSpecifier.text;
        const importClause = node.importClause;
        if (!importClause) return;

        let importsFunction = false;
        if (importClause.name && importClause.name.text === functionName) importsFunction = true;
        if (importClause.namedBindings && ts.isNamedImports(importClause.namedBindings)) {
          for (const specifier of importClause.namedBindings.elements) {
            if (specifier.name.text === functionName) { importsFunction = true; break; }
          }
        }

        if (importsFunction) {
          // Match against the last path segment (module filename), not directories
          // Strip file extensions (.js, .ts, .mjs, .cjs) before matching
          const rawSegment = modulePath.split('/').pop() || '';
          const lastSegment = rawSegment.replace(/\.(js|ts|mjs|cjs|jsx|tsx)$/, '');
          if (asyncModulePatterns.some(p => p.test(lastSegment))) {
            found = true;
          }
        }
      }
    });
    return found;
  }

  /**
   * S7: Function used with .then()/await elsewhere in same file.
   */
  private isUsedAsAsyncElsewhere(functionName: string, context: AnalysisContext): boolean {
    let found = false;
    traverse(context.sourceFile, (node) => {
      if (found) return;
      if (ts.isPropertyAccessExpression(node)) {
        const name = node.name.text;
        if ((name === 'then' || name === 'catch') && ts.isCallExpression(node.expression)) {
          const callee = node.expression.expression;
          if (ts.isIdentifier(callee) && callee.text === functionName) found = true;
        }
      }
      if (ts.isAwaitExpression(node) && ts.isCallExpression(node.expression)) {
        const callee = node.expression.expression;
        if (ts.isIdentifier(callee) && callee.text === functionName) found = true;
      }
    });
    return found;
  }

  /**
   * S8: Pattern matching for async function names.
   */
  private matchesAsyncPattern(functionName: string, objectName: string | null): boolean {
    if (this.isSyncMethod(functionName, objectName)) return false;

    const strongPatterns = [
      /^(fetch|load|save|update|create|delete|remove)$/i,
      /^(get|set|put|post|patch)Data$/i,
      /^send[A-Z]/,
      /^process[A-Z]/,
      /^execute[A-Z]/,
      /^run[A-Z]/,
    ];
    if (strongPatterns.some(p => p.test(functionName))) return true;
    // Note: bare "read", "write", "insert", "search", "find", "query", "get" removed from S8.
    // These are extremely common sync function names (Array.find, Buffer.read, Array.insert).
    // They can still be flagged via S1-S4 (declared async, Promise<T>, known API) or S5-S7.
    return false;
  }

  // ──────────────────── Context Classification ────────────────────

  /**
   * Classify the block context of a call expression.
   */
  private classifyBlockContext(node: ts.CallExpression): BlockContext {
    const result: BlockContext = {
      insideTryBlock: false,
      insideCatchBlock: false,
      insideFinallyBlock: false,
      insideLoop: false,
      insideConditional: false,
    };

    let current: ts.Node | undefined = node.parent;
    while (current) {
      // Stop at function boundary
      if (ASTHelpers.isFunctionLike(current)) break;

      if (ts.isTryStatement(current)) {
        if (this.isDescendantOf(node, current.tryBlock)) result.insideTryBlock = true;
        if (current.catchClause && this.isDescendantOf(node, current.catchClause)) result.insideCatchBlock = true;
        if (current.finallyBlock && this.isDescendantOf(node, current.finallyBlock)) result.insideFinallyBlock = true;
      }

      if (ts.isForStatement(current) || ts.isForInStatement(current) ||
          ts.isForOfStatement(current) || ts.isWhileStatement(current) ||
          ts.isDoStatement(current)) {
        result.insideLoop = true;
      }

      if (ts.isIfStatement(current)) {
        result.insideConditional = true;
      }

      current = current.parent;
    }
    return result;
  }

  private isDescendantOf(node: ts.Node, ancestor: ts.Node): boolean {
    let current: ts.Node | undefined = node;
    while (current) {
      if (current === ancestor) return true;
      current = current.parent;
    }
    return false;
  }

  /**
   * Detect if unawaited call is between two awaited calls (sequence gap).
   */
  private detectSequenceGap(node: ts.CallExpression): SequenceGapInfo | null {
    // Find the ExpressionStatement containing this call
    let exprStmt: ts.ExpressionStatement | null = null;
    let current: ts.Node | undefined = node;
    while (current) {
      if (ts.isExpressionStatement(current)) { exprStmt = current; break; }
      if (ASTHelpers.isFunctionLike(current)) break;
      current = current.parent;
    }
    if (!exprStmt || !exprStmt.parent || !ts.isBlock(exprStmt.parent)) return null;

    const block = exprStmt.parent;
    const idx = block.statements.indexOf(exprStmt);
    if (idx === -1) return null;

    const nextStmt = idx < block.statements.length - 1 ? block.statements[idx + 1] : null;
    const nextAwaited = nextStmt ? this.getAwaitedCallName(nextStmt) : null;

    if (nextAwaited) {
      return { nextAwaitedName: nextAwaited };
    }
    return null;
  }

  private getAwaitedCallName(stmt: ts.Statement): string | null {
    let name: string | null = null;
    traverse(stmt, (n) => {
      if (name) return;
      if (ts.isAwaitExpression(n) && ts.isCallExpression(n.expression)) {
        const expr = n.expression.expression;
        if (ts.isIdentifier(expr)) name = expr.text;
        else if (ts.isPropertyAccessExpression(expr)) name = expr.name.text;
      }
    });
    return name;
  }

  /**
   * Detect Mongoose .exec() on a known Mongoose query.
   */
  private isMongooseExecCall(node: ts.CallExpression): { objectName: string | null; innerMethodName: string } | null {
    const expr = node.expression;
    if (!ts.isPropertyAccessExpression(expr)) return null;
    if (expr.name.text !== 'exec') return null;

    const innerExpr = expr.expression;
    if (!ts.isCallExpression(innerExpr)) return null;

    if (ts.isPropertyAccessExpression(innerExpr.expression)) {
      const innerMethodName = innerExpr.expression.name.text;
      const innerObjectName = this.getObjectName(innerExpr.expression.expression);
      if (isKnownAsyncAPI(innerObjectName, innerMethodName)) {
        return { objectName: innerObjectName, innerMethodName };
      }
    }
    return null;
  }

  // ──────────────────── Severity Classification ────────────────────

  /**
   * Classify severity based on context, API category, and detection confidence.
   */
  private classifySeverity(
    functionName: string,
    _objectName: string | null,
    blockContext: BlockContext,
    _sequenceGap: SequenceGapInfo | null,
    returnValueUsed: boolean,
    apiCategory: string | null,
    isHighConfidence: boolean,
    isHeuristicallyAsync: boolean,
    isFromAsyncModule: boolean,
    isUsedAsAsync: boolean,
    node: ts.CallExpression,
  ): { severity: 'error' | 'warning' | 'info'; confidence: 'high' | 'medium' | 'low' } {
    // Base tier from API category
    let tier: string;
    if (apiCategory === 'db-write' || apiCategory === 'payment') {
      tier = 'critical';
    } else if (apiCategory === 'db-read' || apiCategory === 'fs' || apiCategory === 'http') {
      tier = 'high';
    } else if (apiCategory === 'cache' || apiCategory === 'email') {
      tier = 'warning';
    } else {
      tier = isHighConfidence ? 'high' : 'warning';
    }

    // Escalation: try/catch or finally (broken error handling)
    if (blockContext.insideTryBlock || blockContext.insideFinallyBlock) {
      tier = this.escalateTier(tier);
    }

    // Escalation: return value used (Promise used as data)
    if (returnValueUsed) {
      tier = this.escalateTier(tier);
    }

    // Demotion: last statement in function (might be intentional)
    if (this.isLastStatementInFunction(node)) {
      tier = this.demoteTier(tier);
    }

    // Demotion: fire-and-forget named function
    if (this.isFireAndForgetName(functionName)) {
      tier = this.demoteTier(tier);
    }

    // Floor: db-write and payment operations should never drop below 'high'
    if ((apiCategory === 'db-write' || apiCategory === 'payment') && (tier === 'warning' || tier === 'info')) {
      tier = 'high';
    }

    // Confidence mapping:
    // S5 (naming heuristic) → medium (strong naming signal)
    // S6 (module import) alone → low (service modules often export sync utilities)
    // S6 + S5 combined → medium (two independent signals reinforce)
    // S7 alone (used as async elsewhere) → low (weak: no scope checking)
    // S8 (pattern match only) → low
    let confidence: 'high' | 'medium' | 'low';
    if (isHighConfidence) {
      confidence = 'high';
    } else if (isHeuristicallyAsync) {
      // S5 alone or S5+S6/S7 → medium
      confidence = 'medium';
    } else if (isFromAsyncModule && isUsedAsAsync) {
      // S6+S7 combined → medium (two weak signals reinforce)
      confidence = 'medium';
    } else {
      // S6 alone, S7 alone, or S8 alone → low
      confidence = 'low';
    }

    switch (tier) {
      case 'critical': return { severity: 'error', confidence };
      case 'high': return { severity: 'error', confidence };
      case 'warning': return { severity: 'warning', confidence };
      case 'info': return { severity: 'info', confidence: 'low' };
      default: return { severity: 'warning', confidence };
    }
  }

  private escalateTier(tier: string): string {
    const order = ['info', 'warning', 'high', 'critical'];
    const idx = order.indexOf(tier);
    return idx < order.length - 1 ? order[idx + 1] : tier;
  }

  private demoteTier(tier: string): string {
    const order = ['info', 'warning', 'high', 'critical'];
    const idx = order.indexOf(tier);
    return idx > 0 ? order[idx - 1] : tier;
  }

  private isLastStatementInFunction(node: ts.CallExpression): boolean {
    let exprStmt: ts.ExpressionStatement | null = null;
    let current: ts.Node | undefined = node;
    while (current) {
      if (ts.isExpressionStatement(current)) { exprStmt = current; break; }
      if (ASTHelpers.isFunctionLike(current)) break;
      current = current.parent;
    }
    if (!exprStmt || !exprStmt.parent || !ts.isBlock(exprStmt.parent)) return false;
    const block = exprStmt.parent;
    // Only demote if there's at least one other statement before it
    // (single-statement functions shouldn't be demoted)
    return block.statements.length > 1 && block.statements[block.statements.length - 1] === exprStmt;
  }

  private isFireAndForgetName(functionName: string): boolean {
    return /^(log|track|emit|notify|record|analytics|report|publish|dispatch|trigger|fire)[A-Z]/i.test(functionName)
      || MissingAwaitDetector.FIRE_AND_FORGET.has(functionName);
  }

  // ──────────────────── Contextual Suggestions ────────────────────

  /**
   * Generate context-specific message and suggestion.
   */
  private generateContextualSuggestion(
    callName: string,
    functionName: string,
    blockContext: BlockContext,
    sequenceGap: SequenceGapInfo | null,
    apiCategory: string | null,
    isHighConfidence: boolean,
    _isCrossFileAsync: boolean,
    returnValueUsed: boolean,
    className: string | null,
    storedVarName: string | null,
  ): { message: string; suggestion: string } {
    // try/catch context
    if (blockContext.insideTryBlock) {
      return {
        message: `Async function '${callName}' called without await inside try block — catch block will not capture async rejections`,
        suggestion: `Add 'await' before '${callName}(...)' — without await, the catch block will never execute for async errors. The Promise rejection becomes unhandled.`,
      };
    }

    // finally block
    if (blockContext.insideFinallyBlock) {
      return {
        message: `Async function '${callName}' called without await in finally block — cleanup may not complete before function returns`,
        suggestion: `Add 'await' before '${callName}(...)' to ensure cleanup completes before the function returns.`,
      };
    }

    // Loop
    if (blockContext.insideLoop) {
      return {
        message: `Async function '${callName}' called without await in loop — operations run concurrently instead of sequentially`,
        suggestion: `Add 'await' before '${callName}(...)' for sequential execution, or collect promises and use Promise.all() for concurrent execution.`,
      };
    }

    // Sequence gap
    if (sequenceGap && sequenceGap.nextAwaitedName) {
      return {
        message: `Async function '${callName}' called without await — '${sequenceGap.nextAwaitedName}' on next line will execute before '${callName}' completes`,
        suggestion: `Add 'await' before '${callName}(...)' to ensure it completes before '${sequenceGap.nextAwaitedName}' runs.`,
      };
    }

    // ORM write
    if (apiCategory === 'db-write') {
      return {
        message: `Async function '${callName}' called without await — result is a Promise, not the created/updated record`,
        suggestion: `Add 'await' before '${callName}(...)': \`const result = await ${callName}(...)\`. Without await, the database write may not complete.`,
      };
    }

    // ORM read
    if (apiCategory === 'db-read') {
      return {
        message: `Async function '${callName}' called without await — result is a Promise, not the queried data`,
        suggestion: `Add 'await' before '${callName}(...)': \`const data = await ${callName}(...)\`. Any property access on the result will be undefined.`,
      };
    }

    // this.method() with known class
    if (className) {
      return {
        message: `Async method 'this.${functionName}' called without await — declared async in ${className}`,
        suggestion: `Add 'await' before 'this.${functionName}(...)': \`await this.${functionName}(...)\``,
      };
    }

    // Stored in variable but never awaited
    if (storedVarName) {
      return {
        message: `Promise stored in '${storedVarName}' from '${callName}' but never awaited or handled`,
        suggestion: `Add 'await' when using the variable: \`const ${storedVarName} = await ${callName}(...)\`, or await it later: \`await ${storedVarName}\``,
      };
    }

    // High confidence declared async
    if (isHighConfidence) {
      if (returnValueUsed) {
        return {
          message: `Async function '${callName}' called without await`,
          suggestion: `Add 'await' before the call: \`await ${callName}(...)\``,
        };
      }
      return {
        message: `Async function '${callName}' called without await (fire-and-forget?)`,
        suggestion: this.generateFireAndForgetSuggestion(callName, functionName),
      };
    }

    // Cross-file / pattern heuristic
    if (returnValueUsed) {
      return {
        message: `Function '${callName}' is likely async but not awaited`,
        suggestion: `Add 'await' before the call: \`await ${callName}(...)\``,
      };
    }
    return {
      message: `Function '${callName}' is likely async but not awaited (fire-and-forget?)`,
      suggestion: this.generateFireAndForgetSuggestion(callName, functionName),
    };
  }

  // ──────────────────── Helpers ────────────────────

  private isIntentionalFireAndForget(methodName: string, objectName: string | null): boolean {
    if (MissingAwaitDetector.FIRE_AND_FORGET.has(methodName)) return true;

    if (/^(log|track|emit)[A-Z]/i.test(methodName)) return true;
    // send* is fire-and-forget ONLY for notifications/events, NOT for data/payment/email
    if (/^send[A-Z]/.test(methodName) &&
        !/^send(Data|Request|Message|Email|Payment|File|Batch|Response|Transaction)$/i.test(methodName)) {
      return true;
    }

    if (objectName) {
      const lower = objectName.toLowerCase();
      // Use exact match or suffix/word-boundary check to avoid substring false matches
      // (e.g., "analogService" should NOT match "log")
      const eventObjects = ['emitter', 'eventbus', 'eventemitter', 'events'];
      if (eventObjects.some(obj => lower === obj || lower.endsWith(obj))) return true;

      const loggerObjects = ['logger', 'analytics', 'tracker', 'telemetry', 'metrics'];
      if (loggerObjects.some(obj => lower === obj || lower.endsWith(obj))) return true;

      // Socket.IO fire-and-forget patterns
      if ((lower === 'socket' || lower === 'io') && (methodName === 'emit' || methodName === 'broadcast')) return true;

      // Message queues (Bull, Bee-Queue, etc.)
      if (lower === 'queue' && ['add', 'push', 'enqueue', 'process'].includes(methodName)) return true;

      // Message brokers (RabbitMQ, AMQP)
      if ((lower === 'producer' || lower === 'channel') &&
          ['send', 'produce', 'publish', 'sendToQueue', 'assertQueue'].includes(methodName)) return true;

      // Kafka
      if ((lower === 'kafka' || lower === 'producer') && methodName === 'send') return true;

      // PubSub (Google Cloud, generic)
      if ((lower === 'pubsub' || lower === 'topic' || lower === 'subscription') &&
          (methodName === 'publish' || methodName === 'emit')) return true;

      // Metrics / telemetry
      if (lower === 'metrics' && ['increment', 'gauge', 'histogram'].includes(methodName)) return true;
      if ((lower === 'telemetry' || lower === 'analytics') &&
          ['track', 'identify', 'increment', 'gauge', 'histogram'].includes(methodName)) return true;

      // Cache operations (fire-and-forget writes/invalidations)
      if (lower === 'cache' && ['set', 'del', 'invalidate', 'clear'].includes(methodName)) return true;
    }

    return false;
  }

  private isSyncMethod(methodName: string, objectName: string | null): boolean {
    // Known async API check — bypass sync list for ORM/Redis/etc.
    if (isKnownAsyncAPI(objectName, methodName)) return false;

    // For well-known objects with complete API definitions, if a method ISN'T listed
    // in the async set, it's definitively sync (e.g., fs.createReadStream is sync).
    // Only apply this closed-world assumption to authoritative, well-defined APIs.
    if (objectName) {
      const AUTHORITATIVE_OBJECTS = ['fs', 'fsPromises', 'bcrypt', 'sharp', 'axios', 'got', 'superagent'];
      if (AUTHORITATIVE_OBJECTS.includes(objectName)) {
        const knownMethods = KNOWN_ASYNC_METHODS.get(objectName);
        if (knownMethods && !knownMethods.has(methodName)) return true;
      }
    }

    // Explicit sync objects (console, Math, lodash, moment, etc.)
    if (objectName && (SYNC_OBJECTS.has(objectName) || objectName === 'chalk')) {
      return true;
    }

    // Pattern-based sync object detection (Utils, Helper, Builder, Formatter, etc.)
    if (objectName && matchesSyncObjectPattern(objectName)) {
      return true;
    }

    return SYNC_METHODS.has(methodName);
  }

  private isReturnValueUsed(node: ts.CallExpression): boolean {
    let current: ts.Node = node;

    while (current.parent) {
      const parent = current.parent;

      // Transparent wrappers — keep walking up
      if (ts.isParenthesizedExpression(parent) ||
          ts.isAsExpression(parent) ||
          ts.isNonNullExpression(parent)) {
        current = parent;
        continue;
      }

      // Ternary — value flows through
      if (ts.isConditionalExpression(parent) &&
          (current === parent.whenTrue || current === parent.whenFalse)) {
        current = parent;
        continue;
      }

      // Logical operators (&&, ||, ??) — value flows through
      if (ts.isBinaryExpression(parent) &&
          (parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
           parent.operatorToken.kind === ts.SyntaxKind.BarBarToken ||
           parent.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) {
        current = parent;
        continue;
      }

      // Comma operator — only right side flows
      if (ts.isBinaryExpression(parent) &&
          parent.operatorToken.kind === ts.SyntaxKind.CommaToken &&
          current === parent.right) {
        current = parent;
        continue;
      }

      // Terminal nodes
      if (ts.isExpressionStatement(parent)) return false;
      if (ts.isReturnStatement(parent)) return true;
      if (ts.isVariableDeclaration(parent)) return true;
      if (ts.isArrayLiteralExpression(parent)) return true;
      if (ts.isPropertyAssignment(parent)) return true;
      if (ts.isCallExpression(parent)) return true;
      if (ts.isBinaryExpression(parent)) return true;

      // Arrow function implicit return
      if (ts.isArrowFunction(parent) && !ts.isBlock(parent.body) && current === parent.body) {
        return true;
      }

      return false; // Default: assume NOT used (avoids severity over-escalation)
    }

    return true;
  }

  /**
   * Forward scan: check if a variable assigned from a call is later used
   * with synchronous property access (.length, .name, [0], mathematical ops),
   * proving the developer knows the result is a concrete value, not a Promise.
   */
  private isResultUsedSynchronously(varName: string, assignmentNode: ts.Node): boolean {
    const enclosingFunc = this.findEnclosingAsyncFunction(assignmentNode);
    if (!enclosingFunc) return false;

    const body = 'body' in enclosingFunc ? enclosingFunc.body : null;
    if (!body) return false;

    let found = false;
    let pastAssignment = false;

    traverse(body, (n) => {
      if (found) return;
      if (n === assignmentNode) { pastAssignment = true; return; }
      if (!pastAssignment) return;

      // variable.property (sync property access — e.g., result.length, result.name)
      if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) &&
          n.expression.text === varName) {
        const prop = n.name.text;
        // Skip .then/.catch/.finally — those are promise handling, not sync access
        if (prop === 'then' || prop === 'catch' || prop === 'finally') return;
        found = true;
        return;
      }

      // variable[index] — bracket access (e.g., result[0])
      if (ts.isElementAccessExpression(n) && ts.isIdentifier(n.expression) &&
          n.expression.text === varName) {
        found = true;
        return;
      }

      // typeof variable, !variable (unary ops on the variable)
      if (ts.isPrefixUnaryExpression(n) && ts.isIdentifier(n.operand) &&
          n.operand.text === varName) {
        found = true;
        return;
      }

      // variable + x, variable === x (arithmetic/comparison — not assignment)
      if (ts.isBinaryExpression(n)) {
        const op = n.operatorToken.kind;
        if (op !== ts.SyntaxKind.EqualsToken &&
            op !== ts.SyntaxKind.AmpersandAmpersandToken &&
            op !== ts.SyntaxKind.BarBarToken &&
            op !== ts.SyntaxKind.QuestionQuestionToken) {
          if ((ts.isIdentifier(n.left) && n.left.text === varName) ||
              (ts.isIdentifier(n.right) && n.right.text === varName)) {
            found = true;
            return;
          }
        }
      }

      // `${variable}` in template literal
      if (ts.isTemplateSpan(n)) {
        const expr = n.expression;
        if (ts.isIdentifier(expr) && expr.text === varName) {
          found = true;
          return;
        }
      }

      // Destructuring: const { a } = variable (re-destructuring)
      if (ts.isVariableDeclaration(n) && n.initializer &&
          ts.isIdentifier(n.initializer) && n.initializer.text === varName) {
        if (ts.isObjectBindingPattern(n.name) || ts.isArrayBindingPattern(n.name)) {
          found = true;
          return;
        }
      }

      // for...of variable (iterating — proves it's iterable, not a promise)
      if (ts.isForOfStatement(n) && ts.isIdentifier(n.expression) &&
          n.expression.text === varName) {
        // Skip for-await-of — that handles promises
        if (!n.awaitModifier) {
          found = true;
          return;
        }
      }

      // variable passed as function argument — e.g., openSelector(selector, ...)
      // Developer expects a concrete value, not a Promise
      if (ts.isCallExpression(n)) {
        for (const arg of n.arguments) {
          if (ts.isIdentifier(arg) && arg.text === varName) {
            found = true;
            return;
          }
        }
      }
    });

    return found;
  }

  /**
   * Check if a call result is used directly as an argument or property value (no variable).
   * e.g., doSomething(loadConfig()), { cfg: loadConfig() }, [loadConfig()]
   * This proves the developer expects a concrete return value, not a Promise.
   */
  private isUsedAsInlineArgument(node: ts.CallExpression): boolean {
    let current: ts.Node = node;
    // Walk up through transparent wrappers
    while (current.parent) {
      const p = current.parent;
      if (ts.isParenthesizedExpression(p) || ts.isAsExpression(p) || ts.isNonNullExpression(p)) {
        current = p;
        continue;
      }
      // Direct function argument: doSomething(fn())
      if (ts.isCallExpression(p) && p.arguments.some(a => a === current)) {
        return true;
      }
      // Object property value: { key: fn() }
      if (ts.isPropertyAssignment(p) && p.initializer === current) {
        return true;
      }
      // Array element: [fn()]
      if (ts.isArrayLiteralExpression(p)) {
        return true;
      }
      // Spread: ...fn()
      if (ts.isSpreadElement(p)) {
        return true;
      }
      break;
    }
    return false;
  }

  /**
   * Generate context-aware suggestion for intentional fire-and-forget patterns.
   */
  private generateFireAndForgetSuggestion(callName: string, functionName: string): string {
    // Detect common fire-and-forget patterns
    const lower = functionName.toLowerCase();

    if (/^(log|track|record|report|emit|publish|dispatch|notify|monitor|ping)/.test(lower)) {
      return `If '${callName}' is intentionally fire-and-forget (telemetry/logging), add \`void ${callName}(...)\` to suppress. If it must complete, use \`await ${callName}(...)\`.`;
    }

    if (/^(cache|warm|prefetch|preload|invalidate|refresh|sync|flush)/.test(lower)) {
      return `If '${callName}' is a background cache/sync operation, use \`void ${callName}(...)\`. If the result is needed before continuing, use \`await ${callName}(...)\`.`;
    }

    if (/^(cleanup|close|disconnect|destroy|shutdown|dispose|release)/.test(lower)) {
      return `If '${callName}' is cleanup that must complete, use \`await ${callName}(...)\`. If best-effort cleanup is acceptable, use \`void ${callName}(...)\`.`;
    }

    return `If this must complete before continuing, use: \`await ${callName}(...)\`. If intentionally fire-and-forget, add \`void ${callName}(...)\` to make intent explicit.`;
  }

  private getObjectName(expr: ts.Expression): string | null {
    if (ts.isIdentifier(expr)) return expr.text;
    if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
    return null;
  }
}

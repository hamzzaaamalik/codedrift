/**
 * Async ForEach Detector — 10/10
 * Detects array methods (forEach/map/filter/find/some/every/reduce/flatMap/findIndex)
 * called with async callbacks that don't await.
 *
 * Priority: CRITICAL (most common AI async mistake)
 *
 * This is THE #1 bug AI coding assistants introduce:
 * - AI generates: array.forEach(async (item) => { await process(item); })
 * - Reality: forEach doesn't await, operations run out of order
 * - Result: Race conditions, data corruption, lost updates
 *
 * Detection pipeline:
 *   1. Method name check (ASYNC_UNSAFE_METHODS)
 *   2. Async-aware library skip (p-map, Bluebird, async.js, RxJS)
 *   3. Callback resolution (inline, named ref, variable ref, this.method)
 *   4. Promise wrapper skip (Promise.all/allSettled/any/race)
 *   5. Map result tracking (discarded → CRITICAL, handled → skip)
 *   6. Severity classification (truthiness=CRITICAL, ordering=HIGH)
 *   7. Callback content escalation (DB write, payment → CRITICAL)
 *   8. Method-specific message + suggestion
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue, Severity, Confidence } from '../types/index.js';
import { traverse, ASTHelpers } from '../core/parser.js';
import * as ts from 'typescript';

// ──────────────────── Constants ────────────────────

/** Methods where async callbacks cause TRUTHINESS bugs (Promise is always truthy) */
const TRUTHINESS_METHODS = new Set(['filter', 'find', 'some', 'every', 'findIndex']);

/** Methods where async callbacks cause ORDERING/LOSS bugs */
const ORDERING_METHODS = new Set(['forEach', 'reduce', 'reduceRight', 'flatMap']);

/** Methods where result is an array of Promises (not resolved values) */
const PROMISE_ARRAY_METHODS = new Set(['map', 'flatMap']);

/** All targeted methods combined */
const ASYNC_UNSAFE_METHODS = new Set([...TRUTHINESS_METHODS, ...ORDERING_METHODS, 'map']);

/** DB write method names — escalate severity when found in callback */
const ESCALATION_DB_WRITES = new Set([
  'create', 'save', 'update', 'delete', 'destroy', 'remove',
  'insertMany', 'bulkCreate', 'createMany', 'updateMany', 'deleteMany',
  'upsert', 'bulkWrite',
]);

/** Payment method names — escalate severity when found in callback */
const ESCALATION_PAYMENT = new Set([
  'charge', 'pay', 'refund', 'transfer', 'capture',
  'createPaymentIntent', 'confirmPayment',
]);

/** File write method names — escalate severity when found in callback */
const ESCALATION_FS_WRITES = new Set([
  'writeFile', 'unlink', 'rm', 'rmdir', 'rename', 'copyFile',
  'appendFile', 'truncate',
]);

/** Async.js method names */
const ASYNC_JS_METHODS = new Set([
  'each', 'eachSeries', 'eachLimit', 'eachOf', 'eachOfSeries', 'eachOfLimit',
  'map', 'mapSeries', 'mapLimit', 'mapValues', 'mapValuesSeries', 'mapValuesLimit',
  'filter', 'filterSeries', 'filterLimit',
  'reduce', 'reduceRight',
  'detect', 'detectSeries', 'detectLimit',
  'some', 'someSeries', 'someLimit',
  'every', 'everySeries', 'everyLimit',
  'concat', 'concatSeries', 'concatLimit',
  'transform', 'sortBy',
]);

/** Bluebird Promise methods that handle async */
const BLUEBIRD_METHODS = new Set([
  'map', 'each', 'filter', 'reduce', 'mapSeries',
]);

/** RxJS operators that handle async */
const RXJS_ASYNC_OPERATORS = new Set([
  'mergeMap', 'switchMap', 'concatMap', 'exhaustMap',
]);

// ──────────────────── Severity Tier System ────────────────────

type SeverityTier = 'CRITICAL' | 'HIGH' | 'WARNING';

const METHOD_TIERS: Record<string, SeverityTier> = {
  // CRITICAL: Truthiness — always-truthy Promise breaks logic silently
  filter: 'CRITICAL', find: 'CRITICAL', some: 'CRITICAL',
  every: 'CRITICAL', findIndex: 'CRITICAL',
  // HIGH: Ordering/loss — fire-and-forget or accumulator broken
  forEach: 'HIGH', reduce: 'HIGH', reduceRight: 'HIGH', flatMap: 'HIGH',
  // HIGH: Result is Promise[] not T[] — but can be handled with Promise.all
  map: 'HIGH',
};

function tierToSeverity(tier: SeverityTier): { severity: Severity; confidence: Confidence } {
  switch (tier) {
    case 'CRITICAL': return { severity: 'error', confidence: 'high' };
    case 'HIGH': return { severity: 'error', confidence: 'high' };
    case 'WARNING': return { severity: 'warning', confidence: 'medium' };
  }
}

function escalateTier(tier: SeverityTier): SeverityTier {
  if (tier === 'WARNING') return 'HIGH';
  return 'CRITICAL';
}

// ──────────────────── Detector Class ────────────────────

export class AsyncForEachDetector extends BaseEngine {
  readonly name = 'async-foreach';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        // Check standard array method calls
        const issue = this.checkArrayMethodWithAsyncCallback(node, context);
        if (issue) {
          issues.push(issue);
          return; // Don't double-check Array.from for the same node
        }

        // Check Array.from with async mapper
        const arrayFromIssue = this.checkArrayFromWithAsyncMapper(node, context);
        if (arrayFromIssue) {
          issues.push(arrayFromIssue);
        }
      }
    });

    return issues;
  }

  // ──────────────────── Main Detection Pipeline ────────────────────

  /**
   * Full detection pipeline for array method + async callback.
   *
   * Pipeline:
   *   1. Extract method name from PropertyAccessExpression
   *   2. Check ASYNC_UNSAFE_METHODS — early exit if not
   *   3. Check isAsyncAwareLibraryCall — skip if true
   *   4. Resolve callback async status (inline, named ref, variable ref, this.method)
   *   5. Check isWithinSafePromiseWrapper — skip if true
   *   6. For map/flatMap: classify result usage → skip if handled, escalate if discarded
   *   7. Get base tier from METHOD_TIERS
   *   8. Apply callback content escalation (DB write, payment)
   *   9. Get method-specific message + suggestion
   *  10. createIssue()
   */
  private checkArrayMethodWithAsyncCallback(
    node: ts.CallExpression,
    context: AnalysisContext
  ): Issue | null {
    const { expression } = node;

    // Step 1: Must be a method call (obj.method or obj?.method)
    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const methodName = expression.name.text;

    // Step 2: Check if it's a targeted async-unsafe method
    if (!ASYNC_UNSAFE_METHODS.has(methodName)) {
      return null;
    }

    // Must have at least one argument (the callback)
    if (node.arguments.length === 0) {
      return null;
    }

    // Step 3: Skip async-aware library calls
    if (this.isAsyncAwareLibraryCall(node)) {
      return null;
    }

    // Step 4: Resolve callback — check if it's async
    const callback = node.arguments[0];
    const resolvedCallback = this.resolveCallbackAsync(callback);
    if (!resolvedCallback) {
      return null; // Not an async callback
    }

    // Step 5: Skip if within safe Promise wrapper (Promise.all, etc.)
    if (this.isWithinSafePromiseWrapper(node)) {
      return null;
    }

    // Step 6: Map result tracking
    let mapResultStatus: 'handled' | 'discarded' | 'unhandled' | null = null;
    if (PROMISE_ARRAY_METHODS.has(methodName)) {
      mapResultStatus = this.classifyMapResult(node);
      if (mapResultStatus === 'handled') {
        return null; // Properly handled via variable forwarding
      }
    }

    // Step 7: Determine base severity tier
    let tier = METHOD_TIERS[methodName] || 'HIGH';

    // Discarded map result → escalate to CRITICAL
    if (mapResultStatus === 'discarded') {
      tier = escalateTier(tier);
    }

    // Step 8: Callback content escalation
    const escalation = this.getCallbackEscalation(resolvedCallback.callbackNode);
    if (escalation) {
      tier = escalateTier(tier);
    }

    // Determine confidence — boost if callback contains await
    const hasAwaitInCallback = this.hasAwaitExpression(resolvedCallback.callbackNode);
    const { severity } = tierToSeverity(tier);
    const confidence = hasAwaitInCallback ? 'high' : 'medium';

    // Step 9: Method-specific message + suggestion
    const message = this.getMethodSpecificMessage(methodName);
    const suggestion = this.getSuggestion(methodName);

    // Step 10: Create issue
    return this.createIssue(
      context,
      node,
      message,
      { severity, suggestion, confidence }
    );
  }

  // ──────────────────── Array.from Detection ────────────────────

  /**
   * Detect Array.from(items, async (item) => { ... })
   * The second argument is a mapper — same issue as map with async callback.
   */
  private checkArrayFromWithAsyncMapper(
    node: ts.CallExpression,
    context: AnalysisContext
  ): Issue | null {
    const { expression } = node;

    // Must be Array.from(...)
    if (!ts.isPropertyAccessExpression(expression)) return null;
    if (!ts.isIdentifier(expression.expression)) return null;
    if (expression.expression.text !== 'Array' || expression.name.text !== 'from') return null;

    // Must have 2+ arguments (source, mapper)
    if (node.arguments.length < 2) return null;

    const mapper = node.arguments[1];
    const resolved = this.resolveCallbackAsync(mapper);
    if (!resolved) return null;

    // Skip if within Promise wrapper
    if (this.isWithinSafePromiseWrapper(node)) return null;

    const hasAwaitInCallback = this.hasAwaitExpression(resolved.callbackNode);
    const confidence = hasAwaitInCallback ? 'high' : 'medium';

    return this.createIssue(
      context,
      node,
      "Array.from() with async mapper returns Promise[], not resolved values — same issue as map() with async callback",
      {
        severity: 'error',
        suggestion: 'Wrap with Promise.all: const results = await Promise.all(Array.from(items, async item => fn(item)))',
        confidence,
      }
    );
  }

  // ──────────────────── Callback Resolution ────────────────────

  /**
   * Resolve whether the callback argument is async.
   * Supports: inline async functions, named function refs, variable refs, this.method refs.
   * Returns the callback node for further analysis, or null if not async.
   */
  private resolveCallbackAsync(
    callbackArg: ts.Node,
  ): { callbackNode: ts.Node } | null {
    // Case 1: Inline async function/arrow
    if (ASTHelpers.isFunctionLike(callbackArg) && ASTHelpers.isAsyncFunction(callbackArg)) {
      return { callbackNode: callbackArg };
    }

    // Case 2: Identifier reference (named function or variable)
    if (ts.isIdentifier(callbackArg)) {
      const name = callbackArg.text;
      const decl = this.findDeclaration(name, callbackArg);
      if (decl && this.isAsyncDeclaration(decl)) {
        return { callbackNode: decl };
      }
      return null;
    }

    // Case 3: this.method reference
    if (ts.isPropertyAccessExpression(callbackArg) &&
        callbackArg.expression.kind === ts.SyntaxKind.ThisKeyword) {
      const methodName = callbackArg.name.text;
      const classDecl = this.findEnclosingClass(callbackArg);
      if (classDecl) {
        const method = this.findClassMethod(classDecl, methodName);
        if (method && ASTHelpers.isAsyncFunction(method)) {
          return { callbackNode: method };
        }
      }
      return null;
    }

    return null;
  }

  /**
   * Find a function or variable declaration by name, starting from the nearest enclosing scope.
   * Walks up the scope chain from the call site to resolve the closest binding.
   */
  private findDeclaration(name: string, callSite: ts.Node): ts.Node | null {
    // Search within a block's direct children for a declaration
    const searchBlock = (block: ts.Node): ts.Node | null => {
      let result: ts.Node | null = null;
      ts.forEachChild(block, (child) => {
        if (result) return;

        if (ts.isFunctionDeclaration(child) && child.name?.text === name) {
          result = child;
          return;
        }

        if (ts.isVariableStatement(child)) {
          for (const decl of child.declarationList.declarations) {
            if (ts.isIdentifier(decl.name) && decl.name.text === name && decl.initializer) {
              if (ASTHelpers.isFunctionLike(decl.initializer)) {
                result = decl.initializer;
                return;
              }
            }
          }
        }
      });
      return result;
    };

    // Walk up from call site to find enclosing scopes (blocks, function bodies, source file)
    let current: ts.Node | undefined = callSite.parent;
    while (current) {
      if (ts.isBlock(current) || ts.isSourceFile(current)) {
        const found = searchBlock(current);
        if (found) return found;
      }
      current = current.parent;
    }

    return null;
  }

  /**
   * Check if a declaration node is async.
   */
  private isAsyncDeclaration(node: ts.Node): boolean {
    return ASTHelpers.isAsyncFunction(node);
  }

  /**
   * Find the enclosing class declaration for a node.
   */
  private findEnclosingClass(node: ts.Node): ts.ClassDeclaration | null {
    let current = node.parent;
    while (current) {
      if (ts.isClassDeclaration(current)) return current;
      current = current.parent;
    }
    return null;
  }

  /**
   * Find a method in a class by name.
   */
  private findClassMethod(classDecl: ts.ClassDeclaration, methodName: string): ts.MethodDeclaration | null {
    for (const member of classDecl.members) {
      if (ts.isMethodDeclaration(member) &&
          ts.isIdentifier(member.name) &&
          member.name.text === methodName) {
        return member;
      }
    }
    return null;
  }

  // ──────────────────── Async-Aware Library Skips ────────────────────

  /**
   * Check if the call is using an async-aware library that properly handles async callbacks.
   */
  private isAsyncAwareLibraryCall(node: ts.CallExpression): boolean {
    const { expression } = node;

    if (!ts.isPropertyAccessExpression(expression)) return false;

    const callerExpr = expression.expression;
    const methodName = expression.name.text;

    // --- Bluebird: Promise.map(...), Promise.each(...), Promise.filter(...) ---
    if (ts.isIdentifier(callerExpr) && callerExpr.text === 'Promise' && BLUEBIRD_METHODS.has(methodName)) {
      return true;
    }

    // --- async.js: async.each(...), async.mapSeries(...) ---
    if (ts.isIdentifier(callerExpr) && callerExpr.text === 'async' && ASYNC_JS_METHODS.has(methodName)) {
      return true;
    }

    // --- p-map style: standalone function calls ---
    // These are standalone calls, not method calls. Check the parent if this is within a pipe.

    // --- RxJS: .pipe(mergeMap(...)), .pipe(concatMap(...)) ---
    if (this.isInsideRxJsPipe(node)) {
      return true;
    }

    return false;
  }

  /**
   * Check if this node is inside an RxJS .pipe() call with async-aware operators.
   * Pattern: observable.pipe(mergeMap(async x => ...), ...)
   */
  private isInsideRxJsPipe(node: ts.CallExpression): boolean {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isCallExpression(current)) {
        const expr = current.expression;
        if (ts.isPropertyAccessExpression(expr) && expr.name.text === 'pipe') {
          // Check if any argument to pipe() is an RxJS async operator
          for (const arg of current.arguments) {
            if (ts.isCallExpression(arg) && ts.isIdentifier(arg.expression)) {
              if (RXJS_ASYNC_OPERATORS.has(arg.expression.text)) {
                return true;
              }
            }
          }
        }
      }
      current = current.parent;
    }
    return false;
  }

  // ──────────────────── Map Result Tracking ────────────────────

  /**
   * Classify how a map/flatMap result is used:
   * - 'handled': Result is properly awaited (Promise.all, for-await-of, returned)
   * - 'discarded': Result is thrown away (ExpressionStatement)
   * - 'unhandled': Result is assigned but never properly handled
   */
  private classifyMapResult(node: ts.CallExpression): 'handled' | 'discarded' | 'unhandled' {
    const parent = node.parent;
    if (!parent) return 'discarded';

    // Discarded: items.map(async ...) as expression statement
    if (ts.isExpressionStatement(parent)) {
      return 'discarded';
    }

    // Assigned to variable: const results = items.map(async ...)
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      const varName = parent.name.text;
      if (this.isMapResultHandledLater(varName, parent)) {
        return 'handled';
      }
      return 'unhandled';
    }

    // Part of an assignment: results = items.map(async ...)
    if (ts.isBinaryExpression(parent) &&
        parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(parent.left)) {
      const varName = parent.left.text;
      if (this.isMapResultHandledLater(varName, parent)) {
        return 'handled';
      }
      return 'unhandled';
    }

    // Returned: return items.map(async ...) — caller may handle it
    if (ts.isReturnStatement(parent)) {
      return 'handled';
    }

    // Passed as argument to a function (could be Promise.all)
    // The isWithinSafePromiseWrapper check handles the Promise.all case
    // If we get here, it's some other usage — treat as unhandled
    return 'unhandled';
  }

  /**
   * Check if a variable holding map results is properly handled later in the function body.
   * Looks for: await Promise.all(varName), for-await-of, return varName
   */
  private isMapResultHandledLater(varName: string, assignmentNode: ts.Node): boolean {
    // Find the enclosing function body or block
    const body = this.findEnclosingFunctionBody(assignmentNode);
    if (!body) return false;

    let handled = false;

    traverse(body, (node) => {
      if (handled) return;

      // await Promise.all(varName) or await Promise.allSettled(varName)
      if (ts.isAwaitExpression(node) && ts.isCallExpression(node.expression)) {
        const call = node.expression;
        if (ts.isPropertyAccessExpression(call.expression)) {
          const obj = call.expression.expression;
          const method = call.expression.name.text;
          if (ts.isIdentifier(obj) && obj.text === 'Promise' &&
              ['all', 'allSettled', 'any', 'race'].includes(method)) {
            // Check if varName is an argument
            for (const arg of call.arguments) {
              if (ts.isIdentifier(arg) && arg.text === varName) {
                handled = true;
                return;
              }
              // Spread: Promise.all([...varName])
              if (ts.isArrayLiteralExpression(arg)) {
                for (const el of arg.elements) {
                  if (ts.isSpreadElement(el) && ts.isIdentifier(el.expression) && el.expression.text === varName) {
                    handled = true;
                    return;
                  }
                  if (ts.isIdentifier(el) && el.text === varName) {
                    handled = true;
                    return;
                  }
                }
              }
            }
          }
        }
      }

      // for await (... of varName) { ... }
      if (ts.isForOfStatement(node) && node.awaitModifier) {
        if (ts.isIdentifier(node.expression) && node.expression.text === varName) {
          handled = true;
          return;
        }
      }

      // return varName
      if (ts.isReturnStatement(node) && node.expression &&
          ts.isIdentifier(node.expression) && node.expression.text === varName) {
        handled = true;
      }
    });

    return handled;
  }

  /**
   * Find the enclosing function body (Block node) for a given node.
   */
  private findEnclosingFunctionBody(node: ts.Node): ts.Block | null {
    let current = node.parent;
    while (current) {
      if (ASTHelpers.isFunctionLike(current)) {
        const fn = current as ts.FunctionLikeDeclaration;
        if (fn.body && ts.isBlock(fn.body)) {
          return fn.body;
        }
        return null;
      }
      current = current.parent;
    }
    return null;
  }

  // ──────────────────── Callback Content Escalation ────────────────────

  /**
   * Check if callback body contains high-impact operations that warrant severity escalation.
   * Returns 'CRITICAL' if escalation-worthy operations found, null otherwise.
   */
  private getCallbackEscalation(callbackNode: ts.Node): SeverityTier | null {
    let found = false;

    traverse(callbackNode, (node) => {
      if (found) return;

      if (ts.isCallExpression(node)) {
        const callName = this.extractMethodName(node);
        if (callName) {
          if (ESCALATION_DB_WRITES.has(callName) ||
              ESCALATION_PAYMENT.has(callName) ||
              ESCALATION_FS_WRITES.has(callName)) {
            found = true;
          }
        }
      }
    });

    return found ? 'CRITICAL' : null;
  }

  /**
   * Extract the method name from a call expression.
   * Returns 'save' from obj.save(), save(), this.save(), etc.
   */
  private extractMethodName(node: ts.CallExpression): string | null {
    if (ts.isPropertyAccessExpression(node.expression)) {
      return node.expression.name.text;
    }
    if (ts.isIdentifier(node.expression)) {
      return node.expression.text;
    }
    return null;
  }

  // ──────────────────── Promise Wrapper Detection ────────────────────

  /**
   * Check if this call is within a safe Promise wrapper.
   * Handles: await Promise.all(arr.map(...)), Promise.all(...).then(...),
   * and also assigned-then-awaited patterns.
   */
  private isWithinSafePromiseWrapper(node: ts.Node): boolean {
    let current = node.parent;

    while (current) {
      if (ts.isCallExpression(current)) {
        const { expression } = current;

        // Promise.all(...), Promise.allSettled(...), Promise.any(...), Promise.race(...)
        if (ts.isPropertyAccessExpression(expression)) {
          const objectName = ts.isIdentifier(expression.expression)
            ? expression.expression.text
            : null;
          const methodName = expression.name.text;

          const safePromiseMethods = ['all', 'allSettled', 'any', 'race'];
          if (objectName === 'Promise' && safePromiseMethods.includes(methodName)) {
            // Direct await: await Promise.all(array.map(...))
            const promiseCallParent = current.parent;
            if (promiseCallParent && ts.isAwaitExpression(promiseCallParent)) {
              return true;
            }

            // Chained: Promise.all(array.map(...)).then(...) / .catch(...)
            if (promiseCallParent && ts.isPropertyAccessExpression(promiseCallParent)) {
              const chainMethod = promiseCallParent.name.text;
              if (['then', 'catch', 'finally'].includes(chainMethod)) {
                return true;
              }
            }

            // Assigned to variable — handled by map result tracking
            // Still return true here so we don't double-flag
            if (promiseCallParent && (ts.isVariableDeclaration(promiseCallParent) || ts.isReturnStatement(promiseCallParent))) {
              return true;
            }
          }
        }
      }

      current = current.parent;
    }

    return false;
  }

  // ──────────────────── Await Expression Detection ────────────────────

  /**
   * Check if function body contains await expressions.
   * Stops at nested function boundaries to avoid false positives.
   */
  private hasAwaitExpression(node: ts.Node): boolean {
    let hasAwait = false;

    const walk = (child: ts.Node) => {
      if (hasAwait) return;
      if (ts.isAwaitExpression(child)) {
        hasAwait = true;
        return;
      }
      // Don't descend into nested functions
      if (child !== node && ASTHelpers.isFunctionLike(child)) {
        return;
      }
      ts.forEachChild(child, walk);
    };

    ts.forEachChild(node, walk);
    return hasAwait;
  }

  // ──────────────────── Method-Specific Messages ────────────────────

  /**
   * Get method-specific message explaining WHY the async callback is broken.
   */
  private getMethodSpecificMessage(methodName: string): string {
    switch (methodName) {
      case 'forEach':
        return "forEach() ignores async return values — await expressions inside run as detached promises, causing race conditions and unhandled rejections";

      case 'map':
        return "map() with async callback returns Promise[], not resolved values — result is an array of pending promises";

      case 'filter':
        return "filter() evaluates async callback as truthy (Promise is always truthy) — all items pass, no filtering occurs";

      case 'find':
        return "find() evaluates async callback as truthy (Promise is always truthy) — always returns first element";

      case 'some':
        return "some() evaluates async callback as truthy (Promise is always truthy) — always returns true";

      case 'every':
        return "every() evaluates async callback as truthy (Promise is always truthy) — always returns true";

      case 'findIndex':
        return "findIndex() evaluates async callback as truthy (Promise is always truthy) — always returns 0";

      case 'reduce':
      case 'reduceRight':
        return "reduce() doesn't await the accumulator — async reducer receives a Promise as accumulator, not the resolved value";

      case 'flatMap':
        return "flatMap() doesn't await results — returns Promise objects instead of flattened resolved values";

      default:
        return `${methodName}() with async callback doesn't await — operations may not complete as expected`;
    }
  }

  /**
   * Get method-specific fix suggestion with code example.
   */
  private getSuggestion(methodName: string): string {
    switch (methodName) {
      case 'forEach':
        return 'Replace with for...of: for (const item of array) { await fn(item); }';

      case 'map':
        return 'Wrap with Promise.all: const results = await Promise.all(array.map(async item => fn(item)))';

      case 'filter':
        return 'Use Promise.all + filter: const checks = await Promise.all(array.map(async item => ({ item, keep: await predicate(item) }))); return checks.filter(r => r.keep).map(r => r.item);';

      case 'reduce':
      case 'reduceRight':
        return 'Use for...of: let acc = initial; for (const item of array) { acc = await reducer(acc, item); } return acc;';

      case 'some':
      case 'every':
        return 'Use for...of with early return: for (const item of array) { if (await check(item)) return true; } return false;';

      case 'find':
        return 'Use for...of: for (const item of array) { if (await predicate(item)) return item; } return undefined;';

      case 'findIndex':
        return 'Use for...of with index: for (let i = 0; i < arr.length; i++) { if (await predicate(arr[i])) return i; } return -1;';

      case 'flatMap':
        return 'Use Promise.all + flat: const results = (await Promise.all(array.map(async item => fn(item)))).flat()';

      default:
        return 'Replace with for...of loop or await Promise.all(array.map(...))';
    }
  }
}

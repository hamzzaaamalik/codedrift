/**
 * Missing Await Detector
 * Detects fire-and-forget async function calls that should be awaited
 * Priority: CRITICAL (causes race conditions, data corruption)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse, ASTHelpers } from '../core/parser.js';
import * as ts from 'typescript';

export class MissingAwaitDetector extends BaseEngine {
  readonly name = 'missing-await';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      // Check call expressions that might be async
      if (ts.isCallExpression(node)) {
        const issue = this.checkMissingAwait(node, context);
        if (issue) {
          issues.push(issue);
        }
      }
    });

    return issues;
  }

  /**
   * Check if a call expression is an unawaited async function
   * Now with multi-level confidence scoring
   */
  private checkMissingAwait(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    // Skip if already awaited
    if (this.isAwaited(node)) {
      return null;
    }

    // Skip if void operator used (intentional fire-and-forget)
    if (this.hasVoidOperator(node)) {
      return null;
    }

    // Skip if promise is handled with .then() or .catch()
    if (this.hasPromiseHandler(node)) {
      return null;
    }

    // Skip if assigned to variable (may be awaited later)
    if (this.isAssignedToVariable(node)) {
      return null;
    }

    // Track whether we've already confirmed the method is async (e.g. via class member lookup)
    let knownAsync = false;

    // Skip this.* method calls ONLY if the target method is not declared async in the same class
    if (ts.isPropertyAccessExpression(node.expression)) {
      if (node.expression.expression.kind === ts.SyntaxKind.ThisKeyword) {
        // Check if this method is declared async in the enclosing class
        if (!this.isAsyncMethodInClass(node)) {
          return null;
        }
        // Method IS async — continue analysis (don't skip)
        knownAsync = true;
      }
    }

    // Skip if not inside an async function (await is invalid here — not a real issue)
    if (!this.isInsideAsyncFunction(node)) {
      return null;
    }

    // Skip if inside a top-level async context (framework callbacks, IIFEs, etc.)
    if (this.isTopLevelAsyncContext(node)) {
      return null;
    }

    // Skip if inside Promise.all/Promise.allSettled — collective await handles it
    if (this.isInsidePromiseAll(node)) {
      return null;
    }

    // Get function name for better detection
    const { expression } = node;
    let functionName: string | null = null;
    let objectName: string | null = null;

    if (ts.isIdentifier(expression)) {
      functionName = expression.text;
    } else if (ts.isPropertyAccessExpression(expression)) {
      functionName = expression.name.text;
      objectName = this.getObjectName(expression.expression);
    }

    // Skip intentional fire-and-forget patterns
    if (functionName && this.isIntentionalFireAndForget(functionName, objectName)) {
      return null;
    }

    // Check if function is declared async (highest confidence)
    // Use knownAsync if we already confirmed via class member lookup
    const isDeclaredAsync = knownAsync || (functionName ? this.isDeclaredAsAsync(functionName, context) : false);

    // Cross-file heuristic: naming conventions suggest async (medium confidence)
    const isHeuristicallyAsync = !isDeclaredAsync && functionName ? this.isLikelyAsync(functionName) : false;

    // Cross-file heuristic: imported from async-sounding module (medium confidence)
    const isFromAsyncModule = !isDeclaredAsync && functionName ? this.isImportedFromAsyncModule(functionName, context) : false;

    // Cross-file heuristic: used with .then() or await elsewhere in file (medium confidence)
    const isUsedAsAsync = !isDeclaredAsync && functionName ? this.isUsedAsAsyncElsewhere(functionName, context) : false;

    // Combine cross-file heuristics into a single flag
    const isCrossFileAsync = isHeuristicallyAsync || isFromAsyncModule || isUsedAsAsync;

    // Check if matches async naming patterns (medium confidence)
    const matchesAsyncPattern = functionName ? this.matchesAsyncPattern(functionName, objectName) : false;

    // Check if return value is used (affects confidence)
    const returnValueUsed = this.isReturnValueUsed(node);

    // Determine if this is likely an async function
    let confidence: 'high' | 'medium' | 'low' = 'low';
    let message = 'Async function called without await';
    let suggestion = 'Add await or explicitly use void operator for fire-and-forget';

    if (isDeclaredAsync && returnValueUsed) {
      // HIGH confidence: Declared as async and return value is used
      confidence = 'high';
      message = `Async function '${functionName}' called without await`;
      suggestion = `Add 'await' before the call: \`await ${functionName}(...)\``;
    } else if (isDeclaredAsync) {
      // MEDIUM confidence: Declared as async but return value not used (might be fire-and-forget)
      confidence = 'medium';
      message = `Async function '${functionName}' called without await (fire-and-forget?)`;
      suggestion = `If this must complete before continuing, use: \`await ${functionName}(...)\`. Otherwise add \`void ${functionName}(...)\` to make fire-and-forget intent explicit.`;
    } else if (isCrossFileAsync && returnValueUsed) {
      // MEDIUM confidence: Cross-file heuristic suggests async and return value is used
      confidence = 'medium';
      message = `Function '${functionName}' is likely async but not awaited`;
      suggestion = `Add 'await' before the call: \`await ${functionName}(...)\``;
    } else if (isCrossFileAsync) {
      // MEDIUM confidence: Cross-file heuristic suggests async but return value not used
      confidence = 'medium';
      message = `Function '${functionName}' is likely async but not awaited (fire-and-forget?)`;
      suggestion = `If this must complete before continuing, use: \`await ${functionName}(...)\`. Otherwise add \`void ${functionName}(...)\` to make fire-and-forget intent explicit.`;
    } else if (matchesAsyncPattern && returnValueUsed) {
      // MEDIUM confidence: Matches pattern and return value used
      confidence = 'medium';
      message = `Function '${functionName}' appears async but not awaited`;
      suggestion = `If '${functionName}' is async, prefix with \`await ${functionName}(...)\`. Otherwise no change needed.`;
    } else if (matchesAsyncPattern) {
      // LOW confidence: Matches pattern but return value not used
      confidence = 'low';
      message = `Function '${functionName}' might be async but not awaited`;
      suggestion = 'Verify if this function is async and should be awaited';
      return null; // Skip low confidence fire-and-forget cases
    } else {
      // Not enough evidence - skip
      return null;
    }

    return this.createIssue(context, node, message, {
      severity: confidence === 'high' ? 'error' : 'warning',
      confidence,
      suggestion,
    });
  }

  /**
   * Check if node is awaited
   */
  private isAwaited(node: ts.Node): boolean {
    const parent = node.parent;
    return parent && ts.isAwaitExpression(parent);
  }

  /**
   * Check if node has void operator (void someAsyncFunc())
   */
  private hasVoidOperator(node: ts.Node): boolean {
    const parent = node.parent;
    return parent && ts.isVoidExpression(parent);
  }

  /**
   * Check if promise is handled with .then() or .catch()
   */
  private hasPromiseHandler(node: ts.CallExpression): boolean {
    const parent = node.parent;

    if (!parent || !ts.isPropertyAccessExpression(parent)) {
      return false;
    }

    const methodName = parent.name.text;
    return methodName === 'then' || methodName === 'catch' || methodName === 'finally';
  }

  /**
   * Check if call result is assigned to a variable
   */
  private isAssignedToVariable(node: ts.CallExpression): boolean {
    const parent = node.parent;

    // Variable declaration: const x = asyncFunc()
    if (parent && ts.isVariableDeclaration(parent)) {
      return true;
    }

    // Assignment: x = asyncFunc()
    if (parent && ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      return true;
    }

    // Property assignment: obj.x = asyncFunc()
    if (parent && ts.isPropertyAssignment(parent)) {
      return true;
    }

    return false;
  }

  /**
   * Check if node is inside an async function context
   * (await is only valid inside async functions)
   */
  private isInsideAsyncFunction(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      if (
        ts.isFunctionDeclaration(current) ||
        ts.isFunctionExpression(current) ||
        ts.isArrowFunction(current) ||
        ts.isMethodDeclaration(current)
      ) {
        return !!(current.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword));
      }
      current = current.parent;
    }
    return false; // top-level module scope — no async context
  }

  /**
   * Find the nearest enclosing async function for a given node.
   * Returns the async function node, or null if not inside one.
   */
  private findEnclosingAsyncFunction(node: ts.Node): ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration | null {
    let current = node.parent;
    while (current) {
      if (
        ts.isFunctionDeclaration(current) ||
        ts.isFunctionExpression(current) ||
        ts.isArrowFunction(current) ||
        ts.isMethodDeclaration(current)
      ) {
        const isAsync = current.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword);
        if (isAsync) {
          return current;
        }
        // If we hit a non-async function boundary, stop — the node is not
        // directly inside an async function (it may be nested deeper).
        return null;
      }
      current = current.parent;
    }
    return null;
  }

  /**
   * Determine if the unawaited async call is inside a "top-level async context"
   * — a framework callback or IIFE where nothing can meaningfully await the
   * enclosing function. In these cases flagging missing-await is noise.
   *
   * Recognized contexts:
   *  1. Timer callbacks: setTimeout, setInterval, setImmediate, process.nextTick, queueMicrotask
   *  2. Test framework callbacks: it, test, describe, beforeEach, afterEach, beforeAll, afterAll, before, after
   *  3. Express/Fastify route handlers: app.get, router.post, fastify.put, server.delete, etc.
   *  4. IIFEs (Immediately Invoked Function Expressions)
   *  5. Event handler registrations: .on(), .once(), .addEventListener(), .addListener()
   */
  private isTopLevelAsyncContext(node: ts.Node): boolean {
    const enclosingAsync = this.findEnclosingAsyncFunction(node);
    if (!enclosingAsync) {
      return false;
    }

    const parent = enclosingAsync.parent;
    if (!parent) {
      return false;
    }

    // ── 4. IIFE check ──
    // The async function is immediately invoked: (async () => { ... })()
    // In the AST the function is wrapped in a ParenthesizedExpression which
    // is the expression of a CallExpression, OR the function IS the expression
    // of a CallExpression directly.
    if (this.isIIFE(enclosingAsync)) {
      return true;
    }

    // ── 6. NestJS decorated handlers ──
    // @Get(), @Post(), etc. — framework invokes these methods (method on a class, not a callback)
    if (this.isNestJSHandler(enclosingAsync)) {
      return true;
    }

    // For the remaining checks the async function must be an argument to a CallExpression.
    // Walk up through parenthesized expressions to find the CallExpression.
    const callInfo = this.getEnclosingCallExpression(enclosingAsync);
    if (!callInfo) {
      return false;
    }

    const { callExpr } = callInfo;
    const calleeName = this.getCalleeInfo(callExpr);
    if (!calleeName) {
      return false;
    }

    // ── 1. Timer / scheduler callbacks ──
    const timerFunctions = new Set([
      'setTimeout', 'setInterval', 'setImmediate', 'queueMicrotask',
    ]);
    if (timerFunctions.has(calleeName.fullName) || timerFunctions.has(calleeName.methodName)) {
      return true;
    }
    // process.nextTick
    if (calleeName.objectName === 'process' && calleeName.methodName === 'nextTick') {
      return true;
    }

    // ── 2. Test framework callbacks ──
    const testFunctions = new Set([
      'it', 'test', 'describe', 'beforeEach', 'afterEach',
      'beforeAll', 'afterAll', 'before', 'after',
    ]);
    if (testFunctions.has(calleeName.fullName) || testFunctions.has(calleeName.methodName)) {
      return true;
    }

    // ── 3. Express / Fastify route handler registrations ──
    const routeMethods = new Set([
      'get', 'post', 'put', 'delete', 'patch', 'use', 'all',
      'head', 'options',
    ]);
    const routeObjects = new Set([
      'app', 'router', 'server', 'fastify',
    ]);
    if (
      calleeName.objectName &&
      routeObjects.has(calleeName.objectName) &&
      routeMethods.has(calleeName.methodName)
    ) {
      return true;
    }

    // ── 5. Event handler registrations ──
    const eventMethods = new Set([
      'on', 'once', 'addEventListener', 'addListener',
    ]);
    if (eventMethods.has(calleeName.methodName)) {
      return true;
    }

    return false;
  }

  /**
   * Check if a function node is a NestJS handler decorated with @Get(), @Post(), etc.
   */
  private isNestJSHandler(funcNode: ts.Node): boolean {
    if (!ts.isMethodDeclaration(funcNode)) return false;
    const decorators = ts.canHaveDecorators(funcNode) ? ts.getDecorators(funcNode) : undefined;
    if (!decorators) return false;

    const httpDecorators = new Set(['Get', 'Post', 'Put', 'Patch', 'Delete', 'All', 'Head', 'Options']);
    return decorators.some(d => {
      if (ts.isCallExpression(d.expression) && ts.isIdentifier(d.expression.expression)) {
        return httpDecorators.has(d.expression.expression.text);
      }
      return false;
    });
  }

  /**
   * Check if a node is inside a Promise.all(), Promise.allSettled(), Promise.race(), or Promise.any() call.
   * Individual promises inside these don't need individual await.
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

  /**
   * Check if an async function is an IIFE (Immediately Invoked Function Expression).
   * Patterns:
   *   (async () => { ... })()
   *   (async function() { ... })()
   *   (async function() { ... }).call(ctx)
   */
  private isIIFE(funcNode: ts.Node): boolean {
    let current: ts.Node = funcNode;

    // Walk up through parenthesized expressions
    while (current.parent && ts.isParenthesizedExpression(current.parent)) {
      current = current.parent;
    }

    // The parent should be a CallExpression where `current` is the expression (callee)
    if (current.parent && ts.isCallExpression(current.parent)) {
      if (current.parent.expression === current) {
        return true;
      }
    }

    // Also handle (async () => { ... }).call(...) / .apply(...)
    if (current.parent && ts.isPropertyAccessExpression(current.parent)) {
      const propAccess = current.parent;
      const methodName = propAccess.name.text;
      if ((methodName === 'call' || methodName === 'apply' || methodName === 'bind') &&
          propAccess.parent && ts.isCallExpression(propAccess.parent)) {
        return true;
      }
    }

    return false;
  }

  /**
   * If `funcNode` is an argument to a CallExpression, return that CallExpression.
   * Walks up through parenthesized expressions.
   */
  private getEnclosingCallExpression(funcNode: ts.Node): { callExpr: ts.CallExpression } | null {
    let current: ts.Node = funcNode;

    // Walk up through parenthesized expressions
    while (current.parent && ts.isParenthesizedExpression(current.parent)) {
      current = current.parent;
    }

    // The parent should be a CallExpression and funcNode should be one of its arguments
    if (current.parent && ts.isCallExpression(current.parent)) {
      const callExpr = current.parent;
      // Make sure funcNode is an argument, not the callee itself (that would be an IIFE)
      const isArgument = callExpr.arguments.some(arg => arg === current);
      if (isArgument) {
        return { callExpr };
      }
    }

    return null;
  }

  /**
   * Extract callee information from a CallExpression.
   * Returns the full name, object name, and method name.
   *
   * Examples:
   *   setTimeout(...)          -> { fullName: 'setTimeout', objectName: null, methodName: 'setTimeout' }
   *   app.get(...)             -> { fullName: 'app.get', objectName: 'app', methodName: 'get' }
   *   process.nextTick(...)    -> { fullName: 'process.nextTick', objectName: 'process', methodName: 'nextTick' }
   *   emitter.on(...)          -> { fullName: 'emitter.on', objectName: 'emitter', methodName: 'on' }
   */
  private getCalleeInfo(callExpr: ts.CallExpression): { fullName: string; objectName: string | null; methodName: string } | null {
    const expr = callExpr.expression;

    if (ts.isIdentifier(expr)) {
      return {
        fullName: expr.text,
        objectName: null,
        methodName: expr.text,
      };
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

  /**
   * Check if the return value of a call expression is actually used
   * Returns false for fire-and-forget patterns (standalone statements)
   */
  private isReturnValueUsed(node: ts.CallExpression): boolean {
    const parent = node.parent;

    // Used in variable declaration: const x = asyncFunc()
    if (parent && ts.isVariableDeclaration(parent)) {
      return true;
    }

    // Used in return statement: return asyncFunc()
    if (parent && ts.isReturnStatement(parent)) {
      return true;
    }

    // Used in binary expression: if (asyncFunc()) or x = asyncFunc()
    if (parent && ts.isBinaryExpression(parent)) {
      return true;
    }

    // Used in conditional: condition ? asyncFunc() : other
    if (parent && ts.isConditionalExpression(parent)) {
      return true;
    }

    // Used in array literal: [asyncFunc(), other]
    if (parent && ts.isArrayLiteralExpression(parent)) {
      return true;
    }

    // Used in object literal: { key: asyncFunc() }
    if (parent && ts.isPropertyAssignment(parent)) {
      return true;
    }

    // Used as function argument: someFunc(asyncFunc())
    if (parent && ts.isCallExpression(parent)) {
      return true;
    }

    // Standalone statement (fire-and-forget)
    if (parent && ts.isExpressionStatement(parent)) {
      return false;
    }

    // Default: assume used if we can't determine
    return true;
  }

  /**
   * Check if function name matches common async patterns
   * More refined than likelyReturnsPromise for better confidence scoring
   */
  private matchesAsyncPattern(functionName: string, objectName: string | null): boolean {
    // Skip known synchronous patterns
    if (this.isSyncMethod(functionName, objectName)) {
      return false;
    }

    // Strong async indicators (common async function prefixes)
    const strongAsyncPatterns = [
      /^(fetch|load|save|update|create|delete|remove)$/i,
      /^(get|set|put|post|patch)Data$/i,
      /^send[A-Z]/,
      /^process[A-Z]/,
      /^execute[A-Z]/,
      /^run[A-Z]/,
    ];

    // Weak async indicators (could be sync or async)
    const weakAsyncPatterns = [
      /^(get|read|write|query|insert|find|search)$/i,
    ];

    // Strong pattern match
    if (strongAsyncPatterns.some(pattern => pattern.test(functionName))) {
      return true;
    }

    // Weak pattern match only if not a getter utility
    if (weakAsyncPatterns.some(pattern => pattern.test(functionName))) {
      // Exclude obvious sync getters
      const syncGetterPatterns = [
        /^get\w+(Name|Type|Value|Label|Text|Key|Id|Index|Count|Length|Size)$/i,
      ];
      if (!syncGetterPatterns.some(pattern => pattern.test(functionName))) {
        return true;
      }
    }

    return false;
  }

  /**
   * Heuristic check if call likely returns a Promise
   * @deprecated Use matchesAsyncPattern and isDeclaredAsAsync instead
   */
  // @ts-expect-error - Unused method kept for backward compatibility
  private _likelyReturnsPromise(node: ts.CallExpression, context: AnalysisContext): boolean {
    const { expression } = node;

    // Get function name and object name
    let functionName: string | null = null;
    let objectName: string | null = null;

    if (ts.isIdentifier(expression)) {
      functionName = expression.text;
    } else if (ts.isPropertyAccessExpression(expression)) {
      functionName = expression.name.text;
      objectName = this.getObjectName(expression.expression);
    }

    if (!functionName) {
      return false;
    }

    // Skip intentional fire-and-forget patterns (logging, analytics, monitoring)
    if (this.isIntentionalFireAndForget(functionName, objectName)) {
      return false;
    }

    // Skip common synchronous methods
    if (this.isSyncMethod(functionName, objectName)) {
      return false;
    }

    // Check if function is declared as async in the same file
    if (this.isDeclaredAsAsync(functionName, context)) {
      return true;
    }

    // Skip known synchronous traversal functions
    const syncTraversalFunctions = ['traverse', 'forEach', 'map', 'filter'];
    if (syncTraversalFunctions.includes(functionName)) {
      return false;
    }

    // Heuristic: Common async naming patterns (but only for standalone functions)
    if (!objectName) {
      // Skip obvious synchronous getter utilities
      const syncGetterPatterns = [
        /^get\w+(Name|Type|Value|Label|Text|Key|Id|Index|Count|Length|Size)$/i,
      ];

      if (syncGetterPatterns.some(pattern => pattern.test(functionName))) {
        return false;
      }

      const asyncPatterns = [
        /^(get|fetch|load|save|update|create|delete|send|process|execute|run|handle)/i,
        /^(notify|track|record|write|read|query|insert)/i,
      ];

      return asyncPatterns.some(pattern => pattern.test(functionName));
    }

    return false;
  }

  /**
   * Check if this is an intentional fire-and-forget async call
   * (logging, analytics, background tasks that don't affect main flow)
   */
  private isIntentionalFireAndForget(methodName: string, objectName: string | null): boolean {
    // Common fire-and-forget function patterns
    const fireAndForgetPatterns = [
      // Logging/Analytics
      'log', 'logActivity', 'logEvent', 'logError', 'logWarning', 'logInfo',
      'track', 'trackEvent', 'trackUser', 'trackAction', 'trackPageView',
      'record', 'recordMetric', 'recordEvent', 'recordActivity',
      'report', 'reportError', 'reportEvent',
      'analytics', 'sendAnalytics',

      // Event emitters (async but intentionally not awaited)
      'emit', 'publish', 'dispatch', 'trigger', 'fire',

      // Background monitoring
      'monitor', 'ping', 'heartbeat', 'healthCheck',

      // Cache warming (fire-and-forget)
      'warmCache', 'prefetch', 'preload',

      // Notifications (often fire-and-forget)
      'notify', 'sendNotification', 'alert',
    ];

    if (fireAndForgetPatterns.includes(methodName)) {
      return true;
    }

    // Pattern-based allowlist: log*, track*, emit*, send* (but not sendData/sendRequest)
    if (methodName.match(/^(log|track|emit)[A-Z]/i)) {
      return true;
    }
    if (methodName.match(/^send[A-Z]/) && !methodName.match(/^send(Data|Request|Message)$/i)) {
      return true;
    }

    // Event emitter objects
    if (objectName) {
      const eventEmitterObjects = ['emitter', 'eventBus', 'eventEmitter', 'events', 'bus'];
      if (eventEmitterObjects.some(obj => objectName.toLowerCase().includes(obj))) {
        return true;
      }
    }

    // Logger objects
    if (objectName) {
      const loggerObjects = ['logger', 'log', 'analytics', 'tracker', 'telemetry', 'metrics'];
      if (loggerObjects.some(obj => objectName.toLowerCase().includes(obj))) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if method is known to be synchronous
   */
  private isSyncMethod(methodName: string, objectName: string | null): boolean {
    // Console methods
    if (objectName === 'console') {
      return true;
    }

    // Chalk/Ora methods (terminal formatting)
    const formattingObjects = ['chalk', 'ora'];
    if (objectName && formattingObjects.includes(objectName)) {
      return true;
    }

    // Chalk chaining (chalk.bold, chalk.red.bold, etc) - check if object name contains chalk
    if (objectName && objectName.includes('chalk')) {
      return true;
    }

    // Common sync string/array methods
    const syncMethods = [
      'push', 'pop', 'shift', 'unshift', 'slice', 'splice',
      'toString', 'toLowerCase', 'toUpperCase', 'trim', 'split', 'join',
      'includes', 'startsWith', 'endsWith', 'indexOf', 'match',
      'map', 'filter', 'reduce', 'forEach', 'find', 'some', 'every',
      'add', 'set', 'get', 'has', 'delete', 'clear',
      'bold', 'red', 'green', 'yellow', 'blue', 'cyan', 'magenta', // chalk methods
      'createIssue', 'loadPackageJson', 'extractPackageName', // engine helpers
      'checkMissingAwait', 'checkResponseCall', 'checkLoggerCall', // engine checks
      'containsStackTrace', 'containsSensitiveData', // detector helpers
      'digest', 'update', 'createHash', // crypto methods
      'log', 'warn', 'error', 'info', // console methods (backup)
      'exit', 'cwd', // process methods
      'substring', 'getDefaultBaselinePath', 'saveBaseline', 'loadBaseline', // baseline helpers
    ];

    return syncMethods.includes(methodName);
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
   * Check if function is declared as async in the current file
   */
  private isDeclaredAsAsync(functionName: string, context: AnalysisContext): boolean {
    let isAsync = false;

    traverse(context.sourceFile, (node) => {
      // Function declaration: async function foo() {}
      if (ts.isFunctionDeclaration(node) && node.name?.text === functionName) {
        if (ASTHelpers.isAsyncFunction(node)) {
          isAsync = true;
        }
      }

      // Variable with arrow function: const foo = async () => {}
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === functionName) {
        if (node.initializer && ASTHelpers.isFunctionLike(node.initializer) && ASTHelpers.isAsyncFunction(node.initializer)) {
          isAsync = true;
        }
      }
    });

    return isAsync;
  }

  /**
   * Heuristic: Check if a function name suggests it is async based on common naming conventions.
   * Used as a fallback when the function declaration is not found in the current file
   * (e.g. imported from another module). Returns true for names that start with common
   * async prefixes like fetch, load, save, etc.
   */
  private isLikelyAsync(functionName: string): boolean {
    const asyncPrefixes = ['fetch', 'get', 'load', 'save', 'create', 'update', 'delete', 'find', 'query', 'request', 'send', 'upload', 'download'];
    const lower = functionName.toLowerCase();
    // Check if function name starts with a common async prefix
    // But exclude simple getters like getName, getLength (typically sync)
    return asyncPrefixes.some(prefix => {
      if (!lower.startsWith(prefix)) return false;
      // 'get' prefix: only flag if followed by a "data" word (getUser, getData, getItems — not getName, getLength)
      if (prefix === 'get') {
        const rest = functionName.slice(3);
        const dataWords = ['User', 'Data', 'Items', 'List', 'Record', 'Result', 'Response', 'Config', 'Settings', 'Profile', 'Order', 'Product', 'Post', 'Comment', 'Message', 'File', 'Image', 'Document'];
        return dataWords.some(w => rest.startsWith(w)) || rest.endsWith('s') || rest.endsWith('ById') || rest.endsWith('ByEmail');
      }
      return true;
    });
  }

  /**
   * Heuristic: Check if a function is imported from a module whose file name
   * suggests it contains async operations (service, repository, api, client, handler).
   */
  private isImportedFromAsyncModule(functionName: string, context: AnalysisContext): boolean {
    const asyncModulePatterns = ['service', 'repository', 'api', 'client', 'handler'];
    let importedFromAsyncModule = false;

    traverse(context.sourceFile, (node) => {
      if (importedFromAsyncModule) return; // Already found

      if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
        const modulePath = node.moduleSpecifier.text.toLowerCase();

        // Check if this import brings in the function we're looking for
        const importClause = node.importClause;
        if (!importClause) return;

        let importsFunction = false;

        // Default import: import foo from './service'
        if (importClause.name && importClause.name.text === functionName) {
          importsFunction = true;
        }

        // Named imports: import { foo } from './service'
        if (importClause.namedBindings && ts.isNamedImports(importClause.namedBindings)) {
          for (const specifier of importClause.namedBindings.elements) {
            if (specifier.name.text === functionName) {
              importsFunction = true;
              break;
            }
          }
        }

        if (importsFunction) {
          // Check if module path contains async-sounding keywords
          if (asyncModulePatterns.some(pattern => modulePath.includes(pattern))) {
            importedFromAsyncModule = true;
          }
        }
      }
    });

    return importedFromAsyncModule;
  }

  /**
   * Heuristic: Check if a function is used with .then() or await elsewhere in the same file,
   * which strongly implies it returns a Promise and is async.
   */
  private isUsedAsAsyncElsewhere(functionName: string, context: AnalysisContext): boolean {
    let usedAsAsync = false;

    traverse(context.sourceFile, (node) => {
      if (usedAsAsync) return; // Already found

      // Check for: functionName(...).then(...)
      if (ts.isPropertyAccessExpression(node)) {
        const methodName = node.name.text;
        if (methodName === 'then' || methodName === 'catch') {
          // The object should be a call to functionName
          const obj = node.expression;
          if (ts.isCallExpression(obj)) {
            const callee = obj.expression;
            if (ts.isIdentifier(callee) && callee.text === functionName) {
              usedAsAsync = true;
            }
          }
        }
      }

      // Check for: await functionName(...)
      if (ts.isAwaitExpression(node)) {
        const awaited = node.expression;
        if (ts.isCallExpression(awaited)) {
          const callee = awaited.expression;
          if (ts.isIdentifier(callee) && callee.text === functionName) {
            usedAsAsync = true;
          }
        }
      }
    });

    return usedAsAsync;
  }

  /**
   * Check if `this.methodName()` calls an async method declared in the enclosing class.
   */
  private isAsyncMethodInClass(node: ts.CallExpression): boolean {
    const expr = node.expression;
    if (!ts.isPropertyAccessExpression(expr)) return false;

    const methodName = expr.name.text;

    // Walk up to find the enclosing class
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) {
        // Search class members for the method
        for (const member of current.members) {
          if (ts.isMethodDeclaration(member) && member.name && ts.isIdentifier(member.name)) {
            if (member.name.text === methodName) {
              // Check if the method has the async modifier
              return !!(member.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword));
            }
          }
        }
        // Method not found in class — can't determine, assume sync
        return false;
      }
      current = current.parent;
    }

    // Not inside a class — can't determine
    return false;
  }

}

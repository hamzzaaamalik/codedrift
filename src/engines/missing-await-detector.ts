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

    // Skip this.* method calls (internal helper methods)
    if (ts.isPropertyAccessExpression(node.expression)) {
      if (node.expression.expression.kind === ts.SyntaxKind.ThisKeyword) {
        return null;
      }
    }

    // Check if this call returns a Promise (heuristic-based)
    if (!this.likelyReturnsPromise(node, context)) {
      return null;
    }

    return this.createIssue(context, node, 'Async function called without await', {
      severity: 'error',
      suggestion: 'Add await or explicitly use void operator for fire-and-forget',
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
   * Heuristic check if call likely returns a Promise
   */
  private likelyReturnsPromise(node: ts.CallExpression, context: AnalysisContext): boolean {
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

}

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

        // Check forEach with async callbacks (common mistake!)
        const forEachIssue = this.checkForEachWithAsync(node, context);
        if (forEachIssue) {
          issues.push(forEachIssue);
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
      const asyncPatterns = [
        /^(get|fetch|load|save|update|create|delete|send|process|execute|run|handle)/i,
        /^(notify|track|record|write|read|query|insert)/i,
      ];

      return asyncPatterns.some(pattern => pattern.test(functionName));
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
   * Check if forEach/map/filter is called with async callback
   * This is a common mistake - these methods don't await!
   */
  private checkForEachWithAsync(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    const { expression } = node;

    // Check if it's a method call
    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const methodName = expression.name.text;

    // Only check forEach, map, filter (they don't await callbacks)
    const arrayMethods = ['forEach', 'map', 'filter'];
    if (!arrayMethods.includes(methodName)) {
      return null;
    }

    // Check if callback is async
    if (node.arguments.length === 0) {
      return null;
    }

    const callback = node.arguments[0];

    // Check if callback is an async function
    if (ASTHelpers.isFunctionLike(callback) && ASTHelpers.isAsyncFunction(callback)) {
      return this.createIssue(context, node,
        `${methodName}() with async callback doesn't await - use for...of or Promise.all()`,
        {
          severity: 'error',
          suggestion: `Replace ${methodName}() with for...of loop or await Promise.all(array.map(...))`,
        }
      );
    }

    return null;
  }
}

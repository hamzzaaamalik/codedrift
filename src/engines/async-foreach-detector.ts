/**
 * Async ForEach Detector
 * Detects forEach/map/filter with async callbacks
 * Priority: CRITICAL (most common AI async mistake)
 *
 * This is THE #1 bug AI coding assistants introduce:
 * - AI generates: array.forEach(async (item) => { await process(item); })
 * - Reality: forEach doesn't await, operations run out of order
 * - Result: Race conditions, data corruption, lost updates
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse, ASTHelpers } from '../core/parser.js';
import * as ts from 'typescript';

export class AsyncForEachDetector extends BaseEngine {
  readonly name = 'async-foreach';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        const issue = this.checkArrayMethodWithAsyncCallback(node, context);
        if (issue) {
          issues.push(issue);
        }
      }
    });

    return issues;
  }

  /**
   * Check if array method (forEach/map/filter/reduce) is called with async callback
   * These methods don't await their callbacks!
   *
   * Confidence levels:
   * - High: Direct async callback with await inside (clear pattern)
   * - Medium: Async callback without explicit await (may be intentional)
   */
  private checkArrayMethodWithAsyncCallback(
    node: ts.CallExpression,
    context: AnalysisContext
  ): Issue | null {
    const { expression } = node;

    // Must be a method call (array.forEach)
    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const methodName = expression.name.text;

    // Check if it's an array method that doesn't await
    const nonAwaitingMethods = ['forEach', 'map', 'filter', 'reduce', 'reduceRight', 'some', 'every', 'find', 'findIndex', 'flatMap'];
    if (!nonAwaitingMethods.includes(methodName)) {
      return null;
    }

    // Check if there's a callback argument
    if (node.arguments.length === 0) {
      return null;
    }

    const callback = node.arguments[0];

    // Check if callback is an async function
    if (!ASTHelpers.isFunctionLike(callback)) {
      return null;
    }

    if (!ASTHelpers.isAsyncFunction(callback)) {
      return null;
    }

    // Special case: If parent is a safe Promise wrapper, it's correct usage
    if (this.isWithinSafePromiseWrapper(node)) {
      return null;
    }

    // Determine confidence based on callback content
    const hasAwaitInCallback = this.hasAwaitExpression(callback);
    const confidence = hasAwaitInCallback ? 'high' : 'medium';

    // Generate method-specific suggestions
    const suggestion = this.getSuggestion(methodName);

    return this.createIssue(
      context,
      node,
      `${methodName}() with async callback doesn't await - operations run out of order`,
      {
        severity: 'error',
        suggestion,
        confidence,
      }
    );
  }

  /**
   * Check if function contains await expressions
   */
  private hasAwaitExpression(node: ts.Node): boolean {
    let hasAwait = false;

    traverse(node, (child) => {
      if (ts.isAwaitExpression(child)) {
        hasAwait = true;
      }
    });

    return hasAwait;
  }

  /**
   * Check if this call is within a safe Promise wrapper
   * Examples:
   *   await Promise.all(array.map(async (item) => {...}))
   *   await Promise.allSettled(array.map(async (item) => {...}))
   *   await Promise.any(array.map(async (item) => {...}))
   *   await Promise.race(array.map(async (item) => {...}))
   *   Promise.all(array.map(...)).then(...)
   *   Promise.allSettled(array.map(...)).then(...)
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
          }
        }
      }

      current = current.parent;
    }

    return false;
  }

  /**
   * Get method-specific fix suggestion
   */
  private getSuggestion(methodName: string): string {
    switch (methodName) {
      case 'forEach':
        return 'Use for...of loop: for (const item of array) { await process(item); }';

      case 'map':
        return 'Use Promise.all: await Promise.all(array.map(async (item) => process(item)))';

      case 'filter':
        return 'Use Promise.all + filter: const results = await Promise.all(array.map(async (item) => ({ item, keep: await check(item) }))); const filtered = results.filter(r => r.keep).map(r => r.item);';

      case 'reduce':
        return 'Use for...of with accumulator: let acc = initial; for (const item of array) { acc = await process(acc, item); }';

      case 'some':
      case 'every':
        return 'Use for...of loop with early return: for (const item of array) { if (await check(item)) return true; } return false;';

      case 'find':
        return 'Use for...of loop: for (const item of array) { if (await predicate(item)) return item; } return undefined;';

      case 'findIndex':
        return 'Use for...of loop with index: for (let i = 0; i < array.length; i++) { if (await predicate(array[i])) return i; } return -1;';

      case 'flatMap':
        return 'Use Promise.all + flat: (await Promise.all(array.map(async (item) => fn(item)))).flat()';

      default:
        return 'Replace with for...of loop or await Promise.all(array.map(...))';
    }
  }
}

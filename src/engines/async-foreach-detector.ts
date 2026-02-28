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
    const nonAwaitingMethods = ['forEach', 'map', 'filter', 'reduce', 'reduceRight', 'some', 'every'];
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

    // Special case: If parent is awaited Promise.all(), it's correct usage
    if (this.isWithinAwaitedPromiseAll(node)) {
      return null;
    }

    // Generate method-specific suggestions
    const suggestion = this.getSuggestion(methodName);

    return this.createIssue(
      context,
      node,
      `${methodName}() with async callback doesn't await - operations run out of order`,
      {
        severity: 'error',
        suggestion,
      }
    );
  }

  /**
   * Check if this call is within an awaited Promise.all()
   * Example: await Promise.all(array.map(async (item) => {...}))
   */
  private isWithinAwaitedPromiseAll(node: ts.Node): boolean {
    let current = node.parent;

    while (current) {
      // Check if we're inside Promise.all()
      if (ts.isCallExpression(current)) {
        const { expression } = current;

        // Promise.all(...)
        if (ts.isPropertyAccessExpression(expression)) {
          const objectName = ts.isIdentifier(expression.expression)
            ? expression.expression.text
            : null;
          const methodName = expression.name.text;

          if (objectName === 'Promise' && methodName === 'all') {
            // Check if Promise.all is awaited
            const promiseAllParent = current.parent;
            if (promiseAllParent && ts.isAwaitExpression(promiseAllParent)) {
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

      default:
        return 'Replace with for...of loop or await Promise.all(array.map(...))';
    }
  }
}

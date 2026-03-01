/**
 * Empty Catch Block Detector
 * Detects try-catch blocks that silently swallow errors
 * Priority: HIGH (hides failures, makes debugging impossible)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';

export class EmptyCatchDetector extends BaseEngine {
  readonly name = 'empty-catch';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      if (ts.isTryStatement(node)) {
        const issue = this.checkEmptyCatch(node, context);
        if (issue) {
          issues.push(issue);
        }
      }
    });

    return issues;
  }

  /**
   * Check if try-catch has empty or ineffective error handling
   *
   * Confidence levels:
   * - High: Completely empty catch block or only comments (clear bug)
   * - High: Error variable declared but never used
   * - Medium: Only has silent return (may be intentional)
   * - Medium: Only console.log (developer may be aware)
   * - Low: Useless re-throw (may be placeholder for future logic)
   */
  private checkEmptyCatch(node: ts.TryStatement, context: AnalysisContext): Issue | null {
    const catchClause = node.catchClause;

    if (!catchClause) {
      return null;
    }

    const { block } = catchClause;

    // Completely empty block
    if (block.statements.length === 0) {
      return this.createIssue(context, catchClause, 'Empty catch block silently swallows errors', {
        severity: 'error',
        suggestion: 'Log error, re-throw, or handle appropriately',
        confidence: 'high',
      });
    }

    // Check if block is effectively empty (only comments)
    if (this.isEffectivelyEmpty(block)) {
      return this.createIssue(context, catchClause, 'Catch block only contains comments - errors swallowed', {
        severity: 'error',
        suggestion: 'Add error logging or handling logic',
        confidence: 'high',
      });
    }

    // Check for silent void return
    if (this.hasOnlySilentReturn(block)) {
      return this.createIssue(context, catchClause, 'Catch block only returns - error silently ignored', {
        severity: 'warning',
        suggestion: 'Log error before returning',
        confidence: 'medium',
      });
    }

    // Check for useless re-throw (no value added)
    if (this.hasUselessRethrow(block, catchClause)) {
      return this.createIssue(context, catchClause, 'Useless catch block - only re-throws without adding context', {
        severity: 'warning',
        suggestion: 'Remove catch or add error context/logging before re-throwing',
        confidence: 'low', // May be placeholder for future logic
      });
    }

    // Check if only console.log (not production-ready)
    if (this.hasOnlyConsoleLog(block)) {
      return this.createIssue(context, catchClause, 'Catch block only uses console.log - not production-ready', {
        severity: 'warning',
        suggestion: 'Use proper logger and error handling',
        confidence: 'medium',
      });
    }

    // Check if error is never used
    if (this.errorNotUsed(catchClause)) {
      return this.createIssue(context, catchClause, 'Error caught but never used or logged', {
        severity: 'warning',
        suggestion: 'Use error variable in logging or handling',
        confidence: 'high',
      });
    }

    return null;
  }

  /**
   * Check if block only contains comments (no actual code)
   */
  private isEffectivelyEmpty(block: ts.Block): boolean {
    // TypeScript AST doesn't include comments as statements
    // If there are no statements, the block is empty regardless of comments
    return block.statements.length === 0;
  }

  /**
   * Check if block only contains a return statement with no logging
   */
  private hasOnlySilentReturn(block: ts.Block): boolean {
    if (block.statements.length !== 1) {
      return false;
    }

    const statement = block.statements[0];

    // return; or return undefined;
    if (ts.isReturnStatement(statement)) {
      const returnExpr = statement.expression;
      if (!returnExpr || (ts.isIdentifier(returnExpr) && returnExpr.text === 'undefined')) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if error variable is never used in catch block
   */
  private errorNotUsed(catchClause: ts.CatchClause): boolean {
    const variableDecl = catchClause.variableDeclaration;

    // If no error variable declared (catch { }), it's intentional
    if (!variableDecl) {
      return false;
    }

    const errorName = variableDecl.name;
    if (!ts.isIdentifier(errorName)) {
      return false;
    }

    const errorVarName = errorName.text;
    let errorUsed = false;

    // Traverse catch block looking for error variable usage
    traverse(catchClause.block, (node) => {
      if (ts.isIdentifier(node) && node.text === errorVarName) {
        // Make sure it's not the declaration itself
        if (node !== errorName) {
          errorUsed = true;
        }
      }
    });

    // If error is not used AND block is simple (only console.log/return)
    if (!errorUsed && this.isSimpleLogging(catchClause.block)) {
      return true;
    }

    return false;
  }

  /**
   * Check if block only contains simple logging without error details
   */
  private isSimpleLogging(block: ts.Block): boolean {
    if (block.statements.length === 0) {
      return false;
    }

    // Check if all statements are console.log/error without using error variable
    for (const statement of block.statements) {
      if (ts.isExpressionStatement(statement)) {
        const expr = statement.expression;

        // Check for console.log/error calls
        if (ts.isCallExpression(expr)) {
          const { expression: callExpr } = expr;

          if (ts.isPropertyAccessExpression(callExpr)) {
            const objName = this.getObjectName(callExpr.expression);
            const methodName = callExpr.name.text;

            if (objName === 'console' && (methodName === 'log' || methodName === 'error')) {
              // Has console logging
              continue;
            }
          }
        }
      }

      // If any statement is not simple console.log, return false
      return false;
    }

    return true;
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
   * Check if catch block only re-throws without adding value
   */
  private hasUselessRethrow(block: ts.Block, catchClause: ts.CatchClause): boolean {
    if (block.statements.length !== 1) {
      return false;
    }

    const statement = block.statements[0];

    // Check for: throw e; (same error variable)
    if (ts.isThrowStatement(statement) && statement.expression) {
      const errorVar = catchClause.variableDeclaration;
      if (errorVar && ts.isIdentifier(errorVar.name) && ts.isIdentifier(statement.expression)) {
        // Same variable being thrown
        if (errorVar.name.text === statement.expression.text) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if catch block only uses console.log/error
   */
  private hasOnlyConsoleLog(block: ts.Block): boolean {
    if (block.statements.length === 0) {
      return false;
    }

    // Check if all statements are console.log/error calls
    for (const statement of block.statements) {
      if (!ts.isExpressionStatement(statement)) {
        return false;
      }

      const expr = statement.expression;
      if (!ts.isCallExpression(expr)) {
        return false;
      }

      if (ts.isPropertyAccessExpression(expr.expression)) {
        const objName = this.getObjectName(expr.expression.expression);
        const methodName = expr.expression.name.text;

        if (objName !== 'console') {
          return false;
        }

        const consoleMethods = ['log', 'error', 'warn', 'info', 'debug'];
        if (!consoleMethods.includes(methodName)) {
          return false;
        }
      } else {
        return false;
      }
    }

    // All statements are console calls - flag as not production-ready
    return true;
  }
}

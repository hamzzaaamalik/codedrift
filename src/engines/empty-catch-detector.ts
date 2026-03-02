/**
 * Empty Catch Block Detector
 * Detects try-catch blocks that silently swallow errors
 * Priority: HIGH (hides failures, makes debugging impossible)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import { isMigrationFile } from '../utils/file-utils.js';
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

    // Context-aware: Empty catch is common and acceptable in migration/seed files
    // for rollback scenarios
    const inMigration = isMigrationFile(context.filePath);

    // Completely empty block
    if (block.statements.length === 0) {
      // catch { } without an error binding is intentional optional-catch-binding (ES2019).
      // The developer explicitly chose not to bind the error variable, which signals
      // deliberate suppression. Only flag when a named variable was bound but ignored.
      const hasErrorBinding = catchClause.variableDeclaration !== undefined;
      if (!hasErrorBinding) {
        return null;
      }

      // Check if try block contains a known "probe" pattern (fs.access, JSON.parse, etc.)
      // These patterns intentionally use try-catch for control flow
      if (this.isExpectedErrorPattern(node)) {
        return null;
      }

      return this.createIssue(context, catchClause, 'Empty catch block silently swallows errors', {
        severity: inMigration ? 'info' : 'error', // Downgrade for migrations
        suggestion: inMigration
          ? 'Consider logging migration rollback errors for debugging'
          : 'Log error, re-throw, or handle appropriately',
        confidence: inMigration ? 'low' : 'high', // Downgrade confidence for migrations
      });
    }

    // Check if block is effectively empty (only comments)
    if (this.isEffectivelyEmpty(block)) {
      // Check if try block contains a known "probe" pattern (fs.access, JSON.parse, etc.)
      // These patterns intentionally use try-catch for control flow
      if (this.isExpectedErrorPattern(node)) {
        return null;
      }

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

    // Check if error is properly handled (logger, monitoring, passed to function, instanceof)
    if (this.isErrorHandled(catchClause)) {
      return null;
    }

    // Check if only console.log (not production-ready)
    // NOTE: This check must come AFTER errorNotUsed to avoid duplicate reporting
    // A catch block with console.log but unused error would match both conditions
    const hasConsoleOnly = this.hasOnlyConsoleLog(block);
    const errorUnused = this.errorNotUsed(catchClause);

    // Prioritize the more specific issue: unused error
    if (errorUnused) {
      return this.createIssue(context, catchClause, 'Error caught but never used or logged', {
        severity: 'warning',
        suggestion: 'Use error variable in logging or handling',
        confidence: 'high',
      });
    }

    if (hasConsoleOnly) {
      return this.createIssue(context, catchClause, 'Catch block only uses console.log - not production-ready', {
        severity: 'warning',
        suggestion: 'Use proper logger and error handling',
        confidence: 'medium',
      });
    }

    return null;
  }

  /**
   * Check if the error is properly handled in the catch block:
   * - Logger calls with error variable (logger.error(err), winston.error(err), etc.)
   * - Monitoring services (Sentry.captureException(err), newrelic.noticeError(err), etc.)
   * - Error passed to ANY function call as argument
   * - instanceof check on the error variable
   */
  private isErrorHandled(catchClause: ts.CatchClause): boolean {
    const variableDecl = catchClause.variableDeclaration;
    if (!variableDecl) return false;

    const errorName = variableDecl.name;
    if (!ts.isIdentifier(errorName)) return false;

    const errorVarName = errorName.text;
    let handled = false;

    traverse(catchClause.block, (node) => {
      if (handled) return;

      // Check if error variable is passed as argument to any function call
      if (ts.isCallExpression(node)) {
        for (const arg of node.arguments) {
          if (this.containsIdentifier(arg, errorVarName)) {
            handled = true;
            return;
          }
        }
      }

      // Check for instanceof check on the error variable
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword) {
        if (ts.isIdentifier(node.left) && node.left.text === errorVarName) {
          handled = true;
          return;
        }
      }

      // Check for throw with wrapping: throw new CustomError('msg', err)
      if (ts.isThrowStatement(node) && node.expression) {
        if (ts.isNewExpression(node.expression) && node.expression.arguments) {
          for (const arg of node.expression.arguments) {
            if (this.containsIdentifier(arg, errorVarName)) {
              handled = true;
              return;
            }
          }
        }
      }
    });

    return handled;
  }

  /**
   * Recursively check if a node contains a reference to an identifier
   */
  private containsIdentifier(node: ts.Node, identifierName: string): boolean {
    if (ts.isIdentifier(node) && node.text === identifierName) {
      return true;
    }
    let found = false;
    ts.forEachChild(node, (child) => {
      if (!found && this.containsIdentifier(child, identifierName)) {
        found = true;
      }
    });
    return found;
  }

  /**
   * Check if the try block contains a known "probe" or "check" pattern where
   * an empty catch is idiomatic. Examples:
   * - try { await fs.access(path); } catch { } — check if file exists
   * - try { JSON.parse(str); } catch { } — try-parse pattern
   * - try { require('optional-dep'); } catch { } — optional require
   */
  private isExpectedErrorPattern(tryStatement: ts.TryStatement): boolean {
    const tryBlock = tryStatement.tryBlock;
    // Only applies to simple try blocks (1-2 statements)
    if (tryBlock.statements.length === 0 || tryBlock.statements.length > 2) return false;

    let hasProbeCall = false;
    traverse(tryBlock, (node) => {
      if (hasProbeCall) return;
      if (ts.isCallExpression(node)) {
        const callText = node.expression.getText();
        const probePatterns = [
          /\bfs\.access/,
          /\bfs\.stat/,
          /\bfs\.lstat/,
          /\bfs\.readFile/,
          /\bfs\.readdir/,
          /\bfs\.mkdir/,
          /\bfs\.unlink/,
          /\bfs\.rmdir/,
          /\bJSON\.parse/,
          /\brequire\s*\(/,
          /\.exists\b/,
          /\.ping\b/,
          /\.connect\b/,
        ];
        if (probePatterns.some(p => p.test(callText))) {
          hasProbeCall = true;
        }
      }
    });
    return hasProbeCall;
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

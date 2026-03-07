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

      // Skip if catch block has an intentional suppression comment
      if (this.hasIntentionalSuppressionComment(block, context)) {
        return null;
      }

      // Batch processing: try-catch inside a loop without break/return/throw
      // is intentional continuation — process remaining items despite one failure
      const inLoop = this.isInsideLoop(node) && !this.hasExitStatement(block);

      return this.createIssue(context, catchClause, 'Empty catch block silently swallows errors', {
        severity: inMigration || inLoop ? 'info' : 'error',
        suggestion: inMigration
          ? 'Consider logging migration rollback errors for debugging'
          : inLoop
            ? 'Consider logging errors to avoid silent failures in batch processing'
            : 'Log error, re-throw, or handle appropriately',
        confidence: inMigration || inLoop ? 'low' : 'high',
      });
    }

    // Check if block is effectively empty (only comments)
    if (this.isEffectivelyEmpty(block)) {
      // Check if try block contains a known "probe" pattern (fs.access, JSON.parse, etc.)
      // These patterns intentionally use try-catch for control flow
      if (this.isExpectedErrorPattern(node)) {
        return null;
      }

      const inLoopEffEmpty = this.isInsideLoop(node) && !this.hasExitStatement(block);
      return this.createIssue(context, catchClause, 'Catch block only contains comments - errors swallowed', {
        severity: inLoopEffEmpty ? 'info' : 'error',
        suggestion: inLoopEffEmpty
          ? 'Consider logging errors to avoid silent failures in batch processing'
          : 'Add error logging or handling logic',
        confidence: inLoopEffEmpty ? 'low' : 'high',
      });
    }

    // Check for silent void return
    if (this.hasOnlySilentReturn(block)) {
      const inLoopReturn = this.isInsideLoop(node);
      return this.createIssue(context, catchClause, 'Catch block only returns - error silently ignored', {
        severity: inLoopReturn ? 'info' : 'warning',
        suggestion: inLoopReturn
          ? 'Consider logging errors to avoid silent failures in batch processing'
          : 'Log error before returning',
        confidence: inLoopReturn ? 'low' : 'medium',
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

    // Check for conditional error swallowing BEFORE isErrorHandled:
    // if (err instanceof X) { handle(err) } — no else/rethrow for other error types.
    // Must come first because isErrorHandled would return true (err IS passed to a function).
    if (this.hasConditionalSwallowing(block, catchClause)) {
      return this.createIssue(context, catchClause, 'Catch block only handles some error types - others silently swallowed', {
        severity: 'warning',
        suggestion: 'Add else clause to re-throw or log unhandled error types',
        confidence: 'medium',
      });
    }

    // Check if error is properly handled (logger, monitoring, passed to function, instanceof)
    if (this.isErrorHandled(catchClause)) {
      return null;
    }

    // Cleanup-only catch: catch block only calls cleanup/lifecycle methods
    // (close, dispose, destroy, release, etc.) — downgrade to warning/low
    if (this.isCleanupOnlyCatch(block)) {
      return this.createIssue(context, catchClause, 'Catch block only performs cleanup without logging the error', {
        severity: 'warning',
        suggestion: 'Consider logging the error before cleanup',
        confidence: 'low',
      });
    }

    // Fallback pattern: catch block contains a non-console function call,
    // indicating an alternative code path rather than empty swallowing.
    // e.g., try { useNewFeature(); } catch (e) { useOldFeature(); }
    if (this.hasFallbackCall(block)) {
      return this.createIssue(context, catchClause, 'Catch block uses fallback but does not log the original error', {
        severity: 'info',
        suggestion: 'Consider logging the caught error for debugging',
        confidence: 'low',
      });
    }

    // Check if only console.log (not production-ready)
    // NOTE: This check must come AFTER errorNotUsed to avoid duplicate reporting
    // A catch block with console.log but unused error would match both conditions
    const hasConsoleOnly = this.hasOnlyConsoleLog(block);
    const errorUnused = this.errorNotUsed(catchClause);

    // Skip if catch block contains an intentional suppression comment
    // (e.g. // silence, // ignore, /* empty */, // intentional, // expected, etc.)
    if (errorUnused && this.hasIntentionalSuppressionComment(block, context)) {
      return null;
    }

    // Prioritize the more specific issue: unused error
    if (errorUnused) {
      const inLoopUnused = this.isInsideLoop(node) && !this.hasExitStatement(block);
      return this.createIssue(context, catchClause, 'Error caught but never used or logged', {
        severity: inLoopUnused ? 'info' : 'warning',
        suggestion: inLoopUnused
          ? 'Consider logging errors to avoid silent failures in batch processing'
          : 'Use error variable in logging or handling',
        confidence: inLoopUnused ? 'low' : 'high',
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

      // Check if error variable is passed as argument to a meaningful handler function
      // Excludes: console.*, JSON.stringify, .toString() — these don't actually handle the error
      if (ts.isCallExpression(node)) {
        // Skip console.* calls — logging is not handling
        if (ts.isPropertyAccessExpression(node.expression)) {
          const obj = this.getObjectName(node.expression.expression);
          const method = node.expression.name.text;
          if (obj === 'console') return; // console.log(err) is NOT handling
          if (obj === 'JSON' && method === 'stringify') return; // JSON.stringify(err) is NOT handling
          if (method === 'toString') return; // err.toString() is NOT handling
        }
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
          // Filesystem probes
          /\bfs\.access/,
          /\bfs\.stat/,
          /\bfs\.lstat/,
          /\bfs\.readFile/,
          /\bfs\.readdir/,
          /\bfs\.mkdir/,
          /\bfs\.unlink/,
          /\bfs\.rmdir/,
          // Parse / require probes
          /\bJSON\.parse/,
          /\brequire\s*\(/,
          /\.exists\b/,
          /\.ping\b/,
          /\.connect\b/,
          // Redis operations
          /\bredis\.ping/,
          /\bredis\.connect/,
          /\bredis\.disconnect/,
          // Database connection probes
          /\bdb\.ping/,
          /\bdb\.connect/,
          /\bdb\.authenticate/,
          /\bdb\.sync/,
          // Socket / network probes
          /\bsocket\.connect/,
          /\bsocket\.close/,
          /\bdns\.lookup/,
          /\bdns\.resolve/,
          /\bnet\.connect/,
          /\bnet\.createConnection/,
          // HTTP health-check probes
          /\bhttp\.head/,
          /\bhttp\.options/,
          // ORM / database client connection probes
          /\bmongoose\.connect/,
          /\bsequelize\.authenticate/,
          /\bprisma\.\$connect/,
          // Cache operations (failure is non-critical)
          /\bcache\.get/,
          /\bcache\.set/,
          /\bcache\.del/,
        ];
        if (probePatterns.some(p => p.test(callText))) {
          hasProbeCall = true;
        }
      }
    });
    return hasProbeCall;
  }

  /**
   * Check if the catch block contains a comment indicating intentional error suppression.
   * Patterns: // silence, // ignore, // expected, // intentional, // no-op, // empty,
   * // fallback, // fallthrough, // optional, // non-critical, // best-effort, etc.
   */
  private hasIntentionalSuppressionComment(block: ts.Block, context: AnalysisContext): boolean {
    const blockStart = block.getStart();
    const blockEnd = block.getEnd();
    const blockText = context.sourceFile.text.slice(blockStart, blockEnd);

    // Check for any comment (// or /* */) containing a suppression keyword anywhere
    const commentPattern = /(?:\/\/[^\n]*|\/\*[\s\S]*?\*\/)/g;
    const suppressionKeywords = /\b(?:silence|silent|ignore|ignored|intentional|intentionally|expected|no-?op|fallback|fall[\s-]?through|optional|non-?critical|best[\s-]?effort|noop|suppress|swallow|continue|which\s+is\s+fine|safe\s+to\s+ignore|already\s+(?:handled|dispatched|logged|reported))\b|@todo\b/i;

    let match;
    while ((match = commentPattern.exec(blockText)) !== null) {
      const comment = match[0];
      if (suppressionKeywords.test(comment)) return true;
      // /* empty */ marker
      if (/\/\*\s*empty\s*\*\//.test(comment)) return true;
      // // ... (ellipsis placeholder)
      if (/^\/\/\s*\.{3}\s*$/.test(comment.trim())) return true;
      // Explanatory fallback: "if X fails", "use the base value", "falls back"
      if (/\b(?:if\s+[\w\s]+fails|use\s+the\s+\w+|falls?\s+back)\b/i.test(comment)) return true;
    }

    return false;
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

  /**
   * Check if catch block conditionally handles some error types but silently drops others.
   * Pattern: if (err instanceof SpecificError) { handle(err); }  ← no else/rethrow
   */
  private hasConditionalSwallowing(block: ts.Block, catchClause: ts.CatchClause): boolean {
    const variableDecl = catchClause.variableDeclaration;
    if (!variableDecl) return false;

    const errorName = variableDecl.name;
    if (!ts.isIdentifier(errorName)) return false;
    const errorVarName = errorName.text;

    // Look for if-statements that test the error type
    for (const stmt of block.statements) {
      if (!ts.isIfStatement(stmt)) continue;

      // Check if the condition involves instanceof on the error variable
      const hasInstanceofCheck = this.conditionHasInstanceof(stmt.expression, errorVarName);
      if (!hasInstanceofCheck) continue;

      // Only flag if the error variable is actually used inside the if-body
      // (i.e., there's real error handling for matched types, but others are dropped)
      // Use word-boundary check to avoid matching substrings (e.g., "error" containing "err")
      const thenText = stmt.thenStatement.getText();
      const errorVarRegex = new RegExp(`\\b${errorVarName}\\b`);
      if (!errorVarRegex.test(thenText)) continue;

      // If there's no else clause (or else-if chain that ends without else),
      // unmatched error types fall through silently
      if (!this.hasTerminalElse(stmt)) {
        // Make sure the code after the if doesn't re-throw or handle
        const ifIndex = block.statements.indexOf(stmt);
        const remainingStatements = block.statements.slice(ifIndex + 1);

        // If nothing after the if, unmatched errors are swallowed
        if (remainingStatements.length === 0) {
          return true;
        }

        // Check if remaining statements handle the error (throw, logger call, etc.)
        let handledAfter = false;
        for (const remaining of remainingStatements) {
          if (ts.isThrowStatement(remaining)) { handledAfter = true; break; }
          const text = remaining.getText();
          if (text.includes(errorVarName)) { handledAfter = true; break; }
        }
        if (!handledAfter) return true;
      }
    }

    return false;
  }

  /** Check if an expression contains `errorVar instanceof Something` */
  private conditionHasInstanceof(expr: ts.Expression, errorVarName: string): boolean {
    if (ts.isBinaryExpression(expr)) {
      if (expr.operatorToken.kind === ts.SyntaxKind.InstanceOfKeyword) {
        if (ts.isIdentifier(expr.left) && expr.left.text === errorVarName) {
          return true;
        }
      }
      // Check both sides of && or ||
      if (expr.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
          expr.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        return this.conditionHasInstanceof(expr.left, errorVarName) ||
               this.conditionHasInstanceof(expr.right, errorVarName);
      }
    }
    if (ts.isParenthesizedExpression(expr)) {
      return this.conditionHasInstanceof(expr.expression, errorVarName);
    }
    return false;
  }

  /** Check if an if-statement chain ends with a terminal else (not else-if without else) */
  private hasTerminalElse(stmt: ts.IfStatement): boolean {
    if (!stmt.elseStatement) return false;
    if (ts.isIfStatement(stmt.elseStatement)) {
      return this.hasTerminalElse(stmt.elseStatement);
    }
    // Has a plain else block
    return true;
  }

  /**
   * Check if the catch block contains a non-console function call (fallback pattern).
   * e.g., try { useNewFeature(); } catch (e) { useOldFeature(); }
   * The catch invokes a different function, indicating a fallback — not truly "empty".
   */
  private hasFallbackCall(block: ts.Block): boolean {
    for (const stmt of block.statements) {
      if (!ts.isExpressionStatement(stmt)) continue;
      const expr = stmt.expression;
      if (!ts.isCallExpression(expr)) continue;

      // Skip console.* calls — those aren't fallback behavior
      if (ts.isPropertyAccessExpression(expr.expression)) {
        const obj = this.getObjectName(expr.expression.expression);
        if (obj === 'console') continue;
      }

      // Any other function call is a fallback / alternative path
      return true;
    }
    return false;
  }

  /**
   * Check if the try-catch is inside a loop body (for, for..of, for..in, .forEach callback).
   * When a try-catch is inside a loop and the catch doesn't break/return/throw,
   * it's intentional continuation — process remaining items despite one failure.
   */
  private isInsideLoop(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      if (ts.isForStatement(current) ||
          ts.isForOfStatement(current) ||
          ts.isForInStatement(current) ||
          ts.isWhileStatement(current) ||
          ts.isDoStatement(current)) {
        return true;
      }

      // Check for .forEach() callback: the try-catch is inside an arrow/function
      // that is passed to a .forEach() call
      if ((ts.isArrowFunction(current) || ts.isFunctionExpression(current)) &&
          current.parent && ts.isCallExpression(current.parent)) {
        const callExpr = current.parent.expression;
        if (ts.isPropertyAccessExpression(callExpr) && callExpr.name.text === 'forEach') {
          return true;
        }
      }

      // Stop climbing at function boundaries (don't escape the enclosing function)
      if (ts.isFunctionDeclaration(current) ||
          ts.isMethodDeclaration(current) ||
          ts.isArrowFunction(current) ||
          ts.isFunctionExpression(current)) {
        // We already checked forEach above; if we hit a function boundary
        // without finding a loop, stop
        break;
      }

      current = current.parent;
    }
    return false;
  }

  /**
   * Check if the catch block contains a break, return, or throw statement.
   * Used to distinguish intentional-continuation catches from ones that exit the loop.
   */
  private hasExitStatement(block: ts.Block): boolean {
    let found = false;
    traverse(block, (node) => {
      if (found) return;
      if (ts.isBreakStatement(node) || ts.isReturnStatement(node) || ts.isThrowStatement(node)) {
        found = true;
      }
    });
    return found;
  }

  /**
   * Cleanup/lifecycle method names — if a catch block ONLY calls these,
   * it's a cleanup-only catch and should be downgraded.
   */
  private static readonly CLEANUP_METHODS = new Set([
    'close', 'dispose', 'destroy', 'release', 'cleanup',
    'shutdown', 'disconnect', 'end', 'abort', 'cancel',
    'unsubscribe', 'removeListener',
  ]);

  /**
   * Check if all statements in the catch block are calls to cleanup/lifecycle methods.
   */
  private isCleanupOnlyCatch(block: ts.Block): boolean {
    if (block.statements.length === 0) return false;

    for (const stmt of block.statements) {
      if (!ts.isExpressionStatement(stmt)) return false;
      const expr = stmt.expression;

      // Must be a call expression
      if (!ts.isCallExpression(expr)) return false;

      // Check if method name is a cleanup method
      let methodName: string | null = null;
      if (ts.isPropertyAccessExpression(expr.expression)) {
        methodName = expr.expression.name.text;
      } else if (ts.isIdentifier(expr.expression)) {
        methodName = expr.expression.text;
      }

      if (!methodName || !EmptyCatchDetector.CLEANUP_METHODS.has(methodName)) {
        return false;
      }
    }

    return true;
  }
}

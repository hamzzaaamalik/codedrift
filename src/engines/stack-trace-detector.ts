/**
 * Stack Trace Exposure Detector
 * Detects stack traces being exposed in API responses or logs with sensitive data
 * Priority: HIGH (security vulnerability)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';

export class StackTraceDetector extends BaseEngine {
  readonly name = 'stack-trace-exposure';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        // Check for HTTP response methods (res.json, res.send)
        const responseIssue = this.checkResponseCall(node, context);
        if (responseIssue) {
          issues.push(responseIssue);
        }

        // Check for logger calls with stack traces and sensitive data
        const loggerIssue = this.checkLoggerCall(node, context);
        if (loggerIssue) {
          issues.push(loggerIssue);
        }
      }
    });

    return issues;
  }

  /**
   * Check if a call expression is a response method with stack trace
   */
  private checkResponseCall(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    const { expression } = node;

    // Check for property access expressions like res.json() or response.send()
    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const methodName = expression.name.text;

    // Get the base object name (handles res.status().json() chains)
    const baseObjectName = this.getBaseObjectName(expression.expression);

    // Only check response methods
    if (!this.isResponseMethod(methodName, baseObjectName)) {
      return null;
    }

    // Check arguments for stack trace exposure
    if (node.arguments.length === 0) {
      return null;
    }

    const arg = node.arguments[0];
    const hasStackTrace = this.containsStackTrace(arg, context.sourceFile);

    if (hasStackTrace) {
      return this.createIssue(context, node, 'Stack trace exposed in API response', {
        severity: 'error',
        suggestion: 'Use generic error message. Log stack traces server-side only.',
      });
    }

    return null;
  }

  /**
   * Get the object name from an expression
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
   * Get the base object name, handling method chains like res.status().json()
   */
  private getBaseObjectName(expr: ts.Expression): string | null {
    // If it's a call expression (e.g., res.status()), get the object from that
    if (ts.isCallExpression(expr)) {
      if (ts.isPropertyAccessExpression(expr.expression)) {
        return this.getBaseObjectName(expr.expression.expression);
      }
    }

    // Otherwise use getObjectName
    return this.getObjectName(expr);
  }

  /**
   * Check if method is a response method
   */
  private isResponseMethod(methodName: string, objectName: string | null): boolean {
    // Common response methods
    const responseMethods = ['json', 'send', 'sendStatus', 'end'];

    if (!responseMethods.includes(methodName)) {
      return false;
    }

    // Common response object names
    const responseObjects = ['res', 'response', 'reply'];

    return objectName ? responseObjects.includes(objectName) : false;
  }

  /**
   * Check if argument contains stack trace reference
   */
  private containsStackTrace(arg: ts.Expression, _sourceFile: ts.SourceFile): boolean {
    let hasStack = false;

    const checkNode = (node: ts.Node) => {
      // Check for .stack property access
      if (ts.isPropertyAccessExpression(node)) {
        if (ts.isIdentifier(node.name) && node.name.text === 'stack') {
          // Check if it's error.stack, err.stack, e.stack
          const objName = this.getObjectName(node.expression);
          if (objName && this.isErrorVariableName(objName)) {
            hasStack = true;
          }
        }
      }

      // Check for object literal with stack property
      if (ts.isObjectLiteralExpression(node)) {
        for (const prop of node.properties) {
          if (ts.isPropertyAssignment(prop)) {
            // Check property name
            const propName = this.getPropertyName(prop.name);
            if (propName === 'stack') {
              hasStack = true;
            }

            // Check property value
            if (ts.isPropertyAccessExpression(prop.initializer)) {
              if (ts.isIdentifier(prop.initializer.name) && prop.initializer.name.text === 'stack') {
                hasStack = true;
              }
            }
          } else if (ts.isShorthandPropertyAssignment(prop)) {
            // Check for { stack } shorthand
            if (ts.isIdentifier(prop.name) && prop.name.text === 'stack') {
              hasStack = true;
            }
            // Check for { error } or { err } shorthand
            if (ts.isIdentifier(prop.name) && this.isErrorVariableName(prop.name.text)) {
              hasStack = true;
            }
          }
        }
      }

      // Check for spreading error object: { ...err }
      if (ts.isSpreadAssignment(node)) {
        const spreadExpr = node.expression;
        if (ts.isIdentifier(spreadExpr) && this.isErrorVariableName(spreadExpr.text)) {
          hasStack = true;
        }
      }

      // Check for direct error variable: res.json(err)
      if (ts.isIdentifier(node) && node === arg && this.isErrorVariableName(node.text)) {
        hasStack = true;
      }

      ts.forEachChild(node, checkNode);
    };

    checkNode(arg);
    return hasStack;
  }

  /**
   * Get property name from property name node
   */
  private getPropertyName(name: ts.PropertyName): string | null {
    if (ts.isIdentifier(name)) {
      return name.text;
    }
    if (ts.isStringLiteral(name)) {
      return name.text;
    }
    return null;
  }

  /**
   * Check if variable name is likely an error
   */
  private isErrorVariableName(name: string): boolean {
    const errorNames = ['error', 'err', 'e', 'exception', 'ex'];
    return errorNames.includes(name.toLowerCase());
  }

  /**
   * Check logger calls for stack traces with sensitive data
   */
  private checkLoggerCall(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    const { expression } = node;

    // Check for logger.error(), console.error(), log.error() etc.
    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const methodName = expression.name.text;
    const objectName = this.getObjectName(expression.expression);

    // Only check logging methods
    if (!this.isLoggerMethod(methodName, objectName)) {
      return null;
    }

    // Check if any argument contains both:
    // 1. Stack trace (err.stack)
    // 2. Potentially sensitive data (req.body, req.headers, etc.)
    let hasStackTrace = false;
    let hasSensitiveData = false;

    for (const arg of node.arguments) {
      if (this.containsStackTrace(arg, context.sourceFile)) {
        hasStackTrace = true;
      }
      if (this.containsSensitiveData(arg)) {
        hasSensitiveData = true;
      }
    }

    // Only flag if BOTH stack trace AND sensitive data present
    if (hasStackTrace && hasSensitiveData) {
      return this.createIssue(context, node,
        'Stack trace logged with sensitive request data',
        {
          severity: 'warning',
          suggestion: 'Avoid logging stack traces with req.body, req.headers, or other sensitive data',
        }
      );
    }

    return null;
  }

  /**
   * Check if method is a logger method
   */
  private isLoggerMethod(methodName: string, objectName: string | null): boolean {
    const logMethods = ['error', 'warn', 'log', 'info', 'debug'];
    if (!logMethods.includes(methodName)) {
      return false;
    }

    const logObjects = ['logger', 'log', 'console'];
    return objectName ? logObjects.includes(objectName) : false;
  }

  /**
   * Check if expression contains sensitive request data
   */
  private containsSensitiveData(arg: ts.Expression): boolean {
    let hasSensitive = false;

    const checkNode = (node: ts.Node) => {
      // Check for req.body, req.headers, req.cookies, etc.
      if (ts.isPropertyAccessExpression(node)) {
        const propName = node.name.text;
        const objName = this.getObjectName(node.expression);

        if (objName === 'req' || objName === 'request') {
          const sensitiveProps = ['body', 'headers', 'cookies', 'query', 'params', 'session'];
          if (sensitiveProps.includes(propName)) {
            hasSensitive = true;
          }
        }
      }

      ts.forEachChild(node, checkNode);
    };

    checkNode(arg);
    return hasSensitive;
  }
}

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
    // Track nodes already reported to avoid duplicates
    const reportedNodes = new Set<ts.Node>();

    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node)) {
        // Check for HTTP response methods (res.json, res.send)
        const responseIssue = this.checkResponseCall(node, context);
        if (responseIssue) {
          issues.push(responseIssue);
          reportedNodes.add(node);
        }

        // Check for logger calls with stack traces and sensitive data
        const loggerIssue = this.checkLoggerCall(node, context);
        if (loggerIssue) {
          issues.push(loggerIssue);
          reportedNodes.add(node);
        }
      }

      // Bottom-up traversal: find err.stack property accesses and classify by context
      if (ts.isPropertyAccessExpression(node) &&
          ts.isIdentifier(node.name) && node.name.text === 'stack' &&
          ts.isIdentifier(node.expression) &&
          this.isErrorVariableName(node.expression.text)) {
        // Skip if already reported via the call-expression path above
        if (this.isNodeInsideReportedNode(node, reportedNodes)) {
          return;
        }

        // Stack trace going to a logger — safe, server-side only
        if (this.isInLoggerContext(node)) {
          return;
        }

        // Stack trace going to an HTTP response — severity error
        if (this.isInResponseContext(node)) {
          const issue = this.createIssue(
            context,
            node,
            'Stack trace exposed in API response',
            {
              severity: 'error',
              suggestion: 'Use generic error message. Log stack traces server-side only.',
              confidence: 'high',
            }
          );
          if (issue) {
            issues.push(issue);
          }
        }
      }
    });

    return issues;
  }

  /**
   * Check if a node is nested inside any of the already-reported nodes
   */
  private isNodeInsideReportedNode(node: ts.Node, reportedNodes: Set<ts.Node>): boolean {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (reportedNodes.has(current)) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Walk up the AST to determine if a node is passed to an HTTP response method.
   * Detects: res.json({...}), res.send({...}), reply.send({...}), ctx.body = ..., res.body = ...
   */
  private isInResponseContext(node: ts.Node): boolean {
    const expressResParam = this.getExpressResponseParamName(node);
    let current = node.parent;
    let depth = 0;
    while (current && depth < 8) {
      // res.json({...}), res.send({...}), reply.send({...})
      if (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)) {
        const obj = current.expression.expression;
        const method = current.expression.name.text;
        const responseObjects = ['res', 'response', 'reply', 'ctx'];
        const responseMethods = ['json', 'send', 'end', 'write'];
        // Match hardcoded names OR the Express-detected param name
        if (ts.isIdentifier(obj) &&
            (responseObjects.includes(obj.text) || (expressResParam && obj.text === expressResParam)) &&
            responseMethods.includes(method)) {
          return true;
        }
      }
      // Assignment to ctx.body, res.body, response.data, etc.
      if (ts.isBinaryExpression(current) && ts.isPropertyAccessExpression(current.left)) {
        if (ts.isIdentifier(current.left.expression) &&
            ['ctx', 'res', 'response'].includes(current.left.expression.text) &&
            ['body', 'data'].includes(current.left.name.text)) {
          return true;
        }
      }
      current = current.parent;
      depth++;
    }
    return false;
  }

  /**
   * Walk up the AST to determine if a node is passed to a logger/console call.
   * Detects: logger.error({...}), console.log({...}), pino.info({...}), etc.
   */
  private isInLoggerContext(node: ts.Node): boolean {
    let current = node.parent;
    let depth = 0;
    while (current && depth < 6) {
      if (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)) {
        const obj = current.expression.expression;
        const loggerObjects = ['console', 'logger', 'log', 'winston', 'pino', 'bunyan', 'debug'];
        if (ts.isIdentifier(obj) && loggerObjects.includes(obj.text)) {
          return true;
        }
      }
      current = current.parent;
      depth++;
    }
    return false;
  }

  /**
   * Check if a call expression is a response method with stack trace
   *
   * Confidence levels:
   * - High: Direct error.stack or { stack } in response (clear exposure)
   * - High: Spreading error object in response { ...error }
   * - Medium: Passing error variable to response (may be serialized safely)
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

    // Also accept the Express handler's response parameter (any naming convention)
    const expressResParam = this.getExpressResponseParamName(node);

    // Only check response methods
    if (!this.isResponseMethod(methodName, baseObjectName) &&
        !(expressResParam && baseObjectName === expressResParam)) {
      return null;
    }

    // Check arguments for stack trace exposure
    if (node.arguments.length === 0) {
      return null;
    }

    const arg = node.arguments[0];
    const stackInfo = this.containsStackTrace(arg, context.sourceFile);

    if (stackInfo.hasStack) {
      // Determine confidence based on how explicit the stack trace exposure is
      let confidence: 'high' | 'medium' = 'high';

      // Lower confidence for simple error variable (may be custom error handler)
      if (stackInfo.isSimpleErrorVar && !stackInfo.hasExplicitStack) {
        confidence = 'medium';
      }

      return this.createIssue(context, node, 'Stack trace exposed in API response', {
        severity: 'error',
        suggestion: 'Use generic error message. Log stack traces server-side only.',
        confidence,
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
   * Returns info about the type of stack trace exposure
   */
  private containsStackTrace(arg: ts.Expression, _sourceFile: ts.SourceFile): {
    hasStack: boolean;
    hasExplicitStack: boolean;
    isSimpleErrorVar: boolean;
  } {
    let hasStack = false;
    let hasExplicitStack = false;
    let isSimpleErrorVar = false;

    const checkNode = (node: ts.Node) => {
      // Check for .stack property access
      if (ts.isPropertyAccessExpression(node)) {
        if (ts.isIdentifier(node.name) && node.name.text === 'stack') {
          // Check if it's error.stack, err.stack, e.stack
          const objName = this.getObjectName(node.expression);
          if (objName && this.isErrorVariableName(objName)) {
            hasStack = true;
            hasExplicitStack = true;
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
              hasExplicitStack = true;
            }

            // Check property value
            if (ts.isPropertyAccessExpression(prop.initializer)) {
              if (ts.isIdentifier(prop.initializer.name) && prop.initializer.name.text === 'stack') {
                hasStack = true;
                hasExplicitStack = true;
              }
            }
          } else if (ts.isShorthandPropertyAssignment(prop)) {
            // Check for { stack } shorthand
            if (ts.isIdentifier(prop.name) && prop.name.text === 'stack') {
              hasStack = true;
              hasExplicitStack = true;
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
          hasExplicitStack = true; // Spreading includes all properties including stack
        }
      }

      // Check for direct error variable: res.json(err)
      if (ts.isIdentifier(node) && node === arg && this.isErrorVariableName(node.text)) {
        hasStack = true;
        isSimpleErrorVar = true;
      }

      // Check for String(err) — converts error to string including stack
      if (ts.isCallExpression(node)) {
        const callExpr = node.expression;

        // String(err)
        if (ts.isIdentifier(callExpr) && callExpr.text === 'String' && node.arguments.length > 0) {
          const arg0 = node.arguments[0];
          if (ts.isIdentifier(arg0) && this.isErrorVariableName(arg0.text)) {
            hasStack = true;
            hasExplicitStack = true;
          }
        }

        // JSON.stringify(err)
        if (ts.isPropertyAccessExpression(callExpr) &&
            ts.isIdentifier(callExpr.expression) && callExpr.expression.text === 'JSON' &&
            callExpr.name.text === 'stringify' && node.arguments.length > 0) {
          const arg0 = node.arguments[0];
          if (ts.isIdentifier(arg0) && this.isErrorVariableName(arg0.text)) {
            hasStack = true;
            hasExplicitStack = true;
          }
        }
      }

      // Check for err.toString() — includes error message but not stack; medium confidence
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const propAccess = node.expression;
        if (propAccess.name.text === 'toString' &&
            ts.isIdentifier(propAccess.expression) &&
            this.isErrorVariableName(propAccess.expression.text)) {
          hasStack = true;
          // toString() is lower risk than explicit stack but still leaks internals
        }
      }

      ts.forEachChild(node, checkNode);
    };

    checkNode(arg);
    return { hasStack, hasExplicitStack, isSimpleErrorVar };
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
   *
   * Confidence: High when both stack trace and sensitive data are present
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
      const stackInfo = this.containsStackTrace(arg, context.sourceFile);
      if (stackInfo.hasStack) {
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
          confidence: 'high',
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

    const logObjects = ['logger', 'log', 'console', 'winston', 'pino', 'bunyan', 'debug'];
    return objectName ? logObjects.includes(objectName) : false;
  }

  /**
   * Detect the response parameter name for the enclosing Express-style route handler.
   * Express: app.get('/path', (req, res) => { ... }) — res is params[1]
   * Error handler: app.use((err, req, res, next) => { ... }) — res is params[2]
   *
   * @param node - Any node inside the handler function
   * @returns The variable name used as the response object, or null if not in an Express handler
   */
  private getExpressResponseParamName(node: ts.Node): string | null {
    let current = node.parent;
    while (current) {
      const isFunctionLike = (
        ts.isFunctionDeclaration(current) ||
        ts.isFunctionExpression(current) ||
        ts.isArrowFunction(current) ||
        ts.isMethodDeclaration(current)
      );
      if (isFunctionLike) {
        const fn = current as ts.FunctionLikeDeclaration;
        const fnParent = fn.parent;
        // Is this function directly passed as an argument to an Express-style route call?
        if (fnParent && ts.isCallExpression(fnParent) && this.isExpressRouteCall(fnParent)) {
          const params = fn.parameters;
          // Error handler: (err, req, res, next) — 4 params, res at index 2
          if (params.length === 4 && ts.isIdentifier(params[2].name)) {
            return params[2].name.text;
          }
          // Regular handler: (req, res[, next]) — 2-3 params, res at index 1
          if (params.length >= 2 && params.length < 4 && ts.isIdentifier(params[1].name)) {
            return params[1].name.text;
          }
        }
      }
      current = current.parent;
    }
    return null;
  }

  /**
   * Check if a call expression is an Express-style route registration call.
   * Matches: app.get(), app.post(), router.use(), app.all(), etc.
   */
  private isExpressRouteCall(call: ts.CallExpression): boolean {
    if (!ts.isPropertyAccessExpression(call.expression)) return false;
    const method = call.expression.name.text;
    const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'use', 'all', 'route', 'param'];
    return httpMethods.includes(method);
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

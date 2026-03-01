/**
 * Missing Input Validation Detector
 * Detects API routes that use request data without validation
 * Priority: CRITICAL (SQL injection, XSS, privilege escalation, data corruption)
 *
 * The #1 security issue in AI-generated code:
 * - AI generates API routes that directly use req.body/params/query
 * - No validation = instant security vulnerability
 * - Leads to: SQL injection, NoSQL injection, privilege escalation, XSS
 * - Example: AI generates: const { role } = req.body; await updateUser(id, { role });
 *   → Attacker sends { role: "admin" } → instant privilege escalation
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';

export class MissingInputValidationDetector extends BaseEngine {
  readonly name = 'missing-input-validation';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    // Find all route handlers
    const routeHandlers = this.findRouteHandlers(context);

    // Check each route handler for input validation
    for (const handler of routeHandlers) {
      const handlerIssues = this.checkHandlerValidation(handler, context);
      issues.push(...handlerIssues);
    }

    return issues;
  }

  /**
   * Find all route handler functions
   */
  private findRouteHandlers(context: AnalysisContext): RouteHandler[] {
    const handlers: RouteHandler[] = [];

    traverse(context.sourceFile, (node) => {
      // Express/Fastify style: app.get('/path', (req, res) => {})
      if (ts.isCallExpression(node)) {
        const handler = this.checkExpressStyleRoute(node);
        if (handler) {
          handlers.push(handler);
        }
      }

      // NestJS style: @Get('/path') \n async getUser(@Body() body: any) {}
      if (ts.isMethodDeclaration(node)) {
        const handler = this.checkNestJSStyleRoute(node);
        if (handler) {
          handlers.push(handler);
        }
      }
    });

    return handlers;
  }

  /**
   * Check for Express/Fastify style routes
   * app.get('/path', handler)
   * app.post('/path', middleware, handler)
   * router.put('/path', handler)
   */
  private checkExpressStyleRoute(node: ts.CallExpression): RouteHandler | null {
    const { expression } = node;

    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const objectName = this.getObjectName(expression.expression);
    const methodName = expression.name.text;

    // Check if it's a route method
    const routeMethods = ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'];
    if (!routeMethods.includes(methodName)) {
      return null;
    }

    // Check if object is a router/app
    const routerObjects = ['app', 'router', 'api', 'route', 'server', 'fastify'];
    if (!objectName || !routerObjects.some(r => objectName.toLowerCase().includes(r))) {
      return null;
    }

    // Get the handler function (last argument)
    if (node.arguments.length === 0) {
      return null;
    }

    const lastArg = node.arguments[node.arguments.length - 1];

    // Handler must be a function
    if (!ts.isArrowFunction(lastArg) && !ts.isFunctionExpression(lastArg)) {
      return null;
    }

    return {
      node: lastArg,
      framework: 'express',
      method: methodName,
      isAsync: this.isAsyncFunction(lastArg),
    };
  }

  /**
   * Check for NestJS style routes
   * @Get('/path') or @Post('/path')
   * async methodName(@Body() body, @Param() params) {}
   */
  private checkNestJSStyleRoute(node: ts.MethodDeclaration): RouteHandler | null {
    // Check for HTTP method decorators
    const decorators = ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined;
    if (!decorators || decorators.length === 0) {
      return null;
    }

    for (const decorator of decorators) {
      const expression = decorator.expression;

      // Check if decorator is @Get(), @Post(), etc.
      if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression)) {
        const decoratorName = expression.expression.text;
        const httpMethods = ['Get', 'Post', 'Put', 'Patch', 'Delete', 'All'];

        if (httpMethods.includes(decoratorName)) {
          return {
            node,
            framework: 'nestjs',
            method: decoratorName.toLowerCase(),
            isAsync: this.isAsyncFunction(node),
          };
        }
      }
    }

    return null;
  }

  /**
   * Check if handler has proper input validation
   *
   * Confidence levels:
   * - High: req.body or req.params without validation (clear vulnerability)
   * - Medium: req.query without validation (may be optional filters)
   * - Low: req.headers without validation (sometimes intentionally skipped)
   */
  private checkHandlerValidation(handler: RouteHandler, context: AnalysisContext): Issue[] {
    const issues: Issue[] = [];

    // Check if handler uses request data
    const requestDataUsage = this.findRequestDataUsage(handler.node);

    if (requestDataUsage.length === 0) {
      // No request data used, no validation needed
      return issues;
    }

    // Check if validation exists
    const hasValidation = this.hasValidationInHandler(handler.node, context);

    if (!hasValidation) {
      // Group usages by source type to avoid duplicates
      const sourceTypes = new Set<string>();
      const uniqueUsages: RequestDataUsage[] = [];

      for (const usage of requestDataUsage) {
        // Normalize source (remove "destructured" suffix for grouping)
        const normalizedSource = usage.source.replace(' (destructured)', '');

        if (!sourceTypes.has(normalizedSource)) {
          sourceTypes.add(normalizedSource);
          uniqueUsages.push(usage);
        }
      }

      // No validation found - flag once per source type
      for (const usage of uniqueUsages) {
        // Determine confidence based on usage type
        let confidence: 'high' | 'medium' | 'low' = 'high';

        // req.body without validation is highly likely to be a vulnerability
        if (usage.source.includes('req.body') || usage.source.includes('@Body()')) {
          confidence = 'high';
        }
        // req.params without validation is also high risk (IDOR, injection)
        else if (usage.source.includes('req.params') || usage.source.includes('@Param()')) {
          confidence = 'high';
        }
        // req.query might be used for optional filters (lower confidence)
        else if (usage.source.includes('req.query') || usage.source.includes('@Query()')) {
          confidence = 'medium';
        }
        // req.headers validation is sometimes intentionally skipped
        else if (usage.source.includes('req.headers')) {
          confidence = 'low';
        }

        const issue = this.createIssue(
          context,
          usage.node,
          `API route uses ${usage.source} without validation - ${usage.risk}`,
          {
            severity: 'error',
            suggestion: `Add input validation using joi, zod, yup, class-validator, or express-validator before using ${usage.source}`,
            confidence,
          }
        );
        if (issue) {
          issues.push(issue);
        }
      }
    }

    return issues;
  }

  /**
   * Find all request data usage in handler
   */
  private findRequestDataUsage(node: ts.Node): RequestDataUsage[] {
    const usages: RequestDataUsage[] = [];

    traverse(node, (n) => {
      // req.body
      if (ts.isPropertyAccessExpression(n)) {
        const text = n.getText();

        if (text.match(/req(uest)?\.body/)) {
          usages.push({
            node: n,
            source: 'req.body',
            risk: 'vulnerable to injection attacks and privilege escalation',
          });
        } else if (text.match(/req(uest)?\.params/)) {
          usages.push({
            node: n,
            source: 'req.params',
            risk: 'vulnerable to injection attacks and IDOR',
          });
        } else if (text.match(/req(uest)?\.query/)) {
          usages.push({
            node: n,
            source: 'req.query',
            risk: 'vulnerable to injection attacks',
          });
        } else if (text.match(/req(uest)?\.headers/)) {
          usages.push({
            node: n,
            source: 'req.headers',
            risk: 'vulnerable to header injection',
          });
        }
      }

      // Destructuring: const { email } = req.body
      if (ts.isVariableDeclaration(n) && n.initializer) {
        const initText = n.initializer.getText();

        if (initText.match(/req(uest)?\.body/)) {
          usages.push({
            node: n,
            source: 'req.body (destructured)',
            risk: 'vulnerable to injection attacks and privilege escalation',
          });
        } else if (initText.match(/req(uest)?\.params/)) {
          usages.push({
            node: n,
            source: 'req.params (destructured)',
            risk: 'vulnerable to injection attacks and IDOR',
          });
        } else if (initText.match(/req(uest)?\.query/)) {
          usages.push({
            node: n,
            source: 'req.query (destructured)',
            risk: 'vulnerable to injection attacks',
          });
        }
      }

      // NestJS parameter decorators: @Body() body, @Param() params
      if (ts.isParameter(n)) {
        const decorators = ts.canHaveDecorators(n) ? ts.getDecorators(n) : undefined;
        if (decorators && decorators.length > 0) {
          for (const decorator of decorators) {
            if (ts.isCallExpression(decorator.expression) && ts.isIdentifier(decorator.expression.expression)) {
              const decoratorName = decorator.expression.expression.text;

              if (decoratorName === 'Body') {
                usages.push({
                  node: n,
                  source: '@Body() decorator',
                  risk: 'vulnerable to injection attacks and privilege escalation',
                });
              } else if (decoratorName === 'Param') {
                usages.push({
                  node: n,
                  source: '@Param() decorator',
                  risk: 'vulnerable to injection attacks and IDOR',
                });
              } else if (decoratorName === 'Query') {
                usages.push({
                  node: n,
                  source: '@Query() decorator',
                  risk: 'vulnerable to injection attacks',
                });
              }
            }
          }
        }
      }
    });

    return usages;
  }

  /**
   * Check if handler has validation
   */
  private hasValidationInHandler(node: ts.Node, _context: AnalysisContext): boolean {
    let hasValidation = false;

    traverse(node, (n) => {
      // Check for validation library calls
      if (ts.isCallExpression(n)) {
        const text = n.getText();

        // Common validation patterns
        const validationPatterns = [
          // Joi
          /joi\.(object|validate|assert)/,
          /\.validate\(/,

          // Zod
          /z\.(object|string|number|array)/,
          /\.parse\(/,
          /\.safeParse\(/,

          // Yup
          /yup\.(object|string|number)/,

          // class-validator
          /validate\(/,
          /validateSync\(/,

          // express-validator
          /body\(['"].*['"]\)\..*\(/,
          /param\(['"].*['"]\)\..*\(/,
          /query\(['"].*['"]\)\..*\(/,
          /validationResult\(/,

          // ajv
          /ajv\.validate\(/,
          /ajv\.compile\(/,
        ];

        if (validationPatterns.some(pattern => pattern.test(text))) {
          hasValidation = true;
        }
      }

      // Check for TypeScript type guards with validation
      if (ts.isIfStatement(n)) {
        const condition = n.expression.getText();

        // Type narrowing patterns that include validation
        if (condition.match(/typeof.*===|instanceof|Array\.isArray|is[A-Z]/)) {
          hasValidation = true;
        }
      }

      // Check for validation decorators (NestJS with class-validator)
      if (ts.isParameter(n)) {
        const typeNode = n.type;
        if (typeNode) {
          // If parameter has a DTO type (not 'any'), assume validation exists
          const typeText = typeNode.getText();
          if (!typeText.includes('any') && /[A-Z]/.test(typeText[0])) {
            hasValidation = true;
          }
        }

        // Check for validation decorators on the DTO class
        // This is a simplification - ideally we'd check the actual DTO class
      }
    });

    // Check if there's middleware validation (harder to detect statically)
    // For now, we'll assume no middleware validation

    return hasValidation;
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
   * Check if function is async
   */
  private isAsyncFunction(node: ts.Node): boolean {
    if (ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) {
      const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
      return modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false;
    }
    return false;
  }
}

interface RouteHandler {
  node: ts.Node;
  framework: 'express' | 'nestjs';
  method: string;
  isAsync: boolean;
}

interface RequestDataUsage {
  node: ts.Node;
  source: string;
  risk: string;
}

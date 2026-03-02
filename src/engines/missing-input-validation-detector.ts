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

    // Check for global validation middleware (e.g. app.use(validate()))
    const hasGlobalValidation = this.hasGlobalValidationMiddleware(context.sourceFile);

    traverse(context.sourceFile, (node) => {
      // Express/Fastify style: app.get('/path', (req, res) => {})
      // Also matches Koa style: router.get('/path', (ctx) => {})
      if (ts.isCallExpression(node)) {
        const handler = this.checkExpressStyleRoute(node);
        if (handler) {
          if (hasGlobalValidation) {
            // Global validation middleware detected — skip flagging routes in this file
          } else {
            handlers.push(handler);
          }
          return;
        }

        const hapiHandler = this.checkHapiStyleRoute(node);
        if (hapiHandler) {
          if (hasGlobalValidation) {
            // Global validation middleware detected — skip flagging routes in this file
          } else {
            handlers.push(hapiHandler);
          }
          return;
        }
      }

      // NestJS style: @Get('/path') \n async getUser(@Body() body: any) {}
      if (ts.isMethodDeclaration(node)) {
        const handler = this.checkNestJSStyleRoute(node);
        if (handler) {
          if (hasGlobalValidation) {
            // Global validation middleware detected — skip flagging routes in this file
          } else {
            handlers.push(handler);
          }
        }
      }
    });

    return handlers;
  }

  /**
   * Check for Express/Fastify/Koa style routes
   * app.get('/path', handler)
   * app.post('/path', middleware, handler)
   * router.put('/path', handler)
   * router.get('/path', (ctx) => {})  // Koa
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

    // Detect framework by checking handler parameters
    const framework = this.detectHandlerFramework(lastArg);

    return {
      node: lastArg,
      framework,
      method: methodName,
      isAsync: this.isAsyncFunction(lastArg),
      routeCallExpression: node,
    };
  }

  /**
   * Detect framework from handler function parameters.
   * - (ctx) or (ctx, next) → Koa
   * - (request, h) → Hapi
   * - (req, res) or (request, response) → Express
   */
  private detectHandlerFramework(handler: ts.ArrowFunction | ts.FunctionExpression): 'express' | 'koa' | 'hapi' {
    if (handler.parameters.length >= 1) {
      const firstParam = handler.parameters[0];
      if (ts.isIdentifier(firstParam.name)) {
        const firstName = firstParam.name.text.toLowerCase();

        // Koa: (ctx) or (ctx, next)
        if (firstName === 'ctx') {
          return 'koa';
        }

        // Hapi: (request, h)
        if (handler.parameters.length >= 2 && firstName === 'request') {
          const secondParam = handler.parameters[1];
          if (ts.isIdentifier(secondParam.name) && secondParam.name.text.toLowerCase() === 'h') {
            return 'hapi';
          }
        }
      }
    }

    return 'express';
  }

  /**
   * Check for Hapi style routes
   * server.route({ method: 'GET', path: '/path', handler: (request, h) => {} })
   */
  private checkHapiStyleRoute(node: ts.CallExpression): RouteHandler | null {
    const { expression } = node;

    if (!ts.isPropertyAccessExpression(expression)) {
      return null;
    }

    const objectName = this.getObjectName(expression.expression);
    const methodName = expression.name.text;

    // Hapi uses server.route()
    if (methodName !== 'route') {
      return null;
    }

    // Check if object is a server
    if (!objectName || !/^(server|hapi)$/i.test(objectName)) {
      return null;
    }

    // First argument should be an object literal with method, path, handler
    if (node.arguments.length === 0) {
      return null;
    }

    const routeConfig = node.arguments[0];
    if (!ts.isObjectLiteralExpression(routeConfig)) {
      return null;
    }

    // Find handler property
    let handlerNode: ts.Node | null = null;
    let httpMethod = 'get';

    for (const prop of routeConfig.properties) {
      if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) {
        continue;
      }

      const propName = prop.name.text.toLowerCase();

      if (propName === 'handler') {
        if (ts.isArrowFunction(prop.initializer) || ts.isFunctionExpression(prop.initializer)) {
          handlerNode = prop.initializer;
        }
      }

      if (propName === 'method' && ts.isStringLiteral(prop.initializer)) {
        httpMethod = prop.initializer.text.toLowerCase();
      }
    }

    if (!handlerNode) {
      return null;
    }

    return {
      node: handlerNode,
      framework: 'hapi',
      method: httpMethod,
      isAsync: this.isAsyncFunction(handlerNode),
      routeCallExpression: node,
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

    // Check if validation middleware is present in the route registration
    if (handler.routeCallExpression && this.hasValidationMiddleware(handler.routeCallExpression)) {
      return issues;
    }

    // Check if handler uses request data
    const requestDataUsage = this.findRequestDataUsage(handler.node);

    if (requestDataUsage.length === 0) {
      // No request data used, no validation needed
      return issues;
    }

    // Check if validation exists
    const hasValidation = this.hasValidationInHandler(handler.node, context);

    if (!hasValidation) {
      // Collect fields that have per-field type checks (typeof, instanceof, Array.isArray)
      const validatedFields = this.getFieldsWithTypeChecks(handler.node);

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

        // Body/payload without validation is highly likely to be a vulnerability
        if (usage.source.includes('req.body') || usage.source.includes('@Body()') ||
            usage.source.includes('ctx.request.body') || usage.source.includes('request.payload')) {
          confidence = 'high';
        }
        // Params without validation is also high risk (IDOR, injection)
        else if (usage.source.includes('req.params') || usage.source.includes('@Param()') ||
                 usage.source.includes('ctx.params') || usage.source.includes('request.params')) {
          confidence = 'high';
        }
        // Query might be used for optional filters (lower confidence)
        else if (usage.source.includes('req.query') || usage.source.includes('@Query()') ||
                 usage.source.includes('ctx.query') || usage.source.includes('request.query')) {
          confidence = 'medium';
        }
        // Headers validation is sometimes intentionally skipped
        else if (usage.source.includes('req.headers')) {
          confidence = 'low';
        }

        // Collect specific field names accessed from this source
        const normalizedSource = usage.source.replace(' (destructured)', '');
        let sourceKey: 'body' | 'params' | 'query' | 'headers' | null = null;
        if (normalizedSource.startsWith('req.')) {
          sourceKey = normalizedSource.slice(4) as 'body' | 'params' | 'query' | 'headers';
        }
        // Koa/Hapi sources map to the same field collection keys
        else if (normalizedSource === 'ctx.request.body' || normalizedSource === 'request.payload') {
          sourceKey = 'body';
        } else if (normalizedSource === 'ctx.params' || normalizedSource === 'request.params') {
          sourceKey = 'params';
        } else if (normalizedSource === 'ctx.query' || normalizedSource === 'request.query') {
          sourceKey = 'query';
        }
        let fields = sourceKey ? this.collectFieldNames(handler.node, sourceKey) : [];
        // Remove fields that already have per-field type checks
        if (validatedFields.size > 0) {
          fields = fields.filter(f => !validatedFields.has(f));
        }
        // If all fields from this source are individually validated, skip the issue
        if (fields.length === 0 && sourceKey && this.collectFieldNames(handler.node, sourceKey).length > 0) {
          continue;
        }
        const fieldSuffix = fields.length > 0 ? `.{ ${fields.join(', ')} }` : '';

        const suggestion = fields.length > 0
          ? `${normalizedSource}${fieldSuffix} used without validation — add zod, joi, or yup to validate these fields before use`
          : `Add input validation using joi, zod, yup, class-validator, or express-validator before using ${normalizedSource}`;

        const issue = this.createIssue(
          context,
          usage.node,
          `API route uses ${usage.source} without validation - ${usage.risk}`,
          {
            severity: 'error',
            suggestion,
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
   * Check if a route registration call has validation middleware in its arguments.
   * Detects: express-validator chains, celebrate(), custom validateBody/validateRequest, etc.
   */
  private hasValidationMiddleware(routeCall: ts.CallExpression): boolean {
    const args = routeCall.arguments;
    if (args.length < 2) return false;

    // Middleware args: everything between first (path) and last (handler)
    const middlewareArgs = Array.from(args).slice(1, args.length - 1);

    const allMiddlewareNodes: ts.Node[] = [];
    for (const arg of middlewareArgs) {
      allMiddlewareNodes.push(arg);
      if (ts.isArrayLiteralExpression(arg)) {
        for (const element of arg.elements) {
          allMiddlewareNodes.push(element);
        }
      }
    }

    for (const middlewareNode of allMiddlewareNodes) {
      if (this.isValidationMiddlewareNode(middlewareNode)) {
        return true;
      }
    }

    return false;
  }

  /** Check if a single AST node represents a validation middleware. */
  private isValidationMiddlewareNode(node: ts.Node): boolean {
    if (ts.isCallExpression(node)) {
      return this.isValidationCallExpression(node);
    }
    if (ts.isIdentifier(node)) {
      return this.isValidationIdentifier(node.text);
    }
    return false;
  }

  /** Check if a call expression represents a validation middleware call. */
  private isValidationCallExpression(callExpr: ts.CallExpression): boolean {
    const callee = callExpr.expression;

    // Simple function call: celebrate({...}), validateBody(schema), body('email')
    if (ts.isIdentifier(callee)) {
      const name = callee.text;
      const expressValidatorFns = ['body', 'param', 'query', 'check', 'validationResult', 'checkSchema', 'oneOf'];
      if (expressValidatorFns.includes(name)) return true;
      if (name === 'celebrate') return true;
      if (this.isValidationIdentifier(name)) return true;
    }

    // Method chain: body('email').isEmail(), check('name').notEmpty().trim()
    if (ts.isPropertyAccessExpression(callee)) {
      const rootId = this.getRootCallOfChain(callExpr);
      if (rootId) {
        const rootName = rootId.text;
        const expressValidatorFns = ['body', 'param', 'query', 'check', 'validationResult', 'checkSchema', 'oneOf'];
        if (expressValidatorFns.includes(rootName)) return true;
        if (this.isValidationIdentifier(rootName)) return true;
      }
    }

    return false;
  }

  /** Walk a method chain to find the root callee identifier. */
  private getRootCallOfChain(node: ts.CallExpression): ts.Identifier | null {
    let current: ts.Expression = node.expression;
    let depth = 0;
    while (depth < 20) {
      depth++;
      if (ts.isIdentifier(current)) return current;
      if (ts.isPropertyAccessExpression(current)) { current = current.expression; continue; }
      if (ts.isCallExpression(current)) { current = current.expression; continue; }
      break;
    }
    return null;
  }

  /** Check if a function name looks like a validation middleware. */
  private isValidationIdentifier(name: string): boolean {
    const lower = name.toLowerCase();
    const knownNames = ['validatebody', 'validaterequest', 'validateparams', 'validatequery'];
    if (knownNames.includes(lower)) return true;
    // Match 'validate', 'validator', 'validation' but NOT 'invalidate', 'invalid'
    if ((lower.includes('validat') || lower.includes('validator')) && !lower.includes('invalid')) return true;
    if (lower.includes('sanitiz')) return true;
    return false;
  }

  /**
   * Find all request data usage in handler
   */
  private findRequestDataUsage(node: ts.Node): RequestDataUsage[] {
    const usages: RequestDataUsage[] = [];

    traverse(node, (n) => {
      // req.body / ctx.request.body / request.payload
      if (ts.isPropertyAccessExpression(n)) {
        const text = n.getText();

        // Express/Fastify body
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
        } else if (text.match(/req(uest)?\.files?(?!\w)/)) {
          usages.push({
            node: n,
            source: 'req.files',
            risk: 'vulnerable to unrestricted file upload',
          });
        }
        // Koa context patterns
        else if (text.match(/ctx\.request\.body/)) {
          usages.push({
            node: n,
            source: 'ctx.request.body',
            risk: 'vulnerable to injection attacks and privilege escalation',
          });
        } else if (text.match(/ctx\.params/)) {
          usages.push({
            node: n,
            source: 'ctx.params',
            risk: 'vulnerable to injection attacks and IDOR',
          });
        } else if (text.match(/ctx\.query/)) {
          usages.push({
            node: n,
            source: 'ctx.query',
            risk: 'vulnerable to injection attacks',
          });
        } else if (text.match(/ctx\.request\.files?(?!\w)/)) {
          usages.push({
            node: n,
            source: 'ctx.request.files',
            risk: 'vulnerable to unrestricted file upload',
          });
        }
        // Hapi request patterns
        else if (text.match(/^request\.payload/)) {
          usages.push({
            node: n,
            source: 'request.payload',
            risk: 'vulnerable to injection attacks and privilege escalation',
          });
        } else if (text.match(/^request\.params/)) {
          usages.push({
            node: n,
            source: 'request.params',
            risk: 'vulnerable to injection attacks and IDOR',
          });
        } else if (text.match(/^request\.query/)) {
          usages.push({
            node: n,
            source: 'request.query',
            risk: 'vulnerable to injection attacks',
          });
        }
      }

      // Destructuring: const { email } = req.body / ctx.request.body / request.payload
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
        // Koa destructuring
        else if (initText.match(/ctx\.request\.body/)) {
          usages.push({
            node: n,
            source: 'ctx.request.body (destructured)',
            risk: 'vulnerable to injection attacks and privilege escalation',
          });
        } else if (initText.match(/ctx\.params/)) {
          usages.push({
            node: n,
            source: 'ctx.params (destructured)',
            risk: 'vulnerable to injection attacks and IDOR',
          });
        } else if (initText.match(/ctx\.query/)) {
          usages.push({
            node: n,
            source: 'ctx.query (destructured)',
            risk: 'vulnerable to injection attacks',
          });
        }
        // Hapi destructuring
        else if (initText.match(/request\.payload/)) {
          usages.push({
            node: n,
            source: 'request.payload (destructured)',
            risk: 'vulnerable to injection attacks and privilege escalation',
          });
        } else if (initText.match(/request\.params/)) {
          usages.push({
            node: n,
            source: 'request.params (destructured)',
            risk: 'vulnerable to injection attacks and IDOR',
          });
        } else if (initText.match(/request\.query/)) {
          usages.push({
            node: n,
            source: 'request.query (destructured)',
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

      // Spread operator: db.create({...req.body}), { ...req.params }
      if (ts.isSpreadAssignment(n) || ts.isSpreadElement(n)) {
        const spreadText = n.expression.getText();
        if (spreadText.match(/req(uest)?\.body/)) {
          usages.push({
            node: n,
            source: 'req.body (spread)',
            risk: 'mass assignment — all fields passed to DB/logic without filtering',
          });
        } else if (spreadText.match(/req(uest)?\.params/)) {
          usages.push({
            node: n,
            source: 'req.params (spread)',
            risk: 'mass assignment — all request params spread without filtering',
          });
        } else if (spreadText.match(/req(uest)?\.query/)) {
          usages.push({
            node: n,
            source: 'req.query (spread)',
            risk: 'mass assignment — all query params spread without filtering',
          });
        }
        // Koa spread
        else if (spreadText.match(/ctx\.request\.body/)) {
          usages.push({
            node: n,
            source: 'ctx.request.body (spread)',
            risk: 'mass assignment — all fields passed to DB/logic without filtering',
          });
        } else if (spreadText.match(/ctx\.params/)) {
          usages.push({
            node: n,
            source: 'ctx.params (spread)',
            risk: 'mass assignment — all request params spread without filtering',
          });
        } else if (spreadText.match(/ctx\.query/)) {
          usages.push({
            node: n,
            source: 'ctx.query (spread)',
            risk: 'mass assignment — all query params spread without filtering',
          });
        }
        // Hapi spread
        else if (spreadText.match(/request\.payload/)) {
          usages.push({
            node: n,
            source: 'request.payload (spread)',
            risk: 'mass assignment — all fields passed to DB/logic without filtering',
          });
        } else if (spreadText.match(/request\.params/)) {
          usages.push({
            node: n,
            source: 'request.params (spread)',
            risk: 'mass assignment — all request params spread without filtering',
          });
        } else if (spreadText.match(/request\.query/)) {
          usages.push({
            node: n,
            source: 'request.query (spread)',
            risk: 'mass assignment — all query params spread without filtering',
          });
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
   * Collect field names that have per-field type checks (typeof, instanceof, Array.isArray).
   * Returns a set of field names that are individually validated.
   */
  private getFieldsWithTypeChecks(handlerNode: ts.Node): Set<string> {
    const validatedFields = new Set<string>();

    traverse(handlerNode, (n) => {
      if (ts.isIfStatement(n)) {
        const condText = n.expression.getText();

        // Match: typeof req.body.fieldName === 'string'
        // Match: typeof fieldName === 'string' (where fieldName is destructured from req.body)
        // Also matches Koa (ctx.request.body, ctx.params, ctx.query) and Hapi (request.payload, request.params, request.query)
        const typeofMatch = condText.match(/typeof\s+(?:req(?:uest)?\.(?:body|params|query)\.|ctx\.(?:request\.body|params|query)\.|request\.(?:payload|params|query)\.)?(\w+)\s*===\s*/);
        if (typeofMatch) {
          validatedFields.add(typeofMatch[1]);
        }

        // Match: Array.isArray(req.body.fieldName) or Array.isArray(fieldName)
        const arrayMatch = condText.match(/Array\.isArray\((?:req(?:uest)?\.(?:body|params|query)\.|ctx\.(?:request\.body|params|query)\.|request\.(?:payload|params|query)\.)?(\w+)\)/);
        if (arrayMatch) {
          validatedFields.add(arrayMatch[1]);
        }

        // Match: req.body.fieldName instanceof Something
        const instanceofMatch = condText.match(/(?:req(?:uest)?\.(?:body|params|query)\.|ctx\.(?:request\.body|params|query)\.|request\.(?:payload|params|query)\.)?(\w+)\s+instanceof\s+/);
        if (instanceofMatch) {
          validatedFields.add(instanceofMatch[1]);
        }
      }
    });

    return validatedFields;
  }

  /**
   * Collect the specific field names accessed from a request source within a handler.
   * e.g. req.body.amount, req.body.currency → ['amount', 'currency']
   *      const { amount, currency } = req.body → ['amount', 'currency']
   */
  private collectFieldNames(
    handlerNode: ts.Node,
    sourceKey: 'body' | 'params' | 'query' | 'headers',
  ): string[] {
    const fields = new Set<string>();

    traverse(handlerNode, (n) => {
      // req.body.fieldName — the outer PropertyAccess whose object is req.body
      if (ts.isPropertyAccessExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
        const inner = n.expression;

        // Express: req.body.fieldName, req.params.fieldName
        if (
          inner.name.text === sourceKey &&
          ts.isIdentifier(inner.expression) &&
          inner.expression.text.match(/^req(uest)?$/)
        ) {
          fields.add(n.name.text);
        }

        // Koa: ctx.params.fieldName, ctx.query.fieldName
        if (
          (sourceKey === 'params' || sourceKey === 'query') &&
          inner.name.text === sourceKey &&
          ts.isIdentifier(inner.expression) &&
          inner.expression.text === 'ctx'
        ) {
          fields.add(n.name.text);
        }

        // Hapi: request.params.fieldName, request.query.fieldName
        if (
          (sourceKey === 'params' || sourceKey === 'query') &&
          inner.name.text === sourceKey &&
          ts.isIdentifier(inner.expression) &&
          inner.expression.text === 'request'
        ) {
          fields.add(n.name.text);
        }

        // Hapi: request.payload.fieldName (maps to sourceKey 'body')
        if (
          sourceKey === 'body' &&
          inner.name.text === 'payload' &&
          ts.isIdentifier(inner.expression) &&
          inner.expression.text === 'request'
        ) {
          fields.add(n.name.text);
        }
      }

      // Koa: ctx.request.body.fieldName — 3-level deep PropertyAccess
      if (
        sourceKey === 'body' &&
        ts.isPropertyAccessExpression(n) &&
        ts.isPropertyAccessExpression(n.expression)
      ) {
        const mid = n.expression; // ctx.request.body
        if (
          mid.name.text === 'body' &&
          ts.isPropertyAccessExpression(mid.expression) &&
          mid.expression.name.text === 'request' &&
          ts.isIdentifier(mid.expression.expression) &&
          mid.expression.expression.text === 'ctx'
        ) {
          fields.add(n.name.text);
        }
      }

      // const { field1, field2 } = req.body / ctx.request.body / request.payload
      if (
        ts.isVariableDeclaration(n) &&
        n.initializer &&
        ts.isObjectBindingPattern(n.name)
      ) {
        const initText = n.initializer.getText();
        let matches = false;

        // Express: req.body, req.params, etc.
        if (initText.match(new RegExp(`req(uest)?\\.${sourceKey}`))) {
          matches = true;
        }
        // Koa: ctx.params, ctx.query
        if ((sourceKey === 'params' || sourceKey === 'query') && initText.match(new RegExp(`ctx\\.${sourceKey}`))) {
          matches = true;
        }
        // Koa: ctx.request.body
        if (sourceKey === 'body' && initText.match(/ctx\.request\.body/)) {
          matches = true;
        }
        // Hapi: request.params, request.query
        if ((sourceKey === 'params' || sourceKey === 'query') && initText.match(new RegExp(`request\\.${sourceKey}`))) {
          matches = true;
        }
        // Hapi: request.payload
        if (sourceKey === 'body' && initText.match(/request\.payload/)) {
          matches = true;
        }

        if (matches) {
          for (const element of n.name.elements) {
            if (ts.isIdentifier(element.name)) {
              fields.add(element.name.text);
            }
          }
        }
      }
    });

    return [...fields];
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
   * Check if file-level global validation middleware is applied.
   * Detects patterns like:
   *   app.use(validate())
   *   app.use(joi.validate())
   *   app.use(celebrate())
   *   app.use(expressValidator())
   * When detected, routes in the same file likely have validation applied globally.
   */
  private hasGlobalValidationMiddleware(sourceFile: ts.SourceFile): boolean {
    let hasGlobal = false;

    traverse(sourceFile, (node) => {
      if (hasGlobal) return;

      // Look for app.use() or router.use() calls
      if (!ts.isCallExpression(node)) return;
      const { expression } = node;
      if (!ts.isPropertyAccessExpression(expression)) return;
      if (expression.name.text !== 'use') return;

      const objName = this.getObjectName(expression.expression);
      if (!objName || !/^(app|router|server|api|fastify)$/i.test(objName)) return;

      // Check if any argument is a validation middleware call or identifier
      for (const arg of node.arguments) {
        if (this.isValidationMiddlewareNode(arg)) {
          hasGlobal = true;
          return;
        }

        // Also check for known global validation patterns by text
        const argText = arg.getText().toLowerCase();
        const globalValidationPatterns = [
          'celebrate',
          'joi.validate',
          'express-validator',
          'expressvalidator',
        ];
        if (globalValidationPatterns.some(p => argText.includes(p))) {
          hasGlobal = true;
          return;
        }
      }
    });

    return hasGlobal;
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
  framework: 'express' | 'nestjs' | 'koa' | 'hapi';
  method: string;
  isAsync: boolean;
  /** The full route registration call expression (e.g. app.post('/path', ...middleware, handler)) */
  routeCallExpression?: ts.CallExpression;
}

interface RequestDataUsage {
  node: ts.Node;
  source: string;
  risk: string;
}

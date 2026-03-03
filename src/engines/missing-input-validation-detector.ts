/**
 * Missing Input Validation Detector
 * Detects API routes that use request data without validation
 * Priority: CRITICAL (SQL injection, XSS, privilege escalation, data corruption)
 *
 * Three detection dimensions:
 *   1. What user data is accessed? (body, params, query, headers, cookies, files)
 *   2. Is there validation? (middleware, inline library, manual typeof/allowlist)
 *   3. Is validation complete? (per-field coverage tracking)
 *
 * The #1 security issue in AI-generated code:
 * - AI generates API routes that directly use req.body/params/query
 * - No validation = instant security vulnerability
 * - Leads to: SQL injection, NoSQL injection, privilege escalation, XSS
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';

export class MissingInputValidationDetector extends BaseEngine {
  readonly name = 'missing-input-validation';

  // ──────────────────────── Data Structures ────────────────────────

  /** Sensitive field names that enable privilege escalation if unvalidated */
  private static readonly SENSITIVE_FIELDS = new Set([
    'role', 'roles', 'permission', 'permissions', 'isadmin', 'is_admin',
    'admin', 'password', 'passwordhash', 'password_hash', 'secret',
    'token', 'apikey', 'api_key', 'creditcard', 'credit_card', 'ssn',
    'accesslevel', 'access_level', 'isverified', 'is_verified',
    'issuperadmin', 'is_superadmin', 'privilege', 'privileges',
  ]);

  /** Whole-shape validation methods — when called on req.body, ALL fields are covered */
  private static readonly WHOLE_SHAPE_METHODS = new Set([
    'parse', 'safeParse', 'parseAsync', 'validate', 'validateSync',
    'validateAsync', 'isValid', 'decode', 'create', 'assert',
    'plainToClass', 'plainToInstance',
  ]);

  /** Database write operations */
  private static readonly DB_WRITE_OPS = new Set([
    'create', 'insert', 'insertone', 'insertmany', 'save', 'update',
    'updateone', 'updatemany', 'upsert', 'bulkcreate', 'bulkwrite',
    'findbyidandupdate', 'findoneandupdate', 'replaceone',
    'putitem', 'updateitem', 'set', 'add', 'push',
  ]);

  /** Database read operations */
  private static readonly DB_READ_OPS = new Set([
    'find', 'findone', 'findbyid', 'findbypk', 'findunique', 'findfirst',
    'findall', 'findmany', 'findoneorfail', 'select', 'where', 'query',
    'getitem', 'get', 'fetch', 'count',
  ]);

  /** Logging/utility functions — info severity */
  private static readonly LOGGING_PATTERNS = /\b(console|logger|log|winston|pino|bunyan)\./;

  /** File system operation patterns — error severity */
  private static readonly FILE_OP_PATTERNS = /\b(fs\.(writefile|writefilesync|appendfile|appendfilesync|rename|renamesync|copyfile|copyfilesync|createwritestream)|path\.join|mv|move)\(/;

  /** Queue/messaging patterns — warning severity */
  private static readonly QUEUE_PATTERNS = /\.(add|publish|send|emit|enqueue|produce|dispatch)\(/;

  // ──────────────────────── Main Analyze ────────────────────────

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    // Detect validation library imports for context-sensitive detection
    const validationImports = this.detectValidationImports(context.sourceFile);

    // Find all route handlers
    const routeHandlers = this.findRouteHandlers(context);

    // Check each route handler for input validation
    for (const handler of routeHandlers) {
      const handlerIssues = this.checkHandlerValidation(handler, context, validationImports);
      issues.push(...handlerIssues);
    }

    return issues;
  }

  // ──────────────────── Route Handler Detection ────────────────────

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
          if (!hasGlobalValidation) handlers.push(handler);
          return;
        }

        const hapiHandler = this.checkHapiStyleRoute(node);
        if (hapiHandler) {
          if (!hasGlobalValidation) handlers.push(hapiHandler);
          return;
        }

        // tRPC: publicProcedure.input(schema).mutation(handler)
        const trpcHandler = this.checkTRPCRoute(node);
        if (trpcHandler) {
          if (!hasGlobalValidation) handlers.push(trpcHandler);
          return;
        }
      }

      // NestJS style: @Get('/path') — but skip GraphQL resolvers
      if (ts.isMethodDeclaration(node)) {
        if (this.isGraphQLResolver(node)) return; // GraphQL has built-in type validation
        const handler = this.checkNestJSStyleRoute(node);
        if (handler) {
          if (!hasGlobalValidation) handlers.push(handler);
        }
      }
    });

    return handlers;
  }

  /**
   * Check for Express/Fastify/Koa style routes
   */
  private checkExpressStyleRoute(node: ts.CallExpression): RouteHandler | null {
    const { expression } = node;

    if (!ts.isPropertyAccessExpression(expression)) return null;

    const objectName = this.getObjectName(expression.expression);
    const methodName = expression.name.text;

    const routeMethods = ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'];
    if (!routeMethods.includes(methodName)) return null;

    const routerObjects = ['app', 'router', 'api', 'route', 'server', 'fastify', 'instance'];
    if (!objectName || !routerObjects.some(r => objectName.toLowerCase().includes(r))) return null;

    if (node.arguments.length === 0) return null;

    const lastArg = node.arguments[node.arguments.length - 1];
    if (!ts.isArrowFunction(lastArg) && !ts.isFunctionExpression(lastArg)) return null;

    const framework = this.detectHandlerFramework(lastArg);

    // Check for Fastify schema validation in route options
    let hasSchemaValidation = false;
    if (node.arguments.length >= 2) {
      for (let i = 0; i < node.arguments.length - 1; i++) {
        const arg = node.arguments[i];
        if (ts.isObjectLiteralExpression(arg)) {
          if (this.hasFastifySchemaValidation(arg)) {
            hasSchemaValidation = true;
          }
        }
      }
    }

    return {
      node: lastArg,
      framework,
      method: methodName,
      isAsync: this.isAsyncFunction(lastArg),
      routeCallExpression: node,
      hasSchemaValidation,
    };
  }

  /**
   * Detect framework from handler function parameters.
   */
  private detectHandlerFramework(handler: ts.ArrowFunction | ts.FunctionExpression): 'express' | 'koa' | 'hapi' {
    if (handler.parameters.length >= 1) {
      const firstParam = handler.parameters[0];
      if (ts.isIdentifier(firstParam.name)) {
        const firstName = firstParam.name.text.toLowerCase();
        if (firstName === 'ctx') return 'koa';
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
   */
  private checkHapiStyleRoute(node: ts.CallExpression): RouteHandler | null {
    const { expression } = node;
    if (!ts.isPropertyAccessExpression(expression)) return null;

    const objectName = this.getObjectName(expression.expression);
    const methodName = expression.name.text;
    if (methodName !== 'route') return null;
    if (!objectName || !/^(server|hapi)$/i.test(objectName)) return null;
    if (node.arguments.length === 0) return null;

    const routeConfig = node.arguments[0];
    if (!ts.isObjectLiteralExpression(routeConfig)) return null;

    let handlerNode: ts.Node | null = null;
    let httpMethod = 'get';
    let hasSchemaValidation = false;

    for (const prop of routeConfig.properties) {
      if (!ts.isPropertyAssignment(prop) || !ts.isIdentifier(prop.name)) continue;
      const propName = prop.name.text.toLowerCase();

      if (propName === 'handler') {
        if (ts.isArrowFunction(prop.initializer) || ts.isFunctionExpression(prop.initializer)) {
          handlerNode = prop.initializer;
        }
      }
      if (propName === 'method' && ts.isStringLiteral(prop.initializer)) {
        httpMethod = prop.initializer.text.toLowerCase();
      }
      // Hapi validate config: options.validate.payload
      if (propName === 'options' && ts.isObjectLiteralExpression(prop.initializer)) {
        if (this.hasHapiValidateConfig(prop.initializer)) {
          hasSchemaValidation = true;
        }
      }
      // Direct validate property
      if (propName === 'validate' && ts.isObjectLiteralExpression(prop.initializer)) {
        hasSchemaValidation = true;
      }
    }

    if (!handlerNode) return null;

    return {
      node: handlerNode,
      framework: 'hapi',
      method: httpMethod,
      isAsync: this.isAsyncFunction(handlerNode),
      routeCallExpression: node,
      hasSchemaValidation,
    };
  }

  /**
   * Check for NestJS style routes
   */
  private checkNestJSStyleRoute(node: ts.MethodDeclaration): RouteHandler | null {
    const decorators = ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined;
    if (!decorators || decorators.length === 0) return null;

    // Check for ValidationPipe
    let hasValidationPipe = false;
    for (const decorator of decorators) {
      const expr = decorator.expression;
      if (ts.isCallExpression(expr) && ts.isIdentifier(expr.expression)) {
        if (expr.expression.text === 'UsePipes') {
          const argText = expr.getText();
          if (argText.includes('ValidationPipe')) {
            hasValidationPipe = true;
          }
        }
      }
    }

    for (const decorator of decorators) {
      const expression = decorator.expression;
      if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression)) {
        const decoratorName = expression.expression.text;
        const httpMethods = ['Get', 'Post', 'Put', 'Patch', 'Delete', 'All'];
        if (httpMethods.includes(decoratorName)) {
          return {
            node,
            framework: 'nestjs',
            method: decoratorName.toLowerCase(),
            isAsync: this.isAsyncFunction(node),
            hasSchemaValidation: hasValidationPipe,
          };
        }
      }
    }

    return null;
  }

  /**
   * Check for tRPC procedure with .input() validation
   */
  private checkTRPCRoute(node: ts.CallExpression): RouteHandler | null {
    // Look for .mutation() or .query() calls
    if (!ts.isPropertyAccessExpression(node.expression)) return null;
    const methodName = node.expression.name.text;
    if (methodName !== 'mutation' && methodName !== 'query') return null;

    // Walk the chain to find .input()
    const chainText = node.expression.getText();
    if (chainText.includes('.input(')) {
      // tRPC with .input() → validated
      const lastArg = node.arguments.length > 0 ? node.arguments[node.arguments.length - 1] : null;
      if (lastArg && (ts.isArrowFunction(lastArg) || ts.isFunctionExpression(lastArg))) {
        return {
          node: lastArg,
          framework: 'trpc',
          method: methodName,
          isAsync: this.isAsyncFunction(lastArg),
          hasSchemaValidation: true, // .input() validates
        };
      }
    }
    return null;
  }

  /**
   * Check for GraphQL resolver methods (skip — GraphQL has built-in type validation)
   */
  private isGraphQLResolver(node: ts.MethodDeclaration): boolean {
    // Check for @Resolver, @Query, @Mutation decorators
    const decorators = ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined;
    if (decorators) {
      for (const decorator of decorators) {
        const expr = decorator.expression;
        const name = ts.isCallExpression(expr) && ts.isIdentifier(expr.expression)
          ? expr.expression.text
          : ts.isIdentifier(expr) ? expr.text : '';
        if (['Resolver', 'Query', 'Mutation', 'Subscription', 'ResolveField'].includes(name)) {
          return true;
        }
      }
    }

    // Check if the parent class has @Resolver decorator
    const parent = node.parent;
    if (parent && ts.isClassDeclaration(parent)) {
      const classDecorators = ts.canHaveDecorators(parent) ? ts.getDecorators(parent) : undefined;
      if (classDecorators) {
        for (const decorator of classDecorators) {
          const expr = decorator.expression;
          const name = ts.isCallExpression(expr) && ts.isIdentifier(expr.expression)
            ? expr.expression.text
            : ts.isIdentifier(expr) ? expr.text : '';
          if (name === 'Resolver') return true;
        }
      }
    }

    return false;
  }

  // ──────────────────── Framework Schema Detection ────────────────────

  /** Check if Fastify route options contain { schema: { body: ... } } */
  private hasFastifySchemaValidation(options: ts.ObjectLiteralExpression): boolean {
    for (const prop of options.properties) {
      if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
        if (prop.name.text === 'schema' && ts.isObjectLiteralExpression(prop.initializer)) {
          // Check for body, params, querystring sub-properties
          for (const schemaProp of prop.initializer.properties) {
            if (ts.isPropertyAssignment(schemaProp) && ts.isIdentifier(schemaProp.name)) {
              const name = schemaProp.name.text;
              if (['body', 'params', 'querystring', 'query'].includes(name)) {
                return true;
              }
            }
          }
        }
      }
    }
    return false;
  }

  /** Check if Hapi route config has options.validate.payload/params/query */
  private hasHapiValidateConfig(options: ts.ObjectLiteralExpression): boolean {
    for (const prop of options.properties) {
      if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
        if (prop.name.text === 'validate') {
          return true;
        }
      }
    }
    return false;
  }

  // ──────────────────── Validation Detection ────────────────────

  /**
   * Detect which validation libraries are imported in this file.
   * Used to avoid false positives on generic function names like create() or assert().
   */
  private detectValidationImports(sourceFile: ts.SourceFile): Set<string> {
    const imports = new Set<string>();
    traverse(sourceFile, (node) => {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        const mod = node.moduleSpecifier.text.toLowerCase();
        if (mod.includes('superstruct')) imports.add('superstruct');
        if (mod.includes('io-ts') || mod === 'fp-ts/Either') imports.add('io-ts');
        if (mod.includes('valibot')) imports.add('valibot');
        if (mod.includes('@sinclair/typebox')) imports.add('typebox');
        if (mod.includes('class-transformer')) imports.add('class-transformer');
        if (mod.includes('class-validator')) imports.add('class-validator');
        if (mod.includes('zod')) imports.add('zod');
        if (mod.includes('joi') || mod.includes('celebrate')) imports.add('joi');
        if (mod.includes('yup')) imports.add('yup');
        if (mod.includes('ajv')) imports.add('ajv');
      }
    });
    return imports;
  }

  /**
   * Check if a route registration call has validation middleware in its arguments.
   */
  private hasValidationMiddleware(routeCall: ts.CallExpression): boolean {
    const args = routeCall.arguments;
    if (args.length < 2) return false;

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
      if (this.isValidationMiddlewareNode(middlewareNode)) return true;
    }
    return false;
  }

  /** Check if a single AST node represents a validation middleware. */
  private isValidationMiddlewareNode(node: ts.Node): boolean {
    if (ts.isCallExpression(node)) return this.isValidationCallExpression(node);
    if (ts.isIdentifier(node)) return this.isValidationIdentifier(node.text);
    return false;
  }

  /** Check if a call expression represents a validation middleware call. */
  private isValidationCallExpression(callExpr: ts.CallExpression): boolean {
    const callee = callExpr.expression;

    if (ts.isIdentifier(callee)) {
      const name = callee.text;
      const expressValidatorFns = ['body', 'param', 'query', 'check', 'validationResult', 'checkSchema', 'oneOf'];
      if (expressValidatorFns.includes(name)) return true;
      if (name === 'celebrate') return true;
      if (this.isValidationIdentifier(name)) return true;
    }

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
    if ((lower.includes('validat') || lower.includes('validator')) && !lower.includes('invalid')) return true;
    if (lower.includes('sanitiz')) return true;
    if (lower.includes('zodmiddleware') || lower.includes('yupmiddleware')) return true;
    return false;
  }

  /**
   * Check if handler has validation library calls.
   * Expanded to cover: Joi, Zod, Yup, class-validator, express-validator, AJV,
   * superstruct, io-ts, valibot, TypeBox, class-transformer.
   */
  private hasValidationInHandler(node: ts.Node, _context: AnalysisContext, validationImports: Set<string>): boolean {
    let hasValidation = false;

    traverse(node, (n) => {
      if (hasValidation) return;

      if (ts.isCallExpression(n)) {
        const text = n.getText();

        const validationPatterns = [
          // Joi
          /joi\.(object|validate|assert)/i,
          /Joi\.validate\(/,
          /\.validate\(/,
          /\.validateAsync\(/,

          // Zod
          /z\.(object|string|number|array|boolean|enum|union)/,
          /\.parse\(/,
          /\.safeParse\(/,
          /\.parseAsync\(/,

          // Yup
          /yup\.(object|string|number|boolean|array)/i,
          /\.validateSync\(/,
          /\.isValid\(/,

          // class-validator
          /\bvalidate\(/,
          /\bvalidateSync\(/,

          // express-validator
          /body\(['"].*['"]\)\..*\(/,
          /param\(['"].*['"]\)\..*\(/,
          /query\(['"].*['"]\)\..*\(/,
          /validationResult\(/,

          // AJV
          /ajv\.validate\(/,
          /ajv\.compile\(/,

          // class-transformer
          /plainToClass\(/,
          /plainToInstance\(/,

          // TypeBox
          /TypeCompiler\.Compile\(/,
          /\.Check\(/,
        ];

        // Import-dependent patterns (avoid false positives on generic names)
        if (validationImports.has('superstruct')) {
          validationPatterns.push(/\bcreate\(/);
          validationPatterns.push(/\bassert\(/);
        }
        if (validationImports.has('io-ts')) {
          validationPatterns.push(/\.decode\(/);
          validationPatterns.push(/isLeft\(/);
          validationPatterns.push(/isRight\(/);
        }
        if (validationImports.has('valibot')) {
          validationPatterns.push(/v\.parse\(/);
          validationPatterns.push(/v\.safeParse\(/);
        }

        if (validationPatterns.some(pattern => pattern.test(text))) {
          hasValidation = true;
        }
      }

      // NestJS DTO type checking
      if (ts.isParameter(n)) {
        const typeNode = n.type;
        if (typeNode) {
          const typeText = typeNode.getText();
          if (!typeText.includes('any') && /[A-Z]/.test(typeText[0])) {
            hasValidation = true;
          }
        }
      }
    });

    return hasValidation;
  }

  /**
   * Find variables that hold validated output.
   * e.g., const data = schema.parse(req.body) → 'data' is clean.
   */
  private findValidatedVariables(handlerNode: ts.Node): ValidatedVariable[] {
    const validated: ValidatedVariable[] = [];

    traverse(handlerNode, (n) => {
      if (!ts.isVariableDeclaration(n) || !n.initializer) return;
      if (!ts.isCallExpression(n.initializer)) return;

      const callText = n.initializer.getText();

      // Check if the call is a validation method on req.body/params/query
      const isValidationCall = MissingInputValidationDetector.WHOLE_SHAPE_METHODS.has(
        this.getCallMethodName(n.initializer)
      );

      if (!isValidationCall) return;

      // Check if any argument references request data
      const argsText = n.initializer.arguments.map(a => a.getText()).join(' ');
      const requestSources = ['req.body', 'request.body', 'req.params', 'req.query',
        'ctx.request.body', 'ctx.params', 'ctx.query', 'request.payload',
        'request.params', 'request.query'];

      const matchedSource = requestSources.find(s => argsText.includes(s) || callText.includes(s));
      if (!matchedSource) return;

      // Extract variable name(s)
      if (ts.isIdentifier(n.name)) {
        validated.push({
          name: n.name.text,
          sourceExpression: matchedSource,
          declarationPos: n.getStart(),
        });
      }
      // Destructured: const { error, value } = schema.validate(req.body)
      if (ts.isObjectBindingPattern(n.name)) {
        for (const element of n.name.elements) {
          if (ts.isIdentifier(element.name)) {
            const fieldName = element.name.text;
            // 'value' and 'data' are the common validated output names
            if (['value', 'data', 'result'].includes(fieldName) || element.name.text !== 'error') {
              validated.push({
                name: fieldName,
                sourceExpression: matchedSource,
                declarationPos: n.getStart(),
              });
            }
          }
        }
      }
    });

    return validated;
  }

  /** Get the method name from a call expression */
  private getCallMethodName(call: ts.CallExpression): string {
    const expr = call.expression;
    if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
    if (ts.isIdentifier(expr)) return expr.text;
    return '';
  }

  // ──────────────────── Request Data Usage Detection ────────────────────

  /**
   * Find all request data usage in handler
   */
  private findRequestDataUsage(node: ts.Node): RequestDataUsage[] {
    const usages: RequestDataUsage[] = [];

    traverse(node, (n) => {
      // ── Property access: req.body, req.params, req.query, req.headers, req.files, req.cookies ──
      if (ts.isPropertyAccessExpression(n)) {
        const text = n.getText();

        // Express/Fastify body
        if (text.match(/req(uest)?\.body/)) {
          usages.push({ node: n, source: 'req.body', risk: 'vulnerable to injection attacks and privilege escalation', usageKind: 'direct' });
        } else if (text.match(/req(uest)?\.params/)) {
          usages.push({ node: n, source: 'req.params', risk: 'vulnerable to injection attacks and IDOR', usageKind: 'direct' });
        } else if (text.match(/req(uest)?\.query/)) {
          usages.push({ node: n, source: 'req.query', risk: 'vulnerable to injection attacks', usageKind: 'direct' });
        } else if (text.match(/req(uest)?\.headers/)) {
          usages.push({ node: n, source: 'req.headers', risk: 'vulnerable to header injection', usageKind: 'direct' });
        } else if (text.match(/req(uest)?\.files?(?!\w)/)) {
          usages.push({ node: n, source: 'req.files', risk: 'vulnerable to unrestricted file upload', usageKind: 'direct' });
        } else if (text.match(/req(uest)?\.cookies/)) {
          usages.push({ node: n, source: 'req.cookies', risk: 'vulnerable to session fixation and injection', usageKind: 'direct' });
        } else if (text.match(/req(uest)?\.signedCookies/)) {
          usages.push({ node: n, source: 'req.signedCookies', risk: 'signed but still user-controlled input', usageKind: 'direct' });
        } else if (text.match(/req(uest)?\.ip$/)) {
          usages.push({ node: n, source: 'req.ip', risk: 'spoofable via X-Forwarded-For', usageKind: 'direct' });
        }
        // Koa context patterns
        else if (text.match(/ctx\.request\.body/)) {
          usages.push({ node: n, source: 'ctx.request.body', risk: 'vulnerable to injection attacks and privilege escalation', usageKind: 'direct' });
        } else if (text.match(/ctx\.params/)) {
          usages.push({ node: n, source: 'ctx.params', risk: 'vulnerable to injection attacks and IDOR', usageKind: 'direct' });
        } else if (text.match(/ctx\.query/)) {
          usages.push({ node: n, source: 'ctx.query', risk: 'vulnerable to injection attacks', usageKind: 'direct' });
        } else if (text.match(/ctx\.request\.files?(?!\w)/)) {
          usages.push({ node: n, source: 'ctx.request.files', risk: 'vulnerable to unrestricted file upload', usageKind: 'direct' });
        }
        // Hapi request patterns
        else if (text.match(/^request\.payload/)) {
          usages.push({ node: n, source: 'request.payload', risk: 'vulnerable to injection attacks and privilege escalation', usageKind: 'direct' });
        } else if (text.match(/^request\.params/)) {
          usages.push({ node: n, source: 'request.params', risk: 'vulnerable to injection attacks and IDOR', usageKind: 'direct' });
        } else if (text.match(/^request\.query/)) {
          usages.push({ node: n, source: 'request.query', risk: 'vulnerable to injection attacks', usageKind: 'direct' });
        }
      }

      // ── Element access: req.body[fieldName] — dynamic property ──
      if (ts.isElementAccessExpression(n)) {
        const exprText = n.expression.getText();
        if (exprText.match(/req(uest)?\.body/) && !ts.isStringLiteral(n.argumentExpression)) {
          usages.push({ node: n, source: 'req.body (dynamic)', risk: 'dynamic property — attacker can access any field', usageKind: 'dynamic' });
        }
      }

      // ── Destructuring: const { email } = req.body ──
      if (ts.isVariableDeclaration(n) && n.initializer) {
        const initText = n.initializer.getText();

        if (ts.isObjectBindingPattern(n.name)) {
          // Destructuring
          if (initText.match(/req(uest)?\.body/)) {
            usages.push({ node: n, source: 'req.body (destructured)', risk: 'vulnerable to injection attacks and privilege escalation', usageKind: 'destructured' });
          } else if (initText.match(/req(uest)?\.params/)) {
            usages.push({ node: n, source: 'req.params (destructured)', risk: 'vulnerable to injection attacks and IDOR', usageKind: 'destructured' });
          } else if (initText.match(/req(uest)?\.query/)) {
            usages.push({ node: n, source: 'req.query (destructured)', risk: 'vulnerable to injection attacks', usageKind: 'destructured' });
          }
          // Koa destructuring
          else if (initText.match(/ctx\.request\.body/)) {
            usages.push({ node: n, source: 'ctx.request.body (destructured)', risk: 'vulnerable to injection attacks and privilege escalation', usageKind: 'destructured' });
          } else if (initText.match(/ctx\.params/)) {
            usages.push({ node: n, source: 'ctx.params (destructured)', risk: 'vulnerable to injection attacks and IDOR', usageKind: 'destructured' });
          } else if (initText.match(/ctx\.query/)) {
            usages.push({ node: n, source: 'ctx.query (destructured)', risk: 'vulnerable to injection attacks', usageKind: 'destructured' });
          }
          // Hapi destructuring
          else if (initText.match(/request\.payload/)) {
            usages.push({ node: n, source: 'request.payload (destructured)', risk: 'vulnerable to injection attacks and privilege escalation', usageKind: 'destructured' });
          } else if (initText.match(/request\.params/)) {
            usages.push({ node: n, source: 'request.params (destructured)', risk: 'vulnerable to injection attacks and IDOR', usageKind: 'destructured' });
          } else if (initText.match(/request\.query/)) {
            usages.push({ node: n, source: 'request.query (destructured)', risk: 'vulnerable to injection attacks', usageKind: 'destructured' });
          }
        } else if (ts.isIdentifier(n.name)) {
          // Whole-object alias: const data = req.body
          if (initText.match(/^req(uest)?\.body$/)) {
            usages.push({ node: n, source: 'req.body (alias)', risk: 'entire request body assigned to variable without validation', usageKind: 'alias', aliasName: n.name.text });
          } else if (initText.match(/^req(uest)?\.params$/)) {
            usages.push({ node: n, source: 'req.params (alias)', risk: 'entire params assigned to variable without validation', usageKind: 'alias', aliasName: n.name.text });
          } else if (initText.match(/^req(uest)?\.query$/)) {
            usages.push({ node: n, source: 'req.query (alias)', risk: 'entire query assigned to variable without validation', usageKind: 'alias', aliasName: n.name.text });
          }
        }
      }

      // ── NestJS parameter decorators: @Body() body, @Param() params ──
      if (ts.isParameter(n)) {
        const decorators = ts.canHaveDecorators(n) ? ts.getDecorators(n) : undefined;
        if (decorators && decorators.length > 0) {
          for (const decorator of decorators) {
            if (ts.isCallExpression(decorator.expression) && ts.isIdentifier(decorator.expression.expression)) {
              const decoratorName = decorator.expression.expression.text;
              if (decoratorName === 'Body') {
                usages.push({ node: n, source: '@Body() decorator', risk: 'vulnerable to injection attacks and privilege escalation', usageKind: 'direct' });
              } else if (decoratorName === 'Param') {
                usages.push({ node: n, source: '@Param() decorator', risk: 'vulnerable to injection attacks and IDOR', usageKind: 'direct' });
              } else if (decoratorName === 'Query') {
                usages.push({ node: n, source: '@Query() decorator', risk: 'vulnerable to injection attacks', usageKind: 'direct' });
              }
            }
          }
        }
      }

      // ── Spread operator: { ...req.body }, db.create({...req.body}) ──
      if (ts.isSpreadAssignment(n) || ts.isSpreadElement(n)) {
        const spreadText = n.expression.getText();
        if (spreadText.match(/req(uest)?\.body/)) {
          usages.push({ node: n, source: 'req.body (spread)', risk: 'mass assignment — all fields passed to DB/logic without filtering', usageKind: 'spread' });
        } else if (spreadText.match(/req(uest)?\.params/)) {
          usages.push({ node: n, source: 'req.params (spread)', risk: 'mass assignment — all request params spread without filtering', usageKind: 'spread' });
        } else if (spreadText.match(/req(uest)?\.query/)) {
          usages.push({ node: n, source: 'req.query (spread)', risk: 'mass assignment — all query params spread without filtering', usageKind: 'spread' });
        }
        // Koa spread
        else if (spreadText.match(/ctx\.request\.body/)) {
          usages.push({ node: n, source: 'ctx.request.body (spread)', risk: 'mass assignment — all fields passed to DB/logic without filtering', usageKind: 'spread' });
        } else if (spreadText.match(/ctx\.params/)) {
          usages.push({ node: n, source: 'ctx.params (spread)', risk: 'mass assignment — all request params spread without filtering', usageKind: 'spread' });
        } else if (spreadText.match(/ctx\.query/)) {
          usages.push({ node: n, source: 'ctx.query (spread)', risk: 'mass assignment — all query params spread without filtering', usageKind: 'spread' });
        }
        // Hapi spread
        else if (spreadText.match(/request\.payload/)) {
          usages.push({ node: n, source: 'request.payload (spread)', risk: 'mass assignment — all fields passed to DB/logic without filtering', usageKind: 'spread' });
        } else if (spreadText.match(/request\.params/)) {
          usages.push({ node: n, source: 'request.params (spread)', risk: 'mass assignment — all request params spread without filtering', usageKind: 'spread' });
        } else if (spreadText.match(/request\.query/)) {
          usages.push({ node: n, source: 'request.query (spread)', risk: 'mass assignment — all query params spread without filtering', usageKind: 'spread' });
        }
      }

      // ── Object.assign(target, req.body) — mass assignment ──
      if (ts.isCallExpression(n)) {
        const callText = n.expression.getText();
        if (callText === 'Object.assign' && n.arguments.length >= 2) {
          for (let i = 1; i < n.arguments.length; i++) {
            const argText = n.arguments[i].getText();
            if (argText.match(/req(uest)?\.body/)) {
              usages.push({ node: n, source: 'req.body (Object.assign)', risk: 'mass assignment — Object.assign spreads all fields to target', usageKind: 'object-assign' });
            }
          }
        }
      }

      // ── Function argument: processOrder(req.body) ──
      if (ts.isCallExpression(n) && n.arguments.length > 0) {
        // Exclude known safe patterns (validation calls, logging, response methods)
        const callText = n.expression.getText();
        if (!this.isKnownSafeCall(callText)) {
          for (const arg of n.arguments) {
            const argText = arg.getText();
            if (argText.match(/^req(uest)?\.body$/) || argText.match(/^ctx\.request\.body$/) || argText.match(/^request\.payload$/)) {
              usages.push({ node: n, source: 'req.body (function arg)', risk: 'entire request body passed to function without validation', usageKind: 'function-arg' });
              break;
            }
          }
        }
      }
    });

    return usages;
  }

  /** Check if a call expression is a known safe target (not a business logic function) */
  private isKnownSafeCall(callText: string): boolean {
    // Validation calls, response methods, logging — don't flag these as "function arg" usage
    if (/^(res|response|reply|ctx|console|logger|log)\b/.test(callText)) return true;
    if (/\.(json|send|render|redirect|status|log|info|warn|error|debug)\s*$/.test(callText)) return true;
    if (/^(validate|parse|safeParse|celebrate|schema|joi|zod|yup|ajv)\b/i.test(callText)) return true;
    if (/\.(parse|safeParse|validate|validateSync|validateAsync|decode|compile)\s*$/.test(callText)) return true;
    if (callText === 'Object.assign') return true;
    return false;
  }

  // ──────────────────── Per-Field Tracking ────────────────────

  /**
   * Collect the specific field names accessed from a request source within a handler.
   */
  private collectFieldNames(
    handlerNode: ts.Node,
    sourceKey: 'body' | 'params' | 'query' | 'headers',
  ): string[] {
    const fields = new Set<string>();

    traverse(handlerNode, (n) => {
      // req.body.fieldName — double PropertyAccess
      if (ts.isPropertyAccessExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
        const inner = n.expression;

        // Express: req.body.fieldName
        if (inner.name.text === sourceKey && ts.isIdentifier(inner.expression) && inner.expression.text.match(/^req(uest)?$/)) {
          fields.add(n.name.text);
        }
        // Koa: ctx.params.fieldName, ctx.query.fieldName
        if ((sourceKey === 'params' || sourceKey === 'query') && inner.name.text === sourceKey && ts.isIdentifier(inner.expression) && inner.expression.text === 'ctx') {
          fields.add(n.name.text);
        }
        // Hapi: request.params.fieldName, request.query.fieldName
        if ((sourceKey === 'params' || sourceKey === 'query') && inner.name.text === sourceKey && ts.isIdentifier(inner.expression) && inner.expression.text === 'request') {
          fields.add(n.name.text);
        }
        // Hapi: request.payload.fieldName
        if (sourceKey === 'body' && inner.name.text === 'payload' && ts.isIdentifier(inner.expression) && inner.expression.text === 'request') {
          fields.add(n.name.text);
        }
      }

      // Koa: ctx.request.body.fieldName — 3-level deep
      if (sourceKey === 'body' && ts.isPropertyAccessExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
        const mid = n.expression;
        if (mid.name.text === 'body' && ts.isPropertyAccessExpression(mid.expression) && mid.expression.name.text === 'request' && ts.isIdentifier(mid.expression.expression) && mid.expression.expression.text === 'ctx') {
          fields.add(n.name.text);
        }
      }

      // Destructuring: const { field1, field2 } = req.body
      if (ts.isVariableDeclaration(n) && n.initializer && ts.isObjectBindingPattern(n.name)) {
        const initText = n.initializer.getText();
        let matches = false;

        if (initText.match(new RegExp(`req(uest)?\\.${sourceKey}`))) matches = true;
        if ((sourceKey === 'params' || sourceKey === 'query') && initText.match(new RegExp(`ctx\\.${sourceKey}`))) matches = true;
        if (sourceKey === 'body' && initText.match(/ctx\.request\.body/)) matches = true;
        if ((sourceKey === 'params' || sourceKey === 'query') && initText.match(new RegExp(`request\\.${sourceKey}`))) matches = true;
        if (sourceKey === 'body' && initText.match(/request\.payload/)) matches = true;

        if (matches) {
          for (const element of n.name.elements) {
            if (ts.isBindingElement(element)) {
              // Aliased: { id: userId } → source field is 'id'
              if (element.propertyName && ts.isIdentifier(element.propertyName)) {
                fields.add(element.propertyName.text);
              } else if (ts.isIdentifier(element.name)) {
                fields.add(element.name.text);
              }
              // Nested: { address: { street, city } }
              if (ts.isObjectBindingPattern(element.name)) {
                const parentName = element.propertyName
                  ? (ts.isIdentifier(element.propertyName) ? element.propertyName.text : '')
                  : '';
                for (const nested of element.name.elements) {
                  if (ts.isIdentifier(nested.name)) {
                    fields.add(parentName ? `${parentName}.${nested.name.text}` : nested.name.text);
                  }
                }
              }
            }
          }
        }
      }
    });

    return [...fields];
  }

  /**
   * Extract which fields express-validator covers from middleware arguments.
   * body('email') → req.body.email, param('id') → req.params.id
   */
  private extractExpressValidatorFields(routeCall: ts.CallExpression): Map<string, string[]> {
    const coverage = new Map<string, string[]>();
    const args = routeCall.arguments;
    if (args.length < 2) return coverage;

    const middlewareArgs = Array.from(args).slice(1, args.length - 1);
    const allNodes: ts.Node[] = [];
    for (const arg of middlewareArgs) {
      allNodes.push(arg);
      if (ts.isArrayLiteralExpression(arg)) {
        for (const el of arg.elements) allNodes.push(el);
      }
    }

    for (const mw of allNodes) {
      // Find root call in chain
      if (ts.isCallExpression(mw)) {
        const rootId = this.getRootCallOfChain(mw);
        if (!rootId) continue;
        const rootName = rootId.text;

        // Map function name to source
        let sourceKey: string | null = null;
        if (rootName === 'body') sourceKey = 'body';
        else if (rootName === 'param') sourceKey = 'params';
        else if (rootName === 'query') sourceKey = 'query';
        else if (rootName === 'check') sourceKey = 'any';

        if (!sourceKey) continue;

        // Walk to find the root call expression to get its first argument (field name)
        let rootCall = mw;
        let depth = 0;
        while (depth < 20) {
          depth++;
          const expr = rootCall.expression;
          if (ts.isPropertyAccessExpression(expr) && ts.isCallExpression(expr.expression)) {
            rootCall = expr.expression;
            continue;
          }
          break;
        }

        if (rootCall.arguments.length > 0 && ts.isStringLiteral(rootCall.arguments[0])) {
          const fieldName = rootCall.arguments[0].text;
          if (!coverage.has(sourceKey)) coverage.set(sourceKey, []);
          coverage.get(sourceKey)!.push(fieldName);
        }
      }
    }

    return coverage;
  }

  /**
   * Collect field names that have per-field manual validation.
   * Returns a map of field name → validation strength ('adequate' or 'weak').
   */
  private getManuallyValidatedFields(handlerNode: ts.Node): Map<string, 'adequate' | 'weak'> {
    const validated = new Map<string, 'adequate' | 'weak'>();
    const optPrefix = '(?:req(?:uest)?\\.(?:body|params|query)\\.|ctx\\.(?:request\\.body|params|query)\\.|request\\.(?:payload|params|query)\\.)?';

    const setAll = (regex: RegExp, text: string, strength: 'adequate' | 'weak') => {
      for (const m of text.matchAll(regex)) {
        const field = m[1];
        if (strength === 'adequate' || !validated.has(field)) {
          validated.set(field, strength);
        }
      }
    };

    traverse(handlerNode, (n) => {
      if (!ts.isIfStatement(n)) return;
      const condText = n.expression.getText();

      // typeof field === 'string' (adequate)
      setAll(new RegExp(`typeof\\s+${optPrefix}(\\w+)\\s*[!=]==?\\s*`, 'g'), condText, 'adequate');

      // Array.isArray(field) (adequate)
      setAll(new RegExp(`Array\\.isArray\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

      // field instanceof X (adequate)
      setAll(new RegExp(`${optPrefix}(\\w+)\\s+instanceof\\s+`, 'g'), condText, 'adequate');

      // Number.isInteger(field), Number.isFinite(field), Number.isNaN(field) (adequate)
      setAll(new RegExp(`Number\\.(?:isInteger|isFinite|isNaN)\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

      // ARRAY.includes(field) or SET.has(field) (adequate — allowlist)
      setAll(new RegExp(`\\.(?:includes|has)\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

      // field.match(/pattern/) or /pattern/.test(field) (adequate — regex validation)
      setAll(new RegExp(`${optPrefix}(\\w+)\\.match\\(`, 'g'), condText, 'adequate');
      setAll(new RegExp(`\\.test\\(${optPrefix}(\\w+)\\)`, 'g'), condText, 'adequate');

      // field.length > N, field.trim().length > 0 (adequate)
      setAll(new RegExp(`${optPrefix}(\\w+)(?:\\.trim\\(\\))?\\.length\\s*[><=]`, 'g'), condText, 'adequate');

      // field > N, field < N, field >= N (adequate — range check)
      for (const m of condText.matchAll(new RegExp(`${optPrefix}(\\w+)\\s*[><=]+\\s*\\d`, 'g'))) {
        if (!m[0].includes('.length')) {
          validated.set(m[1], 'adequate');
        }
      }

      // Presence-only: !field or field == null (weak)
      setAll(new RegExp(`!${optPrefix}(\\w+)\\b`, 'g'), condText, 'weak');
      setAll(new RegExp(`${optPrefix}(\\w+)\\s*[!=]==?\\s*(?:null|undefined)\\b`, 'g'), condText, 'weak');
    });

    return validated;
  }

  // ──────────────────── Context-Aware Severity ────────────────────

  /**
   * Classify the usage context of unvalidated data to determine severity.
   */
  private classifyUsageContext(usage: RequestDataUsage, handlerNode: ts.Node): UsageContext {
    const handlerText = handlerNode.getText().toLowerCase();

    // Mass assignment and dynamic property are always critical
    if (usage.usageKind === 'spread' || usage.usageKind === 'object-assign') {
      return { category: 'db-write', isDangerousOperation: true };
    }
    if (usage.usageKind === 'dynamic') {
      return { category: 'db-write', isDangerousOperation: true };
    }

    // File operations — source is req.files or handler has file system calls
    if (usage.source.includes('file')) {
      return { category: 'file-operation', isDangerousOperation: true };
    }
    if (MissingInputValidationDetector.FILE_OP_PATTERNS.test(handlerText)) {
      return { category: 'file-operation', isDangerousOperation: true };
    }

    // Check for DB write operations in handler text
    for (const op of MissingInputValidationDetector.DB_WRITE_OPS) {
      if (handlerText.includes(`.${op}(`)) {
        return { category: 'db-write', isDangerousOperation: true };
      }
    }

    // Simple lookup: params-only with findByPk/findById (must come before general DB_READ)
    if (usage.source.includes('params') && !usage.source.includes('body')) {
      const isSimpleLookup = handlerText.includes('.findbypk(') || handlerText.includes('.findbyid(') || handlerText.includes('.findone(');
      const hasWrite = [...MissingInputValidationDetector.DB_WRITE_OPS].some(op => handlerText.includes(`.${op}(`));
      if (isSimpleLookup && !hasWrite) {
        return { category: 'simple-lookup', isDangerousOperation: false };
      }
    }

    // Check for DB read operations
    for (const op of MissingInputValidationDetector.DB_READ_OPS) {
      if (handlerText.includes(`.${op}(`)) {
        return { category: 'db-read', isDangerousOperation: false };
      }
    }

    // Check for logging
    if (MissingInputValidationDetector.LOGGING_PATTERNS.test(handlerText)) {
      // Only logging if no other operations
      const hasOtherOps = [...MissingInputValidationDetector.DB_WRITE_OPS, ...MissingInputValidationDetector.DB_READ_OPS]
        .some(op => handlerText.includes(`.${op}(`));
      if (!hasOtherOps) {
        return { category: 'logging', isDangerousOperation: false };
      }
    }

    // Check for queue/messaging
    if (MissingInputValidationDetector.QUEUE_PATTERNS.test(handlerText)) {
      return { category: 'queue-publish', isDangerousOperation: false };
    }

    return { category: 'unknown', isDangerousOperation: false };
  }

  /**
   * Determine severity based on usage context and validation state.
   */
  private determineSeverity(usage: RequestDataUsage, context: UsageContext, hasWeakValidation: boolean): { severity: 'error' | 'warning' | 'info'; confidence: 'high' | 'medium' | 'low' } {
    // Mass assignment / dynamic property → always critical
    if (usage.usageKind === 'spread' || usage.usageKind === 'object-assign' || usage.usageKind === 'dynamic') {
      return { severity: 'error', confidence: 'high' };
    }

    // File upload → critical
    if (usage.source.includes('file')) {
      return { severity: 'error', confidence: 'high' };
    }

    // Presence-only (weak) validation → warning
    if (hasWeakValidation) {
      return { severity: 'warning', confidence: 'medium' };
    }

    // req.ip → info
    if (usage.source.includes('req.ip')) {
      return { severity: 'info', confidence: 'low' };
    }

    // Signed cookies → low
    if (usage.source.includes('signedCookies')) {
      return { severity: 'warning', confidence: 'low' };
    }

    // Logging only → info
    if (context.category === 'logging') {
      return { severity: 'info', confidence: 'low' };
    }

    // Queue publish → warning
    if (context.category === 'queue-publish') {
      return { severity: 'warning', confidence: 'medium' };
    }

    // Simple lookup → warning
    if (context.category === 'simple-lookup') {
      return { severity: 'warning', confidence: 'medium' };
    }

    // DB write → error/high
    if (context.category === 'db-write') {
      return { severity: 'error', confidence: 'high' };
    }

    // DB read → error/medium
    if (context.category === 'db-read') {
      return { severity: 'error', confidence: 'medium' };
    }

    // Default based on source
    if (usage.source.includes('body') || usage.source.includes('payload') || usage.source.includes('@Body')) {
      return { severity: 'error', confidence: 'high' };
    }
    if (usage.source.includes('params') || usage.source.includes('@Param')) {
      return { severity: 'error', confidence: 'high' };
    }
    if (usage.source.includes('query') || usage.source.includes('@Query')) {
      return { severity: 'error', confidence: 'medium' };
    }
    if (usage.source.includes('headers')) {
      return { severity: 'warning', confidence: 'low' };
    }
    if (usage.source.includes('cookies')) {
      return { severity: 'warning', confidence: 'medium' };
    }

    return { severity: 'error', confidence: 'medium' };
  }

  // ──────────────────── Suggestion Generation ────────────────────

  /**
   * Generate field-specific, context-aware suggestion.
   */
  private generateSuggestion(usage: RequestDataUsage, _context: UsageContext, fields: string[], normalizedSource: string): string {
    // Mass assignment
    if (usage.usageKind === 'spread' || usage.usageKind === 'object-assign') {
      return `${normalizedSource} spread/assigned into object — mass assignment vulnerability. Destructure only needed fields: const { name, email } = schema.parse(${normalizedSource}), or use a Zod/Joi schema to validate and strip unknown fields.`;
    }

    // Dynamic property access
    if (usage.usageKind === 'dynamic') {
      return `Dynamic property access on ${normalizedSource} allows attacker to access any field. Whitelist allowed property names: const ALLOWED = ['name', 'email']; if (!ALLOWED.includes(key)) return res.status(400).json({ error: 'Invalid field' }).`;
    }

    // File upload
    if (usage.source.includes('file')) {
      return `File upload without validation — add file type allowlist (check mimetype), size limit, and sanitize filename before use. Example: if (!['image/png','image/jpeg'].includes(file.mimetype)) return res.status(400).json({ error: 'Invalid file type' }).`;
    }

    // Check for sensitive fields
    const sensitiveFields = fields.filter(f => MissingInputValidationDetector.SENSITIVE_FIELDS.has(f.toLowerCase()));
    if (sensitiveFields.length > 0) {
      return `${normalizedSource}.{ ${sensitiveFields.join(', ')} } used without validation — ${sensitiveFields.includes('role') || sensitiveFields.includes('roles') ? 'privilege escalation risk if attacker sets role to admin' : 'sensitive field requires strict validation'}. Add: z.object({ ${sensitiveFields.map(f => `${f}: z.enum([...allowedValues])`).join(', ')} }).parse(${normalizedSource}).`;
    }

    // Params without type coercion
    if (normalizedSource.includes('params') || normalizedSource.includes('@Param')) {
      const paramFields = fields.length > 0 ? fields : ['id'];
      return `${normalizedSource}.{ ${paramFields.join(', ')} } used without type validation — params are always strings. Add type coercion: z.coerce.number().positive().parse(req.params.${paramFields[0]}), or param('${paramFields[0]}').isUUID() / .isInt() in middleware.`;
    }

    // Query in DB
    if (normalizedSource.includes('query') || normalizedSource.includes('@Query')) {
      return `${normalizedSource}.{ ${fields.join(', ')} } used without validation — vulnerable to injection and filter manipulation. Add: z.object({ ${fields.map(f => `${f}: z.string()`).join(', ')} }).parse(${normalizedSource}), or validate against allowed values.`;
    }

    // Specific fields
    if (fields.length > 0) {
      const fieldSuffix = `.{ ${fields.join(', ')} }`;
      return `${normalizedSource}${fieldSuffix} used without validation — add zod, joi, or yup schema: z.object({ ${fields.map(f => `${f}: z.string()`).join(', ')} }).parse(${normalizedSource}).`;
    }

    return `Add input validation using joi, zod, yup, class-validator, or express-validator before using ${normalizedSource}.`;
  }

  // ──────────────────── Main Validation Check ────────────────────

  /**
   * Check if handler has proper input validation.
   * This is the core logic that ties all dimensions together.
   */
  private checkHandlerValidation(handler: RouteHandler, context: AnalysisContext, validationImports: Set<string>): Issue[] {
    const issues: Issue[] = [];

    // Skip if framework-level schema validation exists
    if (handler.hasSchemaValidation) return issues;

    // Check if validation middleware is present in the route registration
    if (handler.routeCallExpression && this.hasValidationMiddleware(handler.routeCallExpression)) {
      // Extract which fields express-validator covers (per-field tracking)
      const expressValidatorFields = this.extractExpressValidatorFields(handler.routeCallExpression);

      // If express-validator covers some fields but not all, check for gaps
      if (expressValidatorFields.size > 0) {
        return this.checkPartialValidation(handler, context, expressValidatorFields);
      }

      return issues;
    }

    // Check if handler uses request data
    const requestDataUsage = this.findRequestDataUsage(handler.node);
    if (requestDataUsage.length === 0) return issues;

    // Find validated output variables (const data = schema.parse(req.body))
    const validatedVars = this.findValidatedVariables(handler.node);

    // Check if validation exists in handler
    const hasValidation = this.hasValidationInHandler(handler.node, context, validationImports);

    if (hasValidation) {
      // Validation exists — check if raw req.body is still used after validation
      if (validatedVars.length > 0) {
        // Check for raw req.body usage after validation call
        for (const usage of requestDataUsage) {
          if (usage.usageKind === 'direct' || usage.usageKind === 'destructured') {
            const usagePos = usage.node.getStart();
            const isAfterValidation = validatedVars.some(v => usagePos > v.declarationPos);
            // Don't flag if the usage IS the validation call argument itself
            const isValidationArg = validatedVars.some(v => {
              const diff = v.declarationPos - usagePos;
              return diff >= 0 && diff < 200; // Within the declaration
            });
            if (isAfterValidation && !isValidationArg) {
              // Raw input used after validation — but this is unusual, skip for now
              // to avoid false positives on common patterns
            }
          }
        }
      }
      return issues;
    }

    // No library validation — check manual validation
    const manualValidation = this.getManuallyValidatedFields(handler.node);

    // Group usages by source type to avoid duplicates
    const sourceTypes = new Set<string>();
    const uniqueUsages: RequestDataUsage[] = [];

    for (const usage of requestDataUsage) {
      const normalizedSource = usage.source.replace(/ \(destructured\)| \(spread\)| \(alias\)| \(dynamic\)| \(Object\.assign\)| \(function arg\)/, '');
      if (!sourceTypes.has(normalizedSource)) {
        sourceTypes.add(normalizedSource);
        uniqueUsages.push(usage);
      }
    }

    // Flag once per source type
    for (const usage of uniqueUsages) {
      const normalizedSource = usage.source.replace(/ \(destructured\)| \(spread\)| \(alias\)| \(dynamic\)| \(Object\.assign\)| \(function arg\)/, '');

      // Collect specific field names accessed from this source
      let sourceKey: 'body' | 'params' | 'query' | 'headers' | null = null;
      if (normalizedSource.startsWith('req.')) {
        const key = normalizedSource.slice(4);
        if (['body', 'params', 'query', 'headers'].includes(key)) {
          sourceKey = key as 'body' | 'params' | 'query' | 'headers';
        }
      }
      if (normalizedSource === 'ctx.request.body' || normalizedSource === 'request.payload') sourceKey = 'body';
      if (normalizedSource === 'ctx.params' || normalizedSource === 'request.params') sourceKey = 'params';
      if (normalizedSource === 'ctx.query' || normalizedSource === 'request.query') sourceKey = 'query';

      let fields = sourceKey ? this.collectFieldNames(handler.node, sourceKey) : [];

      // Check manual validation coverage
      let hasWeakValidation = false;
      if (manualValidation.size > 0 && fields.length > 0) {
        const unvalidatedFields: string[] = [];
        let allWeak = true;
        for (const f of fields) {
          const validation = manualValidation.get(f);
          if (!validation) {
            unvalidatedFields.push(f);
            allWeak = false;
          } else if (validation === 'adequate') {
            allWeak = false;
          }
        }

        // All fields have adequate validation → skip
        if (unvalidatedFields.length === 0 && !allWeak) {
          continue;
        }

        // All have weak validation only
        if (unvalidatedFields.length === 0 && allWeak) {
          hasWeakValidation = true;
        }

        // Some fields are validated → only report unvalidated ones
        if (unvalidatedFields.length > 0 && unvalidatedFields.length < fields.length) {
          fields = unvalidatedFields;
        }
      }

      // Classify usage context for severity
      const usageContext = this.classifyUsageContext(usage, handler.node);
      const { severity, confidence } = this.determineSeverity(usage, usageContext, hasWeakValidation);

      const suggestion = this.generateSuggestion(usage, usageContext, fields, normalizedSource);

      const message = hasWeakValidation
        ? `API route uses ${usage.source} with presence-only checks but no type or format validation — ${usage.risk}`
        : `API route uses ${usage.source} without validation — ${usage.risk}`;

      const issue = this.createIssue(context, usage.node, message, { severity, suggestion, confidence });
      if (issue) issues.push(issue);
    }

    return issues;
  }

  /**
   * Check for partial validation gaps when express-validator covers some fields but not all.
   */
  private checkPartialValidation(handler: RouteHandler, context: AnalysisContext, expressValidatorFields: Map<string, string[]>): Issue[] {
    const issues: Issue[] = [];
    const sourceKeys: Array<'body' | 'params' | 'query'> = ['body', 'params', 'query'];

    for (const sourceKey of sourceKeys) {
      const accessedFields = this.collectFieldNames(handler.node, sourceKey);
      if (accessedFields.length === 0) continue;

      // Get express-validator coverage for this source
      const evSource = sourceKey === 'params' ? 'params' : sourceKey;
      const coveredFields = expressValidatorFields.get(evSource) || expressValidatorFields.get('any') || [];

      const unvalidatedFields = accessedFields.filter(f => !coveredFields.includes(f));
      if (unvalidatedFields.length === 0) continue;

      const normalizedSource = `req.${sourceKey}`;
      const coveredText = coveredFields.length > 0 ? ` — ${coveredFields.join(', ')} validated by express-validator` : '';

      const sensitiveUnvalidated = unvalidatedFields.filter(f => MissingInputValidationDetector.SENSITIVE_FIELDS.has(f.toLowerCase()));
      const severity = sensitiveUnvalidated.length > 0 ? 'error' as const : 'error' as const;
      const confidence = 'medium' as const;

      const suggestion = `${normalizedSource}.{ ${unvalidatedFields.join(', ')} } used without validation${coveredText}. Add: ${unvalidatedFields.map(f => `body('${f}').isString()`).join(', ')} to the middleware chain.`;

      const usageNode = handler.node; // Use handler node since specific usage nodes aren't available here
      const issue = this.createIssue(
        context, usageNode,
        `Partial validation gap: ${normalizedSource}.{ ${unvalidatedFields.join(', ')} } not covered by express-validator${coveredText}`,
        { severity, suggestion, confidence }
      );
      if (issue) issues.push(issue);
    }

    return issues;
  }

  // ──────────────────── Global Middleware Detection ────────────────────

  /**
   * Check if file-level global validation middleware is applied.
   */
  private hasGlobalValidationMiddleware(sourceFile: ts.SourceFile): boolean {
    let hasGlobal = false;

    traverse(sourceFile, (node) => {
      if (hasGlobal) return;

      if (!ts.isCallExpression(node)) return;
      const { expression } = node;
      if (!ts.isPropertyAccessExpression(expression)) return;
      if (expression.name.text !== 'use') return;

      const objName = this.getObjectName(expression.expression);
      if (!objName || !/^(app|router|server|api|fastify)$/i.test(objName)) return;

      for (const arg of node.arguments) {
        if (this.isValidationMiddlewareNode(arg)) {
          hasGlobal = true;
          return;
        }

        const argText = arg.getText().toLowerCase();
        const globalValidationPatterns = ['celebrate', 'joi.validate', 'express-validator', 'expressvalidator'];
        if (globalValidationPatterns.some(p => argText.includes(p))) {
          hasGlobal = true;
          return;
        }
      }
    });

    return hasGlobal;
  }

  // ──────────────────── Utility ────────────────────

  /** Get object name from expression */
  private getObjectName(expr: ts.Expression): string | null {
    if (ts.isIdentifier(expr)) return expr.text;
    if (ts.isPropertyAccessExpression(expr)) return this.getObjectName(expr.expression);
    return null;
  }

  /** Check if function is async */
  private isAsyncFunction(node: ts.Node): boolean {
    if (ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) {
      const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
      return modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false;
    }
    return false;
  }
}

// ──────────────────── Interfaces ────────────────────

interface RouteHandler {
  node: ts.Node;
  framework: 'express' | 'nestjs' | 'koa' | 'hapi' | 'trpc' | 'graphql';
  method: string;
  isAsync: boolean;
  routeCallExpression?: ts.CallExpression;
  hasSchemaValidation?: boolean;
}

interface RequestDataUsage {
  node: ts.Node;
  source: string;
  risk: string;
  usageKind?: 'direct' | 'destructured' | 'spread' | 'alias' | 'dynamic' | 'object-assign' | 'function-arg';
  aliasName?: string;
}

interface ValidatedVariable {
  name: string;
  sourceExpression: string;
  declarationPos: number;
}

interface UsageContext {
  category: 'db-write' | 'db-read' | 'file-operation' | 'queue-publish' | 'logging' | 'simple-lookup' | 'unknown';
  isDangerousOperation: boolean;
}

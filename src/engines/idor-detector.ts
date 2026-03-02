/**
 * IDOR (Insecure Direct Object Reference) Detector
 * Detects database queries using user-supplied IDs without authorization checks
 * Priority: CRITICAL (direct data breach, unauthorized access, privacy violation)
 *
 * The #2 most dangerous AI security bug:
 * - AI generates: app.get('/doc/:id', async (req, res) => { const doc = await db.find(req.params.id); })
 * - Attacker: /doc/1, /doc/2, /doc/3... → steals all documents
 * - No ownership check = instant data breach
 * - OWASP Top 10: Broken Access Control (#1)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';

export class IDORDetector extends BaseEngine {
  readonly name = 'idor';

  /** Authorization check patterns used in hasAuthorizationCheck */
  private static readonly AUTH_PATTERNS = [
    /user\.id/,
    /userId/,
    /owner/,
    /belongsTo/,
    /canAccess/,
    /hasPermission/,
    /isOwner/,
    /checkAccess/,
    /authorize/,
    /user_id/,
    /\.id\s*===\s*req\.user/,
    /supplierId/,
    /supplier_id/,
    /orgId/,
    /org_id/,
    /organizationId/,
    /organization_id/,
    /tenantId/,
    /tenant_id/,
    /companyId/,
    /company_id/,
    /teamId/,
    /team_id/,
    /accountId/,
    /account_id/,
    /createdBy/,
    /created_by/,
  ];

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];
    const flaggedLines = new Set<number>();

    traverse(context.sourceFile, (node) => {
      // Check database query calls
      if (ts.isCallExpression(node)) {
        const issue = this.checkDatabaseQuery(node, context);
        if (issue) {
          // Only add if we haven't flagged this line yet (avoid duplicates)
          if (!flaggedLines.has(issue.location.line)) {
            flaggedLines.add(issue.location.line);
            issues.push(issue);
          }
        }
      }
    });

    return issues;
  }

  /**
   * Check if this is a database query with user-supplied ID without auth check
   *
   * Confidence levels:
   * - High: Direct req.params/req.body usage with known ORM methods (findById, findOne, etc.)
   * - High: Variable traced back to request params/body
   * - Medium: Generic variable name like 'id' that likely comes from request
   * - Low: Query methods like 'where' that may have auth in the WHERE clause
   */
  private checkDatabaseQuery(node: ts.CallExpression, context: AnalysisContext): Issue | null {
    const { expression } = node;

    // Get method name
    let methodName: string | null = null;
    let objectName: string | null = null;

    if (ts.isPropertyAccessExpression(expression)) {
      methodName = expression.name.text;
      objectName = this.getObjectName(expression.expression);
    } else if (ts.isIdentifier(expression)) {
      methodName = expression.text;
    }

    if (!methodName) {
      return null;
    }

    // Check if it's a database read or mutation operation
    const databaseOperations = [
      // Read operations
      'findById', 'findByPk', 'findOne', 'findUnique', 'findFirst',
      'getById', 'fetch', 'fetchById', 'retrieve', 'load',
      'select', 'query', 'where',
      // Delete operations
      'destroy', 'destroyAll',
      'deleteOne', 'deleteMany', 'deleteById', 'remove', 'removeById',
      'findByIdAndDelete', 'findByIdAndRemove',
      'findOneAndDelete', 'findOneAndRemove',
      // Update operations
      'update', 'updateOne', 'updateMany', 'updateById',
      'findByIdAndUpdate',
      'findOneAndUpdate', 'findOneAndRemove',
    ];

    if (!databaseOperations.includes(methodName)) {
      return null;
    }

    // Check if database/ORM object
    if (!this.isDatabaseObject(methodName, objectName)) {
      return null;
    }

    // For generic 'query'/'select' methods, only flag if we can confirm raw SQL with user input
    if ((methodName === 'query' || methodName === 'select' || methodName === 'where') && !this.isRawSqlWithUserInput(node)) {
      return null;
    }

    // Check if using user-supplied ID
    const userInputInfo = this.usesUserSuppliedId(node);
    if (!userInputInfo.isUserInput) {
      return null;
    }

    // Check if route has admin middleware — skip flagging for admin-protected routes
    if (this.hasAdminMiddleware(node)) {
      return null;
    }

    // Check if route appears to be a public route (no auth, no req.user references)
    if (this.hasNoAuthMiddleware(node)) {
      return null;
    }

    // Check if there's an authorization check nearby
    const hasAuthCheck = this.hasAuthorizationCheck(node);
    if (hasAuthCheck) {
      return null;
    }

    // Determine confidence based on input directness and method specificity
    let confidence: 'high' | 'medium' | 'low' = 'medium';

    // High confidence: direct req.params/body usage with specific ORM methods
    if (userInputInfo.isDirect) {
      const specificMethods = [
        'findById', 'findByPk', 'findOne', 'findUnique', 'getById',
        'deleteById', 'removeById', 'updateById',
        'findByIdAndDelete', 'findByIdAndUpdate', 'findByIdAndRemove',
      ];
      if (specificMethods.includes(methodName)) {
        confidence = 'high';
      }
    } else if (userInputInfo.isTraced) {
      // High confidence: traced back to request
      confidence = 'high';
    } else if (methodName === 'where' || methodName === 'query' || methodName === 'select') {
      // Lower confidence for generic query methods (may have WHERE user_id)
      confidence = 'low';
    }

    // Determine appropriate suggestion based on operation type
    const mutationMethods = [
      'destroy', 'destroyAll',
      'deleteOne', 'deleteMany', 'deleteById', 'remove', 'removeById',
      'findByIdAndDelete', 'findByIdAndRemove',
      'findOneAndDelete', 'findOneAndRemove',
      'update', 'updateOne', 'updateMany', 'updateById',
      'findByIdAndUpdate', 'findOneAndUpdate',
    ];

    const isMutation = mutationMethods.includes(methodName);
    const operationLabel = isMutation ? 'mutation' : 'query';
    const suggestion = isMutation
      ? 'Add authorization check: verify that the authenticated user owns this resource before modifying/deleting it. Example: WHERE id = ? AND user_id = ?'
      : 'Add authorization check: verify that the authenticated user owns this resource before fetching it. Example: WHERE id = ? AND user_id = ?';

    return this.createIssue(
      context,
      node,
      `Database ${operationLabel} using user-supplied ID without authorization check - IDOR vulnerability`,
      {
        severity: 'error',
        suggestion,
        confidence,
      }
    );
  }

  /**
   * Check if this looks like a database/ORM object
   */
  private isDatabaseObject(methodName: string, objectName: string | null): boolean {
    // Common ORM/database method names that are unambiguous
    const ormMethods = [
      'findById', 'findByPk', 'findOne', 'findUnique', 'findFirst',
      'get', 'getById',
      'destroy', 'destroyAll',
      'deleteOne', 'deleteMany', 'deleteById', 'removeById',
      'findByIdAndDelete', 'findByIdAndUpdate', 'findByIdAndRemove',
      'findOneAndDelete', 'findOneAndUpdate', 'findOneAndRemove',
      'updateOne', 'updateMany', 'updateById',
    ];

    if (ormMethods.includes(methodName)) {
      return true;
    }

    // Common database/model object names
    if (objectName) {
      const dbObjectPatterns = [
        /^db$/i,
        /database/i,
        /^[A-Z].*Model$/,
        /collection/i,
        /repository/i,
        /dao$/i,
        /prisma/i,
        /sequelize/i,
        /mongoose/i,
        /typeorm/i,
        /knex/i,
      ];

      return dbObjectPatterns.some(pattern => pattern.test(objectName));
    }

    return false;
  }

  /**
   * Check if a query/select call contains raw SQL with user-supplied input but no ownership check.
   * Detects: db.query('SELECT * FROM orders WHERE id = $1', [req.params.id])
   *          db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`)
   */
  private isRawSqlWithUserInput(node: ts.CallExpression): boolean {
    if (node.arguments.length === 0) return false;

    const firstArg = node.arguments[0];
    const firstArgText = firstArg.getText();

    // Check if first arg contains SQL keywords
    const sqlKeywords = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b/i;
    if (!sqlKeywords.test(firstArgText)) return false;

    // Check if SQL already has an ownership clause — if so, developer is handling authorization
    const ownershipPatterns = /\b(user_id|owner_id|tenant_id|org_id|organization_id|created_by|account_id|company_id|team_id)\b/i;
    if (ownershipPatterns.test(firstArgText)) return false;

    // Check parameterized args (2nd, 3rd arg etc.) for user input
    for (let i = 1; i < node.arguments.length; i++) {
      const argText = node.arguments[i].getText();
      if (argText.match(/req(uest)?\.(params|query|body)/) ||
          argText.match(/ctx\.(params|query|request\.body)/) ||
          argText.match(/request\.(params|query|payload)/)) {
        return true;
      }
    }

    // Check template literals for interpolated user input
    if (ts.isTemplateExpression(firstArg) || ts.isTaggedTemplateExpression(firstArg)) {
      if (firstArgText.match(/req(uest)?\.(params|query|body)/) ||
          firstArgText.match(/ctx\.(params|query|request\.body)/) ||
          firstArgText.match(/request\.(params|query|payload)/)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if query uses user-supplied ID
   * Returns info about whether it's direct or traced user input
   */
  private usesUserSuppliedId(node: ts.CallExpression): { isUserInput: boolean; isDirect: boolean; isTraced: boolean } {
    if (!node.arguments || node.arguments.length === 0) {
      return { isUserInput: false, isDirect: false, isTraced: false };
    }

    // Check each argument for user input patterns
    for (const arg of node.arguments) {
      const argText = arg.getText();

      // Direct user input patterns (Express, Koa, Hapi)
      const directInputPatterns = [
        // Express/Fastify
        /req(uest)?\.params/,
        /req(uest)?\.query/,
        /req(uest)?\.body/,
        // Koa
        /ctx\.params/,
        /ctx\.query/,
        /ctx\.request\.body/,
        // Hapi
        /request\.params/,
        /request\.query/,
        /request\.payload/,
      ];

      if (directInputPatterns.some(pattern => pattern.test(argText))) {
        return { isUserInput: true, isDirect: true, isTraced: false };
      }

      // Indirect patterns (params., query., body., payload.)
      const indirectInputPatterns = [
        /params\./,
        /query\./,
        /body\./,
        /payload\./,
      ];

      if (indirectInputPatterns.some(pattern => pattern.test(argText))) {
        return { isUserInput: true, isDirect: false, isTraced: false };
      }

      // Check if argument is an identifier that might contain user input
      if (ts.isIdentifier(arg)) {
        const varName = arg.text.toLowerCase();
        if (['id', 'userid', 'documentid', 'resourceid', 'itemid'].includes(varName)) {
          // Trace back to see if it comes from req.params
          const comesFromRequest = this.tracesBackToRequest(arg, node);
          if (comesFromRequest) {
            return { isUserInput: true, isDirect: false, isTraced: true };
          }
          // Only flag untraced 'id' variables if we're inside a route handler context
          // Service-layer functions should not be flagged — auth checks belong in the route handler
          if (this.isInsideRouteHandler(node)) {
            return { isUserInput: true, isDirect: false, isTraced: false };
          }
        }
      }
    }

    return { isUserInput: false, isDirect: false, isTraced: false };
  }

  /**
   * Trace variable back to see if it comes from request
   */
  private tracesBackToRequest(identifier: ts.Identifier, searchScope: ts.Node): boolean {
    const varName = identifier.text;
    let comesFromRequest = false;

    // Search backwards in the same function
    let currentScope = searchScope.parent;
    while (currentScope && !ts.isSourceFile(currentScope)) {
      traverse(currentScope, (node) => {
        // Look for variable declarations: const id = req.params.id
        if (ts.isVariableDeclaration(node)) {
          if (ts.isIdentifier(node.name) && node.name.text === varName) {
            if (node.initializer) {
              const initText = node.initializer.getText();
              if (initText.match(/req(uest)?\.(params|query|body)/) ||
                  initText.match(/ctx\.(params|query|request\.body)/) ||
                  initText.match(/request\.(params|query|payload)/)) {
                comesFromRequest = true;
              }
            }
          }
        }

        // Look for destructuring: const { id } = req.params
        if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name)) {
          for (const element of node.name.elements) {
            if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
              if (element.name.text === varName && node.initializer) {
                const initText = node.initializer.getText();
                if (initText.match(/req(uest)?\.(params|query|body)/) ||
                    initText.match(/ctx\.(params|query|request\.body)/) ||
                    initText.match(/request\.(params|query|payload)/)) {
                  comesFromRequest = true;
                }
              }
            }
          }
        }
      });

      currentScope = currentScope.parent;
    }

    return comesFromRequest;
  }

  /**
   * Check if there's an authorization check nearby
   */
  private hasAuthorizationCheck(queryNode: ts.Node): boolean {
    // Check in the surrounding function
    let functionScope = queryNode.parent;
    while (functionScope && !this.isFunctionLike(functionScope)) {
      functionScope = functionScope.parent;
    }

    if (!functionScope) {
      return false;
    }

    let hasCheck = false;

    traverse(functionScope, (node) => {
      // Check for authorization patterns
      if (ts.isIfStatement(node)) {
        const conditionText = node.expression.getText();

        if (IDORDetector.AUTH_PATTERNS.some(pattern => pattern.test(conditionText))) {
          hasCheck = true;
        }
      }

      if (ts.isConditionalExpression(node)) {
        const conditionText = node.condition.getText();

        if (IDORDetector.AUTH_PATTERNS.some(pattern => pattern.test(conditionText))) {
          hasCheck = true;
        }
      }

      // Check for WHERE clauses with ownership fields
      if (ts.isCallExpression(node)) {
        const text = node.getText();

        if (text.match(/where.*(user_id|userId|owner_id|ownerId|supplier_id|supplierId|org_id|orgId|organization_id|organizationId|tenant_id|tenantId|company_id|companyId|team_id|teamId|account_id|accountId|created_by|createdBy)/i)) {
          hasCheck = true;
        }

        if (text.match(/(user_id|userId|owner_id|ownerId|supplier_id|supplierId|org_id|orgId|organization_id|organizationId|tenant_id|tenantId|company_id|companyId|team_id|teamId|account_id|accountId|created_by|createdBy)\s*=/i)) {
          hasCheck = true;
        }

        // Check for authorization function calls: canAccess(user, doc), authorize(req, resource), etc.
        const callExpr = node.expression;
        let callName: string | null = null;

        if (ts.isIdentifier(callExpr)) {
          callName = callExpr.text;
        } else if (ts.isPropertyAccessExpression(callExpr)) {
          callName = callExpr.name.text;
        }

        if (callName) {
          const authFunctionPatterns = [
            /^(can|check|verify|validate|assert|require)(Access|Permission|Auth|Owner|Ownership|Role|Roles)$/i,
            /^(authorize|authorise|isAuthorized|isOwner|isAllowed|isPermitted)$/i,
            /^(hasPermission|hasAccess|hasRole|hasOwnership|belongsToUser)$/i,
            /^(enforceAccess|enforceOwnership|enforcePermission|enforceAuth)$/i,
            /^guard$/i,
          ];

          if (authFunctionPatterns.some(pattern => pattern.test(callName!))) {
            hasCheck = true;
          }
        }
      }

      // Check for middleware/guard decorators (NestJS)
      if (ts.canHaveDecorators(node)) {
        const decorators = ts.getDecorators(node);
        if (decorators) {
          for (const decorator of decorators) {
            const decoratorText = decorator.getText();
            if (decoratorText.match(/UseGuards|@Auth|@Roles|@RequireAuth/)) {
              hasCheck = true;
            }
          }
        }
      }
    });

    return hasCheck;
  }

  /**
   * Check if the route registration has admin/role-checking middleware.
   * Looks for middleware arguments in route handler calls (e.g., app.get('/path', isAdmin, handler))
   * and skips IDOR flagging if admin middleware is detected.
   */
  private hasAdminMiddleware(queryNode: ts.Node): boolean {
    // Walk up to find the enclosing route registration call
    const routeCall = this.findEnclosingRouteCall(queryNode);
    if (!routeCall) {
      return false;
    }

    // Admin/role-checking middleware function names
    const adminMiddlewareNames = [
      'isAdmin', 'requireAdmin', 'adminOnly',
      'requireRole', 'checkRole', 'authorize',
      'rbac', 'hasRole', 'ensureAdmin',
    ];

    // Check middleware arguments (everything between the path and the last argument which is the handler)
    // Pattern: app.get('/path', middleware1, middleware2, handler)
    const args = routeCall.arguments;
    if (args.length < 2) {
      return false;
    }

    // Middleware args are between the first (path) and last (handler) arguments
    for (let i = 1; i < args.length - 1; i++) {
      const arg = args[i];
      const argText = arg.getText();

      // Check if the middleware is a known admin function name
      if (ts.isIdentifier(arg)) {
        if (adminMiddlewareNames.some(name => name.toLowerCase() === arg.text.toLowerCase())) {
          return true;
        }
      }

      // Check if it's a call expression like requireRole('admin') or authorize('admin')
      if (ts.isCallExpression(arg)) {
        const callExpr = arg.expression;
        let callName: string | null = null;

        if (ts.isIdentifier(callExpr)) {
          callName = callExpr.text;
        } else if (ts.isPropertyAccessExpression(callExpr)) {
          callName = callExpr.name.text;
        }

        if (callName && adminMiddlewareNames.some(name => name.toLowerCase() === callName!.toLowerCase())) {
          return true;
        }

        // Check for string arguments like 'admin', 'superadmin' passed to middleware functions
        for (const callArg of arg.arguments) {
          if (ts.isStringLiteral(callArg)) {
            const value = callArg.text.toLowerCase();
            if (value === 'admin' || value === 'superadmin' || value === 'super_admin') {
              return true;
            }
          }
        }
      }

      // Check the text representation for admin-related patterns
      if (argText.match(/\b(admin|superadmin|super_admin)\b/i)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if the route appears to be a public route with no authentication middleware.
   * Public routes don't need ownership checks, so skip IDOR flagging.
   * Conservative: only skip if the route also doesn't reference req.user or req.session.user.
   */
  private hasNoAuthMiddleware(queryNode: ts.Node): boolean {
    // Walk up to find the enclosing route registration call
    const routeCall = this.findEnclosingRouteCall(queryNode);
    if (!routeCall) {
      return false;
    }

    const args = routeCall.arguments;
    if (args.length < 2) {
      return false;
    }

    // Authentication middleware names to look for
    const authMiddlewareNames = [
      'authenticate', 'requireAuth', 'ensureAuthenticated',
      'isAuthenticated', 'auth', 'jwt', 'verifyToken',
      'requireLogin', 'checkAuth', 'protect',
    ];

    let hasAuthMiddleware = false;

    // Check middleware arguments between path and handler
    for (let i = 1; i < args.length - 1; i++) {
      const arg = args[i];

      if (ts.isIdentifier(arg)) {
        if (authMiddlewareNames.some(name => name.toLowerCase() === arg.text.toLowerCase())) {
          hasAuthMiddleware = true;
          break;
        }
      }

      if (ts.isCallExpression(arg)) {
        const callExpr = arg.expression;
        let callName: string | null = null;

        if (ts.isIdentifier(callExpr)) {
          callName = callExpr.text;
        } else if (ts.isPropertyAccessExpression(callExpr)) {
          callName = callExpr.name.text;
        }

        if (callName && authMiddlewareNames.some(name => name.toLowerCase() === callName!.toLowerCase())) {
          hasAuthMiddleware = true;
          break;
        }

        // Check for passport.authenticate()
        if (ts.isPropertyAccessExpression(callExpr)) {
          const objName = this.getObjectName(callExpr.expression);
          if (objName?.toLowerCase() === 'passport' && callExpr.name.text === 'authenticate') {
            hasAuthMiddleware = true;
            break;
          }
        }
      }

      // Broader text-based check for auth-related middleware
      const argText = arg.getText();
      if (authMiddlewareNames.some(name => argText.toLowerCase().includes(name.toLowerCase()))) {
        hasAuthMiddleware = true;
        break;
      }

      // Check for passport.authenticate in text form
      if (argText.match(/passport\.authenticate/i)) {
        hasAuthMiddleware = true;
        break;
      }
    }

    // If auth middleware IS present, this is not a public route — don't skip
    if (hasAuthMiddleware) {
      return false;
    }

    // No auth middleware found. Now check conservatively: does the handler body
    // reference req.user or req.session.user? If so, it's NOT a public route
    // (auth might be applied globally), so don't skip.
    const handler = args[args.length - 1];
    const handlerText = handler.getText();

    if (handlerText.match(/req(uest)?\.user/) || handlerText.match(/req(uest)?\.session\.user/) ||
        handlerText.match(/ctx\.state\.user/) || handlerText.match(/request\.auth/)) {
      // Handler references req.user / ctx.state.user / request.auth — auth is likely applied elsewhere (globally),
      // so this is NOT a public route. Don't skip IDOR flagging.
      return false;
    }

    // No auth middleware and no req.user references — likely a public route, skip IDOR flagging
    return true;
  }

  /**
   * Find the enclosing route registration call expression.
   * Looks for patterns like app.get(), router.post(), server.route(), etc.
   */
  private findEnclosingRouteCall(node: ts.Node): ts.CallExpression | null {
    const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'all'];

    let current = node.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isCallExpression(current)) {
        const expr = current.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const methodName = expr.name.text.toLowerCase();

          // Express/Koa style: app.get(), router.post(), etc.
          if (httpMethods.includes(methodName)) {
            const objName = this.getObjectName(expr.expression);
            if (objName && /^(app|router|route|server|api)$/i.test(objName)) {
              return current;
            }
          }

          // Hapi style: server.route()
          if (methodName === 'route') {
            const objName = this.getObjectName(expr.expression);
            if (objName && /^(server|hapi)$/i.test(objName)) {
              return current;
            }
          }
        }
      }
      current = current.parent;
    }

    return null;
  }

  /**
   * Check if the node is inside a route handler context.
   * Route handlers are:
   * 1. Callbacks passed to app.get(), router.post(), etc.
   * 2. Functions with (req, res) parameters (Express/Fastify)
   * 3. Functions with (ctx) or (ctx, next) parameters (Koa)
   * 4. Functions with (request, h) parameters (Hapi)
   */
  private isInsideRouteHandler(node: ts.Node): boolean {
    let current: ts.Node | undefined = node.parent;

    while (current && !ts.isSourceFile(current)) {
      // Check if current node is a function-like with route handler parameters
      if (this.isFunctionLike(current)) {
        const funcNode = current as ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction | ts.MethodDeclaration;
        if (funcNode.parameters && funcNode.parameters.length >= 1) {
          const firstParam = funcNode.parameters[0];
          if (ts.isIdentifier(firstParam.name)) {
            const firstName = firstParam.name.text.toLowerCase();

            // Koa style: (ctx) or (ctx, next)
            if (firstName === 'ctx') {
              return true;
            }

            // Express/Fastify/Hapi style: (req, res) or (request, response) or (request, h)
            if (funcNode.parameters.length >= 2) {
              const secondParam = funcNode.parameters[1];
              if (ts.isIdentifier(secondParam.name)) {
                const secondName = secondParam.name.text.toLowerCase();
                if ((firstName === 'req' || firstName === 'request') &&
                    (secondName === 'res' || secondName === 'response' || secondName === 'h')) {
                  return true;
                }
              }
            }
          }
        }
      }

      // Check if we're inside a route registration call (app.get, router.post, server.route, etc.)
      if (ts.isCallExpression(current)) {
        const expr = current.expression;
        if (ts.isPropertyAccessExpression(expr)) {
          const methodName = expr.name.text.toLowerCase();
          const httpMethods = ['get', 'post', 'put', 'patch', 'delete', 'all'];

          // Express/Koa style: app.get(), router.post(), etc.
          if (httpMethods.includes(methodName)) {
            const objName = this.getObjectName(expr.expression);
            if (objName && /^(app|router|route|server|api)$/i.test(objName)) {
              return true;
            }
          }

          // Hapi style: server.route()
          if (methodName === 'route') {
            const objName = this.getObjectName(expr.expression);
            if (objName && /^(server|hapi)$/i.test(objName)) {
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
   * Check if node is function-like
   */
  private isFunctionLike(node: ts.Node): boolean {
    return (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    );
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
}

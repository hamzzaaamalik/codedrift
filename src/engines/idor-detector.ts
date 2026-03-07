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
    /customerId/,
    /customer_id/,
    /merchantId/,
    /merchant_id/,
    /vendorId/,
    /vendor_id/,
    /memberId/,
    /member_id/,
    /clientId/,
    /client_id/,
    /groupId/,
    /group_id/,
    /sellerId/,
    /seller_id/,
    /buyerId/,
    /buyer_id/,
    /patientId/,
    /patient_id/,
    /employeeId/,
    /employee_id/,
    /managerId/,
    /manager_id/,
    /workspaceId/,
    /workspace_id/,
    /projectId/,
    /project_id/,
    // Policy / RBAC / capability-based authorization
    /isAuthorized/,
    /checkPermission/,
    /policy\.check/,
    /policy\.evaluate/,
    /policy\.enforce/,
    /acl\.check/,
    /acl\.verify/,
    /rbac\.check/,
    /permissions\.check/,
    /ability\.can/,
    /accessibleBy/,
  ];

  /** Ownership column names in WHERE clauses — if key matches, query is ownership-scoped */
  private static readonly OWNERSHIP_COLUMNS = new Set<string>([
    'userId', 'user_id', 'UserId',
    'ownerId', 'owner_id', 'OwnerId',
    'createdBy', 'created_by', 'CreatedBy',
    'authorId', 'author_id', 'AuthorId',
    'supplierId', 'supplier_id', 'SupplierId',
    'organizationId', 'organization_id', 'OrganizationId',
    'orgId', 'org_id', 'OrgId',
    'tenantId', 'tenant_id', 'TenantId',
    'companyId', 'company_id', 'CompanyId',
    'teamId', 'team_id', 'TeamId',
    'accountId', 'account_id', 'AccountId',
    'customerId', 'customer_id', 'CustomerId',
    'assignedTo', 'assigned_to', 'AssignedTo',
    'belongsTo', 'belongs_to',
    'merchantId', 'merchant_id', 'MerchantId',
    'vendorId', 'vendor_id', 'VendorId',
    'shopId', 'shop_id', 'ShopId',
    'storeId', 'store_id', 'StoreId',
    'workspaceId', 'workspace_id', 'WorkspaceId',
    'projectId', 'project_id', 'ProjectId',
    'memberId', 'member_id', 'MemberId',
    'clientId', 'client_id', 'ClientId',
    'groupId', 'group_id', 'GroupId',
    'sellerId', 'seller_id', 'SellerId',
    'buyerId', 'buyer_id', 'BuyerId',
    'patientId', 'patient_id', 'PatientId',
    'employeeId', 'employee_id', 'EmployeeId',
    'departmentId', 'department_id', 'DepartmentId',
    'providerId', 'provider_id', 'ProviderId',
    'managerId', 'manager_id', 'ManagerId',
    'agentId', 'agent_id', 'AgentId',
    'partnerId', 'partner_id', 'PartnerId',
    'practitionerId', 'practitioner_id', 'PractitionerId',
    'senderId', 'sender_id', 'SenderId',
    'recipientId', 'recipient_id', 'RecipientId',
    'requesterId', 'requester_id', 'RequesterId',
    'reviewerId', 'reviewer_id', 'ReviewerId',
    'parentId', 'parent_id', 'ParentId',
  ]);

  /** Regex derived from OWNERSHIP_COLUMNS for text-based fallback matching */
  private static readonly OWNERSHIP_COLUMNS_REGEX = new RegExp(
    '\\b(' + [...IDORDetector.OWNERSHIP_COLUMNS].join('|') + ')\\b'
  );

  /** Auth identity patterns — expressions referencing the authenticated user */
  private static readonly AUTH_IDENTITY_PATTERNS: RegExp[] = [
    // req.user.* (most common)
    /req(uest)?\.user\.\w+/,
    /req(uest)?\.session\.user/,
    /req(uest)?\.session\.passport\.user/,
    /req(uest)?\.session\.userId/,
    // Direct on req (JWT middleware often sets these)
    /req(uest)?\.userId/,
    /req(uest)?\.supplierId/,
    /req(uest)?\.orgId/,
    /req(uest)?\.tenantId/,
    /req(uest)?\.companyId/,
    /req(uest)?\.teamId/,
    /req(uest)?\.accountId/,
    /req(uest)?\.customerId/,
    // Auth0 / express-jwt
    /req(uest)?\.auth\.sub/,
    /req(uest)?\.auth\.userId/,
    /req(uest)?\.auth\.org_id/,
    // JWT token / decoded
    /req(uest)?\.token\.sub/,
    /req(uest)?\.token\.userId/,
    /req(uest)?\.decoded\.id/,
    /req(uest)?\.decoded\.userId/,
    // Custom namespace
    /req(uest)?\.currentUser\.\w+/,
    /req(uest)?\.principal\.\w+/,
    /req(uest)?\.identity\.\w+/,
    /req(uest)?\.context\.userId/,
    // Koa
    /ctx\.state\.user/,
    /ctx\.user\.\w+/,
    /ctx\.auth\.\w+/,
    // Hapi
    /request\.auth\.credentials/,
    // Express res.locals (set by prior middleware)
    /res\.locals\.user/,
    /res\.locals\.userId/,
    // JWT claims (express-jwt v7+, custom middleware)
    /req(uest)?\.claims\.\w+/,
    // GraphQL context
    /context\.user\.\w+/,
    // API key / token / service account identity
    /req(uest)?\.apiKey/,
    /req(uest)?\.token/,
    /req(uest)?\.serviceAccount/,
    /ctx\.apiKey/,
    /ctx\.token/,
    /ctx\.serviceAccount/,
    /\bapiKeyId\b/,
    /\btokenId\b/,
    /\bserviceAccountId\b/,
  ];

  /** Admin/role middleware — skip IDOR entirely for these routes */
  private static readonly ADMIN_MIDDLEWARE = new Set<string>([
    'isadmin', 'requireadmin', 'adminonly',
    'requirerole', 'checkrole', 'authorize',
    'rbac', 'hasrole', 'ensureadmin',
    'issupplieradmin', 'issuperadmin', 'issystemadmin',
    'superadminonly', 'requiresuperadmin', 'guard',
    'checkpermission', 'requirepermission', 'haspermission',
    'requirepermissions', 'checkpermissions',
    'acl', 'requirescope', 'checkscope',
    'verifyrole', 'ensurerole',
    'rolemiddleware', 'permissionmiddleware',
    'ismanager', 'ismoderator', 'isstaff',
  ]);

  /** Ownership middleware — the middleware itself IS the ownership check */
  private static readonly OWNERSHIP_MIDDLEWARE = new Set<string>([
    'isowner', 'isresourceowner', 'checkownership',
    'verifyownership', 'belongstouser', 'ensureowner',
    'validateownership', 'requireownership', 'owneronly',
    'checkresourceowner', 'ownermiddleware',
  ]);

  /** Regex patterns for custom admin/role middleware names not in the hardcoded Set */
  private static readonly ADMIN_MIDDLEWARE_PATTERNS = [
    /^require.*(?:admin|role|permission|scope|auth)/i,
    /^check.*(?:admin|role|permission|scope|auth)/i,
    /^ensure.*(?:admin|role|permission|auth)/i,
    /^verify.*(?:role|permission|auth)/i,
    // Matches: adminGuard, adminAuth, adminOnly, adminRequired, roleAuth, permissionAuth, etc.
    // Any middleware whose first word is a role/admin concept and terminates with an
    // access-control suffix is unambiguously an authorization gate.
    /^(?:admin|role|permission|superadmin).*(?:guard|middleware|check|auth|only|required|access|verify)/i,
    // Matches is{Role} convention: isAdmin, isOperationsManager, isCustodianOrOps,
    // isDistributorAdmin, isSuperAdmin, isVendor, etc.
    // Any middleware that starts with 'is' and contains a role/privilege concept
    // is asserting that the caller belongs to that role — it's an authorization gate.
    /^is.*(?:admin|manager|supervisor|operator|moderator|staff|ops|operations|distributor|custodian|vendor|supplier|reseller|executive|director|owner)/i,
    /^can(?:access|manage|delete|update|create|read|write)/i,
    /^has(?:access|role|permission|authority)/i,
  ];

  /** Regex patterns for custom ownership middleware names not in the hardcoded Set */
  private static readonly OWNERSHIP_MIDDLEWARE_PATTERNS = [
    /^(?:require|check|verify|ensure|validate).*(?:owner|ownership)/i,
    /^(?:is|belongs).*(?:owner|resource)/i,
    /^owner.*(?:check|guard|middleware)/i,
  ];

  /** Classify a middleware name as 'admin', 'ownership', or null using both hardcoded Sets and regex patterns. */
  private static classifyMiddleware(name: string): 'admin' | 'ownership' | null {
    const lower = name.toLowerCase();
    if (IDORDetector.ADMIN_MIDDLEWARE.has(lower)) return 'admin';
    if (IDORDetector.OWNERSHIP_MIDDLEWARE.has(lower)) return 'ownership';
    if (IDORDetector.ADMIN_MIDDLEWARE_PATTERNS.some(p => p.test(name))) return 'admin';
    if (IDORDetector.OWNERSHIP_MIDDLEWARE_PATTERNS.some(p => p.test(name))) return 'ownership';
    return null;
  }

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
      'findOneOrFail', 'findUniqueOrThrow', 'findFirstOrThrow',
      'findOneBy', 'findOneByOrFail',
      'getById', 'fetch', 'fetchById', 'retrieve', 'load',
      'select', 'query', 'where', 'first', 'findMany',
      // DynamoDB
      'getItem', 'putItem', 'deleteItem', 'updateItem',
      // Delete operations
      'destroy', 'destroyAll', 'delete', 'del',
      'deleteOne', 'deleteMany', 'deleteById', 'remove', 'removeById',
      'findByIdAndDelete', 'findByIdAndRemove',
      'findOneAndDelete', 'findOneAndRemove',
      // Update operations
      'update', 'updateOne', 'updateMany', 'updateById', 'upsert',
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

    // For generic 'query'/'select'/'first'/'findMany' methods, only flag if we can confirm raw SQL with user input
    const genericMethods = ['query', 'select', 'where', 'first', 'findMany'];
    if (genericMethods.includes(methodName) && !this.isRawSqlWithUserInput(node)) {
      return null;
    }

    // Check if using user-supplied ID
    const userInputInfo = this.usesUserSuppliedId(node);
    if (!userInputInfo.isUserInput) {
      return null;
    }

    // Check if route has admin or ownership middleware — skip IDOR for these
    const middlewareResult = this.checkRouteMiddleware(node);
    if (middlewareResult === 'admin' || middlewareResult === 'ownership') {
      return null;
    }

    // Check if router/app-level middleware handles auth/ownership for all routes
    if (this.hasRouterLevelAuthMiddleware(node)) {
      return null;
    }

    // Check if route appears to be a public route (no auth, no req.user references)
    if (this.hasNoAuthMiddleware(node)) {
      return null;
    }

    // Skip authentication endpoints (login, register, forgot-password, etc.)
    // These inherently query by user-supplied credentials — that's their purpose
    if (this.isAuthenticationRoute(node)) {
      return null;
    }

    // Skip shared reference-data queries (lookup tables like Country, DegreeLevel, Industry)
    // These have no per-user ownership concept — the concern is missing role auth, not IDOR
    if (this.isReferenceDataQuery(node, methodName)) {
      return null;
    }

    // Check if the WHERE clause itself contains ownership columns (AST-level)
    if (this.hasWhereClauseOwnership(node)) {
      return null;
    }

    // Check if the database object name implies tenant/scoped ownership (e.g., tenantDb, scopedRepo)
    if (objectName && /^(tenant|scoped|org|user)(Db|Database|Repo|Repository|Connection|Pool|Client|Query)/i.test(objectName)) {
      return null;
    }

    // Check if there's an authorization check nearby (text-based scan of function body)
    if (this.hasAuthorizationCheck(node)) {
      return null;
    }

    // Check for post-query ownership pattern: fetch then compare with auth identity
    if (this.hasPostQueryOwnershipCheck(node)) {
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

    // Taint analysis: refine confidence if taint tracking is available
    const functionScope = this.findEnclosingFunction(node);
    if (functionScope) {
      for (const arg of node.arguments) {
        if (!ts.isIdentifier(arg)) continue;
        const taintResult = this.checkTaint(context, arg, functionScope);
        if (taintResult === null) continue; // taint unavailable, fall through to heuristic
        if (taintResult.tainted && taintResult.sanitized) {
          // Sanitized user input — not an IDOR risk
          return null;
        }
        if (taintResult.tainted && !taintResult.sanitized) {
          // Confirmed user-controlled and unsanitized — high confidence
          confidence = 'high';
        }
        if (!taintResult.tainted) {
          // Not user-controlled — lower confidence to heuristic-only
          confidence = 'low';
        }
      }
    }

    // Determine appropriate suggestion based on operation type
    const mutationMethods = [
      'destroy', 'destroyAll', 'delete', 'del',
      'deleteOne', 'deleteMany', 'deleteById', 'remove', 'removeById',
      'findByIdAndDelete', 'findByIdAndRemove',
      'findOneAndDelete', 'findOneAndRemove',
      'deleteItem', 'putItem', 'updateItem',
      'update', 'updateOne', 'updateMany', 'updateById', 'upsert',
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
      'findOneOrFail', 'findUniqueOrThrow', 'findFirstOrThrow',
      'findOneBy', 'findOneByOrFail',
      'get', 'getById', 'getItem', 'putItem', 'deleteItem', 'updateItem',
      'destroy', 'destroyAll',
      'deleteOne', 'deleteMany', 'deleteById', 'removeById',
      'findByIdAndDelete', 'findByIdAndUpdate', 'findByIdAndRemove',
      'findOneAndDelete', 'findOneAndUpdate', 'findOneAndRemove',
      'updateOne', 'updateMany', 'updateById', 'upsert',
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
        /firebase/i,
        /firestore/i,
        /supabase/i,
        /dynamodb/i,
        /dynamo/i,
        /^mongo$/i,
        /^Store$/,
        /drizzle/i,
        /objection/i,
        /bookshelf/i,
        /mikro/i,
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
    if (IDORDetector.OWNERSHIP_COLUMNS_REGEX.test(firstArgText)) return false;

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
          // Trace back to see if it comes from req.params or auth identity
          const traceResult = this.tracesBackToRequest(arg, node);
          if (traceResult.comesFromRequest) {
            if (traceResult.isAuthIdentity) {
              // Variable is auth identity (req.userId, req.auth.sub, etc.) — NOT user input
              return { isUserInput: false, isDirect: false, isTraced: false };
            }
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
   * Trace variable back to see if it comes from request user input or auth identity.
   * Returns { comesFromRequest: true, isAuthIdentity: false } for user input (req.params, req.body, req.query)
   * Returns { comesFromRequest: true, isAuthIdentity: true } for auth identity (req.userId, req.auth.sub, etc.)
   */
  private tracesBackToRequest(identifier: ts.Identifier, searchScope: ts.Node): { comesFromRequest: boolean; isAuthIdentity: boolean } {
    const varName = identifier.text;
    let comesFromRequest = false;
    let isAuthIdentity = false;

    // Search backwards in the same function
    let currentScope = searchScope.parent;
    while (currentScope && !ts.isSourceFile(currentScope)) {
      traverse(currentScope, (node) => {
        if (comesFromRequest) return; // Already found

        // Look for variable declarations: const id = req.params.id / const userId = req.userId
        if (ts.isVariableDeclaration(node)) {
          if (ts.isIdentifier(node.name) && node.name.text === varName) {
            if (node.initializer) {
              const initText = node.initializer.getText();
              // User input sources
              if (initText.match(/req(uest)?\.(params|query|body)/) ||
                  initText.match(/ctx\.(params|query|request\.body)/) ||
                  initText.match(/request\.(params|query|payload)/)) {
                comesFromRequest = true;
              }
              // Auth identity sources: const userId = req.userId, const sub = req.auth.sub, etc.
              if (IDORDetector.AUTH_IDENTITY_PATTERNS.some(p => p.test(initText))) {
                comesFromRequest = true;
                isAuthIdentity = true;
              }
            }
          }
        }

        // Look for destructuring: const { id } = req.params / const { supplierId } = req
        if (ts.isVariableDeclaration(node) && ts.isObjectBindingPattern(node.name)) {
          for (const element of node.name.elements) {
            if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
              if (element.name.text === varName && node.initializer) {
                const initText = node.initializer.getText();
                // User input destructuring: const { id } = req.params
                if (initText.match(/req(uest)?\.(params|query|body)/) ||
                    initText.match(/ctx\.(params|query|request\.body)/) ||
                    initText.match(/request\.(params|query|payload)/)) {
                  comesFromRequest = true;
                }
                // Identity destructuring from req directly: const { supplierId } = req
                if (/^req(uest)?$/.test(initText) && IDORDetector.OWNERSHIP_COLUMNS.has(varName)) {
                  comesFromRequest = true;
                  isAuthIdentity = true;
                }
                // Identity destructuring from auth namespace: const { userId } = req.auth
                if (/req(uest)?\.(auth|user|token|decoded|session|currentUser|principal|identity|context)$/.test(initText)) {
                  comesFromRequest = true;
                  isAuthIdentity = true;
                }
              }
            }
          }
        }
      });

      currentScope = currentScope.parent;
    }

    return { comesFromRequest, isAuthIdentity };
  }

  /**
   * Check if there's an authorization check in the enclosing function.
   * Single traversal calling focused sub-methods for efficiency.
   */
  private hasAuthorizationCheck(queryNode: ts.Node): boolean {
    let functionScope = queryNode.parent;
    while (functionScope && !this.isFunctionLike(functionScope)) {
      functionScope = functionScope.parent;
    }
    if (!functionScope) return false;

    let hasCheck = false;

    traverse(functionScope, (node) => {
      if (hasCheck) return;
      if (this.isAuthCondition(node)) { hasCheck = true; return; }
      if (this.isAuthFunctionCall(node)) { hasCheck = true; return; }
      if (this.isAuthDecorator(node)) { hasCheck = true; return; }
      if (this.isOwnershipWhereText(node)) { hasCheck = true; return; }
    });

    return hasCheck;
  }

  /** Check if/ternary conditions for auth patterns */
  private isAuthCondition(node: ts.Node): boolean {
    if (ts.isIfStatement(node)) {
      const condText = node.expression.getText();
      if (IDORDetector.AUTH_PATTERNS.some(p => p.test(condText))) return true;
      if (IDORDetector.AUTH_IDENTITY_PATTERNS.some(p => p.test(condText))) return true;
    }
    if (ts.isConditionalExpression(node)) {
      const condText = node.condition.getText();
      if (IDORDetector.AUTH_PATTERNS.some(p => p.test(condText))) return true;
      if (IDORDetector.AUTH_IDENTITY_PATTERNS.some(p => p.test(condText))) return true;
    }
    return false;
  }

  /** Check for authorization function calls: canAccess(), checkOwnership(), etc. */
  private isAuthFunctionCall(node: ts.Node): boolean {
    if (!ts.isCallExpression(node)) return false;
    const callExpr = node.expression;
    let callName: string | null = null;

    if (ts.isIdentifier(callExpr)) {
      callName = callExpr.text;
    } else if (ts.isPropertyAccessExpression(callExpr)) {
      callName = callExpr.name.text;
    }

    if (!callName) return false;

    const authFunctionPatterns = [
      /^(can|check|verify|validate|assert|require)(Access|Permission|Auth|Owner|Ownership|Role|Roles)$/i,
      /^(authorize|authorise|isAuthorized|isOwner|isAllowed|isPermitted)$/i,
      /^(hasPermission|hasAccess|hasRole|hasOwnership|belongsToUser)$/i,
      /^(enforceAccess|enforceOwnership|enforcePermission|enforceAuth)$/i,
      /^(ensure)(User)?(Owns|Ownership|Access|Permission|Auth)/i,
      /^guard$/i,
      // Throw-based authorization
      /^throw(If|Unless)(Not)?(Owner|Authorized|Allowed|Permitted)/i,
      // CRUD-scoped auth
      /^(assert|check|verify)Can(Read|Write|Delete|Update|Access|Modify|View|Edit)/i,
      // Resource-level
      /^(checkResource|verifyResource)(Access|Ownership|Permission)/i,
      // Scope-based (OAuth)
      /^(require|check|verify)Scope$/i,
      // Policy-based (CASL, etc.)
      /^(can|cannot|ability\.can|ability\.cannot)$/i,
      /^(checkPolicy|enforcePolicy|evaluatePolicy)$/i,
      // CASL accessibleBy
      /^accessibleBy$/i,
    ];

    return authFunctionPatterns.some(p => p.test(callName!));
  }

  /** Check for NestJS guard/auth decorators */
  private isAuthDecorator(node: ts.Node): boolean {
    if (!ts.canHaveDecorators(node)) return false;
    const decorators = ts.getDecorators(node);
    if (!decorators) return false;
    return decorators.some(d => {
      const text = d.getText();
      return /UseGuards|@Auth|@Roles|@RequireAuth|@Authorize|@RequirePermission|@Permissions|@CheckPolicies|@Policy|@Secured|@RolesGuard/.test(text);
    });
  }

  /** Text-based fallback: check call expression text for ownership columns or auth identity */
  private isOwnershipWhereText(node: ts.Node): boolean {
    if (!ts.isCallExpression(node)) return false;

    // Skip response/utility calls to avoid false suppression
    // res.json({ user: req.user.name }) is NOT an ownership check
    const expr = node.expression;
    if (ts.isPropertyAccessExpression(expr)) {
      const objName = this.getObjectName(expr.expression);
      if (objName && /^(res|response|reply|ctx|console|logger|log)$/i.test(objName)) return false;
      const methodName = expr.name.text;
      if (/^(json|send|render|redirect|status|write|end|pipe|emit|dispatch|next|log|error|warn|info|debug|throw)$/i.test(methodName)) return false;
    }

    const text = node.getText();
    if (IDORDetector.OWNERSHIP_COLUMNS_REGEX.test(text)) return true;
    if (IDORDetector.AUTH_IDENTITY_PATTERNS.some(p => p.test(text))) return true;
    return false;
  }

  /**
   * Check if the route registration has admin, ownership, or role-checking middleware.
   * Returns 'admin' for admin/role middleware, 'ownership' for ownership-checking middleware, 'none' otherwise.
   */
  private checkRouteMiddleware(queryNode: ts.Node): 'admin' | 'ownership' | 'none' {
    const routeCall = this.findEnclosingRouteCall(queryNode);
    if (!routeCall) {
      return 'none';
    }

    const args = routeCall.arguments;
    if (args.length < 2) {
      return 'none';
    }

    // Middleware args are between the first (path) and last (handler) arguments
    for (let i = 1; i < args.length - 1; i++) {
      const arg = args[i];
      const argText = arg.getText();

      // Extract middleware name for Set lookups
      let middlewareName: string | null = null;

      if (ts.isIdentifier(arg)) {
        middlewareName = arg.text;
      } else if (ts.isCallExpression(arg)) {
        const callExpr = arg.expression;
        if (ts.isIdentifier(callExpr)) {
          middlewareName = callExpr.text;
        } else if (ts.isPropertyAccessExpression(callExpr)) {
          middlewareName = callExpr.name.text;
        }
      }

      if (middlewareName) {
        const classification = IDORDetector.classifyMiddleware(middlewareName);
        if (classification) return classification;
      }

      // Check call expression string arguments for 'admin'/'superadmin'
      if (ts.isCallExpression(arg)) {
        for (const callArg of arg.arguments) {
          if (ts.isStringLiteral(callArg)) {
            const value = callArg.text.toLowerCase();
            if (value === 'admin' || value === 'superadmin' || value === 'super_admin') {
              return 'admin';
            }
          }
        }
      }

      // Text-based fallback for admin patterns
      if (argText.match(/\b(admin|superadmin|super_admin)\b/i)) {
        return 'admin';
      }
    }

    return 'none';
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

    // Check if route path explicitly indicates a public endpoint
    const firstArg = args[0];
    if (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg)) {
      const routePath = firstArg.text.toLowerCase();
      const publicPathPatterns = ['/public', '/open', '/guest', '/anonymous', '/shared', '/health', '/ping', '/status', '/version'];
      if (publicPathPatterns.some(p => routePath.includes(p))) {
        return true; // Explicitly public route — skip IDOR
      }
    }

    // No auth middleware found. Now check conservatively: does the handler body
    // reference req.user or req.session.user? If so, it's NOT a public route
    // (auth might be applied globally), so don't skip.
    const handler = args[args.length - 1];
    const handlerText = handler.getText();

    if (IDORDetector.AUTH_IDENTITY_PATTERNS.some(p => p.test(handlerText))) {
      // Handler references an auth identity source — auth is likely applied elsewhere (globally),
      // so this is NOT a public route. Don't skip IDOR flagging.
      return false;
    }

    // No auth middleware and no req.user references — likely a public route, skip IDOR flagging
    return true;
  }

  /**
   * Detect authentication routes (login, register, forgot-password, etc.)
   * These inherently query by user-supplied credentials — not IDOR.
   */
  private isAuthenticationRoute(queryNode: ts.Node): boolean {
    const authKeywords = [
      'login', 'signin', 'signIn', 'sign_in',
      'register', 'signup', 'signUp', 'sign_up',
      'forgot', 'forgotPassword', 'forgotpassword', 'forgot_password',
      'resetPassword', 'resetpassword', 'reset_password',
      'verifyEmail', 'verifyemail', 'verify_email',
      'confirm', 'activate', 'authenticate',
      'refreshToken', 'refresh_token',
    ];

    // Strategy 1: Check route path from router.post('/login', ...)
    const routeCall = this.findEnclosingRouteCall(queryNode);
    if (routeCall && routeCall.arguments.length > 0) {
      const firstArg = routeCall.arguments[0];
      if (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg)) {
        const routePath = firstArg.text.toLowerCase();
        const pathPatterns = authKeywords.map(k => '/' + k.toLowerCase());
        if (pathPatterns.some(p => routePath.includes(p))) {
          return true;
        }
      }
    }

    // Strategy 2: Check enclosing function name (for controller-style: const login = function(req, res){})
    let current: ts.Node | undefined = queryNode.parent;
    while (current && !ts.isSourceFile(current)) {
      let funcName: string | null = null;

      // Named function declaration: function login(req, res) {}
      if (ts.isFunctionDeclaration(current) && current.name) {
        funcName = current.name.text;
      }
      // Variable assignment: const login = function(req, res) {} or const login = (req, res) => {}
      if ((ts.isFunctionExpression(current) || ts.isArrowFunction(current)) && current.parent) {
        const parent = current.parent;
        if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
          funcName = parent.name.text;
        }
        // Property assignment: module.exports.login = function() {}
        if (ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
          funcName = parent.name.text;
        }
      }

      if (funcName) {
        const lower = funcName.toLowerCase();
        // Match exact or compound names: login, signupAdmin, facebookLogin, etc.
        if (authKeywords.some(k => lower === k.toLowerCase() || lower.startsWith(k.toLowerCase()) || lower.endsWith(k.toLowerCase()))) {
          return true;
        }
      }
      current = current.parent;
    }

    return false;
  }

  /**
   * Detect queries on shared reference/lookup data (countries, industries, degree levels, etc.)
   * These have no per-user ownership — IDOR doesn't apply.
   *
   * Heuristic: if the query filter uses `name` (not `_id`/`id`) as the key, AND
   * the method is a read-or-create pattern (findOne + nearby create/save), it's a
   * reference data duplicate check. Also skip when the object name itself is a
   * well-known reference-data model.
   */
  private isReferenceDataQuery(queryNode: ts.CallExpression, methodName: string): boolean {
    // Only applies to findOne/findOneBy — the common duplicate-check method
    if (methodName !== 'findOne' && methodName !== 'findOneBy') return false;

    // Check if the query filter key is 'name', 'email', 'cnic', 'code', 'slug', 'title'
    // (non-ID fields used for duplicate checking, not for accessing a specific user resource)
    const filterArg = queryNode.arguments[0];
    if (!filterArg || !ts.isObjectLiteralExpression(filterArg)) return false;

    const filterKeys = filterArg.properties
      .filter((p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p))
      .map(p => ts.isIdentifier(p.name) ? p.name.text : p.name.getText());

    // If the only filter key is a non-ID field, check for creation context
    const nonIdFields = new Set(['name', 'title', 'code', 'slug', 'label', 'key', 'type']);
    const hasOnlyNonIdFields = filterKeys.length > 0 && filterKeys.every(k => nonIdFields.has(k));

    if (hasOnlyNonIdFields) {
      // Check if there's a creation call nearby (new Model(), Model.create(), .save())
      // indicating this is a duplicate check before insert
      const functionScope = this.findEnclosingFunction(queryNode);
      if (functionScope) {
        const bodyText = functionScope.getText();
        if (/\bnew\s+[A-Z]\w*\s*\(/.test(bodyText) || /\.create\s*\(/.test(bodyText) || /\.save\s*\(/.test(bodyText)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Find the enclosing function (arrow, function expression, or method).
   */
  private findEnclosingFunction(node: ts.Node): ts.Node | null {
    let current = node.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) ||
          ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  /**
   * AST-level check for ownership columns in the WHERE clause of the query call.
   * Handles: object literal WHERE, Prisma nested, spread scope, chained .where(), .scope()
   */
  private hasWhereClauseOwnership(queryNode: ts.CallExpression): boolean {
    // Check arguments of the query call for object literals containing ownership keys
    for (const arg of queryNode.arguments) {
      if (ts.isObjectLiteralExpression(arg)) {
        // Look for a 'where' property or check top-level keys directly
        for (const prop of arg.properties) {
          // { where: { userId: x } }
          if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name) && prop.name.text === 'where') {
            if (ts.isObjectLiteralExpression(prop.initializer)) {
              if (this.objectLiteralHasOwnershipKey(prop.initializer)) return true;
            }
          }
          // Direct ownership key in top-level object: findOne({ userId: x, id: y })
          if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
            if (IDORDetector.OWNERSHIP_COLUMNS.has(prop.name.text)) return true;
          }
          if (ts.isShorthandPropertyAssignment(prop)) {
            if (IDORDetector.OWNERSHIP_COLUMNS.has(prop.name.text)) return true;
          }
          // Spread: { ...req.scope }
          if (ts.isSpreadAssignment(prop)) {
            const spreadText = prop.expression.getText();
            if (/scope/i.test(spreadText)) return true;
          }
        }
      }
    }

    // Check for chained .where() calls in the method chain
    // Walk UP from the query call to find if it's part of: knex('orders').where({id}).where({user_id: x})
    let current: ts.Node = queryNode;
    while (current.parent) {
      // Check: someExpr.where({...}) where we are the child
      if (ts.isPropertyAccessExpression(current.parent) && ts.isIdentifier(current.parent.name)) {
        const accessName = current.parent.name.text;

        // Check if parent.parent is a CallExpression (i.e., this is .where() or .scope() call)
        if (current.parent.parent && ts.isCallExpression(current.parent.parent)) {
          const chainCall = current.parent.parent;

          if (accessName === 'where') {
            for (const chainArg of chainCall.arguments) {
              if (ts.isObjectLiteralExpression(chainArg)) {
                if (this.objectLiteralHasOwnershipKey(chainArg)) return true;
              }
            }
          }

          if (accessName === 'scope') {
            for (const chainArg of chainCall.arguments) {
              const argText = chainArg.getText();
              if (/user|owner|tenant|org/i.test(argText)) return true;
            }
          }

          // Continue up the chain
          current = chainCall;
          continue;
        }
      }

      // Also check DOWN: if queryNode is part of a chain and a sibling .where() has ownership
      // e.g., knex('orders').where({id: x}).where({user_id: y}).first()
      // Here the queryNode might be .first() but .where({user_id}) is in the chain
      if (ts.isCallExpression(current.parent)) {
        const parentCall = current.parent;
        if (ts.isPropertyAccessExpression(parentCall.expression)) {
          const methodName = parentCall.expression.name.text;
          if (methodName === 'where') {
            for (const chainArg of parentCall.arguments) {
              if (ts.isObjectLiteralExpression(chainArg)) {
                if (this.objectLiteralHasOwnershipKey(chainArg)) return true;
              }
            }
          }
          if (methodName === 'scope') {
            for (const chainArg of parentCall.arguments) {
              const argText = chainArg.getText();
              if (/user|owner|tenant|org/i.test(argText)) return true;
            }
          }
        }
      }

      // Continue walking up through non-chain nodes (e.g., parenthesized expressions)
      current = current.parent;
    }

    // Text-based fallback: check full call text for ownership columns
    const fullText = queryNode.getText();
    if (IDORDetector.OWNERSHIP_COLUMNS_REGEX.test(fullText)) return true;

    // Check if any WHERE-clause argument text contains auth identity (e.g., Prisma nested: { user: { id: req.user.id } })
    for (const arg of queryNode.arguments) {
      if (ts.isObjectLiteralExpression(arg)) {
        for (const prop of arg.properties) {
          if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name) && prop.name.text === 'where') {
            const whereText = prop.initializer.getText();
            if (IDORDetector.AUTH_IDENTITY_PATTERNS.some(p => p.test(whereText))) return true;
          }
        }
      }
    }

    return false;
  }

  /**
   * Recursively check if an ObjectLiteralExpression contains ownership column keys.
   * Handles PropertyAssignment, ShorthandPropertyAssignment, SpreadAssignment, and nested objects.
   */
  private objectLiteralHasOwnershipKey(obj: ts.ObjectLiteralExpression): boolean {
    for (const prop of obj.properties) {
      if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
        if (IDORDetector.OWNERSHIP_COLUMNS.has(prop.name.text)) return true;
        // Recurse into nested objects: { user: { id: req.user.id } }
        if (ts.isObjectLiteralExpression(prop.initializer)) {
          if (this.objectLiteralHasOwnershipKey(prop.initializer)) return true;
        }
      }
      if (ts.isShorthandPropertyAssignment(prop)) {
        if (IDORDetector.OWNERSHIP_COLUMNS.has(prop.name.text)) return true;
      }
      if (ts.isSpreadAssignment(prop)) {
        const spreadText = prop.expression.getText();
        if (/scope/i.test(spreadText)) return true;
      }
    }
    return false;
  }

  /**
   * Detect post-query ownership check pattern:
   * const order = await Order.findByPk(req.params.id);
   * if (order.userId !== req.user.id) return res.status(403).json({});
   */
  private hasPostQueryOwnershipCheck(queryNode: ts.CallExpression): boolean {
    // Step 1: Check if query result is assigned to a variable
    let varName: string | null = null;
    let assignParent: ts.Node = queryNode;

    // Walk up through AwaitExpression
    if (assignParent.parent && ts.isAwaitExpression(assignParent.parent)) {
      assignParent = assignParent.parent;
    }
    // Check for VariableDeclaration
    if (assignParent.parent && ts.isVariableDeclaration(assignParent.parent)) {
      const decl = assignParent.parent;
      if (ts.isIdentifier(decl.name)) {
        varName = decl.name.text;
      }
    }

    if (!varName) return false;

    // Step 2: Find enclosing function scope
    let functionScope = queryNode.parent;
    while (functionScope && !this.isFunctionLike(functionScope)) {
      functionScope = functionScope.parent;
    }
    if (!functionScope) return false;

    // Step 3: Scan function body for ownership comparison or helper call
    let hasCheck = false;

    traverse(functionScope, (node) => {
      if (hasCheck) return;

      // Pattern A: if (varName.ownershipColumn !== authIdentity)
      if (ts.isIfStatement(node)) {
        const condText = node.expression.getText();
        // Check if condition references varName.ownershipColumn
        const ownershipAccess = new RegExp(`\\b${varName}\\.\\w+`);
        if (ownershipAccess.test(condText)) {
          // Check if condition also references an auth identity pattern
          if (IDORDetector.AUTH_IDENTITY_PATTERNS.some(p => p.test(condText))) {
            hasCheck = true;
            return;
          }
          // Check if any ownership column name is in the condition
          if (IDORDetector.OWNERSHIP_COLUMNS_REGEX.test(condText)) {
            hasCheck = true;
            return;
          }
        }
      }

      // Pattern B: Helper function calls with varName as argument
      if (ts.isCallExpression(node)) {
        const callExpr = node.expression;
        let callName: string | null = null;

        if (ts.isIdentifier(callExpr)) {
          callName = callExpr.text;
        } else if (ts.isPropertyAccessExpression(callExpr)) {
          callName = callExpr.name.text;
        }

        if (callName) {
          const authHelperPatterns = [
            /^(ensure|check|verify|validate|assert|require)(User)?(Owns|Ownership|Access|Permission|Auth)/i,
            /^(isOwner|isAllowed|isPermitted|belongsToUser)$/i,
          ];

          if (authHelperPatterns.some(p => p.test(callName!))) {
            // Check if one of the arguments references our variable
            const argsText = node.arguments.map(a => a.getText()).join(' ');
            if (argsText.includes(varName)) {
              hasCheck = true;
              return;
            }
          }
        }
      }

      // Pattern C: throw after ownership comparison in same block
      if (ts.isThrowStatement(node)) {
        const throwText = node.getText();
        if (/forbidden|unauthorized|access.denied/i.test(throwText)) {
          // Check if a preceding sibling is an if-statement with ownership check
          // Simple heuristic: if we're in a function with a throw and the variable is used, it's likely auth
          const funcText = functionScope!.getText();
          if (funcText.includes(`${varName}.`) && IDORDetector.OWNERSHIP_COLUMNS_REGEX.test(funcText)) {
            hasCheck = true;
            return;
          }
        }
      }
    });

    return hasCheck;
  }

  /**
   * Check if the file has router-level or app-level middleware that handles auth/ownership.
   * Detects: router.use(checkOwnership), app.use(requireAdmin), etc.
   */
  private hasRouterLevelAuthMiddleware(queryNode: ts.Node): boolean {
    let sourceFile: ts.Node = queryNode;
    while (sourceFile && !ts.isSourceFile(sourceFile)) {
      sourceFile = sourceFile.parent;
    }
    if (!sourceFile) return false;

    let found = false;

    traverse(sourceFile, (node) => {
      if (found) return;
      if (!ts.isCallExpression(node)) return;

      const expr = node.expression;
      if (!ts.isPropertyAccessExpression(expr)) return;
      if (expr.name.text !== 'use') return;

      const objName = this.getObjectName(expr.expression);
      if (!objName || !/^(app|router|route|server|api|fastify|instance)$/i.test(objName)) return;

      for (const arg of node.arguments) {
        let middlewareName: string | null = null;

        if (ts.isIdentifier(arg)) {
          middlewareName = arg.text;
        } else if (ts.isCallExpression(arg)) {
          if (ts.isIdentifier(arg.expression)) {
            middlewareName = arg.expression.text;
          } else if (ts.isPropertyAccessExpression(arg.expression)) {
            middlewareName = arg.expression.name.text;
          }
        }

        if (middlewareName) {
          if (IDORDetector.classifyMiddleware(middlewareName)) { found = true; return; }
        }
      }
    });

    return found;
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

          // Express/Koa/Fastify style: app.get(), router.post(), fastify.get(), etc.
          if (httpMethods.includes(methodName)) {
            const objName = this.getObjectName(expr.expression);
            if (objName && /^(app|router|route|server|api|fastify|instance)$/i.test(objName)) {
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

          // Express/Koa/Fastify style: app.get(), router.post(), fastify.get(), etc.
          if (httpMethods.includes(methodName)) {
            const objName = this.getObjectName(expr.expression);
            if (objName && /^(app|router|route|server|api|fastify|instance)$/i.test(objName)) {
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

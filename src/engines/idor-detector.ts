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

    // Check if it's a database read operation
    const readOperations = [
      'findById', 'findByPk', 'findOne', 'findUnique', 'findFirst',
      'getById', 'fetch', 'fetchById', 'retrieve', 'load',
      'select', 'query', 'where',
    ];

    if (!readOperations.includes(methodName)) {
      return null;
    }

    // Check if database/ORM object
    if (!this.isDatabaseObject(methodName, objectName)) {
      return null;
    }

    // Check if using user-supplied ID
    const usesUserInput = this.usesUserSuppliedId(node);
    if (!usesUserInput) {
      return null;
    }

    // Check if there's an authorization check nearby
    const hasAuthCheck = this.hasAuthorizationCheck(node);
    if (hasAuthCheck) {
      return null;
    }

    return this.createIssue(
      context,
      node,
      `Database query using user-supplied ID without authorization check - IDOR vulnerability`,
      {
        severity: 'error',
        suggestion: 'Add authorization check: verify that the authenticated user owns this resource before fetching it. Example: WHERE id = ? AND user_id = ?',
      }
    );
  }

  /**
   * Check if this looks like a database/ORM object
   */
  private isDatabaseObject(methodName: string, objectName: string | null): boolean {
    // Common ORM/database method names
    const ormMethods = [
      'findById', 'findByPk', 'findOne', 'findUnique', 'findFirst',
      'get', 'getById'
    ];

    if (ormMethods.includes(methodName)) {
      return true;
    }

    // Common database/model object names
    if (objectName) {
      const dbObjectPatterns = [
        /^db$/i,
        /database/i,
        /model/i,
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
   * Check if query uses user-supplied ID
   */
  private usesUserSuppliedId(node: ts.CallExpression): boolean {
    if (!node.arguments || node.arguments.length === 0) {
      return false;
    }

    // Check each argument for user input patterns
    for (const arg of node.arguments) {
      const argText = arg.getText();

      // Direct user input patterns
      const userInputPatterns = [
        /req(uest)?\.params/,
        /req(uest)?\.query/,
        /req(uest)?\.body/,
        /params\./,
        /query\./,
        /body\./,
        /\bid\b/,  // Variable named 'id'
      ];

      if (userInputPatterns.some(pattern => pattern.test(argText))) {
        return true;
      }

      // Check if argument is an identifier that might contain user input
      if (ts.isIdentifier(arg)) {
        const varName = arg.text.toLowerCase();
        if (['id', 'userid', 'documentid', 'resourceid', 'itemid'].includes(varName)) {
          // Trace back to see if it comes from req.params
          const comesFromRequest = this.tracesBackToRequest(arg, node);
          if (comesFromRequest) {
            return true;
          }
        }
      }
    }

    return false;
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
              if (initText.match(/req(uest)?\.(params|query|body)/)) {
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
                if (initText.match(/req(uest)?\.(params|query|body)/)) {
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

        // Common authorization check patterns
        const authPatterns = [
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
        ];

        if (authPatterns.some(pattern => pattern.test(conditionText))) {
          hasCheck = true;
        }
      }

      if (ts.isConditionalExpression(node)) {
        const conditionText = node.condition.getText();

        // Common authorization check patterns
        const authPatterns = [
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
        ];

        if (authPatterns.some(pattern => pattern.test(conditionText))) {
          hasCheck = true;
        }
      }

      // Check for WHERE clauses with user_id
      if (ts.isCallExpression(node)) {
        const text = node.getText();

        if (text.match(/where.*user_id|user_id.*=|userId.*=/i)) {
          hasCheck = true;
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

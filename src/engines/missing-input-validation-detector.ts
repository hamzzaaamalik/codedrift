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
 *
 * Implementation split into sub-modules:
 *   - input-validation/route-detection.ts   — route handler detection across frameworks
 *   - input-validation/usage-tracking.ts    — request data usage + field tracking
 *   - input-validation/validation-checking.ts — validation library + manual checks
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';

import {
  RouteHandler,
  findRouteHandlers,
  hasValidationMiddleware,
} from './input-validation/route-detection.js';
import {
  RequestDataUsage,
  findRequestDataUsage,
  collectFieldNames,
  findValidatedVariables,
  extractExpressValidatorFields,
} from './input-validation/usage-tracking.js';
import {
  detectValidationImports,
  hasValidationInHandler,
  getManuallyValidatedFields,
} from './input-validation/validation-checking.js';

// Re-export sub-module types for external consumers
export type { RouteHandler, RequestDataUsage };
export { hasValidationMiddleware } from './input-validation/route-detection.js';
export { extractExpressValidatorFields } from './input-validation/usage-tracking.js';

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
    const validationImports = detectValidationImports(context.sourceFile);

    // Find all route handlers
    const { handlers: routeHandlers } = findRouteHandlers(context.sourceFile);

    // Check each route handler for input validation
    for (const handler of routeHandlers) {
      const handlerIssues = this.checkHandlerValidation(handler, context, validationImports);
      issues.push(...handlerIssues);
    }

    return issues;
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

    // File operations
    if (usage.source.includes('file')) {
      return { category: 'file-operation', isDangerousOperation: true };
    }
    if (MissingInputValidationDetector.FILE_OP_PATTERNS.test(handlerText)) {
      return { category: 'file-operation', isDangerousOperation: true };
    }

    // DB write operations
    for (const op of MissingInputValidationDetector.DB_WRITE_OPS) {
      if (handlerText.includes(`.${op}(`)) {
        return { category: 'db-write', isDangerousOperation: true };
      }
    }

    // Simple lookup
    if (usage.source.includes('params') && !usage.source.includes('body')) {
      const isSimpleLookup = handlerText.includes('.findbypk(') || handlerText.includes('.findbyid(') || handlerText.includes('.findone(');
      const hasWrite = [...MissingInputValidationDetector.DB_WRITE_OPS].some(op => handlerText.includes(`.${op}(`));
      if (isSimpleLookup && !hasWrite) {
        return { category: 'simple-lookup', isDangerousOperation: false };
      }
    }

    // DB read operations
    for (const op of MissingInputValidationDetector.DB_READ_OPS) {
      if (handlerText.includes(`.${op}(`)) {
        return { category: 'db-read', isDangerousOperation: false };
      }
    }

    // Logging
    if (MissingInputValidationDetector.LOGGING_PATTERNS.test(handlerText)) {
      const hasOtherOps = [...MissingInputValidationDetector.DB_WRITE_OPS, ...MissingInputValidationDetector.DB_READ_OPS]
        .some(op => handlerText.includes(`.${op}(`));
      if (!hasOtherOps) {
        return { category: 'logging', isDangerousOperation: false };
      }
    }

    // Queue/messaging
    if (MissingInputValidationDetector.QUEUE_PATTERNS.test(handlerText)) {
      return { category: 'queue-publish', isDangerousOperation: false };
    }

    return { category: 'unknown', isDangerousOperation: false };
  }

  /**
   * Determine severity based on usage context and validation state.
   */
  private determineSeverity(usage: RequestDataUsage, context: UsageContext, hasWeakValidation: boolean): { severity: 'error' | 'warning' | 'info'; confidence: 'high' | 'medium' | 'low' } {
    if (usage.usageKind === 'spread' || usage.usageKind === 'object-assign' || usage.usageKind === 'dynamic') {
      return { severity: 'error', confidence: 'high' };
    }
    if (usage.source.includes('file')) {
      return { severity: 'error', confidence: 'high' };
    }
    if (hasWeakValidation) {
      return { severity: 'warning', confidence: 'medium' };
    }
    if (usage.source.includes('req.ip')) {
      return { severity: 'info', confidence: 'low' };
    }
    if (usage.source.includes('signedCookies')) {
      return { severity: 'warning', confidence: 'low' };
    }
    if (context.category === 'logging') {
      return { severity: 'info', confidence: 'low' };
    }
    if (context.category === 'queue-publish') {
      return { severity: 'warning', confidence: 'medium' };
    }
    if (context.category === 'simple-lookup') {
      return { severity: 'warning', confidence: 'medium' };
    }
    if (context.category === 'db-write') {
      return { severity: 'error', confidence: 'high' };
    }
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

  private generateSuggestion(usage: RequestDataUsage, _context: UsageContext, fields: string[], normalizedSource: string): string {
    if (usage.usageKind === 'spread' || usage.usageKind === 'object-assign') {
      return `${normalizedSource} spread/assigned into object — mass assignment vulnerability. Destructure only needed fields: const { name, email } = schema.parse(${normalizedSource}), or use a Zod/Joi schema to validate and strip unknown fields.`;
    }
    if (usage.usageKind === 'dynamic') {
      return `Dynamic property access on ${normalizedSource} allows attacker to access any field. Whitelist allowed property names: const ALLOWED = ['name', 'email']; if (!ALLOWED.includes(key)) return res.status(400).json({ error: 'Invalid field' }).`;
    }
    if (usage.source.includes('file')) {
      return `File upload without validation — add file type allowlist (check mimetype), size limit, and sanitize filename before use. Example: if (!['image/png','image/jpeg'].includes(file.mimetype)) return res.status(400).json({ error: 'Invalid file type' }).`;
    }

    const sensitiveFields = fields.filter(f => MissingInputValidationDetector.SENSITIVE_FIELDS.has(f.toLowerCase()));
    if (sensitiveFields.length > 0) {
      return `${normalizedSource}.{ ${sensitiveFields.join(', ')} } used without validation — ${sensitiveFields.includes('role') || sensitiveFields.includes('roles') ? 'privilege escalation risk if attacker sets role to admin' : 'sensitive field requires strict validation'}. Add: z.object({ ${sensitiveFields.map(f => `${f}: z.enum([...allowedValues])`).join(', ')} }).parse(${normalizedSource}).`;
    }

    if (normalizedSource.includes('params') || normalizedSource.includes('@Param')) {
      const paramFields = fields.length > 0 ? fields : ['id'];
      return `${normalizedSource}.{ ${paramFields.join(', ')} } used without type validation — params are always strings. Add type coercion: z.coerce.number().positive().parse(req.params.${paramFields[0]}), or param('${paramFields[0]}').isUUID() / .isInt() in middleware.`;
    }

    if (normalizedSource.includes('query') || normalizedSource.includes('@Query')) {
      return `${normalizedSource}.{ ${fields.join(', ')} } used without validation — vulnerable to injection and filter manipulation. Add: z.object({ ${fields.map(f => `${f}: z.string()`).join(', ')} }).parse(${normalizedSource}), or validate against allowed values.`;
    }

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
    if (handler.routeCallExpression && hasValidationMiddleware(handler.routeCallExpression)) {
      const expressValidatorFields = extractExpressValidatorFields(handler.routeCallExpression);
      if (expressValidatorFields.size > 0) {
        return this.checkPartialValidation(handler, context, expressValidatorFields);
      }
      return issues;
    }

    // Check if handler uses request data
    const requestDataUsage = findRequestDataUsage(handler.node);
    if (requestDataUsage.length === 0) return issues;

    // Find validated output variables
    const validatedVars = findValidatedVariables(handler.node);

    // Check if validation exists in handler
    const hasValidation = hasValidationInHandler(handler.node, validationImports, handler.hasSchemaValidation);

    if (hasValidation) {
      if (validatedVars.length > 0) {
        for (const usage of requestDataUsage) {
          if (usage.usageKind === 'direct' || usage.usageKind === 'destructured') {
            const usagePos = usage.node.getStart();
            const isAfterValidation = validatedVars.some(v => usagePos > v.declarationPos);
            const isValidationArg = validatedVars.some(v => {
              const diff = v.declarationPos - usagePos;
              return diff >= 0 && diff < 200;
            });
            if (isAfterValidation && !isValidationArg) {
              // Raw input used after validation — unusual, skip to avoid FPs
            }
          }
        }
      }
      return issues;
    }

    // No library validation — check manual validation
    const manualValidation = getManuallyValidatedFields(handler.node);

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

      let fields = sourceKey ? collectFieldNames(handler.node, sourceKey) : [];

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

        if (unvalidatedFields.length === 0 && !allWeak) {
          continue;
        }
        if (unvalidatedFields.length === 0 && allWeak) {
          hasWeakValidation = true;
        }
        if (unvalidatedFields.length > 0 && unvalidatedFields.length < fields.length) {
          fields = unvalidatedFields;
        }
      }

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
      const accessedFields = collectFieldNames(handler.node, sourceKey);
      if (accessedFields.length === 0) continue;

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

      const usageNode = handler.node;
      const issue = this.createIssue(
        context, usageNode,
        `Partial validation gap: ${normalizedSource}.{ ${unvalidatedFields.join(', ')} } not covered by express-validator${coveredText}`,
        { severity, suggestion, confidence }
      );
      if (issue) issues.push(issue);
    }

    return issues;
  }
}

// ──────────────────── Internal Interfaces ────────────────────

interface UsageContext {
  category: 'db-write' | 'db-read' | 'file-operation' | 'queue-publish' | 'logging' | 'simple-lookup' | 'unknown';
  isDangerousOperation: boolean;
}

// TypeScript import needed for getText() calls
import * as ts from 'typescript';

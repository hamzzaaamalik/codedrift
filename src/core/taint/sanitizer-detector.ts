/**
 * SanitizerDetector — Identifies operations that sanitize or validate
 * tainted data, removing or constraining taint.
 */

import * as ts from 'typescript';
import { SanitizationPoint, SanitizationKind } from './types.js';

// --- Pattern tables ---

const TYPE_COERCION_FUNCTIONS = new Set([
  'parseInt', 'parseFloat', 'Number', 'Boolean', 'String', 'BigInt',
]);

const SCHEMA_PARSE_METHODS = new Set([
  'parse', 'safeParse', 'validate',
]);

const SCHEMA_CALLERS = new Set([
  'z', 'zod', 'joi', 'yup', 'schema', 'ajv', 'vine', 'superstruct',
]);

const SUPERSTRUCT_METHODS = new Set([
  'create', 'assert',
]);

const ESCAPE_FUNCTIONS = new Set([
  'escapeHtml', 'encodeURIComponent', 'encodeURI',
  'sqlEscape', 'xss',
]);

const ESCAPE_DOTTED = new Map<string, Set<string>>([
  ['DOMPurify', new Set(['sanitize'])],
  ['validator', new Set(['escape'])],
]);

const CUSTOM_VALIDATOR_PATTERN = /^(validate|sanitize|check|verify|ensure|clean|filter|guard)/i;

const ALLOWLIST_METHODS = new Set(['includes', 'has']);

const ORM_TYPED_CALLERS = /^(prisma\..+|db)$/;
const ORM_TYPED_METHODS = new Set(['create', 'insert']);

export class SanitizerDetector {
  /**
   * If `node` represents a sanitization operation, return a SanitizationPoint.
   * Otherwise return null.
   */
  checkSanitization(node: ts.Node): SanitizationPoint | null {
    // --- Unary plus: +x ---
    if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.PlusToken) {
      return this.makePoint('type-coercion', '+', node);
    }

    // --- Call expressions ---
    if (ts.isCallExpression(node)) {
      return this.classifyCall(node);
    }

    // --- Switch statement with string cases (allowlist) ---
    if (ts.isSwitchStatement(node)) {
      if (this.switchHasStringCases(node)) {
        return this.makePoint('allowlist', 'switch', node);
      }
    }

    // --- Parameterized query: tagged template or string literal with placeholders ---
    if (ts.isTaggedTemplateExpression(node)) {
      const tag = node.tag.getText();
      if (/sql|query/i.test(tag)) {
        return this.makePoint('parameterized', tag, node);
      }
    }

    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      if (this.hasPlaceholders(node.text)) {
        return this.makePoint('parameterized', 'sql-placeholder', node);
      }
    }

    if (ts.isTemplateExpression(node)) {
      const head = node.head.text;
      const allText = head + node.templateSpans.map(s => s.literal.text).join('');
      if (this.hasPlaceholders(allText)) {
        return this.makePoint('parameterized', 'sql-placeholder', node);
      }
    }

    // --- Regex test/match used as condition ---
    if (this.isRegexCondition(node)) {
      return this.makePoint('regex-match', 'regex-test', node);
    }

    return null;
  }

  // ---- Private helpers ----

  private classifyCall(node: ts.CallExpression): SanitizationPoint | null {
    const callee = node.expression;

    // --- Simple identifier calls ---
    if (ts.isIdentifier(callee)) {
      const name = callee.text;

      if (TYPE_COERCION_FUNCTIONS.has(name)) {
        return this.makePoint('type-coercion', name, node);
      }

      if (ESCAPE_FUNCTIONS.has(name)) {
        return this.makePoint('escape', name, node);
      }

      if (CUSTOM_VALIDATOR_PATTERN.test(name)) {
        return this.makePoint('custom-validator', name, node);
      }

      return null;
    }

    // --- Property access calls: obj.method() ---
    if (ts.isPropertyAccessExpression(callee)) {
      const method = callee.name.text;
      const objText = callee.expression.getText();

      // Schema validation: z.parse, joi.validate, etc.
      if (SCHEMA_CALLERS.has(objText) && SCHEMA_PARSE_METHODS.has(method)) {
        return this.makePoint('schema-validation', `${objText}.${method}`, node);
      }

      // Nested schema: schema.safeParse, z.string().parse(), etc.
      if (SCHEMA_PARSE_METHODS.has(method) && this.looksLikeSchema(callee.expression)) {
        return this.makePoint('schema-validation', `${objText}.${method}`, node);
      }

      // superstruct.create / superstruct.assert
      if (objText === 'superstruct' && SUPERSTRUCT_METHODS.has(method)) {
        return this.makePoint('schema-validation', `superstruct.${method}`, node);
      }

      // Escape: DOMPurify.sanitize, validator.escape
      const escapeMethods = ESCAPE_DOTTED.get(objText);
      if (escapeMethods && escapeMethods.has(method)) {
        return this.makePoint('escape', `${objText}.${method}`, node);
      }

      // Allowlist: ALLOWED.includes(x), allowedSet.has(x)
      if (ALLOWLIST_METHODS.has(method) && this.looksLikeAllowlist(objText)) {
        return this.makePoint('allowlist', `${objText}.${method}`, node);
      }

      // ORM typed: prisma.*.create, db.insert
      if (ORM_TYPED_CALLERS.test(objText) && ORM_TYPED_METHODS.has(method)) {
        return this.makePoint('orm-typed', `${objText}.${method}`, node);
      }

      // Custom validator via method
      if (CUSTOM_VALIDATOR_PATTERN.test(method)) {
        return this.makePoint('custom-validator', `${objText}.${method}`, node);
      }

      return null;
    }

    return null;
  }

  private looksLikeSchema(expr: ts.Expression): boolean {
    // Accept chained calls like z.string().parse() or schema.object().parse()
    const text = expr.getText();
    return SCHEMA_CALLERS.has(text.split('.')[0]) || /schema/i.test(text);
  }

  private looksLikeAllowlist(name: string): boolean {
    return /allow|whitelist|valid|permitted|accepted|known|safe/i.test(name);
  }

  private switchHasStringCases(node: ts.SwitchStatement): boolean {
    for (const clause of node.caseBlock.clauses) {
      if (ts.isCaseClause(clause) && clause.expression && ts.isStringLiteral(clause.expression)) {
        return true;
      }
    }
    return false;
  }

  private hasPlaceholders(text: string): boolean {
    return /\$\d+|\?\s|:\w+/.test(text);
  }

  private isRegexCondition(node: ts.Node): boolean {
    // /pattern/.test(x)
    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      if (ts.isPropertyAccessExpression(callee)) {
        const method = callee.name.text;
        if (method === 'test' && ts.isRegularExpressionLiteral(callee.expression)) {
          return true;
        }
        // x.match(/pattern/)
        if (method === 'match' && node.arguments.length > 0
          && ts.isRegularExpressionLiteral(node.arguments[0])) {
          // Only counts if used as a condition (parent is if/ternary/logical)
          return this.isUsedAsCondition(node);
        }
      }
    }
    return false;
  }

  private isUsedAsCondition(node: ts.Node): boolean {
    const parent = node.parent;
    if (!parent) return false;
    if (ts.isIfStatement(parent) && parent.expression === node) return true;
    if (ts.isConditionalExpression(parent) && parent.condition === node) return true;
    if (ts.isPrefixUnaryExpression(parent) && parent.operator === ts.SyntaxKind.ExclamationToken) return true;
    if (ts.isBinaryExpression(parent) && (
      parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
      || parent.operatorToken.kind === ts.SyntaxKind.BarBarToken
    )) return true;
    return false;
  }

  private makePoint(
    sanitizationKind: SanitizationKind,
    sanitizer: string,
    node: ts.Node,
  ): SanitizationPoint {
    return {
      sanitizer,
      sanitizationKind,
      node,
      position: node.getStart(),
    };
  }
}

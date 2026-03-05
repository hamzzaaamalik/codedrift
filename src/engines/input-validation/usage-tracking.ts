/**
 * Request Data Usage Tracking — sub-module of MissingInputValidationDetector
 *
 * Detects how request data (body, params, query, headers, files, cookies) is accessed
 * in route handlers, including destructuring, spreading, aliasing, and function args.
 */

import * as ts from 'typescript';
import { traverse } from '../../core/parser.js';
import { getRootCallOfChain } from './route-detection.js';

// ──────────────────── Interfaces ────────────────────

export interface RequestDataUsage {
  node: ts.Node;
  source: string;
  risk: string;
  usageKind?: 'direct' | 'destructured' | 'spread' | 'alias' | 'dynamic' | 'object-assign' | 'function-arg';
  aliasName?: string;
}

export interface ValidatedVariable {
  name: string;
  sourceExpression: string;
  declarationPos: number;
}

// ──────────────────── Constants ────────────────────

/** Whole-shape validation methods — when called on req.body, ALL fields are covered */
export const WHOLE_SHAPE_METHODS = new Set([
  'parse', 'safeParse', 'parseAsync', 'validate', 'validateSync',
  'validateAsync', 'isValid', 'decode', 'create', 'assert',
  'plainToClass', 'plainToInstance',
]);

// ──────────────────── Request Data Usage Detection ────────────────────

/**
 * Find all request data usage in handler.
 */
export function findRequestDataUsage(node: ts.Node): RequestDataUsage[] {
  const usages: RequestDataUsage[] = [];

  traverse(node, (n) => {
    // ── Property access: req.body, req.params, req.query, req.headers, req.files, req.cookies ──
    if (ts.isPropertyAccessExpression(n)) {
      const text = n.getText();

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
      const callText = n.expression.getText();
      if (!isKnownSafeCall(callText)) {
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

// ──────────────────── Field Name Collection ────────────────────

/**
 * Collect the specific field names accessed from a request source within a handler.
 */
export function collectFieldNames(
  handlerNode: ts.Node,
  sourceKey: 'body' | 'params' | 'query' | 'headers',
): string[] {
  const fields = new Set<string>();

  traverse(handlerNode, (n) => {
    // req.body.fieldName — double PropertyAccess
    if (ts.isPropertyAccessExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const inner = n.expression;

      if (inner.name.text === sourceKey && ts.isIdentifier(inner.expression) && inner.expression.text.match(/^req(uest)?$/)) {
        fields.add(n.name.text);
      }
      if ((sourceKey === 'params' || sourceKey === 'query') && inner.name.text === sourceKey && ts.isIdentifier(inner.expression) && inner.expression.text === 'ctx') {
        fields.add(n.name.text);
      }
      if ((sourceKey === 'params' || sourceKey === 'query') && inner.name.text === sourceKey && ts.isIdentifier(inner.expression) && inner.expression.text === 'request') {
        fields.add(n.name.text);
      }
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
            if (element.propertyName && ts.isIdentifier(element.propertyName)) {
              fields.add(element.propertyName.text);
            } else if (ts.isIdentifier(element.name)) {
              fields.add(element.name.text);
            }
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

// ──────────────────── Express Validator Field Extraction ────────────────────

/**
 * Extract which fields express-validator covers from middleware arguments.
 */
export function extractExpressValidatorFields(routeCall: ts.CallExpression): Map<string, string[]> {
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
    if (ts.isCallExpression(mw)) {
      const rootId = getRootCallOfChain(mw);
      if (!rootId) continue;
      const rootName = rootId.text;

      let sourceKey: string | null = null;
      if (rootName === 'body') sourceKey = 'body';
      else if (rootName === 'param') sourceKey = 'params';
      else if (rootName === 'query') sourceKey = 'query';
      else if (rootName === 'check') sourceKey = 'any';

      if (!sourceKey) continue;

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

// ──────────────────── Validated Variable Detection ────────────────────

/**
 * Find variables that hold validated output.
 */
export function findValidatedVariables(handlerNode: ts.Node): ValidatedVariable[] {
  const validated: ValidatedVariable[] = [];

  traverse(handlerNode, (n) => {
    if (!ts.isVariableDeclaration(n) || !n.initializer) return;
    if (!ts.isCallExpression(n.initializer)) return;

    const callText = n.initializer.getText();
    const isValidationCall = WHOLE_SHAPE_METHODS.has(getCallMethodName(n.initializer));
    if (!isValidationCall) return;

    const argsText = n.initializer.arguments.map(a => a.getText()).join(' ');
    const requestSources = ['req.body', 'request.body', 'req.params', 'req.query',
      'ctx.request.body', 'ctx.params', 'ctx.query', 'request.payload',
      'request.params', 'request.query'];

    const matchedSource = requestSources.find(s => argsText.includes(s) || callText.includes(s));
    if (!matchedSource) return;

    if (ts.isIdentifier(n.name)) {
      validated.push({
        name: n.name.text,
        sourceExpression: matchedSource,
        declarationPos: n.getStart(),
      });
    }
    if (ts.isObjectBindingPattern(n.name)) {
      for (const element of n.name.elements) {
        if (ts.isIdentifier(element.name)) {
          const fieldName = element.name.text;
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

// ──────────────────── Helpers ────────────────────

function getCallMethodName(call: ts.CallExpression): string {
  const expr = call.expression;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  if (ts.isIdentifier(expr)) return expr.text;
  return '';
}

function isKnownSafeCall(callText: string): boolean {
  if (/^(res|response|reply|ctx|console|logger|log)\b/.test(callText)) return true;
  if (/\.(json|send|render|redirect|status|log|info|warn|error|debug)\s*$/.test(callText)) return true;
  if (/^(validate|parse|safeParse|celebrate|schema|joi|zod|yup|ajv)\b/i.test(callText)) return true;
  if (/\.(parse|safeParse|validate|validateSync|validateAsync|decode|compile)\s*$/.test(callText)) return true;
  if (callText === 'Object.assign') return true;
  return false;
}

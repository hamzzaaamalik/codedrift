/**
 * Express / Connect Framework Model
 *
 * Understands Express-style middleware chains, body-parser registration,
 * router mounting, and the (req, res, next) handler signature.
 */

import * as ts from 'typescript';
import type { TaintSourceKind, SanitizationKind } from '../types.js';
import type {
  FrameworkModel,
  RouteRegistration,
  HandlerReference,
  ChainTaintEffect,
} from './framework-model.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HTTP_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'all',
]);

/** Middleware names that introduce specific taint sources */
const SOURCE_MIDDLEWARE: Record<string, { kind: TaintSourceKind; accessPath: string }[]> = {
  // body-parser family
  'bodyParser.json':        [{ kind: 'req.body', accessPath: 'req.body' }],
  'bodyParser.urlencoded':  [{ kind: 'req.body', accessPath: 'req.body' }],
  'bodyParser.raw':         [{ kind: 'req.body', accessPath: 'req.body' }],
  'bodyParser.text':        [{ kind: 'req.body', accessPath: 'req.body' }],
  'express.json':           [{ kind: 'req.body', accessPath: 'req.body' }],
  'express.urlencoded':     [{ kind: 'req.body', accessPath: 'req.body' }],
  // cookie-parser
  'cookieParser':           [{ kind: 'req.cookies', accessPath: 'req.cookies' }],
  // multer (file uploads)
  'multer':                 [{ kind: 'req.files', accessPath: 'req.files' }],
  'upload.single':          [{ kind: 'req.files', accessPath: 'req.file' }],
  'upload.array':           [{ kind: 'req.files', accessPath: 'req.files' }],
  'upload.fields':          [{ kind: 'req.files', accessPath: 'req.files' }],
};

/** Patterns indicating a middleware performs validation/sanitization */
const SANITIZER_PATTERNS = /^(validate|sanitize|check|verify|assert|authorize|authenticate|guard)/i;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class ExpressModel implements FrameworkModel {
  readonly name = 'express';

  // -----------------------------------------------------------------------
  // Detection
  // -----------------------------------------------------------------------

  detect(sourceFile: ts.SourceFile): boolean {
    const text = sourceFile.text;
    // Quick string check before walking the AST
    if (!text.includes('express') && !text.includes('Router')) {
      return false;
    }
    return this.hasExpressImport(sourceFile) || this.hasRouterCalls(sourceFile);
  }

  // -----------------------------------------------------------------------
  // Route extraction
  // -----------------------------------------------------------------------

  extractRoutes(sourceFile: ts.SourceFile, filePath: string): RouteRegistration[] {
    const routes: RouteRegistration[] = [];
    this.walkForRoutes(sourceFile, filePath, routes);
    return routes;
  }

  // -----------------------------------------------------------------------
  // Chain analysis
  // -----------------------------------------------------------------------

  analyzeChain(chain: HandlerReference[]): ChainTaintEffect {
    const effect: ChainTaintEffect = {
      sourcesAdded: [],
      sanitizationsApplied: [],
      validatedPaths: [],
    };

    for (const handler of chain) {
      const name = handler.name ?? '';

      // Check if this middleware introduces taint sources
      for (const [pattern, sources] of Object.entries(SOURCE_MIDDLEWARE)) {
        if (name === pattern || name.endsWith(`.${pattern.split('.').pop()}`)) {
          for (const src of sources) {
            if (!effect.sourcesAdded.some(s => s.accessPath === src.accessPath)) {
              effect.sourcesAdded.push({ ...src });
            }
          }
        }
      }

      // Check for validation/sanitization middleware
      if (SANITIZER_PATTERNS.test(name)) {
        const sanitizationKind = inferSanitizationKind(name);
        effect.sanitizationsApplied.push({
          kind: sanitizationKind,
          targetPath: 'req.body',
        });
        effect.validatedPaths.push('req.body');
      }

      // Inline handler — inspect for validation patterns in the AST
      if (handler.node && (ts.isFunctionDeclaration(handler.node) || ts.isFunctionExpression(handler.node) || ts.isArrowFunction(handler.node) || ts.isMethodDeclaration(handler.node))) {
        this.analyzeInlineMiddleware(handler.node, effect);
      }
    }

    return effect;
  }

  // -----------------------------------------------------------------------
  // Handler sources
  // -----------------------------------------------------------------------

  getHandlerSources(
    handler: ts.FunctionLikeDeclaration,
  ): { paramIndex: number; sourceKind: TaintSourceKind }[] {
    const params = handler.parameters;
    const sources: { paramIndex: number; sourceKind: TaintSourceKind }[] = [];

    if (params.length === 0) return sources;

    // param 0 = req (always a source)
    const reqSources: TaintSourceKind[] = [
      'req.body', 'req.params', 'req.query', 'req.headers',
      'req.cookies', 'req.files', 'req.ip',
    ];
    for (const kind of reqSources) {
      sources.push({ paramIndex: 0, sourceKind: kind });
    }

    // param 1 (res) — not a source
    // param 2 (next) — not a source

    return sources;
  }

  // -----------------------------------------------------------------------
  // Private: detection helpers
  // -----------------------------------------------------------------------

  private hasExpressImport(sourceFile: ts.SourceFile): boolean {
    for (const stmt of sourceFile.statements) {
      // import express from 'express'  /  import { Router } from 'express'
      if (ts.isImportDeclaration(stmt)) {
        const specifier = stmt.moduleSpecifier;
        if (ts.isStringLiteral(specifier) && specifier.text === 'express') {
          return true;
        }
      }
      // const express = require('express')
      if (ts.isVariableStatement(stmt)) {
        for (const decl of stmt.declarationList.declarations) {
          if (decl.initializer && isRequireCall(decl.initializer, 'express')) {
            return true;
          }
        }
      }
    }
    return false;
  }

  private hasRouterCalls(sourceFile: ts.SourceFile): boolean {
    let found = false;
    const visit = (node: ts.Node): void => {
      if (found) return;
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const method = node.expression.name.text;
        if (HTTP_METHODS.has(method) || method === 'use' || method === 'route') {
          found = true;
          return;
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    return found;
  }

  // -----------------------------------------------------------------------
  // Private: route extraction
  // -----------------------------------------------------------------------

  private walkForRoutes(
    node: ts.Node,
    filePath: string,
    routes: RouteRegistration[],
  ): void {
    if (ts.isCallExpression(node)) {
      this.tryExtractRoute(node, filePath, routes);
    }
    ts.forEachChild(node, child => this.walkForRoutes(child, filePath, routes));
  }

  private tryExtractRoute(
    call: ts.CallExpression,
    filePath: string,
    routes: RouteRegistration[],
  ): void {
    // Pattern: app.get('/path', ...handlers)  or  router.post('/path', ...handlers)
    if (!ts.isPropertyAccessExpression(call.expression)) return;

    const method = call.expression.name.text.toUpperCase();
    const normalizedMethod = method === 'USE' ? 'USE' : method;

    if (!HTTP_METHODS.has(method.toLowerCase()) && method !== 'USE') return;

    const args = call.arguments;
    if (args.length === 0) return;

    // First arg is the route path (string literal) or a middleware for app.use()
    let path = '/';
    let handlerStartIdx = 0;

    const firstArg = args[0];
    if (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg)) {
      path = firstArg.text;
      handlerStartIdx = 1;
    } else if (ts.isTemplateExpression(firstArg)) {
      // Template literal path — extract the head as best effort
      path = firstArg.head.text + ':dynamic';
      handlerStartIdx = 1;
    }

    // Remaining args are handlers/middleware
    const handlers: HandlerReference[] = [];
    for (let i = handlerStartIdx; i < args.length; i++) {
      const handler = this.extractHandler(args[i], i === args.length - 1);
      if (handler) {
        handlers.push(handler);
      }
    }

    if (handlers.length > 0) {
      routes.push({
        method: normalizedMethod,
        path,
        handlers,
        filePath,
        node: call,
      });
    }
  }

  private extractHandler(arg: ts.Expression, isLast: boolean): HandlerReference | null {
    // Identifier — e.g., app.get('/path', myHandler)
    if (ts.isIdentifier(arg)) {
      return {
        name: arg.text,
        role: isLast ? 'handler' : 'middleware',
      };
    }

    // Property access — e.g., app.use(bodyParser.json())
    if (ts.isCallExpression(arg)) {
      const name = getCallName(arg);
      return {
        name,
        role: isLast ? 'handler' : 'middleware',
      };
    }

    // Arrow function or function expression
    if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
      const paramCount = arg.parameters.length;
      const role: HandlerReference['role'] =
        paramCount >= 4 ? 'error-handler' :
        isLast ? 'handler' : 'middleware';
      return { node: arg, role };
    }

    return null;
  }

  // -----------------------------------------------------------------------
  // Private: inline middleware analysis
  // -----------------------------------------------------------------------

  private analyzeInlineMiddleware(
    fn: ts.FunctionLikeDeclaration,
    effect: ChainTaintEffect,
  ): void {
    if (!fn.body) return;

    const visit = (node: ts.Node): void => {
      // Look for schema validation calls (e.g., Joi.validate, zod.parse)
      if (ts.isCallExpression(node)) {
        const callee = getCallName(node);
        if (callee && /\b(validate|parse|safeParse|check)\b/i.test(callee)) {
          effect.sanitizationsApplied.push({
            kind: 'schema-validation',
            targetPath: 'req.body',
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(fn.body);
  }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

function isRequireCall(node: ts.Node, moduleName: string): boolean {
  if (!ts.isCallExpression(node)) return false;
  if (!ts.isIdentifier(node.expression) || node.expression.text !== 'require') return false;
  const arg = node.arguments[0];
  return !!arg && ts.isStringLiteral(arg) && arg.text === moduleName;
}

function getCallName(call: ts.CallExpression): string | undefined {
  if (ts.isIdentifier(call.expression)) {
    return call.expression.text;
  }
  if (ts.isPropertyAccessExpression(call.expression)) {
    const parts: string[] = [];
    let current: ts.Expression = call.expression;
    while (ts.isPropertyAccessExpression(current)) {
      parts.unshift(current.name.text);
      current = current.expression;
    }
    if (ts.isIdentifier(current)) {
      parts.unshift(current.text);
    }
    return parts.join('.');
  }
  return undefined;
}

function inferSanitizationKind(name: string): SanitizationKind {
  const lower = name.toLowerCase();
  if (lower.includes('validate') || lower.includes('check') || lower.includes('assert')) {
    return 'schema-validation';
  }
  if (lower.includes('sanitize') || lower.includes('escape')) {
    return 'escape';
  }
  if (lower.includes('auth') || lower.includes('guard')) {
    return 'custom-validator';
  }
  return 'custom-validator';
}

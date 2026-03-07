/**
 * Next.js Framework Model
 *
 * Understands Next.js App Router (route.ts handlers), Pages Router
 * (pages/api), Server Actions ('use server'), and middleware.
 */

import * as ts from 'typescript';
import type { TaintSourceKind } from '../types.js';
import type {
  FrameworkModel,
  RouteRegistration,
  HandlerReference,
  ChainTaintEffect,
} from './framework-model.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const APP_ROUTER_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);

/** File-path patterns that indicate Next.js route files */
const APP_ROUTER_ROUTE_RE = /[/\\]app[/\\].*[/\\]route\.(ts|tsx|js|jsx)$/;
const PAGES_API_RE = /[/\\]pages[/\\]api[/\\]/;
const MIDDLEWARE_RE = /[/\\]middleware\.(ts|tsx|js|jsx)$/;

const NEXT_MODULES = new Set([
  'next',
  'next/server',
  'next/headers',
  'next/navigation',
]);

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class NextJSModel implements FrameworkModel {
  readonly name = 'nextjs';

  // -----------------------------------------------------------------------
  // Detection
  // -----------------------------------------------------------------------

  detect(sourceFile: ts.SourceFile): boolean {
    const text = sourceFile.text;
    const fileName = sourceFile.fileName;

    // File path heuristics
    if (APP_ROUTER_ROUTE_RE.test(fileName) || PAGES_API_RE.test(fileName) || MIDDLEWARE_RE.test(fileName)) {
      return true;
    }

    // Import heuristics
    if (text.includes('next/server') || text.includes('next/headers') || text.includes('NextResponse')) {
      return this.hasNextImport(sourceFile);
    }

    // Server action directive
    if (text.includes("'use server'") || text.includes('"use server"')) {
      return true;
    }

    return false;
  }

  // -----------------------------------------------------------------------
  // Route extraction
  // -----------------------------------------------------------------------

  extractRoutes(sourceFile: ts.SourceFile, filePath: string): RouteRegistration[] {
    const routes: RouteRegistration[] = [];
    const fileName = sourceFile.fileName;

    if (APP_ROUTER_ROUTE_RE.test(fileName)) {
      this.extractAppRouterRoutes(sourceFile, filePath, routes);
    } else if (PAGES_API_RE.test(fileName)) {
      this.extractPagesApiRoute(sourceFile, filePath, routes);
    } else if (MIDDLEWARE_RE.test(fileName)) {
      this.extractMiddleware(sourceFile, filePath, routes);
    }

    // Server actions can appear in any file
    if (this.hasServerDirective(sourceFile)) {
      this.extractServerActions(sourceFile, filePath, routes);
    }

    return routes;
  }

  // -----------------------------------------------------------------------
  // Chain analysis
  // -----------------------------------------------------------------------

  analyzeChain(_chain: HandlerReference[]): ChainTaintEffect {
    // Next.js has minimal middleware chains — most processing happens in the
    // handler itself.  Middleware runs globally at the edge and can modify
    // headers/cookies but doesn't operate like Express middleware chains.
    return {
      sourcesAdded: [],
      sanitizationsApplied: [],
      validatedPaths: [],
    };
  }

  // -----------------------------------------------------------------------
  // Handler sources
  // -----------------------------------------------------------------------

  getHandlerSources(
    handler: ts.FunctionLikeDeclaration,
  ): { paramIndex: number; sourceKind: TaintSourceKind }[] {
    const sources: { paramIndex: number; sourceKind: TaintSourceKind }[] = [];
    const params = handler.parameters;

    if (params.length === 0) return sources;

    const firstParamName = getParamName(params[0]);

    // Determine what kind of handler this is based on parameter names and types
    if (this.isServerActionParam(params[0])) {
      // Server action: first param is FormData
      sources.push({ paramIndex: 0, sourceKind: 'user-input' });
    } else if (firstParamName === 'req' || firstParamName === 'request') {
      // App Router or Pages Router request object
      sources.push(
        { paramIndex: 0, sourceKind: 'req.body' },
        { paramIndex: 0, sourceKind: 'req.query' },
        { paramIndex: 0, sourceKind: 'req.headers' },
        { paramIndex: 0, sourceKind: 'req.cookies' },
      );
    }

    // Pages router: second param is `res` — not a source
    return sources;
  }

  // -----------------------------------------------------------------------
  // Private: detection helpers
  // -----------------------------------------------------------------------

  private hasNextImport(sourceFile: ts.SourceFile): boolean {
    for (const stmt of sourceFile.statements) {
      if (!ts.isImportDeclaration(stmt)) continue;
      const specifier = stmt.moduleSpecifier;
      if (ts.isStringLiteral(specifier) && NEXT_MODULES.has(specifier.text)) {
        return true;
      }
    }
    return false;
  }

  private hasServerDirective(sourceFile: ts.SourceFile): boolean {
    // 'use server' appears as the first statement (expression statement with string literal)
    for (const stmt of sourceFile.statements) {
      if (ts.isExpressionStatement(stmt) && ts.isStringLiteral(stmt.expression)) {
        if (stmt.expression.text === 'use server') {
          return true;
        }
      }
      // Only check leading statements — the directive must appear before code
      if (!ts.isExpressionStatement(stmt)) break;
    }
    return false;
  }

  // -----------------------------------------------------------------------
  // Private: App Router route extraction
  // -----------------------------------------------------------------------

  private extractAppRouterRoutes(
    sourceFile: ts.SourceFile,
    filePath: string,
    routes: RouteRegistration[],
  ): void {
    const routePath = this.inferRoutePathFromFile(filePath);

    for (const stmt of sourceFile.statements) {
      const fn = this.getExportedFunction(stmt);
      if (!fn) continue;

      const name = fn.name && ts.isIdentifier(fn.name) ? fn.name.text : undefined;
      if (!name || !APP_ROUTER_METHODS.has(name)) continue;

      routes.push({
        method: name,
        path: routePath,
        handlers: [{
          name,
          node: fn,
          role: 'handler',
        }],
        filePath,
        node: fn,
      });
    }
  }

  // -----------------------------------------------------------------------
  // Private: Pages Router API route extraction
  // -----------------------------------------------------------------------

  private extractPagesApiRoute(
    sourceFile: ts.SourceFile,
    filePath: string,
    routes: RouteRegistration[],
  ): void {
    const routePath = this.inferRoutePathFromFile(filePath);

    for (const stmt of sourceFile.statements) {
      // export default function handler(req, res) { ... }
      // export default async (req, res) => { ... }
      if (!ts.isExportAssignment(stmt)) continue;

      const expr = stmt.expression;
      const fn = ts.isFunctionExpression(expr) || ts.isArrowFunction(expr) ? expr : undefined;
      const handlerNode = fn ?? (ts.isIdentifier(expr) ? expr : undefined);
      if (!handlerNode) continue;

      routes.push({
        method: 'ALL',
        path: routePath,
        handlers: [{
          name: ts.isIdentifier(expr) ? expr.text : 'handler',
          node: fn,
          role: 'handler',
        }],
        filePath,
        node: stmt,
      });
    }
  }

  // -----------------------------------------------------------------------
  // Private: middleware extraction
  // -----------------------------------------------------------------------

  private extractMiddleware(
    sourceFile: ts.SourceFile,
    filePath: string,
    routes: RouteRegistration[],
  ): void {
    for (const stmt of sourceFile.statements) {
      const fn = this.getExportedFunction(stmt);
      if (!fn) continue;

      const name = fn.name && ts.isIdentifier(fn.name) ? fn.name.text : undefined;
      if (name !== 'middleware') continue;

      routes.push({
        method: 'USE',
        path: '/*',
        handlers: [{
          name: 'middleware',
          node: fn,
          role: 'middleware',
        }],
        filePath,
        node: fn,
      });
    }
  }

  // -----------------------------------------------------------------------
  // Private: server action extraction
  // -----------------------------------------------------------------------

  private extractServerActions(
    sourceFile: ts.SourceFile,
    filePath: string,
    routes: RouteRegistration[],
  ): void {
    for (const stmt of sourceFile.statements) {
      const fn = this.getExportedFunction(stmt);
      if (!fn) continue;

      const name = fn.name && ts.isIdentifier(fn.name) ? fn.name.text : undefined;
      if (!name) continue;
      // Skip the standard HTTP method names — those are App Router handlers, not actions
      if (APP_ROUTER_METHODS.has(name) || name === 'middleware') continue;

      routes.push({
        method: 'ACTION',
        path: `/__action/${name}`,
        handlers: [{
          name,
          node: fn,
          role: 'handler',
        }],
        filePath,
        node: fn,
      });
    }
  }

  // -----------------------------------------------------------------------
  // Private: helpers
  // -----------------------------------------------------------------------

  private getExportedFunction(stmt: ts.Statement): ts.FunctionDeclaration | undefined {
    if (!ts.isFunctionDeclaration(stmt)) return undefined;
    const modifiers = ts.canHaveModifiers(stmt) ? ts.getModifiers(stmt) : undefined;
    const isExported = modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
    return isExported ? stmt : undefined;
  }

  private inferRoutePathFromFile(filePath: string): string {
    // Normalize separators
    const normalized = filePath.replace(/\\/g, '/');

    // App Router: /app/users/[id]/route.ts -> /users/[id]
    const appMatch = normalized.match(/\/app(\/.*?)\/route\.[tj]sx?$/);
    if (appMatch) {
      return appMatch[1].replace(/\[(\w+)\]/g, ':$1') || '/';
    }

    // Pages Router: /pages/api/users/[id].ts -> /api/users/:id
    const pagesMatch = normalized.match(/\/pages(\/api\/.*?)\.[tj]sx?$/);
    if (pagesMatch) {
      let route = pagesMatch[1];
      // Remove /index suffix
      route = route.replace(/\/index$/, '') || '/';
      return route.replace(/\[(\w+)\]/g, ':$1');
    }

    return '/';
  }

  private isServerActionParam(param: ts.ParameterDeclaration): boolean {
    // Check type annotation for FormData
    if (param.type) {
      const typeText = param.type.getText?.() ?? '';
      if (typeText === 'FormData') return true;
    }
    // Check parameter name
    const name = getParamName(param);
    return name === 'formData' || name === 'data';
  }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function getParamName(param: ts.ParameterDeclaration): string | undefined {
  return ts.isIdentifier(param.name) ? param.name.text : undefined;
}

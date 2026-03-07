/**
 * NestJS Framework Model
 *
 * Understands NestJS decorator-based routing, dependency injection guards,
 * pipes (ValidationPipe), interceptors, and parameter decorators like
 * @Body(), @Param(), @Query().
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

const HTTP_METHOD_DECORATORS = new Set([
  'Get', 'Post', 'Put', 'Delete', 'Patch', 'Options', 'Head', 'All',
]);

const NESTJS_MODULES = new Set([
  '@nestjs/common',
  '@nestjs/core',
  '@nestjs/platform-express',
  '@nestjs/platform-fastify',
]);

/** Maps parameter decorators to taint source kinds */
const PARAM_DECORATOR_MAP: Record<string, TaintSourceKind> = {
  Body:    'decorator.body',
  Param:   'decorator.param',
  Query:   'decorator.query',
  Headers: 'req.headers',
  Req:     'req.body',      // raw request — all sources
  Request: 'req.body',
};

/** Pipes that act as sanitizers */
const SANITIZER_PIPES: Record<string, SanitizationKind> = {
  ValidationPipe:  'schema-validation',
  ParseIntPipe:    'type-coercion',
  ParseFloatPipe:  'type-coercion',
  ParseBoolPipe:   'type-coercion',
  ParseUUIDPipe:   'regex-match',
  ParseEnumPipe:   'allowlist',
  ParseArrayPipe:  'type-coercion',
};

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export class NestJSModel implements FrameworkModel {
  readonly name = 'nestjs';

  // -----------------------------------------------------------------------
  // Detection
  // -----------------------------------------------------------------------

  detect(sourceFile: ts.SourceFile): boolean {
    const text = sourceFile.text;
    if (!text.includes('@nestjs') && !text.includes('Controller') && !text.includes('Injectable')) {
      return false;
    }
    return this.hasNestImport(sourceFile) || this.hasNestDecorators(sourceFile);
  }

  // -----------------------------------------------------------------------
  // Route extraction
  // -----------------------------------------------------------------------

  extractRoutes(sourceFile: ts.SourceFile, filePath: string): RouteRegistration[] {
    const routes: RouteRegistration[] = [];

    for (const stmt of sourceFile.statements) {
      if (!ts.isClassDeclaration(stmt)) continue;

      const controllerPath = this.getDecoratorStringArg(stmt, 'Controller');
      if (controllerPath === undefined) continue; // not a controller

      const basePath = controllerPath || '/';
      this.extractMethodRoutes(stmt, basePath, filePath, routes);
    }

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

      // Guards — they can reject but don't sanitize
      if (handler.role === 'guard') {
        // Guards don't introduce sources or sanitizations
        continue;
      }

      // Pipes — these ARE sanitizers
      if (handler.role === 'pipe') {
        const pipeKind = SANITIZER_PIPES[name];
        if (pipeKind) {
          effect.sanitizationsApplied.push({
            kind: pipeKind,
            targetPath: 'decorator.body',
          });
          effect.validatedPaths.push('decorator.body');
        }
      }

      // Interceptors — may transform data
      if (handler.role === 'interceptor') {
        // Interceptors can modify responses but generally don't sanitize input
        continue;
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
    const sources: { paramIndex: number; sourceKind: TaintSourceKind }[] = [];
    const params = handler.parameters;

    for (let i = 0; i < params.length; i++) {
      const param = params[i];
      const decorators = getDecorators(param);

      for (const decorator of decorators) {
        const name = getDecoratorName(decorator);
        if (name && name in PARAM_DECORATOR_MAP) {
          const sourceKind = PARAM_DECORATOR_MAP[name];
          sources.push({ paramIndex: i, sourceKind });

          // @Req() / @Request() gives access to ALL req sources
          if (name === 'Req' || name === 'Request') {
            for (const kind of ['req.params', 'req.query', 'req.headers', 'req.cookies', 'req.files', 'req.ip'] as TaintSourceKind[]) {
              sources.push({ paramIndex: i, sourceKind: kind });
            }
          }
        }
      }
    }

    return sources;
  }

  // -----------------------------------------------------------------------
  // Private: detection helpers
  // -----------------------------------------------------------------------

  private hasNestImport(sourceFile: ts.SourceFile): boolean {
    for (const stmt of sourceFile.statements) {
      if (!ts.isImportDeclaration(stmt)) continue;
      const specifier = stmt.moduleSpecifier;
      if (ts.isStringLiteral(specifier) && NESTJS_MODULES.has(specifier.text)) {
        return true;
      }
    }
    return false;
  }

  private hasNestDecorators(sourceFile: ts.SourceFile): boolean {
    let found = false;
    const visit = (node: ts.Node): void => {
      if (found) return;
      if (ts.isClassDeclaration(node)) {
        const decorators = getDecorators(node);
        for (const d of decorators) {
          const name = getDecoratorName(d);
          if (name === 'Controller' || name === 'Injectable' || name === 'Module') {
            found = true;
            return;
          }
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

  private extractMethodRoutes(
    classDecl: ts.ClassDeclaration,
    basePath: string,
    filePath: string,
    routes: RouteRegistration[],
  ): void {
    for (const member of classDecl.members) {
      if (!ts.isMethodDeclaration(member)) continue;

      const decorators = getDecorators(member);
      for (const decorator of decorators) {
        const name = getDecoratorName(decorator);
        if (!name || !HTTP_METHOD_DECORATORS.has(name)) continue;

        const methodPath = this.getDecoratorArgString(decorator) ?? '/';
        const fullPath = joinPaths(basePath, methodPath);
        const method = name.toUpperCase();

        // Collect chain elements from class-level and method-level decorators
        const handlers = this.extractChainFromDecorators(classDecl, member);

        // The method itself is the terminal handler
        const handlerName = ts.isIdentifier(member.name) ? member.name.text : undefined;
        handlers.push({
          name: handlerName,
          node: member,
          role: 'handler',
        });

        routes.push({
          method,
          path: fullPath,
          handlers,
          filePath,
          node: member,
        });
      }
    }
  }

  private extractChainFromDecorators(
    classDecl: ts.ClassDeclaration,
    method: ts.MethodDeclaration,
  ): HandlerReference[] {
    const handlers: HandlerReference[] = [];

    // Class-level decorators first (applied to all methods)
    const classDecorators = getDecorators(classDecl);
    for (const d of classDecorators) {
      this.extractChainElement(d, handlers);
    }

    // Method-level decorators
    const methodDecorators = getDecorators(method);
    for (const d of methodDecorators) {
      this.extractChainElement(d, handlers);
    }

    return handlers;
  }

  private extractChainElement(
    decorator: ts.Decorator,
    handlers: HandlerReference[],
  ): void {
    const name = getDecoratorName(decorator);
    if (!name) return;

    if (name === 'UseGuards') {
      const args = getDecoratorCallArgs(decorator);
      for (const arg of args) {
        handlers.push({ name: getExpressionName(arg), role: 'guard' });
      }
    } else if (name === 'UsePipes') {
      const args = getDecoratorCallArgs(decorator);
      for (const arg of args) {
        handlers.push({ name: getExpressionName(arg), role: 'pipe' });
      }
    } else if (name === 'UseInterceptors') {
      const args = getDecoratorCallArgs(decorator);
      for (const arg of args) {
        handlers.push({ name: getExpressionName(arg), role: 'interceptor' });
      }
    }
  }

  // -----------------------------------------------------------------------
  // Private: decorator helpers
  // -----------------------------------------------------------------------

  /** Get the string argument of a class decorator, or undefined if not present */
  private getDecoratorStringArg(
    classDecl: ts.ClassDeclaration,
    decoratorName: string,
  ): string | undefined {
    const decorators = getDecorators(classDecl);
    for (const d of decorators) {
      if (getDecoratorName(d) === decoratorName) {
        return this.getDecoratorArgString(d) ?? '';
      }
    }
    return undefined;
  }

  private getDecoratorArgString(decorator: ts.Decorator): string | undefined {
    if (!ts.isCallExpression(decorator.expression)) return undefined;
    const arg = decorator.expression.arguments[0];
    if (!arg) return undefined;
    if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
      return arg.text;
    }
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/**
 * Get decorators from a node, handling both TS 4.x (node.decorators) and
 * TS 5.x (ts.canHaveDecorators / ts.getDecorators).
 */
function getDecorators(node: ts.Node): readonly ts.Decorator[] {
  // TS 5.x API
  if (typeof ts.canHaveDecorators === 'function' && ts.canHaveDecorators(node)) {
    return ts.getDecorators(node) ?? [];
  }
  // TS 4.x fallback
  return (node as unknown as { decorators?: ts.Decorator[] }).decorators ?? [];
}

function getDecoratorName(decorator: ts.Decorator): string | undefined {
  const expr = decorator.expression;
  // @Controller
  if (ts.isIdentifier(expr)) return expr.text;
  // @Controller('path') — call expression
  if (ts.isCallExpression(expr)) {
    if (ts.isIdentifier(expr.expression)) return expr.expression.text;
    if (ts.isPropertyAccessExpression(expr.expression)) {
      return expr.expression.name.text;
    }
  }
  return undefined;
}

function getDecoratorCallArgs(decorator: ts.Decorator): readonly ts.Expression[] {
  if (ts.isCallExpression(decorator.expression)) {
    return decorator.expression.arguments;
  }
  return [];
}

function getExpressionName(expr: ts.Expression): string | undefined {
  if (ts.isIdentifier(expr)) return expr.text;
  // new ValidationPipe()
  if (ts.isNewExpression(expr) && ts.isIdentifier(expr.expression)) {
    return expr.expression.text;
  }
  if (ts.isPropertyAccessExpression(expr)) {
    return expr.name.text;
  }
  return undefined;
}

function joinPaths(base: string, sub: string): string {
  const b = base.replace(/\/+$/, '');
  const s = sub.startsWith('/') ? sub : `/${sub}`;
  return `${b}${s}`;
}

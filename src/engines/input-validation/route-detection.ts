/**
 * Route Handler Detection — sub-module of MissingInputValidationDetector
 *
 * Detects route handlers across Express, Fastify, Koa, Hapi, NestJS, tRPC, and GraphQL.
 */

import * as ts from 'typescript';
import { traverse } from '../../core/parser.js';

// ──────────────────── Interfaces ────────────────────

export interface RouteHandler {
  node: ts.Node;
  framework: 'express' | 'nestjs' | 'koa' | 'hapi' | 'trpc' | 'graphql';
  method: string;
  isAsync: boolean;
  routeCallExpression?: ts.CallExpression;
  hasSchemaValidation?: boolean;
}

// ──────────────────── Route Detection ────────────────────

/**
 * Find all route handler functions in a source file.
 */
export function findRouteHandlers(sourceFile: ts.SourceFile): { handlers: RouteHandler[]; hasGlobalValidation: boolean } {
  const handlers: RouteHandler[] = [];
  const hasGlobalValidation = hasGlobalValidationMiddleware(sourceFile);

  traverse(sourceFile, (node) => {
    if (ts.isCallExpression(node)) {
      const handler = checkExpressStyleRoute(node);
      if (handler) {
        if (!hasGlobalValidation) handlers.push(handler);
        return;
      }

      const hapiHandler = checkHapiStyleRoute(node);
      if (hapiHandler) {
        if (!hasGlobalValidation) handlers.push(hapiHandler);
        return;
      }

      const trpcHandler = checkTRPCRoute(node);
      if (trpcHandler) {
        if (!hasGlobalValidation) handlers.push(trpcHandler);
        return;
      }
    }

    if (ts.isMethodDeclaration(node)) {
      if (isGraphQLResolver(node)) return;
      const handler = checkNestJSStyleRoute(node);
      if (handler) {
        if (!hasGlobalValidation) handlers.push(handler);
      }
    }
  });

  return { handlers, hasGlobalValidation };
}

// ──────────────────── Express/Fastify/Koa ────────────────────

function checkExpressStyleRoute(node: ts.CallExpression): RouteHandler | null {
  const { expression } = node;
  if (!ts.isPropertyAccessExpression(expression)) return null;

  const objectName = getObjectName(expression.expression);
  const methodName = expression.name.text;

  const routeMethods = ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'];
  if (!routeMethods.includes(methodName)) return null;

  const routerObjects = ['app', 'router', 'api', 'route', 'server', 'fastify', 'instance'];
  if (!objectName || !routerObjects.some(r => objectName.toLowerCase().includes(r))) return null;

  if (node.arguments.length === 0) return null;

  const lastArg = node.arguments[node.arguments.length - 1];
  if (!ts.isArrowFunction(lastArg) && !ts.isFunctionExpression(lastArg)) return null;

  const framework = detectHandlerFramework(lastArg);

  let hasSchemaValidation = false;
  if (node.arguments.length >= 2) {
    for (let i = 0; i < node.arguments.length - 1; i++) {
      const arg = node.arguments[i];
      if (ts.isObjectLiteralExpression(arg)) {
        if (hasFastifySchemaValidation(arg)) {
          hasSchemaValidation = true;
        }
      }
    }
  }

  return {
    node: lastArg,
    framework,
    method: methodName,
    isAsync: isAsyncFunction(lastArg),
    routeCallExpression: node,
    hasSchemaValidation,
  };
}

function detectHandlerFramework(handler: ts.ArrowFunction | ts.FunctionExpression): 'express' | 'koa' | 'hapi' {
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

// ──────────────────── Hapi ────────────────────

function checkHapiStyleRoute(node: ts.CallExpression): RouteHandler | null {
  const { expression } = node;
  if (!ts.isPropertyAccessExpression(expression)) return null;

  const objectName = getObjectName(expression.expression);
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
    if (propName === 'options' && ts.isObjectLiteralExpression(prop.initializer)) {
      if (hasHapiValidateConfig(prop.initializer)) {
        hasSchemaValidation = true;
      }
    }
    if (propName === 'validate' && ts.isObjectLiteralExpression(prop.initializer)) {
      hasSchemaValidation = true;
    }
  }

  if (!handlerNode) return null;

  return {
    node: handlerNode,
    framework: 'hapi',
    method: httpMethod,
    isAsync: isAsyncFunction(handlerNode),
    routeCallExpression: node,
    hasSchemaValidation,
  };
}

// ──────────────────── NestJS ────────────────────

function checkNestJSStyleRoute(node: ts.MethodDeclaration): RouteHandler | null {
  const decorators = ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined;
  if (!decorators || decorators.length === 0) return null;

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
          isAsync: isAsyncFunction(node),
          hasSchemaValidation: hasValidationPipe,
        };
      }
    }
  }

  return null;
}

// ──────────────────── tRPC ────────────────────

function checkTRPCRoute(node: ts.CallExpression): RouteHandler | null {
  if (!ts.isPropertyAccessExpression(node.expression)) return null;
  const methodName = node.expression.name.text;
  if (methodName !== 'mutation' && methodName !== 'query') return null;

  const chainText = node.expression.getText();
  if (chainText.includes('.input(')) {
    const lastArg = node.arguments.length > 0 ? node.arguments[node.arguments.length - 1] : null;
    if (lastArg && (ts.isArrowFunction(lastArg) || ts.isFunctionExpression(lastArg))) {
      return {
        node: lastArg,
        framework: 'trpc',
        method: methodName,
        isAsync: isAsyncFunction(lastArg),
        hasSchemaValidation: true,
      };
    }
  }
  return null;
}

// ──────────────────── GraphQL ────────────────────

function isGraphQLResolver(node: ts.MethodDeclaration): boolean {
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

function hasFastifySchemaValidation(options: ts.ObjectLiteralExpression): boolean {
  for (const prop of options.properties) {
    if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
      if (prop.name.text === 'schema' && ts.isObjectLiteralExpression(prop.initializer)) {
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

function hasHapiValidateConfig(options: ts.ObjectLiteralExpression): boolean {
  for (const prop of options.properties) {
    if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
      if (prop.name.text === 'validate') {
        return true;
      }
    }
  }
  return false;
}

// ──────────────────── Global Middleware Detection ────────────────────

function hasGlobalValidationMiddleware(sourceFile: ts.SourceFile): boolean {
  let hasGlobal = false;

  traverse(sourceFile, (node) => {
    if (hasGlobal) return;
    if (!ts.isCallExpression(node)) return;
    const { expression } = node;
    if (!ts.isPropertyAccessExpression(expression)) return;
    if (expression.name.text !== 'use') return;

    const objName = getObjectName(expression.expression);
    if (!objName || !/^(app|router|server|api|fastify)$/i.test(objName)) return;

    for (const arg of node.arguments) {
      if (isValidationMiddlewareNode(arg)) {
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

// ──────────────────── Validation Middleware Checks ────────────────────
// These are used by both route detection and the main validation checks.

export function isValidationMiddlewareNode(node: ts.Node): boolean {
  if (ts.isCallExpression(node)) return isValidationCallExpression(node);
  if (ts.isIdentifier(node)) return isValidationIdentifier(node.text);
  return false;
}

export function isValidationCallExpression(callExpr: ts.CallExpression): boolean {
  const callee = callExpr.expression;

  if (ts.isIdentifier(callee)) {
    const name = callee.text;
    const expressValidatorFns = ['body', 'param', 'query', 'check', 'validationResult', 'checkSchema', 'oneOf'];
    if (expressValidatorFns.includes(name)) return true;
    if (name === 'celebrate') return true;
    if (isValidationIdentifier(name)) return true;
  }

  if (ts.isPropertyAccessExpression(callee)) {
    // Check if the method name itself is a known validation method (e.g. schema.validate, vine.validate)
    const methodName = callee.name.text;
    const validationMethodNames = ['validate', 'parse', 'safeParse', 'check', 'guard', 'compile', 'decode'];
    if (validationMethodNames.includes(methodName)) return true;

    const rootId = getRootCallOfChain(callExpr);
    if (rootId) {
      const rootName = rootId.text;
      const expressValidatorFns = ['body', 'param', 'query', 'check', 'validationResult', 'checkSchema', 'oneOf'];
      if (expressValidatorFns.includes(rootName)) return true;
      if (isValidationIdentifier(rootName)) return true;
    }
  }

  // Check if any argument name suggests a schema (e.g. validate(userSchema))
  if (callExpr.arguments.length > 0) {
    for (const arg of callExpr.arguments) {
      if (ts.isIdentifier(arg)) {
        const argLower = arg.text.toLowerCase();
        if (argLower.includes('schema') || argLower.includes('validator')) return true;
      }
    }
  }

  return false;
}

export function getRootCallOfChain(node: ts.CallExpression): ts.Identifier | null {
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

export function isValidationIdentifier(name: string): boolean {
  const lower = name.toLowerCase();
  const knownNames = ['validatebody', 'validaterequest', 'validateparams', 'validatequery'];
  if (knownNames.includes(lower)) return true;
  if ((lower.includes('validat') || lower.includes('validator')) && !lower.includes('invalid')) return true;
  if (lower.includes('sanitiz')) return true;
  if (lower.includes('zodmiddleware') || lower.includes('yupmiddleware')) return true;
  return false;
}

export function hasValidationMiddleware(routeCall: ts.CallExpression): boolean {
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
    if (isValidationMiddlewareNode(middlewareNode)) return true;
  }
  return false;
}

// ──────────────────── Shared Utilities ────────────────────

export function getObjectName(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return getObjectName(expr.expression);
  return null;
}

export function isAsyncFunction(node: ts.Node): boolean {
  if (ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node)) {
    const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
    return modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false;
  }
  return false;
}

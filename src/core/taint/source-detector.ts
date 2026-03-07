import * as ts from 'typescript';
import { TaintId, TaintSource, TaintSourceKind } from './types.js';

interface SourcePattern {
  object: string;
  property: string;
  kind: TaintSourceKind;
}

const SOURCE_PATTERNS: SourcePattern[] = [
  // Express
  { object: 'req', property: 'body', kind: 'req.body' },
  { object: 'req', property: 'params', kind: 'req.params' },
  { object: 'req', property: 'query', kind: 'req.query' },
  { object: 'req', property: 'headers', kind: 'req.headers' },
  { object: 'req', property: 'cookies', kind: 'req.cookies' },
  { object: 'req', property: 'files', kind: 'req.files' },
  { object: 'req', property: 'ip', kind: 'req.ip' },
  { object: 'request', property: 'body', kind: 'req.body' },
  { object: 'request', property: 'params', kind: 'req.params' },
  { object: 'request', property: 'query', kind: 'req.query' },
  { object: 'request', property: 'headers', kind: 'req.headers' },
  { object: 'request', property: 'cookies', kind: 'req.cookies' },
  { object: 'request', property: 'files', kind: 'req.files' },
  { object: 'request', property: 'ip', kind: 'req.ip' },

  // Koa
  { object: 'ctx', property: 'params', kind: 'ctx.params' },
  { object: 'ctx', property: 'query', kind: 'ctx.query' },

  // Hapi
  { object: 'request', property: 'payload', kind: 'request.payload' },
];

const NESTJS_DECORATOR_MAP: Record<string, TaintSourceKind> = {
  Body: 'decorator.body',
  Param: 'decorator.param',
  Query: 'decorator.query',
};

export class TaintSourceDetector {
  private counter = 0;

  detectSources(scopeNode: ts.Node): TaintSource[] {
    const sources: TaintSource[] = [];
    this.counter = 0;
    this.walk(scopeNode, sources);
    return sources;
  }

  private walk(node: ts.Node, sources: TaintSource[]): void {
    this.visitNode(node, sources);
    ts.forEachChild(node, (child) => this.walk(child, sources));
  }

  private visitNode(node: ts.Node, sources: TaintSource[]): void {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      this.checkDestructuringOrAlias(node, sources);
    } else if (ts.isPropertyAccessExpression(node)) {
      this.checkPropertyAccess(node, sources);
    } else if (ts.isParameter(node)) {
      this.checkNestJSDecorator(node, sources);
    } else if (ts.isSpreadAssignment(node) || ts.isSpreadElement(node)) {
      this.checkSpread(node, sources);
    }
  }

  private checkPropertyAccess(node: ts.PropertyAccessExpression, sources: TaintSource[]): void {
    // Skip nodes already handled as part of destructuring/alias initializers
    if (this.isPartOfVariableInit(node)) return;
    // Skip nodes that are part of a spread expression
    if (this.isPartOfSpread(node)) return;

    // ctx.request.body — 3-level deep Koa pattern
    if (this.matchKoaRequestBody(node)) {
      const label = this.buildPropertyLabel(node);
      sources.push(this.createSource('ctx.request.body', node, [], label));
      return;
    }

    // Standard 2-level patterns: req.body, ctx.params, request.payload, etc.
    const match = this.matchSourcePattern(node);
    if (match) {
      const label = this.buildPropertyLabel(node);
      sources.push(this.createSource(match.kind, node, [], label));
    }
  }

  private checkDestructuringOrAlias(node: ts.VariableDeclaration, sources: TaintSource[]): void {
    const init = node.initializer!;

    const kind = this.resolveInitializerKind(init);
    if (!kind) return;

    if (ts.isObjectBindingPattern(node.name)) {
      const boundNames = this.extractBindingNames(node.name);
      const label = `${kind} (destructured)`;
      sources.push(this.createSource(kind, node, boundNames, label));
    } else if (ts.isIdentifier(node.name)) {
      const aliasName = node.name.text;
      const label = `${kind} -> ${aliasName}`;
      sources.push(this.createSource(kind, node, [aliasName], label));
    }
  }

  private checkNestJSDecorator(node: ts.ParameterDeclaration, sources: TaintSource[]): void {
    const decorators = ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined;
    if (!decorators) return;

    for (const decorator of decorators) {
      if (!ts.isCallExpression(decorator.expression)) continue;
      if (!ts.isIdentifier(decorator.expression.expression)) continue;

      const name = decorator.expression.expression.text;
      const kind = NESTJS_DECORATOR_MAP[name];
      if (!kind) continue;

      const paramName = ts.isIdentifier(node.name) ? node.name.text : '';
      const boundNames = paramName ? [paramName] : [];
      const label = `@${name}() ${paramName}`;
      sources.push(this.createSource(kind, node, boundNames, label));
    }
  }

  private checkSpread(node: ts.SpreadAssignment | ts.SpreadElement, sources: TaintSource[]): void {
    const kind = this.resolveExpressionKind(node.expression);
    if (!kind) return;

    const label = `...${node.expression.getText()}`;
    sources.push(this.createSource(kind, node, [], label));
  }

  // ── Pattern matching helpers ──

  private matchSourcePattern(node: ts.PropertyAccessExpression): SourcePattern | undefined {
    const prop = node.name.text;
    if (!ts.isIdentifier(node.expression)) return undefined;
    const obj = node.expression.text;
    return SOURCE_PATTERNS.find((p) => p.object === obj && p.property === prop);
  }

  private matchKoaRequestBody(node: ts.PropertyAccessExpression): boolean {
    if (node.name.text !== 'body') return false;
    if (!ts.isPropertyAccessExpression(node.expression)) return false;
    const mid = node.expression;
    if (mid.name.text !== 'request') return false;
    return ts.isIdentifier(mid.expression) && mid.expression.text === 'ctx';
  }

  private resolveInitializerKind(init: ts.Expression): TaintSourceKind | undefined {
    return this.resolveExpressionKind(init);
  }

  private resolveExpressionKind(expr: ts.Expression): TaintSourceKind | undefined {
    // ctx.request.body
    if (ts.isPropertyAccessExpression(expr) && this.matchKoaRequestBody(expr)) {
      return 'ctx.request.body';
    }

    // Standard 2-level: req.body, ctx.params, request.payload, etc.
    if (ts.isPropertyAccessExpression(expr)) {
      const match = this.matchSourcePattern(expr);
      if (match) return match.kind;
    }

    return undefined;
  }

  // ── AST utility helpers ──

  private extractBindingNames(pattern: ts.ObjectBindingPattern): string[] {
    const names: string[] = [];
    for (const element of pattern.elements) {
      if (ts.isBindingElement(element)) {
        if (ts.isIdentifier(element.name)) {
          names.push(element.name.text);
        } else if (ts.isObjectBindingPattern(element.name)) {
          names.push(...this.extractBindingNames(element.name));
        }
      }
    }
    return names;
  }

  private buildPropertyLabel(node: ts.PropertyAccessExpression): string {
    // If parent is also a property access (e.g., req.body.field), use the full text
    const parent = node.parent;
    if (parent && ts.isPropertyAccessExpression(parent) && parent.expression === node) {
      return parent.getText();
    }
    return node.getText();
  }

  private isPartOfVariableInit(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      if (ts.isVariableDeclaration(current) && current.initializer) {
        // Check if our node is within the initializer subtree
        if (this.isDescendantOf(node, current.initializer)) return true;
      }
      current = current.parent;
    }
    return false;
  }

  private isPartOfSpread(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      if (ts.isSpreadAssignment(current) || ts.isSpreadElement(current)) return true;
      current = current.parent;
    }
    return false;
  }

  private isDescendantOf(node: ts.Node, ancestor: ts.Node): boolean {
    let current: ts.Node | undefined = node;
    while (current) {
      if (current === ancestor) return true;
      current = current.parent;
    }
    return false;
  }

  private createSource(
    kind: TaintSourceKind,
    node: ts.Node,
    boundNames: string[],
    label: string,
  ): TaintSource {
    return {
      id: this.nextId(),
      kind,
      node,
      boundNames,
      label,
      position: node.getStart(),
    };
  }

  private nextId(): TaintId {
    return `taint_${this.counter++}`;
  }
}

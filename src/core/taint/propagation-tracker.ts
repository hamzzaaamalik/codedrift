/**
 * Taint Propagation Tracker — Core data flow module
 *
 * Tracks how tainted values flow through variable assignments,
 * destructuring, spread, and other operations within a single
 * function scope.
 */

import * as ts from 'typescript';
import type {
  TaintId,
  TaintSource,
  TaintStep,
  PropagationKind,
  VariableTaintState,
} from './types.js';

export class TaintPropagationTracker {
  private readonly states: Map<string, VariableTaintState> = new Map();

  constructor(sources: TaintSource[]) {
    // Initialize variable state from source boundNames
    for (const source of sources) {
      for (const name of source.boundNames) {
        this.states.set(name, {
          name,
          taintSources: [source.id],
          sanitized: false,
          appliedSanitizations: [],
          declarationNode: source.node,
          propagationPath: [],
        });
      }
    }
  }

  /**
   * Forward pass over statements in the given scope node.
   * Walks statements in source-position order and tracks taint propagation.
   */
  trackPropagation(scopeNode: ts.Node): Map<string, VariableTaintState> {
    this.walkNode(scopeNode);
    return new Map(this.states);
  }

  /** Check if a node reads from a tainted variable */
  isTainted(node: ts.Node): boolean {
    return this.resolveExpressionTaint(node as ts.Expression).length > 0;
  }

  /** Get taint IDs flowing into a node */
  getTaintSources(node: ts.Node): TaintId[] {
    return this.resolveExpressionTaint(node as ts.Expression);
  }

  /** Return current variable taint states */
  getVariableStates(): Map<string, VariableTaintState> {
    return new Map(this.states);
  }

  // ---------------------------------------------------------------------------
  // Core traversal
  // ---------------------------------------------------------------------------

  private walkNode(node: ts.Node): void {
    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        this.processVariableDeclaration(decl);
      }
      return;
    }

    if (ts.isExpressionStatement(node)) {
      const expr = node.expression;
      if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        this.processAssignment(expr);
        return;
      }
    }

    // Recurse into child statements (blocks, if/else, loops, etc.)
    ts.forEachChild(node, (child) => this.walkNode(child));
  }

  // ---------------------------------------------------------------------------
  // Variable declaration handling
  // ---------------------------------------------------------------------------

  private processVariableDeclaration(decl: ts.VariableDeclaration): void {
    if (!decl.initializer) return;

    if (ts.isIdentifier(decl.name)) {
      // Simple: const x = taintedVar
      const taintIds = this.resolveExpressionTaint(decl.initializer);
      if (taintIds.length > 0) {
        const propagation = this.classifyPropagation(decl.initializer);
        this.markTainted(decl.name.text, taintIds, propagation, decl);
      }
    } else if (ts.isObjectBindingPattern(decl.name)) {
      // Destructuring: const { a, b } = taintedVar
      const taintIds = this.resolveExpressionTaint(decl.initializer);
      if (taintIds.length > 0) {
        for (const element of decl.name.elements) {
          if (ts.isIdentifier(element.name)) {
            this.markTainted(element.name.text, taintIds, 'destructuring', decl);
          }
        }
      }
    } else if (ts.isArrayBindingPattern(decl.name)) {
      // Array destructuring: const [a, b] = taintedVar
      const taintIds = this.resolveExpressionTaint(decl.initializer);
      if (taintIds.length > 0) {
        for (const element of decl.name.elements) {
          if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
            this.markTainted(element.name.text, taintIds, 'destructuring', decl);
          }
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Assignment handling
  // ---------------------------------------------------------------------------

  private processAssignment(expr: ts.BinaryExpression): void {
    const taintIds = this.resolveExpressionTaint(expr.right);
    if (taintIds.length === 0) return;

    if (ts.isIdentifier(expr.left)) {
      const propagation = this.classifyPropagation(expr.right);
      this.markTainted(expr.left.text, taintIds, propagation, expr);
    }
  }

  // ---------------------------------------------------------------------------
  // Expression taint resolution
  // ---------------------------------------------------------------------------

  /**
   * Resolve taint IDs flowing through an expression.
   *
   * - Identifier -> check states map
   * - Property access -> check if object is tainted
   * - Call expression -> don't propagate (intra-procedural only)
   * - Template literal / binary concat -> check operands
   * - Await -> check operand
   * - Ternary -> check both branches (conservative)
   * - Spread -> check operand
   * - Object literal with spread -> check spread elements
   * - Paren -> unwrap
   */
  private resolveExpressionTaint(expr: ts.Expression): TaintId[] {
    if (ts.isIdentifier(expr)) {
      return this.getVariableTaint(expr.text);
    }

    if (ts.isPropertyAccessExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression);
    }

    if (ts.isElementAccessExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression);
    }

    if (ts.isCallExpression(expr)) {
      // Intra-procedural: don't propagate return values
      return [];
    }

    if (ts.isTemplateExpression(expr)) {
      const ids: TaintId[] = [];
      if (expr.head && ts.isTemplateHead(expr.head)) {
        // head is static text, no taint
      }
      for (const span of expr.templateSpans) {
        ids.push(...this.resolveExpressionTaint(span.expression));
      }
      return this.dedupe(ids);
    }

    if (ts.isTaggedTemplateExpression(expr)) {
      if (ts.isTemplateExpression(expr.template)) {
        return this.resolveExpressionTaint(expr.template);
      }
      return [];
    }

    if (ts.isBinaryExpression(expr)) {
      if (
        expr.operatorToken.kind === ts.SyntaxKind.PlusToken ||
        expr.operatorToken.kind === ts.SyntaxKind.PlusEqualsToken
      ) {
        return this.dedupe([
          ...this.resolveExpressionTaint(expr.left),
          ...this.resolveExpressionTaint(expr.right),
        ]);
      }
      return [];
    }

    if (ts.isAwaitExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression);
    }

    if (ts.isConditionalExpression(expr)) {
      // Conservative: tainted if either branch is tainted
      return this.dedupe([
        ...this.resolveExpressionTaint(expr.whenTrue),
        ...this.resolveExpressionTaint(expr.whenFalse),
      ]);
    }

    if (ts.isSpreadElement(expr)) {
      return this.resolveExpressionTaint(expr.expression);
    }

    if (ts.isObjectLiteralExpression(expr)) {
      const ids: TaintId[] = [];
      for (const prop of expr.properties) {
        if (ts.isSpreadAssignment(prop)) {
          ids.push(...this.resolveExpressionTaint(prop.expression));
        } else if (ts.isPropertyAssignment(prop)) {
          ids.push(...this.resolveExpressionTaint(prop.initializer));
        } else if (ts.isShorthandPropertyAssignment(prop)) {
          ids.push(...this.getVariableTaint(prop.name.text));
        }
      }
      return this.dedupe(ids);
    }

    if (ts.isArrayLiteralExpression(expr)) {
      const ids: TaintId[] = [];
      for (const el of expr.elements) {
        ids.push(...this.resolveExpressionTaint(el));
      }
      return this.dedupe(ids);
    }

    if (ts.isParenthesizedExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression);
    }

    if (ts.isNonNullExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression);
    }

    if (ts.isAsExpression(expr) || ts.isTypeAssertionExpression(expr)) {
      return this.resolveExpressionTaint(expr.expression);
    }

    return [];
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private getVariableTaint(name: string): TaintId[] {
    const state = this.states.get(name);
    if (!state || state.sanitized) return [];
    return [...state.taintSources];
  }

  private markTainted(
    name: string,
    taintIds: TaintId[],
    propagation: PropagationKind,
    node: ts.Node,
  ): void {
    const step: TaintStep = {
      variableName: name,
      propagation,
      node,
      position: node.getStart(),
    };

    const existing = this.states.get(name);
    if (existing) {
      existing.taintSources = this.dedupe([...existing.taintSources, ...taintIds]);
      existing.propagationPath.push(step);
    } else {
      this.states.set(name, {
        name,
        taintSources: [...taintIds],
        sanitized: false,
        appliedSanitizations: [],
        declarationNode: node,
        propagationPath: [step],
      });
    }
  }

  private classifyPropagation(expr: ts.Expression): PropagationKind {
    if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
      return 'property-access';
    }
    if (ts.isTemplateExpression(expr) || ts.isTaggedTemplateExpression(expr)) {
      return 'template-literal';
    }
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return 'binary-concat';
    }
    if (ts.isAwaitExpression(expr)) {
      return 'await';
    }
    if (ts.isConditionalExpression(expr)) {
      return 'ternary';
    }
    if (ts.isObjectLiteralExpression(expr)) {
      for (const prop of expr.properties) {
        if (ts.isSpreadAssignment(prop)) return 'spread';
      }
    }
    if (ts.isSpreadElement(expr)) {
      return 'spread';
    }
    return 'assignment';
  }

  private dedupe(ids: TaintId[]): TaintId[] {
    return [...new Set(ids)];
  }
}

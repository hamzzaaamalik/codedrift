/**
 * AccessPath — Field-level access chain representation for taint analysis
 *
 * Represents a chain of property accesses from a root variable.
 * Example: `req.body.user.name` → AccessPath('req', ['body', 'user', 'name'])
 */

import * as ts from 'typescript';

const WILDCARD_FIELD = '*';

export class AccessPath {
  constructor(
    readonly root: string,
    readonly fields: string[],
  ) {}

  /**
   * Create from a TypeScript expression node.
   * Supports: Identifier, PropertyAccessExpression, ElementAccessExpression,
   * NonNullExpression, ParenthesizedExpression.
   */
  static fromExpression(expr: ts.Expression): AccessPath | null {
    if (ts.isIdentifier(expr)) {
      return new AccessPath(expr.text, []);
    }

    if (ts.isPropertyAccessExpression(expr)) {
      const base = AccessPath.fromExpression(expr.expression);
      if (!base) return null;
      return new AccessPath(base.root, [...base.fields, expr.name.text]);
    }

    if (ts.isElementAccessExpression(expr)) {
      const base = AccessPath.fromExpression(expr.expression);
      if (!base) return null;

      const arg = expr.argumentExpression;
      let fieldKey: string;

      if (arg && ts.isStringLiteral(arg)) {
        fieldKey = arg.text;
      } else if (arg && ts.isNumericLiteral(arg)) {
        fieldKey = arg.text;
      } else {
        // Dynamic index — use wildcard
        fieldKey = '[*]';
      }

      return new AccessPath(base.root, [...base.fields, fieldKey]);
    }

    if (ts.isNonNullExpression(expr)) {
      return AccessPath.fromExpression(expr.expression);
    }

    if (ts.isParenthesizedExpression(expr)) {
      return AccessPath.fromExpression(expr.expression);
    }

    // Cannot represent this expression as an access path
    return null;
  }

  /**
   * Check if this path starts with the given prefix.
   * Example: req.body.user.name starts with req.body → true
   */
  startsWith(prefix: AccessPath): boolean {
    if (this.root !== prefix.root) return false;
    if (prefix.fields.length > this.fields.length) return false;
    for (let i = 0; i < prefix.fields.length; i++) {
      if (this.fields[i] !== prefix.fields[i]) return false;
    }
    return true;
  }

  /**
   * Get the parent path by removing the last field.
   * Returns null if this is already a root path (no fields).
   */
  parent(): AccessPath | null {
    if (this.fields.length === 0) return null;
    return new AccessPath(this.root, this.fields.slice(0, -1));
  }

  /**
   * Append a field to produce a longer path.
   */
  append(field: string): AccessPath {
    return new AccessPath(this.root, [...this.fields, field]);
  }

  /** Number of fields in the chain */
  get depth(): number {
    return this.fields.length;
  }

  /**
   * Create a wildcard path that matches any single field at the end.
   * Example: AccessPath.wildcard('req', ['body']) → req.body.*
   */
  static wildcard(root: string, fields: string[]): WildcardAccessPath {
    return new WildcardAccessPath(root, [...fields, WILDCARD_FIELD]);
  }

  /**
   * Canonical string representation, used as Map keys.
   */
  toString(): string {
    if (this.fields.length === 0) return this.root;
    return `${this.root}.${this.fields.join('.')}`;
  }

  /** Check structural equality */
  equals(other: AccessPath): boolean {
    if (this.root !== other.root) return false;
    if (this.fields.length !== other.fields.length) return false;
    for (let i = 0; i < this.fields.length; i++) {
      if (this.fields[i] !== other.fields[i]) return false;
    }
    return true;
  }

  /**
   * Check if this path matches another, considering wildcards.
   * A plain AccessPath only matches via exact equality.
   */
  matches(other: AccessPath): boolean {
    return this.equals(other);
  }

  /** Create an independent copy */
  clone(): AccessPath {
    return new AccessPath(this.root, [...this.fields]);
  }
}

/**
 * A wildcard access path — the last field is '*', matching any single field.
 * Example: req.body.* matches req.body.name, req.body.email, etc.
 */
export class WildcardAccessPath extends AccessPath {
  /**
   * Matches another path if:
   * - Same root
   * - Same prefix fields (all except the trailing wildcard)
   * - The other path has exactly one more field than the prefix
   */
  matches(other: AccessPath): boolean {
    if (this.root !== other.root) return false;

    // The wildcard path has fields [...prefix, '*']
    // We match if other has fields [...prefix, <anything>]
    const prefixLen = this.fields.length - 1; // exclude the '*'
    if (other.fields.length !== prefixLen + 1) return false;

    for (let i = 0; i < prefixLen; i++) {
      if (this.fields[i] !== other.fields[i]) return false;
    }
    return true;
  }

  clone(): WildcardAccessPath {
    return new WildcardAccessPath(this.root, [...this.fields]);
  }
}

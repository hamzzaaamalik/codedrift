/**
 * Shared AST Traversal Utilities
 *
 * Reusable tree-walking helpers used across multiple engines.
 * Eliminates duplicated while(parent) loops and traverse+closure patterns.
 */

import * as ts from 'typescript';

/**
 * Walk up the AST parent chain and return the first node matching the predicate.
 * Returns undefined if no ancestor matches.
 */
export function findAncestor<T extends ts.Node>(
  node: ts.Node,
  predicate: (n: ts.Node) => n is T,
): T | undefined;
export function findAncestor(
  node: ts.Node,
  predicate: (n: ts.Node) => boolean,
): ts.Node | undefined;
export function findAncestor(
  node: ts.Node,
  predicate: (n: ts.Node) => boolean,
): ts.Node | undefined {
  let current = node.parent;
  while (current) {
    if (predicate(current)) return current;
    current = current.parent;
  }
  return undefined;
}

/**
 * Traverse a subtree depth-first, stopping early when the visitor returns true.
 * Returns true if any visitor call returned true (i.e., a match was found).
 */
export function traverseUntil(
  node: ts.Node,
  visitor: (node: ts.Node) => boolean,
): boolean {
  if (visitor(node)) return true;
  return ts.forEachChild(node, (child) => traverseUntil(child, visitor)) ?? false;
}

/**
 * Check whether any node in a subtree matches the predicate.
 * Short-circuits on first match.
 */
export function containsNode(
  root: ts.Node,
  predicate: (node: ts.Node) => boolean,
): boolean {
  return traverseUntil(root, predicate);
}

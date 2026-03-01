/**
 * ESTree-compatible AST Parser
 * Uses @typescript-eslint/typescript-estree — a standard ESTree AST backed by the
 * TypeScript compiler, so it handles .ts, .tsx, .js, and .jsx with full fidelity.
 *
 * Results are cached per file path for the duration of one analysis run.
 * Call clearASTCache() before each run to prevent stale entries.
 */

import { parse, TSESTree, simpleTraverse } from '@typescript-eslint/typescript-estree';

export type { TSESTree };

// Per-run cache: filePath → parsed Program
const astCache = new Map<string, TSESTree.Program>();

/**
 * Parse source code into an ESTree-compatible AST, with per-run caching.
 *
 * @param content  - File source code (avoids redundant fs.readFileSync)
 * @param filePath - Cache key and used internally for JSX/TSX detection (.tsx vs .ts)
 * @throws if the file has a syntax error that prevents parsing
 */
export function parseESTree(content: string, filePath: string): TSESTree.Program {
  const cached = astCache.get(filePath);
  if (cached) return cached;

  const ast = parse(content, {
    jsx: true,      // Enable JSX/TSX parsing
    range: true,    // Add [start, end] byte offsets to every node
    loc: true,      // Add { start: { line, column }, end: { line, column } } to every node
    comment: false, // Skip comment nodes — not needed for analysis
    filePath,       // Used internally by the parser for script-kind detection
  });

  astCache.set(filePath, ast);
  return ast;
}

/**
 * Clear the AST cache.
 * Call this at the start of each analysis run to prevent cross-run stale entries.
 */
export function clearASTCache(): void {
  astCache.clear();
}

/**
 * Walk every node in an ESTree AST, calling visitor for each.
 * Thin wrapper around simpleTraverse for a familiar API.
 *
 * @param root    - Root node (usually TSESTree.Program)
 * @param visitor - Called for every node in the tree
 */
export function traverseESTree(
  root: TSESTree.Node,
  visitor: (node: TSESTree.Node) => void
): void {
  simpleTraverse(root, {
    enter(node) {
      visitor(node);
    },
  });
}

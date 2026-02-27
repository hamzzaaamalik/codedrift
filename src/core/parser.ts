/**
 * TypeScript AST Parser
 * Wraps TypeScript Compiler API for fast, type-aware parsing
 */

import * as ts from 'typescript';
import * as fs from 'fs';
import * as path from 'path';

/**
 * Parse a file and return its AST
 * Fast parsing mode - no type-checking for performance
 */
export function parseFile(filePath: string): ts.SourceFile {
  const fileContent = fs.readFileSync(filePath, 'utf-8');

  return ts.createSourceFile(
    filePath,
    fileContent,
    ts.ScriptTarget.Latest,
    true, // setParentNodes for easier traversal
    determineScriptKind(filePath)
  );
}

/**
 * Parse source code string
 */
export function parseSource(code: string, fileName: string = 'source.ts'): ts.SourceFile {
  return ts.createSourceFile(
    fileName,
    code,
    ts.ScriptTarget.Latest,
    true,
    determineScriptKind(fileName)
  );
}

/**
 * Determine script kind from file extension
 */
function determineScriptKind(fileName: string): ts.ScriptKind {
  const ext = path.extname(fileName);

  switch (ext) {
    case '.ts':
      return ts.ScriptKind.TS;
    case '.tsx':
      return ts.ScriptKind.TSX;
    case '.jsx':
      return ts.ScriptKind.JSX;
    case '.js':
    default:
      return ts.ScriptKind.JS;
  }
}

/**
 * Traverse AST with visitor pattern
 */
export function traverse(node: ts.Node, visitor: (node: ts.Node) => void): void {
  visitor(node);
  ts.forEachChild(node, (child) => traverse(child, visitor));
}

/**
 * Find all nodes of a specific kind
 */
export function findNodes<T extends ts.Node>(
  node: ts.Node,
  kind: ts.SyntaxKind
): T[] {
  const results: T[] = [];

  traverse(node, (n) => {
    if (n.kind === kind) {
      results.push(n as T);
    }
  });

  return results;
}

/**
 * Find all nodes matching a predicate
 */
export function findNodesByPredicate<T extends ts.Node>(
  node: ts.Node,
  predicate: (node: ts.Node) => boolean
): T[] {
  const results: T[] = [];

  traverse(node, (n) => {
    if (predicate(n)) {
      results.push(n as T);
    }
  });

  return results;
}

/**
 * Get line and column from position
 */
export function getLocation(node: ts.Node, sourceFile: ts.SourceFile): {
  line: number;
  column: number;
} {
  const { line, character } = sourceFile.getLineAndCharacterOfPosition(
    node.getStart(sourceFile)
  );

  return {
    line: line + 1, // 1-indexed for human readability
    column: character + 1,
  };
}

/**
 * Get the text of a node
 */
export function getNodeText(node: ts.Node, sourceFile: ts.SourceFile): string {
  return node.getText(sourceFile);
}

/**
 * Check if node is within a specific parent type
 */
export function isWithinNodeType(
  node: ts.Node,
  parentKind: ts.SyntaxKind
): boolean {
  let current = node.parent;

  while (current) {
    if (current.kind === parentKind) {
      return true;
    }
    current = current.parent;
  }

  return false;
}

/**
 * Get all import declarations from a file
 */
export function getImports(sourceFile: ts.SourceFile): {
  moduleName: string;
  location: { line: number; column: number };
}[] {
  const imports: { moduleName: string; location: { line: number; column: number } }[] = [];

  traverse(sourceFile, (node) => {
    if (ts.isImportDeclaration(node)) {
      const moduleSpecifier = node.moduleSpecifier;
      if (ts.isStringLiteral(moduleSpecifier)) {
        imports.push({
          moduleName: moduleSpecifier.text,
          location: getLocation(node, sourceFile),
        });
      }
    }

    // Also check require() calls for CommonJS
    if (ts.isCallExpression(node)) {
      const { expression } = node;
      if (
        ts.isIdentifier(expression) &&
        expression.text === 'require' &&
        node.arguments.length > 0
      ) {
        const arg = node.arguments[0];
        if (ts.isStringLiteral(arg)) {
          imports.push({
            moduleName: arg.text,
            location: getLocation(node, sourceFile),
          });
        }
      }
    }
  });

  return imports;
}

/**
 * Type guards and helpers
 */
export const ASTHelpers = {
  /**
   * Check if node is a function-like declaration
   */
  isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
    return (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    );
  },

  /**
   * Check if node is an async function
   */
  isAsyncFunction(node: ts.Node): boolean {
    if (!this.isFunctionLike(node)) return false;

    const modifiers = ts.canHaveModifiers(node)
      ? ts.getModifiers(node)
      : undefined;

    return modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword) ?? false;
  },

  /**
   * Check if expression is awaited
   */
  isAwaited(node: ts.Node): boolean {
    return node.parent?.kind === ts.SyntaxKind.AwaitExpression;
  },

  /**
   * Check if node is within try-catch
   */
  isWithinTryCatch(node: ts.Node): boolean {
    let current = node.parent;
    while (current) {
      if (ts.isTryStatement(current)) {
        return true;
      }
      current = current.parent;
    }
    return false;
  },

  /**
   * Get function name if available
   */
  getFunctionName(node: ts.FunctionLikeDeclaration): string | undefined {
    if (ts.isFunctionDeclaration(node) && node.name) {
      return node.name.text;
    }
    if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) {
      return node.name.text;
    }
    return undefined;
  },
};

/**
 * FileIndex — Parsed AST cache and file metadata for cross-file analysis
 *
 * Indexes functions, classes, and top-level statements from parsed TypeScript
 * source files, caching results for efficient repeated lookups.
 */

import * as ts from 'typescript';
import * as crypto from 'crypto';
import { parseFile } from '../../parser.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FunctionEntry {
  name: string;
  canonicalId: string;
  node: ts.Node;
  paramCount: number;
  isAsync: boolean;
  isGenerator: boolean;
  isExported: boolean;
  containingClass?: string;
}

export interface ClassEntry {
  name: string;
  canonicalId: string;
  node: ts.Node;
  methods: FunctionEntry[];
  constructorEntry?: FunctionEntry;
  isExported: boolean;
  baseClassName?: string;
  implementsNames: string[];
}

export interface FileEntry {
  filePath: string;
  sourceFile: ts.SourceFile;
  functions: FunctionEntry[];
  classes: ClassEntry[];
  topLevelStatements: ts.Node[];
  contentHash: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  const mods = ts.getModifiers(node);
  return mods?.some(m => m.kind === kind) ?? false;
}

function isExportedNode(node: ts.Node): boolean {
  return (
    hasModifier(node, ts.SyntaxKind.ExportKeyword) ||
    hasModifier(node, ts.SyntaxKind.DefaultKeyword)
  );
}

function isAsync(node: ts.Node): boolean {
  return hasModifier(node, ts.SyntaxKind.AsyncKeyword);
}

function isGenerator(node: ts.FunctionDeclaration | ts.MethodDeclaration | ts.FunctionExpression): boolean {
  return node.asteriskToken !== undefined;
}

function paramCount(node: ts.SignatureDeclaration): number {
  return node.parameters?.length ?? 0;
}

function contentHash(text: string): string {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Check whether a variable statement has an export modifier, which applies
 * to all declarations within it (e.g. `export const foo = 1, bar = 2`).
 */
function isVariableStatementExported(node: ts.Node): boolean {
  if (ts.isVariableStatement(node)) {
    return isExportedNode(node);
  }
  // Walk up to the containing VariableStatement if this is a VariableDeclaration
  if (ts.isVariableDeclaration(node) && node.parent && ts.isVariableDeclarationList(node.parent)) {
    const stmt = node.parent.parent;
    if (stmt && ts.isVariableStatement(stmt)) {
      return isExportedNode(stmt);
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// FileIndex
// ---------------------------------------------------------------------------

export class FileIndex {
  private entries: Map<string, FileEntry> = new Map();

  /** Parse and index a file, caching the result. */
  indexFile(filePath: string): FileEntry {
    try {
      const sourceFile = parseFile(filePath);
      const hash = contentHash(sourceFile.text);

      // If already cached and unchanged, return existing
      const existing = this.entries.get(filePath);
      if (existing && existing.contentHash === hash) {
        return existing;
      }

      const functions: FunctionEntry[] = [];
      const classes: ClassEntry[] = [];
      const topLevelStatements: ts.Node[] = [];

      for (const stmt of sourceFile.statements) {
        try {
          this.processTopLevelStatement(
            stmt, filePath, sourceFile, functions, classes, topLevelStatements,
          );
        } catch {
          // Skip malformed statements — don't crash the indexer
          topLevelStatements.push(stmt);
        }
      }

      const entry: FileEntry = {
        filePath,
        sourceFile,
        functions,
        classes,
        topLevelStatements,
        contentHash: hash,
      };

      this.entries.set(filePath, entry);
      return entry;
    } catch {
      // If the file can't be parsed at all, store a minimal entry so callers
      // don't keep retrying on the same broken file.
      const empty: FileEntry = {
        filePath,
        sourceFile: ts.createSourceFile(filePath, '', ts.ScriptTarget.Latest, true),
        functions: [],
        classes: [],
        topLevelStatements: [],
        contentHash: '',
      };
      this.entries.set(filePath, empty);
      return empty;
    }
  }

  /** Get cached entry or null. */
  getEntry(filePath: string): FileEntry | null {
    return this.entries.get(filePath) ?? null;
  }

  /** Check if a file needs re-indexing based on content hash. */
  isStale(filePath: string): boolean {
    const entry = this.entries.get(filePath);
    if (!entry) return true;

    try {
      const sourceFile = parseFile(filePath);
      return contentHash(sourceFile.text) !== entry.contentHash;
    } catch {
      return true;
    }
  }

  /** Remove a file from the index. */
  removeFile(filePath: string): void {
    this.entries.delete(filePath);
  }

  /** Get all indexed file paths. */
  getAllFiles(): string[] {
    return [...this.entries.keys()];
  }

  /** Index multiple files. */
  indexFiles(filePaths: string[]): void {
    for (const fp of filePaths) {
      this.indexFile(fp);
    }
  }

  /** Find a function by canonical ID. */
  findFunction(canonicalId: string): FunctionEntry | null {
    for (const entry of this.entries.values()) {
      const fn = entry.functions.find(f => f.canonicalId === canonicalId);
      if (fn) return fn;
      // Also check class methods
      for (const cls of entry.classes) {
        const method = cls.methods.find(m => m.canonicalId === canonicalId);
        if (method) return method;
        if (cls.constructorEntry?.canonicalId === canonicalId) {
          return cls.constructorEntry;
        }
      }
    }
    return null;
  }

  /** Find a class by canonical ID. */
  findClass(canonicalId: string): ClassEntry | null {
    for (const entry of this.entries.values()) {
      const cls = entry.classes.find(c => c.canonicalId === canonicalId);
      if (cls) return cls;
    }
    return null;
  }

  /** Clear the entire index. */
  clear(): void {
    this.entries.clear();
  }

  // -----------------------------------------------------------------------
  // Private extraction logic
  // -----------------------------------------------------------------------

  private processTopLevelStatement(
    stmt: ts.Statement,
    filePath: string,
    _sourceFile: ts.SourceFile,
    functions: FunctionEntry[],
    classes: ClassEntry[],
    topLevelStatements: ts.Node[],
  ): void {
    // --- Function declarations ---
    if (ts.isFunctionDeclaration(stmt)) {
      const name = stmt.name?.text ?? 'default';
      const exported = isExportedNode(stmt);
      functions.push({
        name,
        canonicalId: `${filePath}#${name}`,
        node: stmt,
        paramCount: paramCount(stmt),
        isAsync: isAsync(stmt),
        isGenerator: isGenerator(stmt),
        isExported: exported,
      });
      return;
    }

    // --- Class declarations ---
    if (ts.isClassDeclaration(stmt)) {
      const cls = this.extractClass(stmt, filePath);
      if (cls) {
        classes.push(cls);
        // Also add methods to the top-level function list for findFunction
        functions.push(...cls.methods);
        if (cls.constructorEntry) {
          functions.push(cls.constructorEntry);
        }
      }
      return;
    }

    // --- Variable statements (arrow functions, function expressions) ---
    if (ts.isVariableStatement(stmt)) {
      const stmtExported = isExportedNode(stmt);
      for (const decl of stmt.declarationList.declarations) {
        const fn = this.extractVariableFunction(decl, filePath, stmtExported);
        if (fn) {
          functions.push(fn);
        }
      }
      // Even if we extracted functions, keep it as top-level for completeness
      topLevelStatements.push(stmt);
      return;
    }

    // --- Export default expression: export default function() {} / export default class {} ---
    if (ts.isExportAssignment(stmt)) {
      if (stmt.expression && (ts.isFunctionExpression(stmt.expression) || ts.isArrowFunction(stmt.expression))) {
        const expr = stmt.expression as ts.FunctionExpression | ts.ArrowFunction;
        functions.push({
          name: 'default',
          canonicalId: `${filePath}#default`,
          node: expr,
          paramCount: paramCount(expr),
          isAsync: isAsync(expr),
          isGenerator: ts.isFunctionExpression(expr) ? isGenerator(expr) : false,
          isExported: true,
        });
        return;
      }
      if (stmt.expression && ts.isClassExpression(stmt.expression)) {
        const cls = this.extractClassLike(stmt.expression, filePath, 'default', true);
        if (cls) {
          classes.push(cls);
          functions.push(...cls.methods);
          if (cls.constructorEntry) functions.push(cls.constructorEntry);
        }
        return;
      }
      topLevelStatements.push(stmt);
      return;
    }

    // Anything else is a top-level statement
    topLevelStatements.push(stmt);
  }

  /**
   * Extract a FunctionEntry from a variable declaration if its initialiser
   * is a function expression or arrow function.
   */
  private extractVariableFunction(
    decl: ts.VariableDeclaration,
    filePath: string,
    stmtExported: boolean,
  ): FunctionEntry | null {
    if (!decl.initializer) return null;
    if (!ts.isIdentifier(decl.name)) return null;

    const init = decl.initializer;
    if (!ts.isArrowFunction(init) && !ts.isFunctionExpression(init)) return null;

    const name = decl.name.text;
    return {
      name,
      canonicalId: `${filePath}#${name}`,
      node: init,
      paramCount: paramCount(init),
      isAsync: isAsync(init),
      isGenerator: ts.isFunctionExpression(init) ? isGenerator(init) : false,
      isExported: stmtExported || isVariableStatementExported(decl),
    };
  }

  /** Extract a ClassEntry from a ClassDeclaration. */
  private extractClass(
    node: ts.ClassDeclaration,
    filePath: string,
  ): ClassEntry | null {
    const name = node.name?.text ?? 'default';
    return this.extractClassLike(node, filePath, name, isExportedNode(node));
  }

  /** Shared extraction for ClassDeclaration and ClassExpression. */
  private extractClassLike(
    node: ts.ClassDeclaration | ts.ClassExpression,
    filePath: string,
    name: string,
    exported: boolean,
  ): ClassEntry {
    const canonicalId = `${filePath}#${name}`;
    const methods: FunctionEntry[] = [];
    let constructorEntry: FunctionEntry | undefined;

    // Heritage clauses
    let baseClassName: string | undefined;
    const implementsNames: string[] = [];

    if (node.heritageClauses) {
      for (const clause of node.heritageClauses) {
        if (clause.token === ts.SyntaxKind.ExtendsKeyword) {
          const firstType = clause.types[0];
          if (firstType && ts.isIdentifier(firstType.expression)) {
            baseClassName = firstType.expression.text;
          }
        } else if (clause.token === ts.SyntaxKind.ImplementsKeyword) {
          for (const typeRef of clause.types) {
            if (ts.isIdentifier(typeRef.expression)) {
              implementsNames.push(typeRef.expression.text);
            }
          }
        }
      }
    }

    // Members
    for (const member of node.members) {
      try {
        if (ts.isConstructorDeclaration(member)) {
          constructorEntry = {
            name: 'constructor',
            canonicalId: `${canonicalId}.constructor`,
            node: member,
            paramCount: paramCount(member),
            isAsync: false,
            isGenerator: false,
            isExported: exported,
            containingClass: name,
          };
        } else if (ts.isMethodDeclaration(member)) {
          const methodName = ts.isIdentifier(member.name)
            ? member.name.text
            : ts.isStringLiteral(member.name)
              ? member.name.text
              : ts.isComputedPropertyName(member.name)
                ? '<computed>'
                : '<unknown>';
          methods.push({
            name: methodName,
            canonicalId: `${canonicalId}.${methodName}`,
            node: member,
            paramCount: paramCount(member),
            isAsync: isAsync(member),
            isGenerator: isGenerator(member),
            isExported: exported,
            containingClass: name,
          });
        } else if (ts.isPropertyDeclaration(member) && member.initializer) {
          // Arrow function class properties: foo = () => {}
          if (ts.isArrowFunction(member.initializer) || ts.isFunctionExpression(member.initializer)) {
            const propName = ts.isIdentifier(member.name) ? member.name.text : '<unknown>';
            const init = member.initializer;
            methods.push({
              name: propName,
              canonicalId: `${canonicalId}.${propName}`,
              node: init,
              paramCount: paramCount(init),
              isAsync: isAsync(init),
              isGenerator: ts.isFunctionExpression(init) ? isGenerator(init) : false,
              isExported: exported,
              containingClass: name,
            });
          }
        }
      } catch {
        // Skip malformed members
      }
    }

    return {
      name,
      canonicalId,
      node,
      methods,
      constructorEntry,
      isExported: exported,
      baseClassName,
      implementsNames,
    };
  }
}

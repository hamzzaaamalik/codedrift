/**
 * ProjectGraph — Top-level orchestrator for cross-file taint analysis.
 *
 * Loads all project files, builds the symbol table, resolves imports,
 * registers call sites and class inheritance, and provides call resolution
 * for taint propagation.
 */

import * as ts from 'typescript';
import * as fs from 'fs';

import { ModuleResolver } from './module-resolver.js';
import type { ImportBinding } from './module-resolver.js';
import { FileIndex } from './file-index.js';
import type { FileEntry as _FileEntry } from './file-index.js';
import { SymbolTable } from './symbol-table.js';
import type { SymbolEntry, CallSite } from './symbol-table.js';

// ---------------------------------------------------------------------------
// ProjectGraph
// ---------------------------------------------------------------------------

export class ProjectGraph {
  readonly projectRoot: string;
  private readonly resolver: ModuleResolver;
  private readonly fileIndex: FileIndex;
  private readonly symbolTable: SymbolTable;

  /** Per-file import bindings for fast call resolution. */
  private readonly fileImports: Map<string, ImportBinding[]> = new Map();

  constructor(projectRoot: string, pathAliases: Set<string>) {
    this.projectRoot = projectRoot;
    this.fileIndex = new FileIndex();
    this.symbolTable = new SymbolTable();
    this.resolver = new ModuleResolver(
      projectRoot,
      pathAliases,
      (absPath: string) => {
        try {
          return fs.existsSync(absPath);
        } catch {
          return false;
        }
      },
    );
  }

  // -------------------------------------------------------------------------
  // Phase 1: Full build
  // -------------------------------------------------------------------------

  /**
   * Parse all files, build the symbol table, resolve imports, register
   * call sites, and resolve class inheritance.
   */
  build(filePaths: string[]): void {
    // Step 1: Index all files (parse ASTs, extract functions/classes)
    this.fileIndex.indexFiles(filePaths);

    // Step 2: For each file, collect module bindings and register exports
    for (const filePath of filePaths) {
      this.processFile(filePath);
    }

    // Step 3: Resolve class inheritance across all files
    this.resolveInheritance(filePaths);

    // Step 4: Walk all function/method bodies to find call sites
    this.discoverCallSites(filePaths);
  }

  // -------------------------------------------------------------------------
  // Incremental update
  // -------------------------------------------------------------------------

  /**
   * Re-process only changed/deleted files without rebuilding everything.
   */
  update(changedFiles: string[], deletedFiles: string[]): void {
    // Remove deleted files
    for (const filePath of deletedFiles) {
      this.fileIndex.removeFile(filePath);
      this.fileImports.delete(filePath);
    }

    // Re-index changed files
    for (const filePath of changedFiles) {
      try {
        this.fileIndex.indexFile(filePath);
        this.processFile(filePath);
      } catch {
        // If a changed file can't be parsed, skip it gracefully
      }
    }

    // Re-resolve inheritance and call sites for changed files only
    this.resolveInheritance(changedFiles);
    this.discoverCallSites(changedFiles);
  }

  // -------------------------------------------------------------------------
  // Call resolution
  // -------------------------------------------------------------------------

  /**
   * Resolve a call expression to its target symbol(s).
   *
   * Handles:
   * - Direct function calls: foo() -> look up 'foo' in imports -> resolve to symbol
   * - Method calls: obj.method() -> look up 'obj' in imports -> resolve class -> find method
   * - Namespace calls: ns.foo() -> look up namespace import -> resolve named export
   * - Constructor: new Foo() -> look up 'Foo' -> resolve to class constructor
   * - this.method() -> look up containing class -> find method (+ inheritance)
   * - super.method() -> look up parent class -> find method
   *
   * Returns array because of dynamic dispatch (multiple possible targets).
   */
  resolveCall(call: ts.CallExpression, fromFile: string): SymbolEntry[] {
    const results: SymbolEntry[] = [];

    try {
      const expr = call.expression;

      // --- new Foo(...) ---
      if (ts.isNewExpression(call.parent) || this.isNewExpressionCall(call)) {
        // The call expression inside `new Foo()` is just `Foo`
        // But typically new expressions are NewExpression, not CallExpression.
        // Handle the case where call.expression is the class identifier.
      }

      // --- Direct identifier call: foo() ---
      if (ts.isIdentifier(expr)) {
        const name = expr.text;
        const symbol = this.resolveIdentifier(name, fromFile);
        if (symbol) {
          results.push(symbol);
        }
        return results;
      }

      // --- Property access: obj.method() or this.method() or super.method() ---
      if (ts.isPropertyAccessExpression(expr)) {
        const methodName = expr.name.text;
        const objExpr = expr.expression;

        // this.method()
        if (objExpr.kind === ts.SyntaxKind.ThisKeyword) {
          const containingClass = this.findContainingClass(call, fromFile);
          if (containingClass) {
            const dispatched = this.symbolTable.resolveMethodDispatch(
              containingClass.canonicalId,
              methodName,
            );
            if (dispatched.length > 0) {
              results.push(...dispatched);
              return results;
            }
            // Check methods map directly
            if (containingClass.methods) {
              const method = containingClass.methods.get(methodName);
              if (method) results.push(method);
            }
          }
          return results;
        }

        // super.method()
        if (objExpr.kind === ts.SyntaxKind.SuperKeyword) {
          const containingClass = this.findContainingClass(call, fromFile);
          if (containingClass?.baseClass) {
            const parentSym = this.symbolTable.getSymbol(containingClass.baseClass);
            if (parentSym?.methods) {
              const method = parentSym.methods.get(methodName);
              if (method) results.push(method);
            }
            // Also check through the full hierarchy above the parent
            const dispatched = this.symbolTable.resolveMethodDispatch(
              containingClass.baseClass,
              methodName,
            );
            if (dispatched.length > 0) {
              results.push(...dispatched);
            }
          }
          return this.deduplicateResults(results);
        }

        // obj.method() where obj is an identifier
        if (ts.isIdentifier(objExpr)) {
          const objName = objExpr.text;
          const imports = this.fileImports.get(fromFile) ?? [];
          const binding = imports.find(imp => imp.localName === objName);

          if (binding) {
            // Namespace import: import * as ns from './mod'; ns.foo()
            if (binding.style === 'namespace' && binding.resolvedPath) {
              const targetSymbol = this.symbolTable.getExportedSymbol(
                binding.resolvedPath,
                methodName,
              );
              if (targetSymbol) {
                results.push(targetSymbol);
                return results;
              }
              // Try re-export resolution
              const reExportOrigin = this.resolver.resolveReExportChain(
                binding.resolvedPath,
                methodName,
              );
              if (reExportOrigin) {
                const originSymbol = this.symbolTable.getExportedSymbol(
                  reExportOrigin.filePath,
                  reExportOrigin.exportName,
                );
                if (originSymbol) results.push(originSymbol);
              }
              return results;
            }

            // Default/named import that resolves to a class: obj.method()
            if (binding.resolvedPath) {
              const objSymbol = this.symbolTable.getExportedSymbol(
                binding.resolvedPath,
                binding.exportName,
              );
              if (objSymbol?.kind === 'class') {
                // Instance method call — check method dispatch
                const dispatched = this.symbolTable.resolveMethodDispatch(
                  objSymbol.canonicalId,
                  methodName,
                );
                if (dispatched.length > 0) {
                  results.push(...dispatched);
                  return results;
                }
                if (objSymbol.methods) {
                  const method = objSymbol.methods.get(methodName);
                  if (method) results.push(method);
                }
                return results;
              }
            }
          }

          // Check if obj is a locally-defined class instance
          const fileEntry = this.fileIndex.getEntry(fromFile);
          if (fileEntry) {
            for (const cls of fileEntry.classes) {
              // Try matching the object name to a class's methods directly
              const clsSym = this.symbolTable.getSymbol(cls.canonicalId);
              if (clsSym?.methods) {
                const method = clsSym.methods.get(methodName);
                if (method) results.push(method);
              }
            }
          }
        }

        return results;
      }
    } catch {
      // Graceful failure — return empty results
    }

    return results;
  }

  // -------------------------------------------------------------------------
  // Reverse lookup
  // -------------------------------------------------------------------------

  /** Get all callers of a symbol (reverse lookup). */
  getCallers(canonicalId: string): CallSite[] {
    return this.symbolTable.getCallersOf(canonicalId);
  }

  // -------------------------------------------------------------------------
  // Import tracing
  // -------------------------------------------------------------------------

  /** Get the full import chain for a binding in a file. */
  traceImport(localName: string, fromFile: string): SymbolEntry | null {
    return this.resolveIdentifier(localName, fromFile);
  }

  // -------------------------------------------------------------------------
  // Accessors
  // -------------------------------------------------------------------------

  /** Get the module resolver instance. */
  getResolver(): ModuleResolver {
    return this.resolver;
  }

  /** Get the file index. */
  getFileIndex(): FileIndex {
    return this.fileIndex;
  }

  /** Get the symbol table. */
  getSymbolTable(): SymbolTable {
    return this.symbolTable;
  }

  /** Get stats. */
  getStats(): { files: number; symbols: number; callSites: number } {
    const stats = this.symbolTable.getStats();
    return {
      files: stats.files,
      symbols: stats.symbols,
      callSites: stats.callSites,
    };
  }

  // =========================================================================
  // Private helpers
  // =========================================================================

  /**
   * Process a single file: collect module bindings, store imports,
   * register exports in the symbol table, and resolve re-exports.
   */
  private processFile(filePath: string): void {
    try {
      const fileEntry = this.fileIndex.getEntry(filePath);
      if (!fileEntry) return;

      const resolution = this.resolver.collectBindings(fileEntry.sourceFile);

      // Store imports for call resolution
      this.fileImports.set(filePath, resolution.imports);

      // Register exports in the symbol table
      this.symbolTable.registerFile(filePath, resolution.exports, fileEntry);

      // Resolve re-export chains and register the origin symbols
      for (const [exportName, origin] of resolution.reExportOrigins) {
        const reExportSymbol = this.symbolTable.getExportedSymbol(filePath, exportName);
        if (reExportSymbol) {
          reExportSymbol.originalCanonicalId = `${origin.filePath}#${origin.exportName}`;
        }
      }
    } catch {
      // Skip files that fail to process
    }
  }

  /**
   * Resolve class inheritance across all given files.
   * For each class with a baseClassName, find the base class symbol
   * (either locally defined or imported) and register the relationship.
   */
  private resolveInheritance(filePaths: string[]): void {
    for (const filePath of filePaths) {
      try {
        const fileEntry = this.fileIndex.getEntry(filePath);
        if (!fileEntry) continue;

        for (const cls of fileEntry.classes) {
          if (!cls.baseClassName) continue;

          const childSymbol = this.symbolTable.getSymbol(cls.canonicalId)
            ?? this.symbolTable.getExportedSymbol(filePath, cls.name);

          if (!childSymbol) continue;

          // Try to find the base class: first check imports, then local classes
          const baseSymbol = this.resolveIdentifier(cls.baseClassName, filePath);
          if (baseSymbol && baseSymbol.kind === 'class') {
            this.symbolTable.registerInheritance(
              childSymbol.canonicalId,
              baseSymbol.canonicalId,
            );
            continue;
          }

          // Check local classes in the same file
          const localBase = fileEntry.classes.find(c => c.name === cls.baseClassName);
          if (localBase) {
            const localBaseSym = this.symbolTable.getSymbol(localBase.canonicalId);
            if (localBaseSym) {
              this.symbolTable.registerInheritance(
                childSymbol.canonicalId,
                localBaseSym.canonicalId,
              );
            }
          }
        }
      } catch {
        // Skip files with inheritance resolution errors
      }
    }
  }

  /**
   * Walk all function/method bodies in the given files to discover call sites
   * and register them in the symbol table.
   */
  private discoverCallSites(filePaths: string[]): void {
    for (const filePath of filePaths) {
      try {
        const fileEntry = this.fileIndex.getEntry(filePath);
        if (!fileEntry) continue;

        // Walk top-level functions
        for (const fn of fileEntry.functions) {
          this.walkForCallSites(fn.node, fn.canonicalId, filePath);
        }

        // Walk class methods and constructors
        for (const cls of fileEntry.classes) {
          for (const method of cls.methods) {
            this.walkForCallSites(method.node, method.canonicalId, filePath);
          }
          if (cls.constructorEntry) {
            this.walkForCallSites(
              cls.constructorEntry.node,
              cls.constructorEntry.canonicalId,
              filePath,
            );
          }
        }

        // Walk top-level statements (module-level calls)
        for (const stmt of fileEntry.topLevelStatements) {
          this.walkForCallSites(stmt, `${filePath}#<module>`, filePath);
        }
      } catch {
        // Skip files with call site discovery errors
      }
    }
  }

  /**
   * Recursively walk a node looking for CallExpression nodes.
   * For each call found, try to resolve the callee and register a CallSite.
   */
  private walkForCallSites(
    node: ts.Node,
    callerCanonicalId: string,
    filePath: string,
  ): void {
    try {
      if (ts.isCallExpression(node)) {
        const targets = this.resolveCall(node, filePath);
        for (const target of targets) {
          this.symbolTable.registerCallSite({
            callerCanonicalId,
            calleeCanonicalId: target.canonicalId,
            node,
            filePath,
            argCount: node.arguments.length,
          });
        }
      }

      // Also handle `new Foo()` as a call to the constructor
      if (ts.isNewExpression(node)) {
        const newTargets = this.resolveNewExpression(node, filePath);
        for (const target of newTargets) {
          this.symbolTable.registerCallSite({
            callerCanonicalId,
            calleeCanonicalId: target.canonicalId,
            node: node as unknown as ts.CallExpression,
            filePath,
            argCount: node.arguments?.length ?? 0,
          });
        }
      }

      ts.forEachChild(node, child => {
        // Don't recurse into nested function/class declarations — they have
        // their own callerCanonicalId and are handled separately.
        if (
          ts.isFunctionDeclaration(child) ||
          ts.isFunctionExpression(child) ||
          ts.isArrowFunction(child) ||
          ts.isClassDeclaration(child) ||
          ts.isClassExpression(child) ||
          ts.isMethodDeclaration(child) ||
          ts.isConstructorDeclaration(child)
        ) {
          return;
        }
        this.walkForCallSites(child, callerCanonicalId, filePath);
      });
    } catch {
      // Graceful — skip nodes that cause errors
    }
  }

  /**
   * Resolve a `new Foo()` expression to the class constructor symbol.
   */
  private resolveNewExpression(node: ts.NewExpression, fromFile: string): SymbolEntry[] {
    const results: SymbolEntry[] = [];

    try {
      const expr = node.expression;

      if (ts.isIdentifier(expr)) {
        const name = expr.text;
        const symbol = this.resolveIdentifier(name, fromFile);
        if (symbol?.kind === 'class') {
          // Return the constructor if available, otherwise the class itself
          if (symbol.methods) {
            const ctor = symbol.methods.get('constructor');
            if (ctor) {
              results.push(ctor);
              return results;
            }
          }
          results.push(symbol);
        }
      }

      // new obj.Foo() — property access
      if (ts.isPropertyAccessExpression(expr)) {
        const className = expr.name.text;
        if (ts.isIdentifier(expr.expression)) {
          const objName = expr.expression.text;
          const imports = this.fileImports.get(fromFile) ?? [];
          const binding = imports.find(imp => imp.localName === objName);
          if (binding?.style === 'namespace' && binding.resolvedPath) {
            const classSym = this.symbolTable.getExportedSymbol(
              binding.resolvedPath,
              className,
            );
            if (classSym?.kind === 'class' && classSym.methods) {
              const ctor = classSym.methods.get('constructor');
              if (ctor) results.push(ctor);
              else results.push(classSym);
            }
          }
        }
      }
    } catch {
      // Graceful failure
    }

    return results;
  }

  /**
   * Resolve a local identifier to a SymbolEntry.
   * Checks imports first, then local file symbols.
   */
  private resolveIdentifier(name: string, fromFile: string): SymbolEntry | null {
    // Check imports
    const imports = this.fileImports.get(fromFile) ?? [];
    const binding = imports.find(
      imp => imp.localName === name && !imp.isTypeOnly,
    );

    if (binding?.resolvedPath) {
      // For namespace imports, resolve to the module's namespace
      // (callers should use resolveCall for ns.method())
      if (binding.style === 'namespace') {
        // Return the first exported symbol as a namespace representative,
        // or look for a default export
        return this.symbolTable.getExportedSymbol(binding.resolvedPath, 'default')
          ?? this.symbolTable.getFileSymbols(binding.resolvedPath)[0]
          ?? null;
      }

      // Named/default import — resolve to the exported symbol
      let symbol = this.symbolTable.getExportedSymbol(
        binding.resolvedPath,
        binding.exportName,
      );

      // If the symbol is a re-export, chase the original
      if (symbol?.originalCanonicalId) {
        const original = this.symbolTable.getSymbol(symbol.originalCanonicalId);
        if (original) symbol = original;
      }

      if (symbol) return symbol;

      // Try re-export chain resolution
      const reExportOrigin = this.resolver.resolveReExportChain(
        binding.resolvedPath,
        binding.exportName,
      );
      if (reExportOrigin) {
        const originSymbol = this.symbolTable.getExportedSymbol(
          reExportOrigin.filePath,
          reExportOrigin.exportName,
        );
        if (originSymbol) return originSymbol;
      }
    }

    // Check local file symbols (functions/classes defined in the same file)
    const fileEntry = this.fileIndex.getEntry(fromFile);
    if (fileEntry) {
      // Check functions
      for (const fn of fileEntry.functions) {
        if (fn.name === name) {
          return this.symbolTable.getSymbol(fn.canonicalId) ?? null;
        }
      }
      // Check classes
      for (const cls of fileEntry.classes) {
        if (cls.name === name) {
          return this.symbolTable.getSymbol(cls.canonicalId) ?? null;
        }
      }
    }

    return null;
  }

  /**
   * Find the containing class symbol for a node (used for this/super resolution).
   */
  private findContainingClass(node: ts.Node, fromFile: string): SymbolEntry | null {
    let current: ts.Node | undefined = node;

    while (current) {
      if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) {
        const className = current.name?.text ?? 'default';
        const canonicalId = `${fromFile}#${className}`;

        // Try symbol table first
        const sym = this.symbolTable.getSymbol(canonicalId);
        if (sym) return sym;

        // Try exported symbol
        return this.symbolTable.getExportedSymbol(fromFile, className);
      }
      current = current.parent;
    }

    return null;
  }

  /**
   * Check if a CallExpression is actually part of a NewExpression.
   * This handles edge cases in AST representation.
   */
  private isNewExpressionCall(call: ts.CallExpression): boolean {
    return call.parent !== undefined && ts.isNewExpression(call.parent);
  }

  /**
   * Deduplicate symbol entries by canonicalId.
   */
  private deduplicateResults(results: SymbolEntry[]): SymbolEntry[] {
    const seen = new Set<string>();
    return results.filter(sym => {
      if (seen.has(sym.canonicalId)) return false;
      seen.add(sym.canonicalId);
      return true;
    });
  }
}

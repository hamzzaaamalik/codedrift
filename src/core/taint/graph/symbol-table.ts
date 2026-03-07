/**
 * SymbolTable — Global symbol registry for cross-file taint analysis
 *
 * Maps exported symbols to their declarations across the entire project,
 * tracks call sites, and resolves class inheritance for virtual dispatch.
 */

import * as ts from 'typescript';
import type { FileEntry, FunctionEntry, ClassEntry } from './file-index.js';

// ---------------------------------------------------------------------------
// Types — Import/Export bindings from ModuleResolver
// ---------------------------------------------------------------------------

export interface ImportBinding {
  localName: string;
  exportName: string;
  specifier: string;
  resolvedPath: string | null;
  style: 'named' | 'default' | 'namespace' | 'side-effect';
  isDynamic: boolean;
  isTypeOnly: boolean;
  node: ts.Node;
}

export interface ExportBinding {
  exportName: string;
  localName: string;
  style:
    | 'named'
    | 'default'
    | 'const'
    | 'class'
    | 'module-exports'
    | 'module-exports-direct'
    | 'exports-property'
    | 're-export'
    | 'wildcard-re-export';
  node: ts.Node;
  fromSpecifier?: string;
  fromResolvedPath?: string;
}

// ---------------------------------------------------------------------------
// Symbol / call-site types
// ---------------------------------------------------------------------------

export type SymbolKind = 'function' | 'class' | 'variable' | 'type' | 'namespace' | 'enum';

export interface SymbolEntry {
  canonicalId: string;
  filePath: string;
  exportName: string;
  localName: string;
  kind: SymbolKind;
  node: ts.Node;
  isDefaultExport: boolean;

  // Classes
  methods?: Map<string, SymbolEntry>;
  baseClass?: string;

  // Functions
  paramCount?: number;
  isAsync?: boolean;

  // Re-export resolution
  originalCanonicalId?: string;
}

export interface CallSite {
  callerCanonicalId: string;
  calleeCanonicalId: string;
  node: ts.CallExpression;
  filePath: string;
  argCount: number;
}

// ---------------------------------------------------------------------------
// SymbolTable
// ---------------------------------------------------------------------------

export class SymbolTable {
  private symbols: Map<string, SymbolEntry> = new Map();
  private callSites: CallSite[] = [];
  /** Reverse map: canonicalId -> Set of caller canonicalIds */
  private callers: Map<string, Set<string>> = new Map();
  /** Track which files have been registered so we can report stats. */
  private registeredFiles: Set<string> = new Set();

  // -----------------------------------------------------------------------
  // Registration
  // -----------------------------------------------------------------------

  /**
   * Register all exported symbols from a file, matching export bindings
   * against the file index's extracted functions and classes.
   */
  registerFile(
    filePath: string,
    exports: ExportBinding[],
    fileEntry: FileEntry,
  ): void {
    this.registeredFiles.add(filePath);

    // Build quick lookup maps from the FileEntry
    const fnByName = new Map<string, FunctionEntry>();
    for (const fn of fileEntry.functions) {
      fnByName.set(fn.name, fn);
    }
    const clsByName = new Map<string, ClassEntry>();
    for (const cls of fileEntry.classes) {
      clsByName.set(cls.name, cls);
    }

    for (const exp of exports) {
      try {
        this.registerExportBinding(filePath, exp, fnByName, clsByName);
      } catch {
        // Skip malformed bindings
      }
    }
  }

  // -----------------------------------------------------------------------
  // Lookups
  // -----------------------------------------------------------------------

  /** Look up a symbol by canonical ID. */
  getSymbol(canonicalId: string): SymbolEntry | null {
    return this.symbols.get(canonicalId) ?? null;
  }

  /** Look up a symbol by file path and export name. */
  getExportedSymbol(filePath: string, exportName: string): SymbolEntry | null {
    return this.symbols.get(`${filePath}#${exportName}`) ?? null;
  }

  /** Get all symbols from a file. */
  getFileSymbols(filePath: string): SymbolEntry[] {
    const prefix = `${filePath}#`;
    const result: SymbolEntry[] = [];
    for (const [id, sym] of this.symbols) {
      if (id.startsWith(prefix) && sym.filePath === filePath) {
        result.push(sym);
      }
    }
    return result;
  }

  // -----------------------------------------------------------------------
  // Call graph
  // -----------------------------------------------------------------------

  /** Register a call site (callerCanonicalId -> calleeCanonicalId). */
  registerCallSite(callSite: CallSite): void {
    this.callSites.push(callSite);

    // Maintain reverse map
    let set = this.callers.get(callSite.calleeCanonicalId);
    if (!set) {
      set = new Set();
      this.callers.set(callSite.calleeCanonicalId, set);
    }
    set.add(callSite.callerCanonicalId);
  }

  /** Get all call sites targeting a symbol. */
  getCallersOf(canonicalId: string): CallSite[] {
    return this.callSites.filter(cs => cs.calleeCanonicalId === canonicalId);
  }

  /** Get all call sites originating from a symbol. */
  getCalleesOf(canonicalId: string): CallSite[] {
    return this.callSites.filter(cs => cs.callerCanonicalId === canonicalId);
  }

  // -----------------------------------------------------------------------
  // Inheritance
  // -----------------------------------------------------------------------

  /** Register a resolved base class relationship. */
  registerInheritance(childCanonicalId: string, parentCanonicalId: string): void {
    const child = this.symbols.get(childCanonicalId);
    if (child && child.kind === 'class') {
      child.baseClass = parentCanonicalId;
    }
  }

  /**
   * Get the full class hierarchy as canonicalIds.
   * Walks upward from the given class to the root, then returns
   * in order from root to leaf.
   */
  getClassHierarchy(classCanonicalId: string): string[] {
    const chain: string[] = [];
    const visited = new Set<string>();
    let current: string | undefined = classCanonicalId;

    while (current && !visited.has(current)) {
      visited.add(current);
      chain.push(current);
      const sym = this.symbols.get(current);
      current = sym?.baseClass;
    }

    // Reverse so root class comes first
    chain.reverse();
    return chain;
  }

  /**
   * Find all implementations of a class method through the inheritance chain.
   * Walks from the class upward to the root, collecting every override found.
   */
  resolveMethodDispatch(classCanonicalId: string, methodName: string): SymbolEntry[] {
    const hierarchy = this.getClassHierarchy(classCanonicalId);
    const results: SymbolEntry[] = [];

    for (const clsId of hierarchy) {
      const cls = this.symbols.get(clsId);
      if (!cls || cls.kind !== 'class' || !cls.methods) continue;
      const method = cls.methods.get(methodName);
      if (method) {
        results.push(method);
      }
    }

    return results;
  }

  // -----------------------------------------------------------------------
  // Maintenance
  // -----------------------------------------------------------------------

  /** Clear everything. */
  clear(): void {
    this.symbols.clear();
    this.callSites.length = 0;
    this.callers.clear();
    this.registeredFiles.clear();
  }

  /** Get stats. */
  getStats(): { symbols: number; callSites: number; files: number } {
    return {
      symbols: this.symbols.size,
      callSites: this.callSites.length,
      files: this.registeredFiles.size,
    };
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private registerExportBinding(
    filePath: string,
    exp: ExportBinding,
    fnByName: Map<string, FunctionEntry>,
    clsByName: Map<string, ClassEntry>,
  ): void {
    const exportName = exp.exportName;
    const localName = exp.localName;
    const isDefault = exportName === 'default' || exp.style === 'default';
    const canonicalId = `${filePath}#${exportName}`;

    // --- Re-exports: delegate to original file ---
    if (exp.style === 're-export' || exp.style === 'wildcard-re-export') {
      if (exp.fromResolvedPath) {
        const originalId = `${exp.fromResolvedPath}#${localName}`;
        const entry: SymbolEntry = {
          canonicalId,
          filePath,
          exportName,
          localName,
          kind: 'variable', // Will be refined when the original file is registered
          node: exp.node,
          isDefaultExport: isDefault,
          originalCanonicalId: originalId,
        };
        this.symbols.set(canonicalId, entry);
      }
      return;
    }

    // --- CJS module.exports = { foo, bar } ---
    if (exp.style === 'module-exports') {
      // The node is the object literal; create entries for each property
      const objLiteral = this.findObjectLiteral(exp.node);
      if (objLiteral && ts.isObjectLiteralExpression(objLiteral)) {
        for (const prop of objLiteral.properties) {
          try {
            if (ts.isShorthandPropertyAssignment(prop)) {
              const propName = prop.name.text;
              this.registerSingleExport(
                filePath, propName, propName, false, prop, fnByName, clsByName,
              );
            } else if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
              const propName = prop.name.text;
              const valueName = ts.isIdentifier(prop.initializer) ? prop.initializer.text : propName;
              this.registerSingleExport(
                filePath, propName, valueName, false, prop, fnByName, clsByName,
              );
            }
          } catch {
            // Skip malformed properties
          }
        }
        return;
      }
      // Fallback: register as a single variable export
      this.symbols.set(canonicalId, {
        canonicalId,
        filePath,
        exportName,
        localName,
        kind: 'variable',
        node: exp.node,
        isDefaultExport: isDefault,
      });
      return;
    }

    // --- Standard exports ---
    this.registerSingleExport(
      filePath, exportName, localName, isDefault, exp.node, fnByName, clsByName,
    );
  }

  /**
   * Register a single named export, matching it against known functions/classes.
   */
  private registerSingleExport(
    filePath: string,
    exportName: string,
    localName: string,
    isDefault: boolean,
    node: ts.Node,
    fnByName: Map<string, FunctionEntry>,
    clsByName: Map<string, ClassEntry>,
  ): void {
    const canonicalId = `${filePath}#${exportName}`;

    // Try matching to a class
    const cls = clsByName.get(localName);
    if (cls) {
      const methods = new Map<string, SymbolEntry>();
      for (const m of cls.methods) {
        methods.set(m.name, {
          canonicalId: m.canonicalId,
          filePath,
          exportName: m.name,
          localName: m.name,
          kind: 'function',
          node: m.node,
          isDefaultExport: false,
          paramCount: m.paramCount,
          isAsync: m.isAsync,
        });
      }

      const entry: SymbolEntry = {
        canonicalId,
        filePath,
        exportName,
        localName,
        kind: 'class',
        node: cls.node,
        isDefaultExport: isDefault,
        methods,
        baseClass: undefined, // Resolved later via registerInheritance
      };

      // Register constructor as a method too
      if (cls.constructorEntry) {
        methods.set('constructor', {
          canonicalId: cls.constructorEntry.canonicalId,
          filePath,
          exportName: 'constructor',
          localName: 'constructor',
          kind: 'function',
          node: cls.constructorEntry.node,
          isDefaultExport: false,
          paramCount: cls.constructorEntry.paramCount,
          isAsync: false,
        });
      }

      this.symbols.set(canonicalId, entry);
      return;
    }

    // Try matching to a function
    const fn = fnByName.get(localName);
    if (fn) {
      this.symbols.set(canonicalId, {
        canonicalId,
        filePath,
        exportName,
        localName,
        kind: 'function',
        node: fn.node,
        isDefaultExport: isDefault,
        paramCount: fn.paramCount,
        isAsync: fn.isAsync,
      });
      return;
    }

    // Fallback: variable
    this.symbols.set(canonicalId, {
      canonicalId,
      filePath,
      exportName,
      localName,
      kind: 'variable',
      node,
      isDefaultExport: isDefault,
    });
  }

  /**
   * Attempt to find an ObjectLiteralExpression from a module.exports node.
   * Handles `module.exports = { ... }` where the node might be the
   * BinaryExpression or the ObjectLiteralExpression itself.
   */
  private findObjectLiteral(node: ts.Node): ts.ObjectLiteralExpression | null {
    if (ts.isObjectLiteralExpression(node)) {
      return node;
    }
    if (ts.isBinaryExpression(node) && ts.isObjectLiteralExpression(node.right)) {
      return node.right;
    }
    // Walk children one level (ExpressionStatement → BinaryExpression → OLE)
    let result: ts.ObjectLiteralExpression | null = null;
    ts.forEachChild(node, child => {
      if (result) return;
      if (ts.isObjectLiteralExpression(child)) {
        result = child;
      } else if (ts.isBinaryExpression(child) && ts.isObjectLiteralExpression(child.right)) {
        result = child.right;
      }
    });
    return result;
  }
}

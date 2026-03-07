/**
 * Module Resolver — Universal import/export resolver for cross-file taint analysis.
 *
 * Resolves ES module imports, CommonJS require/exports, dynamic imports,
 * path aliases, and re-export chains to absolute file paths.
 */

import * as ts from 'typescript';
import * as path from 'path';
import * as fs from 'fs';

// ─── Types ───────────────────────────────────────────────────────────────────

export type ImportStyle = 'named' | 'default' | 'namespace' | 'side-effect';

export type ExportStyle =
  | 'named'
  | 'default'
  | 'const'
  | 'class'
  | 'module-exports'
  | 'module-exports-direct'
  | 'exports-property'
  | 're-export'
  | 'wildcard-re-export';

export interface ImportBinding {
  localName: string;
  exportName: string;        // 'default' for default imports, '*' for namespace
  specifier: string;         // raw specifier string
  resolvedPath: string | null; // absolute path or null if unresolvable
  style: ImportStyle;
  isDynamic: boolean;
  isTypeOnly: boolean;
  node: ts.Node;
}

export interface ExportBinding {
  exportName: string;        // 'default' for default exports
  localName: string;         // local declaration name
  style: ExportStyle;
  node: ts.Node;
  /** For re-exports: the source specifier */
  fromSpecifier?: string;
  fromResolvedPath?: string;
}

export interface DynamicImportSite {
  specifierExpr: ts.Expression;
  /** Static prefix extracted from template/concat, or null */
  staticPrefix: string | null;
  /** Fully resolved path if deterministic, null otherwise */
  resolvedPath: string | null;
  /** All candidate paths from glob expansion */
  candidates: string[];
  node: ts.Node;
}

export interface ModuleResolution {
  imports: ImportBinding[];
  exports: ExportBinding[];
  dynamicImports: DynamicImportSite[];
  /** Re-export chains resolved to original declarations */
  reExportOrigins: Map<string, { filePath: string; exportName: string }>;
}

// ─── File resolution extensions ──────────────────────────────────────────────

const RESOLVE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx'];

const INDEX_FILES = RESOLVE_EXTENSIONS.map(ext => `index${ext}`);

// ─── Module Resolver ─────────────────────────────────────────────────────────

export class ModuleResolver {
  private readonly projectRoot: string;
  private readonly pathAliases: Set<string>;
  private readonly fileExists: (absPath: string) => boolean;

  /** Cache specifier resolutions: `${fromFile}::${specifier}` -> resolved path */
  private readonly resolveCache = new Map<string, string | null>();

  constructor(
    projectRoot: string,
    pathAliases: Set<string>,
    fileExists: (absPath: string) => boolean,
  ) {
    this.projectRoot = path.resolve(projectRoot);
    this.pathAliases = pathAliases;
    this.fileExists = fileExists;
  }

  // ── Public API ───────────────────────────────────────────────────────────

  /**
   * Resolve a single import specifier to an absolute file path.
   * Returns null for external packages or unresolvable specifiers.
   */
  resolveSpecifier(specifier: string, fromFile: string): string | null {
    const cacheKey = `${fromFile}::${specifier}`;
    if (this.resolveCache.has(cacheKey)) {
      return this.resolveCache.get(cacheKey)!;
    }

    const result = this.resolveSpecifierUncached(specifier, fromFile);
    this.resolveCache.set(cacheKey, result);
    return result;
  }

  /**
   * Collect all imports, exports, and dynamic imports from a source file.
   */
  collectBindings(sourceFile: ts.SourceFile): ModuleResolution {
    const imports: ImportBinding[] = [];
    const exports: ExportBinding[] = [];
    const dynamicImports: DynamicImportSite[] = [];
    const filePath = sourceFile.fileName;

    this.visitNode(sourceFile, sourceFile, filePath, imports, exports, dynamicImports);

    // Resolve re-export origins
    const reExportOrigins = new Map<string, { filePath: string; exportName: string }>();
    for (const exp of exports) {
      if (
        (exp.style === 're-export' || exp.style === 'wildcard-re-export') &&
        exp.fromResolvedPath
      ) {
        const origin = this.resolveReExportChain(
          exp.fromResolvedPath,
          exp.exportName === '*' ? '*' : exp.exportName,
        );
        if (origin) {
          reExportOrigins.set(exp.exportName, origin);
        }
      }
    }

    return { imports, exports, dynamicImports, reExportOrigins };
  }

  /**
   * Resolve a dynamic import expression to candidate paths.
   */
  resolveDynamic(
    expr: ts.Expression,
    fromFile: string,
    sourceFile: ts.SourceFile,
  ): DynamicImportSite {
    // Case 1: string literal — fully resolvable
    if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
      const specifier = ts.isStringLiteral(expr) ? expr.text : expr.text;
      const resolved = this.resolveSpecifier(specifier, fromFile);
      return {
        specifierExpr: expr,
        staticPrefix: specifier,
        resolvedPath: resolved,
        candidates: resolved ? [resolved] : [],
        node: expr,
      };
    }

    // Case 2: template literal — extract static prefix
    if (ts.isTemplateExpression(expr)) {
      const prefix = expr.head.text;
      const staticPrefix = prefix || null;
      return this.buildDynamicSite(expr, staticPrefix, fromFile);
    }

    // Case 3: binary expression (string concatenation) — extract static prefix
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const prefix = this.extractConcatPrefix(expr);
      return this.buildDynamicSite(expr, prefix, fromFile);
    }

    // Case 4: identifier — try backward slice for string literal assignment
    if (ts.isIdentifier(expr)) {
      const resolved = this.tryBackwardSlice(expr, sourceFile, fromFile);
      if (resolved) {
        return {
          specifierExpr: expr,
          staticPrefix: resolved.specifier,
          resolvedPath: resolved.path,
          candidates: resolved.path ? [resolved.path] : [],
          node: expr,
        };
      }
    }

    // Unresolvable
    return {
      specifierExpr: expr,
      staticPrefix: null,
      resolvedPath: null,
      candidates: [],
      node: expr,
    };
  }

  /**
   * Follow re-export chains to find the original declaration.
   * Prevents cycles via the `visited` set.
   */
  resolveReExportChain(
    filePath: string,
    exportName: string,
    visited?: Set<string>,
  ): { filePath: string; exportName: string } | null {
    const key = `${filePath}::${exportName}`;
    const seen = visited ?? new Set<string>();
    if (seen.has(key)) return null; // cycle
    seen.add(key);

    // We need to parse the target file to check its exports
    let sourceFile: ts.SourceFile;
    try {
      const content = this.readFileContent(filePath);
      if (content === null) return null;
      sourceFile = ts.createSourceFile(
        filePath,
        content,
        ts.ScriptTarget.Latest,
        true,
        this.getScriptKind(filePath),
      );
    } catch {
      return null;
    }

    // Collect exports from the target file
    const resolution = this.collectBindings(sourceFile);

    // For wildcard re-exports, the name passes through
    if (exportName === '*') {
      return { filePath, exportName: '*' };
    }

    for (const exp of resolution.exports) {
      if (exp.exportName !== exportName) continue;

      if (
        (exp.style === 're-export' || exp.style === 'wildcard-re-export') &&
        exp.fromResolvedPath
      ) {
        // Follow the chain
        const nextExportName = exp.style === 'wildcard-re-export' ? exportName : exp.exportName;
        return this.resolveReExportChain(exp.fromResolvedPath, nextExportName, seen);
      }

      // Found the original declaration
      return { filePath, exportName };
    }

    // Check wildcard re-exports — the name might pass through a `export * from`
    for (const exp of resolution.exports) {
      if (exp.style === 'wildcard-re-export' && exp.fromResolvedPath) {
        const origin = this.resolveReExportChain(exp.fromResolvedPath, exportName, seen);
        if (origin) return origin;
      }
    }

    return null;
  }

  // ── Private: specifier resolution ────────────────────────────────────────

  private resolveSpecifierUncached(specifier: string, fromFile: string): string | null {
    if (!specifier) return null;

    // Relative import: ./foo, ../foo
    if (specifier.startsWith('.')) {
      const dir = path.dirname(fromFile);
      const absolute = path.resolve(dir, specifier);
      return this.tryResolveFile(absolute);
    }

    // Path alias: @/foo, @components/bar, etc.
    for (const alias of this.pathAliases) {
      if (specifier === alias || specifier.startsWith(alias)) {
        // Map alias to project root + remainder
        // e.g. "@/foo" with alias "@/" -> projectRoot/foo
        const remainder = specifier.slice(alias.length);
        const absolute = path.resolve(this.projectRoot, 'src', remainder);
        const resolved = this.tryResolveFile(absolute);
        if (resolved) return resolved;

        // Also try without 'src' prefix (some projects alias to root)
        const absoluteNoSrc = path.resolve(this.projectRoot, remainder);
        return this.tryResolveFile(absoluteNoSrc);
      }
    }

    // Bare specifier (external package): lodash, react, etc.
    // Mark as external — return null
    return null;
  }

  /**
   * Try to resolve an absolute base path to an existing file.
   * Tries extensions, then index files in directory.
   */
  private tryResolveFile(basePath: string): string | null {
    // Normalize to forward slashes for consistent fileExists checks across platforms
    const normalize = (p: string) => p.replace(/\\/g, '/');

    // Exact match (already has extension)
    if (this.hasKnownExtension(basePath) && this.fileExists(normalize(basePath))) {
      return this.normalizePath(basePath);
    }

    // Try appending extensions
    for (const ext of RESOLVE_EXTENSIONS) {
      const candidate = basePath + ext;
      if (this.fileExists(normalize(candidate))) {
        return this.normalizePath(candidate);
      }
    }

    // Try as directory with index file
    for (const indexFile of INDEX_FILES) {
      const candidate = path.join(basePath, indexFile);
      if (this.fileExists(normalize(candidate))) {
        return this.normalizePath(candidate);
      }
    }

    // Exact match without known extension (e.g. specifier already includes .js)
    if (this.fileExists(normalize(basePath))) {
      return this.normalizePath(basePath);
    }

    return null;
  }

  private hasKnownExtension(filePath: string): boolean {
    const ext = path.extname(filePath);
    return RESOLVE_EXTENSIONS.includes(ext);
  }

  private normalizePath(p: string): string {
    return path.resolve(p).replace(/\\/g, '/');
  }

  // ── Private: AST visitors ────────────────────────────────────────────────

  private visitNode(
    node: ts.Node,
    sourceFile: ts.SourceFile,
    filePath: string,
    imports: ImportBinding[],
    exports: ExportBinding[],
    dynamicImports: DynamicImportSite[],
  ): void {
    // ES import declarations
    if (ts.isImportDeclaration(node)) {
      this.collectESImport(node, sourceFile, filePath, imports);
    }

    // ES export declarations
    else if (ts.isExportDeclaration(node)) {
      this.collectESExportDeclaration(node, sourceFile, filePath, exports);
    }

    // export default ...
    else if (ts.isExportAssignment(node)) {
      this.collectExportAssignment(node, exports);
    }

    // Declarations with export modifier: export function foo(), export class Bar, export const x
    else if (this.hasExportModifier(node)) {
      this.collectExportedDeclaration(node, exports);
    }

    // require() calls (CJS)
    else if (this.isRequireCall(node)) {
      this.collectRequireImport(node as ts.CallExpression, sourceFile, filePath, imports);
    }

    // module.exports = ... or exports.foo = ...
    else if (this.isModuleExportsAssignment(node)) {
      this.collectCJSExport(node as ts.BinaryExpression, exports);
    } else if (this.isExportsPropertyAssignment(node)) {
      this.collectExportsPropertyExport(node as ts.BinaryExpression, exports);
    }

    // Dynamic import() calls
    else if (this.isDynamicImportCall(node)) {
      const callExpr = node as ts.CallExpression;
      const arg = callExpr.arguments[0];
      if (arg) {
        dynamicImports.push(this.resolveDynamic(arg, filePath, sourceFile));
      }
    }

    // Recurse
    ts.forEachChild(node, child =>
      this.visitNode(child, sourceFile, filePath, imports, exports, dynamicImports),
    );
  }

  // ── ES Import collection ────────────────────────────────────────────────

  private collectESImport(
    node: ts.ImportDeclaration,
    _sourceFile: ts.SourceFile,
    filePath: string,
    imports: ImportBinding[],
  ): void {
    if (!ts.isStringLiteral(node.moduleSpecifier)) return;

    const specifier = node.moduleSpecifier.text;
    const resolvedPath = this.resolveSpecifier(specifier, filePath);
    const isTypeOnly = node.importClause?.isTypeOnly === true;

    const clause = node.importClause;
    if (!clause) {
      // Side-effect import: import './polyfills'
      imports.push({
        localName: '',
        exportName: '',
        specifier,
        resolvedPath,
        style: 'side-effect',
        isDynamic: false,
        isTypeOnly,
        node,
      });
      return;
    }

    // Default import: import foo from './bar'
    if (clause.name) {
      imports.push({
        localName: clause.name.text,
        exportName: 'default',
        specifier,
        resolvedPath,
        style: 'default',
        isDynamic: false,
        isTypeOnly: isTypeOnly || clause.isTypeOnly === true,
        node,
      });
    }

    const namedBindings = clause.namedBindings;
    if (!namedBindings) return;

    // Namespace import: import * as bar from './bar'
    if (ts.isNamespaceImport(namedBindings)) {
      imports.push({
        localName: namedBindings.name.text,
        exportName: '*',
        specifier,
        resolvedPath,
        style: 'namespace',
        isDynamic: false,
        isTypeOnly: isTypeOnly || clause.isTypeOnly === true,
        node,
      });
    }

    // Named imports: import { foo, bar as baz } from './bar'
    else if (ts.isNamedImports(namedBindings)) {
      for (const element of namedBindings.elements) {
        const exportName = element.propertyName
          ? element.propertyName.text
          : element.name.text;
        imports.push({
          localName: element.name.text,
          exportName,
          specifier,
          resolvedPath,
          style: 'named',
          isDynamic: false,
          isTypeOnly: isTypeOnly || element.isTypeOnly === true,
          node: element,
        });
      }
    }
  }

  // ── ES Export collection ─────────────────────────────────────────────────

  private collectESExportDeclaration(
    node: ts.ExportDeclaration,
    _sourceFile: ts.SourceFile,
    filePath: string,
    exports: ExportBinding[],
  ): void {
    const fromSpecifier = node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)
      ? node.moduleSpecifier.text
      : undefined;
    const fromResolvedPath = fromSpecifier
      ? this.resolveSpecifier(fromSpecifier, filePath) ?? undefined
      : undefined;

    // export * from './bar' (wildcard re-export)
    if (!node.exportClause) {
      if (fromSpecifier) {
        exports.push({
          exportName: '*',
          localName: '*',
          style: 'wildcard-re-export',
          node,
          fromSpecifier,
          fromResolvedPath,
        });
      }
      return;
    }

    // export * as ns from './bar' (namespace re-export)
    if (ts.isNamespaceExport(node.exportClause)) {
      exports.push({
        exportName: node.exportClause.name.text,
        localName: '*',
        style: 'wildcard-re-export',
        node,
        fromSpecifier,
        fromResolvedPath,
      });
      return;
    }

    // export { foo, bar as baz } or export { foo } from './bar'
    if (ts.isNamedExports(node.exportClause)) {
      for (const element of node.exportClause.elements) {
        const exportName = element.name.text;
        const localName = element.propertyName
          ? element.propertyName.text
          : element.name.text;
        const style: ExportStyle = fromSpecifier ? 're-export' : 'named';
        exports.push({
          exportName,
          localName,
          style,
          node: element,
          fromSpecifier,
          fromResolvedPath,
        });
      }
    }
  }

  private collectExportAssignment(
    node: ts.ExportAssignment,
    exports: ExportBinding[],
  ): void {
    // export default expression
    if (!node.isExportEquals) {
      const localName = ts.isIdentifier(node.expression)
        ? node.expression.text
        : 'default';
      exports.push({
        exportName: 'default',
        localName,
        style: 'default',
        node,
      });
    }
  }

  private collectExportedDeclaration(
    node: ts.Node,
    exports: ExportBinding[],
  ): void {
    const isDefault = this.hasDefaultModifier(node);

    if (ts.isFunctionDeclaration(node)) {
      const name = node.name?.text ?? 'default';
      exports.push({
        exportName: isDefault ? 'default' : name,
        localName: name,
        style: isDefault ? 'default' : 'named',
        node,
      });
    } else if (ts.isClassDeclaration(node)) {
      const name = node.name?.text ?? 'default';
      exports.push({
        exportName: isDefault ? 'default' : name,
        localName: name,
        style: isDefault ? 'default' : 'class',
        node,
      });
    } else if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) {
          exports.push({
            exportName: decl.name.text,
            localName: decl.name.text,
            style: 'const',
            node: decl,
          });
        }
      }
    } else if (ts.isEnumDeclaration(node) || ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) {
      if (node.name && ts.isIdentifier(node.name)) {
        exports.push({
          exportName: node.name.text,
          localName: node.name.text,
          style: 'named',
          node,
        });
      }
    }
  }

  // ── CJS Import collection ───────────────────────────────────────────────

  private collectRequireImport(
    node: ts.CallExpression,
    _sourceFile: ts.SourceFile,
    filePath: string,
    imports: ImportBinding[],
  ): void {
    const arg = node.arguments[0];
    if (!arg || !ts.isStringLiteral(arg)) return;

    const specifier = arg.text;
    const resolvedPath = this.resolveSpecifier(specifier, filePath);

    // Check parent context to determine the binding name
    const parent = node.parent;

    // const foo = require('./bar')
    if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      imports.push({
        localName: parent.name.text,
        exportName: 'default',
        specifier,
        resolvedPath,
        style: 'namespace',
        isDynamic: false,
        isTypeOnly: false,
        node,
      });
      return;
    }

    // const { a, b } = require('./bar')
    if (parent && ts.isVariableDeclaration(parent) && ts.isObjectBindingPattern(parent.name)) {
      for (const element of parent.name.elements) {
        if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
          const exportName = element.propertyName && ts.isIdentifier(element.propertyName)
            ? element.propertyName.text
            : element.name.text;
          imports.push({
            localName: element.name.text,
            exportName,
            specifier,
            resolvedPath,
            style: 'named',
            isDynamic: false,
            isTypeOnly: false,
            node: element,
          });
        }
      }
      return;
    }

    // Bare require('./bar') — side-effect
    imports.push({
      localName: '',
      exportName: '',
      specifier,
      resolvedPath,
      style: 'side-effect',
      isDynamic: false,
      isTypeOnly: false,
      node,
    });
  }

  // ── CJS Export collection ────────────────────────────────────────────────

  private collectCJSExport(
    node: ts.BinaryExpression,
    exports: ExportBinding[],
  ): void {
    const right = node.right;

    // module.exports = { foo, bar }
    if (ts.isObjectLiteralExpression(right)) {
      for (const prop of right.properties) {
        if (ts.isShorthandPropertyAssignment(prop)) {
          exports.push({
            exportName: prop.name.text,
            localName: prop.name.text,
            style: 'module-exports',
            node: prop,
          });
        } else if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
          const localName = ts.isIdentifier(prop.initializer)
            ? prop.initializer.text
            : prop.name.text;
          exports.push({
            exportName: prop.name.text,
            localName,
            style: 'module-exports',
            node: prop,
          });
        } else if (ts.isMethodDeclaration(prop) && ts.isIdentifier(prop.name)) {
          exports.push({
            exportName: prop.name.text,
            localName: prop.name.text,
            style: 'module-exports',
            node: prop,
          });
        }
      }
    } else {
      // module.exports = fn (direct export)
      const localName = ts.isIdentifier(right) ? right.text : 'default';
      exports.push({
        exportName: 'default',
        localName,
        style: 'module-exports-direct',
        node,
      });
    }
  }

  private collectExportsPropertyExport(
    node: ts.BinaryExpression,
    exports: ExportBinding[],
  ): void {
    // exports.foo = fn
    const left = node.left;
    if (!ts.isPropertyAccessExpression(left)) return;

    const exportName = left.name.text;
    const localName = ts.isIdentifier(node.right)
      ? node.right.text
      : exportName;

    exports.push({
      exportName,
      localName,
      style: 'exports-property',
      node,
    });
  }

  // ── Node type checks ────────────────────────────────────────────────────

  private isRequireCall(node: ts.Node): boolean {
    if (!ts.isCallExpression(node)) return false;
    const expr = node.expression;
    return ts.isIdentifier(expr) && expr.text === 'require' && node.arguments.length > 0;
  }

  private isDynamicImportCall(node: ts.Node): boolean {
    if (!ts.isCallExpression(node)) return false;
    // import() expression — the expression is an ImportKeyword token
    return node.expression.kind === ts.SyntaxKind.ImportKeyword;
  }

  private isModuleExportsAssignment(node: ts.Node): boolean {
    if (!ts.isBinaryExpression(node)) return false;
    if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false;
    const left = node.left;
    // module.exports = ...
    return (
      ts.isPropertyAccessExpression(left) &&
      ts.isIdentifier(left.expression) &&
      left.expression.text === 'module' &&
      left.name.text === 'exports'
    );
  }

  private isExportsPropertyAssignment(node: ts.Node): boolean {
    if (!ts.isBinaryExpression(node)) return false;
    if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return false;
    const left = node.left;
    // exports.foo = ...
    return (
      ts.isPropertyAccessExpression(left) &&
      ts.isIdentifier(left.expression) &&
      left.expression.text === 'exports' &&
      left.name.text !== 'default' // avoid `exports.default` overlap
    );
  }

  private hasExportModifier(node: ts.Node): boolean {
    if (!ts.canHaveModifiers(node)) return false;
    const modifiers = ts.getModifiers(node);
    return modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
  }

  private hasDefaultModifier(node: ts.Node): boolean {
    if (!ts.canHaveModifiers(node)) return false;
    const modifiers = ts.getModifiers(node);
    return modifiers?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword) ?? false;
  }

  // ── Dynamic import helpers ───────────────────────────────────────────────

  private buildDynamicSite(
    expr: ts.Expression,
    staticPrefix: string | null,
    fromFile: string,
  ): DynamicImportSite {
    const candidates: string[] = [];

    if (staticPrefix) {
      // Resolve the prefix directory for potential glob matching
      const dir = path.dirname(fromFile);
      const prefixPath = path.resolve(dir, staticPrefix);

      // If the prefix itself resolves, include it
      const resolved = this.tryResolveFile(prefixPath);
      if (resolved) {
        candidates.push(resolved);
      }
    }

    return {
      specifierExpr: expr,
      staticPrefix,
      resolvedPath: candidates.length === 1 ? candidates[0] : null,
      candidates,
      node: expr,
    };
  }

  /**
   * Extract the leftmost string literal from a binary + expression chain.
   * e.g. `'./routes/' + name + '.js'` -> `'./routes/'`
   */
  private extractConcatPrefix(expr: ts.BinaryExpression): string | null {
    const left = expr.left;
    if (ts.isStringLiteral(left)) {
      return left.text;
    }
    if (ts.isBinaryExpression(left) && left.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return this.extractConcatPrefix(left);
    }
    return null;
  }

  /**
   * Attempt backward slice: look for string literal assignments to an identifier
   * within the same scope (function/block). Simple intra-procedural analysis.
   */
  private tryBackwardSlice(
    ident: ts.Identifier,
    _sourceFile: ts.SourceFile,
    fromFile: string,
  ): { specifier: string; path: string | null } | null {
    const name = ident.text;

    // Walk up to find the enclosing function/block scope
    let scope: ts.Node = ident;
    while (scope.parent) {
      if (
        ts.isFunctionDeclaration(scope) ||
        ts.isFunctionExpression(scope) ||
        ts.isArrowFunction(scope) ||
        ts.isBlock(scope) ||
        ts.isSourceFile(scope)
      ) {
        break;
      }
      scope = scope.parent;
    }

    // Search for variable declarations or assignments in scope
    let foundSpecifier: string | null = null;

    const searchAssignments = (node: ts.Node): void => {
      // const varName = 'some/path'
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) {
        if (node.initializer && ts.isStringLiteral(node.initializer)) {
          foundSpecifier = node.initializer.text;
        }
      }
      // varName = 'some/path'
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.left) &&
        node.left.text === name &&
        ts.isStringLiteral(node.right)
      ) {
        foundSpecifier = node.right.text;
      }

      ts.forEachChild(node, searchAssignments);
    };

    searchAssignments(scope);

    if (foundSpecifier) {
      return {
        specifier: foundSpecifier,
        path: this.resolveSpecifier(foundSpecifier, fromFile),
      };
    }

    return null;
  }

  // ── Utility ──────────────────────────────────────────────────────────────

  private readFileContent(absPath: string): string | null {
    try {
      return fs.readFileSync(absPath, 'utf-8');
    } catch {
      return null;
    }
  }

  private getScriptKind(fileName: string): ts.ScriptKind {
    const ext = path.extname(fileName);
    switch (ext) {
      case '.ts': return ts.ScriptKind.TS;
      case '.tsx': return ts.ScriptKind.TSX;
      case '.jsx': return ts.ScriptKind.JSX;
      case '.js':
      default: return ts.ScriptKind.JS;
    }
  }
}

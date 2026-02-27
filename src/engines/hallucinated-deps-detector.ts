/**
 * Hallucinated Dependency Detector
 * Detects imports from packages that don't exist in package.json
 * Priority: HIGHEST (breaks at runtime)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { getImports, traverse } from '../core/parser.js';
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

// Node.js built-in modules (don't require package.json)
const NODE_BUILTINS = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
  'events', 'fs', 'fs/promises', 'http', 'http2', 'https', 'inspector',
  'module', 'net', 'os', 'path', 'perf_hooks', 'process', 'punycode',
  'querystring', 'readline', 'repl', 'stream', 'stream/promises',
  'string_decoder', 'sys', 'timers', 'timers/promises', 'tls', 'trace_events',
  'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib'
]);

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

export class HallucinatedDepsDetector extends BaseEngine {
  readonly name = 'hallucinated-deps';
  private packageJson: PackageJson | null = null;
  private packageJsonLoaded = false;

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    // Load package.json once
    if (!this.packageJsonLoaded) {
      this.loadPackageJson();
      this.packageJsonLoaded = true;
    }

    // Get all static imports from the file
    const imports = getImports(context.sourceFile);

    for (const imp of imports) {
      const packageName = this.extractPackageName(imp.moduleName);

      // Skip relative/absolute imports
      if (this.isRelativeOrAbsolute(imp.moduleName)) {
        continue;
      }

      // Skip type-only imports (they don't cause runtime errors)
      // Note: getImports doesn't distinguish, we check in AST below

      // Skip Node.js built-ins
      if (this.isNodeBuiltin(packageName)) {
        continue;
      }

      // Check if package exists
      if (!this.packageExists(packageName)) {
        // Report the issue with location from parser
        issues.push({
          engine: this.name,
          severity: 'error',
          message: `Hallucinated dependency: '${packageName}' not found in package.json`,
          filePath: context.filePath,
          location: imp.location,
          suggestion: `Run 'npm install ${packageName}' or remove import if AI hallucinated this package`,
        });
      }
    }

    // Also check dynamic imports: import('module')
    traverse(context.sourceFile, (node) => {
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const arg = node.arguments[0];
        if (arg && ts.isStringLiteral(arg)) {
          const moduleName = arg.text;
          const packageName = this.extractPackageName(moduleName);

          if (!this.isRelativeOrAbsolute(moduleName) &&
              !this.isNodeBuiltin(packageName) &&
              !this.packageExists(packageName)) {
            const issue = this.createIssue(context, node,
              `Hallucinated dependency in dynamic import: '${packageName}' not found`,
              { severity: 'error', suggestion: `Install ${packageName} or remove dynamic import` }
            );
            if (issue) issues.push(issue);
          }
        }
      }
    });

    return issues;
  }

  /**
   * Load package.json from project root
   */
  private loadPackageJson(): void {
    try {
      const cwd = process.cwd();
      const packageJsonPath = path.join(cwd, 'package.json');

      if (fs.existsSync(packageJsonPath)) {
        const content = fs.readFileSync(packageJsonPath, 'utf-8');
        this.packageJson = JSON.parse(content);
      }
    } catch (error) {
      // If package.json doesn't exist or is invalid, all imports will be flagged
      console.warn('Warning: Could not load package.json');
      this.packageJson = null;
    }
  }

  /**
   * Extract package name from module specifier
   * Examples:
   *   'express' → 'express'
   *   '@types/node' → '@types/node'
   *   'lodash/debounce' → 'lodash'
   */
  private extractPackageName(moduleName: string): string {
    // Handle scoped packages (@org/package)
    if (moduleName.startsWith('@')) {
      const parts = moduleName.split('/');
      return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : moduleName;
    }

    // Handle subpath imports (package/subpath)
    const firstSlash = moduleName.indexOf('/');
    if (firstSlash > 0) {
      return moduleName.substring(0, firstSlash);
    }

    return moduleName;
  }

  /**
   * Check if import is relative or absolute path
   */
  private isRelativeOrAbsolute(moduleName: string): boolean {
    return moduleName.startsWith('.') || moduleName.startsWith('/');
  }

  /**
   * Check if module is a Node.js built-in
   */
  private isNodeBuiltin(packageName: string): boolean {
    // Handle 'node:' prefix (new Node.js convention)
    if (packageName.startsWith('node:')) {
      return true;
    }

    return NODE_BUILTINS.has(packageName);
  }

  /**
   * Check if package exists in package.json
   */
  private packageExists(packageName: string): boolean {
    if (!this.packageJson) {
      return false;
    }

    return !!(
      this.packageJson.dependencies?.[packageName] ||
      this.packageJson.devDependencies?.[packageName] ||
      this.packageJson.peerDependencies?.[packageName]
    );
  }
}

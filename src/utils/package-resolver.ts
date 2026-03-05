/**
 * Package Resolver
 * Handles package.json lookup, dependency checking, and workspace resolution
 */

import * as fs from 'fs';
import * as path from 'path';
import { PackageResolver as IPackageResolver, PackageResolution } from '../types/index.js';

/**
 * Package.json structure
 */
interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  workspaces?: string[] | { packages?: string[] };
}

/**
 * Workspace information
 */
interface WorkspaceInfo {
  name: string;
  path: string;
  packageJson: PackageJson;
}

/**
 * PackageResolver implementation
 * Provides package.json lookup and dependency checking with workspace support
 */
export class PackageResolver implements IPackageResolver {
  public packageJson: PackageJson;
  private packageJsonPath: string;
  private packageJsonCache: Map<string, PackageJson> = new Map();
  private workspaces: WorkspaceInfo[] = [];
  private workspacesLoaded = false;
  private workspaceNameCache: Map<string, string | undefined> = new Map();
  private lockedPackages: Set<string> | null = null;

  /**
   * Create a new PackageResolver
   * @param rootPath - Root directory to start searching for package.json
   */
  constructor(rootPath: string = process.cwd()) {
    const result = this.findNearestPackageJson(rootPath);
    if (!result) {
      throw new Error(`No package.json found in ${rootPath} or parent directories`);
    }

    this.packageJsonPath = result;
    this.packageJson = this.loadPackageJson(result);
  }

  /**
   * Load package.json from a path
   * @param filePath - Path to package.json
   * @returns Parsed package.json content
   */
  private loadPackageJson(filePath: string): PackageJson {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      throw new Error(`Failed to load package.json from ${filePath}: ${error}`);
    }
  }

  /**
   * Find the nearest package.json by walking up the directory tree
   * @param filePath - Starting file or directory path
   * @returns Path to package.json or null if not found
   */
  public findNearestPackageJson(filePath: string): string | null {
    // Check if it's a file, if so get its directory
    let currentDir: string;
    try {
      const stats = fs.statSync(filePath);
      currentDir = stats.isDirectory() ? filePath : path.dirname(filePath);
    } catch {
      currentDir = path.dirname(filePath);
    }

    // Walk up the directory tree
    while (true) {
      const packageJsonPath = path.join(currentDir, 'package.json');

      // Check cache first
      if (this.packageJsonCache.has(packageJsonPath)) {
        return packageJsonPath;
      }

      if (fs.existsSync(packageJsonPath)) {
        return packageJsonPath;
      }

      const parentDir = path.dirname(currentDir);

      // Reached filesystem root
      if (parentDir === currentDir) {
        return null;
      }

      currentDir = parentDir;
    }
  }

  /**
   * Check if a package exists in dependencies
   * @param name - Package name (e.g., 'express' or '@types/node')
   * @returns True if package exists in dependencies
   */
  public hasDependency(name: string): boolean {
    return !!(this.packageJson.dependencies?.[name]);
  }

  /**
   * Check if a package exists in devDependencies
   * @param name - Package name
   * @returns True if package exists in devDependencies
   */
  public hasDevDependency(name: string): boolean {
    return !!(this.packageJson.devDependencies?.[name]);
  }

  /**
   * Check if a package exists in any dependency field
   * @param name - Package name
   * @returns True if package exists in any dependency type
   */
  public hasAnyDependency(name: string): boolean {
    return !!(
      this.packageJson.dependencies?.[name] ||
      this.packageJson.devDependencies?.[name] ||
      this.packageJson.peerDependencies?.[name] ||
      this.packageJson.optionalDependencies?.[name]
    );
  }

  /**
   * Check if a package exists (alias for hasAnyDependency)
   * @param name - Package name
   * @returns True if package exists
   */
  public packageExists(name: string): boolean {
    return this.hasAnyDependency(name);
  }

  /**
   * Check if a package exists in a workspace-aware manner
   * Checks both the nearest package.json to the file AND workspace packages
   * @param name - Package name
   * @param filePath - File path to check (used to find nearest package.json)
   * @returns True if package exists in workspace or root dependencies, or is a workspace package
   */
  public packageExistsForFile(name: string, filePath: string): boolean {
    // Load workspaces if not already loaded
    if (!this.workspacesLoaded) {
      this.loadWorkspaces();
    }

    // CRITICAL FIX: Check if file is IN the package being imported (self-import scenario)
    // This prevents false positives for workspace self-imports (e.g., openclaw importing openclaw)

    // Strategy 1: Check workspace name (for monorepos)
    const fileWorkspace = this.getWorkspaceName(filePath);
    if (fileWorkspace && fileWorkspace === name) {
      return true;
    }

    // Strategy 2: Single walk UP the directory tree — check for self-imports AND dependencies
    // This handles monorepos where extensions/*/package.json import root package
    const rootDir = path.dirname(this.packageJsonPath);
    let searchDir = path.dirname(filePath);

    while (searchDir.startsWith(rootDir) || searchDir === rootDir) {
      const pkgPath = path.join(searchDir, 'package.json');

      if (fs.existsSync(pkgPath)) {
        try {
          let pkgJson: PackageJson;
          if (this.packageJsonCache.has(pkgPath)) {
            pkgJson = this.packageJsonCache.get(pkgPath)!;
          } else {
            pkgJson = this.loadPackageJson(pkgPath);
            this.packageJsonCache.set(pkgPath, pkgJson);
          }

          // Self-import check: any package.json in the tree with same name
          if (pkgJson.name === name) {
            if (process.env.CODEDRIFT_DEBUG) {
              console.log(`\n[PackageResolver] ✅ SELF-IMPORT DETECTED!`);
              console.log(`[PackageResolver] Import "${name}" matches package.json at ${pkgPath}`);
              console.log(`[PackageResolver] Package name: "${pkgJson.name}"\n`);
            }
            return true;
          }

          // Dependency check (skip root — checked at the end via hasAnyDependency)
          if (pkgPath !== this.packageJsonPath && this.isInDependencies(name, pkgJson)) {
            return true;
          }
        } catch (error) {
          // Ignore errors loading package.json
        }
      }

      const parentDir = path.dirname(searchDir);
      if (parentDir === searchDir) {
        break; // Reached filesystem root
      }
      searchDir = parentDir;
    }

    // Check if it's a workspace package (global workspace check)
    for (const workspace of this.workspaces) {
      if (workspace.name === name) {
        return true;
      }
    }

    // Check root package.json
    if (this.hasAnyDependency(name)) {
      return true;
    }

    // Check all workspace package.jsons — in a monorepo, packages declared in any
    // workspace are hoisted to the root node_modules and available to all packages.
    // This handles the common pattern where a shared dep lives in one workspace
    // (e.g., @codebuff/internal has drizzle-orm) but other workspaces import it.
    for (const workspace of this.workspaces) {
      if (this.isInDependencies(name, workspace.packageJson)) {
        return true;
      }
    }

    // Check lockfile — transitive deps are locked and available at runtime even if not
    // explicitly declared in any package.json. Covers bun.lock, package-lock.json,
    // yarn.lock, and pnpm-lock.yaml.
    if (this.isInLockfile(name)) {
      return true;
    }

    // Final fallback: check if installed in node_modules (handles linked workspace
    // packages, bundler-resolved deps, and nested workspace patterns not covered above)
    return this.existsInNodeModules(name, filePath);
  }

  /**
   * Check if a package name is in any dependency field of a package.json
   * @param name - Package name
   * @param packageJson - PackageJson object to check
   * @returns True if package is in any dependency type
   */
  private isInDependencies(name: string, packageJson: PackageJson): boolean {
    return !!(
      packageJson.dependencies?.[name] ||
      packageJson.devDependencies?.[name] ||
      packageJson.peerDependencies?.[name] ||
      packageJson.optionalDependencies?.[name]
    );
  }

  /**
   * Get workspace name for a file path
   * Searches through workspace packages to find which one contains the file
   * @param filePath - File path to check
   * @returns Workspace name or undefined if not in a workspace
   */
  public getWorkspaceName(filePath: string): string | undefined {
    if (!this.workspacesLoaded) {
      this.loadWorkspaces();
    }

    const cached = this.workspaceNameCache.get(filePath);
    if (cached !== undefined || this.workspaceNameCache.has(filePath)) {
      return cached;
    }

    // Normalize the file path
    const normalizedPath = path.resolve(filePath);

    // Find the workspace that contains this file
    let result: string | undefined;
    for (const workspace of this.workspaces) {
      const workspacePath = path.resolve(workspace.path);
      if (normalizedPath.startsWith(workspacePath)) {
        result = workspace.name;
        break;
      }
    }

    this.workspaceNameCache.set(filePath, result);
    return result;
  }

  /**
   * Load all workspaces defined in the root package.json
   * Supports npm, yarn, and pnpm workspace configurations
   */
  public loadWorkspaces(): void {
    if (this.workspacesLoaded) {
      return;
    }

    this.workspacesLoaded = true;
    this.workspaces = [];

    const workspacePatterns = this.getWorkspacePatterns();
    if (workspacePatterns.length === 0) {
      return;
    }

    const rootDir = path.dirname(this.packageJsonPath);

    // Resolve workspace patterns
    for (const pattern of workspacePatterns) {
      const workspacePaths = this.resolveWorkspacePattern(rootDir, pattern);

      for (const workspacePath of workspacePaths) {
        const packageJsonPath = path.join(workspacePath, 'package.json');

        if (fs.existsSync(packageJsonPath)) {
          try {
            const packageJson = this.loadPackageJson(packageJsonPath);
            this.packageJsonCache.set(packageJsonPath, packageJson);

            if (packageJson.name) {
              this.workspaces.push({
                name: packageJson.name,
                path: workspacePath,
                packageJson,
              });
            }
          } catch (error) {
            // Skip invalid package.json files
            console.warn(`Warning: Could not load workspace package.json: ${packageJsonPath}`);
          }
        }
      }
    }
  }

  /**
   * Get workspace patterns from package.json
   * @returns Array of workspace patterns
   */
  private getWorkspacePatterns(): string[] {
    const workspaces = this.packageJson.workspaces;

    if (!workspaces) {
      return [];
    }

    // Handle array format: { "workspaces": ["packages/*"] }
    if (Array.isArray(workspaces)) {
      return workspaces;
    }

    // Handle object format: { "workspaces": { "packages": ["packages/*"] } }
    if (typeof workspaces === 'object' && workspaces.packages) {
      return workspaces.packages;
    }

    return [];
  }

  /**
   * Resolve a workspace pattern to actual directories
   * Supports wildcards like 'packages/*'
   * @param rootDir - Root directory
   * @param pattern - Workspace pattern (e.g., 'packages/*')
   * @returns Array of resolved workspace paths
   */
  private resolveWorkspacePattern(rootDir: string, pattern: string): string[] {
    const resolved: string[] = [];

    // Simple wildcard support for common patterns like 'packages/*'
    if (pattern.endsWith('/*')) {
      const baseDir = path.join(rootDir, pattern.slice(0, -2));

      if (fs.existsSync(baseDir)) {
        try {
          const entries = fs.readdirSync(baseDir, { withFileTypes: true });

          for (const entry of entries) {
            if (entry.isDirectory()) {
              resolved.push(path.join(baseDir, entry.name));
            }
          }
        } catch (error) {
          // Skip directories that can't be read
        }
      }
    } else {
      // Direct path (no wildcard)
      const directPath = path.join(rootDir, pattern);
      if (fs.existsSync(directPath)) {
        resolved.push(directPath);
      }
    }

    return resolved;
  }

  /**
   * Check if a package is present in the project's lockfile.
   * Transitive dependencies are locked even if not explicitly declared in package.json.
   * Supports bun.lock, package-lock.json, yarn.lock, and pnpm-lock.yaml.
   */
  private isInLockfile(name: string): boolean {
    if (this.lockedPackages === null) {
      this.lockedPackages = this.loadLockfile();
    }
    return this.lockedPackages.has(name);
  }

  /**
   * Load and parse the project lockfile to extract all locked package names.
   * Returns a Set of package names that are locked (directly or transitively).
   */
  private loadLockfile(): Set<string> {
    const rootDir = path.dirname(this.packageJsonPath);
    const locked = new Set<string>();

    // bun.lock — JSONC format (trailing commas). Package entries are lines like:
    //     "package-name": ["package-name@version", ...],
    const bunLockPath = path.join(rootDir, 'bun.lock');
    if (fs.existsSync(bunLockPath)) {
      try {
        const content = fs.readFileSync(bunLockPath, 'utf-8');
        // Match 4-space indented keys followed by ': [' (package entries, not workspace entries)
        const re = /^    "([^"]+)": \[/gm;
        let m: RegExpExecArray | null;
        while ((m = re.exec(content)) !== null) {
          locked.add(m[1]);
        }
        return locked;
      } catch {
        // Fall through to other lockfiles
      }
    }

    // package-lock.json — proper JSON, packages in the "packages" key
    const npmLockPath = path.join(rootDir, 'package-lock.json');
    if (fs.existsSync(npmLockPath)) {
      try {
        const lock = JSON.parse(fs.readFileSync(npmLockPath, 'utf-8'));
        if (lock.packages && typeof lock.packages === 'object') {
          for (const key of Object.keys(lock.packages)) {
            // Keys are like "node_modules/express" or "node_modules/@types/node"
            const pkgName = key.replace(/^node_modules\//, '');
            if (pkgName) locked.add(pkgName);
          }
        }
        return locked;
      } catch {
        // Fall through
      }
    }

    // yarn.lock — text format. Package blocks start with "name@version:" or '"@scope/name@version":'
    const yarnLockPath = path.join(rootDir, 'yarn.lock');
    if (fs.existsSync(yarnLockPath)) {
      try {
        const content = fs.readFileSync(yarnLockPath, 'utf-8');
        // Match package names from block headers: "name@version, name@other-version:"
        const re = /^(?:")?(@?[a-z0-9][-a-z0-9._]*)@/gm;
        let m: RegExpExecArray | null;
        while ((m = re.exec(content)) !== null) {
          locked.add(m[1]);
        }
        return locked;
      } catch {
        // Fall through
      }
    }

    // pnpm-lock.yaml — YAML format. Package names appear under "packages:" key
    const pnpmLockPath = path.join(rootDir, 'pnpm-lock.yaml');
    if (fs.existsSync(pnpmLockPath)) {
      try {
        const content = fs.readFileSync(pnpmLockPath, 'utf-8');
        // Match "  /package-name@version:" or "  /@scope/name@version:" lines
        const re = /^  \/?(@?[a-z0-9][-a-z0-9._/]*)@/gm;
        let m: RegExpExecArray | null;
        while ((m = re.exec(content)) !== null) {
          locked.add(m[1]);
        }
        return locked;
      } catch {
        // Fall through
      }
    }

    return locked;
  }

  /**
   * Check if a package exists in node_modules (walking up from file path).
   * This catches packages installed via workspace hoisting, symlinks, or bundler resolution
   * that aren't captured by package.json dependency fields or workspace patterns.
   */
  private existsInNodeModules(name: string, filePath: string): boolean {
    const rootDir = path.dirname(this.packageJsonPath);
    let searchDir = path.dirname(filePath);

    while (searchDir.startsWith(rootDir) || searchDir === rootDir) {
      const modulePath = path.join(searchDir, 'node_modules', name);
      // Check for directory or package.json inside (handles scoped packages)
      if (fs.existsSync(path.join(modulePath, 'package.json')) || fs.existsSync(modulePath)) {
        return true;
      }

      const parentDir = path.dirname(searchDir);
      if (parentDir === searchDir) break;
      searchDir = parentDir;
    }

    return false;
  }

  /**
   * Get all loaded workspaces
   * @returns Array of workspace information
   */
  public getWorkspaces(): WorkspaceInfo[] {
    if (!this.workspacesLoaded) {
      this.loadWorkspaces();
    }
    return this.workspaces;
  }

  /**
   * Resolve package information for a file
   * @param filePath - File path to resolve
   * @returns Package resolution information or null
   */
  public resolvePackage(filePath: string): PackageResolution | null {
    const packageJsonPath = this.findNearestPackageJson(filePath);

    if (!packageJsonPath) {
      return null;
    }

    const workspaceName = this.getWorkspaceName(filePath);

    return {
      packageJsonPath,
      workspaceName,
      isWorkspace: workspaceName !== undefined,
    };
  }
}

/**
 * Extract package name from a module specifier
 * Handles scoped packages and subpath imports
 *
 * Examples:
 *   'express' -> 'express'
 *   '@types/node' -> '@types/node'
 *   'lodash/debounce' -> 'lodash'
 *   '@org/package/subpath' -> '@org/package'
 *
 * @param moduleName - Module specifier
 * @returns Package name
 */
export function extractPackageName(moduleName: string): string {
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

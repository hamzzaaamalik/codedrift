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

    // First, check if it's a workspace package itself
    for (const workspace of this.workspaces) {
      if (workspace.name === name) {
        return true;
      }
    }

    // Find the nearest package.json to this file (could be workspace package.json)
    const nearestPackageJson = this.findNearestPackageJson(filePath);
    if (nearestPackageJson) {
      // Load and check dependencies in this package.json
      let packageJson: PackageJson;
      if (this.packageJsonCache.has(nearestPackageJson)) {
        packageJson = this.packageJsonCache.get(nearestPackageJson)!;
      } else {
        packageJson = this.loadPackageJson(nearestPackageJson);
        this.packageJsonCache.set(nearestPackageJson, packageJson);
      }

      // Check all dependency types in the nearest package.json
      if (packageJson.dependencies?.[name] ||
          packageJson.devDependencies?.[name] ||
          packageJson.peerDependencies?.[name] ||
          packageJson.optionalDependencies?.[name]) {
        return true;
      }
    }

    // Finally, check root package.json
    return this.hasAnyDependency(name);
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

    // Normalize the file path
    const normalizedPath = path.resolve(filePath);

    // Find the workspace that contains this file
    for (const workspace of this.workspaces) {
      const workspacePath = path.resolve(workspace.path);
      if (normalizedPath.startsWith(workspacePath)) {
        return workspace.name;
      }
    }

    return undefined;
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

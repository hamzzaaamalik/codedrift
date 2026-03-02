/**
 * TsConfig Resolver
 * Reads tsconfig.json and extracts TypeScript path alias prefixes.
 * Used to prevent hallucinated-deps from flagging internal path aliases.
 */

import * as fs from 'fs';
import * as path from 'path';

interface TsConfig {
  extends?: string;
  compilerOptions?: {
    paths?: Record<string, string[]>;
  };
}

function loadTsConfigFile(filePath: string): TsConfig | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    // tsconfig.json is JSON-with-comments (JSONC): strip comments and trailing commas
    const stripped = content
      .replace(/\/\/[^\n]*/g, '')       // strip // single-line comments
      .replace(/\/\*[\s\S]*?\*\//g, '') // strip /* block comments */
      .replace(/,(\s*[}\]])/g, '$1');   // strip trailing commas before } or ]
    return JSON.parse(stripped);
  } catch {
    return null;
  }
}

/**
 * Convert a tsconfig paths key to an alias prefix.
 *   "@/*"         -> "@/"   (wildcard — match anything starting with "@/")
 *   "@config"     -> "@config" (exact — match only this string)
 *   "#/*"         -> "#/"
 */
function toAliasPrefix(pattern: string): string {
  return pattern.endsWith('/*') ? pattern.slice(0, -1) : pattern;
}

function collectAliases(
  filePath: string,
  aliases: Set<string>,
  visited: Set<string>
): void {
  if (visited.has(filePath) || !fs.existsSync(filePath)) {
    return;
  }
  visited.add(filePath);

  const config = loadTsConfigFile(filePath);
  if (!config) return;

  // Follow extends chain first (parent provides base, current overrides)
  if (config.extends) {
    let parentPath = path.resolve(path.dirname(filePath), config.extends);
    // tsconfig extends can omit the .json extension
    if (!parentPath.endsWith('.json')) {
      parentPath += '.json';
    }
    collectAliases(parentPath, aliases, visited);
  }

  // Extract alias prefixes from this config's compilerOptions.paths
  const paths = config.compilerOptions?.paths;
  if (paths) {
    for (const pattern of Object.keys(paths)) {
      aliases.add(toAliasPrefix(pattern));
    }
  }
}

/**
 * Load all TypeScript path alias prefixes for a project root.
 * Checks tsconfig.json, tsconfig.build.json, tsconfig.app.json, tsconfig.base.json.
 * Follows "extends" chains recursively.
 *
 * @param rootDir - The project root directory (where tsconfig.json lives)
 * @returns Set of alias prefixes, e.g. { "@/", "@components/", "@config" }
 */
export function loadPathAliases(rootDir: string): Set<string> {
  const aliases = new Set<string>();
  const visited = new Set<string>();

  const tsconfigNames = [
    'tsconfig.json',
    'tsconfig.build.json',
    'tsconfig.app.json',
    'tsconfig.base.json',
  ];

  for (const name of tsconfigNames) {
    collectAliases(path.join(rootDir, name), aliases, visited);
  }

  return aliases;
}

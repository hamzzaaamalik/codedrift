/**
 * IncrementalEngine — File-level caching and cascade invalidation for
 * cross-file taint analysis.
 *
 * Caches function summaries to disk so only changed files (and their
 * transitive dependents) need re-analysis on subsequent runs.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** What is stored in the cache for each file */
interface CacheEntry {
  filePath: string;
  contentHash: string;
  summaryIds: string[];      // canonicalIds of summaries from this file
  dependencies: string[];    // files this file imports (for cascade invalidation)
  timestamp: number;
}

interface CacheManifest {
  version: string;           // cache format version
  projectRoot: string;
  entries: Record<string, CacheEntry>;  // filePath -> CacheEntry
  summaries: Record<string, any>;       // canonicalId -> serialised FunctionSummary (without ts.Node)
}

export interface IncrementalResult {
  /** Files that were re-analyzed */
  reanalyzed: string[];
  /** Files loaded from cache */
  cached: string[];
  /** Files that were deleted/removed */
  removed: string[];
  /** Summaries that changed (trigger downstream re-resolution) */
  changedSummaries: string[];
  /** Aggregate statistics */
  stats: { totalFiles: number; cachedFiles: number; reanalyzedFiles: number };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CACHE_FORMAT_VERSION = '1';
const MANIFEST_FILENAME = 'manifest.json';

// ---------------------------------------------------------------------------
// IncrementalEngine
// ---------------------------------------------------------------------------

export class IncrementalEngine {
  private manifest: CacheManifest | null = null;
  private readonly cacheDir: string;
  private readonly projectRoot: string;

  constructor(projectRoot: string, cacheDir?: string) {
    this.projectRoot = projectRoot;
    this.cacheDir = cacheDir ?? path.join(projectRoot, '.codedrift-cache', 'taint');
  }

  // -----------------------------------------------------------------------
  // Cache I/O
  // -----------------------------------------------------------------------

  /**
   * Load the cache manifest from disk.
   * Returns counts of valid, stale, and missing entries.
   */
  loadCache(): { valid: number; stale: number; missing: number } {
    const manifestPath = path.join(this.cacheDir, MANIFEST_FILENAME);

    let valid = 0;
    let stale = 0;
    let missing = 0;

    if (!fs.existsSync(manifestPath)) {
      this.manifest = this.createEmptyManifest();
      return { valid: 0, stale: 0, missing: 0 };
    }

    try {
      const raw = fs.readFileSync(manifestPath, 'utf-8');
      const parsed: CacheManifest = JSON.parse(raw);

      // Version mismatch → discard entire cache
      if (parsed.version !== CACHE_FORMAT_VERSION) {
        this.manifest = this.createEmptyManifest();
        return { valid: 0, stale: 0, missing: 0 };
      }

      this.manifest = parsed;

      // Validate each entry against the file system
      for (const [filePath, entry] of Object.entries(this.manifest.entries)) {
        if (!fs.existsSync(filePath)) {
          missing++;
          continue;
        }

        const currentHash = this.computeHash(filePath);
        if (currentHash === entry.contentHash) {
          valid++;
        } else {
          stale++;
        }
      }
    } catch {
      // Corrupt manifest → start fresh
      this.manifest = this.createEmptyManifest();
    }

    return { valid, stale, missing };
  }

  /**
   * Save the cache manifest to disk.
   */
  saveCache(): void {
    if (!this.manifest) return;

    fs.mkdirSync(this.cacheDir, { recursive: true });
    const manifestPath = path.join(this.cacheDir, MANIFEST_FILENAME);
    fs.writeFileSync(manifestPath, JSON.stringify(this.manifest, null, 2), 'utf-8');
  }

  /**
   * Clear the entire cache (both in-memory and on disk).
   */
  clearCache(): void {
    this.manifest = this.createEmptyManifest();

    const manifestPath = path.join(this.cacheDir, MANIFEST_FILENAME);
    if (fs.existsSync(manifestPath)) {
      fs.unlinkSync(manifestPath);
    }
  }

  // -----------------------------------------------------------------------
  // Staleness detection
  // -----------------------------------------------------------------------

  /**
   * Determine which files need re-analysis.
   *
   * A file is stale if:
   *  1. Its content hash changed
   *  2. Any of its dependencies changed (cascade)
   *  3. It is not in the cache at all
   */
  getStaleFiles(allFiles: string[]): {
    stale: string[];
    cached: string[];
    deleted: string[];
  } {
    this.ensureManifest();

    const allFileSet = new Set(allFiles);
    const directlyStale = new Set<string>();
    const cached: string[] = [];
    const deleted: string[] = [];

    // 1. Detect deleted files (in cache but not in allFiles)
    for (const filePath of Object.keys(this.manifest!.entries)) {
      if (!allFileSet.has(filePath)) {
        deleted.push(filePath);
      }
    }

    // 2. Detect directly stale and uncached files
    for (const filePath of allFiles) {
      const entry = this.manifest!.entries[filePath];

      if (!entry) {
        // Not in cache at all
        directlyStale.add(filePath);
        continue;
      }

      const currentHash = this.computeHash(filePath);
      if (currentHash !== entry.contentHash) {
        directlyStale.add(filePath);
      }
    }

    // 3. Cascade invalidation: files that depend on directly-stale files
    const cascaded = this.getCascadeInvalidations(Array.from(directlyStale));
    const allStale = new Set(directlyStale);
    for (const f of cascaded) {
      // Only mark as stale if it's in the current file set and not already stale
      if (allFileSet.has(f)) {
        allStale.add(f);
      }
    }

    // Everything not stale is cached
    for (const filePath of allFiles) {
      if (!allStale.has(filePath)) {
        cached.push(filePath);
      }
    }

    return {
      stale: Array.from(allStale),
      cached,
      deleted,
    };
  }

  // -----------------------------------------------------------------------
  // Hashing
  // -----------------------------------------------------------------------

  /**
   * Compute SHA-256 content hash for a file (first 16 hex characters).
   */
  computeHash(filePath: string): string {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
    } catch {
      // If the file can't be read, return an empty hash so it's always stale
      return '';
    }
  }

  // -----------------------------------------------------------------------
  // Cache updates
  // -----------------------------------------------------------------------

  /**
   * Update the cache with new summaries for a reanalyzed file.
   */
  updateCache(
    filePath: string,
    contentHash: string,
    summaryIds: string[],
    dependencies: string[],
  ): void {
    this.ensureManifest();

    // Remove old summaries for this file from the summary store
    const oldEntry = this.manifest!.entries[filePath];
    if (oldEntry) {
      for (const id of oldEntry.summaryIds) {
        delete this.manifest!.summaries[id];
      }
    }

    this.manifest!.entries[filePath] = {
      filePath,
      contentHash,
      summaryIds,
      dependencies,
      timestamp: Date.now(),
    };
  }

  /**
   * Remove a file from the cache entirely.
   */
  removeFromCache(filePath: string): void {
    this.ensureManifest();

    const entry = this.manifest!.entries[filePath];
    if (!entry) return;

    // Remove associated summaries
    for (const id of entry.summaryIds) {
      delete this.manifest!.summaries[id];
    }

    delete this.manifest!.entries[filePath];
  }

  // -----------------------------------------------------------------------
  // Cascade invalidation
  // -----------------------------------------------------------------------

  /**
   * Determine cascade invalidation: given a set of changed files, find all
   * other files that transitively depend on them and need re-analysis.
   *
   * Builds a reverse dependency map (file -> files that import it), then
   * walks forward from the changed set, collecting dependents. Uses a
   * visited set to handle cycles.
   */
  getCascadeInvalidations(changedFiles: string[]): string[] {
    this.ensureManifest();

    // Build reverse dependency map: file -> set of files that import it
    const reverseDeps = new Map<string, Set<string>>();

    for (const [filePath, entry] of Object.entries(this.manifest!.entries)) {
      for (const dep of entry.dependencies) {
        let dependents = reverseDeps.get(dep);
        if (!dependents) {
          dependents = new Set<string>();
          reverseDeps.set(dep, dependents);
        }
        dependents.add(filePath);
      }
    }

    // BFS/DFS from changed files through reverse dependency edges
    const visited = new Set<string>(changedFiles);
    const queue = [...changedFiles];
    const cascaded: string[] = [];

    while (queue.length > 0) {
      const current = queue.pop()!;
      const dependents = reverseDeps.get(current);
      if (!dependents) continue;

      for (const dep of dependents) {
        if (!visited.has(dep)) {
          visited.add(dep);
          cascaded.push(dep);
          queue.push(dep);
        }
      }
    }

    return cascaded;
  }

  // -----------------------------------------------------------------------
  // Summary access
  // -----------------------------------------------------------------------

  /**
   * Get cached summary data for a file (if valid).
   * Returns null if the file is not in the cache or is stale.
   */
  getCachedSummaries(filePath: string): any[] | null {
    this.ensureManifest();

    const entry = this.manifest!.entries[filePath];
    if (!entry) return null;

    // Check staleness
    const currentHash = this.computeHash(filePath);
    if (currentHash !== entry.contentHash) return null;

    const summaries: any[] = [];
    for (const id of entry.summaryIds) {
      const summary = this.manifest!.summaries[id];
      if (summary) {
        summaries.push(summary);
      }
    }

    return summaries.length > 0 ? summaries : null;
  }

  /**
   * Store a serialised summary (without ts.Node references) in the manifest.
   */
  storeSummary(canonicalId: string, summary: any): void {
    this.ensureManifest();
    this.manifest!.summaries[canonicalId] = summary;
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private ensureManifest(): void {
    if (!this.manifest) {
      this.manifest = this.createEmptyManifest();
    }
  }

  private createEmptyManifest(): CacheManifest {
    return {
      version: CACHE_FORMAT_VERSION,
      projectRoot: this.projectRoot,
      entries: {},
      summaries: {},
    };
  }
}

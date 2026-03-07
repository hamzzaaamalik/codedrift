/**
 * HeapModel — Field-sensitive abstract heap for taint tracking
 *
 * Tracks taint state at the field level (e.g. obj.field granularity)
 * with support for aliasing, destructuring, spread, and control-flow merging.
 */

import type { TaintId, SanitizationKind } from '../types.js';
import { AccessPath, WildcardAccessPath } from './access-path.js';

/** Taint state for a single access path */
export interface FieldTaintState {
  accessPath: AccessPath;
  taintSources: TaintId[];
  sanitized: boolean;
  appliedSanitizations: SanitizationKind[];
}

/** Synthetic field name for function return values */
const RETURN_PATH_ROOT = '$return';

export class HeapModel {
  /** Internal map: access path string → taint state */
  private taintMap: Map<string, FieldTaintState>;
  /** Alias map: access path string → set of aliased path strings */
  private aliases: Map<string, Set<string>>;

  constructor() {
    this.taintMap = new Map();
    this.aliases = new Map();
  }

  // ── Taint Operations ────────────────────────────────────────────

  /** Mark an access path as tainted with the given source IDs */
  taint(path: AccessPath, sourceIds: TaintId[]): void {
    if (sourceIds.length === 0) return;
    const key = path.toString();
    const existing = this.taintMap.get(key);
    if (existing) {
      // Merge sources, avoid duplicates
      const combined = new Set([...existing.taintSources, ...sourceIds]);
      existing.taintSources = [...combined];
      existing.sanitized = false;
      existing.appliedSanitizations = [];
    } else {
      this.taintMap.set(key, {
        accessPath: path.clone(),
        taintSources: [...sourceIds],
        sanitized: false,
        appliedSanitizations: [],
      });
    }
  }

  /** Mark an access path as sanitized */
  sanitize(path: AccessPath, sanitizationKind: SanitizationKind): void {
    const key = path.toString();
    const existing = this.taintMap.get(key);
    if (existing) {
      existing.sanitized = true;
      if (!existing.appliedSanitizations.includes(sanitizationKind)) {
        existing.appliedSanitizations.push(sanitizationKind);
      }
    } else {
      // Create an entry marking this path as sanitized (no taint sources)
      this.taintMap.set(key, {
        accessPath: path.clone(),
        taintSources: [],
        sanitized: true,
        appliedSanitizations: [sanitizationKind],
      });
    }

    // Also sanitize all child paths in the map
    const prefix = key + '.';
    for (const [k, state] of this.taintMap) {
      if (k.startsWith(prefix)) {
        state.sanitized = true;
        if (!state.appliedSanitizations.includes(sanitizationKind)) {
          state.appliedSanitizations.push(sanitizationKind);
        }
      }
    }
  }

  // ── Query Operations ────────────────────────────────────────────

  /**
   * Query the taint state for an access path.
   *
   * Checks (in order):
   * 1. Exact match in taintMap
   * 2. Any parent path is tainted (field of tainted object inherits taint)
   * 3. Any alias is tainted (transitively)
   * 4. Wildcard matches
   *
   * Returns null if no taint information is found.
   */
  query(path: AccessPath): FieldTaintState | null {
    return this.queryInternal(path, new Set<string>());
  }

  private queryInternal(path: AccessPath, visited: Set<string>): FieldTaintState | null {
    const key = path.toString();
    if (visited.has(key)) return null;
    visited.add(key);

    // 1. Exact match
    const exact = this.taintMap.get(key);
    if (exact && exact.taintSources.length > 0) {
      return exact;
    }

    // 2. Parent taint — if any parent is tainted and not sanitized, child inherits
    const parentResult = this.queryParentTaint(path, visited);
    if (parentResult) return parentResult;

    // 3. Wildcard matches — check if any wildcard path matches
    const wildcardResult = this.queryWildcard(path);
    if (wildcardResult) return wildcardResult;

    // 4. Alias resolution — check all aliases transitively
    const aliasResult = this.queryAliases(path, visited);
    if (aliasResult) return aliasResult;

    // If exact match existed but with no taint sources (sanitized-only entry)
    if (exact) return exact;

    return null;
  }

  private queryParentTaint(path: AccessPath, visited: Set<string>): FieldTaintState | null {
    let current = path.parent();
    while (current) {
      const parentKey = current.toString();
      // Check directly in taintMap (avoid infinite recursion by not doing full query)
      const parentState = this.taintMap.get(parentKey);
      if (parentState && parentState.taintSources.length > 0 && !parentState.sanitized) {
        // Child inherits parent's taint
        return {
          accessPath: path.clone(),
          taintSources: [...parentState.taintSources],
          sanitized: false,
          appliedSanitizations: [],
        };
      }
      // Also check parent's aliases
      const parentAliasResult = this.queryAliasesForParent(current, path, visited);
      if (parentAliasResult) return parentAliasResult;

      current = current.parent();
    }
    return null;
  }

  private queryAliasesForParent(
    parentPath: AccessPath,
    originalPath: AccessPath,
    visited: Set<string>,
  ): FieldTaintState | null {
    const parentKey = parentPath.toString();
    const aliasSet = this.aliases.get(parentKey);
    if (!aliasSet) return null;

    // Compute suffix from parentPath to originalPath
    const suffix = originalPath.fields.slice(parentPath.fields.length);

    for (const aliasKey of aliasSet) {
      if (visited.has(aliasKey)) continue;
      const aliasPath = this.pathFromKey(aliasKey);
      if (!aliasPath) continue;

      // Build the equivalent path through the alias
      let resolvedPath = aliasPath;
      for (const field of suffix) {
        resolvedPath = resolvedPath.append(field);
      }
      const result = this.queryInternal(resolvedPath, visited);
      if (result && result.taintSources.length > 0 && !result.sanitized) {
        return {
          accessPath: originalPath.clone(),
          taintSources: [...result.taintSources],
          sanitized: false,
          appliedSanitizations: [],
        };
      }
    }
    return null;
  }

  private queryWildcard(path: AccessPath): FieldTaintState | null {
    for (const [, state] of this.taintMap) {
      if (
        state.accessPath instanceof WildcardAccessPath &&
        state.accessPath.matches(path) &&
        state.taintSources.length > 0 &&
        !state.sanitized
      ) {
        return {
          accessPath: path.clone(),
          taintSources: [...state.taintSources],
          sanitized: false,
          appliedSanitizations: [],
        };
      }
    }
    return null;
  }

  private queryAliases(path: AccessPath, visited: Set<string>): FieldTaintState | null {
    const key = path.toString();
    const aliasSet = this.aliases.get(key);
    if (!aliasSet) return null;

    for (const aliasKey of aliasSet) {
      if (visited.has(aliasKey)) continue;
      const aliasPath = this.pathFromKey(aliasKey);
      if (!aliasPath) continue;

      const result = this.queryInternal(aliasPath, visited);
      if (result && result.taintSources.length > 0) {
        return {
          accessPath: path.clone(),
          taintSources: [...result.taintSources],
          sanitized: result.sanitized,
          appliedSanitizations: [...result.appliedSanitizations],
        };
      }
    }
    return null;
  }

  /** Is this path tainted? (convenience boolean) */
  isTainted(path: AccessPath): boolean {
    const state = this.query(path);
    return state !== null && state.taintSources.length > 0 && !state.sanitized;
  }

  /** Get all taint source IDs flowing into a path */
  getTaintSources(path: AccessPath): TaintId[] {
    const state = this.query(path);
    if (!state || state.sanitized) return [];
    return [...state.taintSources];
  }

  // ── Aliasing & Assignment ───────────────────────────────────────

  /**
   * Assignment: target = source
   * Creates an alias so target points to the same heap region as source.
   */
  alias(target: AccessPath, source: AccessPath): void {
    const targetKey = target.toString();
    const sourceKey = source.toString();

    // Prevent self-alias
    if (targetKey === sourceKey) return;

    if (!this.aliases.has(targetKey)) {
      this.aliases.set(targetKey, new Set());
    }
    this.aliases.get(targetKey)!.add(sourceKey);
  }

  /**
   * Destructuring: const { a, b } = source
   * Creates field-specific paths from the source's fields.
   */
  destructure(
    bindings: { localName: string; fieldName: string }[],
    source: AccessPath,
  ): void {
    for (const { localName, fieldName } of bindings) {
      const fieldPath = source.append(fieldName);
      const localPath = new AccessPath(localName, []);
      this.alias(localPath, fieldPath);

      // If the source field is tainted, propagate directly
      const fieldState = this.query(fieldPath);
      if (fieldState && fieldState.taintSources.length > 0 && !fieldState.sanitized) {
        this.taint(localPath, fieldState.taintSources);
      }
    }
  }

  /**
   * Object spread: target = { ...src1, ...src2, explicit: val }
   * Merges taint from all spread sources. Explicit properties override.
   */
  spreadMerge(
    target: AccessPath,
    spreadSources: AccessPath[],
    explicitFields: { name: string; valuePath: AccessPath | null }[],
  ): void {
    const mergedSources: TaintId[] = [];

    // Gather taint from spread sources
    for (const src of spreadSources) {
      const srcState = this.query(src);
      if (srcState && srcState.taintSources.length > 0 && !srcState.sanitized) {
        mergedSources.push(...srcState.taintSources);
      }

      // Also copy field-level taint from each spread source
      const srcKey = src.toString();
      const srcPrefix = srcKey + '.';
      for (const [k, state] of this.taintMap) {
        if (k.startsWith(srcPrefix) && state.taintSources.length > 0 && !state.sanitized) {
          const suffix = k.slice(srcPrefix.length);
          const targetField = target.append(suffix);
          this.taint(targetField, state.taintSources);
        }
      }
    }

    if (mergedSources.length > 0) {
      this.taint(target, [...new Set(mergedSources)]);
    }

    // Explicit fields override
    for (const { name, valuePath } of explicitFields) {
      const fieldPath = target.append(name);
      if (valuePath) {
        const valState = this.query(valuePath);
        if (valState && valState.taintSources.length > 0 && !valState.sanitized) {
          this.taint(fieldPath, valState.taintSources);
        } else {
          // Explicit clean value clears taint on this field
          const fKey = fieldPath.toString();
          const existing = this.taintMap.get(fKey);
          if (existing) {
            existing.taintSources = [];
            existing.sanitized = true;
            existing.appliedSanitizations = [];
          }
        }
      }
    }
  }

  /**
   * Array write: arr.push(element) or arr[i] = element
   * Taints the array's element wildcard path.
   */
  arrayWrite(arr: AccessPath, element: AccessPath): void {
    const elemState = this.query(element);
    if (elemState && elemState.taintSources.length > 0 && !elemState.sanitized) {
      const wildcardPath = AccessPath.wildcard(arr.root, arr.fields);
      this.taint(wildcardPath, elemState.taintSources);
    }
  }

  /**
   * Map/Set write: map.set(key, value)
   * Use key='*' for dynamic keys.
   */
  mapWrite(map: AccessPath, key: string, value: AccessPath): void {
    const valState = this.query(value);
    if (valState && valState.taintSources.length > 0 && !valState.sanitized) {
      if (key === '*') {
        const wildcardPath = AccessPath.wildcard(map.root, map.fields);
        this.taint(wildcardPath, valState.taintSources);
      } else {
        const keyPath = map.append(key);
        this.taint(keyPath, valState.taintSources);
      }
    }
  }

  /**
   * Function return: models the return value.
   * Creates a synthetic '$return' path that callers can query.
   */
  setReturn(valuePath: AccessPath): void {
    const returnPath = new AccessPath(RETURN_PATH_ROOT, []);
    const state = this.query(valuePath);
    if (state && state.taintSources.length > 0) {
      this.taint(returnPath, state.taintSources);
      if (state.sanitized) {
        for (const kind of state.appliedSanitizations) {
          this.sanitize(returnPath, kind);
        }
      }
    }
    this.alias(returnPath, valuePath);
  }

  /** Get the return path's taint state */
  getReturn(): FieldTaintState | null {
    const returnPath = new AccessPath(RETURN_PATH_ROOT, []);
    return this.query(returnPath);
  }

  // ── Control Flow ────────────────────────────────────────────────

  /**
   * Fork the heap for branching (if/else creates two independent copies).
   * Deep-copies both the taintMap and aliases.
   */
  fork(): HeapModel {
    const forked = new HeapModel();

    for (const [key, state] of this.taintMap) {
      forked.taintMap.set(key, {
        accessPath: state.accessPath.clone(),
        taintSources: [...state.taintSources],
        sanitized: state.sanitized,
        appliedSanitizations: [...state.appliedSanitizations],
      });
    }

    for (const [key, aliasSet] of this.aliases) {
      forked.aliases.set(key, new Set(aliasSet));
    }

    return forked;
  }

  /**
   * Join two heap models at a merge point (conservative: union of taint).
   * A path is tainted if tainted in EITHER branch.
   * A path is sanitized only if sanitized in BOTH branches.
   */
  static join(a: HeapModel, b: HeapModel): HeapModel {
    const merged = new HeapModel();

    // Collect all keys from both heaps
    const allKeys = new Set<string>([
      ...a.taintMap.keys(),
      ...b.taintMap.keys(),
    ]);

    for (const key of allKeys) {
      const stateA = a.taintMap.get(key);
      const stateB = b.taintMap.get(key);

      if (stateA && stateB) {
        // Present in both — union sources, intersect sanitization
        const combinedSources = new Set([
          ...stateA.taintSources,
          ...stateB.taintSources,
        ]);
        const bothSanitized = stateA.sanitized && stateB.sanitized;
        const commonSanitizations = stateA.appliedSanitizations.filter(
          (s) => stateB.appliedSanitizations.includes(s),
        );

        merged.taintMap.set(key, {
          accessPath: stateA.accessPath.clone(),
          taintSources: [...combinedSources],
          sanitized: bothSanitized,
          appliedSanitizations: bothSanitized ? commonSanitizations : [],
        });
      } else {
        // Present in only one branch — conservatively include it
        const state = (stateA ?? stateB)!;
        merged.taintMap.set(key, {
          accessPath: state.accessPath.clone(),
          taintSources: [...state.taintSources],
          // Not sanitized if only one branch has it (the other branch doesn't know)
          sanitized: false,
          appliedSanitizations: [],
        });
      }
    }

    // Merge aliases (union)
    const allAliasKeys = new Set<string>([
      ...a.aliases.keys(),
      ...b.aliases.keys(),
    ]);

    for (const key of allAliasKeys) {
      const setA = a.aliases.get(key);
      const setB = b.aliases.get(key);
      const combined = new Set<string>();
      if (setA) for (const v of setA) combined.add(v);
      if (setB) for (const v of setB) combined.add(v);
      merged.aliases.set(key, combined);
    }

    return merged;
  }

  // ── Utilities ───────────────────────────────────────────────────

  /** Get all tainted paths (for debugging/reporting) */
  getAllTaintedPaths(): AccessPath[] {
    const result: AccessPath[] = [];
    for (const state of this.taintMap.values()) {
      if (state.taintSources.length > 0 && !state.sanitized) {
        result.push(state.accessPath.clone());
      }
    }
    return result;
  }

  /** Clear all state */
  clear(): void {
    this.taintMap.clear();
    this.aliases.clear();
  }

  /** Get stats */
  getStats(): { paths: number; aliases: number; tainted: number } {
    let tainted = 0;
    for (const state of this.taintMap.values()) {
      if (state.taintSources.length > 0 && !state.sanitized) {
        tainted++;
      }
    }
    return {
      paths: this.taintMap.size,
      aliases: this.aliases.size,
      tainted,
    };
  }

  // ── Internal Helpers ────────────────────────────────────────────

  /**
   * Reconstruct an AccessPath from its string key.
   * Handles simple dot-separated paths.
   */
  private pathFromKey(key: string): AccessPath | null {
    if (!key) return null;
    const parts = key.split('.');
    if (parts.length === 0) return null;
    return new AccessPath(parts[0], parts.slice(1));
  }
}

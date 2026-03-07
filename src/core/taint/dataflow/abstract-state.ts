/**
 * AbstractState — Program-point taint state for data flow analysis
 *
 * Represents the complete abstract state at a single program point during
 * taint analysis. Combines variable-level taint facts (from the lattice)
 * with field-sensitive heap tracking (from the HeapModel).
 *
 * Key design decisions:
 * - Variables are tracked in a flat map for fast lookup.
 * - Field-level tracking delegates to the HeapModel for alias-aware,
 *   wildcard-aware, hierarchical taint propagation.
 * - `clone()` produces a fully independent copy for branch forking.
 * - `join()` conservatively merges two states at CFG merge points.
 * - `equals()` enables fixpoint detection for iterative analysis.
 */

import type { TaintFact } from './lattice.js';
import {
  TaintValue,
  joinFacts,
  createTaintedFact,
  createUntaintedFact,
} from './lattice.js';
import { HeapModel } from '../heap/heap-model.js';
import { AccessPath } from '../heap/access-path.js';
import type { SanitizationKind } from '../types.js';

export class AbstractState {
  /** Variable-level taint facts keyed by variable name */
  private vars: Map<string, TaintFact>;
  /** Field-sensitive heap model for object/property tracking */
  private heap: HeapModel;

  constructor() {
    this.vars = new Map();
    this.heap = new HeapModel();
  }

  // ── Variable Operations ──────────────────────────────────────────

  /**
   * Get the taint fact for a variable.
   *
   * Returns UNTAINTED_FACT for variables not previously recorded, which
   * is the safe default: unknown locals are assumed clean until proven
   * otherwise by data flow.
   *
   * @param name - The variable name to look up
   */
  getVar(name: string): TaintFact {
    return this.vars.get(name) ?? createUntaintedFact();
  }

  /**
   * Set the taint fact for a variable, replacing any previous fact.
   *
   * @param name - The variable name
   * @param fact - The taint fact to associate with this variable
   */
  setVar(name: string, fact: TaintFact): void {
    this.vars.set(name, fact);
  }

  /**
   * Check whether a variable has an explicit taint fact recorded.
   *
   * Note: `hasVar` returning false does not mean the variable is untainted;
   * it means the analysis has not yet encountered the variable.
   */
  hasVar(name: string): boolean {
    return this.vars.has(name);
  }

  /**
   * Get a snapshot of all recorded variable taint facts.
   *
   * The returned map is a shallow copy; mutating it will not affect
   * the abstract state, but the TaintFact objects are shared.
   */
  getAllVars(): Map<string, TaintFact> {
    return new Map(this.vars);
  }

  // ── Field-Sensitive Operations ───────────────────────────────────

  /**
   * Mark a heap field as tainted.
   *
   * Delegates to the HeapModel which handles hierarchical propagation,
   * alias resolution, and wildcard matching.
   *
   * @param path - The access path to taint (e.g. req.body.user)
   * @param paramIndex - Index of the function parameter contributing taint
   * @param sourceKind - Semantic category of the taint source
   */
  taintField(path: AccessPath, paramIndex: number, sourceKind: string): void {
    const sourceId = `param:${paramIndex}:${sourceKind}`;
    this.heap.taint(path, [sourceId]);
  }

  /**
   * Mark a heap field as sanitized.
   *
   * @param path - The access path to sanitize
   * @param sanitizerKind - The kind of sanitization applied
   */
  sanitizeField(path: AccessPath, sanitizerKind: string): void {
    this.heap.sanitize(path, sanitizerKind as SanitizationKind);
  }

  /**
   * Query the taint state of a heap field.
   *
   * Translates the HeapModel's FieldTaintState into a TaintFact for
   * uniform consumption by the data flow engine.
   *
   * @param path - The access path to query
   * @returns A TaintFact reflecting the field's taint state
   */
  isFieldTainted(path: AccessPath): TaintFact {
    const state = this.heap.query(path);

    if (!state || state.taintSources.length === 0) {
      if (state?.sanitized) {
        return {
          value: TaintValue.Sanitized,
          sourceParams: new Set<number>(),
          sourceKinds: new Set<string>(),
          sanitizations: [...state.appliedSanitizations],
          isSanitized: true,
        };
      }
      return createUntaintedFact();
    }

    // Extract param indices and source kinds from taint source IDs
    // Source IDs follow the format "param:<index>:<sourceKind>"
    const sourceParams = new Set<number>();
    const sourceKinds = new Set<string>();

    for (const sourceId of state.taintSources) {
      const parts = sourceId.split(':');
      if (parts[0] === 'param' && parts.length >= 3) {
        const idx = parseInt(parts[1], 10);
        if (!isNaN(idx)) {
          sourceParams.add(idx);
        }
        sourceKinds.add(parts.slice(2).join(':'));
      } else {
        // Non-param source — preserve as source kind
        sourceKinds.add(sourceId);
      }
    }

    if (state.sanitized) {
      return {
        value: TaintValue.Sanitized,
        sourceParams,
        sourceKinds,
        sanitizations: [...state.appliedSanitizations],
        isSanitized: true,
      };
    }

    return {
      value: TaintValue.Tainted,
      sourceParams,
      sourceKinds,
      sanitizations: [],
      isSanitized: false,
    };
  }

  // ── Alias Tracking ───────────────────────────────────────────────

  /**
   * Record an alias relationship: `target` points to the same heap
   * location as `source`.
   *
   * This is used for assignments like `const x = req.body` where `x`
   * should inherit taint from `req.body`.
   *
   * @param target - The access path being assigned to
   * @param source - The access path being assigned from
   */
  addAlias(target: AccessPath, source: AccessPath): void {
    this.heap.alias(target, source);
  }

  // ── Branch Handling ──────────────────────────────────────────────

  /**
   * Create a deep copy of this state for branch forking.
   *
   * Both the variable map and the heap model are independently copied,
   * so mutations to the clone do not affect the original and vice versa.
   */
  clone(): AbstractState {
    const cloned = new AbstractState();

    // Deep copy each variable fact
    for (const [name, fact] of this.vars) {
      cloned.vars.set(name, {
        value: fact.value,
        sourceParams: new Set(fact.sourceParams),
        sourceKinds: new Set(fact.sourceKinds),
        sanitizations: [...fact.sanitizations],
        isSanitized: fact.isSanitized,
        accessPath: fact.accessPath ? [...fact.accessPath] : undefined,
      });
    }

    // Fork the heap model (deep copy handled by HeapModel.fork)
    cloned.heap = this.heap.fork();

    return cloned;
  }

  // ── CFG Join ─────────────────────────────────────────────────────

  /**
   * Join two abstract states at a CFG merge point.
   *
   * Produces a conservative over-approximation:
   * - Variables present in both states are joined via `joinFacts`.
   * - Variables present in only one state are kept (the other branch
   *   may not have assigned to them, so the original value persists).
   * - Heap models are joined via `HeapModel.join` (union of taint,
   *   intersection of sanitization).
   *
   * @param a - State from the first incoming edge
   * @param b - State from the second incoming edge
   * @returns Merged state
   */
  static join(a: AbstractState, b: AbstractState): AbstractState {
    const merged = new AbstractState();

    // Collect all variable names from both states
    const allVarNames = new Set<string>([
      ...a.vars.keys(),
      ...b.vars.keys(),
    ]);

    for (const name of allVarNames) {
      const factA = a.vars.get(name);
      const factB = b.vars.get(name);

      if (factA && factB) {
        // Present in both branches — join the facts
        merged.vars.set(name, joinFacts(factA, factB));
      } else {
        // Present in only one branch — keep as-is (deep copy)
        const fact = (factA ?? factB)!;
        merged.vars.set(name, {
          value: fact.value,
          sourceParams: new Set(fact.sourceParams),
          sourceKinds: new Set(fact.sourceKinds),
          sanitizations: [...fact.sanitizations],
          isSanitized: fact.isSanitized,
          accessPath: fact.accessPath ? [...fact.accessPath] : undefined,
        });
      }
    }

    // Join heap models
    merged.heap = HeapModel.join(a.heap, b.heap);

    return merged;
  }

  // ── Fixpoint Detection ───────────────────────────────────────────

  /**
   * Check structural equality with another abstract state.
   *
   * Used by the iterative fixpoint solver to determine when the analysis
   * has stabilised (no more changes propagate).
   *
   * @param other - The state to compare against
   * @returns true if both states are structurally identical
   */
  equals(other: AbstractState): boolean {
    // Quick size check
    if (this.vars.size !== other.vars.size) return false;

    // Check each variable fact
    for (const [name, fact] of this.vars) {
      const otherFact = other.vars.get(name);
      if (!otherFact) return false;
      if (!factsEqual(fact, otherFact)) return false;
    }

    // Check heap equality via stats — a pragmatic approximation.
    // Full structural comparison of heap models is expensive; the stats
    // check catches the vast majority of differences.
    const heapStatsA = this.heap.getStats();
    const heapStatsB = other.heap.getStats();
    if (
      heapStatsA.paths !== heapStatsB.paths ||
      heapStatsA.aliases !== heapStatsB.aliases ||
      heapStatsA.tainted !== heapStatsB.tainted
    ) {
      return false;
    }

    return true;
  }

  // ── Entry State Factory ──────────────────────────────────────────

  /**
   * Create the initial abstract state for a function entry point.
   *
   * Each parameter is assigned a synthetic tainted fact with its index
   * as the source parameter. This models the assumption that all
   * function parameters may carry user-controlled data.
   *
   * @param paramCount - Number of function parameters
   * @param paramNames - Names of the parameters (parallel array)
   * @returns An AbstractState with each parameter tainted
   */
  static createEntryState(paramCount: number, paramNames: string[]): AbstractState {
    const state = new AbstractState();

    for (let i = 0; i < paramCount; i++) {
      const name = i < paramNames.length ? paramNames[i] : `$arg${i}`;
      const fact = createTaintedFact(i, 'user-input');
      state.vars.set(name, fact);

      // Also taint the parameter in the heap model so field accesses
      // on the parameter (e.g. req.body) inherit taint via parent lookup
      const paramPath = new AccessPath(name, []);
      state.heap.taint(paramPath, [`param:${i}:user-input`]);
    }

    return state;
  }

  // ── Provenance Queries ───────────────────────────────────────────

  /**
   * Get the set of parameter indices that contribute taint to a variable.
   *
   * This is useful for interprocedural analysis: when a callee's return
   * value is tainted, we need to know which of the caller's arguments
   * propagated through.
   *
   * @param name - The variable name
   * @returns Set of zero-based parameter indices (empty if untainted)
   */
  getParamSources(name: string): Set<number> {
    const fact = this.vars.get(name);
    if (!fact) return new Set();
    return new Set(fact.sourceParams);
  }

  /**
   * Check whether a variable's taint has been sanitized.
   *
   * @param name - The variable name
   * @returns true if the variable is in the Sanitized state
   */
  isSanitized(name: string): boolean {
    const fact = this.vars.get(name);
    if (!fact) return false;
    return fact.isSanitized;
  }

  /**
   * Get the list of sanitizer names applied to a variable.
   *
   * @param name - The variable name
   * @returns Array of sanitizer names (empty if none applied)
   */
  getSanitizations(name: string): string[] {
    const fact = this.vars.get(name);
    if (!fact) return [];
    return [...fact.sanitizations];
  }
}

// ── Internal Helpers ─────────────────────────────────────────────────

/**
 * Check structural equality of two TaintFacts.
 *
 * Compares value, sourceParams, sourceKinds, sanitizations, and
 * isSanitized fields. The accessPath field is also compared when present.
 */
function factsEqual(a: TaintFact, b: TaintFact): boolean {
  if (a.value !== b.value) return false;
  if (a.isSanitized !== b.isSanitized) return false;

  // Compare sourceParams sets
  if (a.sourceParams.size !== b.sourceParams.size) return false;
  for (const p of a.sourceParams) {
    if (!b.sourceParams.has(p)) return false;
  }

  // Compare sourceKinds sets
  if (a.sourceKinds.size !== b.sourceKinds.size) return false;
  for (const k of a.sourceKinds) {
    if (!b.sourceKinds.has(k)) return false;
  }

  // Compare sanitizations arrays (order-sensitive)
  if (a.sanitizations.length !== b.sanitizations.length) return false;
  for (let i = 0; i < a.sanitizations.length; i++) {
    if (a.sanitizations[i] !== b.sanitizations[i]) return false;
  }

  // Compare accessPath if present
  if (a.accessPath !== undefined || b.accessPath !== undefined) {
    if (!a.accessPath || !b.accessPath) return false;
    if (a.accessPath.length !== b.accessPath.length) return false;
    for (let i = 0; i < a.accessPath.length; i++) {
      if (a.accessPath[i] !== b.accessPath[i]) return false;
    }
  }

  return true;
}

/**
 * Taint Lattice — Abstract value domain for taint analysis
 *
 * Implements a standard five-element lattice for abstract interpretation
 * of taint state at each program point:
 *
 * ```
 *        Top (T)        — may be tainted or untainted (unknown)
 *       /     \
 *  Tainted   Sanitized   — definitely tainted / definitely sanitized
 *       \     /
 *     Untainted          — definitely clean
 *         |
 *      Bottom (B)       — unreachable / no information
 * ```
 *
 * The lattice ordering is:
 *   Bottom < Untainted < {Tainted, Sanitized} < Top
 *
 * Tainted and Sanitized are incomparable siblings; their join is Top.
 */

// ── Taint Value Enum ─────────────────────────────────────────────────

/**
 * Abstract taint value in the lattice.
 *
 * Numeric encoding preserves the partial order for efficient comparisons,
 * but join/meet are explicitly defined since the lattice is not totally ordered.
 */
export enum TaintValue {
  /** Unreachable / no information (lattice bottom) */
  Bottom = 0,
  /** Definitely clean — no tainted data flows here */
  Untainted = 1,
  /** Definitely tainted — user-controlled data flows here */
  Tainted = 2,
  /** Definitely sanitized — taint was present but has been neutralised */
  Sanitized = 3,
  /** Unknown — may be tainted or untainted (lattice top, conservative) */
  Top = 4,
}

// ── Lattice Operations ───────────────────────────────────────────────

/**
 * Least upper bound (join / merge).
 *
 * Used at CFG join points where control flow merges. The result must
 * conservatively over-approximate both inputs:
 *
 * - `Bottom join x = x`  (bottom is the identity)
 * - `x join x = x`
 * - `Tainted join Untainted = Top`
 * - `Tainted join Sanitized = Top`
 * - `Sanitized join Untainted = Top`
 * - `Top join x = Top`
 */
export function join(a: TaintValue, b: TaintValue): TaintValue {
  if (a === b) return a;
  if (a === TaintValue.Bottom) return b;
  if (b === TaintValue.Bottom) return a;
  if (a === TaintValue.Top || b === TaintValue.Top) return TaintValue.Top;

  // Remaining cases: {Tainted, Sanitized, Untainted} x {Tainted, Sanitized, Untainted}
  // where a !== b. Any two distinct non-bottom/non-top elements join to Top.
  return TaintValue.Top;
}

/**
 * Greatest lower bound (meet / intersection).
 *
 * Used for path-sensitive refinement where both conditions must hold:
 *
 * - `Top meet x = x`  (top is the identity)
 * - `x meet x = x`
 * - `Bottom meet x = Bottom`
 * - `Tainted meet Untainted = Bottom` (contradictory → unreachable)
 * - `Tainted meet Sanitized = Bottom`
 * - `Sanitized meet Untainted = Bottom`
 */
export function meet(a: TaintValue, b: TaintValue): TaintValue {
  if (a === b) return a;
  if (a === TaintValue.Top) return b;
  if (b === TaintValue.Top) return a;
  if (a === TaintValue.Bottom || b === TaintValue.Bottom) return TaintValue.Bottom;

  // Two distinct concrete values meet to Bottom (contradictory).
  return TaintValue.Bottom;
}

/**
 * Partial order check: `a` is less than or equal to `b` in the lattice.
 *
 * Returns true when `a` is at least as precise (lower) as `b`:
 * - `Bottom <= everything`
 * - `everything <= Top`
 * - `Untainted <= {Tainted, Sanitized, Top}`  — Untainted is below the mid-level
 * - `Tainted` and `Sanitized` are incomparable (neither is <= the other)
 *
 * Formally: `a <= b` iff `join(a, b) === b`.
 */
export function isLeq(a: TaintValue, b: TaintValue): boolean {
  return join(a, b) === b;
}

// ── Taint Fact ───────────────────────────────────────────────────────

/**
 * A taint fact combines the abstract lattice value with metadata that
 * tracks provenance (which parameters contribute taint), the kinds of
 * taint sources, and any sanitization history.
 */
export interface TaintFact {
  /** Abstract taint value from the lattice */
  value: TaintValue;
  /** Indices of function parameters that contribute taint to this value */
  sourceParams: Set<number>;
  /** Semantic categories of taint sources (e.g. 'req-body', 'req-params') */
  sourceKinds: Set<string>;
  /** Names of sanitizers that have been applied (ordered by application) */
  sanitizations: string[];
  /** Shorthand: true when `value === TaintValue.Sanitized` */
  isSanitized: boolean;
  /** Optional field access path for tracking specific heap locations */
  accessPath?: string[];
}

// ── Fact Operations ──────────────────────────────────────────────────

/**
 * Join two taint facts at a CFG merge point.
 *
 * - Lattice values are joined.
 * - Source parameters and source kinds are unioned (conservative).
 * - Sanitizations are intersected only if both facts are sanitized;
 *   otherwise sanitization credit is lost (conservative).
 */
export function joinFacts(a: TaintFact, b: TaintFact): TaintFact {
  const value = join(a.value, b.value);

  const sourceParams = new Set<number>([...a.sourceParams, ...b.sourceParams]);
  const sourceKinds = new Set<string>([...a.sourceKinds, ...b.sourceKinds]);

  // Sanitization: only keep credit if both branches agree the value is sanitized
  const bothSanitized = a.isSanitized && b.isSanitized;
  let sanitizations: string[];
  if (bothSanitized) {
    // Intersect: only sanitizers applied on both paths are reliable
    const bSanitizationSet = new Set(b.sanitizations);
    sanitizations = a.sanitizations.filter((s) => bSanitizationSet.has(s));
  } else {
    sanitizations = [];
  }

  const isSanitized = value === TaintValue.Sanitized;

  return {
    value,
    sourceParams,
    sourceKinds,
    sanitizations,
    isSanitized,
  };
}

/**
 * Meet two taint facts for path-sensitive refinement.
 *
 * - Lattice values are met.
 * - Source parameters and source kinds are intersected (both must agree).
 * - Sanitizations are unioned (either path's sanitization counts).
 */
export function meetFacts(a: TaintFact, b: TaintFact): TaintFact {
  const value = meet(a.value, b.value);

  // Intersect provenance — only params/kinds present in both are retained
  const sourceParams = new Set<number>(
    [...a.sourceParams].filter((p) => b.sourceParams.has(p)),
  );
  const sourceKinds = new Set<string>(
    [...a.sourceKinds].filter((k) => b.sourceKinds.has(k)),
  );

  // Union sanitizations — if either path sanitized, the refinement keeps it
  const sanitizationSet = new Set([...a.sanitizations, ...b.sanitizations]);
  const sanitizations = [...sanitizationSet];

  const isSanitized = value === TaintValue.Sanitized;

  return {
    value,
    sourceParams,
    sourceKinds,
    sanitizations,
    isSanitized,
  };
}

// ── Fact Factories ───────────────────────────────────────────────────

/**
 * Create a taint fact representing a tainted value originating from a
 * specific function parameter.
 *
 * @param paramIndex - Zero-based index of the contributing parameter
 * @param sourceKind - Optional semantic category (e.g. 'req-body')
 */
export function createTaintedFact(paramIndex: number, sourceKind?: string): TaintFact {
  const sourceKinds = new Set<string>();
  if (sourceKind !== undefined) {
    sourceKinds.add(sourceKind);
  }
  return {
    value: TaintValue.Tainted,
    sourceParams: new Set([paramIndex]),
    sourceKinds,
    sanitizations: [],
    isSanitized: false,
  };
}

/**
 * Create a taint fact representing a definitely-clean (untainted) value.
 */
export function createUntaintedFact(): TaintFact {
  return {
    value: TaintValue.Untainted,
    sourceParams: new Set(),
    sourceKinds: new Set(),
    sanitizations: [],
    isSanitized: false,
  };
}

/**
 * Create a taint fact representing an unreachable / no-information state.
 */
export function createBottomFact(): TaintFact {
  return {
    value: TaintValue.Bottom,
    sourceParams: new Set(),
    sourceKinds: new Set(),
    sanitizations: [],
    isSanitized: false,
  };
}

// ── Predicates ───────────────────────────────────────────────────────

/**
 * Returns true if the fact is conservatively considered tainted.
 *
 * This includes both `Tainted` (definitely tainted) and `Top` (may be
 * tainted — we cannot prove it is clean). This conservative check is
 * appropriate for sink reachability: if we cannot prove a value is clean,
 * we must report a potential flow.
 */
export function isTainted(fact: TaintFact): boolean {
  return fact.value === TaintValue.Tainted || fact.value === TaintValue.Top;
}

// ── Singleton Constants ──────────────────────────────────────────────

/**
 * Shared bottom fact — represents unreachable code or uninitialised state.
 * Do not mutate; treat as immutable.
 */
export const BOTTOM_FACT: Readonly<TaintFact> = Object.freeze({
  value: TaintValue.Bottom,
  sourceParams: Object.freeze(new Set<number>()) as Set<number>,
  sourceKinds: Object.freeze(new Set<string>()) as Set<string>,
  sanitizations: [] as string[],
  isSanitized: false,
});

/**
 * Shared untainted fact — represents a definitely-clean value.
 * Do not mutate; treat as immutable.
 */
export const UNTAINTED_FACT: Readonly<TaintFact> = Object.freeze({
  value: TaintValue.Untainted,
  sourceParams: Object.freeze(new Set<number>()) as Set<number>,
  sourceKinds: Object.freeze(new Set<string>()) as Set<string>,
  sanitizations: [] as string[],
  isSanitized: false,
});

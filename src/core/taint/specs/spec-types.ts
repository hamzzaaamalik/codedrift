/**
 * Taint Specification Rule Types
 *
 * Declarative types for defining taint sources, sinks, sanitizers,
 * and propagators in YAML/JSON spec files (.codedrift-taint.yml).
 * Replaces hardcoded pattern lists with user-configurable rules.
 */

/** Severity levels for taint rules */
export type TaintRuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * A pattern that matches AST nodes.
 *
 * Examples:
 * - `"req.body.**"` — any nested property of req.body
 * - `"$pool.query($sql, ...)"` — call with metavar object and args
 * - `"parseInt($x)"` — function call with metavar arg
 * - `"@Body() $param"` — decorator pattern
 * - `"$x = $tainted"` — assignment pattern
 */
export interface TaintPattern {
  /** The pattern string, e.g., "req.body.**", "$pool.query($arg, ...)" */
  pattern: string;
  /** Parsed pattern components (filled by parser) */
  parsed?: ParsedPattern;
}

/**
 * Parsed pattern — the pattern broken into matchable components.
 *
 * Metavariable convention: names starting with `$` match any single
 * expression/identifier and capture it for binding lookup.
 */
export interface ParsedPattern {
  /** Type of pattern */
  kind: 'property-access' | 'call-expression' | 'identifier' | 'decorator' | 'assignment';
  /** Object part, e.g., "req" or "$pool" ($ = metavariable) */
  object?: string;
  /** Property chain, e.g., ["body", "**"] for req.body.** */
  properties?: string[];
  /** Method name for calls */
  method?: string;
  /** Argument patterns for calls */
  args?: PatternArg[];
  /** Is this a metavariable pattern? (starts with $) */
  hasMetavars: boolean;
  /** Extracted metavariable names */
  metavars: string[];
}

/** Argument in a call pattern */
export interface PatternArg {
  /** Variable name or metavar, e.g., "$arg" */
  name: string;
  /** Is this a rest/spread match? ("...") */
  isRest: boolean;
}

/** Source specification — where tainted data enters */
export interface TaintSourceSpec {
  pattern: TaintPattern;
  /** Taint kind label, e.g., "user-input", "db-result" */
  kind: string;
  /** Optional note explaining why this is a source */
  note?: string;
}

/** Sink specification — where tainted data is consumed dangerously */
export interface TaintSinkSpec {
  pattern: TaintPattern;
  /** Which argument positions must be taint-free (0-indexed) */
  taintedArgs: number[];
  /** Optional condition for the sink to apply */
  condition?: string;
  /** Optional note */
  note?: string;
}

/** Sanitizer specification — functions/operations that neutralize taint */
export interface TaintSanitizerSpec {
  pattern: TaintPattern;
  /** What sanitization kind this represents */
  sanitizationKind?: string;
  /** Optional condition, e.g., "args.length >= 2" */
  condition?: string;
  /** Optional note */
  note?: string;
}

/** Propagator specification — functions that pass taint through */
export interface TaintPropagatorSpec {
  pattern: TaintPattern;
  /** Which input carries taint (metavar name or "this") */
  from: string;
  /** Where taint flows to ("return", metavar name, "this") */
  to: string;
  /** Optional note */
  note?: string;
}

/** A complete taint rule combining sources, sinks, sanitizers, and propagators */
export interface TaintRule {
  /** Unique rule identifier, e.g., "sql-injection" */
  id: string;
  /** Human-readable description */
  message: string;
  /** Severity */
  severity: TaintRuleSeverity;
  /** Whether this rule is enabled */
  enabled: boolean;
  /** Sources for this rule */
  sources: TaintSourceSpec[];
  /** Sinks for this rule */
  sinks: TaintSinkSpec[];
  /** Sanitizers that neutralize taint for this rule */
  sanitizers: TaintSanitizerSpec[];
  /** Propagators — functions that pass taint through */
  propagators: TaintPropagatorSpec[];
  /** Tags for categorization */
  tags?: string[];
  /** CWE IDs */
  cwe?: number[];
  /** OWASP category */
  owasp?: string[];
}

/** Complete taint specification file */
export interface TaintSpec {
  /** Version of the spec format */
  version: string;
  /** Global source definitions (apply to all rules) */
  globalSources?: TaintSourceSpec[];
  /** Global sanitizer definitions (apply to all rules) */
  globalSanitizers?: TaintSanitizerSpec[];
  /** Global propagator definitions */
  globalPropagators?: TaintPropagatorSpec[];
  /** Individual rules */
  rules: TaintRule[];
}

/** Result of loading specs from disk */
export interface TaintSpecLoadResult {
  specs: TaintSpec[];
  /** Merged view: all rules from all spec files */
  allRules: TaintRule[];
  /** All sources across all specs (including globals) */
  allSources: TaintSourceSpec[];
  /** All sinks across all specs */
  allSinks: TaintSinkSpec[];
  /** All sanitizers across all specs (including globals) */
  allSanitizers: TaintSanitizerSpec[];
  /** All propagators (including globals) */
  allPropagators: TaintPropagatorSpec[];
  /** Errors encountered during loading */
  errors: { file: string; message: string }[];
}

/**
 * TaintQueryEngine — Demand-driven cross-file taint query engine.
 *
 * Provides forward and backward taint flow queries over pre-computed
 * function summaries.  Given a set of summaries (produced by the
 * SummaryBuilder), the engine can:
 *
 *   1. Find ALL taint flows in the project (forward from every source)
 *   2. Query backward from a specific sink to discover reaching sources
 *   3. Query forward from a specific source to discover reachable sinks
 *   4. Summarise a set of flows by severity / type
 */

import type {
  TaintSourceKind,
  TaintSinkKind,
  SanitizationKind,
} from '../types.js';

import type {
  FunctionSummary,
  SummaryInput,
  SummaryOutput,
  SummarySinkHit,
  SummaryCallEdge,
} from '../summaries/summary-types.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** A step in a taint flow trace */
export interface TraceStep {
  filePath: string;
  functionName: string;
  canonicalId: string;
  line: number;
  description: string;
  accessPath: string;
  propagation: string;
}

/** A cross-file hop in the flow */
export interface CrossFileHop {
  fromFile: string;
  toFile: string;
  fromFunction: string;
  toFunction: string;
  paramIndex: number;
}

/** Complete result of a taint query */
export interface TaintQueryResult {
  sourceKind: TaintSourceKind;
  sourceFunction: string;
  sourceFile: string;

  sinkKind: TaintSinkKind;
  sinkCallee: string;
  sinkFunction: string;
  sinkFile: string;
  sinkLine: number;

  trace: TraceStep[];
  crossFileHops: CrossFileHop[];
  sanitizations: SanitizationKind[];
  isSanitized: boolean;
  confidence: 'definite' | 'likely' | 'possible';
  fileCount: number;
  hopCount: number;
}

/** Query options */
export interface QueryOptions {
  maxDepth?: number;
  includeSanitized?: boolean;
  sinkKindFilter?: TaintSinkKind[];
  sourceKindFilter?: TaintSourceKind[];
  minConfidence?: 'definite' | 'likely' | 'possible';
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const DEFAULT_MAX_DEPTH = 10;

const CONFIDENCE_RANK: Record<string, number> = {
  definite: 3,
  likely: 2,
  possible: 1,
};

function meetsMinConfidence(
  value: 'definite' | 'likely' | 'possible',
  min: 'definite' | 'likely' | 'possible',
): boolean {
  return (CONFIDENCE_RANK[value] ?? 0) >= (CONFIDENCE_RANK[min] ?? 0);
}

/** Build a human-readable access path string from a SummaryInput. */
function inputAccessPath(input: SummaryInput): string {
  const base =
    input.label ||
    (input.kind === 'param' ? `param[${input.paramIndex}]` : input.kind);
  if (input.accessPath && input.accessPath.length > 0) {
    return `${base}.${input.accessPath.join('.')}`;
  }
  return base;
}

/** Build a human-readable access path string from a SummaryOutput. */
function outputAccessPath(output: SummaryOutput): string {
  const base = output.label || output.kind;
  if (output.accessPath && output.accessPath.length > 0) {
    return `${base}.${output.accessPath.join('.')}`;
  }
  return base;
}

/** Check whether a SummaryInput matches a given param index. */
function inputMatchesParam(input: SummaryInput, paramIndex: number): boolean {
  return input.kind === 'param' && input.paramIndex === paramIndex;
}

/** Deduplicate results by composite key. */
function deduplicateResults(results: TaintQueryResult[]): TaintQueryResult[] {
  const seen = new Set<string>();
  const out: TaintQueryResult[] = [];
  for (const r of results) {
    const key = `${r.sourceFunction}|${r.sourceKind}|${r.sinkFunction}|${r.sinkKind}|${r.sinkLine}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(r);
    }
  }
  return out;
}

/** Human-readable sink description. */
function sinkDescription(sinkHit: SummarySinkHit): string {
  const callee = sinkHit.sinkCallee;
  const risk: Record<string, string> = {
    'db-query': 'potential SQL injection',
    'db-mutation': 'potential SQL injection',
    'command-execution': 'potential command injection',
    'file-read': 'potential path traversal',
    'file-write': 'potential arbitrary file write',
    'html-output': 'potential XSS',
    'template-render': 'potential template injection',
    'redirect': 'potential open redirect',
    'url-construction': 'potential SSRF',
    'eval': 'potential code injection',
    'dynamic-import': 'potential code injection',
    'http-request': 'potential SSRF',
    'log-output': 'potential log injection',
  };
  const riskLabel = risk[sinkHit.sinkKind] ?? sinkHit.sinkKind;
  return `Flows to ${callee}() — ${riskLabel}`;
}

/** Human-readable source description. */
function sourceDescription(sourceKind: TaintSourceKind): string {
  return `User input enters via ${sourceKind}`;
}

// ---------------------------------------------------------------------------
// Forward-walk state carried through recursion
// ---------------------------------------------------------------------------

interface ForwardState {
  sourceKind: TaintSourceKind;
  sourceSummary: FunctionSummary;
  trace: TraceStep[];
  crossFileHops: CrossFileHop[];
  sanitizations: SanitizationKind[];
  isSanitized: boolean;
  confidence: 'definite' | 'likely' | 'possible';
  visited: Set<string>;
  depth: number;
}

// ---------------------------------------------------------------------------
// Normalised options (all fields required)
// ---------------------------------------------------------------------------

interface NormalisedOptions {
  maxDepth: number;
  includeSanitized: boolean;
  sinkKindFilter: TaintSinkKind[] | null;
  sourceKindFilter: TaintSourceKind[] | null;
  minConfidence: 'definite' | 'likely' | 'possible';
}

// ---------------------------------------------------------------------------
// TaintQueryEngine
// ---------------------------------------------------------------------------

export class TaintQueryEngine {
  constructor(
    /** Get a single summary by canonical ID. */
    private summaryGetter: (canonicalId: string) => FunctionSummary | null,
    /** Get all summaries belonging to one file. */
    _fileSummaryGetter: (filePath: string) => FunctionSummary[],
    /** Return every canonical ID in the project. */
    private allIdsGetter: () => string[],
  ) {}

  // -----------------------------------------------------------------------
  // findAllFlows — forward from every taint source
  // -----------------------------------------------------------------------

  findAllFlows(options?: QueryOptions): TaintQueryResult[] {
    const opts = this.normalizeOptions(options);
    const allIds = this.allIdsGetter();
    const results: TaintQueryResult[] = [];

    for (const id of allIds) {
      const summary = this.summaryGetter(id);
      if (!summary || summary.taintSources.length === 0) continue;

      for (const src of summary.taintSources) {
        if (opts.sourceKindFilter && !opts.sourceKindFilter.includes(src.kind)) {
          continue;
        }
        const flows = this.walkForwardFromSource(summary, src.kind, src.output, opts);
        results.push(...flows);
      }
    }

    return this.applyFilters(deduplicateResults(results), opts);
  }

  // -----------------------------------------------------------------------
  // queryFromSource — forward from one specific source function
  // -----------------------------------------------------------------------

  queryFromSource(
    sourceCanonicalId: string,
    options?: QueryOptions,
  ): TaintQueryResult[] {
    const opts = this.normalizeOptions(options);
    const summary = this.summaryGetter(sourceCanonicalId);
    if (!summary) return [];

    const results: TaintQueryResult[] = [];
    for (const src of summary.taintSources) {
      if (opts.sourceKindFilter && !opts.sourceKindFilter.includes(src.kind)) {
        continue;
      }
      results.push(
        ...this.walkForwardFromSource(summary, src.kind, src.output, opts),
      );
    }

    return this.applyFilters(deduplicateResults(results), opts);
  }

  // -----------------------------------------------------------------------
  // queryFromSink — backward from a specific sink hit
  // -----------------------------------------------------------------------

  queryFromSink(
    sinkCanonicalId: string,
    sinkHitIndex: number,
    options?: QueryOptions,
  ): TaintQueryResult[] {
    const opts = this.normalizeOptions(options);
    const summary = this.summaryGetter(sinkCanonicalId);
    if (!summary) return [];
    if (sinkHitIndex < 0 || sinkHitIndex >= summary.sinkHits.length) return [];

    const sinkHit = summary.sinkHits[sinkHitIndex];
    if (opts.sinkKindFilter && !opts.sinkKindFilter.includes(sinkHit.sinkKind)) {
      return [];
    }

    const results: TaintQueryResult[] = [];
    const visited = new Set<string>();

    this.walkBackward(
      summary,
      sinkHit,
      /* traceBelow */ [],
      /* crossFileHops */ [],
      sinkHit.sanitizations.slice(),
      sinkHit.sanitized,
      'definite',
      visited,
      0,
      opts,
      results,
    );

    return this.applyFilters(deduplicateResults(results), opts);
  }

  // -----------------------------------------------------------------------
  // getFlowSummary
  // -----------------------------------------------------------------------

  getFlowSummary(flows: TaintQueryResult[]): {
    total: number;
    unsanitized: number;
    sanitized: number;
    bySinkKind: Map<TaintSinkKind, number>;
    bySourceKind: Map<TaintSourceKind, number>;
    byConfidence: Map<string, number>;
    maxHops: number;
    filesInvolved: Set<string>;
  } {
    const bySinkKind = new Map<TaintSinkKind, number>();
    const bySourceKind = new Map<TaintSourceKind, number>();
    const byConfidence = new Map<string, number>();
    const filesInvolved = new Set<string>();
    let unsanitized = 0;
    let sanitized = 0;
    let maxHops = 0;

    for (const f of flows) {
      if (f.isSanitized) {
        sanitized++;
      } else {
        unsanitized++;
      }

      bySinkKind.set(f.sinkKind, (bySinkKind.get(f.sinkKind) ?? 0) + 1);
      bySourceKind.set(
        f.sourceKind,
        (bySourceKind.get(f.sourceKind) ?? 0) + 1,
      );
      byConfidence.set(
        f.confidence,
        (byConfidence.get(f.confidence) ?? 0) + 1,
      );

      if (f.hopCount > maxHops) maxHops = f.hopCount;

      filesInvolved.add(f.sourceFile);
      filesInvolved.add(f.sinkFile);
      for (const hop of f.crossFileHops) {
        filesInvolved.add(hop.fromFile);
        filesInvolved.add(hop.toFile);
      }
    }

    return {
      total: flows.length,
      unsanitized,
      sanitized,
      bySinkKind,
      bySourceKind,
      byConfidence,
      maxHops,
      filesInvolved,
    };
  }

  // =======================================================================
  // Private — forward walk
  // =======================================================================

  /**
   * Walk forward from a single taint source output, collecting every
   * reachable sink along the way.
   */
  private walkForwardFromSource(
    sourceSummary: FunctionSummary,
    sourceKind: TaintSourceKind,
    sourceOutput: SummaryOutput,
    opts: NormalisedOptions,
  ): TaintQueryResult[] {
    const results: TaintQueryResult[] = [];

    const initialTrace: TraceStep = {
      filePath: sourceSummary.filePath,
      functionName: sourceSummary.functionName,
      canonicalId: sourceSummary.canonicalId,
      line: 0,
      description: sourceDescription(sourceKind),
      accessPath: outputAccessPath(sourceOutput),
      propagation: 'source',
    };

    const state: ForwardState = {
      sourceKind,
      sourceSummary,
      trace: [initialTrace],
      crossFileHops: [],
      sanitizations: [],
      isSanitized: false,
      confidence: 'definite',
      visited: new Set<string>([sourceSummary.canonicalId]),
      depth: 0,
    };

    // 1. Check for local sinks in the source function itself.
    this.collectLocalSinks(sourceSummary, sourceOutput, state, opts, results);

    // 2. Follow call edges where taint feeds into a callee parameter.
    this.followCallEdgesForward(
      sourceSummary,
      sourceOutput,
      state,
      opts,
      results,
    );

    // 3. If the source output is 'return', find callers and continue forward.
    if (sourceOutput.kind === 'return') {
      this.followReturnToCallers(sourceSummary, state, opts, results);
    }

    return results;
  }

  /**
   * Collect sinkHits inside `summary` reachable from `taintOutput`.
   */
  private collectLocalSinks(
    summary: FunctionSummary,
    taintOutput: SummaryOutput,
    state: ForwardState,
    opts: NormalisedOptions,
    results: TaintQueryResult[],
  ): void {
    for (const hit of summary.sinkHits) {
      if (!this.outputReachesInput(taintOutput, hit.input, summary)) continue;

      const sanitizations = [...state.sanitizations, ...hit.sanitizations];
      const isSanitized = state.isSanitized || hit.sanitized;

      if (!opts.includeSanitized && isSanitized) continue;
      if (opts.sinkKindFilter && !opts.sinkKindFilter.includes(hit.sinkKind)) {
        continue;
      }

      const sinkTrace: TraceStep = {
        filePath: summary.filePath,
        functionName: summary.functionName,
        canonicalId: summary.canonicalId,
        line: hit.line,
        description: sinkDescription(hit),
        accessPath: inputAccessPath(hit.input),
        propagation: 'sink',
      };

      const confidence = this.combineConfidence(state.confidence, 'definite');

      results.push(
        this.buildResult(
          state,
          summary,
          hit,
          [...state.trace, sinkTrace],
          state.crossFileHops,
          sanitizations,
          isSanitized,
          confidence,
        ),
      );
    }
  }

  /**
   * Follow callEdges from `summary` where `taintOutput` feeds into a
   * callee parameter, then recurse into the callee.
   */
  private followCallEdgesForward(
    summary: FunctionSummary,
    taintOutput: SummaryOutput,
    state: ForwardState,
    opts: NormalisedOptions,
    results: TaintQueryResult[],
  ): void {
    for (const edge of summary.callEdges) {
      if (state.depth >= opts.maxDepth) return;
      if (state.visited.has(edge.calleeCanonicalId)) continue;

      const taintedParams = this.taintedParamsViaEdge(
        edge,
        taintOutput,
        summary,
      );
      if (taintedParams.length === 0) continue;

      const callee = this.summaryGetter(edge.calleeCanonicalId);
      if (!callee) continue;

      const callTrace: TraceStep = {
        filePath: summary.filePath,
        functionName: summary.functionName,
        canonicalId: summary.canonicalId,
        line: edge.line,
        description: `Passed as argument ${taintedParams.join(', ')} to ${callee.functionName}()`,
        accessPath: outputAccessPath(taintOutput),
        propagation: 'call-arg',
      };

      // Record cross-file hops.
      const hops = [...state.crossFileHops];
      if (summary.filePath !== callee.filePath) {
        for (const pi of taintedParams) {
          hops.push({
            fromFile: summary.filePath,
            toFile: callee.filePath,
            fromFunction: summary.functionName,
            toFunction: callee.functionName,
            paramIndex: pi,
          });
        }
      }

      const newVisited = new Set(state.visited);
      newVisited.add(edge.calleeCanonicalId);

      for (const paramIdx of taintedParams) {
        // Accumulate sanitizations from the callee itself.
        let sanitizations = [...state.sanitizations];
        let isSanitized = state.isSanitized;
        if (callee.isSanitizer && callee.sanitizerKind) {
          sanitizations.push(callee.sanitizerKind);
          isSanitized = true;
        }

        const innerState: ForwardState = {
          sourceKind: state.sourceKind,
          sourceSummary: state.sourceSummary,
          trace: [...state.trace, callTrace],
          crossFileHops: hops,
          sanitizations,
          isSanitized,
          confidence: state.confidence,
          visited: newVisited,
          depth: state.depth + 1,
        };

        // Check callee's sinks for this param.
        this.collectSinksForParam(callee, paramIdx, innerState, opts, results);

        // Check callee's transfers from this param.
        for (const transfer of callee.transfers) {
          if (!inputMatchesParam(transfer.from, paramIdx)) continue;

          const tConf = this.combineConfidence(
            innerState.confidence,
            transfer.confidence,
          );
          const tSanitizations = [
            ...innerState.sanitizations,
            ...transfer.sanitizations,
          ];
          const tSanitized = innerState.isSanitized || transfer.isSanitized;

          const transferState: ForwardState = {
            ...innerState,
            confidence: tConf,
            sanitizations: tSanitizations,
            isSanitized: tSanitized,
          };

          // If transfer flows to return, follow callers of callee.
          if (transfer.to.kind === 'return') {
            this.followReturnToCallers(callee, transferState, opts, results);
          }

          // Continue through callee's own call edges.
          this.followCallEdgesForward(
            callee,
            transfer.to,
            transferState,
            opts,
            results,
          );
        }

        // Also follow callee's callEdges that pass the param directly.
        this.followCallEdgesForwardFromParam(
          callee,
          paramIdx,
          innerState,
          opts,
          results,
        );
      }
    }
  }

  /**
   * Follow callEdges in `summary` that directly forward a given param
   * to another callee (without going through a transfer first).
   */
  private followCallEdgesForwardFromParam(
    summary: FunctionSummary,
    paramIndex: number,
    state: ForwardState,
    opts: NormalisedOptions,
    results: TaintQueryResult[],
  ): void {
    for (const edge of summary.callEdges) {
      if (state.depth >= opts.maxDepth) return;
      if (state.visited.has(edge.calleeCanonicalId)) continue;

      const mappedParams: number[] = [];
      for (const am of edge.argMapping) {
        if (inputMatchesParam(am.callerInput, paramIndex)) {
          mappedParams.push(am.calleeParamIndex);
        }
      }
      if (mappedParams.length === 0) continue;

      const callee = this.summaryGetter(edge.calleeCanonicalId);
      if (!callee) continue;

      const callTrace: TraceStep = {
        filePath: summary.filePath,
        functionName: summary.functionName,
        canonicalId: summary.canonicalId,
        line: edge.line,
        description: `Passed as argument ${mappedParams.join(', ')} to ${callee.functionName}()`,
        accessPath: `param[${paramIndex}]`,
        propagation: 'call-arg',
      };

      const hops = [...state.crossFileHops];
      if (summary.filePath !== callee.filePath) {
        for (const pi of mappedParams) {
          hops.push({
            fromFile: summary.filePath,
            toFile: callee.filePath,
            fromFunction: summary.functionName,
            toFunction: callee.functionName,
            paramIndex: pi,
          });
        }
      }

      const newVisited = new Set(state.visited);
      newVisited.add(edge.calleeCanonicalId);

      for (const calleeParam of mappedParams) {
        let sanitizations = [...state.sanitizations];
        let isSanitized = state.isSanitized;
        if (callee.isSanitizer && callee.sanitizerKind) {
          sanitizations.push(callee.sanitizerKind);
          isSanitized = true;
        }

        const innerState: ForwardState = {
          sourceKind: state.sourceKind,
          sourceSummary: state.sourceSummary,
          trace: [...state.trace, callTrace],
          crossFileHops: hops,
          sanitizations,
          isSanitized,
          confidence: state.confidence,
          visited: newVisited,
          depth: state.depth + 1,
        };

        // Sinks in callee for this param.
        this.collectSinksForParam(
          callee,
          calleeParam,
          innerState,
          opts,
          results,
        );

        // Continue through callee's transfers.
        for (const transfer of callee.transfers) {
          if (!inputMatchesParam(transfer.from, calleeParam)) continue;

          const tState: ForwardState = {
            ...innerState,
            confidence: this.combineConfidence(
              innerState.confidence,
              transfer.confidence,
            ),
            sanitizations: [
              ...innerState.sanitizations,
              ...transfer.sanitizations,
            ],
            isSanitized: innerState.isSanitized || transfer.isSanitized,
          };

          if (transfer.to.kind === 'return') {
            this.followReturnToCallers(callee, tState, opts, results);
          }

          this.followCallEdgesForward(
            callee,
            transfer.to,
            tState,
            opts,
            results,
          );
        }

        // Recurse through callee's own callEdges for this param.
        this.followCallEdgesForwardFromParam(
          callee,
          calleeParam,
          innerState,
          opts,
          results,
        );
      }
    }
  }

  /**
   * Collect sinkHits in `summary` that are reachable from the given param.
   */
  private collectSinksForParam(
    summary: FunctionSummary,
    paramIndex: number,
    state: ForwardState,
    opts: NormalisedOptions,
    results: TaintQueryResult[],
  ): void {
    for (const hit of summary.sinkHits) {
      if (!inputMatchesParam(hit.input, paramIndex)) continue;

      const sanitizations = [...state.sanitizations, ...hit.sanitizations];
      const isSanitized = state.isSanitized || hit.sanitized;

      if (!opts.includeSanitized && isSanitized) continue;
      if (opts.sinkKindFilter && !opts.sinkKindFilter.includes(hit.sinkKind)) {
        continue;
      }

      const sinkTrace: TraceStep = {
        filePath: summary.filePath,
        functionName: summary.functionName,
        canonicalId: summary.canonicalId,
        line: hit.line,
        description: sinkDescription(hit),
        accessPath: inputAccessPath(hit.input),
        propagation: 'sink',
      };

      const confidence = this.combineConfidence(state.confidence, 'definite');

      results.push(
        this.buildResult(
          state,
          summary,
          hit,
          [...state.trace, sinkTrace],
          state.crossFileHops,
          sanitizations,
          isSanitized,
          confidence,
        ),
      );
    }
  }

  /**
   * When a function returns tainted data, scan all summaries for callers
   * that call this function and capture its return value, then continue
   * forward from the return-assignment site.
   */
  private followReturnToCallers(
    callee: FunctionSummary,
    state: ForwardState,
    opts: NormalisedOptions,
    results: TaintQueryResult[],
  ): void {
    if (state.depth >= opts.maxDepth) return;

    const allIds = this.allIdsGetter();

    for (const callerId of allIds) {
      if (state.visited.has(callerId)) continue;

      const caller = this.summaryGetter(callerId);
      if (!caller) continue;

      for (const edge of caller.callEdges) {
        if (edge.calleeCanonicalId !== callee.canonicalId) continue;
        if (!edge.returnMapping) continue;

        const returnTrace: TraceStep = {
          filePath: caller.filePath,
          functionName: caller.functionName,
          canonicalId: caller.canonicalId,
          line: edge.line,
          description: `Return value assigned to '${edge.returnMapping.assignedTo}'`,
          accessPath: edge.returnMapping.assignedTo,
          propagation: 'return',
        };

        const hops = [...state.crossFileHops];
        if (callee.filePath !== caller.filePath) {
          hops.push({
            fromFile: callee.filePath,
            toFile: caller.filePath,
            fromFunction: callee.functionName,
            toFunction: caller.functionName,
            paramIndex: -1, // return value, not a param
          });
        }

        const newVisited = new Set(state.visited);
        newVisited.add(callerId);

        const returnOutput: SummaryOutput = {
          kind: 'return',
          accessPath: edge.returnMapping.accessPath,
          label: edge.returnMapping.assignedTo,
        };

        const innerState: ForwardState = {
          sourceKind: state.sourceKind,
          sourceSummary: state.sourceSummary,
          trace: [...state.trace, returnTrace],
          crossFileHops: hops,
          sanitizations: [...state.sanitizations],
          isSanitized: state.isSanitized,
          confidence: state.confidence,
          visited: newVisited,
          depth: state.depth + 1,
        };

        // Check caller's sinks for the return value.
        this.collectLocalSinks(caller, returnOutput, innerState, opts, results);

        // Continue through caller's call edges.
        this.followCallEdgesForward(
          caller,
          returnOutput,
          innerState,
          opts,
          results,
        );
      }
    }
  }

  // =======================================================================
  // Private — backward walk
  // =======================================================================

  /**
   * Walk backward from a sinkHit, searching for taint sources that feed
   * the sink's input.  Builds trace bottom-up (reversed at result time).
   */
  private walkBackward(
    summary: FunctionSummary,
    sinkHit: SummarySinkHit,
    traceBelow: TraceStep[],
    crossFileHops: CrossFileHop[],
    sanitizations: SanitizationKind[],
    isSanitized: boolean,
    confidence: 'definite' | 'likely' | 'possible',
    visited: Set<string>,
    depth: number,
    opts: NormalisedOptions,
    results: TaintQueryResult[],
  ): void {
    if (depth > opts.maxDepth) return;
    if (visited.has(summary.canonicalId)) return;

    visited.add(summary.canonicalId);

    const sinkTrace: TraceStep = {
      filePath: summary.filePath,
      functionName: summary.functionName,
      canonicalId: summary.canonicalId,
      line: sinkHit.line,
      description:
        depth === 0
          ? sinkDescription(sinkHit)
          : `Passes ${inputAccessPath(sinkHit.input)} onward`,
      accessPath: inputAccessPath(sinkHit.input),
      propagation: depth === 0 ? 'sink' : 'assignment',
    };

    const currentTrace = [sinkTrace, ...traceBelow];

    // Case 1: The sink input comes from a taint source in THIS function.
    for (const src of summary.taintSources) {
      if (!this.outputReachesInput(src.output, sinkHit.input, summary)) {
        continue;
      }
      if (opts.sourceKindFilter && !opts.sourceKindFilter.includes(src.kind)) {
        continue;
      }

      const sourceTrace: TraceStep = {
        filePath: summary.filePath,
        functionName: summary.functionName,
        canonicalId: summary.canonicalId,
        line: 0,
        description: sourceDescription(src.kind),
        accessPath: outputAccessPath(src.output),
        propagation: 'source',
      };

      const fullTrace = [sourceTrace, ...currentTrace];
      const finalSanitized = isSanitized || sinkHit.sanitized;

      if (!opts.includeSanitized && finalSanitized) continue;

      const finalConf = this.combineConfidence(confidence, 'definite');
      if (!meetsMinConfidence(finalConf, opts.minConfidence)) continue;

      const files = new Set<string>();
      for (const step of fullTrace) files.add(step.filePath);

      results.push({
        sourceKind: src.kind,
        sourceFunction: summary.canonicalId,
        sourceFile: summary.filePath,
        sinkKind: sinkHit.sinkKind,
        sinkCallee: sinkHit.sinkCallee,
        sinkFunction: summary.canonicalId,
        sinkFile: summary.filePath,
        sinkLine: sinkHit.line,
        trace: fullTrace,
        crossFileHops,
        sanitizations,
        isSanitized: finalSanitized,
        confidence: finalConf,
        fileCount: files.size,
        hopCount: crossFileHops.length,
      });
    }

    // Case 2: The sink input is a parameter — walk backward through callers.
    if (
      sinkHit.input.kind === 'param' &&
      sinkHit.input.paramIndex !== undefined
    ) {
      this.walkBackwardThroughCallers(
        summary,
        sinkHit.input.paramIndex,
        sinkHit,
        currentTrace,
        crossFileHops,
        sanitizations,
        isSanitized,
        confidence,
        visited,
        depth,
        opts,
        results,
      );
    }

    visited.delete(summary.canonicalId);
  }

  /**
   * Find all functions that call `callee` and pass data to `paramIndex`,
   * then recurse backward into those callers.
   */
  private walkBackwardThroughCallers(
    callee: FunctionSummary,
    paramIndex: number,
    originalSinkHit: SummarySinkHit,
    traceBelow: TraceStep[],
    crossFileHops: CrossFileHop[],
    sanitizations: SanitizationKind[],
    isSanitized: boolean,
    confidence: 'definite' | 'likely' | 'possible',
    visited: Set<string>,
    depth: number,
    opts: NormalisedOptions,
    results: TaintQueryResult[],
  ): void {
    const allIds = this.allIdsGetter();

    for (const callerId of allIds) {
      if (visited.has(callerId)) continue;

      const caller = this.summaryGetter(callerId);
      if (!caller) continue;

      for (const edge of caller.callEdges) {
        if (edge.calleeCanonicalId !== callee.canonicalId) continue;

        for (const am of edge.argMapping) {
          if (am.calleeParamIndex !== paramIndex) continue;

          const callerInput = am.callerInput;

          const callTrace: TraceStep = {
            filePath: caller.filePath,
            functionName: caller.functionName,
            canonicalId: caller.canonicalId,
            line: edge.line,
            description: `Passes ${inputAccessPath(callerInput)} as argument ${paramIndex} to ${callee.functionName}()`,
            accessPath: inputAccessPath(callerInput),
            propagation: 'call-arg',
          };

          const hops = [...crossFileHops];
          if (caller.filePath !== callee.filePath) {
            hops.push({
              fromFile: caller.filePath,
              toFile: callee.filePath,
              fromFunction: caller.functionName,
              toFunction: callee.functionName,
              paramIndex,
            });
          }

          const currentTrace = [callTrace, ...traceBelow];

          // Check if the caller has a taint source that reaches callerInput.
          for (const src of caller.taintSources) {
            if (!this.outputReachesInput(src.output, callerInput, caller)) {
              continue;
            }
            if (
              opts.sourceKindFilter &&
              !opts.sourceKindFilter.includes(src.kind)
            ) {
              continue;
            }

            const sourceTrace: TraceStep = {
              filePath: caller.filePath,
              functionName: caller.functionName,
              canonicalId: caller.canonicalId,
              line: 0,
              description: sourceDescription(src.kind),
              accessPath: outputAccessPath(src.output),
              propagation: 'source',
            };

            const fullTrace = [sourceTrace, ...currentTrace];
            const finalSanitized = isSanitized || originalSinkHit.sanitized;

            if (!opts.includeSanitized && finalSanitized) continue;

            const finalConf = this.combineConfidence(confidence, 'definite');
            if (!meetsMinConfidence(finalConf, opts.minConfidence)) continue;

            const files = new Set<string>();
            for (const step of fullTrace) files.add(step.filePath);

            results.push({
              sourceKind: src.kind,
              sourceFunction: caller.canonicalId,
              sourceFile: caller.filePath,
              sinkKind: originalSinkHit.sinkKind,
              sinkCallee: originalSinkHit.sinkCallee,
              sinkFunction: callee.canonicalId,
              sinkFile: callee.filePath,
              sinkLine: originalSinkHit.line,
              trace: fullTrace,
              crossFileHops: hops,
              sanitizations: [
                ...sanitizations,
                ...originalSinkHit.sanitizations,
              ],
              isSanitized: finalSanitized,
              confidence: finalConf,
              fileCount: files.size,
              hopCount: hops.length,
            });
          }

          // If callerInput is also a param, recurse further up.
          if (
            callerInput.kind === 'param' &&
            callerInput.paramIndex !== undefined
          ) {
            const syntheticHit: SummarySinkHit = {
              input: callerInput,
              sinkKind: originalSinkHit.sinkKind,
              sinkCallee: originalSinkHit.sinkCallee,
              sanitized: originalSinkHit.sanitized,
              sanitizations: originalSinkHit.sanitizations,
              line: edge.line,
            };

            this.walkBackward(
              caller,
              syntheticHit,
              traceBelow,
              hops,
              [...sanitizations],
              isSanitized,
              confidence,
              visited,
              depth + 1,
              opts,
              results,
            );
          }
        }
      }
    }
  }

  // =======================================================================
  // Private — matching helpers
  // =======================================================================

  /**
   * Determine which callee params receive taint via a callEdge, given that
   * taint currently lives at `taintOutput` in the caller.
   */
  private taintedParamsViaEdge(
    edge: SummaryCallEdge,
    taintOutput: SummaryOutput,
    callerSummary: FunctionSummary,
  ): number[] {
    const params: number[] = [];
    for (const am of edge.argMapping) {
      if (this.outputReachesInput(taintOutput, am.callerInput, callerSummary)) {
        params.push(am.calleeParamIndex);
      }
    }
    return params;
  }

  /**
   * Heuristic check: can a SummaryOutput reach a SummaryInput within the
   * same function?
   *
   * Covers:
   *   - Label equality (same variable name)
   *   - Access-path prefix match ("req.body" reaches "req.body.name")
   *   - Transfer-chain connectivity
   */
  private outputReachesInput(
    output: SummaryOutput,
    input: SummaryInput,
    summary: FunctionSummary,
  ): boolean {
    // Direct label match.
    if (output.label && input.label && output.label === input.label) {
      return true;
    }

    // Access-path prefix match.
    if (output.accessPath && input.accessPath) {
      const outPath = output.accessPath.join('.');
      const inPath = input.accessPath.join('.');
      if (inPath.startsWith(outPath) || outPath.startsWith(inPath)) {
        return true;
      }
    }

    // Check via transfer edges in the same function.
    for (const transfer of summary.transfers) {
      if (
        transfer.to.label === output.label &&
        transfer.from.label === input.label
      ) {
        return true;
      }
      if (
        transfer.from.kind === input.kind &&
        transfer.from.paramIndex === input.paramIndex &&
        transfer.to.label === output.label
      ) {
        return true;
      }
    }

    return false;
  }

  // =======================================================================
  // Private — utility
  // =======================================================================

  /** Combine two confidence levels, degrading when a step is 'possible'. */
  private combineConfidence(
    current: 'definite' | 'likely' | 'possible',
    step: 'definite' | 'possible',
  ): 'definite' | 'likely' | 'possible' {
    if (step === 'possible' && current === 'definite') return 'likely';
    if (step === 'possible') return 'possible';
    return current;
  }

  /** Build a TaintQueryResult from forward-walk state. */
  private buildResult(
    state: ForwardState,
    sinkSummary: FunctionSummary,
    sinkHit: SummarySinkHit,
    trace: TraceStep[],
    crossFileHops: CrossFileHop[],
    sanitizations: SanitizationKind[],
    isSanitized: boolean,
    confidence: 'definite' | 'likely' | 'possible',
  ): TaintQueryResult {
    const files = new Set<string>();
    for (const step of trace) files.add(step.filePath);

    return {
      sourceKind: state.sourceKind,
      sourceFunction: state.sourceSummary.canonicalId,
      sourceFile: state.sourceSummary.filePath,
      sinkKind: sinkHit.sinkKind,
      sinkCallee: sinkHit.sinkCallee,
      sinkFunction: sinkSummary.canonicalId,
      sinkFile: sinkSummary.filePath,
      sinkLine: sinkHit.line,
      trace,
      crossFileHops,
      sanitizations: this.uniqueSanitizations(sanitizations),
      isSanitized,
      confidence,
      fileCount: files.size,
      hopCount: crossFileHops.length,
    };
  }

  /** Deduplicate sanitization kinds preserving order. */
  private uniqueSanitizations(list: SanitizationKind[]): SanitizationKind[] {
    const seen = new Set<SanitizationKind>();
    const out: SanitizationKind[] = [];
    for (const s of list) {
      if (!seen.has(s)) {
        seen.add(s);
        out.push(s);
      }
    }
    return out;
  }

  /** Normalise user-supplied options into an internal form with defaults. */
  private normalizeOptions(options?: QueryOptions): NormalisedOptions {
    return {
      maxDepth: options?.maxDepth ?? DEFAULT_MAX_DEPTH,
      includeSanitized: options?.includeSanitized ?? false,
      sinkKindFilter: options?.sinkKindFilter ?? null,
      sourceKindFilter: options?.sourceKindFilter ?? null,
      minConfidence: options?.minConfidence ?? 'possible',
    };
  }

  /** Apply post-hoc filters to a result set. */
  private applyFilters(
    results: TaintQueryResult[],
    opts: NormalisedOptions,
  ): TaintQueryResult[] {
    return results.filter((r) => {
      if (!opts.includeSanitized && r.isSanitized) return false;
      if (opts.sinkKindFilter && !opts.sinkKindFilter.includes(r.sinkKind)) {
        return false;
      }
      if (
        opts.sourceKindFilter &&
        !opts.sourceKindFilter.includes(r.sourceKind)
      ) {
        return false;
      }
      if (!meetsMinConfidence(r.confidence, opts.minConfidence)) return false;
      return true;
    });
  }
}

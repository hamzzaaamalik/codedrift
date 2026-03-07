/**
 * SummaryResolver — Multi-hop fixed-point resolution for cross-file taint analysis.
 *
 * After per-function summaries have been built (by the SummaryBuilder), each
 * summary may contain callEdges to other functions.  The resolver iteratively
 * "inlines" callee summaries into callers until a fixed point is reached,
 * propagating taint transfers and sink hits across call boundaries.
 *
 * Example: if A(x) calls B(x) and B's summary says param[0] -> sql-injection,
 * the resolver adds a transitive sink hit on A: param[0] -> sql-injection (via B).
 */

import type {
  FunctionSummary,
  SummaryInput,
  SummaryOutput,
  SummaryTransfer,
  SummarySinkHit,
  SummaryCallEdge,
} from './summary-types.js';
import type { SanitizationKind } from '../types.js';
import { SummaryStore } from './summary-store.js';

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

export interface ResolverStats {
  iterations: number;
  transfersAdded: number;
  sinkHitsAdded: number;
  functionsUpdated: number;
  cyclesDetected: number;
}

export interface CrossFileFlow {
  /** The function whose input is the original source of taint */
  sourceFunction: string;
  sourceInput: SummaryInput;
  /** The function containing the ultimate sink */
  sinkFunction: string;
  sinkHit: SummarySinkHit;
  /** Intermediate hops between source and sink */
  hops: CrossFileHop[];
  /** Whether the flow is sanitized at any point along the chain */
  sanitized: boolean;
}

export interface CrossFileHop {
  fromFunction: string;
  toFunction: string;
  inputToParam: {
    callerInput: SummaryInput;
    calleeParamIndex: number;
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

const MAX_ITERATIONS = 10;

/** Create a deterministic key for a SummaryTransfer so we can deduplicate. */
function transferKey(t: SummaryTransfer): string {
  return `${inputKey(t.from)}|${outputKey(t.to)}|${t.sanitizations.join(',')}|${t.isSanitized}|${t.confidence}`;
}

/** Create a deterministic key for a SummarySinkHit. */
function sinkHitKey(h: SummarySinkHit): string {
  return `${inputKey(h.input)}|${h.sinkKind}|${h.sinkCallee}|${h.sanitized}|${h.sanitizations.join(',')}|${h.line}`;
}

function inputKey(i: SummaryInput): string {
  return `${i.kind}:${i.paramIndex ?? ''}:${(i.accessPath ?? []).join('.')}`;
}

function outputKey(o: SummaryOutput): string {
  return `${o.kind}:${o.paramIndex ?? ''}:${o.callbackParamIndex ?? ''}:${o.callbackArgIndex ?? ''}:${(o.accessPath ?? []).join('.')}`;
}

/** Compose sanitization lists from caller and callee edges. */
function composeSanitizations(
  callerSanitizations: SanitizationKind[],
  calleeSanitizations: SanitizationKind[],
): SanitizationKind[] {
  const merged = new Set<SanitizationKind>([
    ...callerSanitizations,
    ...calleeSanitizations,
  ]);
  return Array.from(merged);
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

export class SummaryResolver {
  /** Reverse call-graph: calleeId -> set of callerIds */
  private callers = new Map<string, Set<string>>();

  constructor(private store: SummaryStore) {}

  // -----------------------------------------------------------------------
  // Fixed-point resolution
  // -----------------------------------------------------------------------

  resolve(): ResolverStats {
    const stats: ResolverStats = {
      iterations: 0,
      transfersAdded: 0,
      sinkHitsAdded: 0,
      functionsUpdated: 0,
      cyclesDetected: 0,
    };

    // Build reverse call-graph for worklist propagation.
    this.buildReverseCallGraph();

    // Worklist: set of canonicalIds whose summaries need (re-)processing.
    const worklist = new Set<string>();
    for (const id of this.store.getAllIds()) {
      const s = this.store.get(id);
      if (s && s.callEdges.length > 0) {
        worklist.add(id);
      }
    }

    // Track per-summary fingerprints to detect changes.
    const fingerprints = new Map<string, string>();
    const computeFingerprint = (s: FunctionSummary): string =>
      `${s.transfers.length}:${s.sinkHits.length}`;

    for (const id of this.store.getAllIds()) {
      const s = this.store.get(id)!;
      fingerprints.set(id, computeFingerprint(s));
    }

    // Iterative fixed-point loop.
    while (worklist.size > 0 && stats.iterations < MAX_ITERATIONS) {
      stats.iterations++;
      const batch = Array.from(worklist);
      worklist.clear();

      // Track which functions are currently being resolved in this round
      // to detect (and break) cycles.
      const inProgress = new Set<string>();

      for (const callerId of batch) {
        const result = this.resolveSummary(callerId, inProgress, stats);
        if (!result) continue;

        const summary = this.store.get(callerId)!;
        const newFp = computeFingerprint(summary);
        const oldFp = fingerprints.get(callerId);

        if (newFp !== oldFp) {
          fingerprints.set(callerId, newFp);
          stats.functionsUpdated++;

          // Summary changed — enqueue all callers so they can pick up
          // the new transfers / sink hits.
          const callerSet = this.callers.get(callerId);
          if (callerSet) {
            for (const c of callerSet) {
              worklist.add(c);
            }
          }
        }
      }
    }

    return stats;
  }

  // -----------------------------------------------------------------------
  // Cross-file flow extraction (post-resolution)
  // -----------------------------------------------------------------------

  getCrossFileFlows(): CrossFileFlow[] {
    const flows: CrossFileFlow[] = [];

    for (const id of this.store.getAllIds()) {
      const summary = this.store.get(id)!;
      if (summary.sinkHits.length === 0) continue;

      // For each sink hit, trace backward through callEdges to find
      // the entry-point function in a different file.
      for (const hit of summary.sinkHits) {
        const chains = this.traceBackward(id, hit.input, new Set<string>());
        for (const chain of chains) {
          if (chain.hops.length === 0) continue; // same-function hit, not cross-file
          const sourceFunc = chain.hops[0].fromFunction;
          const sourceSummary = this.store.get(sourceFunc);
          const sinkSummary = this.store.get(id);
          if (!sourceSummary || !sinkSummary) continue;

          // Only report truly cross-file flows.
          if (sourceSummary.filePath === sinkSummary.filePath &&
              chain.hops.every(h => {
                const from = this.store.get(h.fromFunction);
                const to = this.store.get(h.toFunction);
                return from && to && from.filePath === sinkSummary!.filePath;
              })) {
            continue;
          }

          flows.push({
            sourceFunction: sourceFunc,
            sourceInput: chain.sourceInput,
            sinkFunction: id,
            sinkHit: hit,
            hops: chain.hops,
            sanitized: hit.sanitized || chain.sanitized,
          });
        }
      }
    }

    return flows;
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  /**
   * Build the reverse call-graph so we know, for any callee, which callers
   * should be re-enqueued when the callee's summary changes.
   */
  private buildReverseCallGraph(): void {
    this.callers.clear();
    for (const id of this.store.getAllIds()) {
      const s = this.store.get(id)!;
      for (const edge of s.callEdges) {
        let set = this.callers.get(edge.calleeCanonicalId);
        if (!set) {
          set = new Set<string>();
          this.callers.set(edge.calleeCanonicalId, set);
        }
        set.add(id);
      }
    }
  }

  /**
   * Process a single summary: for every callEdge, compose callee transfers
   * and sink hits into the caller's summary.
   *
   * Returns true if any modifications were made.
   */
  private resolveSummary(
    callerId: string,
    inProgress: Set<string>,
    stats: ResolverStats,
  ): boolean {
    const summary = this.store.get(callerId);
    if (!summary) return false;

    // Cycle guard.
    if (inProgress.has(callerId)) {
      stats.cyclesDetected++;
      return false;
    }
    inProgress.add(callerId);

    // Build sets of existing transfer / sink-hit keys for dedup.
    const existingTransfers = new Set<string>(summary.transfers.map(transferKey));
    const existingSinkHits = new Set<string>(summary.sinkHits.map(sinkHitKey));

    let changed = false;

    for (const edge of summary.callEdges) {
      const calleeSummary = this.store.get(edge.calleeCanonicalId);
      if (!calleeSummary) continue; // external / unknown function

      // Self-recursion guard.
      if (edge.calleeCanonicalId === callerId) {
        stats.cyclesDetected++;
        continue;
      }

      for (const mapping of edge.argMapping) {
        const callerInput = mapping.callerInput;
        const calleeParamIndex = mapping.calleeParamIndex;

        // ---- Compose transfers ----
        for (const transfer of calleeSummary.transfers) {
          if (
            transfer.from.kind !== 'param' ||
            transfer.from.paramIndex !== calleeParamIndex
          ) {
            continue;
          }

          const newTransfer = this.composeTransfer(
            callerInput,
            transfer,
            edge,
          );
          if (!newTransfer) continue;

          const key = transferKey(newTransfer);
          if (!existingTransfers.has(key)) {
            existingTransfers.add(key);
            summary.transfers.push(newTransfer);
            stats.transfersAdded++;
            changed = true;
          }
        }

        // ---- Compose sink hits ----
        for (const hit of calleeSummary.sinkHits) {
          if (
            hit.input.kind !== 'param' ||
            hit.input.paramIndex !== calleeParamIndex
          ) {
            continue;
          }

          const newHit = this.composeTransitiveSinkHit(
            callerInput,
            hit,
            edge,
          );
          const key = sinkHitKey(newHit);
          if (!existingSinkHits.has(key)) {
            existingSinkHits.add(key);
            summary.sinkHits.push(newHit);
            stats.sinkHitsAdded++;
            changed = true;
          }
        }
      }
    }

    inProgress.delete(callerId);
    return changed;
  }

  /**
   * Build a composed SummaryTransfer from a caller's input through a callee's
   * transfer edge.  Returns null if the callee transfer output is 'return'
   * but the call edge has no returnMapping (the return value is unused).
   */
  private composeTransfer(
    callerInput: SummaryInput,
    calleeTransfer: SummaryTransfer,
    edge: SummaryCallEdge,
  ): SummaryTransfer | null {
    let composedOutput: SummaryOutput;

    switch (calleeTransfer.to.kind) {
      case 'return': {
        if (!edge.returnMapping) return null; // Return value is unused.
        composedOutput = {
          kind: 'return',
          accessPath: edge.returnMapping.accessPath,
          label: `return via ${edge.calleeCanonicalId}`,
        };
        break;
      }
      case 'param-mutation': {
        // The callee mutates one of its own params.  Map back to caller scope.
        // Find which caller input corresponds to the mutated callee param.
        const mutatedMapping = edge.argMapping.find(
          m => m.calleeParamIndex === calleeTransfer.to.paramIndex,
        );
        if (!mutatedMapping) return null;
        composedOutput = {
          kind: 'param-mutation',
          paramIndex: mutatedMapping.callerInput.paramIndex,
          accessPath: calleeTransfer.to.accessPath,
          label: `mutation via ${edge.calleeCanonicalId}`,
        };
        break;
      }
      case 'callback-arg': {
        composedOutput = { ...calleeTransfer.to };
        break;
      }
      case 'promise-resolve': {
        if (!edge.returnMapping) return null;
        composedOutput = {
          kind: 'promise-resolve',
          accessPath: edge.returnMapping.accessPath,
          label: `promise via ${edge.calleeCanonicalId}`,
        };
        break;
      }
      default: {
        // this-mutation, global-mutation — pass through as-is.
        composedOutput = { ...calleeTransfer.to };
        break;
      }
    }

    const sanitizations = composeSanitizations([], calleeTransfer.sanitizations);
    const isSanitized = calleeTransfer.isSanitized;
    const confidence: 'definite' | 'possible' =
      calleeTransfer.confidence === 'possible' ? 'possible' : 'definite';

    return {
      from: { ...callerInput },
      to: composedOutput,
      sanitizations,
      isSanitized,
      confidence,
    };
  }

  /**
   * Create a transitive SummarySinkHit on the caller based on a callee's
   * sink hit and the arg mapping.
   */
  private composeTransitiveSinkHit(
    callerInput: SummaryInput,
    calleeSinkHit: SummarySinkHit,
    _edge: SummaryCallEdge,
  ): SummarySinkHit {
    const sanitizations = composeSanitizations([], calleeSinkHit.sanitizations);
    return {
      input: { ...callerInput },
      sinkKind: calleeSinkHit.sinkKind,
      sinkCallee: calleeSinkHit.sinkCallee,
      sanitized: calleeSinkHit.sanitized,
      sanitizations,
      line: calleeSinkHit.line,
    };
  }

  // -----------------------------------------------------------------------
  // Backward tracing for cross-file flow extraction
  // -----------------------------------------------------------------------

  /**
   * Trace backward from a function + input to find caller chains that
   * originate in a different file.  Returns an array of chains (there can
   * be multiple callers for the same callee).
   */
  private traceBackward(
    functionId: string,
    input: SummaryInput,
    visited: Set<string>,
  ): { sourceInput: SummaryInput; hops: CrossFileHop[]; sanitized: boolean }[] {
    if (visited.has(functionId)) return [];
    visited.add(functionId);

    const callerIds = this.callers.get(functionId);
    if (!callerIds || callerIds.size === 0) {
      // This is an entry point (no callers). The input itself is the source.
      return [{ sourceInput: input, hops: [], sanitized: false }];
    }

    const results: { sourceInput: SummaryInput; hops: CrossFileHop[]; sanitized: boolean }[] = [];

    for (const callerId of callerIds) {
      const callerSummary = this.store.get(callerId);
      if (!callerSummary) continue;

      for (const edge of callerSummary.callEdges) {
        if (edge.calleeCanonicalId !== functionId) continue;

        // Find which caller input maps to our function's input param.
        if (input.kind !== 'param') continue;

        for (const mapping of edge.argMapping) {
          if (mapping.calleeParamIndex !== input.paramIndex) continue;

          const hop: CrossFileHop = {
            fromFunction: callerId,
            toFunction: functionId,
            inputToParam: {
              callerInput: mapping.callerInput,
              calleeParamIndex: mapping.calleeParamIndex,
            },
          };

          // Recurse into the caller.
          const upstreamChains = this.traceBackward(
            callerId,
            mapping.callerInput,
            visited,
          );

          if (upstreamChains.length === 0) {
            // Caller is an entry point.
            results.push({
              sourceInput: mapping.callerInput,
              hops: [hop],
              sanitized: false,
            });
          } else {
            for (const chain of upstreamChains) {
              results.push({
                sourceInput: chain.sourceInput,
                hops: [...chain.hops, hop],
                sanitized: chain.sanitized,
              });
            }
          }
        }
      }
    }

    visited.delete(functionId);
    return results;
  }
}

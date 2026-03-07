/**
 * Function Summary Types — Data structures for inter-procedural taint analysis.
 *
 * A FunctionSummary captures how taint flows through a function without
 * needing to re-analyze the body: which parameters propagate to the return
 * value, which reach sinks, and which calls fan out to other functions.
 */

import type { TaintSourceKind, TaintSinkKind, SanitizationKind } from '../types.js';

/** Identifies a specific taint input to a function */
export interface SummaryInput {
  kind: 'param' | 'this' | 'global' | 'closure';
  /** For 'param': parameter index (0-based) */
  paramIndex?: number;
  /** Field path within the input, e.g. ['body', 'name'] for param.body.name */
  accessPath?: string[];
  /** Human-readable label */
  label: string;
}

/** Identifies a specific taint output from a function */
export interface SummaryOutput {
  kind: 'return' | 'param-mutation' | 'this-mutation' | 'global-mutation' | 'callback-arg' | 'promise-resolve';
  /** For param-mutation: which param index is mutated */
  paramIndex?: number;
  /** For callback-arg: the param index of the callback, and which arg of the callback */
  callbackParamIndex?: number;
  callbackArgIndex?: number;
  /** Field path of the output */
  accessPath?: string[];
  label: string;
}

/** A single taint transfer edge in the summary */
export interface SummaryTransfer {
  from: SummaryInput;
  to: SummaryOutput;
  /** Sanitizations applied along this transfer path */
  sanitizations: SanitizationKind[];
  /** Is the taint fully sanitized by the time it reaches 'to'? */
  isSanitized: boolean;
  /** Confidence: 'definite' = all code paths, 'possible' = some paths only */
  confidence: 'definite' | 'possible';
}

/** A sink reached within the function body */
export interface SummarySinkHit {
  /** Which input flows to this sink */
  input: SummaryInput;
  /** Kind of sink */
  sinkKind: TaintSinkKind;
  /** The callee/API that constitutes the sink */
  sinkCallee: string;
  /** Was taint sanitized before reaching this sink? */
  sanitized: boolean;
  /** Sanitizations applied before the sink */
  sanitizations: SanitizationKind[];
  /** Line number for reporting */
  line: number;
}

/** A call to another function within the body (for multi-hop resolution) */
export interface SummaryCallEdge {
  /** Canonical ID of the callee (e.g., "src/db.ts#query") */
  calleeCanonicalId: string;
  /** How caller's inputs map to callee's parameters */
  argMapping: {
    callerInput: SummaryInput;
    calleeParamIndex: number;
  }[];
  /** Where the callee's return value goes */
  returnMapping?: {
    assignedTo: string;       // Variable name assigned to
    accessPath?: string[];    // Field path if applicable
  };
  /** Line number of the call */
  line: number;
}

/** Complete taint summary for one function */
export interface FunctionSummary {
  /** Canonical ID: "filePath#functionName" */
  canonicalId: string;
  filePath: string;
  functionName: string;
  paramCount: number;
  paramNames: string[];
  isAsync: boolean;
  isExported: boolean;
  isConstructor: boolean;
  containingClass?: string;

  /** Taint transfer edges: input -> output */
  transfers: SummaryTransfer[];

  /** Sinks hit within the function body */
  sinkHits: SummarySinkHit[];

  /** Calls to other functions */
  callEdges: SummaryCallEdge[];

  /** Does this function introduce new taint sources? */
  taintSources: { kind: TaintSourceKind; output: SummaryOutput }[];

  /** Is this function itself a sanitizer? */
  isSanitizer: boolean;
  sanitizerKind?: SanitizationKind;

  /** Content hash of function body for incremental invalidation */
  bodyHash: string;

  /** Was this summary computed or just a stub? */
  isComplete: boolean;
}

/** Summary store statistics */
export interface SummaryStoreStats {
  totalSummaries: number;
  completeSummaries: number;
  filesProcessed: number;
  transferEdges: number;
  sinkHits: number;
}

/**
 * Taint Analysis — Public API
 *
 * Re-exports the orchestrator and all type definitions used by
 * engine authors and the core analyzer.
 */

// Intra-procedural (existing)
export { TaintAnalyzer } from './taint-analyzer.js';

// Cross-file (new)
export { ProjectGraph } from './graph/project-graph.js';
export { ModuleResolver } from './graph/module-resolver.js';
export { FileIndex } from './graph/file-index.js';
export { SymbolTable } from './graph/symbol-table.js';
export { CFGBuilder } from './cfg/cfg-builder.js';
export { AccessPath } from './heap/access-path.js';
export { HeapModel } from './heap/heap-model.js';
export { SummaryBuilder } from './summaries/summary-builder.js';
export { SummaryStore } from './summaries/summary-store.js';
export { SummaryResolver } from './summaries/summary-resolver.js';
export { TaintQueryEngine } from './query/taint-query.js';
export { TaintSpecParser } from './specs/spec-parser.js';
export { FrameworkDetector } from './frameworks/framework-detector.js';
export { IncrementalEngine } from './incremental/incremental-engine.js';
export { FlowRenderer } from './reporting/flow-renderer.js';
export { SarifEmitter } from './reporting/sarif-emitter.js';

// Data flow analysis (CFG-driven, path-sensitive, field-sensitive)
export { DataFlowSolver } from './dataflow/dataflow-solver.js';
export { AbstractState } from './dataflow/abstract-state.js';
export { TransferFunctions } from './dataflow/transfer-functions.js';
export { PathSensitivityAnalyzer } from './dataflow/path-sensitivity.js';
export { DefUseAnalyzer } from './dataflow/def-use.js';

// Types
export type {
  TaintAnalysisResult,
  TaintFlow,
  TaintSource,
  TaintSink,
  TaintStep,
  SanitizationPoint,
  VariableTaintState,
  TaintId,
  TaintSourceKind,
  TaintSinkKind,
  PropagationKind,
  SanitizationKind,
} from './types.js';

export type {
  FunctionSummary,
  SummaryTransfer,
  SummarySinkHit,
  SummaryCallEdge,
  SummaryInput,
  SummaryOutput,
} from './summaries/summary-types.js';

export type {
  TaintQueryResult,
  TraceStep,
  CrossFileHop,
  QueryOptions,
} from './query/taint-query.js';

export type { CFG, BasicBlock, CFGEdge, DominatorInfo } from './cfg/cfg-types.js';
export type { TaintSpec, TaintRule } from './specs/spec-types.js';
export type { FrameworkModel, RouteRegistration } from './frameworks/framework-model.js';
export type { CrossFileFlow, CrossFileHop as ResolverCrossFileHop } from './summaries/summary-resolver.js';

export type { TaintFact, TaintValue } from './dataflow/lattice.js';
export type { DataFlowResult, SolverConfig } from './dataflow/dataflow-solver.js';
export type { TransferEffect } from './dataflow/transfer-functions.js';
export type { BranchRefinement, RefinementAction, ValidationPattern } from './dataflow/path-sensitivity.js';
export type { DefSite, UseSite, DefUseChain } from './dataflow/def-use.js';

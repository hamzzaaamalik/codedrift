/**
 * Data Flow Analysis Module — Public API
 *
 * Re-exports all types, classes, and utilities from the dataflow
 * sub-modules for convenient consumption by the rest of CodeDrift.
 */

// Lattice types and operations
export {
  TaintValue,
  TaintFact,
  joinFacts,
  meetFacts,
  createTaintedFact,
  createUntaintedFact,
  createBottomFact,
  isTainted,
  BOTTOM_FACT,
  UNTAINTED_FACT,
} from './lattice.js';

// Abstract state
export { AbstractState } from './abstract-state.js';

// Transfer functions
export { TransferFunctions, TransferEffect } from './transfer-functions.js';

// Path sensitivity
export {
  PathSensitivityAnalyzer,
  BranchRefinement,
  RefinementAction,
  ValidationPattern,
} from './path-sensitivity.js';

// Def-use chains
export { DefUseAnalyzer, DefSite, UseSite, DefUseChain } from './def-use.js';

// Data flow solver (main entry point)
export { DataFlowSolver, DataFlowResult, SolverConfig } from './dataflow-solver.js';

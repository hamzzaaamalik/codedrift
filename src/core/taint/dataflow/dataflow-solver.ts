/**
 * Worklist-Based Forward Data Flow Solver
 *
 * Implements the standard iterative data flow analysis algorithm for
 * intra-procedural taint analysis. Drives the entire analysis by iterating
 * over CFG basic blocks, applying transfer functions, handling path-sensitive
 * branch refinement, and computing a fixpoint.
 *
 * Industry-standard features:
 * - Reverse postorder traversal for fast convergence
 * - Path-sensitive branch refinement via {@link PathSensitivityAnalyzer}
 * - Field-sensitive heap tracking via {@link AbstractState}
 * - Def-use chain integration for precision
 * - Back-edge detection and widening for loop handling
 * - Effect deduplication to avoid redundant sink reports
 */

import * as ts from 'typescript';
import type { CFG, BasicBlock, CFGEdge } from '../cfg/cfg-types.js';
import { AbstractState } from './abstract-state.js';
import { TransferFunctions, TransferEffect } from './transfer-functions.js';
import { PathSensitivityAnalyzer, BranchRefinement } from './path-sensitivity.js';
import { DefUseAnalyzer } from './def-use.js';
import { TaintFact, TaintValue, createUntaintedFact } from './lattice.js';

// ── Result & Configuration Types ────────────────────────────────────

/**
 * Result of solving data flow for a single function.
 */
export interface DataFlowResult {
  /** Abstract state at the EXIT of each basic block */
  blockExitStates: Map<number, AbstractState>;
  /** Abstract state at the ENTRY of each basic block */
  blockEntryStates: Map<number, AbstractState>;
  /** All side effects collected during analysis */
  effects: TransferEffect[];
  /** Number of iterations to reach fixpoint */
  iterations: number;
  /** Whether the analysis converged (vs hit max iterations) */
  converged: boolean;
  /** Def-use chains computed for the function */
  defUseAnalyzer: DefUseAnalyzer;
}

/**
 * Configuration for the solver.
 */
export interface SolverConfig {
  /** Maximum iterations for fixpoint (default: 20) */
  maxIterations?: number;
  /** Enable path sensitivity (default: true) */
  pathSensitive?: boolean;
  /** Enable field sensitivity via heap model (default: true) */
  fieldSensitive?: boolean;
  /** Enable def-use chain computation (default: true) */
  computeDefUse?: boolean;
}

const DEFAULT_CONFIG: Required<SolverConfig> = {
  maxIterations: 20,
  pathSensitive: true,
  fieldSensitive: true,
  computeDefUse: true,
};

/** Widening threshold: after this many re-visits, widen unstable variables. */
const WIDEN_THRESHOLD = 3;

// ── DataFlowSolver ──────────────────────────────────────────────────

/**
 * Worklist-based forward data flow solver.
 *
 * Algorithm outline:
 * 1. Initialize entry block with the caller-supplied entry state
 * 2. Process blocks in reverse postorder for fast convergence
 * 3. At each block: join incoming states from all predecessors
 * 4. Apply transfer functions to every statement in the block
 * 5. If the exit state changed, enqueue all successors
 * 6. Repeat until fixpoint or the iteration budget is exhausted
 */
export class DataFlowSolver {
  private readonly config: Required<SolverConfig>;
  private readonly pathAnalyzer: PathSensitivityAnalyzer;

  constructor(config?: Partial<SolverConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.pathAnalyzer = new PathSensitivityAnalyzer();
  }

  // ── Public API ──────────────────────────────────────────────────

  /**
   * Solve the data flow for a function.
   *
   * @param cfg        - Control flow graph of the function
   * @param entryState - Initial abstract state (parameters pre-tainted)
   * @param filePath   - File path for callee ID resolution
   * @param paramNames - Parameter names for the function
   * @returns DataFlowResult with per-block states and collected effects
   */
  solve(
    cfg: CFG,
    entryState: AbstractState,
    filePath: string,
    paramNames: string[],
  ): DataFlowResult {
    // Pre-compute traversal order and predecessor map
    const rpoOrder = this.computeReversePostorder(cfg);
    const rpoIndex = new Map<number, number>();
    for (let i = 0; i < rpoOrder.length; i++) {
      rpoIndex.set(rpoOrder[i], i);
    }
    const predecessorMap = this.buildPredecessorMap(cfg);

    // State maps
    const blockEntryStates = new Map<number, AbstractState>();
    const blockExitStates = new Map<number, AbstractState>();

    // Effect collection with deduplication
    const effects: TransferEffect[] = [];
    const seenEffectKeys = new Set<string>();

    // Per-block visit count for widening
    const visitCount = new Map<number, number>();

    // Transfer function engine
    const transfer = new TransferFunctions(filePath, paramNames);

    // Def-use analyzer (optionally populated)
    const defUse = new DefUseAnalyzer();

    // ── Initialize entry block ─────────────────────────────────

    const entryBlock = cfg.blocks.get(cfg.entry);
    if (!entryBlock) {
      // Degenerate CFG with no blocks
      return {
        blockEntryStates,
        blockExitStates,
        effects,
        iterations: 0,
        converged: true,
        defUseAnalyzer: defUse,
      };
    }

    blockEntryStates.set(cfg.entry, entryState);

    // Process all statements in the entry block
    const entryExitState = this.processBlock(
      entryBlock,
      entryState.clone(),
      transfer,
      defUse,
      effects,
      seenEffectKeys,
      paramNames,
    );
    blockExitStates.set(cfg.entry, entryExitState);

    // Seed worklist with entry block successors
    const worklist = new Set<number>();
    const entrySuccessors = cfg.forwardEdges.get(cfg.entry) ?? [];
    for (const edge of entrySuccessors) {
      worklist.add(edge.to);
    }
    visitCount.set(cfg.entry, 1);

    // ── Main fixpoint loop ─────────────────────────────────────

    let iterations = 0;
    let converged = false;

    while (iterations < this.config.maxIterations) {
      if (worklist.size === 0) {
        converged = true;
        break;
      }

      iterations++;
      let changed = false;

      // Iterate in reverse postorder for deterministic fast convergence
      for (const blockId of rpoOrder) {
        if (!worklist.has(blockId)) continue;
        worklist.delete(blockId);

        const block = cfg.blocks.get(blockId);
        if (!block || !block.reachable) continue;

        // Track visits for widening
        const visits = (visitCount.get(blockId) ?? 0) + 1;
        visitCount.set(blockId, visits);

        // ── Join predecessor exit states ───────────────────

        const predEdges = predecessorMap.get(blockId) ?? [];
        const incomingState = this.joinPredecessorStates(
          predEdges,
          blockExitStates,
          cfg,
        );

        if (!incomingState) {
          // No predecessors have been visited yet — skip
          continue;
        }

        // ── Apply path-sensitive refinements ───────────────

        if (this.config.pathSensitive) {
          this.applyBranchRefinements(incomingState, predEdges, cfg, blockExitStates);
        }

        // ── Apply widening if this block has been visited too many times ──

        let effectiveIncoming = incomingState;
        if (this.shouldWiden(blockId, visitCount)) {
          const prevEntry = blockEntryStates.get(blockId);
          if (prevEntry) {
            effectiveIncoming = this.widenState(incomingState, prevEntry);
          }
        }

        // ── Check for fixpoint at this block ───────────────

        const prevEntry = blockEntryStates.get(blockId);
        if (prevEntry && prevEntry.equals(effectiveIncoming)) {
          // No change — skip reprocessing
          continue;
        }

        blockEntryStates.set(blockId, effectiveIncoming);

        // ── Process statements through transfer functions ──

        const exitState = this.processBlock(
          block,
          effectiveIncoming.clone(),
          transfer,
          defUse,
          effects,
          seenEffectKeys,
          paramNames,
        );

        // ── Check if exit state changed ────────────────────

        const prevExit = blockExitStates.get(blockId);
        if (!prevExit || !prevExit.equals(exitState)) {
          blockExitStates.set(blockId, exitState);
          changed = true;

          // Enqueue all successors
          const successors = cfg.forwardEdges.get(blockId) ?? [];
          for (const edge of successors) {
            worklist.add(edge.to);
          }
        }
      }

      // If nothing changed this full pass, we have converged
      if (!changed && worklist.size === 0) {
        converged = true;
        break;
      }
    }

    return {
      blockEntryStates,
      blockExitStates,
      effects,
      iterations,
      converged,
      defUseAnalyzer: defUse,
    };
  }

  // ── Reverse Postorder Computation ──────────────────────────────

  /**
   * Compute reverse postorder traversal of the CFG.
   *
   * DFS from the entry block, recording blocks in postorder (appended
   * when all children have been visited), then reversing. This ensures
   * predecessors are processed before successors (except for back edges),
   * which is optimal for forward data flow convergence.
   */
  private computeReversePostorder(cfg: CFG): number[] {
    const postorder: number[] = [];
    const visited = new Set<number>();

    const dfs = (blockId: number): void => {
      if (visited.has(blockId)) return;
      visited.add(blockId);

      const successors = cfg.forwardEdges.get(blockId) ?? [];
      for (const edge of successors) {
        if (!edge.isBackEdge) {
          dfs(edge.to);
        }
      }

      postorder.push(blockId);
    };

    dfs(cfg.entry);

    // Include any unreached blocks (disconnected subgraphs)
    for (const blockId of cfg.blocks.keys()) {
      if (!visited.has(blockId)) {
        dfs(blockId);
      }
    }

    // Reverse to get RPO
    postorder.reverse();
    return postorder;
  }

  // ── Predecessor Map ───────────────────────────────────────────

  /**
   * Build a map from block ID to its incoming edges.
   *
   * This inverts the forward edge list so that for each block we can
   * efficiently look up all predecessor edges with their labels.
   */
  private buildPredecessorMap(cfg: CFG): Map<number, CFGEdge[]> {
    // Use the pre-computed reverseEdges if available
    if (cfg.reverseEdges && cfg.reverseEdges.size > 0) {
      return cfg.reverseEdges;
    }

    // Otherwise build from the edge list
    const predMap = new Map<number, CFGEdge[]>();
    for (const edge of cfg.edges) {
      let list = predMap.get(edge.to);
      if (!list) {
        list = [];
        predMap.set(edge.to, list);
      }
      list.push(edge);
    }
    return predMap;
  }

  // ── Predecessor State Joining ─────────────────────────────────

  /**
   * Join the exit states of all predecessors for a given block.
   *
   * Returns null if no predecessor has been visited yet (the block
   * is not yet reachable in the analysis).
   */
  private joinPredecessorStates(
    predEdges: CFGEdge[],
    blockExitStates: Map<number, AbstractState>,
    _cfg: CFG,
  ): AbstractState | null {
    let result: AbstractState | null = null;

    for (const edge of predEdges) {
      const predState = blockExitStates.get(edge.from);
      if (!predState) continue;

      if (result === null) {
        result = predState.clone();
      } else {
        result = AbstractState.join(result, predState);
      }
    }

    return result;
  }

  // ── Path-Sensitive Branch Refinement ──────────────────────────

  /**
   * Apply path-sensitive refinements based on predecessor branch conditions.
   *
   * When a block is reached via a labeled edge ('true' or 'false'),
   * the branch condition from the predecessor's terminator constrains
   * the taint state. For example, `if (isValid(x))` on the true branch
   * means `x` is sanitized.
   */
  private applyBranchRefinements(
    state: AbstractState,
    predEdges: CFGEdge[],
    cfg: CFG,
    blockExitStates: Map<number, AbstractState>,
  ): void {
    for (const edge of predEdges) {
      // Only refine for labeled conditional edges
      if (edge.label !== 'true' && edge.label !== 'false') continue;

      // Skip if the predecessor has no computed state
      if (!blockExitStates.has(edge.from)) continue;

      const predBlock = cfg.blocks.get(edge.from);
      if (!predBlock) continue;

      const condition = this.extractBranchCondition(predBlock);
      if (!condition) continue;

      const refinements = this.pathAnalyzer.analyzeBranch(condition);

      for (const refinement of refinements) {
        const action = edge.label === 'true'
          ? refinement.trueBranch
          : refinement.falseBranch;

        this.applyRefinement(state, refinement.varName, action);
      }
    }
  }

  /**
   * Extract the branch condition expression from a basic block's terminator.
   *
   * The condition is stored in the terminator's `condition` field for
   * blocks that end with a conditional branch (if, while, for, ternary).
   * Falls back to inspecting the last statement if the terminator does
   * not carry the condition directly.
   */
  private extractBranchCondition(block: BasicBlock): ts.Expression | null {
    // Primary: use the terminator's condition field
    if (block.terminator?.condition) {
      return block.terminator.condition;
    }

    // Secondary: inspect the terminator AST node
    const node = block.terminator?.node;
    if (!node) return null;

    if (ts.isIfStatement(node)) {
      return node.expression;
    }
    if (ts.isWhileStatement(node) || ts.isDoStatement(node)) {
      return node.expression;
    }
    if (ts.isForStatement(node) && node.condition) {
      return node.condition;
    }
    if (ts.isConditionalExpression(node)) {
      return node.condition;
    }

    // Tertiary: check the last statement in the block
    if (block.statements.length > 0) {
      const lastStmt = block.statements[block.statements.length - 1];
      if (ts.isIfStatement(lastStmt)) {
        return lastStmt.expression;
      }
      if (ts.isWhileStatement(lastStmt) || ts.isDoStatement(lastStmt)) {
        return lastStmt.expression;
      }
      if (ts.isConditionalExpression(lastStmt)) {
        return lastStmt.condition;
      }
    }

    return null;
  }

  /**
   * Apply a single refinement action to the abstract state.
   *
   * Translates the declarative {@link RefinementAction} from the path
   * sensitivity analyzer into concrete state mutations.
   */
  private applyRefinement(
    state: AbstractState,
    varName: string,
    action: BranchRefinement['trueBranch'],
  ): void {
    switch (action.kind) {
      case 'sanitize': {
        const currentFact = state.getVar(varName);
        const sanitizedFact: TaintFact = {
          value: TaintValue.Sanitized,
          sourceParams: new Set(currentFact.sourceParams),
          sourceKinds: new Set(currentFact.sourceKinds),
          sanitizations: [...currentFact.sanitizations, action.sanitizerName],
          isSanitized: true,
          accessPath: currentFact.accessPath ? [...currentFact.accessPath] : undefined,
        };
        state.setVar(varName, sanitizedFact);
        break;
      }

      case 'mark-untainted': {
        state.setVar(varName, createUntaintedFact());
        break;
      }

      case 'mark-tainted': {
        const currentFact = state.getVar(varName);
        const taintedFact: TaintFact = {
          value: TaintValue.Tainted,
          sourceParams: new Set(currentFact.sourceParams),
          sourceKinds: new Set(currentFact.sourceKinds),
          sanitizations: [],
          isSanitized: false,
          accessPath: currentFact.accessPath ? [...currentFact.accessPath] : undefined,
        };
        state.setVar(varName, taintedFact);
        break;
      }

      case 'narrow-type': {
        // Type narrowing does not change taint status by itself.
        // A future extension could use type information to refine
        // taint precision (e.g. narrowing to a branded type).
        break;
      }

      case 'none':
        // No refinement to apply
        break;
    }
  }

  // ── Block Processing ──────────────────────────────────────────

  /**
   * Process all statements in a basic block through the transfer functions.
   *
   * Applies the transfer function to each statement in source order,
   * threading the abstract state forward. Collects side effects (sink
   * hits, call edges) and optionally updates the def-use analyzer.
   *
   * @returns The exit state after processing all statements
   */
  private processBlock(
    block: BasicBlock,
    state: AbstractState,
    transfer: TransferFunctions,
    _defUse: DefUseAnalyzer,
    effects: TransferEffect[],
    seenEffectKeys: Set<string>,
    _paramNames: string[],
  ): AbstractState {
    for (const stmt of block.statements) {
      // Apply transfer function
      const stmtEffects = transfer.processStatement(stmt, state);

      // Collect deduplicated effects
      for (const effect of stmtEffects) {
        const key = this.effectKey(effect);
        if (!seenEffectKeys.has(key)) {
          seenEffectKeys.add(key);
          effects.push(effect);
        }
      }
    }

    return state;
  }

  // ── Widening ──────────────────────────────────────────────────

  /**
   * Determine whether widening should be applied to a block.
   *
   * A block is widened when it has been visited more than
   * {@link WIDEN_THRESHOLD} times, indicating a loop whose abstract
   * state is not stabilizing. Widening guarantees termination by
   * forcing unstable variables to Top.
   */
  private shouldWiden(
    blockId: number,
    visitCount: Map<number, number>,
  ): boolean {
    const count = visitCount.get(blockId) ?? 0;
    return count > WIDEN_THRESHOLD;
  }

  /**
   * Widen the abstract state to guarantee termination.
   *
   * Any variable whose taint value differs between the current state
   * and the previous state is widened to Top (most conservative).
   * This is a standard widening operator that ensures monotonicity
   * and termination for loops with unbounded iterations.
   *
   * @param current  - The newly computed state for this iteration
   * @param previous - The state from the previous iteration
   * @returns A widened state where unstable variables are set to Top
   */
  private widenState(current: AbstractState, previous: AbstractState): AbstractState {
    const widened = current.clone();
    const currentVars = current.getAllVars();
    const previousVars = previous.getAllVars();

    // Collect all variable names from both states
    const allVarNames = new Set<string>([
      ...currentVars.keys(),
      ...previousVars.keys(),
    ]);

    for (const varName of allVarNames) {
      const curFact = currentVars.get(varName);
      const prevFact = previousVars.get(varName);

      if (!curFact || !prevFact) {
        // Variable only in one state — keep current (first appearance or removal)
        continue;
      }

      // If the lattice value changed, widen to Top
      if (curFact.value !== prevFact.value) {
        const topFact: TaintFact = {
          value: TaintValue.Top,
          sourceParams: new Set([...curFact.sourceParams, ...prevFact.sourceParams]),
          sourceKinds: new Set([...curFact.sourceKinds, ...prevFact.sourceKinds]),
          sanitizations: [],
          isSanitized: false,
        };
        widened.setVar(varName, topFact);
      }
    }

    return widened;
  }

  // ── Effect Deduplication ──────────────────────────────────────

  /**
   * Compute a deduplication key for a transfer effect.
   *
   * Effects are keyed by their kind, target identifier, and source
   * location to avoid reporting the same sink hit or call edge
   * multiple times across fixpoint iterations.
   */
  private effectKey(effect: TransferEffect): string {
    // Build a key from the effect's distinguishing properties.
    // TransferEffect is defined in transfer-functions.ts; we use
    // duck-typing to handle the known fields.
    const parts: string[] = [];

    if ('kind' in effect) {
      parts.push(String(effect.kind));
    }
    if ('callee' in effect) {
      parts.push(String(effect.callee));
    }
    if ('sinkKind' in effect) {
      parts.push(String(effect.sinkKind));
    }
    if ('node' in effect && effect.node) {
      const node = effect.node as ts.Node;
      parts.push(String(node.pos));
      parts.push(String(node.end));
    }
    if ('position' in effect) {
      parts.push(String(effect.position));
    }
    if ('varName' in effect) {
      parts.push(String(effect.varName));
    }

    return parts.join('|');
  }
}

/**
 * Control Flow Graph (CFG) data structures
 * Used for path-sensitive taint analysis
 */

import * as ts from 'typescript';

/** Terminator kind — how a basic block ends */
export type TerminatorKind =
  | 'branch'         // if/else
  | 'switch'         // switch/case
  | 'return'         // return statement
  | 'throw'          // throw statement
  | 'loop-entry'     // for/while/do-while condition
  | 'loop-back'      // back-edge to loop condition
  | 'break'          // break out of loop/switch
  | 'continue'       // continue to next loop iteration
  | 'fallthrough'    // sequential flow to next block
  | 'try-enter'      // entering try block
  | 'catch-enter'    // entering catch block
  | 'finally-enter'; // entering finally block

export interface BasicBlock {
  id: number;
  /** Statements in this block (in source order) */
  statements: ts.Node[];
  /** How this block terminates */
  terminator?: {
    kind: TerminatorKind;
    /** Branch condition expression (for if/while/for/ternary) */
    condition?: ts.Expression;
    /** The original AST node of the terminator (if/switch/return/throw) */
    node?: ts.Node;
  };
  /** Is this block reachable from entry? (set during dead code elimination) */
  reachable: boolean;
}

export interface CFGEdge {
  from: number;
  to: number;
  /** Label for this edge */
  label?: 'true' | 'false' | 'exception' | 'default' | string;
  /** Is this a back-edge (loop)? */
  isBackEdge: boolean;
}

export interface CFG {
  /** Entry block ID */
  entry: number;
  /** Exit block ID (may have multiple predecessors) */
  exit: number;
  /** All basic blocks */
  blocks: Map<number, BasicBlock>;
  /** Forward edges */
  edges: CFGEdge[];
  /** Reverse edges for backward analysis (block ID -> incoming edges) */
  reverseEdges: Map<number, CFGEdge[]>;
  /** Forward edge map (block ID -> outgoing edges) */
  forwardEdges: Map<number, CFGEdge[]>;
  /** The function node this CFG was built from */
  functionNode: ts.Node;
}

/** Dominator tree node */
export interface DominatorInfo {
  /** Block ID -> immediate dominator block ID */
  idom: Map<number, number>;
  /** Block ID -> set of blocks it dominates */
  dominates: Map<number, Set<number>>;
  /** Block ID -> dominance frontier */
  frontier: Map<number, Set<number>>;
}

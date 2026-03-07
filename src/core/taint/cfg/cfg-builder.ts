/**
 * CFG Builder — constructs a Control Flow Graph from TypeScript function AST
 *
 * Handles: sequential flow, if/else, switch/case, for/while/do-while,
 * for-in/for-of, try/catch/finally, return, throw, break, continue,
 * short-circuit operators (&&, ||, ??), optional chaining (?.), ternary (?:).
 */

import * as ts from 'typescript';
import type {
  BasicBlock,
  CFG,
  CFGEdge,
  DominatorInfo,
  TerminatorKind,
} from './cfg-types.js';

/** Loop context for resolving break/continue targets */
interface LoopContext {
  label?: string;
  /** Block ID where `continue` should jump (condition or update) */
  continueTarget: number;
  /** Block ID where `break` should jump (join after loop) */
  breakTarget: number;
}

/** Switch context for resolving break targets */
interface SwitchContext {
  label?: string;
  breakTarget: number;
}

/** Try context for routing exceptions to catch/finally */
interface TryContext {
  /** Block ID of the catch entry (if present) */
  catchEntry?: number;
  /** Block ID of the finally entry (if present) */
  finallyEntry?: number;
}

export class CFGBuilder {
  private nextBlockId = 0;
  private blocks: Map<number, BasicBlock> = new Map();
  private edges: CFGEdge[] = [];
  private currentBlock!: BasicBlock;

  private loopStack: LoopContext[] = [];
  private switchStack: SwitchContext[] = [];
  private tryStack: TryContext[] = [];

  private exitBlockId!: number;

  // ──────────────────────────────────────────────
  // Public API
  // ──────────────────────────────────────────────

  /** Build a CFG for a function body or source file */
  build(functionNode: ts.FunctionLikeDeclaration | ts.SourceFile): CFG {
    this.reset();

    const entryBlock = this.newBlock();
    const exitBlock = this.newBlock();
    this.exitBlockId = exitBlock.id;
    this.currentBlock = entryBlock;

    const body = this.getFunctionBody(functionNode);
    if (body) {
      if (ts.isBlock(body)) {
        this.processStatements(body.statements);
      } else if (ts.isSourceFile(functionNode)) {
        this.processStatements(functionNode.statements);
      } else {
        // Arrow function with expression body — treat as implicit return
        this.addStatementToCurrentBlock(body);
        this.sealBlock('return', body);
        this.addEdge(this.currentBlock.id, this.exitBlockId);
      }
    }

    // If current block has no terminator, fall through to exit
    if (this.currentBlock && !this.currentBlock.terminator) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, this.exitBlockId);
    }

    const cfg: CFG = {
      entry: entryBlock.id,
      exit: exitBlock.id,
      blocks: this.blocks,
      edges: this.edges,
      reverseEdges: new Map(),
      forwardEdges: new Map(),
      functionNode,
    };

    this.buildEdgeMaps(cfg);
    this.markReachable(cfg);

    return cfg;
  }

  /** Compute dominator tree using Cooper-Harvey-Kennedy iterative algorithm */
  computeDominators(cfg: CFG): DominatorInfo {
    const rpo = this.reversePostOrder(cfg);
    const blockIds = rpo.filter((id) => {
      const block = cfg.blocks.get(id);
      return block !== undefined && block.reachable;
    });

    const idom = new Map<number, number>();
    const orderIndex = new Map<number, number>();
    blockIds.forEach((id, idx) => orderIndex.set(id, idx));

    // Entry dominates itself
    idom.set(cfg.entry, cfg.entry);

    const intersect = (b1: number, b2: number): number => {
      let finger1 = b1;
      let finger2 = b2;
      while (finger1 !== finger2) {
        while ((orderIndex.get(finger1) ?? 0) > (orderIndex.get(finger2) ?? 0)) {
          finger1 = idom.get(finger1) ?? cfg.entry;
        }
        while ((orderIndex.get(finger2) ?? 0) > (orderIndex.get(finger1) ?? 0)) {
          finger2 = idom.get(finger2) ?? cfg.entry;
        }
      }
      return finger1;
    };

    let changed = true;
    while (changed) {
      changed = false;
      for (const b of blockIds) {
        if (b === cfg.entry) continue;

        const preds = (cfg.reverseEdges.get(b) ?? [])
          .map((e) => e.from)
          .filter((p) => idom.has(p));

        if (preds.length === 0) continue;

        let newIdom = preds[0];
        for (let i = 1; i < preds.length; i++) {
          if (idom.has(preds[i])) {
            newIdom = intersect(newIdom, preds[i]);
          }
        }

        if (idom.get(b) !== newIdom) {
          idom.set(b, newIdom);
          changed = true;
        }
      }
    }

    // Build dominates sets
    const dominates = new Map<number, Set<number>>();
    for (const id of blockIds) {
      dominates.set(id, new Set());
    }
    for (const [block, dom] of idom) {
      if (block !== dom) {
        dominates.get(dom)?.add(block);
      }
    }

    // Build dominance frontiers
    const frontier = new Map<number, Set<number>>();
    for (const id of blockIds) {
      frontier.set(id, new Set());
    }
    for (const b of blockIds) {
      const preds = (cfg.reverseEdges.get(b) ?? []).map((e) => e.from);
      if (preds.length >= 2) {
        for (const p of preds) {
          let runner = p;
          while (runner !== idom.get(b) && runner !== undefined) {
            frontier.get(runner)?.add(b);
            const next = idom.get(runner);
            if (next === runner || next === undefined) break;
            runner = next;
          }
        }
      }
    }

    return { idom, dominates, frontier };
  }

  /** Mark reachable blocks from entry via BFS */
  markReachable(cfg: CFG): void {
    // Reset all blocks to unreachable
    for (const block of cfg.blocks.values()) {
      block.reachable = false;
    }

    const visited = new Set<number>();
    const queue: number[] = [cfg.entry];
    visited.add(cfg.entry);

    while (queue.length > 0) {
      const blockId = queue.shift()!;
      const block = cfg.blocks.get(blockId);
      if (block) {
        block.reachable = true;
      }

      const outgoing = cfg.forwardEdges.get(blockId) ?? [];
      for (const edge of outgoing) {
        if (!visited.has(edge.to)) {
          visited.add(edge.to);
          queue.push(edge.to);
        }
      }
    }
  }

  // ──────────────────────────────────────────────
  // Internal — block management
  // ──────────────────────────────────────────────

  private reset(): void {
    this.nextBlockId = 0;
    this.blocks = new Map();
    this.edges = [];
    this.loopStack = [];
    this.switchStack = [];
    this.tryStack = [];
  }

  private newBlock(): BasicBlock {
    const block: BasicBlock = {
      id: this.nextBlockId++,
      statements: [],
      reachable: false,
    };
    this.blocks.set(block.id, block);
    return block;
  }

  private addEdge(
    from: number,
    to: number,
    label?: CFGEdge['label'],
    isBackEdge = false,
  ): void {
    this.edges.push({ from, to, label, isBackEdge });
  }

  /** Seal the current block with a terminator */
  private sealBlock(
    kind: TerminatorKind,
    nodeOrCondition?: ts.Node,
    condition?: ts.Expression,
  ): void {
    if (this.currentBlock.terminator) return; // already sealed
    this.currentBlock.terminator = {
      kind,
      node: nodeOrCondition,
      condition,
    };
  }

  /** Start a new block, linking from the current one if it's unsealed */
  /* reserved for future use: startNewBlock()
  private startNewBlock(): BasicBlock {
    const block = this.newBlock();
    if (this.currentBlock && !this.currentBlock.terminator) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, block.id);
    }
    this.currentBlock = block;
    return block;
  }
  */

  /** Start a new block without linking from the current one */
  private startDisconnectedBlock(): BasicBlock {
    const block = this.newBlock();
    this.currentBlock = block;
    return block;
  }

  private addStatementToCurrentBlock(node: ts.Node): void {
    this.currentBlock.statements.push(node);
  }

  private isBlockTerminated(): boolean {
    return !!this.currentBlock.terminator;
  }

  // ──────────────────────────────────────────────
  // Internal — get function body
  // ──────────────────────────────────────────────

  private getFunctionBody(
    node: ts.FunctionLikeDeclaration | ts.SourceFile,
  ): ts.Node | undefined {
    if (ts.isSourceFile(node)) return node;
    if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) return node.body;
    if (ts.isFunctionExpression(node)) return node.body;
    if (ts.isArrowFunction(node)) return node.body;
    if (ts.isGetAccessor(node) || ts.isSetAccessor(node)) return node.body;
    if (ts.isConstructorDeclaration(node)) return node.body;
    return undefined;
  }

  // ──────────────────────────────────────────────
  // Internal — statement processing
  // ──────────────────────────────────────────────

  private processStatements(
    statements: ts.NodeArray<ts.Statement> | ReadonlyArray<ts.Statement>,
  ): void {
    for (const stmt of statements) {
      if (this.isBlockTerminated()) {
        // Dead code after terminator — still create blocks for analysis
        this.startDisconnectedBlock();
      }
      this.processStatement(stmt);
    }
  }

  private processStatement(stmt: ts.Statement): void {
    try {
      if (ts.isIfStatement(stmt)) {
        this.processIfStatement(stmt);
      } else if (ts.isSwitchStatement(stmt)) {
        this.processSwitchStatement(stmt);
      } else if (ts.isForStatement(stmt)) {
        this.processForStatement(stmt);
      } else if (ts.isWhileStatement(stmt)) {
        this.processWhileStatement(stmt);
      } else if (ts.isDoStatement(stmt)) {
        this.processDoWhileStatement(stmt);
      } else if (ts.isForInStatement(stmt)) {
        this.processForInOfStatement(stmt);
      } else if (ts.isForOfStatement(stmt)) {
        this.processForInOfStatement(stmt);
      } else if (ts.isTryStatement(stmt)) {
        this.processTryStatement(stmt);
      } else if (ts.isReturnStatement(stmt)) {
        this.processReturnStatement(stmt);
      } else if (ts.isThrowStatement(stmt)) {
        this.processThrowStatement(stmt);
      } else if (ts.isBreakStatement(stmt)) {
        this.processBreakStatement(stmt);
      } else if (ts.isContinueStatement(stmt)) {
        this.processContinueStatement(stmt);
      } else if (ts.isBlock(stmt)) {
        this.processStatements(stmt.statements);
      } else if (ts.isLabeledStatement(stmt)) {
        this.processLabeledStatement(stmt);
      } else if (ts.isExpressionStatement(stmt)) {
        this.processExpressionStatement(stmt);
      } else if (ts.isVariableStatement(stmt)) {
        this.processVariableStatement(stmt);
      } else {
        // All other statements — add to current block as-is
        this.addStatementToCurrentBlock(stmt);
      }
    } catch {
      // Safety net: don't crash on unexpected AST shapes
      this.addStatementToCurrentBlock(stmt);
    }
  }

  // ──────────────────────────────────────────────
  // if/else
  // ──────────────────────────────────────────────

  private processIfStatement(stmt: ts.IfStatement): void {
    // Process condition with short-circuit handling
    this.processExpression(stmt.expression);

    this.sealBlock('branch', stmt, stmt.expression);

    const thenBlock = this.newBlock();
    const elseBlock = this.newBlock();
    const joinBlock = this.newBlock();

    this.addEdge(this.currentBlock.id, thenBlock.id, 'true');
    this.addEdge(this.currentBlock.id, elseBlock.id, 'false');

    // Process then branch
    this.currentBlock = thenBlock;
    this.processStatement(stmt.thenStatement);
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, joinBlock.id);
    }

    // Process else branch
    this.currentBlock = elseBlock;
    if (stmt.elseStatement) {
      this.processStatement(stmt.elseStatement);
    }
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, joinBlock.id);
    }

    this.currentBlock = joinBlock;
  }

  // ──────────────────────────────────────────────
  // switch/case
  // ──────────────────────────────────────────────

  private processSwitchStatement(stmt: ts.SwitchStatement): void {
    this.addStatementToCurrentBlock(stmt.expression);
    this.sealBlock('switch', stmt);

    const switchEntryBlock = this.currentBlock;
    const joinBlock = this.newBlock();

    this.switchStack.push({
      label: this.getPendingLabel(),
      breakTarget: joinBlock.id,
    });

    const clauses = stmt.caseBlock.clauses;
    let previousCaseBlock: BasicBlock | undefined;
    let hasDefault = false;

    for (let i = 0; i < clauses.length; i++) {
      const clause = clauses[i];
      const caseBlock = this.newBlock();

      if (ts.isCaseClause(clause)) {
        const label = `case:${clause.expression.getText?.() ?? String(i)}`;
        this.addEdge(switchEntryBlock.id, caseBlock.id, label);
      } else {
        // DefaultClause
        hasDefault = true;
        this.addEdge(switchEntryBlock.id, caseBlock.id, 'default');
      }

      // Fall-through from previous case (no break)
      if (previousCaseBlock && !previousCaseBlock.terminator) {
        this.sealBlockOnTarget(previousCaseBlock, 'fallthrough');
        this.addEdge(previousCaseBlock.id, caseBlock.id);
      }

      this.currentBlock = caseBlock;
      this.processStatements(clause.statements);
      previousCaseBlock = this.currentBlock;
    }

    // Last case falls through to join if no break
    if (previousCaseBlock && !previousCaseBlock.terminator) {
      this.sealBlockOnTarget(previousCaseBlock, 'fallthrough');
      this.addEdge(previousCaseBlock.id, joinBlock.id);
    }

    // If no default case, switch entry can fall through to join
    if (!hasDefault) {
      this.addEdge(switchEntryBlock.id, joinBlock.id, 'default');
    }

    this.switchStack.pop();
    this.currentBlock = joinBlock;
  }

  private sealBlockOnTarget(block: BasicBlock, kind: TerminatorKind): void {
    if (!block.terminator) {
      block.terminator = { kind };
    }
  }

  // ──────────────────────────────────────────────
  // for loop
  // ──────────────────────────────────────────────

  private processForStatement(stmt: ts.ForStatement): void {
    // Initializer in current block
    if (stmt.initializer) {
      this.addStatementToCurrentBlock(stmt.initializer);
    }

    const condBlock = this.newBlock();
    const bodyBlock = this.newBlock();
    const updateBlock = this.newBlock();
    const joinBlock = this.newBlock();

    // Current -> condition
    this.sealBlock('fallthrough');
    this.addEdge(this.currentBlock.id, condBlock.id);

    // Condition block
    this.currentBlock = condBlock;
    if (stmt.condition) {
      this.addStatementToCurrentBlock(stmt.condition);
      this.sealBlock('loop-entry', stmt, stmt.condition);
    } else {
      this.sealBlock('loop-entry', stmt);
    }
    this.addEdge(condBlock.id, bodyBlock.id, 'true');
    this.addEdge(condBlock.id, joinBlock.id, 'false');

    // Push loop context
    this.loopStack.push({
      label: this.getPendingLabel(),
      continueTarget: updateBlock.id,
      breakTarget: joinBlock.id,
    });

    // Body
    this.currentBlock = bodyBlock;
    this.processStatement(stmt.statement);
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, updateBlock.id);
    }

    // Update block
    this.currentBlock = updateBlock;
    if (stmt.incrementor) {
      this.addStatementToCurrentBlock(stmt.incrementor);
    }
    this.sealBlock('loop-back', stmt);
    this.addEdge(updateBlock.id, condBlock.id, undefined, true);

    this.loopStack.pop();
    this.currentBlock = joinBlock;
  }

  // ──────────────────────────────────────────────
  // while loop
  // ──────────────────────────────────────────────

  private processWhileStatement(stmt: ts.WhileStatement): void {
    const condBlock = this.newBlock();
    const bodyBlock = this.newBlock();
    const joinBlock = this.newBlock();

    this.sealBlock('fallthrough');
    this.addEdge(this.currentBlock.id, condBlock.id);

    // Condition
    this.currentBlock = condBlock;
    this.addStatementToCurrentBlock(stmt.expression);
    this.sealBlock('loop-entry', stmt, stmt.expression);
    this.addEdge(condBlock.id, bodyBlock.id, 'true');
    this.addEdge(condBlock.id, joinBlock.id, 'false');

    this.loopStack.push({
      label: this.getPendingLabel(),
      continueTarget: condBlock.id,
      breakTarget: joinBlock.id,
    });

    // Body
    this.currentBlock = bodyBlock;
    this.processStatement(stmt.statement);
    if (!this.isBlockTerminated()) {
      this.sealBlock('loop-back', stmt);
      this.addEdge(this.currentBlock.id, condBlock.id, undefined, true);
    }

    this.loopStack.pop();
    this.currentBlock = joinBlock;
  }

  // ──────────────────────────────────────────────
  // do-while loop
  // ──────────────────────────────────────────────

  private processDoWhileStatement(stmt: ts.DoStatement): void {
    const bodyBlock = this.newBlock();
    const condBlock = this.newBlock();
    const joinBlock = this.newBlock();

    this.sealBlock('fallthrough');
    this.addEdge(this.currentBlock.id, bodyBlock.id);

    this.loopStack.push({
      label: this.getPendingLabel(),
      continueTarget: condBlock.id,
      breakTarget: joinBlock.id,
    });

    // Body (executes at least once)
    this.currentBlock = bodyBlock;
    this.processStatement(stmt.statement);
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, condBlock.id);
    }

    // Condition
    this.currentBlock = condBlock;
    this.addStatementToCurrentBlock(stmt.expression);
    this.sealBlock('loop-entry', stmt, stmt.expression);
    this.addEdge(condBlock.id, bodyBlock.id, 'true', true);
    this.addEdge(condBlock.id, joinBlock.id, 'false');

    this.loopStack.pop();
    this.currentBlock = joinBlock;
  }

  // ──────────────────────────────────────────────
  // for-in / for-of
  // ──────────────────────────────────────────────

  private processForInOfStatement(
    stmt: ts.ForInStatement | ts.ForOfStatement,
  ): void {
    // Iterator expression in current block
    this.addStatementToCurrentBlock(stmt.expression);

    const condBlock = this.newBlock();
    const bodyBlock = this.newBlock();
    const joinBlock = this.newBlock();

    this.sealBlock('fallthrough');
    this.addEdge(this.currentBlock.id, condBlock.id);

    // Condition block (has next element?)
    this.currentBlock = condBlock;
    this.addStatementToCurrentBlock(stmt.initializer);
    this.sealBlock('loop-entry', stmt);
    this.addEdge(condBlock.id, bodyBlock.id, 'true');
    this.addEdge(condBlock.id, joinBlock.id, 'false');

    this.loopStack.push({
      label: this.getPendingLabel(),
      continueTarget: condBlock.id,
      breakTarget: joinBlock.id,
    });

    // Body
    this.currentBlock = bodyBlock;
    this.processStatement(stmt.statement);
    if (!this.isBlockTerminated()) {
      this.sealBlock('loop-back', stmt);
      this.addEdge(this.currentBlock.id, condBlock.id, undefined, true);
    }

    this.loopStack.pop();
    this.currentBlock = joinBlock;
  }

  // ──────────────────────────────────────────────
  // try/catch/finally
  // ──────────────────────────────────────────────

  private processTryStatement(stmt: ts.TryStatement): void {
    const tryBlock = this.newBlock();
    const catchBlock = stmt.catchClause ? this.newBlock() : undefined;
    const finallyBlock = stmt.finallyBlock ? this.newBlock() : undefined;
    const joinBlock = this.newBlock();

    // Push try context
    this.tryStack.push({
      catchEntry: catchBlock?.id,
      finallyEntry: finallyBlock?.id,
    });

    // Entry -> try
    this.sealBlock('try-enter', stmt);
    this.addEdge(this.currentBlock.id, tryBlock.id);

    // Process try block
    this.currentBlock = tryBlock;
    this.processStatements(stmt.tryBlock.statements);

    this.tryStack.pop();

    // Try end -> finally or join
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      if (finallyBlock) {
        this.addEdge(this.currentBlock.id, finallyBlock.id);
      } else {
        this.addEdge(this.currentBlock.id, joinBlock.id);
      }
    }

    // Exception edge from try entry to catch
    if (catchBlock) {
      this.addEdge(tryBlock.id, catchBlock.id, 'exception');
    }

    // Process catch block
    if (catchBlock && stmt.catchClause) {
      this.currentBlock = catchBlock;
      catchBlock.terminator = undefined; // ensure fresh
      if (stmt.catchClause.variableDeclaration) {
        this.addStatementToCurrentBlock(stmt.catchClause.variableDeclaration);
      }
      this.processStatements(stmt.catchClause.block.statements);
      if (!this.isBlockTerminated()) {
        this.sealBlock('fallthrough');
        if (finallyBlock) {
          this.addEdge(this.currentBlock.id, finallyBlock.id);
        } else {
          this.addEdge(this.currentBlock.id, joinBlock.id);
        }
      }
    }

    // Process finally block
    if (finallyBlock && stmt.finallyBlock) {
      this.currentBlock = finallyBlock;
      this.processStatements(stmt.finallyBlock.statements);
      if (!this.isBlockTerminated()) {
        this.sealBlock('fallthrough');
        this.addEdge(this.currentBlock.id, joinBlock.id);
      }
    }

    this.currentBlock = joinBlock;
  }

  // ──────────────────────────────────────────────
  // return / throw / break / continue
  // ──────────────────────────────────────────────

  private processReturnStatement(stmt: ts.ReturnStatement): void {
    this.addStatementToCurrentBlock(stmt);
    this.sealBlock('return', stmt);

    const finallyTarget = this.getEnclosingFinally();
    if (finallyTarget !== undefined) {
      this.addEdge(this.currentBlock.id, finallyTarget);
    } else {
      this.addEdge(this.currentBlock.id, this.exitBlockId);
    }
  }

  private processThrowStatement(stmt: ts.ThrowStatement): void {
    this.addStatementToCurrentBlock(stmt);
    this.sealBlock('throw', stmt);

    const catchTarget = this.getEnclosingCatch();
    if (catchTarget !== undefined) {
      this.addEdge(this.currentBlock.id, catchTarget, 'exception');
    } else {
      const finallyTarget = this.getEnclosingFinally();
      if (finallyTarget !== undefined) {
        this.addEdge(this.currentBlock.id, finallyTarget);
      } else {
        this.addEdge(this.currentBlock.id, this.exitBlockId, 'exception');
      }
    }
  }

  private processBreakStatement(stmt: ts.BreakStatement): void {
    this.addStatementToCurrentBlock(stmt);
    this.sealBlock('break', stmt);

    const label = stmt.label?.text;
    const target = this.findBreakTarget(label);
    if (target !== undefined) {
      this.addEdge(this.currentBlock.id, target);
    }
  }

  private processContinueStatement(stmt: ts.ContinueStatement): void {
    this.addStatementToCurrentBlock(stmt);
    this.sealBlock('continue', stmt);

    const label = stmt.label?.text;
    const target = this.findContinueTarget(label);
    if (target !== undefined) {
      this.addEdge(this.currentBlock.id, target, undefined, true);
    }
  }

  // ──────────────────────────────────────────────
  // Labeled statements
  // ──────────────────────────────────────────────

  private pendingLabel?: string;

  private getPendingLabel(): string | undefined {
    const label = this.pendingLabel;
    this.pendingLabel = undefined;
    return label;
  }

  private processLabeledStatement(stmt: ts.LabeledStatement): void {
    this.pendingLabel = stmt.label.text;
    this.processStatement(stmt.statement);
  }

  // ──────────────────────────────────────────────
  // Expression statements — handle short-circuit ops
  // ──────────────────────────────────────────────

  private processExpressionStatement(stmt: ts.ExpressionStatement): void {
    this.processExpression(stmt.expression);
  }

  private processVariableStatement(stmt: ts.VariableStatement): void {
    for (const decl of stmt.declarationList.declarations) {
      if (decl.initializer) {
        // Check for short-circuit or ternary in initializer
        if (this.hasShortCircuit(decl.initializer)) {
          this.processExpression(decl.initializer);
          this.addStatementToCurrentBlock(decl);
        } else {
          this.addStatementToCurrentBlock(decl);
        }
      } else {
        this.addStatementToCurrentBlock(decl);
      }
    }
  }

  /**
   * Process an expression that might contain short-circuit operators.
   * Returns the block where the expression evaluation ends.
   */
  private processExpression(expr: ts.Expression): BasicBlock {
    if (ts.isBinaryExpression(expr)) {
      const op = expr.operatorToken.kind;

      // && short-circuit
      if (op === ts.SyntaxKind.AmpersandAmpersandToken) {
        return this.processShortCircuit(expr, 'and');
      }

      // || short-circuit
      if (op === ts.SyntaxKind.BarBarToken) {
        return this.processShortCircuit(expr, 'or');
      }

      // ?? nullish coalescing
      if (op === ts.SyntaxKind.QuestionQuestionToken) {
        return this.processShortCircuit(expr, 'nullish');
      }
    }

    if (ts.isConditionalExpression(expr)) {
      return this.processTernary(expr);
    }

    // Optional chaining — model as implicit null branch
    if (this.isOptionalChain(expr)) {
      return this.processOptionalChain(expr);
    }

    // Default: add expression to current block
    this.addStatementToCurrentBlock(expr);
    return this.currentBlock;
  }

  // ──────────────────────────────────────────────
  // Short-circuit: &&, ||, ??
  // ──────────────────────────────────────────────

  private processShortCircuit(
    expr: ts.BinaryExpression,
    kind: 'and' | 'or' | 'nullish',
  ): BasicBlock {
    // Evaluate left side
    this.processExpression(expr.left);
    this.sealBlock('branch', expr, expr.left as ts.Expression);

    const leftBlock = this.currentBlock;
    const rightBlock = this.newBlock();
    const joinBlock = this.newBlock();

    if (kind === 'and') {
      // && : if left is truthy, evaluate right; else skip
      this.addEdge(leftBlock.id, rightBlock.id, 'true');
      this.addEdge(leftBlock.id, joinBlock.id, 'false');
    } else {
      // || or ?? : if left is falsy/nullish, evaluate right; else skip
      this.addEdge(leftBlock.id, joinBlock.id, 'true');
      this.addEdge(leftBlock.id, rightBlock.id, 'false');
    }

    this.currentBlock = rightBlock;
    this.processExpression(expr.right);
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, joinBlock.id);
    }

    this.currentBlock = joinBlock;
    return joinBlock;
  }

  // ──────────────────────────────────────────────
  // Ternary: condition ? then : else
  // ──────────────────────────────────────────────

  private processTernary(expr: ts.ConditionalExpression): BasicBlock {
    this.processExpression(expr.condition);
    this.sealBlock('branch', expr, expr.condition);

    const condBlock = this.currentBlock;
    const thenBlock = this.newBlock();
    const elseBlock = this.newBlock();
    const joinBlock = this.newBlock();

    this.addEdge(condBlock.id, thenBlock.id, 'true');
    this.addEdge(condBlock.id, elseBlock.id, 'false');

    this.currentBlock = thenBlock;
    this.processExpression(expr.whenTrue);
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, joinBlock.id);
    }

    this.currentBlock = elseBlock;
    this.processExpression(expr.whenFalse);
    if (!this.isBlockTerminated()) {
      this.sealBlock('fallthrough');
      this.addEdge(this.currentBlock.id, joinBlock.id);
    }

    this.currentBlock = joinBlock;
    return joinBlock;
  }

  // ──────────────────────────────────────────────
  // Optional chaining: a?.b, a?.(), a?.[x]
  // ──────────────────────────────────────────────

  private isOptionalChain(node: ts.Node): boolean {
    if (ts.isPropertyAccessExpression(node) && node.questionDotToken) return true;
    if (ts.isElementAccessExpression(node) && node.questionDotToken) return true;
    if (ts.isCallExpression(node) && node.questionDotToken) return true;
    return false;
  }

  private processOptionalChain(expr: ts.Expression): BasicBlock {
    // Model ?. as: if (obj != null) access property, else short-circuit to undefined
    this.addStatementToCurrentBlock(expr);
    this.sealBlock('branch', expr);

    const checkBlock = this.currentBlock;
    const accessBlock = this.newBlock();
    const joinBlock = this.newBlock();

    this.addEdge(checkBlock.id, accessBlock.id, 'true');
    this.addEdge(checkBlock.id, joinBlock.id, 'false');

    // Access block just falls through to join
    this.currentBlock = accessBlock;
    this.sealBlock('fallthrough');
    this.addEdge(accessBlock.id, joinBlock.id);

    this.currentBlock = joinBlock;
    return joinBlock;
  }

  // ──────────────────────────────────────────────
  // Helpers — context lookups
  // ──────────────────────────────────────────────

  private findBreakTarget(label?: string): number | undefined {
    if (label) {
      // Search loops and switches for matching label
      for (let i = this.loopStack.length - 1; i >= 0; i--) {
        if (this.loopStack[i].label === label) return this.loopStack[i].breakTarget;
      }
      for (let i = this.switchStack.length - 1; i >= 0; i--) {
        if (this.switchStack[i].label === label) return this.switchStack[i].breakTarget;
      }
    } else {
      // Unlabeled break: innermost loop or switch
      if (this.switchStack.length > 0 && this.loopStack.length > 0) {
        // The one pushed more recently wins — compare break target IDs
        // Higher ID = more recent
        const loopTarget = this.loopStack[this.loopStack.length - 1].breakTarget;
        const switchTarget = this.switchStack[this.switchStack.length - 1].breakTarget;
        return Math.max(loopTarget, switchTarget) === loopTarget ? loopTarget : switchTarget;
      }
      if (this.loopStack.length > 0) {
        return this.loopStack[this.loopStack.length - 1].breakTarget;
      }
      if (this.switchStack.length > 0) {
        return this.switchStack[this.switchStack.length - 1].breakTarget;
      }
    }
    return undefined;
  }

  private findContinueTarget(label?: string): number | undefined {
    if (label) {
      for (let i = this.loopStack.length - 1; i >= 0; i--) {
        if (this.loopStack[i].label === label) return this.loopStack[i].continueTarget;
      }
    } else if (this.loopStack.length > 0) {
      return this.loopStack[this.loopStack.length - 1].continueTarget;
    }
    return undefined;
  }

  private getEnclosingCatch(): number | undefined {
    for (let i = this.tryStack.length - 1; i >= 0; i--) {
      if (this.tryStack[i].catchEntry !== undefined) {
        return this.tryStack[i].catchEntry;
      }
    }
    return undefined;
  }

  private getEnclosingFinally(): number | undefined {
    for (let i = this.tryStack.length - 1; i >= 0; i--) {
      if (this.tryStack[i].finallyEntry !== undefined) {
        return this.tryStack[i].finallyEntry;
      }
    }
    return undefined;
  }

  private hasShortCircuit(node: ts.Node): boolean {
    if (ts.isBinaryExpression(node)) {
      const op = node.operatorToken.kind;
      if (
        op === ts.SyntaxKind.AmpersandAmpersandToken ||
        op === ts.SyntaxKind.BarBarToken ||
        op === ts.SyntaxKind.QuestionQuestionToken
      ) {
        return true;
      }
    }
    if (ts.isConditionalExpression(node)) return true;
    if (this.isOptionalChain(node)) return true;

    let found = false;
    ts.forEachChild(node, (child) => {
      if (!found && this.hasShortCircuit(child)) {
        found = true;
      }
    });
    return found;
  }

  // ──────────────────────────────────────────────
  // Edge maps and post-processing
  // ──────────────────────────────────────────────

  private buildEdgeMaps(cfg: CFG): void {
    const forward = new Map<number, CFGEdge[]>();
    const reverse = new Map<number, CFGEdge[]>();

    for (const block of cfg.blocks.values()) {
      forward.set(block.id, []);
      reverse.set(block.id, []);
    }

    for (const edge of cfg.edges) {
      if (!forward.has(edge.from)) forward.set(edge.from, []);
      if (!reverse.has(edge.to)) reverse.set(edge.to, []);
      forward.get(edge.from)!.push(edge);
      reverse.get(edge.to)!.push(edge);
    }

    cfg.forwardEdges = forward;
    cfg.reverseEdges = reverse;
  }

  // ──────────────────────────────────────────────
  // Reverse postorder (for dominator computation)
  // ──────────────────────────────────────────────

  private reversePostOrder(cfg: CFG): number[] {
    const visited = new Set<number>();
    const postOrder: number[] = [];

    const dfs = (blockId: number): void => {
      if (visited.has(blockId)) return;
      visited.add(blockId);

      const outgoing = cfg.forwardEdges.get(blockId) ?? [];
      for (const edge of outgoing) {
        dfs(edge.to);
      }
      postOrder.push(blockId);
    };

    dfs(cfg.entry);
    return postOrder.reverse();
  }
}

/**
 * Def-Use Chain Analysis
 *
 * Computes definition-use chains over a Control Flow Graph (CFG).
 * Def-use chains track where each variable is defined (assigned) and where
 * it is used (read), enabling precise data flow tracking for taint analysis.
 *
 * The analysis consists of three phases:
 *   1. **Scanning** — walk each basic block's statements to collect DefSites and UseSites.
 *   2. **Reaching definitions** — iterative worklist algorithm to compute which
 *      definitions can reach each block entry/exit.
 *   3. **Chain construction** — connect each definition to the uses it can reach.
 */

import * as ts from 'typescript';
import type { CFG } from '../cfg/cfg-types.js';

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

/** A site where a variable is defined (written). */
export interface DefSite {
  /** The variable name being defined. */
  varName: string;
  /** ID of the basic block containing this definition. */
  blockId: number;
  /** Index of the statement within `block.statements`. */
  statementIndex: number;
  /** The AST node representing this definition. */
  node: ts.Node;
  /** Classification of how the variable is defined. */
  kind:
    | 'param'
    | 'declaration'
    | 'assignment'
    | 'destructuring'
    | 'for-binding'
    | 'catch-binding'
    | 'import';
}

/** A site where a variable is used (read). */
export interface UseSite {
  /** The variable name being read. */
  varName: string;
  /** ID of the basic block containing this use. */
  blockId: number;
  /** Index of the statement within `block.statements`. */
  statementIndex: number;
  /** The AST node representing this use. */
  node: ts.Node;
  /** Classification of how the variable is used. */
  kind: 'read' | 'call-arg' | 'return' | 'property-access' | 'condition';
}

/** A def-use chain: one definition linked to all uses it can reach. */
export interface DefUseChain {
  /** The definition site. */
  def: DefSite;
  /** All use sites reachable from this definition without an intervening redefinition. */
  uses: UseSite[];
}

// ────────────────────────────────────────────────────────────────────────────
// GEN / KILL sets for reaching-definitions data flow
// ────────────────────────────────────────────────────────────────────────────

/** Per-block GEN/KILL sets used during the reaching-definitions fixpoint. */
interface BlockGenKill {
  /** Definitions generated in this block (last def per variable wins). */
  gen: Map<string, DefSite>;
  /** Variable names killed (redefined) in this block. */
  kill: Set<string>;
}

// ────────────────────────────────────────────────────────────────────────────
// Analyzer
// ────────────────────────────────────────────────────────────────────────────

/**
 * Analyzes a CFG to produce def-use chains for every variable.
 *
 * Usage:
 * ```ts
 * const analyzer = new DefUseAnalyzer();
 * analyzer.build(cfg);
 * analyzer.computeReachingDefinitions(cfg);
 * const chains = analyzer.getChains('userInput');
 * ```
 */
export class DefUseAnalyzer {
  /** varName -> all definition sites */
  private defs: Map<string, DefSite[]> = new Map();
  /** varName -> all use sites */
  private uses: Map<string, UseSite[]> = new Map();
  /** blockId -> definitions inside that block */
  private blockDefs: Map<number, DefSite[]> = new Map();
  /** blockId -> uses inside that block */
  private blockUses: Map<number, UseSite[]> = new Map();
  /**
   * varName -> blockId -> set of DefSites that reach the *entry* of that block.
   * Populated by {@link computeReachingDefinitions}.
   */
  private reachingDefs: Map<string, Map<number, Set<DefSite>>> = new Map();

  /** Whether reaching definitions have been computed. */
  private reachingDefsComputed = false;

  constructor() {
    // Maps are initialized inline; nothing else needed.
  }

  // ──────────────────────────────────────────────
  // Public API
  // ──────────────────────────────────────────────

  /**
   * Build def-use information for all variables in the CFG.
   *
   * Scans every reachable basic block's statements for definitions and uses,
   * populating the internal maps. Does **not** compute reaching definitions
   * automatically — call {@link computeReachingDefinitions} afterwards.
   *
   * @param cfg - The control flow graph to analyze.
   */
  build(cfg: CFG): void {
    this.clear();

    for (const [blockId, block] of cfg.blocks) {
      if (!block.reachable) continue;

      for (let stmtIdx = 0; stmtIdx < block.statements.length; stmtIdx++) {
        const stmt = block.statements[stmtIdx];
        this.scanNode(stmt, blockId, stmtIdx, /* insideCondition */ false);
      }

      // Also scan the terminator's condition if present (it contains uses).
      if (block.terminator?.condition) {
        // Attribute terminator uses to the last statement index + 1 so they
        // sort after all regular statements but stay within this block.
        const terminatorIdx = block.statements.length;
        this.scanForUses(
          block.terminator.condition,
          blockId,
          terminatorIdx,
          /* insideCondition */ true,
        );
      }
    }
  }

  /**
   * Get all definitions of a variable.
   * @returns Array of DefSites, or an empty array if the variable has no definitions.
   */
  getDefinitions(varName: string): DefSite[] {
    return this.defs.get(varName) ?? [];
  }

  /**
   * Get all uses of a variable.
   * @returns Array of UseSites, or an empty array if the variable has no uses.
   */
  getUses(varName: string): UseSite[] {
    return this.uses.get(varName) ?? [];
  }

  /**
   * Get definitions in a specific block.
   * @returns Array of DefSites in the given block, or empty array.
   */
  getBlockDefs(blockId: number): DefSite[] {
    return this.blockDefs.get(blockId) ?? [];
  }

  /**
   * Get uses in a specific block.
   * @returns Array of UseSites in the given block, or empty array.
   */
  getBlockUses(blockId: number): UseSite[] {
    return this.blockUses.get(blockId) ?? [];
  }

  /**
   * Compute reaching definitions using iterative data flow analysis.
   *
   * For each block B:
   * - **IN[B]**  = union of OUT[P] for every predecessor P of B
   * - **OUT[B]** = GEN[B] ∪ (IN[B] − KILL[B])
   *
   * Uses a worklist algorithm that iterates until a fixpoint is reached.
   * Must be called after {@link build}.
   *
   * @param cfg - The same CFG passed to {@link build}.
   */
  computeReachingDefinitions(cfg: CFG): void {
    // 1. Compute GEN and KILL for each block.
    const genKill = new Map<number, BlockGenKill>();
    for (const [blockId, block] of cfg.blocks) {
      if (!block.reachable) continue;
      genKill.set(blockId, this.computeGenKill(blockId));
    }

    // 2. Collect all variable names.
    const allVars = this.getAllVariables();

    // 3. Initialize IN and OUT maps.  Key: blockId, Value: varName -> Set<DefSite>
    const inSets = new Map<number, Map<string, Set<DefSite>>>();
    const outSets = new Map<number, Map<string, Set<DefSite>>>();

    for (const [blockId, block] of cfg.blocks) {
      if (!block.reachable) continue;
      inSets.set(blockId, new Map());
      outSets.set(blockId, new Map());
      for (const v of allVars) {
        inSets.get(blockId)!.set(v, new Set());
        outSets.get(blockId)!.set(v, new Set());
      }
    }

    // 4. Build predecessor map from reverseEdges.
    const predecessors = new Map<number, number[]>();
    for (const [blockId] of cfg.blocks) {
      const incoming = cfg.reverseEdges.get(blockId) ?? [];
      predecessors.set(
        blockId,
        incoming.map((e) => e.from).filter((id) => cfg.blocks.get(id)?.reachable),
      );
    }

    // 5. Worklist iteration.
    const worklist: number[] = [];
    for (const [blockId, block] of cfg.blocks) {
      if (block.reachable) worklist.push(blockId);
    }

    let changed = true;
    while (changed) {
      changed = false;

      for (const blockId of worklist) {
        const blockIn = inSets.get(blockId)!;
        const blockOut = outSets.get(blockId)!;
        const gk = genKill.get(blockId);
        if (!gk) continue;

        // IN[B] = ∪ OUT[P] for predecessors P
        for (const v of allVars) {
          const inSet = blockIn.get(v)!;
          const prevSize = inSet.size;

          for (const predId of predecessors.get(blockId) ?? []) {
            const predOut = outSets.get(predId)?.get(v);
            if (predOut) {
              for (const def of predOut) {
                inSet.add(def);
              }
            }
          }

          // OUT[B] = GEN[B] ∪ (IN[B] - KILL[B])
          const outSet = blockOut.get(v)!;
          const prevOutSize = outSet.size;

          // If this variable is killed in the block, IN defs don't flow through.
          if (!gk.kill.has(v)) {
            for (const def of inSet) {
              outSet.add(def);
            }
          }

          // GEN always flows to OUT.
          const genDef = gk.gen.get(v);
          if (genDef) {
            outSet.add(genDef);
          }

          if (inSet.size !== prevSize || outSet.size !== prevOutSize) {
            changed = true;
          }
        }
      }
    }

    // 6. Store reaching-definitions (IN sets) for later querying.
    this.reachingDefs.clear();
    for (const v of allVars) {
      const perBlock = new Map<number, Set<DefSite>>();
      for (const [blockId] of inSets) {
        const s = inSets.get(blockId)!.get(v);
        if (s && s.size > 0) {
          perBlock.set(blockId, new Set(s));
        }
      }
      if (perBlock.size > 0) {
        this.reachingDefs.set(v, perBlock);
      }
    }

    this.reachingDefsComputed = true;
  }

  /**
   * Get reaching definitions for a variable at the entry of a specific block.
   *
   * @param varName - The variable name.
   * @param blockId - The basic block ID.
   * @returns Array of DefSites that can reach the entry of `blockId`, or empty array.
   */
  getReachingDefs(varName: string, blockId: number): DefSite[] {
    const perBlock = this.reachingDefs.get(varName);
    if (!perBlock) return [];
    const s = perBlock.get(blockId);
    return s ? [...s] : [];
  }

  /**
   * Build complete def-use chains for a variable by connecting each definition
   * to the uses it can reach via reaching definitions.
   *
   * A use U in block B is linked to definition D if:
   * - D is in the reaching-definitions set at B's entry and no redefinition of the
   *   same variable occurs in B before U, **or**
   * - D is in the same block as U and is the last definition before U in statement order.
   *
   * @param varName - The variable name to build chains for.
   * @returns Array of DefUseChains (one per definition).
   */
  getChains(varName: string): DefUseChain[] {
    const allDefs = this.getDefinitions(varName);
    if (allDefs.length === 0) return [];

    // Build a map: DefSite -> UseSite[] for accumulation.
    const chainMap = new Map<DefSite, UseSite[]>();
    for (const def of allDefs) {
      chainMap.set(def, []);
    }

    const allUses = this.getUses(varName);

    for (const use of allUses) {
      const reachingAtBlock = this.getActiveDefsAtUse(varName, use);
      for (const def of reachingAtBlock) {
        chainMap.get(def)?.push(use);
      }
    }

    const chains: DefUseChain[] = [];
    for (const [def, uses] of chainMap) {
      chains.push({ def, uses });
    }
    return chains;
  }

  /**
   * Get all variable names found during the build phase.
   * @returns Array of unique variable names (sorted alphabetically).
   */
  getAllVariables(): string[] {
    const vars = new Set<string>();
    for (const key of this.defs.keys()) vars.add(key);
    for (const key of this.uses.keys()) vars.add(key);
    return [...vars].sort();
  }

  // ──────────────────────────────────────────────
  // Private — scanning
  // ──────────────────────────────────────────────

  /**
   * Recursively scan an AST node for definitions and uses.
   * Stops recursion at nested function boundaries (function declarations,
   * arrow functions, method declarations) to keep analysis intraprocedural.
   */
  private scanNode(
    node: ts.Node,
    blockId: number,
    stmtIdx: number,
    insideCondition: boolean,
  ): void {
    // Definitions
    this.scanForDefs(node, blockId, stmtIdx);
    // Uses
    this.scanForUses(node, blockId, stmtIdx, insideCondition);
  }

  /**
   * Walk the node tree looking for definition sites.
   * Does NOT recurse into nested function/arrow/method declarations.
   */
  private scanForDefs(node: ts.Node, blockId: number, stmtIdx: number): void {
    this.visitForDefs(node, blockId, stmtIdx);
  }

  /** Recursive visitor for definitions. */
  private visitForDefs(node: ts.Node, blockId: number, stmtIdx: number): void {
    // Do not recurse into nested function boundaries.
    if (this.isNestedFunctionBoundary(node)) return;

    // Variable declaration: `let x = ...` / `const x = ...` / `var x = ...`
    if (ts.isVariableDeclaration(node)) {
      if (ts.isIdentifier(node.name)) {
        this.addDef({
          varName: node.name.text,
          blockId,
          statementIndex: stmtIdx,
          node,
          kind: 'declaration',
        });
      } else if (ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name)) {
        this.extractBindingPatternDefs(node.name, blockId, stmtIdx, 'destructuring');
      }
      // Still recurse into the initializer for nested defs (rare but possible).
      if (node.initializer) {
        this.visitForDefs(node.initializer, blockId, stmtIdx);
      }
      return;
    }

    // Assignment: `x = expr`
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      if (ts.isIdentifier(node.left)) {
        this.addDef({
          varName: node.left.text,
          blockId,
          statementIndex: stmtIdx,
          node,
          kind: 'assignment',
        });
      } else if (
        ts.isObjectBindingPattern(node.left as ts.Node) ||
        ts.isArrayBindingPattern(node.left as ts.Node)
      ) {
        // Destructuring assignment: `[a, b] = expr`
        this.extractDestructuringAssignmentDefs(node.left, blockId, stmtIdx);
      }
      // Recurse into the right side.
      this.visitForDefs(node.right, blockId, stmtIdx);
      return;
    }

    // Compound assignment operators: +=, -=, *=, etc.
    if (ts.isBinaryExpression(node) && this.isCompoundAssignment(node.operatorToken.kind)) {
      if (ts.isIdentifier(node.left)) {
        this.addDef({
          varName: node.left.text,
          blockId,
          statementIndex: stmtIdx,
          node,
          kind: 'assignment',
        });
      }
      this.visitForDefs(node.right, blockId, stmtIdx);
      return;
    }

    // Prefix/postfix increment/decrement: `++x`, `x--`
    if (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) {
      if (
        (node.operator === ts.SyntaxKind.PlusPlusToken ||
          node.operator === ts.SyntaxKind.MinusMinusToken) &&
        ts.isIdentifier(node.operand)
      ) {
        this.addDef({
          varName: node.operand.text,
          blockId,
          statementIndex: stmtIdx,
          node,
          kind: 'assignment',
        });
      }
    }

    // Parameter declaration
    if (ts.isParameter(node)) {
      if (ts.isIdentifier(node.name)) {
        this.addDef({
          varName: node.name.text,
          blockId,
          statementIndex: stmtIdx,
          node,
          kind: 'param',
        });
      } else if (ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name)) {
        this.extractBindingPatternDefs(node.name, blockId, stmtIdx, 'destructuring');
      }
      return;
    }

    // for-of / for-in binding: `for (const x of iterable)`
    if (ts.isForOfStatement(node) || ts.isForInStatement(node)) {
      this.extractForBindingDefs(node.initializer, blockId, stmtIdx);
      // Recurse into the body (but not the expression — that's a use handled separately).
      return;
    }

    // catch clause: `catch (e) { ... }`
    if (ts.isCatchClause(node) && node.variableDeclaration) {
      if (ts.isIdentifier(node.variableDeclaration.name)) {
        this.addDef({
          varName: node.variableDeclaration.name.text,
          blockId,
          statementIndex: stmtIdx,
          node: node.variableDeclaration,
          kind: 'catch-binding',
        });
      }
      return;
    }

    // Import declaration: `import { a, b } from 'mod'`
    if (ts.isImportDeclaration(node)) {
      this.extractImportDefs(node, blockId, stmtIdx);
      return;
    }

    // Function declarations define their name in the enclosing scope.
    if (ts.isFunctionDeclaration(node) && node.name) {
      this.addDef({
        varName: node.name.text,
        blockId,
        statementIndex: stmtIdx,
        node,
        kind: 'declaration',
      });
      // Do NOT recurse into the function body.
      return;
    }

    // Recurse into children.
    ts.forEachChild(node, (child) => this.visitForDefs(child, blockId, stmtIdx));
  }

  /**
   * Walk the node tree looking for use sites.
   * Does NOT recurse into nested function/arrow/method declarations.
   */
  private scanForUses(
    node: ts.Node,
    blockId: number,
    stmtIdx: number,
    insideCondition: boolean,
  ): void {
    this.visitForUses(node, blockId, stmtIdx, insideCondition);
  }

  /** Recursive visitor for uses. */
  private visitForUses(
    node: ts.Node,
    blockId: number,
    stmtIdx: number,
    insideCondition: boolean,
  ): void {
    if (this.isNestedFunctionBoundary(node)) return;

    // Identifier — the core use detection point.
    if (ts.isIdentifier(node)) {
      // Skip if this identifier is a definition target.
      if (this.isDefTarget(node)) return;
      // Skip property name positions (e.g., `obj.prop` — `prop` is not a use of a variable).
      if (this.isPropertyName(node)) return;
      // Skip label identifiers.
      if (this.isLabel(node)) return;
      // Skip type-only positions.
      if (this.isTypePosition(node)) return;

      const kind = this.classifyUse(node, insideCondition);
      this.addUse({
        varName: node.text,
        blockId,
        statementIndex: stmtIdx,
        node,
        kind,
      });
      return;
    }

    // Propagate condition context into sub-expressions.
    let childInsideCondition = insideCondition;
    if (
      ts.isIfStatement(node) ||
      ts.isWhileStatement(node) ||
      ts.isDoStatement(node) ||
      ts.isConditionalExpression(node)
    ) {
      // The condition sub-expression gets the condition flag.
      const condExpr =
        ts.isConditionalExpression(node) ? node.condition : (node as ts.IfStatement).expression;
      if (condExpr) {
        this.visitForUses(condExpr, blockId, stmtIdx, /* insideCondition */ true);
      }
      // Recurse into remaining children with the outer context.
      ts.forEachChild(node, (child) => {
        if (child !== condExpr) {
          this.visitForUses(child, blockId, stmtIdx, childInsideCondition);
        }
      });
      return;
    }

    if (ts.isForStatement(node) && node.condition) {
      this.visitForUses(node.condition, blockId, stmtIdx, /* insideCondition */ true);
      ts.forEachChild(node, (child) => {
        if (child !== node.condition) {
          this.visitForUses(child, blockId, stmtIdx, childInsideCondition);
        }
      });
      return;
    }

    // Default: recurse into children.
    ts.forEachChild(node, (child) => {
      this.visitForUses(child, blockId, stmtIdx, childInsideCondition);
    });
  }

  // ──────────────────────────────────────────────
  // Private — definition extraction helpers
  // ──────────────────────────────────────────────

  /** Extract variable names from binding patterns (`{ a, b: c }` or `[x, y]`). */
  private extractBindingPatternDefs(
    pattern: ts.BindingPattern,
    blockId: number,
    stmtIdx: number,
    kind: DefSite['kind'],
  ): void {
    for (const element of pattern.elements) {
      if (ts.isOmittedExpression(element)) continue;
      const bindingElem = element as ts.BindingElement;
      if (ts.isIdentifier(bindingElem.name)) {
        this.addDef({
          varName: bindingElem.name.text,
          blockId,
          statementIndex: stmtIdx,
          node: bindingElem,
          kind,
        });
      } else if (
        ts.isObjectBindingPattern(bindingElem.name) ||
        ts.isArrayBindingPattern(bindingElem.name)
      ) {
        this.extractBindingPatternDefs(bindingElem.name, blockId, stmtIdx, kind);
      }
    }
  }

  /**
   * Extract definitions from destructuring assignment LHS.
   * Handles patterns like `[a, b] = [1, 2]` and `({ x, y } = obj)`.
   */
  private extractDestructuringAssignmentDefs(
    lhs: ts.Expression,
    blockId: number,
    stmtIdx: number,
  ): void {
    if (ts.isArrayLiteralExpression(lhs)) {
      for (const elem of lhs.elements) {
        if (ts.isIdentifier(elem)) {
          this.addDef({
            varName: elem.text,
            blockId,
            statementIndex: stmtIdx,
            node: elem,
            kind: 'destructuring',
          });
        } else if (ts.isArrayLiteralExpression(elem) || ts.isObjectLiteralExpression(elem)) {
          this.extractDestructuringAssignmentDefs(elem, blockId, stmtIdx);
        }
      }
    } else if (ts.isObjectLiteralExpression(lhs)) {
      for (const prop of lhs.properties) {
        if (ts.isShorthandPropertyAssignment(prop)) {
          this.addDef({
            varName: prop.name.text,
            blockId,
            statementIndex: stmtIdx,
            node: prop,
            kind: 'destructuring',
          });
        } else if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.initializer)) {
          this.addDef({
            varName: prop.initializer.text,
            blockId,
            statementIndex: stmtIdx,
            node: prop,
            kind: 'destructuring',
          });
        }
      }
    }
  }

  /** Extract bindings from `for (const x of ...)` or `for (const x in ...)`. */
  private extractForBindingDefs(
    initializer: ts.ForInitializer,
    blockId: number,
    stmtIdx: number,
  ): void {
    if (ts.isVariableDeclarationList(initializer)) {
      for (const decl of initializer.declarations) {
        if (ts.isIdentifier(decl.name)) {
          this.addDef({
            varName: decl.name.text,
            blockId,
            statementIndex: stmtIdx,
            node: decl,
            kind: 'for-binding',
          });
        } else if (
          ts.isObjectBindingPattern(decl.name) ||
          ts.isArrayBindingPattern(decl.name)
        ) {
          this.extractBindingPatternDefs(decl.name, blockId, stmtIdx, 'for-binding');
        }
      }
    }
  }

  /** Extract bindings from import declarations. */
  private extractImportDefs(
    node: ts.ImportDeclaration,
    blockId: number,
    stmtIdx: number,
  ): void {
    const clause = node.importClause;
    if (!clause) return;

    // Default import: `import Foo from 'mod'`
    if (clause.name) {
      this.addDef({
        varName: clause.name.text,
        blockId,
        statementIndex: stmtIdx,
        node: clause,
        kind: 'import',
      });
    }

    // Named/namespace bindings
    if (clause.namedBindings) {
      if (ts.isNamespaceImport(clause.namedBindings)) {
        // `import * as ns from 'mod'`
        this.addDef({
          varName: clause.namedBindings.name.text,
          blockId,
          statementIndex: stmtIdx,
          node: clause.namedBindings,
          kind: 'import',
        });
      } else if (ts.isNamedImports(clause.namedBindings)) {
        // `import { a, b as c } from 'mod'`
        for (const spec of clause.namedBindings.elements) {
          this.addDef({
            varName: spec.name.text,
            blockId,
            statementIndex: stmtIdx,
            node: spec,
            kind: 'import',
          });
        }
      }
    }
  }

  // ──────────────────────────────────────────────
  // Private — use classification helpers
  // ──────────────────────────────────────────────

  /**
   * Classify an identifier use based on its syntactic context.
   */
  private classifyUse(node: ts.Identifier, insideCondition: boolean): UseSite['kind'] {
    const parent = node.parent;
    if (!parent) return 'read';

    // Return statement: `return x`
    if (ts.isReturnStatement(parent) && parent.expression === node) {
      return 'return';
    }

    // Call argument: `foo(x)`
    if (ts.isCallExpression(parent) && parent.arguments.includes(node as ts.Expression)) {
      return 'call-arg';
    }

    // New expression argument: `new Foo(x)`
    if (ts.isNewExpression(parent) && parent.arguments?.includes(node as ts.Expression)) {
      return 'call-arg';
    }

    // Property access: `x.prop` — x is the object being accessed.
    if (ts.isPropertyAccessExpression(parent) && parent.expression === node) {
      return 'property-access';
    }

    // Element access: `x[0]`
    if (ts.isElementAccessExpression(parent) && parent.expression === node) {
      return 'property-access';
    }

    // Condition context.
    if (insideCondition) {
      return 'condition';
    }

    return 'read';
  }

  /**
   * Check if an identifier is the definition target (left side of assignment,
   * variable declaration name, parameter name, etc.).
   */
  private isDefTarget(node: ts.Identifier): boolean {
    const parent = node.parent;
    if (!parent) return false;

    // Variable declaration name.
    if (ts.isVariableDeclaration(parent) && parent.name === node) return true;

    // Left side of assignment.
    if (
      ts.isBinaryExpression(parent) &&
      parent.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      parent.left === node
    ) {
      return true;
    }

    // Compound assignment left side.
    if (ts.isBinaryExpression(parent) && this.isCompoundAssignment(parent.operatorToken.kind) && parent.left === node) {
      return true;
    }

    // Parameter name.
    if (ts.isParameter(parent) && parent.name === node) return true;

    // Binding element name.
    if (ts.isBindingElement(parent) && parent.name === node) return true;

    // Function declaration name.
    if (ts.isFunctionDeclaration(parent) && parent.name === node) return true;

    // Import specifier name (the local binding, not the imported name).
    if (ts.isImportSpecifier(parent) && parent.name === node) return true;

    // Catch variable.
    if (ts.isVariableDeclaration(parent) && parent.name === node && ts.isCatchClause(parent.parent)) {
      return true;
    }

    // Prefix/postfix increment/decrement.
    if (
      (ts.isPrefixUnaryExpression(parent) || ts.isPostfixUnaryExpression(parent)) &&
      (parent.operator === ts.SyntaxKind.PlusPlusToken ||
        parent.operator === ts.SyntaxKind.MinusMinusToken) &&
      parent.operand === node
    ) {
      return true;
    }

    return false;
  }

  /**
   * Check if an identifier is a property name (the `.prop` in `obj.prop`).
   */
  private isPropertyName(node: ts.Identifier): boolean {
    const parent = node.parent;
    if (!parent) return false;

    // `obj.prop` — prop is the name, not a variable read.
    if (ts.isPropertyAccessExpression(parent) && parent.name === node) return true;

    // Property assignment name: `{ key: value }` — key is not a variable read.
    if (ts.isPropertyAssignment(parent) && parent.name === node) return true;

    // Method declaration name.
    if (ts.isMethodDeclaration(parent) && parent.name === node) return true;

    // Shorthand property in non-destructuring context: `{ x }` in object literal.
    // Note: shorthand properties are both a use and a name, so we do NOT skip them.

    return false;
  }

  /** Check if an identifier is a label (e.g., `myLabel:` or `break myLabel`). */
  private isLabel(node: ts.Identifier): boolean {
    const parent = node.parent;
    if (!parent) return false;
    if (ts.isLabeledStatement(parent) && parent.label === node) return true;
    if (ts.isBreakOrContinueStatement(parent) && parent.label === node) return true;
    return false;
  }

  /** Check if an identifier is in a type-only position (type annotations, generics). */
  private isTypePosition(node: ts.Identifier): boolean {
    let current: ts.Node = node;
    while (current.parent) {
      const p = current.parent;
      if (ts.isTypeNode(p) || ts.isTypeAliasDeclaration(p) || ts.isInterfaceDeclaration(p)) {
        return true;
      }
      // Type parameter
      if (ts.isTypeParameterDeclaration(p)) return true;
      // Type argument list (the `<T>` in `foo<T>()`)
      if (ts.isTypeReferenceNode(p)) return true;
      // Heritage clauses (implements, extends) with type references
      if (ts.isHeritageClause(p)) return true;
      current = p;
    }
    return false;
  }

  /** Check whether a node is a nested function boundary we should NOT recurse into. */
  private isNestedFunctionBoundary(node: ts.Node): boolean {
    return (
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isGetAccessorDeclaration(node) ||
      ts.isSetAccessorDeclaration(node) ||
      // For function declarations, we still register the name as a def (handled above)
      // but we do not recurse into the body.
      (ts.isFunctionDeclaration(node) && node.body !== undefined)
    );
  }

  /** Check if an operator token kind is a compound assignment (+=, -=, etc.). */
  private isCompoundAssignment(kind: ts.SyntaxKind): boolean {
    return (
      kind === ts.SyntaxKind.PlusEqualsToken ||
      kind === ts.SyntaxKind.MinusEqualsToken ||
      kind === ts.SyntaxKind.AsteriskEqualsToken ||
      kind === ts.SyntaxKind.SlashEqualsToken ||
      kind === ts.SyntaxKind.PercentEqualsToken ||
      kind === ts.SyntaxKind.AmpersandEqualsToken ||
      kind === ts.SyntaxKind.BarEqualsToken ||
      kind === ts.SyntaxKind.CaretEqualsToken ||
      kind === ts.SyntaxKind.LessThanLessThanEqualsToken ||
      kind === ts.SyntaxKind.GreaterThanGreaterThanEqualsToken ||
      kind === ts.SyntaxKind.GreaterThanGreaterThanGreaterThanEqualsToken ||
      kind === ts.SyntaxKind.AsteriskAsteriskEqualsToken ||
      kind === ts.SyntaxKind.BarBarEqualsToken ||
      kind === ts.SyntaxKind.AmpersandAmpersandEqualsToken ||
      kind === ts.SyntaxKind.QuestionQuestionEqualsToken
    );
  }

  // ──────────────────────────────────────────────
  // Private — reaching definitions helpers
  // ──────────────────────────────────────────────

  /**
   * Compute GEN and KILL sets for a single block.
   *
   * - **GEN[B]**: the last definition of each variable in block B (since earlier
   *   definitions in the same block are killed by the later one).
   * - **KILL[B]**: the set of variable names that are defined anywhere in B
   *   (their definitions from other blocks are killed).
   */
  private computeGenKill(blockId: number): BlockGenKill {
    const defs = this.getBlockDefs(blockId);
    const gen = new Map<string, DefSite>();
    const kill = new Set<string>();

    // Walk defs in statement order; later defs overwrite earlier ones in GEN.
    for (const def of defs) {
      gen.set(def.varName, def);
      kill.add(def.varName);
    }

    return { gen, kill };
  }

  /**
   * Determine which definitions are active (reaching) at a specific use site.
   *
   * If the use is in block B at statement index S:
   * - Check if there is a definition of the same variable in B at statement index < S.
   *   If so, only the latest such definition reaches this use.
   * - Otherwise, use the reaching definitions at the entry of B.
   */
  private getActiveDefsAtUse(varName: string, use: UseSite): DefSite[] {
    const blockDefs = this.getBlockDefs(use.blockId).filter(
      (d) => d.varName === varName && d.statementIndex < use.statementIndex,
    );

    if (blockDefs.length > 0) {
      // The last definition before this use in the same block is the active one.
      const lastDef = blockDefs[blockDefs.length - 1];
      return [lastDef];
    }

    // No local def before this use — reaching definitions from block entry apply.
    if (this.reachingDefsComputed) {
      return this.getReachingDefs(varName, use.blockId);
    }

    // Fallback if reaching defs not computed: return all definitions of this variable.
    return this.getDefinitions(varName);
  }

  // ──────────────────────────────────────────────
  // Private — map management
  // ──────────────────────────────────────────────

  /** Register a definition site in all relevant maps. */
  private addDef(def: DefSite): void {
    // Per-variable map.
    let varDefs = this.defs.get(def.varName);
    if (!varDefs) {
      varDefs = [];
      this.defs.set(def.varName, varDefs);
    }
    varDefs.push(def);

    // Per-block map.
    let bDefs = this.blockDefs.get(def.blockId);
    if (!bDefs) {
      bDefs = [];
      this.blockDefs.set(def.blockId, bDefs);
    }
    bDefs.push(def);
  }

  /** Register a use site in all relevant maps. */
  private addUse(use: UseSite): void {
    // Per-variable map.
    let varUses = this.uses.get(use.varName);
    if (!varUses) {
      varUses = [];
      this.uses.set(use.varName, varUses);
    }
    varUses.push(use);

    // Per-block map.
    let bUses = this.blockUses.get(use.blockId);
    if (!bUses) {
      bUses = [];
      this.blockUses.set(use.blockId, bUses);
    }
    bUses.push(use);
  }

  /** Clear all internal state for a fresh analysis. */
  private clear(): void {
    this.defs.clear();
    this.uses.clear();
    this.blockDefs.clear();
    this.blockUses.clear();
    this.reachingDefs.clear();
    this.reachingDefsComputed = false;
  }
}

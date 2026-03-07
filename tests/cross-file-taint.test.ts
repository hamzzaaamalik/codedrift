/**
 * Cross-file taint analysis system tests.
 *
 * Tests the core layers: AccessPath, HeapModel, CFGBuilder,
 * SummaryBuilder, SummaryResolver, ModuleResolver, FlowRenderer,
 * and a multi-file integration scenario.
 */

import { describe, it, expect } from 'vitest';
import * as ts from 'typescript';

import { AccessPath, WildcardAccessPath } from '../src/core/taint/heap/access-path.js';
import { HeapModel } from '../src/core/taint/heap/heap-model.js';
import { CFGBuilder } from '../src/core/taint/cfg/cfg-builder.js';
import { SummaryBuilder } from '../src/core/taint/summaries/summary-builder.js';
import { SummaryStore } from '../src/core/taint/summaries/summary-store.js';
import { SummaryResolver } from '../src/core/taint/summaries/summary-resolver.js';
import { ModuleResolver } from '../src/core/taint/graph/module-resolver.js';
import { FlowRenderer } from '../src/core/taint/reporting/flow-renderer.js';

import type { FunctionSummary, SummaryInput, SummaryTransfer, SummarySinkHit, SummaryCallEdge } from '../src/core/taint/summaries/summary-types.js';
import type { TaintQueryResult, TraceStep } from '../src/core/taint/query/taint-query.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseCode(code: string, fileName = 'test.ts'): ts.SourceFile {
  return ts.createSourceFile(fileName, code, ts.ScriptTarget.Latest, true);
}

function getFirstFunction(sf: ts.SourceFile): ts.FunctionDeclaration {
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt)) return stmt;
  }
  throw new Error('No function found');
}

function getFirstExpression(sf: ts.SourceFile): ts.Expression {
  for (const stmt of sf.statements) {
    if (ts.isExpressionStatement(stmt)) return stmt.expression;
  }
  throw new Error('No expression statement found');
}

/** Create a minimal valid FunctionSummary stub for resolver tests. */
function makeSummary(overrides: Partial<FunctionSummary> & { canonicalId: string; filePath: string }): FunctionSummary {
  return {
    functionName: overrides.canonicalId.split('#')[1] ?? 'anon',
    paramCount: 1,
    paramNames: ['x'],
    isAsync: false,
    isExported: true,
    isConstructor: false,
    transfers: [],
    sinkHits: [],
    callEdges: [],
    taintSources: [],
    isSanitizer: false,
    bodyHash: 'deadbeef',
    isComplete: true,
    ...overrides,
  };
}

function makeParamInput(index: number, label?: string): SummaryInput {
  return { kind: 'param', paramIndex: index, label: label ?? `param[${index}]` };
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. AccessPath
// ═══════════════════════════════════════════════════════════════════════════

describe('AccessPath', () => {
  describe('fromExpression', () => {
    it('parses an identifier', () => {
      const sf = parseCode('req;');
      const expr = getFirstExpression(sf);
      const ap = AccessPath.fromExpression(expr);
      expect(ap).not.toBeNull();
      expect(ap!.root).toBe('req');
      expect(ap!.fields).toEqual([]);
    });

    it('parses a property access chain', () => {
      const sf = parseCode('req.body.name;');
      const expr = getFirstExpression(sf);
      const ap = AccessPath.fromExpression(expr);
      expect(ap).not.toBeNull();
      expect(ap!.root).toBe('req');
      expect(ap!.fields).toEqual(['body', 'name']);
    });

    it('parses element access with string literal', () => {
      const sf = parseCode('obj["key"];');
      const expr = getFirstExpression(sf);
      const ap = AccessPath.fromExpression(expr);
      expect(ap).not.toBeNull();
      expect(ap!.root).toBe('obj');
      expect(ap!.fields).toEqual(['key']);
    });

    it('parses element access with numeric literal', () => {
      const sf = parseCode('arr[0];');
      const expr = getFirstExpression(sf);
      const ap = AccessPath.fromExpression(expr);
      expect(ap).not.toBeNull();
      expect(ap!.fields).toEqual(['0']);
    });

    it('uses wildcard for dynamic element access', () => {
      const sf = parseCode('arr[i];');
      const expr = getFirstExpression(sf);
      const ap = AccessPath.fromExpression(expr);
      expect(ap).not.toBeNull();
      expect(ap!.fields).toEqual(['[*]']);
    });

    it('returns null for unsupported expressions', () => {
      const sf = parseCode('1 + 2;');
      const expr = getFirstExpression(sf);
      const ap = AccessPath.fromExpression(expr);
      expect(ap).toBeNull();
    });
  });

  describe('startsWith', () => {
    it('returns true when path starts with prefix', () => {
      const full = new AccessPath('req', ['body', 'name']);
      const prefix = new AccessPath('req', ['body']);
      expect(full.startsWith(prefix)).toBe(true);
    });

    it('returns true for exact match', () => {
      const a = new AccessPath('req', ['body']);
      const b = new AccessPath('req', ['body']);
      expect(a.startsWith(b)).toBe(true);
    });

    it('returns false when prefix is longer', () => {
      const short = new AccessPath('req', ['body']);
      const long = new AccessPath('req', ['body', 'name']);
      expect(short.startsWith(long)).toBe(false);
    });

    it('returns false for different roots', () => {
      const a = new AccessPath('req', ['body']);
      const b = new AccessPath('res', ['body']);
      expect(a.startsWith(b)).toBe(false);
    });
  });

  describe('parent', () => {
    it('returns parent by removing last field', () => {
      const ap = new AccessPath('req', ['body', 'name']);
      const p = ap.parent();
      expect(p).not.toBeNull();
      expect(p!.toString()).toBe('req.body');
    });

    it('returns null for a root path', () => {
      const ap = new AccessPath('x', []);
      expect(ap.parent()).toBeNull();
    });
  });

  describe('append', () => {
    it('appends a field to the path', () => {
      const ap = new AccessPath('req', ['body']);
      const extended = ap.append('name');
      expect(extended.toString()).toBe('req.body.name');
    });
  });

  describe('equals', () => {
    it('returns true for structurally equal paths', () => {
      const a = new AccessPath('req', ['body', 'name']);
      const b = new AccessPath('req', ['body', 'name']);
      expect(a.equals(b)).toBe(true);
    });

    it('returns false for different paths', () => {
      const a = new AccessPath('req', ['body']);
      const b = new AccessPath('req', ['query']);
      expect(a.equals(b)).toBe(false);
    });
  });

  describe('toString', () => {
    it('returns root for root-only path', () => {
      expect(new AccessPath('x', []).toString()).toBe('x');
    });

    it('returns dotted path', () => {
      expect(new AccessPath('req', ['body', 'id']).toString()).toBe('req.body.id');
    });
  });

  describe('WildcardAccessPath', () => {
    it('matches any single field in wildcard position', () => {
      const wild = AccessPath.wildcard('req', ['body']);
      const concrete = new AccessPath('req', ['body', 'name']);
      expect(wild.matches(concrete)).toBe(true);
    });

    it('does not match different depth', () => {
      const wild = AccessPath.wildcard('req', ['body']);
      const deep = new AccessPath('req', ['body', 'name', 'first']);
      expect(wild.matches(deep)).toBe(false);
    });

    it('does not match different root', () => {
      const wild = AccessPath.wildcard('req', ['body']);
      const other = new AccessPath('res', ['body', 'name']);
      expect(wild.matches(other)).toBe(false);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. HeapModel
// ═══════════════════════════════════════════════════════════════════════════

describe('HeapModel', () => {
  describe('taint + isTainted', () => {
    it('marks a path as tainted', () => {
      const heap = new HeapModel();
      const path = new AccessPath('req', ['body']);
      heap.taint(path, ['src1']);
      expect(heap.isTainted(path)).toBe(true);
    });

    it('is not tainted when nothing has been marked', () => {
      const heap = new HeapModel();
      const path = new AccessPath('x', []);
      expect(heap.isTainted(path)).toBe(false);
    });

    it('merges taint sources on re-taint', () => {
      const heap = new HeapModel();
      const path = new AccessPath('x', []);
      heap.taint(path, ['a']);
      heap.taint(path, ['b']);
      const sources = heap.getTaintSources(path);
      expect(sources).toContain('a');
      expect(sources).toContain('b');
    });
  });

  describe('parent inheritance', () => {
    it('child inherits taint from tainted parent', () => {
      const heap = new HeapModel();
      const parent = new AccessPath('req', ['body']);
      heap.taint(parent, ['src1']);
      const child = new AccessPath('req', ['body', 'name']);
      expect(heap.isTainted(child)).toBe(true);
    });

    it('parent is not tainted by child', () => {
      const heap = new HeapModel();
      const child = new AccessPath('req', ['body', 'name']);
      heap.taint(child, ['src1']);
      const parent = new AccessPath('req', ['body']);
      expect(heap.isTainted(parent)).toBe(false);
    });
  });

  describe('sanitize', () => {
    it('sanitizing a tainted path removes taint', () => {
      const heap = new HeapModel();
      const path = new AccessPath('x', []);
      heap.taint(path, ['src1']);
      heap.sanitize(path, 'type-coercion');
      expect(heap.isTainted(path)).toBe(false);
    });

    it('sanitizing a parent also sanitizes children', () => {
      const heap = new HeapModel();
      const parent = new AccessPath('obj', []);
      const child = new AccessPath('obj', ['field']);
      heap.taint(parent, ['src1']);
      heap.taint(child, ['src2']);
      heap.sanitize(parent, 'escape');
      expect(heap.isTainted(child)).toBe(false);
    });

    it('query returns sanitized state', () => {
      const heap = new HeapModel();
      const path = new AccessPath('x', []);
      heap.taint(path, ['src1']);
      heap.sanitize(path, 'type-coercion');
      const state = heap.query(path);
      expect(state).not.toBeNull();
      expect(state!.sanitized).toBe(true);
      expect(state!.appliedSanitizations).toContain('type-coercion');
    });
  });

  describe('alias', () => {
    it('aliased path inherits taint from source', () => {
      const heap = new HeapModel();
      const a = new AccessPath('a', []);
      const b = new AccessPath('b', []);
      heap.taint(a, ['src1']);
      heap.alias(b, a);
      expect(heap.isTainted(b)).toBe(true);
    });

    it('aliased path field inherits taint from source field', () => {
      const heap = new HeapModel();
      const a = new AccessPath('a', ['x']);
      const b = new AccessPath('b', []);
      heap.taint(a, ['src1']);
      heap.alias(b, new AccessPath('a', []));
      // b.x should be tainted because b -> a and a.x is tainted
      const bx = new AccessPath('b', ['x']);
      expect(heap.isTainted(bx)).toBe(true);
    });
  });

  describe('destructure', () => {
    it('destructured bindings inherit field taint from source', () => {
      const heap = new HeapModel();
      const obj = new AccessPath('obj', []);
      heap.taint(obj, ['src1']);
      heap.destructure(
        [
          { localName: 'x', fieldName: 'x' },
          { localName: 'y', fieldName: 'y' },
        ],
        obj,
      );
      expect(heap.isTainted(new AccessPath('x', []))).toBe(true);
      expect(heap.isTainted(new AccessPath('y', []))).toBe(true);
    });
  });

  describe('fork + join', () => {
    it('fork creates independent copy', () => {
      const heap = new HeapModel();
      const path = new AccessPath('x', []);
      heap.taint(path, ['src1']);
      const forked = heap.fork();
      // Taint new path only in forked
      forked.taint(new AccessPath('y', []), ['src2']);
      expect(heap.isTainted(new AccessPath('y', []))).toBe(false);
      expect(forked.isTainted(new AccessPath('y', []))).toBe(true);
    });

    it('join unions taint from both branches', () => {
      const heap = new HeapModel();
      const x = new AccessPath('x', []);
      heap.taint(x, ['src1']);

      const branchA = heap.fork();
      const branchB = heap.fork();

      branchA.taint(new AccessPath('a', []), ['srcA']);
      branchB.taint(new AccessPath('b', []), ['srcB']);

      const merged = HeapModel.join(branchA, branchB);
      expect(merged.isTainted(x)).toBe(true);
      expect(merged.isTainted(new AccessPath('a', []))).toBe(true);
      expect(merged.isTainted(new AccessPath('b', []))).toBe(true);
    });

    it('join requires both branches sanitized to mark as sanitized', () => {
      const heap = new HeapModel();
      const x = new AccessPath('x', []);
      heap.taint(x, ['src1']);

      const branchA = heap.fork();
      const branchB = heap.fork();

      branchA.sanitize(x, 'escape');
      // branchB does NOT sanitize

      const merged = HeapModel.join(branchA, branchB);
      // Should NOT be sanitized because only one branch sanitized
      expect(merged.isTainted(x)).toBe(true);
    });

    it('join marks as sanitized when both branches sanitize', () => {
      const heap = new HeapModel();
      const x = new AccessPath('x', []);
      heap.taint(x, ['src1']);

      const branchA = heap.fork();
      const branchB = heap.fork();

      branchA.sanitize(x, 'escape');
      branchB.sanitize(x, 'escape');

      const merged = HeapModel.join(branchA, branchB);
      expect(merged.isTainted(x)).toBe(false);
      const state = merged.query(x);
      expect(state!.sanitized).toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. CFGBuilder
// ═══════════════════════════════════════════════════════════════════════════

describe('CFGBuilder', () => {
  function buildCFG(code: string) {
    const sf = parseCode(code);
    const fn = getFirstFunction(sf);
    const builder = new CFGBuilder();
    return builder.build(fn);
  }

  describe('sequential function', () => {
    it('creates entry and exit blocks connected by edges', () => {
      const cfg = buildCFG('function f() { const x = 1; const y = 2; }');
      expect(cfg.blocks.size).toBeGreaterThanOrEqual(2);
      // Entry block should have statements
      const entry = cfg.blocks.get(cfg.entry)!;
      expect(entry.statements.length).toBeGreaterThan(0);
      expect(entry.reachable).toBe(true);
    });
  });

  describe('if/else', () => {
    it('creates branch edges with true/false labels', () => {
      const cfg = buildCFG('function f(x: boolean) { if (x) { a(); } else { b(); } }');
      // Should have at least entry, then, else, join, exit blocks
      expect(cfg.blocks.size).toBeGreaterThanOrEqual(3);
      // Find branch edges
      const branchEdges = cfg.edges.filter(e => e.label === 'true' || e.label === 'false');
      expect(branchEdges.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('loop', () => {
    it('creates a back-edge for while loop', () => {
      const cfg = buildCFG('function f() { while (true) { x(); } }');
      const backEdges = cfg.edges.filter(e => e.isBackEdge);
      expect(backEdges.length).toBeGreaterThanOrEqual(1);
    });

    it('creates a back-edge for for loop', () => {
      const cfg = buildCFG('function f() { for (let i = 0; i < 10; i++) { x(); } }');
      const backEdges = cfg.edges.filter(e => e.isBackEdge);
      expect(backEdges.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('return', () => {
    it('terminates block with return and edges to exit', () => {
      const cfg = buildCFG('function f() { return 42; }');
      const entry = cfg.blocks.get(cfg.entry)!;
      expect(entry.terminator).toBeDefined();
      expect(entry.terminator!.kind).toBe('return');
      // Should have edge to exit
      const toExit = cfg.edges.filter(e => e.to === cfg.exit);
      expect(toExit.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('reachability', () => {
    it('marks dead code after return as unreachable', () => {
      const cfg = buildCFG('function f() { return 1; const x = 2; }');
      // The block containing `const x = 2` should be unreachable
      let hasUnreachable = false;
      for (const block of cfg.blocks.values()) {
        if (!block.reachable && block.id !== cfg.exit && block.statements.length > 0) {
          hasUnreachable = true;
        }
      }
      expect(hasUnreachable).toBe(true);
    });

    it('entry block is always reachable', () => {
      const cfg = buildCFG('function f() { }');
      const entry = cfg.blocks.get(cfg.entry)!;
      expect(entry.reachable).toBe(true);
    });
  });

  describe('try/catch', () => {
    it('creates exception edge from try to catch', () => {
      const cfg = buildCFG('function f() { try { a(); } catch(e) { b(); } }');
      const exceptionEdges = cfg.edges.filter(e => e.label === 'exception');
      expect(exceptionEdges.length).toBeGreaterThanOrEqual(1);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. SummaryBuilder
// ═══════════════════════════════════════════════════════════════════════════

describe('SummaryBuilder', () => {
  const builder = new SummaryBuilder();

  function buildSummary(code: string, functionName = 'f'): FunctionSummary {
    const sf = parseCode(code, 'test.ts');
    const fn = getFirstFunction(sf);
    return builder.buildFunctionSummary(
      fn,
      `test.ts#${functionName}`,
      'test.ts',
      true,
    );
  }

  describe('param to return transfer', () => {
    it('detects param flowing to return', () => {
      const summary = buildSummary('function f(x: any) { return x; }');
      const returnTransfers = summary.transfers.filter(t => t.to.kind === 'return');
      expect(returnTransfers.length).toBeGreaterThanOrEqual(1);
      const fromParam0 = returnTransfers.find(
        t => t.from.kind === 'param' && t.from.paramIndex === 0,
      );
      expect(fromParam0).toBeDefined();
    });
  });

  describe('sink hit detection', () => {
    it('detects db.query with param as sink hit', () => {
      const summary = buildSummary(
        'function f(input: string) { db.query("SELECT * FROM t WHERE id = " + input); }',
      );
      expect(summary.sinkHits.length).toBeGreaterThanOrEqual(1);
      const dbHit = summary.sinkHits.find(h => h.sinkKind === 'db-query');
      expect(dbHit).toBeDefined();
      expect(dbHit!.input.kind).toBe('param');
    });
  });

  describe('sanitized transfer', () => {
    it('marks transfer as sanitized when parseInt is applied', () => {
      const summary = buildSummary(
        'function f(x: any) { const safe = parseInt(x); return safe; }',
      );
      const returnTransfers = summary.transfers.filter(
        t => t.to.kind === 'return' && t.from.kind === 'param' && t.from.paramIndex === 0,
      );
      // Either we have a sanitized transfer, or the function itself is a sanitizer
      const hasSanitization = returnTransfers.some(t => t.isSanitized || t.sanitizations.length > 0)
        || summary.isSanitizer;
      expect(hasSanitization).toBe(true);
    });
  });

  describe('call edge creation', () => {
    it('creates call edge when param is passed to another function', () => {
      const summary = buildSummary(
        'function f(data: any) { process(data); }',
      );
      expect(summary.callEdges.length).toBeGreaterThanOrEqual(1);
      const processEdge = summary.callEdges.find(e =>
        e.calleeCanonicalId.includes('process'),
      );
      expect(processEdge).toBeDefined();
    });
  });

  describe('taint source detection', () => {
    it('detects req.body as taint source in handler functions', () => {
      const summary = buildSummary(
        'function f(req: any, res: any) { const data = req.body; return data; }',
      );
      // The builder should detect req.body as a taint source or param[0] flowing to return
      const hasReqSource = summary.taintSources.some(
        s => s.kind === 'req.body',
      );
      const hasParam0Transfer = summary.transfers.some(
        t => t.from.kind === 'param' && t.from.paramIndex === 0,
      );
      expect(hasReqSource || hasParam0Transfer).toBe(true);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. SummaryResolver
// ═══════════════════════════════════════════════════════════════════════════

describe('SummaryResolver', () => {
  describe('one-hop resolution', () => {
    it('propagates sink hit from callee to caller', () => {
      const store = new SummaryStore();

      // B: param[0] hits db-query sink
      store.add(makeSummary({
        canonicalId: 'b.ts#processB',
        filePath: 'b.ts',
        functionName: 'processB',
        sinkHits: [{
          input: makeParamInput(0),
          sinkKind: 'db-query',
          sinkCallee: 'db.query',
          sanitized: false,
          sanitizations: [],
          line: 5,
        }],
      }));

      // A: calls B, mapping param[0] -> B's param[0]
      store.add(makeSummary({
        canonicalId: 'a.ts#handleA',
        filePath: 'a.ts',
        functionName: 'handleA',
        callEdges: [{
          calleeCanonicalId: 'b.ts#processB',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 3,
        }],
      }));

      const resolver = new SummaryResolver(store);
      const stats = resolver.resolve();

      expect(stats.sinkHitsAdded).toBeGreaterThanOrEqual(1);
      const aSummary = store.get('a.ts#handleA')!;
      expect(aSummary.sinkHits.length).toBeGreaterThanOrEqual(1);
      const transitiveHit = aSummary.sinkHits.find(h => h.sinkKind === 'db-query');
      expect(transitiveHit).toBeDefined();
    });
  });

  describe('two-hop resolution', () => {
    it('propagates sink hit across A -> B -> C chain', () => {
      const store = new SummaryStore();

      // C: param[0] hits db-query sink
      store.add(makeSummary({
        canonicalId: 'c.ts#runQuery',
        filePath: 'c.ts',
        functionName: 'runQuery',
        sinkHits: [{
          input: makeParamInput(0),
          sinkKind: 'db-query',
          sinkCallee: 'db.query',
          sanitized: false,
          sanitizations: [],
          line: 10,
        }],
      }));

      // B: calls C with param[0]
      store.add(makeSummary({
        canonicalId: 'b.ts#processB',
        filePath: 'b.ts',
        functionName: 'processB',
        callEdges: [{
          calleeCanonicalId: 'c.ts#runQuery',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 5,
        }],
      }));

      // A: calls B with param[0]
      store.add(makeSummary({
        canonicalId: 'a.ts#handleA',
        filePath: 'a.ts',
        functionName: 'handleA',
        callEdges: [{
          calleeCanonicalId: 'b.ts#processB',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 3,
        }],
      }));

      const resolver = new SummaryResolver(store);
      resolver.resolve();

      const aSummary = store.get('a.ts#handleA')!;
      const dbHit = aSummary.sinkHits.find(h => h.sinkKind === 'db-query');
      expect(dbHit).toBeDefined();
    });
  });

  describe('sanitization composition', () => {
    it('preserves sanitization flag when callee sanitizes', () => {
      const store = new SummaryStore();

      // B: param[0] hits sink, but sanitized
      store.add(makeSummary({
        canonicalId: 'b.ts#safeProcess',
        filePath: 'b.ts',
        functionName: 'safeProcess',
        sinkHits: [{
          input: makeParamInput(0),
          sinkKind: 'db-query',
          sinkCallee: 'db.query',
          sanitized: true,
          sanitizations: ['parameterized'],
          line: 5,
        }],
      }));

      // A: calls B
      store.add(makeSummary({
        canonicalId: 'a.ts#handleA',
        filePath: 'a.ts',
        functionName: 'handleA',
        callEdges: [{
          calleeCanonicalId: 'b.ts#safeProcess',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 3,
        }],
      }));

      const resolver = new SummaryResolver(store);
      resolver.resolve();

      const aSummary = store.get('a.ts#handleA')!;
      const hit = aSummary.sinkHits.find(h => h.sinkKind === 'db-query');
      expect(hit).toBeDefined();
      expect(hit!.sanitized).toBe(true);
      expect(hit!.sanitizations).toContain('parameterized');
    });
  });

  describe('cycle detection', () => {
    it('terminates without infinite loop on mutual recursion', () => {
      const store = new SummaryStore();

      // A calls B
      store.add(makeSummary({
        canonicalId: 'a.ts#funcA',
        filePath: 'a.ts',
        functionName: 'funcA',
        callEdges: [{
          calleeCanonicalId: 'b.ts#funcB',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 3,
        }],
      }));

      // B calls A
      store.add(makeSummary({
        canonicalId: 'b.ts#funcB',
        filePath: 'b.ts',
        functionName: 'funcB',
        callEdges: [{
          calleeCanonicalId: 'a.ts#funcA',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 5,
        }],
      }));

      const resolver = new SummaryResolver(store);
      // Should not hang — mutual recursion is handled by worklist convergence
      const stats = resolver.resolve();
      expect(stats.iterations).toBeGreaterThanOrEqual(1);
    });

    it('terminates on self-recursion', () => {
      const store = new SummaryStore();

      store.add(makeSummary({
        canonicalId: 'a.ts#recurse',
        filePath: 'a.ts',
        functionName: 'recurse',
        callEdges: [{
          calleeCanonicalId: 'a.ts#recurse',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 2,
        }],
        sinkHits: [{
          input: makeParamInput(0),
          sinkKind: 'command-execution',
          sinkCallee: 'exec',
          sanitized: false,
          sanitizations: [],
          line: 3,
        }],
      }));

      const resolver = new SummaryResolver(store);
      const stats = resolver.resolve();
      expect(stats.cyclesDetected).toBeGreaterThanOrEqual(1);
    });
  });

  describe('transfer composition', () => {
    it('composes callee return transfer into caller', () => {
      const store = new SummaryStore();

      // B: param[0] -> return
      store.add(makeSummary({
        canonicalId: 'b.ts#transform',
        filePath: 'b.ts',
        functionName: 'transform',
        transfers: [{
          from: makeParamInput(0),
          to: { kind: 'return', label: 'return' },
          sanitizations: [],
          isSanitized: false,
          confidence: 'definite',
        }],
      }));

      // A: calls B with param[0], assigns return to variable
      store.add(makeSummary({
        canonicalId: 'a.ts#handler',
        filePath: 'a.ts',
        functionName: 'handler',
        callEdges: [{
          calleeCanonicalId: 'b.ts#transform',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          returnMapping: { assignedTo: 'result' },
          line: 3,
        }],
      }));

      const resolver = new SummaryResolver(store);
      const stats = resolver.resolve();

      expect(stats.transfersAdded).toBeGreaterThanOrEqual(1);
      const aSummary = store.get('a.ts#handler')!;
      const returnTransfer = aSummary.transfers.find(
        t => t.from.kind === 'param' && t.from.paramIndex === 0 && t.to.kind === 'return',
      );
      expect(returnTransfer).toBeDefined();
    });
  });

  describe('cross-file flow extraction', () => {
    it('extracts flows across different files', () => {
      const store = new SummaryStore();

      // Sink function in file B
      store.add(makeSummary({
        canonicalId: 'b.ts#query',
        filePath: 'b.ts',
        functionName: 'query',
        sinkHits: [{
          input: makeParamInput(0),
          sinkKind: 'db-query',
          sinkCallee: 'db.query',
          sanitized: false,
          sanitizations: [],
          line: 5,
        }],
      }));

      // Caller in file A
      store.add(makeSummary({
        canonicalId: 'a.ts#handle',
        filePath: 'a.ts',
        functionName: 'handle',
        callEdges: [{
          calleeCanonicalId: 'b.ts#query',
          argMapping: [{
            callerInput: makeParamInput(0),
            calleeParamIndex: 0,
          }],
          line: 3,
        }],
      }));

      const resolver = new SummaryResolver(store);
      resolver.resolve();

      const flows = resolver.getCrossFileFlows();
      expect(flows.length).toBeGreaterThanOrEqual(1);
      const flow = flows[0];
      expect(flow.sinkHit.sinkKind).toBe('db-query');
      expect(flow.hops.length).toBeGreaterThanOrEqual(1);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. ModuleResolver
// ═══════════════════════════════════════════════════════════════════════════

describe('ModuleResolver', () => {
  describe('resolveSpecifier', () => {
    it('resolves relative path to absolute path', () => {
      const path = require('path');
      const root = path.resolve('/project');
      const fromFile = path.join(root, 'src', 'index.ts');
      const targetFile = path.join(root, 'src', 'utils.ts');
      const existingFiles = new Set([
        targetFile.replace(/\\/g, '/'),
      ]);
      const resolver = new ModuleResolver(
        root,
        new Set<string>(),
        (p) => existingFiles.has(p.replace(/\\/g, '/')),
      );
      const result = resolver.resolveSpecifier('./utils', fromFile);
      expect(result).not.toBeNull();
      expect(result!.replace(/\\/g, '/')).toContain('utils.ts');
    });

    it('returns null for bare specifier (external package)', () => {
      const path = require('path');
      const root = path.resolve('/project');
      const resolver = new ModuleResolver(
        root,
        new Set<string>(),
        () => false,
      );
      const result = resolver.resolveSpecifier('lodash', path.join(root, 'src', 'index.ts'));
      expect(result).toBeNull();
    });

    it('resolves path alias when configured', () => {
      const path = require('path');
      const root = path.resolve('/project');
      const fromFile = path.join(root, 'src', 'index.ts');
      const targetFile = path.join(root, 'src', 'components', 'button.ts');
      const existingFiles = new Set([
        targetFile.replace(/\\/g, '/'),
      ]);
      const resolver = new ModuleResolver(
        root,
        new Set(['@/']),
        (p) => existingFiles.has(p.replace(/\\/g, '/')),
      );
      const result = resolver.resolveSpecifier('@/components/button', fromFile);
      expect(result).not.toBeNull();
      expect(result!.replace(/\\/g, '/')).toContain('button.ts');
    });

    it('resolves index file in directory', () => {
      const path = require('path');
      const root = path.resolve('/project');
      const fromFile = path.join(root, 'src', 'app.ts');
      const targetFile = path.join(root, 'src', 'utils', 'index.ts');
      const existingFiles = new Set([
        targetFile.replace(/\\/g, '/'),
      ]);
      const resolver = new ModuleResolver(
        root,
        new Set<string>(),
        (p) => existingFiles.has(p.replace(/\\/g, '/')),
      );
      const result = resolver.resolveSpecifier('./utils', fromFile);
      expect(result).not.toBeNull();
      expect(result!.replace(/\\/g, '/')).toContain('index.ts');
    });
  });

  describe('collectBindings', () => {
    it('collects ES named imports', () => {
      const resolver = new ModuleResolver('/project', new Set<string>(), () => false);
      const sf = parseCode(
        'import { foo, bar as baz } from "./utils";',
        '/project/src/index.ts',
      );
      const result = resolver.collectBindings(sf);
      expect(result.imports.length).toBe(2);
      expect(result.imports[0].localName).toBe('foo');
      expect(result.imports[0].exportName).toBe('foo');
      expect(result.imports[0].style).toBe('named');
      expect(result.imports[1].localName).toBe('baz');
      expect(result.imports[1].exportName).toBe('bar');
    });

    it('collects default import', () => {
      const resolver = new ModuleResolver('/project', new Set<string>(), () => false);
      const sf = parseCode(
        'import MyModule from "./my-module";',
        '/project/src/index.ts',
      );
      const result = resolver.collectBindings(sf);
      const defaultImport = result.imports.find(i => i.style === 'default');
      expect(defaultImport).toBeDefined();
      expect(defaultImport!.localName).toBe('MyModule');
      expect(defaultImport!.exportName).toBe('default');
    });

    it('collects namespace import', () => {
      const resolver = new ModuleResolver('/project', new Set<string>(), () => false);
      const sf = parseCode(
        'import * as utils from "./utils";',
        '/project/src/index.ts',
      );
      const result = resolver.collectBindings(sf);
      const nsImport = result.imports.find(i => i.style === 'namespace');
      expect(nsImport).toBeDefined();
      expect(nsImport!.localName).toBe('utils');
      expect(nsImport!.exportName).toBe('*');
    });

    it('collects exported function declarations', () => {
      const resolver = new ModuleResolver('/project', new Set<string>(), () => false);
      const sf = parseCode(
        'export function myFunc() { return 1; }',
        '/project/src/index.ts',
      );
      const result = resolver.collectBindings(sf);
      const exp = result.exports.find(e => e.exportName === 'myFunc');
      expect(exp).toBeDefined();
    });

    it('collects re-exports', () => {
      const resolver = new ModuleResolver('/project', new Set<string>(), () => false);
      const sf = parseCode(
        'export { foo } from "./other";',
        '/project/src/index.ts',
      );
      const result = resolver.collectBindings(sf);
      const reExport = result.exports.find(e => e.exportName === 'foo');
      expect(reExport).toBeDefined();
      expect(reExport!.style).toBe('re-export');
      expect(reExport!.fromSpecifier).toBe('./other');
    });

    it('collects wildcard re-exports', () => {
      const resolver = new ModuleResolver('/project', new Set<string>(), () => false);
      const sf = parseCode(
        'export * from "./utils";',
        '/project/src/index.ts',
      );
      const result = resolver.collectBindings(sf);
      const wildcard = result.exports.find(e => e.style === 'wildcard-re-export');
      expect(wildcard).toBeDefined();
      expect(wildcard!.exportName).toBe('*');
    });

    it('collects CJS require imports', () => {
      const resolver = new ModuleResolver('/project', new Set<string>(), () => false);
      const sf = parseCode(
        'const utils = require("./utils");',
        '/project/src/index.js',
      );
      const result = resolver.collectBindings(sf);
      expect(result.imports.length).toBeGreaterThanOrEqual(1);
      const req = result.imports.find(i => i.localName === 'utils');
      expect(req).toBeDefined();
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. FlowRenderer
// ═══════════════════════════════════════════════════════════════════════════

describe('FlowRenderer', () => {
  const renderer = new FlowRenderer();

  describe('getSeverity', () => {
    it('returns CRITICAL for db-query unsanitized', () => {
      expect(renderer.getSeverity('db-query', false)).toBe('CRITICAL');
    });

    it('returns CRITICAL for command-execution unsanitized', () => {
      expect(renderer.getSeverity('command-execution', false)).toBe('CRITICAL');
    });

    it('returns CRITICAL for eval unsanitized', () => {
      expect(renderer.getSeverity('eval', false)).toBe('CRITICAL');
    });

    it('returns HIGH for file-read unsanitized', () => {
      expect(renderer.getSeverity('file-read', false)).toBe('HIGH');
    });

    it('returns HIGH for html-output unsanitized', () => {
      expect(renderer.getSeverity('html-output', false)).toBe('HIGH');
    });

    it('returns MEDIUM for redirect unsanitized', () => {
      expect(renderer.getSeverity('redirect', false)).toBe('MEDIUM');
    });

    it('returns LOW for log-output unsanitized', () => {
      expect(renderer.getSeverity('log-output', false)).toBe('LOW');
    });

    it('returns INFO for any sanitized sink', () => {
      expect(renderer.getSeverity('db-query', true)).toBe('INFO');
      expect(renderer.getSeverity('command-execution', true)).toBe('INFO');
      expect(renderer.getSeverity('file-read', true)).toBe('INFO');
    });
  });

  describe('getSuggestion', () => {
    it('suggests parameterized queries for db-query', () => {
      const suggestion = renderer.getSuggestion('db-query', 'db.query');
      expect(suggestion.toLowerCase()).toContain('parameterized');
    });

    it('suggests execFile for command-execution', () => {
      const suggestion = renderer.getSuggestion('command-execution', 'exec');
      expect(suggestion.toLowerCase()).toContain('execfile');
    });

    it('suggests path validation for file-read', () => {
      const suggestion = renderer.getSuggestion('file-read', 'readFile');
      expect(suggestion.toLowerCase()).toContain('path');
    });

    it('returns generic suggestion for unknown sink kind', () => {
      const suggestion = renderer.getSuggestion('unknown-kind', 'someApi');
      expect(suggestion).toContain('someApi');
    });
  });

  describe('renderCompact', () => {
    it('produces one-line format with severity, rule, hops, and files', () => {
      const flow: TaintQueryResult = {
        sourceKind: 'req.body',
        sourceFunction: 'handler',
        sourceFile: 'handler.ts',
        sinkKind: 'db-query',
        sinkCallee: 'db.query',
        sinkFunction: 'runQuery',
        sinkFile: 'db.ts',
        sinkLine: 10,
        trace: [
          {
            filePath: 'handler.ts',
            functionName: 'handler',
            canonicalId: 'handler.ts#handler',
            line: 5,
            description: 'req.body',
            accessPath: 'req.body',
            propagation: 'source',
          },
          {
            filePath: 'db.ts',
            functionName: 'runQuery',
            canonicalId: 'db.ts#runQuery',
            line: 10,
            description: 'db.query(input)',
            accessPath: 'db-query',
            propagation: 'sink',
          },
        ],
        crossFileHops: [],
        sanitizations: [],
        isSanitized: false,
        confidence: 'definite',
        fileCount: 2,
        hopCount: 1,
      };

      const compact = renderer.renderCompact(flow);
      expect(compact).toContain('CRITICAL');
      expect(compact).toContain('db-query');
      expect(compact).toContain('1 hop');
      expect(compact).toContain('2 files');
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. Integration: Full cross-file flow detection
// ═══════════════════════════════════════════════════════════════════════════

describe('Integration: cross-file taint flow', () => {
  it('detects flow from req.body through process() to db.query() across files', () => {
    const summaryBuilder = new SummaryBuilder();

    // File A: handler.ts
    const handlerCode = `
      export function handle(req: any, res: any) {
        const data = req.body;
        const result = process(data);
        res.json(result);
      }
    `;
    const handlerSf = parseCode(handlerCode, 'handler.ts');
    const handlerFn = getFirstFunction(handlerSf);
    const handlerSummary = summaryBuilder.buildFunctionSummary(
      handlerFn,
      'handler.ts#handle',
      'handler.ts',
      true,
    );

    // File B: processor.ts
    const processorCode = `
      export function process(input: any) {
        return db.query('SELECT * FROM users WHERE id = ' + input);
      }
    `;
    const processorSf = parseCode(processorCode, 'processor.ts');
    const processorFn = getFirstFunction(processorSf);
    const processorSummary = summaryBuilder.buildFunctionSummary(
      processorFn,
      'processor.ts#process',
      'processor.ts',
      true,
    );

    // Verify processor has sink hit
    expect(processorSummary.sinkHits.length).toBeGreaterThanOrEqual(1);
    const processorSinkHit = processorSummary.sinkHits.find(h => h.sinkKind === 'db-query');
    expect(processorSinkHit).toBeDefined();

    // The SummaryBuilder resolves call targets locally (handler.ts#process),
    // but the actual target is processor.ts#process. In real usage, the
    // ProjectGraph rewires these. We simulate that here by fixing the call edge.
    for (const edge of handlerSummary.callEdges) {
      if (edge.calleeCanonicalId === 'handler.ts#process') {
        edge.calleeCanonicalId = 'processor.ts#process';
      }
    }

    // Store and resolve
    const store = new SummaryStore();
    store.add(handlerSummary);
    store.add(processorSummary);

    const resolver = new SummaryResolver(store);
    const stats = resolver.resolve();

    // After resolution, handler should have a transitive sink hit
    const resolvedHandler = store.get('handler.ts#handle')!;

    // Check if handler has a sink hit propagated from processor
    const hasTransitiveSinkHit = resolvedHandler.sinkHits.some(
      h => h.sinkKind === 'db-query',
    );

    // Handler must have call edge to process and the sink hit must propagate
    const hasCallEdge = resolvedHandler.callEdges.some(
      e => e.calleeCanonicalId === 'processor.ts#process',
    );

    expect(hasCallEdge).toBe(true);
    expect(hasTransitiveSinkHit).toBe(true);
  });

  it('resolution produces correct stats', () => {
    const store = new SummaryStore();

    store.add(makeSummary({
      canonicalId: 'sink.ts#dangerous',
      filePath: 'sink.ts',
      functionName: 'dangerous',
      sinkHits: [{
        input: makeParamInput(0),
        sinkKind: 'command-execution',
        sinkCallee: 'exec',
        sanitized: false,
        sanitizations: [],
        line: 3,
      }],
    }));

    store.add(makeSummary({
      canonicalId: 'mid.ts#middle',
      filePath: 'mid.ts',
      functionName: 'middle',
      callEdges: [{
        calleeCanonicalId: 'sink.ts#dangerous',
        argMapping: [{ callerInput: makeParamInput(0), calleeParamIndex: 0 }],
        line: 2,
      }],
    }));

    store.add(makeSummary({
      canonicalId: 'entry.ts#entry',
      filePath: 'entry.ts',
      functionName: 'entry',
      callEdges: [{
        calleeCanonicalId: 'mid.ts#middle',
        argMapping: [{ callerInput: makeParamInput(0), calleeParamIndex: 0 }],
        line: 1,
      }],
    }));

    const resolver = new SummaryResolver(store);
    const stats = resolver.resolve();

    // Should have propagated sink hits
    expect(stats.sinkHitsAdded).toBeGreaterThanOrEqual(2);

    // entry should now have the transitive command-execution hit
    const entrySummary = store.get('entry.ts#entry')!;
    const cmdHit = entrySummary.sinkHits.find(h => h.sinkKind === 'command-execution');
    expect(cmdHit).toBeDefined();
    expect(cmdHit!.sinkCallee).toBe('exec');
  });
});

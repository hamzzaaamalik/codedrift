/**
 * TaintAnalyzer — Orchestrator for data flow taint analysis
 *
 * Coordinates source detection, propagation tracking, sink detection,
 * and sanitizer detection to produce complete taint flow results.
 */

import * as ts from 'typescript';
import { TaintSourceDetector } from './source-detector.js';
import { TaintPropagationTracker } from './propagation-tracker.js';
import { TaintSinkDetector } from './sink-detector.js';
import { SanitizerDetector } from './sanitizer-detector.js';
import type {
  TaintAnalysisResult,
  TaintFlow,
  TaintSource,
  TaintSink,
  SanitizationPoint,
  VariableTaintState,
} from './types.js';

/** Empty result returned when no taint sources are found */
const EMPTY_RESULT: TaintAnalysisResult = Object.freeze({
  sources: [],
  sinks: [],
  flows: [],
  unsanitizedFlows: [],
  variableStates: new Map(),
});

export class TaintAnalyzer {
  private readonly sourceDetector = new TaintSourceDetector();
  private readonly sinkDetector = new TaintSinkDetector();
  private readonly sanitizerDetector = new SanitizerDetector();

  /** Scope cache keyed by node start position — avoids redundant work across engines */
  private readonly scopeCache = new Map<number, TaintAnalysisResult>();

  /**
   * Full taint analysis of a function/method scope.
   *
   * Algorithm:
   * 1. Detect sources — if none, return empty result early
   * 2. Track propagation through assignments/transformations
   * 3. Detect sinks in the scope
   * 4. For each sink, check if any argument is tainted
   * 5. For tainted args, check if sanitization was applied
   * 6. Build TaintFlow objects (source -> steps -> sink)
   * 7. Classify flows as sanitized or unsanitized
   */
  analyzeScope(scopeNode: ts.Node): TaintAnalysisResult {
    const cacheKey = scopeNode.getStart();
    const cached = this.scopeCache.get(cacheKey);
    if (cached) return cached;

    // Step 1: Detect sources
    const sources = this.sourceDetector.detectSources(scopeNode);
    if (sources.length === 0) {
      this.scopeCache.set(cacheKey, EMPTY_RESULT);
      return EMPTY_RESULT;
    }

    // Step 2: Track propagation (tracker needs sources in constructor)
    const propagationTracker = new TaintPropagationTracker(sources);
    const variableStates = propagationTracker.trackPropagation(scopeNode);

    // Step 3: Detect sinks
    const sinks = this.sinkDetector.detectSinks(scopeNode);

    // Step 4-6: Build flows by matching tainted variables to sink arguments
    const flows: TaintFlow[] = [];

    for (const sink of sinks) {
      const sinkFlows = this.buildFlowsForSink(sink, variableStates, sources, scopeNode);
      flows.push(...sinkFlows);
    }

    // Step 7: Classify
    const unsanitizedFlows = flows.filter(f => !f.isSanitized);

    const result: TaintAnalysisResult = {
      sources,
      sinks,
      flows,
      unsanitizedFlows,
      variableStates,
    };

    this.scopeCache.set(cacheKey, result);
    return result;
  }

  /**
   * Point query: is a specific expression tainted within a scope?
   * Useful for engines that already found a suspicious pattern and want
   * to check whether the value was user-controlled.
   */
  isExpressionTainted(
    expr: ts.Node,
    scopeNode: ts.Node,
  ): { tainted: boolean; sourceKinds: string[]; sanitized: boolean } {
    const result = this.analyzeScope(scopeNode);

    // Check if the expression is an identifier we track
    if (ts.isIdentifier(expr)) {
      const state = result.variableStates.get(expr.text);
      if (state && state.taintSources.length > 0) {
        const sourceKinds = state.taintSources
          .map(id => result.sources.find(s => s.id === id)?.kind)
          .filter((k): k is NonNullable<typeof k> => k != null) as string[];
        return {
          tainted: true,
          sourceKinds,
          sanitized: state.sanitized,
        };
      }
    }

    // Check property access expressions like `obj.prop`
    if (ts.isPropertyAccessExpression(expr)) {
      const text = expr.getText();
      const state = result.variableStates.get(text);
      if (state && state.taintSources.length > 0) {
        const sourceKinds = state.taintSources
          .map(id => result.sources.find(s => s.id === id)?.kind)
          .filter((k): k is NonNullable<typeof k> => k != null) as string[];
        return {
          tainted: true,
          sourceKinds,
          sanitized: state.sanitized,
        };
      }
    }

    return { tainted: false, sourceKinds: [], sanitized: false };
  }

  /**
   * Build taint flows for a single sink by checking which of its arguments
   * carry tainted data and whether sanitization was applied.
   */
  private buildFlowsForSink(
    sink: TaintSink,
    variableStates: Map<string, VariableTaintState>,
    sources: TaintSource[],
    scopeNode: ts.Node,
  ): TaintFlow[] {
    const flows: TaintFlow[] = [];
    const taintedArgIndices: number[] = [];

    // Walk the sink node to find identifiers that are tainted
    const taintedNames = new Map<string, VariableTaintState>();
    this.collectTaintedIdentifiers(sink.node, variableStates, taintedNames);

    for (const [_name, state] of taintedNames) {
      for (const sourceId of state.taintSources) {
        const source = sources.find(s => s.id === sourceId);
        if (!source) continue;

        // Walk the scope to find sanitization points along the path
        const sanitizations = this.findSanitizationsInScope(scopeNode);

        const isSanitized = state.sanitized || sanitizations.length > 0;

        // Determine confidence based on path length and sanitization
        let confidence: 'high' | 'medium' | 'low' = 'high';
        if (state.propagationPath.length > 5) confidence = 'medium';
        if (state.propagationPath.length > 10) confidence = 'low';

        flows.push({
          source,
          steps: state.propagationPath,
          sink: { ...sink, taintedArgIndices },
          sanitizations,
          isSanitized,
          confidence,
        });
      }
    }

    return flows;
  }

  /**
   * Walk a scope node and collect all sanitization points found.
   */
  private findSanitizationsInScope(scopeNode: ts.Node): SanitizationPoint[] {
    const sanitizations: SanitizationPoint[] = [];
    const visit = (node: ts.Node): void => {
      const point = this.sanitizerDetector.checkSanitization(node);
      if (point) {
        sanitizations.push(point);
      }
      ts.forEachChild(node, visit);
    };
    visit(scopeNode);
    return sanitizations;
  }

  /**
   * Recursively collect identifiers in a node that have taint state.
   */
  private collectTaintedIdentifiers(
    node: ts.Node,
    variableStates: Map<string, VariableTaintState>,
    result: Map<string, VariableTaintState>,
  ): void {
    if (ts.isIdentifier(node)) {
      const state = variableStates.get(node.text);
      if (state && state.taintSources.length > 0) {
        result.set(node.text, state);
      }
    }

    ts.forEachChild(node, child =>
      this.collectTaintedIdentifiers(child, variableStates, result),
    );
  }
}

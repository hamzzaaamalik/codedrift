/**
 * Taint Analysis Types — Data flow tracking for CodeDrift
 *
 * Tracks tainted (user-controlled) values from sources through
 * assignments and transformations to dangerous sinks.
 */

import * as ts from 'typescript';

/** Unique identifier for a tainted value within a single file analysis */
export type TaintId = string;

/** Category of taint source — where user input enters */
export type TaintSourceKind =
  // Express
  | 'req.body' | 'req.params' | 'req.query' | 'req.headers'
  | 'req.cookies' | 'req.files' | 'req.ip'
  // Koa
  | 'ctx.request.body' | 'ctx.params' | 'ctx.query'
  // Hapi
  | 'request.payload' | 'request.params' | 'request.query'
  // NestJS decorators
  | 'decorator.body' | 'decorator.param' | 'decorator.query'
  // System
  | 'process.argv' | 'process.env'
  // Generic
  | 'user-input';

/** Category of sink — where tainted data is consumed dangerously */
export type TaintSinkKind =
  | 'db-query' | 'db-mutation'
  | 'file-read' | 'file-write'
  | 'command-execution'
  | 'html-output' | 'template-render'
  | 'redirect' | 'url-construction'
  | 'eval' | 'dynamic-import'
  | 'http-request'
  | 'log-output';

/** How taint was propagated at a given step */
export type PropagationKind =
  | 'assignment'
  | 'destructuring'
  | 'spread'
  | 'property-access'
  | 'function-arg'
  | 'return-value'
  | 'array-element'
  | 'template-literal'
  | 'binary-concat'
  | 'ternary'
  | 'await'
  | 'computed-key';

/** What kind of sanitization was applied */
export type SanitizationKind =
  | 'type-coercion'
  | 'type-check'
  | 'schema-validation'
  | 'allowlist'
  | 'regex-match'
  | 'escape'
  | 'parameterized'
  | 'length-check'
  | 'custom-validator'
  | 'orm-typed';

/** A source of tainted data */
export interface TaintSource {
  id: TaintId;
  kind: TaintSourceKind;
  node: ts.Node;
  /** Variable name(s) initially receiving this taint */
  boundNames: string[];
  /** Human-readable label, e.g. "req.params.id" */
  label: string;
  position: number;
}

/** A sink where tainted data is consumed dangerously */
export interface TaintSink {
  kind: TaintSinkKind;
  node: ts.Node;
  /** The method or API being called */
  callee: string;
  /** Which argument positions receive tainted data */
  taintedArgIndices: number[];
  position: number;
}

/** A single step in taint propagation */
export interface TaintStep {
  variableName: string;
  propagation: PropagationKind;
  node: ts.Node;
  position: number;
}

/** A sanitization point that removes or constrains taint */
export interface SanitizationPoint {
  sanitizer: string;
  sanitizationKind: SanitizationKind;
  node: ts.Node;
  outputVariable?: string;
  position: number;
}

/** A complete taint flow: source -> steps -> sink */
export interface TaintFlow {
  source: TaintSource;
  steps: TaintStep[];
  sink: TaintSink;
  sanitizations: SanitizationPoint[];
  isSanitized: boolean;
  confidence: 'high' | 'medium' | 'low';
}

/** Per-variable taint state tracked during analysis */
export interface VariableTaintState {
  name: string;
  taintSources: TaintId[];
  sanitized: boolean;
  appliedSanitizations: SanitizationKind[];
  declarationNode: ts.Node;
  propagationPath: TaintStep[];
}

/** Result of taint analysis for a single scope */
export interface TaintAnalysisResult {
  sources: TaintSource[];
  sinks: TaintSink[];
  flows: TaintFlow[];
  unsanitizedFlows: TaintFlow[];
  variableStates: Map<string, VariableTaintState>;
}

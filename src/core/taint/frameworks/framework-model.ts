/**
 * Framework Model — Base interface for framework-aware taint analysis.
 *
 * Each web framework has unique conventions for routing, middleware chains,
 * and how user input enters handler functions.  A FrameworkModel captures
 * these conventions so the cross-file taint engine can reason about
 * implicit data flow between separately-defined functions.
 */

import * as ts from 'typescript';
import type { TaintSourceKind, SanitizationKind } from '../types.js';

// ---------------------------------------------------------------------------
// Route & handler types
// ---------------------------------------------------------------------------

/** A route handler with its middleware chain */
export interface RouteRegistration {
  /** HTTP method (GET, POST, etc.) or 'USE' for middleware */
  method: string;
  /** Route path pattern, e.g., '/users/:id' */
  path: string;
  /** Ordered list of handler/middleware references */
  handlers: HandlerReference[];
  /** File where the route was registered */
  filePath: string;
  /** AST node of the registration */
  node: ts.Node;
}

/** Reference to a handler function (may be inline or imported) */
export interface HandlerReference {
  /** If the handler is a named import or variable */
  name?: string;
  /** Canonical ID if resolved */
  canonicalId?: string;
  /** If inline arrow/function expression */
  node?: ts.Node;
  /** Role in the chain */
  role: 'middleware' | 'handler' | 'error-handler' | 'guard' | 'pipe' | 'interceptor';
}

// ---------------------------------------------------------------------------
// Chain taint effects
// ---------------------------------------------------------------------------

/** Taint implications of a middleware/handler chain */
export interface ChainTaintEffect {
  /** Sources introduced (e.g., bodyParser adds req.body) */
  sourcesAdded: { kind: TaintSourceKind; accessPath: string }[];
  /** Sanitizations applied by middleware before handler */
  sanitizationsApplied: { kind: SanitizationKind; targetPath: string }[];
  /** Fields validated/constrained by middleware */
  validatedPaths: string[];
}

// ---------------------------------------------------------------------------
// Base interface
// ---------------------------------------------------------------------------

/** Base interface for all framework models */
export interface FrameworkModel {
  /** Framework name (e.g. 'express', 'nestjs', 'nextjs') */
  readonly name: string;

  /** Detect if this framework is used in a source file */
  detect(sourceFile: ts.SourceFile): boolean;

  /** Extract all route registrations from a source file */
  extractRoutes(sourceFile: ts.SourceFile, filePath: string): RouteRegistration[];

  /** Analyze the taint effects of a middleware/handler chain */
  analyzeChain(chain: HandlerReference[]): ChainTaintEffect;

  /** Get framework-specific taint sources for a handler function */
  getHandlerSources(
    handler: ts.FunctionLikeDeclaration,
  ): { paramIndex: number; sourceKind: TaintSourceKind }[];
}

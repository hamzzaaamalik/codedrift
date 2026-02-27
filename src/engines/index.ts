/**
 * Analysis Engines Registry
 */

import { AnalysisEngine } from '../types/index.js';
import { HallucinatedDepsDetector } from './hallucinated-deps-detector.js';
import { StackTraceDetector } from './stack-trace-detector.js';
import { MissingAwaitDetector } from './missing-await-detector.js';
import { EmptyCatchDetector } from './empty-catch-detector.js';
import { SecretDetector } from './secret-detector.js';

/**
 * Registry of all available analysis engines
 */
export const engines: AnalysisEngine[] = [
  // Phase 2: AI Anti-Patterns (COMPLETE)
  new HallucinatedDepsDetector(),
  new StackTraceDetector(),
  new MissingAwaitDetector(),
  new EmptyCatchDetector(),
  new SecretDetector(),

  // Phase 3: Structural Drift (TODO)
  // - CircularDependencyEngine
  // - CouplingMetricsEngine
];

/**
 * Get engine by name
 */
export function getEngine(name: string): AnalysisEngine | undefined {
  return engines.find(e => e.name === name);
}

/**
 * Get all engines
 */
export function getAllEngines(): AnalysisEngine[] {
  return engines;
}

/**
 * Export base class for engine development
 */
export { BaseEngine } from './base-engine.js';

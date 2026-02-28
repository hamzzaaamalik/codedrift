/**
 * Analysis Engines Registry
 */

import { AnalysisEngine } from '../types/index.js';
import { HallucinatedDepsDetector } from './hallucinated-deps-detector.js';
import { StackTraceDetector } from './stack-trace-detector.js';
import { MissingAwaitDetector } from './missing-await-detector.js';
import { AsyncForEachDetector } from './async-foreach-detector.js';
import { EmptyCatchDetector } from './empty-catch-detector.js';
import { SecretDetector } from './secret-detector.js';
import { UnsafeRegexDetector } from './unsafe-regex-detector.js';
import { ConsoleInProductionDetector } from './console-in-production-detector.js';
import { MissingInputValidationDetector } from './missing-input-validation-detector.js';
import { IDORDetector } from './idor-detector.js';

/**
 * Registry of all available analysis engines
 */
export const engines: AnalysisEngine[] = [
  // Tier 1: Critical AI Anti-Patterns
  new HallucinatedDepsDetector(),
  new StackTraceDetector(),
  new MissingAwaitDetector(),
  new AsyncForEachDetector(),     // #1 most common AI mistake
  new EmptyCatchDetector(),
  new SecretDetector(),
  new UnsafeRegexDetector(),      // ReDoS vulnerabilities
  new ConsoleInProductionDetector(), // Console.log in production
  new MissingInputValidationDetector(), // Missing input validation (CRITICAL)
  new IDORDetector(),             // Insecure Direct Object Reference (CRITICAL)

  // Future: Structural Drift Detection
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

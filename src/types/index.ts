/**
 * Core type definitions for CodeDrift
 */

export type Severity = 'error' | 'warning' | 'info';

export interface Issue {
  engine: string;
  severity: Severity;
  message: string;
  filePath: string;
  location: {
    line: number;
    column: number;
  };
  suggestion?: string;
}

export interface AnalysisContext {
  sourceFile: any; // TypeScript SourceFile
  filePath: string;
  content: string;
  dependencyGraph?: DependencyGraph;
}

export interface AnalysisEngine {
  name: string;
  analyze(context: AnalysisContext): Promise<(Issue | null)[]>;
}

export interface DependencyGraph {
  nodes: Map<string, FileNode>;
  edges: Map<string, Set<string>>; // from -> Set<to>
}

export interface FileNode {
  path: string;
  imports: string[];
  exports: string[];
  size: number;
  hash: string;
}

export interface AnalysisResult {
  issues: Issue[];
  stats: {
    analyzed: number;
    cached: number;
    total: number;
  };
}

export interface CacheEntry {
  hash: string;
  issues: Issue[];
  timestamp: number;
  dependencies: string[];
}

export type RuleLevel = 'error' | 'warn' | 'off';

export interface CodeDriftConfig {
  // File patterns to exclude from analysis
  exclude?: string[];

  // Rule configuration
  rules?: {
    'stack-trace-exposure'?: RuleLevel;
    'hallucinated-deps'?: RuleLevel;
    'missing-await'?: RuleLevel;
    'empty-catch'?: RuleLevel;
    'hardcoded-secret'?: RuleLevel;
  };

  // Exit code behavior
  failOn?: 'error' | 'warn';

  // Cache settings
  cache?: {
    enabled?: boolean;
    ttl?: number;
  };
}

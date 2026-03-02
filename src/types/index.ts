/**
 * Core type definitions for CodeDrift
 */

export type Severity = 'error' | 'warning' | 'info';
export type Confidence = 'high' | 'medium' | 'low';

/**
 * Additional metadata about the file and context where an issue was found
 */
export interface IssueMetadata {
  /** Whether the file is a test file */
  isTestFile: boolean;
  /** Whether the file is auto-generated */
  isGeneratedFile: boolean;
  /** Name of the workspace package this file belongs to (for monorepos) */
  workspaceName?: string;
  /** Shannon entropy of the code (higher = more complex/random) */
  entropy?: number;
  /** A snippet of code around the issue for context */
  contextSnippet?: string;
  /** Missing package name (for hallucinated-deps detector) */
  missingPackage?: string;
  /** Allow any additional metadata */
  [key: string]: any;
}

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
  confidence?: Confidence;
  metadata?: IssueMetadata;
  riskScore?: number; // 0-100
  priority?: 'critical' | 'high' | 'medium' | 'low';
}

export interface AnalysisContext {
  sourceFile: any; // TypeScript SourceFile
  filePath: string;
  content: string;
  dependencyGraph?: DependencyGraph;
  /** Package resolver for checking dependencies and workspaces */
  packageResolver?: PackageResolver;
  /** Partial metadata to be merged into issue metadata */
  metadata?: Partial<IssueMetadata>;
  /**
   * TypeScript path alias prefixes loaded from tsconfig.json at scan start.
   * e.g. { "@/", "@components/", "@config" }
   * Used to prevent hallucinated-deps from flagging internal path aliases.
   */
  pathAliases?: Set<string>;
}

/**
 * Result of package resolution
 */
export interface PackageResolution {
  /** Path to the nearest package.json */
  packageJsonPath: string;
  /** Name of the workspace (if in a monorepo) */
  workspaceName?: string;
  /** Whether the package is part of a workspace */
  isWorkspace: boolean;
}

/**
 * Package resolver interface for dependency checking
 */
export interface PackageResolver {
  /** Loaded package.json content */
  packageJson: any;
  /** Check if a package exists in dependencies */
  hasDependency(name: string): boolean;
  /** Check if a package exists in devDependencies */
  hasDevDependency(name: string): boolean;
  /** Check if a package exists in any dependency field */
  hasAnyDependency(name: string): boolean;
  /** Find nearest package.json for a file path */
  findNearestPackageJson(filePath: string): string | null;
  /** Check if a package exists (alias for hasAnyDependency) */
  packageExists(name: string): boolean;
  /** Check if a package exists for a specific file (workspace-aware) */
  packageExistsForFile?(name: string, filePath: string): boolean;
  /** Get workspace name for a file path */
  getWorkspaceName(filePath: string): string | undefined;
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

export interface IssueGroup {
  fingerprint: string;
  primaryIssue: Issue;
  occurrences: Issue[];
  count: number;
}

export interface AnalysisResult {
  issues: Issue[];
  issueGroups?: IssueGroup[]; // For deduplication view
  stats: {
    analyzed: number;
    cached: number;
    total: number;
  };
  startTime?: number;
  endTime?: number;
}

export interface CacheEntry {
  hash: string;
  issues: Issue[];
  timestamp: number;
  dependencies: string[];
}

export type RuleLevel = 'error' | 'warn' | 'off';

export type OutputFormat = 'terminal' | 'summary' | 'detailed' | 'compact' | 'json' | 'html' | 'sarif';

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
    'sql-injection'?: RuleLevel;
    'xss-detector'?: RuleLevel;
    'idor'?: RuleLevel;
    'console-in-production'?: RuleLevel;
  };

  // Exit code behavior
  failOn?: 'error' | 'warn';

  // Cache settings
  cache?: {
    enabled?: boolean;
    ttl?: number;
  };

  // Output options
  format?: OutputFormat;
  output?: string;

  // Advanced filtering options
  /** Respect .gitignore patterns when scanning files */
  respectGitignore?: boolean;
  /** Root directory of the workspace/project */
  workspaceRoot?: string;
  /** Exclude test files from analysis */
  excludeTestFiles?: boolean;
  /** Minimum confidence threshold for reporting issues */
  confidenceThreshold?: Confidence;
}

export interface JSONReport {
  summary: {
    totalFiles: number;
    analyzedFiles: number;
    totalIssues: number;
    criticalIssues: number;
    warnings: number;
    timestamp: string;
    duration: number;
  };
  issues: Array<{
    engine: string;
    severity: Severity;
    message: string;
    filePath: string;
    location: {
      line: number;
      column: number;
    };
    suggestion?: string;
    ruleId: string;
  }>;
  config: {
    failOn: string;
    rulesEnabled: string[];
  };
}

import { glob } from 'glob';
import { AnalysisResult, AnalysisContext, Issue, CodeDriftConfig } from '../types/index.js';
import { parseFile } from './parser.js';
import { clearASTCache } from './ast-parser.js';
import { getAllEngines } from '../engines/index.js';
import { loadConfig, isRuleEnabled, getRuleSeverity, meetsConfidenceThreshold } from './config.js';
import { PackageResolver, GitIgnoreParser, isTestFile } from '../utils/index.js';
import { isBuildArtifact } from '../utils/file-utils.js';
import { loadPathAliases } from '../utils/tsconfig-resolver.js';
import { enrichIssueWithRisk } from './risk-scorer.js';
import { adjustSeverities } from './severity-adjuster.js';
import { deduplicateIssues } from './deduplicator.js';
import { shouldAutoIgnore, shouldBoostConfidence } from './smart-filters.js';
import { TaintAnalyzer } from './taint/index.js';
import { ProjectGraph } from './taint/graph/project-graph.js';
import { SummaryBuilder } from './taint/summaries/summary-builder.js';
import { SummaryStore } from './taint/summaries/summary-store.js';
import { SummaryResolver } from './taint/summaries/summary-resolver.js';
import { TaintQueryEngine } from './taint/query/taint-query.js';
import { IncrementalEngine } from './taint/incremental/incremental-engine.js';

export interface AnalysisProgressEvent {
  phase: string;
  totalFiles?: number;
  currentFile?: number;
  filePath?: string;
  newIssue?: {
    severity: string;
    engine: string;
    message: string;
    filePath: string;
    line: number;
  };
  /** Final issue counts after post-processing (filtering, dedup, severity adjustment). */
  finalCounts?: { critical: number; high: number; medium: number; low: number; total: number };
  error?: string;
}

interface AnalyzeOptions {
  fullScan?: boolean;
  generateGraph?: boolean;
  updateBaseline?: boolean;
  onProgress?: (event: AnalysisProgressEvent) => void;
}

/**
 * Main analyzer orchestrator
 * Coordinates file discovery, parsing, and engine execution
 */
export async function analyzeProject(_options: AnalyzeOptions): Promise<AnalysisResult> {
  const cwd = process.cwd();
  const progress = _options.onProgress ?? (() => {});

  // Load configuration
  const config = loadConfig();

  // Initialize package resolver
  let packageResolver: PackageResolver | null = null;
  try {
    packageResolver = new PackageResolver(cwd);
  } catch (error) {
    // Package.json not found, continue without it
    console.warn('Warning: No package.json found, some features will be limited');
  }

  // Initialize gitignore parser if enabled
  let gitignoreParser: GitIgnoreParser | null = null;
  if (config.respectGitignore) {
    gitignoreParser = new GitIgnoreParser(cwd);

    // Add config excludes to gitignore parser
    if (config.exclude) {
      gitignoreParser.addPatterns(config.exclude);
    }
  }

  // Reset ESTree AST cache for this run (prevents stale entries across runs)
  clearASTCache();

  // Load TypeScript path aliases once per scan (prevents false positives in hallucinated-deps)
  const pathAliases = loadPathAliases(cwd);

  // Discover files
  progress({ phase: 'discovering' });
  const allDiscoveredFiles = await discoverFiles(cwd, config, gitignoreParser);
  progress({ phase: 'discovering', totalFiles: allDiscoveredFiles.length });

  // CRITICAL FIX: Filter test files BEFORE analysis if excludeTestFiles is enabled
  // This prevents test files from being processed at all, reducing false positives
  const files = config.excludeTestFiles
    ? allDiscoveredFiles.filter(f => !isTestFile(f))
    : allDiscoveredFiles;

  // Get all enabled engines
  const engines = getAllEngines();

  // Cross-file taint analysis — Phase 1: Build project graph + summaries
  progress({ phase: 'building-graph', totalFiles: files.length });
  let crossFileTaint: AnalysisContext['crossFileTaint'];
  try {
    const projectGraph = new ProjectGraph(cwd, pathAliases);
    projectGraph.build(files);

    const incremental = new IncrementalEngine(cwd);
    incremental.loadCache();
    const { stale: staleFiles } = incremental.getStaleFiles(files);

    const summaryStore = new SummaryStore();
    const summaryBuilder = new SummaryBuilder();

    // Load cached summaries for non-stale files
    for (const filePath of files) {
      if (!staleFiles.includes(filePath)) {
        const cached = incremental.getCachedSummaries(filePath);
        if (cached) {
          for (const s of cached) summaryStore.add(s);
        }
      }
    }

    // Build summaries for stale files
    progress({ phase: 'building-summaries', totalFiles: staleFiles.length, currentFile: 0 });
    let summaryCount = 0;
    for (const filePath of staleFiles) {
      try {
        const sf = parseFile(filePath);
        const fileEntry = projectGraph.getFileIndex().getEntry(filePath);
        const exportedNames = new Set(
          projectGraph.getSymbolTable().getFileSymbols(filePath).map(s => s.exportName),
        );
        const fileSummaries = summaryBuilder.buildFileSummaries(sf, filePath, exportedNames);
        summaryStore.addAll(fileSummaries);

        // Update cache
        const hash = incremental.computeHash(filePath);
        const deps = (fileEntry as any)?.imports?.map((i: any) => i.resolvedPath).filter(Boolean) ?? [];
        incremental.updateCache(filePath, hash, fileSummaries.map(s => s.canonicalId), deps);
        summaryCount++;
        progress({ phase: 'building-summaries', totalFiles: staleFiles.length, currentFile: summaryCount, filePath });
      } catch {
        // Skip files that fail to summarize
      }
    }

    // Phase 2: Multi-hop resolution
    progress({ phase: 'resolving-flows' });
    const resolver = new SummaryResolver(summaryStore);
    resolver.resolve();

    // Save cache for next run
    try { incremental.saveCache(); } catch { /* non-critical */ }

    // Create query engine
    const queryEngine = new TaintQueryEngine(
      (id) => summaryStore.get(id),
      (fp) => summaryStore.getForFile(fp),
      () => summaryStore.getAllIds(),
    );

    crossFileTaint = { queryEngine, summaryStore, projectGraph };
  } catch (error) {
    console.warn('Warning: Cross-file taint analysis failed:',
      error instanceof Error ? error.message : error);
  }

  // Analyze each file
  progress({ phase: 'analyzing', totalFiles: files.length, currentFile: 0 });
  const allIssues: Issue[] = [];
  let analyzedCount = 0;

  for (const filePath of files) {
    try {
      // Check if this is a test file (for metadata purposes)
      const isTest = isTestFile(filePath);

      // Parse file (sourceFile.text holds the content — no second read needed)
      const sourceFile = parseFile(filePath);
      const content = sourceFile.text;

      // Detect workspace name
      const workspaceName = packageResolver?.getWorkspaceName(filePath);

      // Create analysis context
      const context: AnalysisContext = {
        sourceFile,
        filePath,
        content,
        packageResolver: packageResolver || undefined,
        pathAliases,
        taintAnalyzer: new TaintAnalyzer(),
        crossFileTaint,
        metadata: {
          isTestFile: isTest,
          workspaceName,
        },
      };

      // Run all enabled engines in parallel with per-engine error isolation
      const enginePromises = engines
        .filter(engine => isRuleEnabled(config, engine.name))
        .map(async engine => {
          try {
            const issues = await engine.analyze(context);

            // Filter out null issues (suppressed by comments)
            const validIssues = issues.filter((issue): issue is Issue => issue !== null);

            // Apply rule severity overrides
            return validIssues.map(issue => {
              const configSeverity = getRuleSeverity(config, engine.name);
              if (configSeverity) {
                return { ...issue, severity: configSeverity };
              }
              return issue;
            });
          } catch (engineError) {
            // Per-engine isolation: one engine crashing doesn't stop others
            console.warn(
              `Warning: Engine '${engine.name}' failed on ${filePath}:`,
              engineError instanceof Error ? engineError.message : engineError,
            );
            return [] as Issue[];
          }
        });

      const engineResults = await Promise.all(enginePromises);
      for (const issues of engineResults) {
        for (const issue of issues) {
          allIssues.push(issue);
          progress({
            phase: 'analyzing',
            newIssue: {
              severity: issue.severity,
              engine: issue.engine,
              message: issue.message,
              filePath: issue.filePath,
              line: issue.location.line,
            },
          });
        }
      }

      analyzedCount++;
      progress({ phase: 'analyzing', totalFiles: files.length, currentFile: analyzedCount, filePath });
      // codedrift-disable-next-line empty-catch
    } catch (error) {
      // Log parsing errors but continue analyzing other files
      // This is intentional - we don't want one bad file to stop the entire analysis
      console.warn(`Warning: Failed to parse ${filePath}:`, error instanceof Error ? error.message : error);
      // Continue with next file
    }
  }

  progress({ phase: 'post-processing' });

  // Apply smart auto-ignore filters for common false positives
  const afterAutoIgnore = allIssues.filter(issue => !shouldAutoIgnore(issue));

  // Filter issues by confidence threshold
  const threshold = config.confidenceThreshold || 'medium';
  const filteredIssues = afterAutoIgnore.filter(issue => meetsConfidenceThreshold(issue, threshold));

  // Boost confidence for high-quality issues (BEFORE severity adjustment so it takes effect)
  let processedIssues = filteredIssues.map(issue => {
    if (shouldBoostConfidence(issue) && issue.confidence !== 'high') {
      return { ...issue, confidence: 'high' as const };
    }
    return issue;
  });

  // Apply smart severity adjustments based on context (now uses boosted confidence)
  processedIssues = adjustSeverities(processedIssues);

  // Enrich with risk scores and priority levels
  processedIssues = processedIssues.map(enrichIssueWithRisk);

  // Sort by risk score (highest first)
  processedIssues.sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));

  // Generate deduplication groups (always available, but optionally used)
  const issueGroups = deduplicateIssues(processedIssues);

  // Send final counts to dashboard so it can show filtered vs raw
  const finalCounts = {
    critical: processedIssues.filter(i => i.severity === 'error').length,
    high: processedIssues.filter(i => i.severity === 'warning').length,
    medium: processedIssues.filter(i => i.severity === 'info').length,
    low: 0,
    total: processedIssues.length,
  };
  progress({ phase: 'complete', finalCounts });

  return {
    issues: processedIssues,
    issueGroups,
    stats: {
      analyzed: analyzedCount,
      cached: 0, // Phase 4: Implement caching
      total: allDiscoveredFiles.length,
    },
  };
}

/**
 * Discover JavaScript/TypeScript files in the project
 */
async function discoverFiles(
  rootDir: string,
  config: CodeDriftConfig,
  gitignoreParser: GitIgnoreParser | null
): Promise<string[]> {
  const patterns = [
    '**/*.ts',
    '**/*.js',
    '**/*.tsx',
    '**/*.jsx',
  ];

  // Use configured exclude patterns (only if gitignore is not enabled)
  const ignore = config.respectGitignore ? [] : (config.exclude || [
    '**/node_modules/**',
    '**/dist/**',
    '**/build/**',
  ]);

  const files: string[] = [];

  for (const pattern of patterns) {
    const matches = await glob(pattern, {
      cwd: rootDir,
      ignore,
      absolute: true,
      nodir: true,
    });
    files.push(...matches);
  }

  // Deduplicate
  let uniqueFiles = [...new Set(files)];

  // Filter using gitignore parser if enabled
  if (gitignoreParser) {
    uniqueFiles = uniqueFiles.filter(file => !gitignoreParser.shouldIgnore(file));
  }

  // Always skip build artifacts — minified/bundled files generate only false positives
  // and are never source code the developer wrote or maintains.
  uniqueFiles = uniqueFiles.filter(file => !isBuildArtifact(file));

  return uniqueFiles;
}

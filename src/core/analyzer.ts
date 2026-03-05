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

interface AnalyzeOptions {
  fullScan?: boolean;
  generateGraph?: boolean;
  updateBaseline?: boolean;
}

/**
 * Main analyzer orchestrator
 * Coordinates file discovery, parsing, and engine execution
 */
export async function analyzeProject(_options: AnalyzeOptions): Promise<AnalysisResult> {
  const cwd = process.cwd();

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
  const allDiscoveredFiles = await discoverFiles(cwd, config, gitignoreParser);

  // CRITICAL FIX: Filter test files BEFORE analysis if excludeTestFiles is enabled
  // This prevents test files from being processed at all, reducing false positives
  const files = config.excludeTestFiles
    ? allDiscoveredFiles.filter(f => !isTestFile(f))
    : allDiscoveredFiles;

  // Get all enabled engines
  const engines = getAllEngines();

  // Analyze each file
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
        allIssues.push(...issues);
      }

      analyzedCount++;
      // codedrift-disable-next-line empty-catch
    } catch (error) {
      // Log parsing errors but continue analyzing other files
      // This is intentional - we don't want one bad file to stop the entire analysis
      console.warn(`Warning: Failed to parse ${filePath}:`, error instanceof Error ? error.message : error);
      // Continue with next file
    }
  }

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

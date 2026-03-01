import { glob } from 'glob';
import { AnalysisResult, AnalysisContext, Issue, CodeDriftConfig } from '../types/index.js';
import { parseFile } from './parser.js';
import { getAllEngines } from '../engines/index.js';
import { loadConfig, isRuleEnabled, getRuleSeverity, meetsConfidenceThreshold } from './config.js';
import { PackageResolver, GitIgnoreParser, isTestFile } from '../utils/index.js';
import * as fs from 'fs';

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

  // Discover files
  const files = await discoverFiles(cwd, config, gitignoreParser);

  // Get all enabled engines
  const engines = getAllEngines();

  // Analyze each file
  const allIssues: Issue[] = [];
  let analyzedCount = 0;

  for (const filePath of files) {
    try {
      // Check if this is a test file
      const isTest = isTestFile(filePath);

      // Skip test files if configured
      if (config.excludeTestFiles && isTest) {
        continue;
      }

      // Parse file
      const sourceFile = parseFile(filePath);
      const content = fs.readFileSync(filePath, 'utf-8');

      // Detect workspace name
      const workspaceName = packageResolver?.getWorkspaceName(filePath);

      // Create analysis context
      const context: AnalysisContext = {
        sourceFile,
        filePath,
        content,
        packageResolver: packageResolver || undefined,
        metadata: {
          isTestFile: isTest,
          workspaceName,
        },
      };

      // Run all engines
      for (const engine of engines) {
        // Check if engine is enabled
        if (!isRuleEnabled(config, engine.name)) {
          continue;
        }

        const issues = await engine.analyze(context);

        // Filter out null issues (suppressed by comments)
        const validIssues = issues.filter((issue): issue is Issue => issue !== null);

        // Apply rule severity overrides
        const adjustedIssues = validIssues.map(issue => {
          const configSeverity = getRuleSeverity(config, engine.name);
          if (configSeverity) {
            return { ...issue, severity: configSeverity };
          }
          return issue;
        });

        allIssues.push(...adjustedIssues);
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

  // Filter issues by confidence threshold
  const threshold = config.confidenceThreshold || 'low';
  const filteredIssues = allIssues.filter(issue => meetsConfidenceThreshold(issue, threshold));

  return {
    issues: filteredIssues,
    stats: {
      analyzed: analyzedCount,
      cached: 0, // Phase 4: Implement caching
      total: files.length,
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

  return uniqueFiles;
}

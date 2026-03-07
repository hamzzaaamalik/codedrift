import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import * as fs from 'fs';
import { analyzeProject, type AnalysisProgressEvent } from './core/analyzer.js';
import { ProgressDashboard } from './cli/progress-dashboard.js';
import { loadConfig } from './core/config.js';
import { formatJSON } from './core/formatter.js';
import { formatOutput, formatSARIF } from './formatters/index.js';
import { generateHTMLReport } from './core/html-report.js';
import { loadBaseline, saveBaseline, filterNewIssues, getDefaultBaselinePath } from './core/baseline.js';
import type { OutputFormat, Confidence } from './types/index.js';
import { fileURLToPath } from 'url';
import path from 'path';

// Read version from package.json
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const packageJson = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf-8'));

const program = new Command();

program
  .name('codedrift')
  .description('Local-first AI refactoring guardrail for Node.js backends')
  .version(packageJson.version);

program
  .command('analyze', { isDefault: true })
  .description('Analyze project for AI-induced regressions and drift')
  .option('--full', 'Force full scan (ignore cache)')
  .option('--graph', 'Generate dependency graph visualization')
  .option('--format <type>', 'Output format: summary (default), detailed, compact, json, html, sarif')
  .option('--details', 'Show detailed output (alias for --format detailed)')
  .option('--verbose', 'Show verbose output (alias for --format detailed)')
  .option('--quiet', 'Show only critical and high severity issues')
  .option('--no-color', 'Disable colored output')
  .option('--group-by <type>', 'Group issues by: severity (default), file, engine')
  .option('--output <file>', 'Write report to file')
  .option('--baseline', 'Save current issues as baseline')
  .option('--compare-baseline', 'Show only new issues not in baseline')
  .option('--baseline-file <path>', 'Custom baseline file path')
  .option('--confidence-threshold <level>', 'Minimum confidence level to report: high, medium, low (default: low)')
  .option('--exclude-tests', 'Exclude test files from analysis')
  .option('--min-risk <score>', 'Only show issues with risk score >= N (0-100)', parseInt)
  .option('--priority <level>', 'Only show issues with priority >= level (low, medium, high, critical)')
  .option('--deduplicate', 'Group duplicate issues together (exact match)')
  .option('--deduplicate-by-message', 'Group issues by message pattern (looser grouping)')
  .option('--show-risk-scores', 'Display risk scores in output')
  .action(async (options) => {
    const config = loadConfig();

    // Validate format option
    if (options.format) {
      const validFormats = ['summary', 'detailed', 'compact', 'json', 'html', 'sarif'];
      if (!validFormats.includes(options.format)) {
        console.error(chalk.red(`Invalid format: ${options.format}`));
        console.error(chalk.gray('Valid values: summary, detailed, compact, json, html, sarif'));
        process.exit(1);
      }
    }

    // Validate group-by option
    if (options.groupBy) {
      const validGroupBy = ['severity', 'file', 'engine'];
      if (!validGroupBy.includes(options.groupBy)) {
        console.error(chalk.red(`Invalid group-by: ${options.groupBy}`));
        console.error(chalk.gray('Valid values: severity, file, engine'));
        process.exit(1);
      }
    }

    // Detect CI environment first
    const ci = !!process.env.CI || !process.stdout.isTTY;

    // Override config with CLI options
    // In CI mode, default to compact format unless explicitly specified
    const defaultFormat = ci ? 'compact' : 'summary';
    const outputFormat: OutputFormat = options.format || config.format || defaultFormat as OutputFormat;
    const outputFile = options.output || config.output;

    // Apply CLI overrides to config
    if (options.confidenceThreshold) {
      const validLevels: Confidence[] = ['high', 'medium', 'low'];
      const threshold = options.confidenceThreshold.toLowerCase() as Confidence;
      if (!validLevels.includes(threshold)) {
        console.error(chalk.red(`Invalid confidence threshold: ${options.confidenceThreshold}`));
        console.error(chalk.gray('Valid values: high, medium, low'));
        process.exit(1);
      }
      config.confidenceThreshold = threshold;
    }

    if (options.excludeTests) {
      config.excludeTestFiles = true;
    }

    // Use interactive dashboard for terminal output (not in CI, not to file)
    const useInteractive = (outputFormat === 'terminal' || outputFormat === 'summary' || outputFormat === 'detailed')
                           && !outputFile && !ci;
    const dashboard = new ProgressDashboard(useInteractive);
    // Fallback spinner for CI or non-interactive
    const spinner = (!useInteractive && !ci && !outputFile) ? ora('🔍 Analyzing...').start() : null;

    try {
      if (useInteractive) dashboard.start();

      const startTime = Date.now();
      const result = await analyzeProject({
        fullScan: options.full,
        generateGraph: options.graph,
        updateBaseline: false, // We handle baseline separately
        onProgress: (event: AnalysisProgressEvent) => {
          dashboard.update(event as any);
        },
      });
      const endTime = Date.now();

      result.startTime = startTime;
      result.endTime = endTime;

      if (useInteractive) {
        dashboard.stop();
      } else if (spinner) {
        spinner.succeed('🔬 Analysis complete');
      }

      // Handle baseline mode
      const baselineFile = options.baselineFile || getDefaultBaselinePath();

      if (options.baseline) {
        // Save baseline
        saveBaseline(result.issues, baselineFile, packageJson.version);
        console.log(chalk.green(`✓ Baseline saved to ${baselineFile}`));
        console.log(chalk.gray(`  ${result.issues.length} issues captured as baseline`));
        process.exit(0);
      }

      // Filter issues if comparing against baseline
      let issuesToReport = result.issues;
      if (options.compareBaseline) {
        const baseline = loadBaseline(baselineFile);
        if (!baseline) {
          console.warn(chalk.yellow(`⚠ No baseline found at ${baselineFile}`));
          console.warn(chalk.yellow('  Run with --baseline to create one'));
        } else {
          const originalCount = result.issues.length;
          issuesToReport = filterNewIssues(result.issues, baseline);
          const newCount = issuesToReport.length;

          if (outputFormat === 'terminal') {
            console.log(chalk.blue(`ℹ Baseline comparison enabled`));
            console.log(chalk.gray(`  Total issues: ${originalCount}`));
            console.log(chalk.gray(`  New issues: ${newCount}`));
            console.log(chalk.gray(`  Baseline issues: ${originalCount - newCount}\n`));
          }
        }
      }

      // Apply risk score filtering
      if (options.minRisk !== undefined) {
        const minRisk = options.minRisk;
        if (minRisk < 0 || minRisk > 100) {
          console.error(chalk.red(`Invalid risk score: ${minRisk} (must be 0-100)`));
          process.exit(1);
        }
        const beforeCount = issuesToReport.length;
        issuesToReport = issuesToReport.filter(issue => (issue.riskScore || 0) >= minRisk);
        if (outputFormat === 'terminal') {
          console.log(chalk.blue(`ℹ Risk score filter: >= ${minRisk}`));
          console.log(chalk.gray(`  Filtered: ${beforeCount} → ${issuesToReport.length} issues\n`));
        }
      }

      // Apply priority filtering
      if (options.priority) {
        const priorityLevels = ['low', 'medium', 'high', 'critical'];
        const minPriority = options.priority.toLowerCase();
        if (!priorityLevels.includes(minPriority)) {
          console.error(chalk.red(`Invalid priority: ${options.priority}`));
          console.error(chalk.gray('Valid values: low, medium, high, critical'));
          process.exit(1);
        }
        const minLevel = priorityLevels.indexOf(minPriority);
        const beforeCount = issuesToReport.length;
        issuesToReport = issuesToReport.filter(issue => {
          const issueLevel = priorityLevels.indexOf(issue.priority || 'low');
          return issueLevel >= minLevel;
        });
        if (outputFormat === 'terminal') {
          console.log(chalk.blue(`ℹ Priority filter: >= ${minPriority}`));
          console.log(chalk.gray(`  Filtered: ${beforeCount} → ${issuesToReport.length} issues\n`));
        }
      }

      // Use filtered issues for output and exit code
      const reportResult = { ...result, issues: issuesToReport };

      // Store CLI options for formatters
      const formatterOptions = {
        showRiskScores: options.showRiskScores || false,
        deduplicate: options.deduplicate || false,
      };

      // Format output
      let outputContent: string;

      // Auto-detect format from file extension if output file specified
      let finalFormat = outputFormat;
      if (outputFile && !options.format) {
        if (outputFile.endsWith('.html')) {
          finalFormat = 'html' as OutputFormat;
        } else if (outputFile.endsWith('.json')) {
          finalFormat = 'json';
        } else if (outputFile.endsWith('.sarif')) {
          finalFormat = 'sarif' as OutputFormat;
        }
      }

      if (finalFormat === 'json') {
        outputContent = formatJSON(reportResult, config);
      } else if (finalFormat === 'html') {
        outputContent = generateHTMLReport(reportResult, config, formatterOptions);
      } else if (finalFormat === 'sarif') {
        outputContent = formatSARIF(reportResult, config);
      } else {
        // Use the new formatOutput function for terminal/summary/detailed/compact formats
        outputContent = formatOutput(reportResult, config, {
          format: (finalFormat === 'terminal' ? 'summary' : finalFormat) as any,
          noColor: options.noColor,
          quiet: options.quiet,
          verbose: options.verbose,
          details: options.details,
          groupBy: options.groupBy,
        });
      }

      // Write to file or stdout
      if (outputFile) {
        fs.mkdirSync(path.dirname(outputFile), { recursive: true });
        fs.writeFileSync(outputFile, outputContent, 'utf-8');
        if (finalFormat === 'terminal') {
          console.log(chalk.green(`✓ Report written to ${outputFile}`));
        } else if (finalFormat === 'sarif') {
          console.log(chalk.green(`✓ SARIF report written to ${outputFile}`));
          console.log(chalk.gray('  Upload to GitHub Code Scanning: Settings → Security → Code scanning'));
        } else {
          console.log(chalk.green(`✓ ${finalFormat.toUpperCase()} report written to ${outputFile}`));
        }
      } else {
        console.log(outputContent);

        // Auto-generate HTML report on local interactive runs
        if (!ci && !options.output && finalFormat !== 'json' && finalFormat !== 'sarif' && finalFormat !== 'html') {
          const htmlPath = 'codedrift-report.html';
          const htmlContent = generateHTMLReport(reportResult, config, formatterOptions);
          fs.mkdirSync(path.dirname(htmlPath), { recursive: true });
          fs.writeFileSync(htmlPath, htmlContent, 'utf-8');
          console.log(chalk.cyan(`\nReport: ${htmlPath} (open in browser)`));
        }
      }

      // Determine exit code based on filtered issues
      const criticalIssues = issuesToReport.filter(i => i.severity === 'error');
      const highIssues = issuesToReport.filter(i => i.severity === 'warning');

      const failOn = config.failOn || 'error';
      const shouldFail = failOn === 'error'
        ? criticalIssues.length > 0
        : (criticalIssues.length > 0 || highIssues.length > 0);

      // Exit codes
      if (shouldFail) {
        // Exit code 1: Critical/high issues found
        if (!ci && !outputFile) {
          const reason = failOn === 'warn' ? 'errors or warnings' : 'critical issues';
          console.log(chalk.red.bold(`\n❌ Build failed due to ${reason}`));
        }
        process.exit(1);
      } else {
        // Exit code 0: No issues found
        if (!ci && !outputFile && finalFormat !== 'compact') {
          console.log(chalk.green.bold('\n✅ No critical issues found'));
        }
        process.exit(0);
      }

    } catch (error) {
      if (useInteractive) dashboard.stop(error instanceof Error ? error.message : String(error));
      if (spinner) spinner.stop();
      console.error(chalk.red.bold('\n❌ Error:'), error instanceof Error ? error.message : error);
      // Exit code 2: Analysis error
      process.exit(2);
    }
  });


program.parse();

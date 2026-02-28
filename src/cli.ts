#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import * as fs from 'fs';
import * as readline from 'readline/promises';
import { analyzeProject } from './core/analyzer.js';
import { loadConfig } from './core/config.js';
import { formatTerminal, formatJSON } from './core/formatter.js';
import { generateHTMLReport } from './core/html-report.js';
import { loadBaseline, saveBaseline, filterNewIssues, getDefaultBaselinePath } from './core/baseline.js';
import type { OutputFormat, AnalysisResult, CodeDriftConfig } from './types/index.js';

const program = new Command();

program
  .name('codedrift')
  .description('Local-first AI refactoring guardrail for Node.js backends')
  .version('1.1.0');

program
  .command('analyze', { isDefault: true })
  .description('Analyze project for AI-induced regressions and drift')
  .option('--full', 'Force full scan (ignore cache)')
  .option('--graph', 'Generate dependency graph visualization')
  .option('--format <type>', 'Output format: terminal, json, html (default: terminal)')
  .option('--output <file>', 'Write report to file')
  .option('--baseline', 'Save current issues as baseline')
  .option('--compare-baseline', 'Show only new issues not in baseline')
  .option('--baseline-file <path>', 'Custom baseline file path')
  .action(async (options) => {
    const config = loadConfig();

    // Override config with CLI options
    const outputFormat: OutputFormat = options.format || config.format || 'terminal';
    const outputFile = options.output || config.output;

    const useSpinner = outputFormat === 'terminal' && !outputFile;
    const spinner = useSpinner ? ora('Initializing CodeDrift...').start() : null;

    try {
      if (spinner) spinner.text = 'Analyzing project...';

      const startTime = Date.now();
      const result = await analyzeProject({
        fullScan: options.full,
        generateGraph: options.graph,
        updateBaseline: false, // We handle baseline separately
      });
      const endTime = Date.now();

      result.startTime = startTime;
      result.endTime = endTime;

      if (spinner) spinner.stop();

      // Handle baseline mode
      const baselineFile = options.baselineFile || getDefaultBaselinePath();

      if (options.baseline) {
        // Save baseline
        saveBaseline(result.issues, baselineFile, '1.1.0');
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

      // Use filtered issues for output and exit code
      const reportResult = { ...result, issues: issuesToReport };

      // Format output
      let outputContent: string;

      // Auto-detect format from file extension if output file specified
      let finalFormat = outputFormat;
      if (outputFile && !options.format) {
        if (outputFile.endsWith('.html')) {
          finalFormat = 'html' as OutputFormat;
        } else if (outputFile.endsWith('.json')) {
          finalFormat = 'json';
        }
      }

      if (finalFormat === 'json') {
        outputContent = formatJSON(reportResult, config);
      } else if (finalFormat === 'html') {
        outputContent = generateHTMLReport(reportResult, config);
      } else {
        outputContent = formatTerminal(reportResult, config);
      }

      // Write to file or stdout
      if (outputFile) {
        fs.writeFileSync(outputFile, outputContent, 'utf-8');
        if (finalFormat === 'terminal') {
          console.log(chalk.green(`✓ Report written to ${outputFile}`));
        } else {
          console.log(chalk.green(`✓ ${finalFormat.toUpperCase()} report written to ${outputFile}`));
        }
      } else {
        console.log(outputContent);

        // Interactive: Ask if user wants HTML report (only in terminal mode with issues)
        if (finalFormat === 'terminal' && issuesToReport.length > 0) {
          await promptForHTMLReport(reportResult, config);
        }
      }

      // Determine exit code based on filtered issues
      const criticalIssues = issuesToReport.filter(i => i.severity === 'error');
      const highIssues = issuesToReport.filter(i => i.severity === 'warning');

      const failOn = config.failOn || 'error';
      const shouldFail = failOn === 'error'
        ? criticalIssues.length > 0
        : (criticalIssues.length > 0 || highIssues.length > 0);

      if (shouldFail) {
        const reason = failOn === 'warn' ? 'errors or warnings' : 'critical issues';
        if (outputFormat === 'terminal' && !outputFile) {
          console.log(chalk.red.bold(`\n❌ Build failed due to ${reason} (exit code 1)`));
        }
        process.exit(1);
      } else {
        if (outputFormat === 'terminal' && !outputFile) {
          console.log(chalk.green.bold('\n✅ No critical issues found'));
        }
        process.exit(0);
      }

    } catch (error) {
      if (spinner) spinner.stop();
      console.error(chalk.red.bold('\n❌ Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

/**
 * Prompt user if they want to generate an HTML report
 */
async function promptForHTMLReport(result: AnalysisResult, config: CodeDriftConfig): Promise<void> {
  try {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    console.log(''); // Add spacing
    const answer = await rl.question(chalk.cyan('📄 Generate HTML report? (y/n): '));
    rl.close();

    if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
      const defaultFilename = 'codedrift-report.html';
      const filename = defaultFilename;

      const htmlContent = generateHTMLReport(result, config);
      fs.writeFileSync(filename, htmlContent, 'utf-8');

      console.log(chalk.green(`✓ HTML report saved to ${filename}`));
      console.log(chalk.gray(`  Open it in your browser to see the full report`));
    }
  } catch (error) {
    // User cancelled or error - just continue
    console.log(''); // Add spacing
  }
}

program.parse();

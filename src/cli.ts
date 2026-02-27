#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { analyzeProject } from './core/analyzer.js';
import { loadConfig } from './core/config.js';

const program = new Command();

program
  .name('codedrift')
  .description('Local-first AI refactoring guardrail for Node.js backends')
  .version('1.0.0');

program
  .command('analyze', { isDefault: true })
  .description('Analyze project for AI-induced regressions and drift')
  .option('--full', 'Force full scan (ignore cache)')
  .option('--graph', 'Generate dependency graph visualization')
  .option('--baseline', 'Update baseline snapshot')
  .action(async (options) => {
    const spinner = ora('Initializing CodeDrift...').start();

    try {
      spinner.text = 'Analyzing project...';

      const result = await analyzeProject({
        fullScan: options.full,
        generateGraph: options.graph,
        updateBaseline: options.baseline,
      });

      spinner.stop();

      // Display results
      console.log(chalk.bold('\n📊 CodeDrift Analysis Complete\n'));

      const criticalIssues = result.issues.filter(i => i.severity === 'error');
      const highIssues = result.issues.filter(i => i.severity === 'warning');
      const infoIssues = result.issues.filter(i => i.severity === 'info');

      if (criticalIssues.length > 0) {
        console.log(chalk.red.bold(`🔴 CRITICAL Issues (${criticalIssues.length}) - Blocking\n`));
        criticalIssues.forEach(issue => {
          console.log(`  ${chalk.gray(issue.filePath)}:${issue.location.line}`);
          console.log(`  ${chalk.red('❌')} ${issue.message}`);
          if (issue.suggestion) {
            console.log(`  ${chalk.dim('→')} ${issue.suggestion}`);
          }
          console.log();
        });
      }

      if (highIssues.length > 0) {
        console.log(chalk.yellow.bold(`⚠️  HIGH Issues (${highIssues.length})\n`));
        highIssues.forEach(issue => {
          console.log(`  ${chalk.gray(issue.filePath)}:${issue.location.line}`);
          console.log(`  ${chalk.yellow('⚠️')} ${issue.message}`);
          if (issue.suggestion) {
            console.log(`  ${chalk.dim('→')} ${issue.suggestion}`);
          }
          console.log();
        });
      }

      if (infoIssues.length > 0 && infoIssues.length <= 10) {
        console.log(chalk.blue.bold(`ℹ️  INFO (${infoIssues.length})\n`));
        infoIssues.forEach(issue => {
          console.log(`  ${chalk.gray(issue.filePath)}:${issue.location.line}`);
          console.log(`  ${chalk.blue('ℹ️')} ${issue.message}`);
          console.log();
        });
      } else if (infoIssues.length > 10) {
        console.log(chalk.blue(`ℹ️  INFO: ${infoIssues.length} low-priority issues (use --verbose to show all)`));
        console.log();
      }

      console.log(chalk.bold('📊 Stats'));
      console.log(`  • Analyzed: ${result.stats.analyzed} files`);
      console.log(`  • Cached: ${result.stats.cached} files`);
      console.log(`  • Total: ${result.stats.total} files`);
      console.log();

      // Load config to check failOn setting
      const config = loadConfig();
      const failOn = config.failOn || 'error';

      // Exit with code 1 based on configuration
      const shouldFail = failOn === 'error'
        ? criticalIssues.length > 0
        : (criticalIssues.length > 0 || highIssues.length > 0);

      if (shouldFail) {
        const reason = failOn === 'warn' ? 'errors or warnings' : 'critical issues';
        console.log(chalk.red.bold(`❌ Build failed due to ${reason} (exit code 1)`));
        process.exit(1);
      } else {
        console.log(chalk.green.bold('✅ No critical issues found'));
        process.exit(0);
      }

    } catch (error) {
      spinner.stop();
      console.error(chalk.red.bold('\n❌ Error:'), error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

program.parse();

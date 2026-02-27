/**
 * Output formatters for different report formats
 */

import type { AnalysisResult, Issue, JSONReport, CodeDriftConfig } from '../types/index.js';
import chalk from 'chalk';

export function formatTerminal(result: AnalysisResult, _config: CodeDriftConfig): string {
  const { issues, stats } = result;

  const criticalIssues = issues.filter(i => i.severity === 'error');
  const highIssues = issues.filter(i => i.severity === 'warning');

  let output = '\n' + chalk.bold('CodeDrift Analysis Complete\n');

  if (criticalIssues.length > 0) {
    output += '\n' + chalk.red.bold(`CRITICAL Issues (${criticalIssues.length}) - Blocking\n`);
    criticalIssues.forEach(issue => {
      output += '\n' + formatIssue(issue);
    });
  }

  if (highIssues.length > 0) {
    output += '\n' + chalk.yellow.bold(`\nWARNINGS (${highIssues.length})\n`);
    highIssues.forEach(issue => {
      output += '\n' + formatIssue(issue);
    });
  }

  if (issues.length === 0) {
    output += '\n' + chalk.green.bold('✓ No issues found!\n');
  }

  output += '\n' + chalk.bold('Stats\n');
  output += `  • Analyzed: ${stats.analyzed} files\n`;
  output += `  • Total: ${stats.total} files\n`;

  if (result.startTime && result.endTime) {
    const duration = result.endTime - result.startTime;
    output += `  • Duration: ${duration}ms\n`;
  }

  return output;
}

function formatIssue(issue: Issue): string {
  let output = '';

  output += chalk.cyan(`  ${issue.filePath}:${issue.location.line}\n`);
  output += `  ${issue.message}\n`;

  if (issue.suggestion) {
    output += chalk.gray(`  → ${issue.suggestion}\n`);
  }

  return output;
}

export function formatJSON(result: AnalysisResult, config: CodeDriftConfig): string {
  const { issues, stats, startTime, endTime } = result;

  const criticalIssues = issues.filter(i => i.severity === 'error');
  const warnings = issues.filter(i => i.severity === 'warning');

  const duration = startTime && endTime ? endTime - startTime : 0;

  const rulesEnabled = Object.entries(config.rules || {})
    .filter(([_, level]) => level !== 'off')
    .map(([rule]) => rule);

  const jsonReport: JSONReport = {
    summary: {
      totalFiles: stats.total,
      analyzedFiles: stats.analyzed,
      totalIssues: issues.length,
      criticalIssues: criticalIssues.length,
      warnings: warnings.length,
      timestamp: new Date().toISOString(),
      duration,
    },
    issues: issues.map(issue => ({
      engine: issue.engine,
      severity: issue.severity,
      message: issue.message,
      filePath: issue.filePath,
      location: {
        line: issue.location.line,
        column: issue.location.column,
      },
      suggestion: issue.suggestion,
      ruleId: issue.engine,
    })),
    config: {
      failOn: config.failOn || 'error',
      rulesEnabled,
    },
  };

  return JSON.stringify(jsonReport, null, 2);
}

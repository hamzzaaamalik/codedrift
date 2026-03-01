/**
 * Detailed formatter - full issue details with code context
 */

import type { AnalysisResult, CodeDriftConfig, Issue } from '../types/index.js';
import chalk from 'chalk';
import * as fs from 'fs';
import { getEngineName, getSeverityIcon, getConfidenceStars } from './types.js';

interface DetailedOptions {
  noColor?: boolean;
  ci?: boolean;
}

/**
 * Format analysis result with detailed information
 */
export function formatDetailed(
  result: AnalysisResult,
  _config: CodeDriftConfig,
  options: DetailedOptions = {}
): string {
  const { issues, stats } = result;
  const { noColor = false, ci = false } = options;

  // Disable colors in CI or if requested
  const useColors = !noColor && !ci;
  const useEmoji = !ci;

  // Color helpers
  const red = useColors ? chalk.red.bold : (s: string) => s;
  const yellow = useColors ? chalk.yellow.bold : (s: string) => s;
  const cyan = useColors ? chalk.cyan : (s: string) => s;
  const gray = useColors ? chalk.gray : (s: string) => s;
  const green = useColors ? chalk.green : (s: string) => s;
  const bold = useColors ? chalk.bold : (s: string) => s;

  let output = '\n';

  // Header
  output += cyan('━'.repeat(70)) + '\n';
  output += bold('  CodeDrift Analysis - Detailed Report\n');
  output += cyan('━'.repeat(70)) + '\n\n';

  // Summary
  const criticalIssues = issues.filter(i => i.severity === 'error');
  const warnings = issues.filter(i => i.severity === 'warning');

  output += bold('Summary:\n');
  output += `  Total Issues: ${cyan(issues.length.toString())}\n`;
  output += `  Critical: ${red(criticalIssues.length.toString())}  `;
  output += `Warnings: ${yellow(warnings.length.toString())}\n`;
  output += `  Files Analyzed: ${cyan(stats.analyzed.toString())}/${stats.total}\n`;
  output += '\n';

  if (issues.length === 0) {
    const successIcon = useEmoji ? '✅ ' : '';
    output += green(`${successIcon}No issues found! Your code looks clean.\n\n`);
    return output;
  }

  // Group by severity, then show each issue
  const criticalFirst = [...criticalIssues, ...warnings];

  criticalFirst.forEach((issue, index) => {
    output += formatDetailedIssue(issue, index + 1, useColors, useEmoji);
    output += '\n';
  });

  // Footer
  output += cyan('━'.repeat(70)) + '\n';

  if (result.startTime && result.endTime) {
    const duration = result.endTime - result.startTime;
    const durationSec = (duration / 1000).toFixed(2);
    output += gray(`Analysis completed in ${durationSec}s\n`);
  }

  return output;
}

/**
 * Format a single issue with full details
 */
function formatDetailedIssue(
  issue: Issue,
  _index: number,
  useColors: boolean,
  useEmoji: boolean
): string {
  const red = useColors ? chalk.red.bold : (s: string) => s;
  const yellow = useColors ? chalk.yellow.bold : (s: string) => s;
  const cyan = useColors ? chalk.cyan : (s: string) => s;
  const gray = useColors ? chalk.gray : (s: string) => s;
  const bold = useColors ? chalk.bold : (s: string) => s;

  let output = '';

  // Separator
  output += cyan('━'.repeat(70)) + '\n';

  // Title
  const icon = getSeverityIcon(issue.severity, useEmoji);
  const severityText = issue.severity === 'error' ? red('CRITICAL') : yellow('WARNING');
  const engineName = getEngineName(issue.engine);

  output += `${icon} ${severityText} • ${bold(engineName)}\n`;
  output += cyan('━'.repeat(70)) + '\n\n';

  // Details
  const filePath = issue.filePath;
  const location = `${issue.location.line}:${issue.location.column}`;

  output += `  ${bold('File:')}       ${filePath}:${location}\n`;
  output += `  ${bold('Engine:')}     ${issue.engine}\n`;

  const confidence = issue.confidence || 'high';
  const stars = getConfidenceStars(confidence);
  output += `  ${bold('Confidence:')} ${stars} ${capitalize(confidence)}\n`;

  output += '\n';

  // Message
  output += `  ${issue.message}\n`;
  output += '\n';

  // Code context
  const context = getCodeContext(issue.filePath, issue.location.line, useColors);
  if (context) {
    output += context + '\n';
  }

  // Suggestion
  if (issue.suggestion) {
    const suggestionIcon = useEmoji ? '💡 ' : '';
    output += `  ${cyan(suggestionIcon + 'Suggestion:')}\n`;
    output += `     ${gray(issue.suggestion)}\n`;
  }

  return output;
}

/**
 * Get code context around the issue location
 */
function getCodeContext(
  filePath: string,
  line: number,
  useColors: boolean
): string | null {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    const startLine = Math.max(0, line - 3); // 2 lines before
    const endLine = Math.min(lines.length - 1, line + 1); // 2 lines after

    let output = '';
    const gray = useColors ? chalk.gray : (s: string) => s;
    const red = useColors ? chalk.red : (s: string) => s;
    const yellow = useColors ? chalk.yellow : (s: string) => s;

    for (let i = startLine; i <= endLine; i++) {
      const lineNum = (i + 1).toString().padStart(4, ' ');
      const lineContent = lines[i] || '';

      if (i + 1 === line) {
        // Highlight the problem line
        const color = useColors ? red : (s: string) => s;
        output += `  ${color(lineNum + ' | ' + lineContent)}\n`;

        // Add caret indicator
        const spaces = ' '.repeat(6 + lineContent.search(/\S/));
        const carets = yellow('^'.repeat(Math.min(lineContent.trim().length, 40)));
        output += `  ${spaces}${carets}\n`;
      } else {
        output += `  ${gray(lineNum + ' | ' + lineContent)}\n`;
      }
    }

    return output;
  } catch (error) {
    return null;
  }
}

/**
 * Capitalize first letter
 */
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

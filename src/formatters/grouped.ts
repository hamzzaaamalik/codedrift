/**
 * Grouped formatter - group issues by file, engine, or severity
 */

import type { AnalysisResult, CodeDriftConfig, Issue } from '../types/index.js';
import chalk from 'chalk';
import { groupIssues, type GroupByType, getEngineName, getSeverityIcon } from './types.js';

interface GroupedOptions {
  noColor?: boolean;
  ci?: boolean;
  groupBy: GroupByType;
}

/**
 * Format analysis result with grouping
 */
export function formatGrouped(
  result: AnalysisResult,
  _config: CodeDriftConfig,
  options: GroupedOptions
): string {
  const { issues, stats } = result;
  const { noColor = false, ci = false, groupBy } = options;

  // Disable colors in CI or if requested
  const useColors = !noColor && !ci;
  const useEmoji = !ci;

  const red = useColors ? chalk.red.bold : (s: string) => s;
  const yellow = useColors ? chalk.yellow.bold : (s: string) => s;
  const cyan = useColors ? chalk.cyan : (s: string) => s;
  const gray = useColors ? chalk.gray : (s: string) => s;
  const bold = useColors ? chalk.bold : (s: string) => s;
  const green = useColors ? chalk.green : (s: string) => s;

  let output = '\n';

  // Header
  output += cyan('═'.repeat(70)) + '\n';
  output += bold('  CodeDrift Analysis - Grouped by ' + capitalize(groupBy) + '\n');
  output += cyan('═'.repeat(70)) + '\n\n';

  // Summary
  const criticalIssues = issues.filter(i => i.severity === 'error');
  const warnings = issues.filter(i => i.severity === 'warning');

  output += `  Total Issues: ${cyan(issues.length.toString())}  `;
  output += `Critical: ${red(criticalIssues.length.toString())}  `;
  output += `Warnings: ${yellow(warnings.length.toString())}\n`;
  output += `  Files Analyzed: ${cyan(stats.analyzed.toString())}/${stats.total}\n`;
  output += '\n';

  if (issues.length === 0) {
    const successIcon = useEmoji ? '✅ ' : '';
    output += green(`${successIcon}No issues found! Your code looks clean.\n\n`);
    return output;
  }

  // Group issues
  const groups = groupIssues(issues, groupBy);

  // Display each group
  groups.forEach((group, index) => {
    if (index > 0) {
      output += '\n';
    }

    // Group header
    output += gray('─'.repeat(70)) + '\n';

    const groupName = formatGroupName(group.name, groupBy, useEmoji);
    const counts = formatGroupCounts(group, useColors);

    output += bold(`${groupName}\n`);
    output += gray(`  ${counts}\n`);
    output += gray('─'.repeat(70)) + '\n';

    // Show issues in group (limit to 10 per group for readability)
    const toShow = group.issues.slice(0, 10);

    toShow.forEach((issue, issueIndex) => {
      output += formatGroupedIssue(issue, groupBy, useColors, useEmoji);

      if (issueIndex < toShow.length - 1) {
        output += '\n';
      }
    });

    // Show remaining count if truncated
    if (group.issues.length > 10) {
      const remaining = group.issues.length - 10;
      output += `\n${gray(`  ... and ${remaining} more issue${remaining > 1 ? 's' : ''} in this group`)}\n`;
    }
  });

  // Footer
  output += '\n';
  output += cyan('═'.repeat(70)) + '\n';

  if (result.startTime && result.endTime) {
    const duration = result.endTime - result.startTime;
    const durationSec = (duration / 1000).toFixed(2);
    output += gray(`Analysis completed in ${durationSec}s\n`);
  }

  return output;
}

/**
 * Format group name based on grouping type
 */
function formatGroupName(name: string, groupBy: GroupByType, useEmoji: boolean): string {
  switch (groupBy) {
    case 'severity':
      const icon = getSeverityIcon(name, useEmoji);
      return `${icon} ${capitalize(name)} Severity`;

    case 'engine':
      const engineIcon = useEmoji ? '🔧 ' : '';
      return `${engineIcon}${getEngineName(name)}`;

    case 'file':
      const fileIcon = useEmoji ? '📄 ' : '';
      const shortPath = truncateFilePath(name);
      return `${fileIcon}${shortPath}`;

    default:
      return name;
  }
}

/**
 * Format group counts
 */
function formatGroupCounts(group: any, useColors: boolean): string {
  const red = useColors ? chalk.red : (s: string) => s;
  const yellow = useColors ? chalk.yellow : (s: string) => s;
  const cyan = useColors ? chalk.cyan : (s: string) => s;

  const parts: string[] = [];

  if (group.criticalCount > 0) {
    parts.push(red(`${group.criticalCount} critical`));
  }
  if (group.warningCount > 0) {
    parts.push(yellow(`${group.warningCount} warning${group.warningCount > 1 ? 's' : ''}`));
  }

  parts.push(cyan(`${group.issues.length} total`));

  return parts.join(', ');
}

/**
 * Format a single issue within a group
 */
function formatGroupedIssue(
  issue: Issue,
  groupBy: GroupByType,
  useColors: boolean,
  useEmoji: boolean
): string {
  const gray = useColors ? chalk.gray : (s: string) => s;
  const cyan = useColors ? chalk.cyan : (s: string) => s;

  let output = '';

  // Show different details based on grouping
  switch (groupBy) {
    case 'file':
      // When grouped by file, show line and engine
      const icon = getSeverityIcon(issue.severity, useEmoji);
      const engineName = getEngineName(issue.engine);
      output += `\n  ${icon} ${cyan(`Line ${issue.location.line}`)}: ${engineName}\n`;
      output += `     ${gray(issue.message)}\n`;
      break;

    case 'engine':
      // When grouped by engine, show file and line
      const sevIcon = getSeverityIcon(issue.severity, useEmoji);
      const filePath = truncateFilePath(issue.filePath);
      output += `\n  ${sevIcon} ${cyan(`${filePath}:${issue.location.line}`)}\n`;
      output += `     ${gray(issue.message)}\n`;
      break;

    case 'severity':
      // When grouped by severity, show file and engine
      const engName = getEngineName(issue.engine);
      const path = truncateFilePath(issue.filePath);
      output += `\n  ${cyan(engName)}: ${gray(path + ':' + issue.location.line)}\n`;
      output += `     ${gray(issue.message)}\n`;
      break;
  }

  return output;
}

/**
 * Truncate file path for display
 */
function truncateFilePath(filePath: string, maxLength: number = 55): string {
  if (filePath.length <= maxLength) {
    return filePath;
  }

  const parts = filePath.split(/[/\\]/);
  const filename = parts[parts.length - 1];
  const parent = parts[parts.length - 2];

  if (parent && filename) {
    const short = `.../${parent}/${filename}`;
    if (short.length <= maxLength) {
      return short;
    }
  }

  return '...' + filePath.slice(-(maxLength - 3));
}

/**
 * Capitalize first letter
 */
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

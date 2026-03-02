/**
 * Smart summary formatter - concise, actionable output (default)
 */

import type { AnalysisResult, CodeDriftConfig } from '../types/index.js';
import chalk from 'chalk';
import { calculateRiskScore, getSeverityIcon, getEngineName } from './types.js';

interface SummaryOptions {
  noColor?: boolean;
  ci?: boolean;
}

/**
 * Format analysis result as smart summary
 */
export function formatSummary(
  result: AnalysisResult,
  _config: CodeDriftConfig,
  options: SummaryOptions = {}
): string {
  const { issues, stats } = result;
  const { noColor = false, ci = false } = options;

  // Disable colors in CI or if requested
  const useColors = !noColor && !ci;
  const useEmoji = !ci;

  // Color helpers
  const red = useColors ? chalk.red.bold : (s: string) => s;
  const orange = useColors ? chalk.hex('#FFA500').bold : (s: string) => s;
  const yellow = useColors ? chalk.yellow.bold : (s: string) => s;
  const blue = useColors ? chalk.blue.bold : (s: string) => s;
  const cyan = useColors ? chalk.cyan : (s: string) => s;
  const gray = useColors ? chalk.gray : (s: string) => s;
  const green = useColors ? chalk.green.bold : (s: string) => s;

  let output = '\n';

  // Analysis header with file breakdown
  const analyzeIcon = useEmoji ? '🔍 ' : '';
  const excluded = stats.total - stats.analyzed;
  if (excluded > 0) {
    output += gray(`${analyzeIcon}Scanned ${stats.total.toLocaleString()} files, analyzing ${stats.analyzed.toLocaleString()} (${excluded.toLocaleString()} excluded by config)\n`);
  } else {
    output += gray(`${analyzeIcon}Analyzing ${stats.total.toLocaleString()} files...\n`);
  }
  output += '\n';

  // Complete header
  const completeIcon = useEmoji ? '📊 ' : '';
  output += cyan(`${completeIcon}Analysis Complete\n`);
  output += '\n';

  // Filter by confidence (high only for summary)
  const highConfidenceIssues = issues.filter(i => (i.confidence || 'high') === 'high');

  // Count by severity
  const criticalIssues = highConfidenceIssues.filter(i => i.severity === 'error');
  const highIssues = highConfidenceIssues.filter(i => i.severity === 'warning');
  const mediumIssues = issues.filter(i => i.severity === 'warning' && (i.confidence || 'high') === 'medium');
  const lowIssues = issues.filter(i => (i.confidence || 'high') === 'low');

  // Severity summary
  const critIcon = getSeverityIcon('error', useEmoji);
  const highIcon = getSeverityIcon('warning', useEmoji);
  const medIcon = useEmoji ? '🟡' : '[MEDIUM]';
  const lowIcon = getSeverityIcon('info', useEmoji);

  const critText = `${critIcon} Critical:`;
  const highText = `${highIcon} High:`;
  const medText = `${medIcon} Medium:`;
  const lowText = `${lowIcon} Low:`;

  const pad = 24;
  output += `  ${critText.padEnd(pad, ' ')}${red(criticalIssues.length.toString().padStart(6))}`;
  if (criticalIssues.length > 0) {
    output += red('    ← Fix these first!');
  }
  output += '\n';

  output += `  ${highText.padEnd(pad, ' ')}${orange(highIssues.length.toString().padStart(6))}\n`;
  output += `  ${medText.padEnd(pad, ' ')}${yellow(mediumIssues.length.toString().padStart(6))}\n`;
  output += `  ${lowText.padEnd(pad, ' ')}${blue(lowIssues.length.toString().padStart(6))}\n`;

  output += `  ${'─'.repeat(30)}\n`;
  output += `  Total:${' '.repeat(pad - 6)}${cyan(highConfidenceIssues.length.toString().padStart(6))} ${gray('(high confidence only)')}\n`;
  output += '\n';

  // Top 5 issues to fix
  if (criticalIssues.length > 0 || highIssues.length > 0) {
    const topIcon = useEmoji ? '🎯 ' : '';
    output += cyan(`${topIcon}Top 5 Issues to Fix:\n`);
    output += '\n';

    // Calculate risk scores and sort
    const allPriorityIssues = [...criticalIssues, ...highIssues];
    const scored = allPriorityIssues.map(issue => ({
      issue,
      score: calculateRiskScore(issue),
    }));
    scored.sort((a, b) => b.score - a.score);

    // Diversify top 5 - show different engine types for better overview
    const top5: typeof scored = [];
    const seenEngines = new Set<string>();

    // First pass: one issue per engine type (diverse)
    for (const item of scored) {
      if (!seenEngines.has(item.issue.engine)) {
        top5.push(item);
        seenEngines.add(item.issue.engine);
        if (top5.length >= 5) break;
      }
    }

    // Second pass: if we don't have 5 yet, fill with highest scored issues
    if (top5.length < 5) {
      for (const item of scored) {
        if (!top5.includes(item)) {
          top5.push(item);
          if (top5.length >= 5) break;
        }
      }
    }

    top5.forEach(({ issue }, index) => {
      const icon = getSeverityIcon(issue.severity, useEmoji);
      const engineName = getEngineName(issue.engine);
      const location = `${truncateFilePath(issue.filePath)}:${issue.location.line}`;

      const color = issue.severity === 'error' ? red : orange;
      output += `  ${(index + 1)}.  ${icon} ${color(engineName)} ${gray(`(${location})`)}\n`;

      if (issue.message && index < 3) {
        output += `      ${gray(issue.message)}\n`;
      }
    });

    output += '\n';
  } else if (highConfidenceIssues.length === 0) {
    const successIcon = useEmoji ? '✅ ' : '';
    output += green(`${successIcon}No issues found! Your code looks clean.\n`);
    output += '\n';
  }

  // Hints
  if (highConfidenceIssues.length > 0) {
    const hintIcon = useEmoji ? '💡 ' : '';
    output += gray(`${hintIcon}Run with --details to see all issues\n`);

  }

  // Stats
  if (result.startTime && result.endTime) {
    const duration = result.endTime - result.startTime;
    const durationSec = (duration / 1000).toFixed(2);
    const speed = (stats.analyzed / (duration / 1000)).toFixed(0);
    output += '\n';
    output += gray(`Analyzed ${stats.analyzed} files in ${durationSec}s (${speed} files/sec)\n`);
  }

  return output;
}

/**
 * Truncate file path for display
 */
function truncateFilePath(filePath: string, maxLength: number = 50): string {
  if (filePath.length <= maxLength) {
    return filePath;
  }

  // Try to keep filename and immediate parent
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

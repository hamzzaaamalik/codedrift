/**
 * Compact formatter - one line per issue (CI-friendly)
 */

import type { AnalysisResult, CodeDriftConfig } from '../types/index.js';
import chalk from 'chalk';
import { calculateRiskScore } from './types.js';

interface CompactOptions {
  noColor?: boolean;
  ci?: boolean;
}

/**
 * Format analysis result in compact one-line-per-issue format
 * Format: file:line:col - [engine] severity: message
 */
export function formatCompact(
  result: AnalysisResult,
  _config: CodeDriftConfig,
  options: CompactOptions = {}
): string {
  const { issues } = result;
  const { noColor = false, ci = false } = options;

  // Disable colors in CI or if requested
  const useColors = !noColor && !ci;

  const red = useColors ? chalk.red : (s: string) => s;
  const yellow = useColors ? chalk.yellow : (s: string) => s;
  const cyan = useColors ? chalk.cyan : (s: string) => s;
  const gray = useColors ? chalk.gray : (s: string) => s;

  if (issues.length === 0) {
    return '';
  }

  // Sort by risk score
  const sorted = [...issues].map(issue => ({
    issue,
    score: calculateRiskScore(issue),
  })).sort((a, b) => b.score - a.score);

  let output = '';

  sorted.forEach(({ issue }) => {
    const location = `${issue.filePath}:${issue.location.line}:${issue.location.column}`;
    const engine = `[${issue.engine}]`;
    const severity = issue.severity === 'error' ? 'error' : 'warning';

    // Color the severity
    const coloredSeverity = issue.severity === 'error' ? red(severity) : yellow(severity);

    // Build compact line
    const parts = [
      cyan(location),
      gray(engine),
      coloredSeverity + ':',
      issue.message,
    ];

    output += parts.join(' ') + '\n';
  });

  return output;
}

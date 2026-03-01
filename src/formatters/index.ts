/**
 * Formatter orchestrator - coordinates all output formats
 */

import type { AnalysisResult, CodeDriftConfig } from '../types/index.js';
import { formatJSON } from '../core/formatter.js';
import { formatSummary } from './summary.js';
import { formatDetailed } from './detailed.js';
import { formatCompact } from './compact.js';
import { formatGrouped } from './grouped.js';
import { formatSARIF } from './sarif.js';
import type { FormatType, GroupByType } from './types.js';

export interface FormatterOptions {
  /** Format type */
  format?: FormatType;
  /** Group by criteria (for summary/detailed modes) */
  groupBy?: GroupByType;
  /** Show only critical/high issues */
  quiet?: boolean;
  /** Disable colors */
  noColor?: boolean;
  /** CI mode detection */
  ci?: boolean;
  /** Verbose mode (alias for detailed) */
  verbose?: boolean;
  /** Details mode */
  details?: boolean;
}

/**
 * Main formatter entry point
 */
export function formatOutput(
  result: AnalysisResult,
  config: CodeDriftConfig,
  options: FormatterOptions = {}
): string {
  // Detect CI environment
  const ci = options.ci ?? (process.env.CI === 'true' || !process.stdout.isTTY);
  const noColor = options.noColor ?? ci;

  // Determine format
  let format = options.format || 'summary';
  if (options.verbose || options.details) {
    format = 'detailed';
  }

  // Filter by quiet mode (only critical/high)
  let filteredResult = result;
  if (options.quiet) {
    const quietIssues = result.issues.filter(i =>
      i.severity === 'error' ||
      (i.severity === 'warning' && (i.confidence || 'high') === 'high')
    );
    filteredResult = { ...result, issues: quietIssues };
  }

  // Format based on type
  const formatterOpts = { noColor, ci };

  switch (format) {
    case 'summary':
      if (options.groupBy) {
        return formatGrouped(filteredResult, config, {
          ...formatterOpts,
          groupBy: options.groupBy,
        });
      }
      return formatSummary(filteredResult, config, formatterOpts);

    case 'detailed':
      if (options.groupBy) {
        return formatGrouped(filteredResult, config, {
          ...formatterOpts,
          groupBy: options.groupBy,
        });
      }
      return formatDetailed(filteredResult, config, formatterOpts);

    case 'compact':
      return formatCompact(filteredResult, config, formatterOpts);

    case 'json':
      return formatJSON(filteredResult, config);

    case 'sarif':
      return formatSARIF(filteredResult, config);

    default:
      return formatSummary(filteredResult, config, formatterOpts);
  }
}

// Re-export types
export type { FormatType, GroupByType } from './types.js';
export { formatSummary } from './summary.js';
export { formatDetailed } from './detailed.js';
export { formatCompact } from './compact.js';
export { formatGrouped } from './grouped.js';
export { formatSARIF } from './sarif.js';

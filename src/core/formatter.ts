/**
 * Output formatters for different report formats
 */

import type { AnalysisResult, Issue, JSONReport, CodeDriftConfig } from '../types/index.js';
import chalk from 'chalk';

interface FormatterOptions {
  showRiskScores?: boolean;
  deduplicate?: boolean;
}

export function formatTerminal(result: AnalysisResult, _config: CodeDriftConfig, options?: FormatterOptions): string {
  const showRiskScores = options?.showRiskScores || false;
  const { issues, stats } = result;

  const criticalIssues = issues.filter(i => i.severity === 'error');
  const warnings = issues.filter(i => i.severity === 'warning');

  // Group by confidence
  const highConfidence = issues.filter(i => (i.confidence || 'high') === 'high');
  const mediumConfidence = issues.filter(i => (i.confidence || 'high') === 'medium');
  const lowConfidence = issues.filter(i => (i.confidence || 'high') === 'low');

  let output = '\n' + chalk.bold.cyan('═'.repeat(60)) + '\n';
  output += chalk.bold('  CodeDrift Analysis Complete\n');
  output += chalk.bold.cyan('═'.repeat(60)) + '\n';

  // Group issues by engine
  const issuesByEngine = groupIssuesByEngine(issues);

  // Summary section
  output += '\n' + chalk.bold('📊 Summary\n');
  output += chalk.gray('─'.repeat(60)) + '\n';

  if (issues.length === 0) {
    output += '\n' + chalk.green.bold('  ✓ No issues found! Your code looks clean.\n');
  } else {
    // Show confidence breakdown
    output += '\n' + chalk.bold('  Confidence Levels:\n');
    if (highConfidence.length > 0) {
      output += `  ${chalk.green('●')} High: ${chalk.bold(highConfidence.length.toString())} issue${highConfidence.length > 1 ? 's' : ''}\n`;
    }
    if (mediumConfidence.length > 0) {
      output += `  ${chalk.yellow('●')} Medium: ${chalk.bold(mediumConfidence.length.toString())} issue${mediumConfidence.length > 1 ? 's' : ''}\n`;
    }
    if (lowConfidence.length > 0) {
      output += `  ${chalk.gray('●')} Low: ${chalk.bold(lowConfidence.length.toString())} issue${lowConfidence.length > 1 ? 's' : ''}\n`;
    }
    output += '\n';
    // Show grouped summary
    const sortedEngines = Object.entries(issuesByEngine)
      .sort((a, b) => {
        // Sort by: critical count desc, then total count desc
        const aCritical = a[1].filter(i => i.severity === 'error').length;
        const bCritical = b[1].filter(i => i.severity === 'error').length;
        if (aCritical !== bCritical) return bCritical - aCritical;
        return b[1].length - a[1].length;
      });

    for (const [engine, engineIssues] of sortedEngines) {
      const engineCritical = engineIssues.filter(i => i.severity === 'error').length;
      const engineWarnings = engineIssues.filter(i => i.severity === 'warning').length;
      const filePaths = new Set<string>();
      for (const issue of engineIssues) {
        filePaths.add(issue.filePath);
      }
      const fileCount = filePaths.size;

      const icon = engineCritical > 0 ? '🔴' : '⚠️ ';
      const severityText = engineCritical > 0
        ? chalk.red(`${engineCritical} critical`)
        : chalk.yellow(`${engineWarnings} warnings`);

      output += `\n  ${icon} ${chalk.bold(getRuleName(engine))}: ${severityText}`;
      output += chalk.gray(` across ${fileCount} file${fileCount > 1 ? 's' : ''}`);
    }
  }

  // Critical issues - show top 10 most dangerous
  if (criticalIssues.length > 0) {
    output += '\n\n' + chalk.red.bold(`🚨 CRITICAL Issues (${criticalIssues.length}) - Must Fix\n`);
    output += chalk.gray('─'.repeat(60)) + '\n';

    // Prioritize: IDOR, input validation, secrets, then others
    const prioritized = prioritizeIssues(criticalIssues);
    const toShow = prioritized.slice(0, 10);

    toShow.forEach((issue, index) => {
      output += '\n' + formatIssueSummary(issue, index + 1, showRiskScores);
    });

    if (criticalIssues.length > 10) {
      const remaining = criticalIssues.length - 10;
      output += '\n' + chalk.gray(`  ... and ${remaining} more critical issue${remaining > 1 ? 's' : ''}\n`);
      output += chalk.gray(`  Run with --format json to see all issues\n`);
    }
  }

  // Warnings - show summary only
  if (warnings.length > 0) {
    output += '\n\n' + chalk.yellow.bold(`⚠️  Warnings (${warnings.length})\n`);
    output += chalk.gray('─'.repeat(60)) + '\n';

    const warningsByEngine = groupIssuesByEngine(warnings);
    for (const [engine, engineIssues] of Object.entries(warningsByEngine)) {
      const filePaths = new Set<string>();
      for (const issue of engineIssues) {
        filePaths.add(issue.filePath);
      }
      const fileCount = filePaths.size;
      output += `\n  • ${chalk.bold(getRuleName(engine))}: ${engineIssues.length} finding${engineIssues.length > 1 ? 's' : ''} in ${fileCount} file${fileCount > 1 ? 's' : ''}`;
    }

    output += '\n\n' + chalk.gray(`  Run with --format json to see all warnings\n`);
  }

  // Stats section
  output += '\n\n' + chalk.bold('📈 Stats\n');
  output += chalk.gray('─'.repeat(60)) + '\n';
  output += `  Files analyzed: ${chalk.cyan(stats.analyzed.toString())} / ${stats.total}\n`;

  if (result.startTime && result.endTime) {
    const duration = result.endTime - result.startTime;
    const speed = (stats.analyzed / (duration / 1000)).toFixed(0);
    output += `  Duration: ${chalk.cyan(duration + 'ms')} (${speed} files/sec)\n`;
  }

  // Final verdict
  output += '\n' + chalk.bold.cyan('═'.repeat(60)) + '\n';
  if (criticalIssues.length > 0) {
    output += chalk.red.bold('❌ Fix critical issues before deploying to production\n');
  } else if (warnings.length > 0) {
    output += chalk.yellow.bold('⚠️  Consider fixing warnings to improve code quality\n');
  } else {
    output += chalk.green.bold('✅ All checks passed!\n');
  }
  output += chalk.bold.cyan('═'.repeat(60)) + '\n';

  return output;
}

/**
 * Group issues by detection engine
 */
function groupIssuesByEngine(issues: Issue[]): Record<string, Issue[]> {
  const grouped: Record<string, Issue[]> = {};
  for (const issue of issues) {
    if (!grouped[issue.engine]) {
      grouped[issue.engine] = [];
    }
    grouped[issue.engine].push(issue);
  }
  return grouped;
}

/**
 * Prioritize issues by danger level
 */
function prioritizeIssues(issues: Issue[]): Issue[] {
  const priority = {
    'idor': 1,                          // Data breach risk
    'missing-input-validation': 2,      // Injection risk
    'hardcoded-secret': 3,              // Credential exposure
    'stack-trace-exposure': 4,          // Information disclosure
    'missing-await': 5,                 // Data corruption
    'async-foreach': 6,                 // Race conditions
    'hallucinated-deps': 7,             // Runtime crash
    'unsafe-regex': 8,                  // DoS risk
    'console-in-production': 9,         // Data leakage
    'empty-catch': 10,                  // Silent failures
  };

  return [...issues].sort((a, b) => {
    const aPriority = priority[a.engine as keyof typeof priority] || 99;
    const bPriority = priority[b.engine as keyof typeof priority] || 99;
    return aPriority - bPriority;
  });
}

/**
 * Get human-readable rule name
 */
function getRuleName(engine: string): string {
  const names: Record<string, string> = {
    'idor': 'Insecure Direct Object Reference',
    'missing-input-validation': 'Missing Input Validation',
    'hardcoded-secret': 'Hardcoded Secrets',
    'stack-trace-exposure': 'Stack Trace Exposure',
    'missing-await': 'Missing Await',
    'async-foreach': 'Async forEach/map',
    'hallucinated-deps': 'Hallucinated Dependencies',
    'unsafe-regex': 'Unsafe Regex (ReDoS)',
    'console-in-production': 'Console in Production',
    'empty-catch': 'Empty Catch Blocks',
  };
  return names[engine] || engine;
}

/**
 * Format a single issue in condensed format
 */
function formatIssueSummary(issue: Issue, index: number, showRiskScores = false): string {
  let output = '';

  const confidence = issue.confidence || 'high';
  const confidenceBadge = getConfidenceBadge(confidence);

  const fileLocation = `${issue.filePath}:${issue.location.line}`;

  let badges = confidenceBadge;
  if (showRiskScores && issue.riskScore !== undefined) {
    const riskBadge = getRiskBadge(issue.riskScore, issue.priority);
    badges += ' ' + riskBadge;
  }

  output += `  ${chalk.bold(index + '.')} ${chalk.cyan(fileLocation)} ${badges}\n`;
  output += `     ${issue.message}\n`;

  if (issue.suggestion) {
    output += `     ${chalk.gray('→ ' + issue.suggestion)}\n`;
  }

  return output;
}

/**
 * Get colored risk score badge
 */
function getRiskBadge(riskScore: number, priority?: string): string {
  const priorityColors = {
    'critical': chalk.red.bold,
    'high': chalk.yellow.bold,
    'medium': chalk.blue.bold,
    'low': chalk.gray.bold,
  };

  const colorFn = priorityColors[priority as keyof typeof priorityColors] || chalk.gray.bold;
  return colorFn(`[RISK: ${riskScore}]`);
}

/**
 * Get colored confidence badge
 */
function getConfidenceBadge(confidence: string): string {
  switch (confidence) {
    case 'high':
      return chalk.green.bold('[HIGH]');
    case 'medium':
      return chalk.yellow.bold('[MED]');
    case 'low':
      return chalk.gray.bold('[LOW]');
    default:
      return '';
  }
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

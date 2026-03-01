/**
 * HTML report generator - Professional corporate design
 * Creates self-contained HTML report with inline CSS
 */

import type { AnalysisResult, Issue, CodeDriftConfig } from '../types/index.js';

interface HTMLReportOptions {
  showRiskScores?: boolean;
  deduplicate?: boolean;
}

export function generateHTMLReport(result: AnalysisResult, config: CodeDriftConfig, _options?: HTMLReportOptions): string {
  const { issues, stats, startTime, endTime } = result;

  // Debug: Log issue count before HTML generation (only in debug mode)
  if (process.env.CODEDRIFT_DEBUG) {
    console.log(`[HTML Report] Generating report with ${issues.length} issues`);
  }

  // Detect project root from issues (find common path prefix)
  const projectRoot = detectProjectRoot(issues);

  // Make all file paths relative
  const relativeIssues = issues.map(issue => ({
    ...issue,
    filePath: makeRelativePath(issue.filePath, projectRoot)
  }));

  const criticalIssues = relativeIssues.filter(i => i.severity === 'error');
  const warnings = relativeIssues.filter(i => i.severity === 'warning');
  const duration = startTime && endTime ? endTime - startTime : 0;

  const highConfidence = relativeIssues.filter(i => (i.confidence || 'high') === 'high');
  const mediumConfidence = relativeIssues.filter(i => (i.confidence || 'high') === 'medium');
  const lowConfidence = relativeIssues.filter(i => (i.confidence || 'high') === 'low');

  // Group issues for top lists
  const issuesByFile = new Map<string, Issue[]>();
  const issuesByEngine = new Map<string, Issue[]>();

  for (const issue of relativeIssues) {
    // Group by file
    const fileIssues = issuesByFile.get(issue.filePath) || [];
    fileIssues.push(issue);
    issuesByFile.set(issue.filePath, fileIssues);

    // Group by engine
    const engineIssues = issuesByEngine.get(issue.engine) || [];
    engineIssues.push(issue);
    issuesByEngine.set(issue.engine, engineIssues);
  }

  // Calculate top problematic files
  const topFiles = Array.from(issuesByFile.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 5);

  // Calculate top issue types
  const topEngines = Array.from(issuesByEngine.entries())
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 5);

  // Get all unique engines for filter dropdown
  const allEngines = Array.from(issuesByEngine.keys()).sort();

  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeDrift Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.5;
            color: #1f2937;
            background: #f9fafb;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            background: #ffffff;
            border-bottom: 1px solid #e5e7eb;
            padding: 24px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-left h1 {
            font-size: 20px;
            font-weight: 600;
            color: #111827;
            margin-bottom: 4px;
        }

        .header-left .subtitle {
            font-size: 13px;
            color: #6b7280;
        }

        .header-right {
            text-align: right;
        }

        .timestamp {
            color: #9ca3af;
            font-size: 12px;
        }

        .main-content {
            padding: 32px 40px;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }

        .metric-card {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
        }

        .metric-card .label {
            font-size: 12px;
            font-weight: 500;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }

        .metric-card .value {
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }

        .value.critical { color: #dc2626; }
        .value.warning { color: #f59e0b; }
        .value.success { color: #10b981; }
        .value.neutral { color: #6b7280; }

        .section {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }

        .section-header {
            padding: 16px 24px;
            border-bottom: 1px solid #e5e7eb;
            background: #f9fafb;
        }

        .section-header h2 {
            font-size: 16px;
            font-weight: 600;
            color: #111827;
        }

        .section-body {
            padding: 24px;
        }

        .issue {
            border-left: 3px solid #dc2626;
            padding: 16px;
            margin-bottom: 12px;
            background: #fef2f2;
            border-radius: 4px;
        }

        .issue.warning {
            border-left-color: #f59e0b;
            background: #fffbeb;
        }

        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 8px;
        }

        .issue-location {
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', 'Consolas', monospace;
            font-size: 13px;
            color: #3b82f6;
            font-weight: 500;
        }

        .issue-badge {
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }

        .badge-error {
            background: #dc2626;
            color: white;
        }

        .badge-warning {
            background: #f59e0b;
            color: white;
        }

        .badge-confidence {
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            margin-left: 8px;
        }

        .badge-high {
            background: #10b981;
            color: white;
        }

        .badge-medium {
            background: #f59e0b;
            color: white;
        }

        .badge-low {
            background: #6b7280;
            color: white;
        }

        .risk-badge {
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            margin-left: 8px;
        }

        .risk-critical {
            background: #dc2626;
            color: white;
        }

        .risk-high {
            background: #fb8500;
            color: white;
        }

        .risk-medium {
            background: #ffc107;
            color: black;
        }

        .risk-low {
            background: #0366d6;
            color: white;
        }

        .issue-message {
            font-size: 14px;
            font-weight: 500;
            margin-bottom: 8px;
            color: #111827;
        }

        .issue-suggestion {
            color: #6b7280;
            font-size: 13px;
            padding: 12px;
            background: rgba(255,255,255,0.5);
            border-radius: 4px;
            margin-top: 8px;
            border-left: 2px solid #d1d5db;
        }

        .no-issues {
            text-align: center;
            padding: 64px 24px;
        }

        .no-issues h3 {
            font-size: 18px;
            font-weight: 600;
            color: #111827;
            margin-bottom: 8px;
        }

        .no-issues p {
            color: #6b7280;
            font-size: 14px;
        }

        .file-group {
            margin-bottom: 24px;
        }

        .file-group-header {
            font-size: 14px;
            font-weight: 600;
            color: #111827;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .file-count {
            font-size: 12px;
            font-weight: 500;
            color: #6b7280;
            background: #f3f4f6;
            padding: 4px 10px;
            border-radius: 12px;
        }

        footer {
            text-align: center;
            padding: 32px 40px;
            color: #9ca3af;
            font-size: 13px;
            border-top: 1px solid #e5e7eb;
            background: white;
        }

        footer a {
            color: #3b82f6;
            text-decoration: none;
            font-weight: 500;
        }

        footer a:hover {
            text-decoration: underline;
        }

        pre {
            background: #f9fafb;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
            border: 1px solid #e5e7eb;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', 'Consolas', monospace;
        }

        @media (max-width: 1024px) {
            .summary-grid {
                grid-template-columns: repeat(3, 1fr);
            }
        }

        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            header {
                flex-direction: column;
                align-items: start;
                gap: 12px;
            }

            .main-content {
                padding: 24px 20px;
            }
        }

        /* Executive Summary Dashboard Styles */
        .executive-summary {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            color: #1f2937;
            padding: 32px;
            border-radius: 12px;
            margin-bottom: 32px;
        }

        .executive-summary h2 {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .summary-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        .summary-stat-card {
            background: #ffffff;
            border-radius: 8px;
            padding: 16px;
            border: 1px solid #e5e7eb;
        }

        .summary-stat-card .stat-label {
            font-size: 12px;
            color: #6b7280;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .summary-stat-card .stat-value {
            font-size: 28px;
            font-weight: 700;
            color: #1f2937;
        }

        .top-issues-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .top-list {
            background: #ffffff;
            border-radius: 8px;
            padding: 20px;
            border: 1px solid #e5e7eb;
        }

        .top-list h3 {
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 16px;
            color: #111827;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .top-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #e5e7eb;
        }

        .top-item:last-child {
            border-bottom: none;
        }

        .top-item-name {
            font-size: 13px;
            color: #1f2937;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            margin-right: 12px;
        }

        .top-item-count {
            font-weight: 700;
            font-size: 16px;
            background: #f3f4f6;
            color: #1f2937;
            padding: 4px 12px;
            border-radius: 12px;
        }

        /* Progress Bar Styles */
        .progress-bar {
            background: #e5e7eb;
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }

        .progress-fill {
            height: 100%;
            background: #3b82f6;
            transition: width 0.3s ease;
        }

        /* Filter Controls */
        .filter-controls {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }

        .filter-controls h3 {
            font-size: 14px;
            font-weight: 600;
            color: #111827;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .filter-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            margin-bottom: 12px;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .filter-group label {
            font-size: 12px;
            font-weight: 500;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .filter-group select,
        .filter-group input {
            padding: 8px 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
            background: white;
            color: #1f2937;
            transition: border-color 0.15s;
        }

        .filter-group select:focus,
        .filter-group input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        .smart-filters {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 12px;
        }

        .smart-filter-btn {
            padding: 6px 12px;
            background: #f3f4f6;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 500;
            color: #6b7280;
            cursor: pointer;
            transition: all 0.15s;
        }

        .smart-filter-btn:hover {
            background: #e5e7eb;
            color: #1f2937;
        }

        .smart-filter-btn.active {
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
        }

        .filter-status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid #e5e7eb;
            font-size: 13px;
            color: #6b7280;
        }

        .clear-filters-btn {
            padding: 6px 14px;
            background: #dc2626;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.15s;
        }

        .clear-filters-btn:hover {
            background: #b91c1c;
        }

        /* Search Box */
        .search-box {
            position: relative;
            margin-bottom: 16px;
        }

        .search-box input {
            width: 100%;
            padding: 10px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.15s;
        }

        .search-box input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        /* Enhanced Issue Cards */
        .issue-group {
            border: 2px solid #3b82f6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            background: white;
        }

        .issue-group-header {
            padding: 16px 20px;
            background: #eff6ff;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }

        .issue-group-header:hover {
            background: #dbeafe;
        }

        .issue-group-info {
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .issue-group-count {
            font-size: 13px;
            color: #6b7280;
        }

        .issue-group-expand {
            color: #3b82f6;
            font-size: 20px;
            transition: transform 0.2s;
        }

        .issue-group.expanded .issue-group-expand {
            transform: rotate(180deg);
        }

        .issue-group-body {
            padding: 16px;
            border-top: 1px solid #e5e7eb;
        }

        .issue-card {
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
            background: white;
            transition: box-shadow 0.2s;
        }

        .issue-card:hover {
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        .issue-card-header {
            padding: 14px 16px;
            background: #f9fafb;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: start;
            gap: 12px;
            user-select: none;
        }

        .issue-card-header:hover {
            background: #f3f4f6;
        }

        .issue-card-left {
            flex: 1;
            min-width: 0;
        }

        .issue-card-title {
            font-size: 14px;
            font-weight: 600;
            color: #111827;
            margin-bottom: 6px;
        }

        .issue-card-meta {
            font-size: 12px;
            color: #6b7280;
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .issue-card-expand {
            color: #9ca3af;
            font-size: 20px;
            transition: transform 0.2s;
        }

        .issue-card.expanded .issue-card-expand {
            transform: rotate(180deg);
        }

        .issue-card-body {
            display: none;
            padding: 16px;
            border-top: 1px solid #e5e7eb;
        }

        .issue-card.expanded .issue-card-body {
            display: block;
        }

        .code-snippet {
            background: #1f2937;
            color: #e5e7eb;
            padding: 16px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', 'Consolas', monospace;
            font-size: 13px;
            line-height: 1.6;
            margin-top: 12px;
        }

        .code-line-number {
            color: #6b7280;
            margin-right: 16px;
            user-select: none;
        }

        .suggestion-box {
            background: #ecfdf5;
            border-left: 3px solid #10b981;
            padding: 12px 16px;
            border-radius: 4px;
            margin-top: 12px;
        }

        .suggestion-box-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }

        .suggestion-label {
            font-size: 12px;
            font-weight: 600;
            color: #059669;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .copy-btn {
            padding: 4px 10px;
            background: #10b981;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.15s;
        }

        .copy-btn:hover {
            background: #059669;
        }

        .suggestion-text {
            font-size: 13px;
            color: #047857;
        }

        /* Collapsible Sections */
        .collapsible-section {
            margin-bottom: 16px;
        }

        .collapsible-header {
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 14px 18px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            transition: background 0.15s;
        }

        .collapsible-header:hover {
            background: #f3f4f6;
        }

        .collapsible-header h3 {
            font-size: 15px;
            font-weight: 600;
            color: #111827;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .collapsible-count {
            background: #e5e7eb;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 13px;
            font-weight: 600;
            color: #1f2937;
        }

        .collapsible-body {
            margin-top: 12px;
            display: none;
        }

        .collapsible-section.expanded .collapsible-body {
            display: block;
        }

        .collapsible-section.expanded .collapsible-header {
            border-bottom-left-radius: 0;
            border-bottom-right-radius: 0;
            border-bottom: none;
        }

        /* Action Buttons */
        .action-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }

        .action-btn {
            padding: 10px 18px;
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 500;
            color: #1f2937;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.15s;
        }

        .action-btn:hover {
            background: #f9fafb;
            border-color: #d1d5db;
        }

        .action-btn.primary {
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
        }

        .action-btn.primary:hover {
            background: #2563eb;
        }

        /* Back to Top Button */
        .back-to-top {
            position: fixed;
            bottom: 30px;
            right: 30px;
            width: 50px;
            height: 50px;
            background: #3b82f6;
            color: white;
            border: none;
            border-radius: 50%;
            font-size: 24px;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .back-to-top.visible {
            opacity: 1;
            visibility: visible;
        }

        .back-to-top:hover {
            background: #2563eb;
            transform: translateY(-3px);
            box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4);
        }

        /* Enhanced Footer */
        .enhanced-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .footer-version {
            font-size: 12px;
            color: #6b7280;
        }

        @media (max-width: 1024px) {
            .summary-grid {
                grid-template-columns: repeat(3, 1fr);
            }
            .summary-stats {
                grid-template-columns: repeat(2, 1fr);
            }
            .top-issues-grid {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            header {
                flex-direction: column;
                align-items: start;
                gap: 12px;
            }

            .main-content {
                padding: 24px 20px;
            }

            .summary-stats {
                grid-template-columns: 1fr;
            }

            .filter-row {
                grid-template-columns: 1fr;
            }

            .executive-summary {
                padding: 24px;
            }
        }

        @media print {
            body {
                background: white;
            }
            .filter-tabs,
            .filter-controls,
            .action-buttons,
            .back-to-top,
            .search-box {
                display: none !important;
            }
            .issue-card-body {
                display: block !important;
            }
            .collapsible-body {
                display: block !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-left">
                <h1>CodeDrift Security Report</h1>
                <p class="subtitle">AI Code Safety Analysis</p>
            </div>
            <div class="header-right">
                <p class="timestamp">Generated: ${new Date().toLocaleString()}</p>
                ${criticalIssues.length > 0
                    ? '<p style="color: #dc2626; font-weight: 600; font-size: 14px; margin-top: 4px;">Critical Issues Found</p>'
                    : '<p style="color: #10b981; font-weight: 600; font-size: 14px; margin-top: 4px;">All Clear</p>'
                }
            </div>
        </header>

        <div class="main-content">
            ${issues.length > 0 ? `
            <!-- Executive Summary Dashboard -->
            <div class="executive-summary">
                <h2>Executive Summary</h2>
                <div class="summary-stats">
                    <div class="summary-stat-card">
                        <div class="stat-label">Total Issues</div>
                        <div class="stat-value">${issues.length}</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: 100%"></div>
                        </div>
                    </div>
                    <div class="summary-stat-card">
                        <div class="stat-label">Files Scanned</div>
                        <div class="stat-value">${stats.analyzed}</div>
                    </div>
                    <div class="summary-stat-card">
                        <div class="stat-label">Scan Duration</div>
                        <div class="stat-value">${(duration / 1000).toFixed(2)}s</div>
                    </div>
                </div>

                <div class="summary-stats">
                    <div class="summary-stat-card">
                        <div class="stat-label">Critical</div>
                        <div class="stat-value">${criticalIssues.length}</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${issues.length ? (criticalIssues.length / issues.length * 100) : 0}%"></div>
                        </div>
                    </div>
                    <div class="summary-stat-card">
                        <div class="stat-label">Warnings</div>
                        <div class="stat-value">${warnings.length}</div>
                        <div class="progress-bar">
                            <div class="progress-fill" style="width: ${issues.length ? (warnings.length / issues.length * 100) : 0}%"></div>
                        </div>
                    </div>
                    <div class="summary-stat-card">
                        <div class="stat-label">Files Affected</div>
                        <div class="stat-value">${issuesByFile.size}</div>
                    </div>
                </div>

                <div class="top-issues-grid">
                    <div class="top-list">
                        <h3>Top 5 Most Problematic Files</h3>
                        ${topFiles.length > 0 ? topFiles.map(([file, fileIssues]) => `
                        <div class="top-item">
                            <div class="top-item-name" title="${escapeHtml(file)}">${escapeHtml(file.split('/').pop() || file)}</div>
                            <div class="top-item-count">${fileIssues.length}</div>
                        </div>
                        `).join('') : '<div style="opacity: 0.7; font-size: 13px;">No issues found</div>'}
                    </div>
                    <div class="top-list">
                        <h3>Top 5 Issue Types</h3>
                        ${topEngines.length > 0 ? topEngines.map(([engine, engineIssues]) => {
                            const engineNames: Record<string, string> = {
                                'idor': 'IDOR',
                                'missing-input-validation': 'Input Validation',
                                'hardcoded-secret': 'Hardcoded Secrets',
                                'stack-trace-exposure': 'Stack Trace',
                                'missing-await': 'Missing Await',
                                'async-foreach': 'Async Loops',
                                'hallucinated-deps': 'Hallucinated Deps',
                                'unsafe-regex': 'Unsafe Regex',
                                'console-in-production': 'Console Logs',
                                'empty-catch': 'Empty Catch',
                            };
                            return `
                        <div class="top-item">
                            <div class="top-item-name">${engineNames[engine] || engine}</div>
                            <div class="top-item-count">${engineIssues.length}</div>
                        </div>
                        `;
                        }).join('') : '<div style="opacity: 0.7; font-size: 13px;">No issues found</div>'}
                    </div>
                </div>
            </div>
            ` : ''}
            <div class="summary-grid">
                <div class="metric-card">
                    <div class="label">Total Issues</div>
                    <div class="value ${issues.length === 0 ? 'success' : 'neutral'}">${issues.length}</div>
                </div>
                <div class="metric-card">
                    <div class="label">Critical</div>
                    <div class="value critical">${criticalIssues.length}</div>
                </div>
                <div class="metric-card">
                    <div class="label">Warnings</div>
                    <div class="value warning">${warnings.length}</div>
                </div>
                <div class="metric-card">
                    <div class="label">High Confidence</div>
                    <div class="value ${highConfidence.length > 0 ? 'critical' : 'success'}">${highConfidence.length}</div>
                </div>
                <div class="metric-card">
                    <div class="label">Medium Confidence</div>
                    <div class="value ${mediumConfidence.length > 0 ? 'warning' : 'neutral'}">${mediumConfidence.length}</div>
                </div>
                <div class="metric-card">
                    <div class="label">Low Confidence</div>
                    <div class="value neutral">${lowConfidence.length}</div>
                </div>
                <div class="metric-card">
                    <div class="label">Files Scanned</div>
                    <div class="value neutral">${stats.analyzed}</div>
                </div>
                <div class="metric-card">
                    <div class="label">Duration</div>
                    <div class="value neutral">${(duration / 1000).toFixed(1)}s</div>
                </div>
            </div>

            ${issues.length === 0 ? `
            <div class="section">
                <div class="section-body">
                    <div class="no-issues">
                        <h3>No Issues Found</h3>
                        <p>Your code passed all security and quality checks.</p>
                    </div>
                </div>
            </div>
            ` : `
            <!-- Filter Controls -->
            <div class="filter-controls">
                <h3>Filter & Search</h3>

                <div class="search-box">
                    <input type="text" id="issue-search" placeholder="Search issues by message, file, or engine...">
                </div>

                <div class="filter-row">
                    <div class="filter-group">
                        <label>Severity</label>
                        <select id="filter-severity">
                            <option value="all">All</option>
                            <option value="error">Critical</option>
                            <option value="warning">Warning</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Confidence</label>
                        <select id="filter-confidence">
                            <option value="all">All</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>Engine</label>
                        <select id="filter-engine">
                            <option value="all">All Engines</option>
                            ${allEngines.map(engine => {
                                const engineNames: Record<string, string> = {
                                    'idor': 'IDOR',
                                    'missing-input-validation': 'Input Validation',
                                    'hardcoded-secret': 'Hardcoded Secrets',
                                    'stack-trace-exposure': 'Stack Trace Exposure',
                                    'missing-await': 'Missing Await',
                                    'async-foreach': 'Async forEach/map',
                                    'hallucinated-deps': 'Hallucinated Dependencies',
                                    'unsafe-regex': 'Unsafe Regex (ReDoS)',
                                    'console-in-production': 'Console in Production',
                                    'empty-catch': 'Empty Catch Blocks',
                                };
                                return `<option value="${engine}">${engineNames[engine] || engine}</option>`;
                            }).join('')}
                        </select>
                    </div>
                    <div class="filter-group">
                        <label>File Pattern</label>
                        <input type="text" id="filter-file" placeholder="e.g., *.ts, src/**">
                    </div>
                </div>

                <div class="smart-filters">
                    <button class="smart-filter-btn" data-filter="high-confidence">High Confidence Only</button>
                    <button class="smart-filter-btn" data-filter="critical-only">Critical Only</button>
                    <button class="smart-filter-btn" data-filter="security-only">Security Issues</button>
                </div>

                <div class="filter-status">
                    <span id="filter-status-text">Showing ${issues.length} of ${issues.length} issues</span>
                    <button class="clear-filters-btn" onclick="clearAllFilters()">Clear All Filters</button>
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="action-buttons">
                <button class="action-btn primary" onclick="window.print()">Export to PDF</button>
                <button class="action-btn" onclick="exportToCSV()">Export to CSV</button>
                <button class="action-btn" onclick="expandAll()">Expand All</button>
                <button class="action-btn" onclick="collapseAll()">Collapse All</button>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>Issues</h2>
                </div>
                <div class="section-body">
                    <!-- All Issues (Filtered by JavaScript) -->
                    <div id="issues-list">
                        ${renderIssuesWithGrouping(relativeIssues)}
                    </div>
                </div>
            </div>
            `}

            <div class="section">
                <div class="section-header">
                    <h2>Configuration</h2>
                </div>
                <div class="section-body">
                    <pre>${JSON.stringify({
                        failOn: config.failOn || 'error',
                        rulesEnabled: Object.entries(config.rules || {})
                            .filter(([_, level]) => level !== 'off')
                            .map(([rule]) => rule)
                    }, null, 2)}</pre>
                </div>
            </div>
        </div>

        <footer>
            <div class="enhanced-footer">
                <div>
                    <p><strong>CodeDrift v1.2.3</strong> - AI Code Safety Guardian</p>
                    <p style="margin-top: 4px;">
                        <a href="https://github.com/hamzzaaamalik/codedrift" target="_blank">github.com/hamzzaaamalik/codedrift</a>
                    </p>
                </div>
                <div class="footer-version">
                    <div>Report generated: ${new Date().toLocaleString()}</div>
                    <div>Total scan time: ${(duration / 1000).toFixed(2)}s</div>
                </div>
            </div>
        </footer>

        <!-- Back to Top Button -->
        <button class="back-to-top" onclick="scrollToTop()" id="backToTopBtn">↑</button>
    </div>

    <script>
        const filterState = {
            severity: 'all',
            confidence: 'all',
            engine: 'all',
            filePattern: '',
            searchQuery: '',
            smartFilters: new Set()
        };
        const totalIssues = ${issues.length};

        function toggleIssueGroup(header) {
            const group = header.closest('.issue-group');
            group.classList.toggle('expanded');
            const body = group.querySelector('.issue-group-body');
            body.style.display = body.style.display === 'none' ? 'block' : 'none';
        }

        function toggleIssueCard(header) {
            header.closest('.issue-card').classList.toggle('expanded');
        }

        function expandAll() {
            document.querySelectorAll('.issue-card').forEach(card => card.classList.add('expanded'));
            document.querySelectorAll('.issue-group').forEach(group => {
                group.classList.add('expanded');
                group.querySelector('.issue-group-body').style.display = 'block';
            });
        }

        function collapseAll() {
            document.querySelectorAll('.issue-card').forEach(card => card.classList.remove('expanded'));
            document.querySelectorAll('.issue-group').forEach(group => {
                group.classList.remove('expanded');
                group.querySelector('.issue-group-body').style.display = 'none';
            });
        }

        function applyFilters() {
            const cards = document.querySelectorAll('.issue-card');
            let visibleCount = 0;
            cards.forEach(card => {
                let visible = true;
                if (filterState.severity !== 'all' && card.dataset.severity !== filterState.severity) visible = false;
                if (filterState.confidence !== 'all' && card.dataset.confidence !== filterState.confidence) visible = false;
                if (filterState.engine !== 'all' && card.dataset.engine !== filterState.engine) visible = false;
                if (filterState.filePattern) {
                    const pattern = filterState.filePattern.toLowerCase();
                    const filePath = card.dataset.file.toLowerCase();
                    if (pattern.includes('*')) {
                        const regex = new RegExp('^' + pattern.replace(/\\*/g, '.*') + '$');
                        if (!regex.test(filePath)) visible = false;
                    } else if (!filePath.includes(pattern)) visible = false;
                }
                if (filterState.searchQuery && !card.textContent.toLowerCase().includes(filterState.searchQuery.toLowerCase())) visible = false;
                if (filterState.smartFilters.has('high-confidence') && card.dataset.confidence !== 'high') visible = false;
                if (filterState.smartFilters.has('critical-only') && card.dataset.severity !== 'error') visible = false;
                if (filterState.smartFilters.has('security-only')) {
                    const securityEngines = ['idor', 'missing-input-validation', 'hardcoded-secret', 'stack-trace-exposure', 'unsafe-regex'];
                    if (!securityEngines.includes(card.dataset.engine)) visible = false;
                }
                card.style.display = visible ? 'block' : 'none';
                if (visible) visibleCount++;
            });
            updateFilterStatus(visibleCount);
        }

        function updateFilterStatus(visibleCount) {
            const statusText = document.getElementById('filter-status-text');
            if (statusText) {
                const activeFilters = countActiveFilters();
                if (filterState.smartFilters.has('critical-only') && visibleCount < totalIssues) {
                    statusText.textContent = 'Showing ' + visibleCount + ' critical issues — clear filter to see all ' + totalIssues;
                } else {
                    statusText.textContent = 'Showing ' + visibleCount + ' of ' + totalIssues + ' issues' + (activeFilters > 0 ? ' (' + activeFilters + ' filter' + (activeFilters === 1 ? '' : 's') + ' active)' : '');
                }
            }
        }

        function countActiveFilters() {
            let count = 0;
            if (filterState.severity !== 'all') count++;
            if (filterState.confidence !== 'all') count++;
            if (filterState.engine !== 'all') count++;
            if (filterState.filePattern) count++;
            if (filterState.searchQuery) count++;
            count += filterState.smartFilters.size;
            return count;
        }

        function clearAllFilters() {
            filterState.severity = 'all';
            filterState.confidence = 'all';
            filterState.engine = 'all';
            filterState.filePattern = '';
            filterState.searchQuery = '';
            filterState.smartFilters.clear();
            const severityFilter = document.getElementById('filter-severity');
            const confidenceFilter = document.getElementById('filter-confidence');
            const engineFilter = document.getElementById('filter-engine');
            const fileFilter = document.getElementById('filter-file');
            const searchBox = document.getElementById('issue-search');
            if (severityFilter) severityFilter.value = 'all';
            if (confidenceFilter) confidenceFilter.value = 'all';
            if (engineFilter) engineFilter.value = 'all';
            if (fileFilter) fileFilter.value = '';
            if (searchBox) searchBox.value = '';
            document.querySelectorAll('.smart-filter-btn').forEach(btn => btn.classList.remove('active'));
            applyFilters();
        }

        let searchTimeout;
        function debounceSearch(value) {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(function() {
                filterState.searchQuery = value;
                applyFilters();
            }, 300);
        }

        function copyToClipboard(button, index) {
            const suggestionBox = button.closest('.suggestion-box');
            const suggestionText = suggestionBox.querySelector('.suggestion-text');
            const text = suggestionText.dataset.suggestion || suggestionText.textContent;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function() {
                    const originalText = button.textContent;
                    button.textContent = 'Copied!';
                    button.style.background = '#059669';
                    setTimeout(function() {
                        button.textContent = originalText;
                        button.style.background = '#10b981';
                    }, 2000);
                }).catch(function(err) {
                    button.textContent = 'Failed';
                    setTimeout(function() {
                        button.textContent = 'Copy';
                    }, 2000);
                });
            }
        }

        function exportToCSV() {
            const cards = Array.from(document.querySelectorAll('.issue-card')).filter(function(card) {
                return card.style.display !== 'none';
            });
            const headers = ['Severity', 'Confidence', 'File', 'Line', 'Engine', 'Message', 'Suggestion'];
            const rows = cards.map(function(card) {
                const severity = card.dataset.severity;
                const confidence = card.dataset.confidence;
                const file = card.dataset.file;
                const meta = card.querySelector('.issue-card-meta').textContent;
                const lineMatch = meta.match(/:(\d+)/);
                const line = lineMatch ? lineMatch[1] : '';
                const engine = card.dataset.engine;
                const message = card.querySelector('.issue-card-title').textContent.trim().substring(2);
                const suggestionBox = card.querySelector('.suggestion-text');
                const suggestion = suggestionBox ? suggestionBox.textContent : '';
                return [severity, confidence, file, line, engine, message, suggestion].map(function(field) {
                    return '"' + String(field).replace(/"/g, '""') + '"';
                }).join(',');
            });
            const csv = [headers.join(',')].concat(rows).join('\\n');
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'codedrift-report-' + new Date().toISOString().split('T')[0] + '.csv';
            a.click();
            URL.revokeObjectURL(url);
        }

        function scrollToTop() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        window.addEventListener('scroll', function() {
            const btn = document.getElementById('backToTopBtn');
            if (btn) {
                if (window.scrollY > 300) btn.classList.add('visible');
                else btn.classList.remove('visible');
            }
        });

        document.addEventListener('DOMContentLoaded', function() {
            // Auto-enable "Critical Only" filter if there are critical issues
            const criticalCount = document.querySelectorAll('.issue-card[data-severity="error"]').length;
            if (criticalCount > 0) {
                filterState.smartFilters.add('critical-only');
                const criticalBtn = document.querySelector('[data-filter="critical-only"]');
                if (criticalBtn) {
                    criticalBtn.classList.add('active');
                }
                applyFilters();
            }

            const severityFilter = document.getElementById('filter-severity');
            if (severityFilter) {
                severityFilter.addEventListener('change', function(e) {
                    filterState.severity = e.target.value;
                    applyFilters();
                });
            }
            const confidenceFilter = document.getElementById('filter-confidence');
            if (confidenceFilter) {
                confidenceFilter.addEventListener('change', function(e) {
                    filterState.confidence = e.target.value;
                    applyFilters();
                });
            }
            const engineFilter = document.getElementById('filter-engine');
            if (engineFilter) {
                engineFilter.addEventListener('change', function(e) {
                    filterState.engine = e.target.value;
                    applyFilters();
                });
            }
            const fileFilter = document.getElementById('filter-file');
            if (fileFilter) {
                fileFilter.addEventListener('input', function(e) {
                    filterState.filePattern = e.target.value;
                    applyFilters();
                });
            }
            const searchBox = document.getElementById('issue-search');
            if (searchBox) {
                searchBox.addEventListener('input', function(e) {
                    debounceSearch(e.target.value);
                });
            }
            document.querySelectorAll('.smart-filter-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const filter = this.dataset.filter;
                    if (filterState.smartFilters.has(filter)) {
                        filterState.smartFilters.delete(filter);
                        this.classList.remove('active');
                    } else {
                        filterState.smartFilters.add(filter);
                        this.classList.add('active');
                    }
                    applyFilters();
                });
            });
            updateFilterStatus(totalIssues);
        });
    </script>
</body>
</html>`;
}

/**
 * Render issues with intelligent grouping for high-volume issue types
 * Groups issues with 50+ instances under a collapsible summary
 */
function renderIssuesWithGrouping(issues: Issue[]): string {
  // Group by engine to detect high-volume issues
  const byEngine = new Map<string, Issue[]>();
  for (const issue of issues) {
    const existing = byEngine.get(issue.engine) || [];
    existing.push(issue);
    byEngine.set(issue.engine, existing);
  }

  // Identify high-volume groups (30+ issues OR >40% of total)
  const highVolumeThreshold = 30;
  const percentageThreshold = 0.4; // 40% of total issues
  const highVolumeEngines = new Set<string>();
  for (const [engine, engineIssues] of byEngine.entries()) {
    const percentage = engineIssues.length / issues.length;
    if (engineIssues.length >= highVolumeThreshold || percentage >= percentageThreshold) {
      highVolumeEngines.add(engine);
    }
  }

  // If no high-volume groups, render normally
  if (highVolumeEngines.size === 0) {
    return renderIssues(issues);
  }

  // Render with grouping
  const engineNames: Record<string, string> = {
    'idor': 'Insecure Direct Object Reference',
    'missing-input-validation': 'Missing Input Validation',
    'hardcoded-secret': 'Hardcoded Secrets',
    'stack-trace-exposure': 'Stack Trace Exposure',
    'missing-await': 'Missing Await',
    'async-foreach': 'Async forEach/map',
    'hallucinated-deps': 'Hallucinated Dependencies',
    'unsafe-regex': 'Unsafe Regular Expressions (ReDoS)',
    'console-in-production': 'Console in Production',
    'empty-catch': 'Empty Catch Blocks',
  };

  let html = '';
  const renderedEngines = new Set<string>();

  // Separate critical issues from remaining issues
  const remainingIssues = issues.filter(i => !renderedEngines.has(i.engine));
  const criticalIssues = remainingIssues.filter(i => i.severity === 'error');
  const nonCriticalIssues = remainingIssues.filter(i => i.severity !== 'error');

  // Render critical issues FIRST (highest priority, always visible)
  if (criticalIssues.length > 0) {
    html += renderIssues(criticalIssues);
  }

  // Then render high-volume groups (collapsed by default)
  for (const engine of highVolumeEngines) {
    const engineIssues = byEngine.get(engine)!;
    const fileCount = new Set(engineIssues.map(i => i.filePath)).size;
    const engineName = engineNames[engine] || engine;

    html += `
    <div class="issue-group">
      <div class="issue-group-header" onclick="toggleIssueGroup(this)">
        <div class="issue-group-info">
          <strong>${escapeHtml(engineName)}</strong>
          <span class="issue-group-count">${engineIssues.length} issues across ${fileCount} files</span>
        </div>
        <div class="issue-group-expand">▼</div>
      </div>
      <div class="issue-group-body" style="display: none;">
        ${renderIssues(engineIssues)}
      </div>
    </div>
    `;
    renderedEngines.add(engine);
  }

  // Finally render remaining non-critical issues
  if (nonCriticalIssues.length > 0) {
    html += renderIssues(nonCriticalIssues);
  }

  return html;
}

function renderIssues(issues: Issue[]): string {
  return issues.map((issue, index) => {
    const confidence = issue.confidence || 'high';
    const engineNames: Record<string, string> = {
      'idor': 'Insecure Direct Object Reference',
      'missing-input-validation': 'Missing Input Validation',
      'hardcoded-secret': 'Hardcoded Secrets',
      'stack-trace-exposure': 'Stack Trace Exposure',
      'missing-await': 'Missing Await',
      'async-foreach': 'Async forEach/map',
      'hallucinated-deps': 'Hallucinated Dependencies',
      'unsafe-regex': 'Unsafe Regular Expressions (ReDoS)',
      'console-in-production': 'Console in Production',
      'empty-catch': 'Empty Catch Blocks',
    };

    return `
    <div class="issue-card" data-severity="${issue.severity}" data-confidence="${confidence}" data-engine="${issue.engine}" data-file="${escapeHtml(issue.filePath)}">
        <div class="issue-card-header" onclick="toggleIssueCard(this)">
            <div class="issue-card-left">
                <div class="issue-card-title">
                    ${escapeHtml(issue.message)}
                </div>
                <div class="issue-card-meta">
                    <span class="issue-badge badge-${issue.severity}">${issue.severity.toUpperCase()}</span>
                    <span class="badge-confidence badge-${confidence}">${confidence.toUpperCase()}</span>
                    ${issue.riskScore !== undefined ? `<span class="risk-badge risk-${issue.priority || 'low'}">Risk: ${issue.riskScore}/100</span>` : ''}
                    <span>${escapeHtml(issue.filePath)}:${issue.location.line}</span>
                    <span>•</span>
                    <span>${engineNames[issue.engine] || issue.engine}</span>
                </div>
            </div>
            <div class="issue-card-expand">▼</div>
        </div>
        <div class="issue-card-body">
            <div><strong>File:</strong> ${escapeHtml(issue.filePath)}</div>
            <div><strong>Line:</strong> ${issue.location.line}</div>
            <div><strong>Engine:</strong> ${engineNames[issue.engine] || issue.engine}</div>
            <div><strong>Severity:</strong> ${issue.severity.toUpperCase()}</div>
            <div><strong>Confidence:</strong> ${confidence.toUpperCase()}</div>
            ${issue.riskScore !== undefined ? `<div><strong>Risk Score:</strong> ${issue.riskScore}/100 (${issue.priority?.toUpperCase() || 'LOW'} priority)</div>` : ''}
            ${issue.suggestion ? `
            <div class="suggestion-box">
                <div class="suggestion-box-header">
                    <span class="suggestion-label">Suggestion</span>
                    <button class="copy-btn" onclick="copyToClipboard(this, ${index})">Copy</button>
                </div>
                <div class="suggestion-text" data-suggestion="${escapeHtml(issue.suggestion).replace(/"/g, '&quot;')}">${escapeHtml(issue.suggestion)}</div>
            </div>
            ` : ''}
        </div>
    </div>
  `;
  }).join('');
}

// Removed: render functions for views (caused 5x multiplier bug)
// @ts-expect-error - Unused function, kept for potential future use
function _renderIssuesByFile(issuesByFile: Map<string, Issue[]>): string {
  const entries = Array.from(issuesByFile.entries()).sort((a, b) => b[1].length - a[1].length);

  return entries.map(([file, issues]) => `
    <div class="file-group">
        <div class="file-group-header">
            <span>${escapeHtml(file)}</span>
            <span class="file-count">${issues.length} issue${issues.length === 1 ? '' : 's'}</span>
        </div>
        ${renderIssues(issues)}
    </div>
  `).join('');
}

// @ts-expect-error - Unused function, kept for potential future use
function _renderIssuesByEngine(issuesByEngine: Map<string, Issue[]>): string {
  // Prioritize by danger level, not just count
  const priority: Record<string, number> = {
    'idor': 1,
    'missing-input-validation': 2,
    'hardcoded-secret': 3,
    'stack-trace-exposure': 4,
    'missing-await': 5,
    'async-foreach': 6,
    'hallucinated-deps': 7,
    'unsafe-regex': 8,
    'console-in-production': 9,
    'empty-catch': 10,
  };

  const entries = Array.from(issuesByEngine.entries()).sort((a, b) => {
    const aPriority = priority[a[0]] || 99;
    const bPriority = priority[b[0]] || 99;
    if (aPriority !== bPriority) return aPriority - bPriority;
    return b[1].length - a[1].length; // If same priority, sort by count
  });

  const engineNames: Record<string, string> = {
    'idor': 'Insecure Direct Object Reference',
    'missing-input-validation': 'Missing Input Validation',
    'hardcoded-secret': 'Hardcoded Secrets',
    'stack-trace-exposure': 'Stack Trace Exposure',
    'missing-await': 'Missing Await',
    'async-foreach': 'Async forEach/map',
    'hallucinated-deps': 'Hallucinated Dependencies',
    'unsafe-regex': 'Unsafe Regular Expressions (ReDoS)',
    'console-in-production': 'Console in Production',
    'empty-catch': 'Empty Catch Blocks',
  };

  return entries.map(([engine, issues]) => `
    <div class="file-group">
        <div class="file-group-header">
            <span>${engineNames[engine] || engine}</span>
            <span class="file-count">${issues.length} issue${issues.length === 1 ? '' : 's'}</span>
        </div>
        ${renderIssues(issues)}
    </div>
  `).join('');
}

// @ts-expect-error - Unused function, kept for potential future use
function _groupIssuesByFile(issues: Issue[]): Map<string, Issue[]> {
  const map = new Map<string, Issue[]>();

  for (const issue of issues) {
    const existing = map.get(issue.filePath) || [];
    existing.push(issue);
    map.set(issue.filePath, existing);
  }

  return map;
}

// @ts-expect-error - Unused function, kept for potential future use
function _groupIssuesByEngine(issues: Issue[]): Map<string, Issue[]> {
  const map = new Map<string, Issue[]>();

  for (const issue of issues) {
    const existing = map.get(issue.engine) || [];
    existing.push(issue);
    map.set(issue.engine, existing);
  }

  return map;
}

// Function kept for potential future use
// @ts-expect-error - Unused function kept for future use
function _groupIssuesByConfidence(_issues: Issue[]): Map<string, Issue[]> {
  const map = new Map<string, Issue[]>();

  for (const issue of _issues) {
    const confidence = issue.confidence || 'high';
    const existing = map.get(confidence) || [];
    existing.push(issue);
    map.set(confidence, existing);
  }

  return map;
}

/**
 * Detect project root by finding common path prefix across all issues
 */
function detectProjectRoot(issues: Issue[]): string {
  if (issues.length === 0) return '';

  const paths = issues.map(i => i.filePath);
  if (paths.length === 0) return '';

  // Normalize paths (handle both / and \)
  const normalizedPaths = paths.map(p => p.replace(/\\/g, '/'));

  // Split into parts
  const pathParts = normalizedPaths.map(p => p.split('/'));

  // Find common prefix
  let commonPrefix: string[] = [];
  const firstPath = pathParts[0];

  for (let i = 0; i < firstPath.length; i++) {
    const part = firstPath[i];
    if (pathParts.every(p => p[i] === part)) {
      commonPrefix.push(part);
    } else {
      break;
    }
  }

  // Return common prefix as path (exclude filename)
  return commonPrefix.slice(0, -1).join('/');
}

/**
 * Make file path relative to project root
 */
function makeRelativePath(filePath: string, projectRoot: string): string {
  if (!projectRoot) return filePath;

  const normalized = filePath.replace(/\\/g, '/');
  const rootNormalized = projectRoot.replace(/\\/g, '/');

  if (normalized.startsWith(rootNormalized)) {
    return normalized.slice(rootNormalized.length + 1); // +1 for trailing slash
  }

  return filePath;
}

function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };

  return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * HTML report generator - Professional corporate design
 * Creates self-contained HTML report with inline CSS
 */

import type { AnalysisResult, Issue, CodeDriftConfig } from '../types/index.js';

export function generateHTMLReport(result: AnalysisResult, config: CodeDriftConfig): string {
  const { issues, stats, startTime, endTime } = result;

  const criticalIssues = issues.filter(i => i.severity === 'error');
  const warnings = issues.filter(i => i.severity === 'warning');
  const duration = startTime && endTime ? endTime - startTime : 0;

  const issuesByFile = groupIssuesByFile(issues);
  const issuesByEngine = groupIssuesByEngine(issues);

  const highConfidence = issues.filter(i => (i.confidence || 'high') === 'high');
  const mediumConfidence = issues.filter(i => (i.confidence || 'high') === 'medium');
  const lowConfidence = issues.filter(i => (i.confidence || 'high') === 'low');

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

        .filter-tabs {
            display: flex;
            gap: 8px;
            margin-bottom: 24px;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 16px;
        }

        .filter-tab {
            padding: 8px 16px;
            background: transparent;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
            color: #6b7280;
            transition: all 0.15s;
        }

        .filter-tab:hover {
            border-color: #d1d5db;
            background: #f9fafb;
        }

        .filter-tab.active {
            background: #3b82f6;
            color: white;
            border-color: #3b82f6;
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

        .view-container {
            display: none;
        }

        .view-container.active {
            display: block;
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

        .no-issues .icon {
            font-size: 48px;
            color: #10b981;
            margin-bottom: 16px;
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

        @media print {
            body {
                background: white;
            }
            .filter-tabs {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-left">
                <h1>🛡️ CodeDrift Security Report</h1>
                <p class="subtitle">AI Code Safety Analysis</p>
            </div>
            <div class="header-right">
                <p class="timestamp">Generated: ${new Date().toLocaleString()}</p>
                ${criticalIssues.length > 0
                    ? '<p style="color: #dc2626; font-weight: 600; font-size: 14px; margin-top: 4px;">⚠️ Critical Issues Found</p>'
                    : '<p style="color: #10b981; font-weight: 600; font-size: 14px; margin-top: 4px;">✓ All Clear</p>'
                }
            </div>
        </header>

        <div class="main-content">
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
                    <div class="value neutral">${duration}ms</div>
                </div>
            </div>

            ${issues.length === 0 ? `
            <div class="section">
                <div class="section-body">
                    <div class="no-issues">
                        <div class="icon">✓</div>
                        <h3>No Issues Found</h3>
                        <p>Your code passed all security and quality checks.</p>
                    </div>
                </div>
            </div>
            ` : `
            <div class="section">
                <div class="section-header">
                    <h2>Issues</h2>
                </div>
                <div class="section-body">
                    <div class="filter-tabs">
                        <button class="filter-tab active" onclick="showView('all')">All (${issues.length})</button>
                        <button class="filter-tab" onclick="showView('severity')">By Severity</button>
                        <button class="filter-tab" onclick="showView('file')">By File</button>
                        <button class="filter-tab" onclick="showView('engine')">By Engine</button>
                        <button class="filter-tab" onclick="showView('confidence')">By Confidence</button>
                    </div>

                    <!-- View: All Issues -->
                    <div id="view-all" class="view-container active">
                        ${renderIssues(issues)}
                    </div>

                    <!-- View: By Severity -->
                    <div id="view-severity" class="view-container">
                        ${criticalIssues.length > 0 ? `
                        <div class="file-group">
                            <div class="file-group-header">
                                <span>Critical Issues</span>
                                <span class="file-count">${criticalIssues.length} issue${criticalIssues.length === 1 ? '' : 's'}</span>
                            </div>
                            ${renderIssues(criticalIssues)}
                        </div>
                        ` : ''}
                        ${warnings.length > 0 ? `
                        <div class="file-group">
                            <div class="file-group-header">
                                <span>Warnings</span>
                                <span class="file-count">${warnings.length} issue${warnings.length === 1 ? '' : 's'}</span>
                            </div>
                            ${renderIssues(warnings)}
                        </div>
                        ` : ''}
                    </div>

                    <!-- View: By File -->
                    <div id="view-file" class="view-container">
                        ${renderIssuesByFile(issuesByFile)}
                    </div>

                    <!-- View: By Engine -->
                    <div id="view-engine" class="view-container">
                        ${renderIssuesByEngine(issuesByEngine)}
                    </div>

                    <!-- View: By Confidence -->
                    <div id="view-confidence" class="view-container">
                        ${highConfidence.length > 0 ? `
                        <div class="file-group">
                            <div class="file-group-header">
                                <span>High Confidence</span>
                                <span class="file-count">${highConfidence.length} issue${highConfidence.length === 1 ? '' : 's'}</span>
                            </div>
                            ${renderIssues(highConfidence)}
                        </div>
                        ` : ''}
                        ${mediumConfidence.length > 0 ? `
                        <div class="file-group">
                            <div class="file-group-header">
                                <span>Medium Confidence</span>
                                <span class="file-count">${mediumConfidence.length} issue${mediumConfidence.length === 1 ? '' : 's'}</span>
                            </div>
                            ${renderIssues(mediumConfidence)}
                        </div>
                        ` : ''}
                        ${lowConfidence.length > 0 ? `
                        <div class="file-group">
                            <div class="file-group-header">
                                <span>Low Confidence</span>
                                <span class="file-count">${lowConfidence.length} issue${lowConfidence.length === 1 ? '' : 's'}</span>
                            </div>
                            ${renderIssues(lowConfidence)}
                        </div>
                        ` : ''}
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
            <p><strong>CodeDrift v1.1.0</strong> - AI Code Safety Guardian</p>
            <p style="margin-top: 8px;">
                <a href="https://github.com/hamzzaaamalik/codedrift" target="_blank">github.com/hamzzaaamalik/codedrift</a>
            </p>
        </footer>
    </div>

    <script>
        function showView(viewName) {
            // Hide all view containers
            const views = document.querySelectorAll('.view-container');
            views.forEach(view => view.classList.remove('active'));

            // Show selected view
            const selectedView = document.getElementById('view-' + viewName);
            if (selectedView) {
                selectedView.classList.add('active');
            }

            // Update tab states
            const tabs = document.querySelectorAll('.filter-tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            event.target.classList.add('active');
        }
    </script>
</body>
</html>`;
}

function renderIssues(issues: Issue[]): string {
  return issues.map(issue => {
    const confidence = issue.confidence || 'high';
    return `
    <div class="issue ${issue.severity}">
        <div class="issue-header">
            <div class="issue-location">${escapeHtml(issue.filePath)}:${issue.location.line}</div>
            <div>
                <span class="issue-badge badge-${issue.severity}">${issue.severity}</span>
                <span class="badge-confidence badge-${confidence}">${confidence}</span>
            </div>
        </div>
        <div class="issue-message">${escapeHtml(issue.message)}</div>
        ${issue.suggestion ? `<div class="issue-suggestion">${escapeHtml(issue.suggestion)}</div>` : ''}
    </div>
  `;
  }).join('');
}

function renderIssuesByFile(issuesByFile: Map<string, Issue[]>): string {
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

function renderIssuesByEngine(issuesByEngine: Map<string, Issue[]>): string {
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

function groupIssuesByFile(issues: Issue[]): Map<string, Issue[]> {
  const map = new Map<string, Issue[]>();

  for (const issue of issues) {
    const existing = map.get(issue.filePath) || [];
    existing.push(issue);
    map.set(issue.filePath, existing);
  }

  return map;
}

function groupIssuesByEngine(issues: Issue[]): Map<string, Issue[]> {
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
function _groupIssuesByConfidence(issues: Issue[]): Map<string, Issue[]> {
  const map = new Map<string, Issue[]>();

  for (const issue of issues) {
    const confidence = issue.confidence || 'high';
    const existing = map.get(confidence) || [];
    existing.push(issue);
    map.set(confidence, existing);
  }

  return map;
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

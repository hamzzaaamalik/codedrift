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
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            color: #FFFFFF;
            background-color: #0B0F1A;
            background-image:
                radial-gradient(circle at 20% 20%, rgba(17,24,39,0.9) 0%, transparent 40%),
                radial-gradient(circle at 80% 30%, rgba(30,41,59,0.6) 0%, transparent 45%);
            min-height: 100vh;
        }

        .container { max-width: 1400px; margin: 0 auto; }

        header {
            background: rgba(11,15,26,0.92);
            border-bottom: 1px solid rgba(255,255,255,0.15);
            padding: 18px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(12px);
        }

        .header-left h1 {
            font-size: 17px;
            font-weight: 600;
            color: #FFFFFF;
            margin-bottom: 2px;
            letter-spacing: -0.01em;
        }

        .header-left .subtitle { font-size: 12px; color: #64748B; letter-spacing: 0.03em; }
        .header-right { text-align: right; }
        .timestamp { color: #FFFFFF; font-size: 11px; }

        .header-status-badge {
            display: inline-block;
            margin-top: 5px;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.04em;
        }
        .header-status-critical {
            background: rgba(239,68,68,0.12);
            color: #EF4444;
            border: 1px solid rgba(239,68,68,0.22);
        }
        .header-status-clear {
            background: rgba(16,185,129,0.12);
            color: #10B981;
            border: 1px solid rgba(16,185,129,0.22);
        }

        .main-content { padding: 32px 40px; }

        /* ── Hero Stats ─────────────────────────────────────────── */
        .hero-stats {
            display: flex;
            background: #0F172A;
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 14px;
            margin-bottom: 28px;
            overflow: hidden;
        }
        .hero-stat {
            flex: 1;
            padding: 24px 28px;
            border-right: 1px solid rgba(255,255,255,0.05);
        }
        .hero-stat:last-child { border-right: none; }
        .hero-stat .stat-label {
            font-size: 10px;
            font-weight: 600;
            color: #FFFFFF;
            text-transform: uppercase;
            letter-spacing: 0.09em;
            margin-bottom: 10px;
        }
        .hero-stat .stat-value {
            font-size: 36px;
            font-weight: 700;
            line-height: 1;
            letter-spacing: -0.025em;
            font-variant-numeric: tabular-nums;
        }
        .s-critical { color: #EF4444; }
        .s-warning  { color: #F59E0B; }
        .s-success  { color: #10B981; }
        .s-neutral  { color: #FFFFFF; }
        .s-blue     { color: #60A5FA; }

        /* ── Metric Cards (kept for compat) ─────────────────────── */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 28px;
        }
        .metric-card {
            background: #0F172A;
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 12px;
            padding: 18px 20px;
            transition: border-color 0.15s;
        }
        .metric-card:hover { border-color: rgba(255,255,255,0.26); }
        .metric-card .label {
            font-size: 10px;
            font-weight: 600;
            color: #FFFFFF;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 8px;
        }
        .metric-card .value {
            font-size: 30px;
            font-weight: 700;
            line-height: 1;
            letter-spacing: -0.02em;
        }
        .value.critical { color: #EF4444; }
        .value.warning  { color: #F59E0B; }
        .value.success  { color: #10B981; }
        .value.neutral  { color: #FFFFFF; }

        /* ── Section wrapper ────────────────────────────────────── */
        .section {
            background: #0F172A;
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 12px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .section-header {
            padding: 13px 22px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            background: rgba(255,255,255,0.02);
        }
        .section-header h2 {
            font-size: 11px;
            font-weight: 600;
            color: #64748B;
            text-transform: uppercase;
            letter-spacing: 0.07em;
        }
        .section-body { padding: 20px; }

        /* ── Executive Summary ──────────────────────────────────── */
        .executive-summary {
            background: #0F172A;
            border: 1px solid rgba(255,255,255,0.15);
            color: #FFFFFF;
            padding: 28px 32px;
            border-radius: 14px;
            margin-bottom: 24px;
        }
        .executive-summary h2 {
            font-size: 11px;
            font-weight: 600;
            color: #FFFFFF;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 20px;
        }
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }
        .summary-stat-card {
            background: rgba(255,255,255,0.03);
            border-radius: 10px;
            padding: 16px;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .summary-stat-card .stat-label {
            font-size: 10px;
            color: #FFFFFF;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 600;
        }
        .summary-stat-card .stat-value {
            font-size: 26px;
            font-weight: 700;
            color: #FFFFFF;
            letter-spacing: -0.01em;
        }
        .top-issues-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        .top-list {
            background: rgba(255,255,255,0.02);
            border-radius: 10px;
            padding: 18px 20px;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .top-list h3 {
            font-size: 10px;
            font-weight: 600;
            margin-bottom: 14px;
            color: #FFFFFF;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }
        .top-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid rgba(255,255,255,0.04);
        }
        .top-item:last-child { border-bottom: none; }
        .top-item-name {
            color: #FFFFFF;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            flex: 1;
            margin-right: 12px;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 11px;
        }
        .top-item-count {
            font-weight: 700;
            font-size: 13px;
            background: rgba(255,255,255,0.05);
            color: #FFFFFF;
            padding: 2px 10px;
            border-radius: 8px;
            min-width: 32px;
            text-align: center;
        }

        /* ── Progress Bar ───────────────────────────────────────── */
        .progress-bar {
            background: rgba(255,255,255,0.05);
            height: 2px;
            border-radius: 2px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #F59E0B, #FBBF24);
            transition: width 0.8s ease;
        }

        /* ── Filter Controls ────────────────────────────────────── */
        .filter-controls {
            background: #0F172A;
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 12px;
            padding: 18px 20px;
            margin-bottom: 16px;
        }
        .filter-controls h3 {
            font-size: 10px;
            font-weight: 600;
            color: #FFFFFF;
            margin-bottom: 14px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .filter-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 10px;
            margin-bottom: 10px;
        }
        .filter-group { display: flex; flex-direction: column; gap: 5px; }
        .filter-group label {
            font-size: 10px;
            font-weight: 600;
            color: #FFFFFF;
            text-transform: uppercase;
            letter-spacing: 0.07em;
        }
        .filter-group select,
        .filter-group input {
            padding: 7px 11px;
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 7px;
            font-size: 12px;
            background: rgba(255,255,255,0.04);
            color: #E2E8F0;
            transition: border-color 0.15s;
            outline: none;
        }
        .filter-group select:focus,
        .filter-group input:focus {
            border-color: rgba(59,130,246,0.45);
            box-shadow: 0 0 0 3px rgba(59,130,246,0.07);
        }
        .filter-group select option { background: #1E293B; color: #F1F5F9; }
        .filter-group input::placeholder { color: #FFFFFF; }

        .smart-filters { display: flex; gap: 7px; flex-wrap: wrap; margin-top: 10px; }
        .smart-filter-btn {
            padding: 4px 11px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 6px;
            font-size: 11px;
            font-weight: 500;
            color: #FFFFFF;
            cursor: pointer;
            transition: all 0.15s;
        }
        .smart-filter-btn:hover { background: rgba(255,255,255,0.07); color: #F1F5F9; border-color: rgba(255,255,255,0.13); }
        .smart-filter-btn.active { background: rgba(245,158,11,0.12); color: #F59E0B; border-color: rgba(245,158,11,0.28); }

        .filter-status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid rgba(255,255,255,0.05);
            font-size: 11px;
            color: #FFFFFF;
        }
        .clear-filters-btn {
            padding: 4px 11px;
            background: rgba(239,68,68,0.08);
            color: #EF4444;
            border: 1px solid rgba(239,68,68,0.18);
            border-radius: 6px;
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }
        .clear-filters-btn:hover { background: rgba(239,68,68,0.14); }

        /* ── Search Box ─────────────────────────────────────────── */
        .search-box { position: relative; margin-bottom: 12px; }
        .search-box input {
            width: 100%;
            padding: 8px 14px;
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 8px;
            font-size: 13px;
            background: rgba(255,255,255,0.03);
            color: #E2E8F0;
            transition: border-color 0.15s;
            outline: none;
        }
        .search-box input::placeholder { color: #FFFFFF; }
        .search-box input:focus {
            border-color: rgba(59,130,246,0.45);
            box-shadow: 0 0 0 3px rgba(59,130,246,0.07);
        }

        /* ── Action Buttons ─────────────────────────────────────── */
        .action-buttons { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
        .action-btn {
            padding: 7px 14px;
            background: rgba(255,255,255,0.04);
            border: 1px solid rgba(255,255,255,0.07);
            border-radius: 7px;
            font-size: 12px;
            font-weight: 500;
            color: #FFFFFF;
            cursor: pointer;
            transition: all 0.15s;
        }
        .action-btn:hover { background: rgba(255,255,255,0.07); color: #F1F5F9; border-color: rgba(255,255,255,0.13); }
        .action-btn.primary {
            background: rgba(245,158,11,0.10);
            color: #F59E0B;
            border-color: rgba(245,158,11,0.25);
        }
        .action-btn.primary:hover { background: rgba(245,158,11,0.16); }

        /* ── Issue Group (high-volume) ──────────────────────────── */
        .issue-group {
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 12px;
            margin-bottom: 10px;
            overflow: hidden;
            background: #0F172A;
            transition: border-color 0.15s;
        }
        .issue-group:hover { border-color: rgba(255,255,255,0.24); }
        .issue-group-header {
            padding: 13px 18px;
            background: rgba(255,255,255,0.02);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            transition: background 0.15s;
        }
        .issue-group-header:hover { background: rgba(255,255,255,0.04); }
        .issue-group-info { display: flex; flex-direction: column; gap: 3px; }
        .issue-group-info strong { font-size: 13px; color: #FFFFFF; }
        .issue-group-count { font-size: 11px; color: #64748B; }
        .issue-group-expand { color: #FFFFFF; font-size: 14px; transition: transform 0.2s; }
        .issue-group.expanded .issue-group-expand { transform: rotate(180deg); }
        .issue-group-body { padding: 10px; border-top: 1px solid rgba(255,255,255,0.04); }

        /* ── Issue Cards ────────────────────────────────────────── */
        .issue-card {
            border: 1px solid rgba(255,255,255,0.12);
            border-radius: 10px;
            margin-bottom: 7px;
            overflow: hidden;
            background: rgba(15,23,42,0.6);
            transition: border-color 0.15s, box-shadow 0.15s;
        }
        .issue-card:last-child { margin-bottom: 0; }
        .issue-card:hover {
            border-color: rgba(255,255,255,0.22);
            box-shadow: 0 6px 24px rgba(0,0,0,0.35);
        }
        .issue-card-header {
            padding: 11px 14px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: start;
            gap: 12px;
            user-select: none;
        }
        .issue-card-header:hover { background: rgba(255,255,255,0.02); }
        .issue-card-left { flex: 1; min-width: 0; }
        .issue-card-title {
            font-size: 13px;
            font-weight: 500;
            color: #FFFFFF;
            margin-bottom: 6px;
            line-height: 1.4;
        }
        .issue-card-meta {
            font-size: 11px;
            color: #FFFFFF;
            display: flex;
            align-items: center;
            gap: 7px;
            flex-wrap: wrap;
        }
        .issue-file {
            color: #64748B;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 11px;
        }
        .issue-line {
            color: #3B82F6;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 11px;
            font-weight: 600;
        }
        .rule-tag {
            background: rgba(59,130,246,0.09);
            color: #60A5FA;
            border: 1px solid rgba(59,130,246,0.16);
            border-radius: 4px;
            padding: 1px 6px;
            font-size: 10px;
            font-weight: 500;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            letter-spacing: 0.01em;
        }
        .issue-card-expand { color: #334155; font-size: 14px; transition: transform 0.2s; flex-shrink: 0; margin-top: 1px; }
        .issue-card.expanded .issue-card-expand { transform: rotate(180deg); }
        .issue-card-body {
            display: none;
            padding: 14px 16px;
            border-top: 1px solid rgba(255,255,255,0.04);
            background: rgba(0,0,0,0.18);
        }
        .issue-card-body > div { font-size: 12px; color: #C8D0DC; margin-bottom: 3px; }
        .issue-card-body > div strong { color: #FFFFFF; font-weight: 500; }
        .issue-card.expanded .issue-card-body { display: block; }

        /* ── Severity / Confidence Badges ───────────────────────── */
        .issue-badge {
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .badge-error   { background: rgba(239,68,68,0.12);  color: #EF4444; border: 1px solid rgba(239,68,68,0.22); }
        .badge-warning { background: rgba(245,158,11,0.12); color: #F59E0B; border: 1px solid rgba(245,158,11,0.22); }

        .badge-confidence {
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .badge-high   { background: rgba(16,185,129,0.10); color: #10B981; border: 1px solid rgba(16,185,129,0.20); }
        .badge-medium { background: rgba(245,158,11,0.10); color: #F59E0B; border: 1px solid rgba(245,158,11,0.20); }
        .badge-low    { background: rgba(100,116,139,0.10); color: #64748B; border: 1px solid rgba(100,116,139,0.18); }

        .risk-badge {
            padding: 2px 7px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .risk-critical { background: rgba(239,68,68,0.12);  color: #EF4444; border: 1px solid rgba(239,68,68,0.22); }
        .risk-high     { background: rgba(234,88,12,0.12);  color: #F97316; border: 1px solid rgba(234,88,12,0.22); }
        .risk-medium   { background: rgba(245,158,11,0.12); color: #F59E0B; border: 1px solid rgba(245,158,11,0.22); }
        .risk-low      { background: rgba(59,130,246,0.10); color: #60A5FA; border: 1px solid rgba(59,130,246,0.18); }

        /* ── Suggestion Box ─────────────────────────────────────── */
        .suggestion-box {
            background: rgba(16,185,129,0.05);
            border-left: 2px solid rgba(16,185,129,0.35);
            padding: 11px 14px;
            border-radius: 6px;
            margin-top: 10px;
        }
        .suggestion-box-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }
        .suggestion-label {
            font-size: 10px;
            font-weight: 600;
            color: #10B981;
            text-transform: uppercase;
            letter-spacing: 0.07em;
        }
        .copy-btn {
            padding: 2px 8px;
            background: rgba(16,185,129,0.10);
            color: #10B981;
            border: 1px solid rgba(16,185,129,0.20);
            border-radius: 4px;
            font-size: 10px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
        }
        .copy-btn:hover { background: rgba(16,185,129,0.18); }
        .suggestion-text {
            font-size: 12px;
            color: #6EE7B7;
            line-height: 1.5;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
        }

        /* ── Code Snippet ───────────────────────────────────────── */
        .code-snippet {
            background: #050810;
            color: #FFFFFF;
            padding: 13px 15px;
            border-radius: 7px;
            overflow-x: auto;
            font-family: 'SF Mono', 'Monaco', 'Fira Code', 'Consolas', monospace;
            font-size: 12px;
            line-height: 1.6;
            margin-top: 10px;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .code-line-number { color: #2D3F55; margin-right: 14px; user-select: none; }

        /* ── Collapsible ────────────────────────────────────────── */
        .collapsible-section { margin-bottom: 10px; }
        .collapsible-header {
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 8px;
            padding: 11px 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
            transition: background 0.15s;
        }
        .collapsible-header:hover { background: rgba(255,255,255,0.04); }
        .collapsible-header h3 { font-size: 13px; font-weight: 500; color: #FFFFFF; display: flex; align-items: center; gap: 8px; }
        .collapsible-count { background: rgba(255,255,255,0.05); padding: 2px 9px; border-radius: 8px; font-size: 11px; font-weight: 600; color: #FFFFFF; }
        .collapsible-body { margin-top: 7px; display: none; }
        .collapsible-section.expanded .collapsible-body { display: block; }
        .collapsible-section.expanded .collapsible-header { border-bottom-left-radius: 0; border-bottom-right-radius: 0; border-bottom: none; }

        /* ── No Issues State ────────────────────────────────────── */
        .no-issues { text-align: center; padding: 64px 24px; }
        .no-issues h3 { font-size: 18px; font-weight: 600; color: #F1F5F9; margin-bottom: 8px; }
        .no-issues p { color: #64748B; font-size: 14px; }

        /* ── pre / config ───────────────────────────────────────── */
        pre {
            background: #050810;
            color: #FFFFFF;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 12px;
            border: 1px solid rgba(255,255,255,0.05);
            font-family: 'SF Mono', 'Monaco', 'Fira Code', 'Consolas', monospace;
            line-height: 1.6;
        }

        /* ── File group ─────────────────────────────────────────── */
        .file-group { margin-bottom: 20px; }
        .file-group-header {
            font-size: 11px;
            font-weight: 600;
            color: #FFFFFF;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
        }
        .file-count { font-size: 10px; font-weight: 600; color: #64748B; background: rgba(255,255,255,0.04); padding: 2px 7px; border-radius: 8px; }

        /* ── Issue type labels ──────────────────────────────────── */
        .issue { border-left: 2px solid rgba(239,68,68,0.5); padding: 14px; margin-bottom: 10px; background: rgba(239,68,68,0.05); border-radius: 6px; }
        .issue.warning { border-left-color: rgba(245,158,11,0.5); background: rgba(245,158,11,0.05); }
        .issue-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px; }
        .issue-location { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 12px; color: #60A5FA; font-weight: 600; }
        .issue-message { font-size: 13px; font-weight: 500; margin-bottom: 6px; color: #FFFFFF; }
        .issue-suggestion { color: #FFFFFF; font-size: 12px; padding: 10px 12px; background: rgba(255,255,255,0.03); border-radius: 5px; margin-top: 8px; border-left: 2px solid rgba(255,255,255,0.08);
        }

        /* ── Responsive ─────────────────────────────────────────── */
        @media (max-width: 1024px) {
            .summary-grid { grid-template-columns: repeat(3, 1fr); }
            .summary-stats { grid-template-columns: repeat(2, 1fr); }
            .top-issues-grid { grid-template-columns: 1fr; }
            .hero-stats { flex-wrap: wrap; }
            .hero-stat { min-width: 140px; }
        }
        @media (max-width: 768px) {
            .summary-grid { grid-template-columns: repeat(2, 1fr); }
            header { flex-direction: column; align-items: start; gap: 10px; padding: 16px 20px; }
            .main-content { padding: 20px; }
            .summary-stats { grid-template-columns: 1fr; }
            .filter-row { grid-template-columns: 1fr; }
            .executive-summary { padding: 20px; }
            .hero-stats { flex-direction: column; }
        }
        @media print {
            body { background: white; color: black; }
            .filter-controls, .action-buttons, .back-to-top, .search-box { display: none !important; }
            .issue-card-body { display: block !important; }
            .collapsible-body { display: block !important; }
        }

        /* ── Back to Top ────────────────────────────────────────── */
        .back-to-top {
            position: fixed; bottom: 28px; right: 28px;
            width: 38px; height: 38px;
            background: rgba(245,158,11,0.09);
            color: #F59E0B;
            border: 1px solid rgba(245,158,11,0.22);
            border-radius: 9px; font-size: 16px; cursor: pointer;
            opacity: 0; visibility: hidden; transition: all 0.25s;
            display: flex; align-items: center; justify-content: center;
        }
        .back-to-top.visible { opacity: 1; visibility: visible; }
        .back-to-top:hover { background: rgba(245,158,11,0.16); transform: translateY(-2px); }

        /* ── Footer ─────────────────────────────────────────────── */
        footer {
            text-align: center; padding: 22px 40px;
            color: #FFFFFF; font-size: 11px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        footer a { color: #60A5FA; text-decoration: none; }
        footer a:hover { color: #93C5FD; }
        .enhanced-footer { display: flex; justify-content: space-between; align-items: center; }
        .enhanced-footer strong { color: #FFFFFF; }
        .footer-version { font-size: 11px; color: #FFFFFF; text-align: right; line-height: 1.8; }
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
                    ? '<span class="header-status-badge header-status-critical">Issues Found</span>'
                    : '<span class="header-status-badge header-status-clear">All Clear</span>'
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
            <div class="hero-stats">
                <div class="hero-stat">
                    <div class="stat-label">Critical</div>
                    <div class="stat-value s-critical" data-count-up="${criticalIssues.length}">${criticalIssues.length}</div>
                </div>
                <div class="hero-stat">
                    <div class="stat-label">Warnings</div>
                    <div class="stat-value s-warning" data-count-up="${warnings.length}">${warnings.length}</div>
                </div>
                <div class="hero-stat">
                    <div class="stat-label">High Confidence</div>
                    <div class="stat-value ${highConfidence.length > 0 ? 's-critical' : 's-success'}" data-count-up="${highConfidence.length}">${highConfidence.length}</div>
                </div>
                <div class="hero-stat">
                    <div class="stat-label">Total Issues</div>
                    <div class="stat-value s-neutral" data-count-up="${issues.length}">${issues.length}</div>
                </div>
                <div class="hero-stat">
                    <div class="stat-label">Files Scanned</div>
                    <div class="stat-value s-blue" data-count-up="${stats.analyzed}">${stats.analyzed}</div>
                </div>
                <div class="hero-stat">
                    <div class="stat-label">Duration</div>
                    <div class="stat-value s-neutral">${(duration / 1000).toFixed(1)}s</div>
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

            // Hide issue groups where all cards are filtered out
            document.querySelectorAll('.issue-group').forEach(function(group) {
                const groupCards = group.querySelectorAll('.issue-card');
                const hasVisible = Array.from(groupCards).some(function(c) { return c.style.display !== 'none'; });
                group.style.display = hasVisible ? '' : 'none';
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

            // Count-up animation for hero stats
            document.querySelectorAll('[data-count-up]').forEach(function(el) {
                var target = parseInt(el.getAttribute('data-count-up'), 10);
                if (isNaN(target) || target === 0) return;
                var duration = 600;
                var start = performance.now();
                function tick(now) {
                    var elapsed = now - start;
                    var progress = Math.min(elapsed / duration, 1);
                    // ease-out cubic
                    var eased = 1 - Math.pow(1 - progress, 3);
                    el.textContent = Math.round(eased * target).toString();
                    if (progress < 1) requestAnimationFrame(tick);
                }
                requestAnimationFrame(tick);
            });
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

  // Non-high-volume issues only (high-volume engines get their own collapsed groups below)
  const criticalIssues = issues.filter(i => i.severity === 'error' && !highVolumeEngines.has(i.engine));
  const nonCriticalIssues = issues.filter(i => i.severity !== 'error' && !highVolumeEngines.has(i.engine));

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
  }

  // Finally render remaining non-critical issues (from non-high-volume engines)
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
                    <span class="issue-file">${escapeHtml(issue.filePath)}</span><span class="issue-line">:${issue.location.line}</span>
                    <span class="rule-tag">${issue.engine}</span>
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

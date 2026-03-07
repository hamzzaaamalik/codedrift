/**
 * FlowRenderer — Terminal and structured rendering of taint flow traces.
 */

import type { TaintQueryResult, TraceStep } from '../query/taint-query.js';

/** A rendered flow for terminal display */
export interface RenderedFlow {
  header: string;
  body: string;
  suggestion: string;
  text: string;
}

// ---------------------------------------------------------------------------
// Sink-kind labels and rule IDs
// ---------------------------------------------------------------------------

const SINK_KIND_LABELS: Record<string, string> = {
  'db-query': 'SQL Injection',
  'db-mutation': 'SQL Injection',
  'command-execution': 'Command Injection',
  'file-read': 'Path Traversal',
  'file-write': 'Path Traversal',
  'html-output': 'Cross-Site Scripting (XSS)',
  'template-render': 'Cross-Site Scripting (XSS)',
  'redirect': 'Open Redirect',
  'url-construction': 'Server-Side Request Forgery (SSRF)',
  'eval': 'Code Injection',
  'dynamic-import': 'Code Injection',
  'http-request': 'Server-Side Request Forgery (SSRF)',
  'log-output': 'Log Injection',
};

const FIX_SUGGESTIONS: Record<string, (callee: string) => string> = {
  'db-query': (callee) =>
    `Use parameterized queries: ${callee}('SELECT ... WHERE id = ?', [value])`,
  'db-mutation': (callee) =>
    `Use parameterized queries: ${callee}('INSERT INTO ... SET ?', [value])`,
  'command-execution': () =>
    'Avoid shell commands with user input. Use execFile() with an args array instead of exec()',
  'file-read': () =>
    'Validate and canonicalize file paths. Use path.resolve() and verify the result is within an allowed directory',
  'file-write': () =>
    'Validate and canonicalize file paths. Use path.resolve() and verify the result is within an allowed directory',
  'html-output': () =>
    'Escape HTML entities before rendering. Use a library like DOMPurify or encode with textContent',
  'template-render': () =>
    'Use auto-escaping template engine features. Avoid {{{raw}}} or |safe filters on user input',
  'redirect': () =>
    'Validate redirect URLs against an allowlist. Reject absolute URLs or URLs with different origins',
  'url-construction': () =>
    'Validate URLs against an allowlist of allowed hosts/schemes',
  'eval': () =>
    'Never pass user input to eval(). Refactor to avoid dynamic code execution entirely',
  'dynamic-import': () =>
    'Validate module specifiers against an allowlist. Never allow user input to control import paths',
  'http-request': () =>
    'Validate request URLs against an allowlist of allowed hosts/schemes',
  'log-output': () =>
    'Sanitize log output to prevent log injection. Strip newlines and control characters',
};

// ---------------------------------------------------------------------------
// FlowRenderer
// ---------------------------------------------------------------------------

export class FlowRenderer {
  renderFlow(flow: TaintQueryResult): RenderedFlow {
    const severity = this.getSeverity(flow.sinkKind, flow.isSanitized);
    const label = SINK_KIND_LABELS[flow.sinkKind] ?? flow.sinkKind;
    const desc = flow.isSanitized
      ? `User input reaches ${flow.sinkCallee} but is sanitized`
      : `User input reaches ${label.toLowerCase()} unsanitized`;

    const header = `${severity}: ${label} — ${desc}`;
    const summaryLine = this.buildSummaryLine(flow);
    const traceBody = this.buildTraceBody(flow);
    const body = `${summaryLine}\n\n${traceBody}`;
    const suggestion = this.getSuggestion(flow.sinkKind, flow.sinkCallee);
    const fixLine = `  └─ FIX: ${suggestion}`;
    const text = `${header}\n\n${body}\n${fixLine}\n`;

    return { header, body, suggestion, text };
  }

  renderReport(flows: TaintQueryResult[]): string {
    if (flows.length === 0) return 'No taint flows detected.';

    const sorted = [...flows].sort((a, b) => {
      return this.severityOrder(this.getSeverity(a.sinkKind, a.isSanitized))
           - this.severityOrder(this.getSeverity(b.sinkKind, b.isSanitized));
    });

    const parts: string[] = [];
    const unsanitized = flows.filter(f => !f.isSanitized).length;
    const sanitized = flows.filter(f => f.isSanitized).length;
    parts.push(`Taint Analysis Report — ${flows.length} flow(s) detected`);
    parts.push(`  Unsanitized: ${unsanitized}  |  Sanitized: ${sanitized}`);
    parts.push('');
    parts.push('='.repeat(72));

    for (let i = 0; i < sorted.length; i++) {
      parts.push('');
      parts.push(`[${i + 1}/${sorted.length}]`);
      parts.push(this.renderFlow(sorted[i]).text);
      if (i < sorted.length - 1) parts.push('-'.repeat(72));
    }

    parts.push('='.repeat(72));
    return parts.join('\n');
  }

  renderCompact(flow: TaintQueryResult): string {
    const severity = this.getSeverity(flow.sinkKind, flow.isSanitized);
    const ruleId = flow.sinkKind;
    const chain = this.buildChainLabel(flow);
    return `${severity} ${ruleId}: ${chain} [${flow.hopCount} hop${flow.hopCount !== 1 ? 's' : ''}, ${flow.fileCount} file${flow.fileCount !== 1 ? 's' : ''}]`;
  }

  getSuggestion(sinkKind: string, sinkCallee: string): string {
    const factory = FIX_SUGGESTIONS[sinkKind];
    if (factory) return factory(sinkCallee);
    return `Sanitize user input before passing it to ${sinkCallee}`;
  }

  getSeverity(sinkKind: string, sanitized: boolean): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' {
    if (sanitized) return 'INFO';
    switch (sinkKind) {
      case 'db-query': case 'db-mutation': case 'command-execution':
      case 'eval': case 'dynamic-import':
        return 'CRITICAL';
      case 'file-read': case 'file-write': case 'html-output':
      case 'template-render': case 'http-request': case 'url-construction':
        return 'HIGH';
      case 'redirect':
        return 'MEDIUM';
      case 'log-output':
        return 'LOW';
      default:
        return 'MEDIUM';
    }
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private buildSummaryLine(flow: TaintQueryResult): string {
    const chain = this.buildChainLabel(flow);
    const lines: string[] = [];
    lines.push(`  Flow: ${chain}`);
    lines.push(`  Hops: ${flow.fileCount} file${flow.fileCount !== 1 ? 's' : ''}, ${flow.hopCount} function${flow.hopCount !== 1 ? 's' : ''}`);
    lines.push(`  Confidence: ${flow.confidence}`);
    if (flow.sanitizations.length > 0) {
      lines.push(`  Sanitizations: ${flow.sanitizations.join(', ')}`);
    }
    return lines.join('\n');
  }

  private buildChainLabel(flow: TaintQueryResult): string {
    const parts: string[] = [];

    for (const step of flow.trace) {
      if (step.propagation === 'source') {
        parts.push(step.accessPath || step.description);
      } else if (step.propagation === 'call-arg' || step.propagation === 'return') {
        const name = step.functionName ? `${step.functionName}()` : step.description;
        if (parts[parts.length - 1] !== name) {
          parts.push(name);
        }
      } else if (step.propagation === 'sink') {
        parts.push(step.description);
      }
    }

    if (parts.length === 0) {
      parts.push(flow.sourceKind, flow.sinkCallee);
    }

    return parts.join(' → ');
  }

  private buildTraceBody(flow: TaintQueryResult): string {
    const lines: string[] = [];
    const trace = flow.trace;

    for (let i = 0; i < trace.length; i++) {
      const step = trace[i];
      const isFirst = i === 0;

      const connector = isFirst ? '┌' : '├';
      const stepLabel = this.getStepLabel(step, i);
      lines.push(`  ${connector}─ ${stepLabel} ${'─'.repeat(Math.max(0, 56 - stepLabel.length))}`);
      lines.push(`  │ ${step.filePath}:${step.line}`);
      lines.push('  │');
      lines.push(`  │   ${step.description}`);

      const marker = this.buildMarker(step);
      if (marker) {
        lines.push(`  │   ${marker}`);
      }

      lines.push('  │');
    }

    return lines.join('\n');
  }

  private getStepLabel(step: TraceStep, index: number): string {
    if (step.propagation === 'source') return 'SOURCE';
    if (step.propagation === 'sink') return 'SINK';
    const isCrossFile = index > 0;
    const crossFileTag = isCrossFile ? ' (cross-file)' : '';
    return `STEP ${index}${crossFileTag}`;
  }

  private buildMarker(step: TraceStep): string | null {
    switch (step.propagation) {
      case 'source':
        return `${'~'.repeat(8)}  ← taint enters here (${step.accessPath})`;
      case 'call-arg':
        return `${'~'.repeat(8)}  ← passed as argument`;
      case 'sink':
        return `${'~'.repeat(8)}  ← UNSANITIZED user input in ${SINK_KIND_LABELS[step.accessPath] ?? step.accessPath}`;
      default:
        return null;
    }
  }

  private severityOrder(severity: string): number {
    switch (severity) {
      case 'CRITICAL': return 0;
      case 'HIGH': return 1;
      case 'MEDIUM': return 2;
      case 'LOW': return 3;
      case 'INFO': return 4;
      default: return 5;
    }
  }
}

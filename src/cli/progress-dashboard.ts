/**
 * ProgressDashboard — Rich terminal UI for CodeDrift analysis progress.
 *
 * Renders a live-updating box-drawing dashboard showing:
 * - Current analysis phase with spinner
 * - File progress bar with speed (files/sec)
 * - Live issue count by severity
 * - Recent findings stream
 * - Elapsed time, phase history
 *
 * Uses only chalk + raw ANSI — zero extra dependencies.
 */

import chalk from 'chalk';

// ── ANSI helpers ─────────────────────────────────────────────────────────

const ESC = '\x1b[';
const HIDE_CURSOR = `${ESC}?25l`;
const SHOW_CURSOR = `${ESC}?25h`;
const CLEAR_SCREEN_DOWN = `${ESC}0J`;

function moveCursorUp(n: number): string {
  return n > 0 ? `${ESC}${n}A` : '';
}

// ── Emoji / wide-char display width ──────────────────────────────────────

/**
 * Measure the display width of a string, accounting for:
 * - ANSI escape codes (0 width)
 * - Emoji / surrogate pairs (2 columns each)
 * - Regular ASCII (1 column each)
 */
function displayWidth(str: string): number {
  // Strip ANSI escape codes
  const stripped = str.replace(/\x1b\[[0-9;]*m/g, '');
  let width = 0;
  for (let i = 0; i < stripped.length; i++) {
    const code = stripped.charCodeAt(i);
    // Surrogate pair (emoji) — counts as 2 columns, skip low surrogate
    if (code >= 0xD800 && code <= 0xDBFF) {
      width += 2;
      i++; // skip low surrogate
      continue;
    }
    // Common emoji in BMP (misc symbols, dingbats, etc.)
    if (
      (code >= 0x2600 && code <= 0x27BF) || // Misc symbols & dingbats
      (code >= 0x2B50 && code <= 0x2B55) || // Stars
      (code >= 0xFE00 && code <= 0xFE0F) || // Variation selectors (0 width)
      code === 0x200D                        // ZWJ (0 width)
    ) {
      if (code >= 0xFE00 || code === 0x200D) {
        // Zero-width joiners and variation selectors
        continue;
      }
      width += 2;
      continue;
    }
    // Box-drawing, block elements — 1 column
    width += 1;
  }
  return width;
}

// ── Types ────────────────────────────────────────────────────────────────

export type AnalysisPhase =
  | 'discovering'
  | 'loading-workspace'
  | 'building-graph'
  | 'building-summaries'
  | 'resolving-flows'
  | 'analyzing'
  | 'post-processing'
  | 'complete'
  | 'error';

export interface ProgressEvent {
  phase: AnalysisPhase;
  totalFiles?: number;
  currentFile?: number;
  filePath?: string;
  newIssue?: {
    severity: string;
    engine: string;
    message: string;
    filePath: string;
    line: number;
  };
  /** Final issue counts after post-processing (filtering, dedup, severity adjustment). */
  finalCounts?: { critical: number; high: number; medium: number; low: number; total: number };
  error?: string;
}

interface PhaseRecord {
  phase: AnalysisPhase;
  startTime: number;
  endTime?: number;
}

interface DashboardState {
  phase: AnalysisPhase;
  totalFiles: number;
  discoveredFiles: number;
  currentFile: number;
  currentFilePath: string;
  issues: { critical: number; high: number; medium: number; low: number };
  finalCounts: { critical: number; high: number; medium: number; low: number; total: number } | null;
  recentFindings: string[];
  startTime: number;
  lastRenderLines: number;
  phaseHistory: PhaseRecord[];
  filesPerSec: number;
  lastSpeedUpdate: number;
  lastSpeedFile: number;
}

// ── Constants ────────────────────────────────────────────────────────────

const SPINNER_FRAMES = ['◐', '◓', '◑', '◒'];
const BAR_FILLED = '━';
const BAR_EMPTY = '─';

const PHASE_LABELS: Record<AnalysisPhase, string> = {
  'discovering':        'Discovering files',
  'loading-workspace':  'Loading workspace',
  'building-graph':     'Building project graph',
  'building-summaries': 'Building taint summaries',
  'resolving-flows':    'Resolving multi-hop flows',
  'analyzing':          'Analyzing files',
  'post-processing':    'Post-processing results',
  'complete':           'Analysis complete',
  'error':              'Error',
};

// Using ASCII-safe labels instead of emoji to avoid width issues
const PHASE_MARKERS: Record<AnalysisPhase, string> = {
  'discovering':        chalk.cyan('[DISC]'),
  'loading-workspace':  chalk.cyan('[LOAD]'),
  'building-graph':     chalk.cyan('[GRAPH]'),
  'building-summaries': chalk.cyan('[TAINT]'),
  'resolving-flows':    chalk.cyan('[FLOW]'),
  'analyzing':          chalk.yellow('[SCAN]'),
  'post-processing':    chalk.magenta('[POST]'),
  'complete':           chalk.green('[DONE]'),
  'error':              chalk.red('[ERR]'),
};

// ── Dashboard class ──────────────────────────────────────────────────────

export class ProgressDashboard {
  private state: DashboardState;
  private spinnerIndex = 0;
  private timer: ReturnType<typeof setInterval> | null = null;
  private enabled: boolean;
  private width: number;

  constructor(enabled = true) {
    this.enabled = enabled;
    this.width = Math.min(process.stdout.columns || 72, 76);
    this.state = {
      phase: 'discovering',
      totalFiles: 0,
      discoveredFiles: 0,
      currentFile: 0,
      currentFilePath: '',
      issues: { critical: 0, high: 0, medium: 0, low: 0 },
      finalCounts: null,
      recentFindings: [],
      startTime: Date.now(),
      lastRenderLines: 0,
      phaseHistory: [{ phase: 'discovering', startTime: Date.now() }],
      filesPerSec: 0,
      lastSpeedUpdate: Date.now(),
      lastSpeedFile: 0,
    };
  }

  start(): void {
    if (!this.enabled) return;
    process.stdout.write(HIDE_CURSOR);
    this.render();
    this.timer = setInterval(() => {
      this.spinnerIndex = (this.spinnerIndex + 1) % SPINNER_FRAMES.length;
      this.updateSpeed();
      this.render();
    }, 100);
  }

  update(event: ProgressEvent): void {
    // Track phase transitions
    if (event.phase && event.phase !== this.state.phase) {
      const prev = this.state.phaseHistory[this.state.phaseHistory.length - 1];
      if (prev) prev.endTime = Date.now();
      this.state.phaseHistory.push({ phase: event.phase, startTime: Date.now() });
      this.state.phase = event.phase;
    }

    if (event.phase === 'discovering' && event.totalFiles !== undefined) {
      this.state.discoveredFiles = event.totalFiles;
    }
    if (event.totalFiles !== undefined) this.state.totalFiles = event.totalFiles;
    if (event.currentFile !== undefined) this.state.currentFile = event.currentFile;
    if (event.filePath) this.state.currentFilePath = event.filePath;

    if (event.finalCounts) {
      this.state.finalCounts = event.finalCounts;
    }

    if (event.newIssue) {
      const sev = event.newIssue.severity;
      if (sev === 'error') this.state.issues.critical++;
      else if (sev === 'warning') this.state.issues.high++;
      else this.state.issues.medium++;

      const shortPath = this.shortenPath(event.newIssue.filePath, this.width - 20);
      const sevIcon = sev === 'error' ? chalk.red('!') : sev === 'warning' ? chalk.yellow('*') : chalk.blue('-');
      const engine = chalk.dim(event.newIssue.engine.padEnd(18));
      const finding = `  ${sevIcon} ${engine} ${shortPath}:${event.newIssue.line}`;
      this.state.recentFindings.push(finding);
      if (this.state.recentFindings.length > 5) {
        this.state.recentFindings.shift();
      }
    }

    if (!this.enabled) return;
    // Don't render on every single event during fast phases — throttle
    this.render();
  }

  stop(error?: string): void {
    if (!this.enabled) return;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    const prev = this.state.phaseHistory[this.state.phaseHistory.length - 1];
    if (prev) prev.endTime = Date.now();

    if (error) {
      this.state.phase = 'error';
      this.state.phaseHistory.push({ phase: 'error', startTime: Date.now(), endTime: Date.now() });
    } else {
      this.state.phase = 'complete';
      this.state.phaseHistory.push({ phase: 'complete', startTime: Date.now(), endTime: Date.now() });
    }
    this.render();
    process.stdout.write(SHOW_CURSOR + '\n');
  }

  callback(): (event: ProgressEvent) => void {
    return (event: ProgressEvent) => this.update(event);
  }

  // ── Speed calculation ──────────────────────────────────────────────────

  private updateSpeed(): void {
    const now = Date.now();
    const elapsed = now - this.state.lastSpeedUpdate;
    if (elapsed >= 500) {
      const filesDone = this.state.currentFile - this.state.lastSpeedFile;
      this.state.filesPerSec = Math.round((filesDone / elapsed) * 1000);
      this.state.lastSpeedUpdate = now;
      this.state.lastSpeedFile = this.state.currentFile;
    }
  }

  // ── Rendering ──────────────────────────────────────────────────────────

  private render(): void {
    const lines = this.buildFrame();
    const output = lines.join('\n');

    if (this.state.lastRenderLines > 0) {
      process.stdout.write(moveCursorUp(this.state.lastRenderLines));
    }
    process.stdout.write('\r' + CLEAR_SCREEN_DOWN + output);
    this.state.lastRenderLines = lines.length;
  }

  private buildFrame(): string[] {
    const w = this.width;
    const lines: string[] = [];

    const isComplete = this.state.phase === 'complete';
    const isError = this.state.phase === 'error';
    const bc = isComplete ? chalk.green : isError ? chalk.red : chalk.cyan;

    // ── Top border ──
    lines.push(bc(`┌${'─'.repeat(w - 2)}┐`));

    // ── Title bar ──
    const title = ' CodeDrift';
    const elapsed = this.formatElapsed();
    const speed = this.state.phase === 'analyzing' && this.state.filesPerSec > 0
      ? `${this.state.filesPerSec} files/s  `
      : '';
    const rightSide = `${speed}${elapsed} `;
    lines.push(this.padRow(` ${chalk.bold.white(title)}`, chalk.dim(rightSide), bc));

    // ── Separator ──
    lines.push(bc(`├${'─'.repeat(w - 2)}┤`));

    // ── Phase + status ──
    const spinner = isComplete || isError ? ' ' : chalk.cyan(SPINNER_FRAMES[this.spinnerIndex]);
    const marker = PHASE_MARKERS[this.state.phase];
    const label = PHASE_LABELS[this.state.phase];
    const styledLabel = isComplete ? chalk.green.bold(label) : isError ? chalk.red.bold(label) : chalk.white(label);
    lines.push(this.pad(` ${spinner} ${marker} ${styledLabel}${this.getPhaseDetail()}`, bc));

    // ── Progress bar ──
    if (this.state.totalFiles > 0 &&
        (this.state.phase === 'analyzing' || this.state.phase === 'building-summaries' || isComplete)) {
      const cur = this.state.currentFile;
      const tot = this.state.totalFiles;
      const pct = Math.min(100, Math.round((cur / tot) * 100));
      const countStr = `${cur.toLocaleString()}/${tot.toLocaleString()}`;
      const pctStr = `${pct}%`;
      const meta = ` ${countStr} ${pctStr}`;
      const barMax = w - 6 - meta.length; // 2 border + 2 pad + meta
      const filled = Math.round((pct / 100) * barMax);
      const barStr = chalk.green(BAR_FILLED.repeat(filled)) + chalk.dim(BAR_EMPTY.repeat(Math.max(0, barMax - filled)));
      lines.push(this.pad(`   ${barStr}${chalk.dim(meta)}`, bc));
    }

    // ── Current file path ──
    if (this.state.currentFilePath && !isComplete && !isError) {
      const shortPath = this.shortenPath(this.state.currentFilePath, w - 10);
      lines.push(this.pad(`   ${chalk.dim('->')} ${chalk.dim(shortPath)}`, bc));
    }

    // ── Stats separator ──
    lines.push(bc(`├${'─'.repeat(w - 2)}┤`));

    // ── Issue counts row ──
    const fc = this.state.finalCounts;
    if (fc) {
      // Post-processing complete — show final filtered counts
      const rawTotal = this.state.issues.critical + this.state.issues.high + this.state.issues.medium;
      const statsLine = fc.total > 0
        ? ` ${chalk.red.bold(String(fc.critical))} critical  ${chalk.yellow.bold(String(fc.high))} high  ${chalk.blue.bold(String(fc.medium))} medium  ${chalk.dim('|')}  ${chalk.white.bold(String(fc.total))} final`
        : ` ${chalk.green('No issues after filtering')}`;
      lines.push(this.pad(statsLine, bc));
      if (rawTotal > fc.total) {
        lines.push(this.pad(chalk.dim(`   ${rawTotal - fc.total} issues filtered (auto-ignore, confidence, dedup)`), bc));
      }
    } else {
      const { critical, high, medium } = this.state.issues;
      const totalIssues = critical + high + medium;
      const statsLine = totalIssues > 0
        ? ` ${chalk.red.bold(String(critical))} critical  ${chalk.yellow.bold(String(high))} high  ${chalk.blue.bold(String(medium))} medium  ${chalk.dim('|')}  ${chalk.white.bold(String(totalIssues))} raw`
        : ` ${chalk.dim('No issues found yet')}`;
      lines.push(this.pad(statsLine, bc));
    }

    // ── Files info ──
    const discovered = this.state.discoveredFiles;
    const analyzed = this.state.phase === 'analyzing' || isComplete ? this.state.currentFile : 0;
    if (discovered > 0) {
      const excluded = discovered - this.state.totalFiles;
      let filesInfo = ` ${chalk.dim('Files:')} ${discovered.toLocaleString()} discovered`;
      if (this.state.totalFiles > 0 && this.state.totalFiles < discovered) {
        filesInfo += chalk.dim(` (${excluded.toLocaleString()} excluded)`);
      }
      if (analyzed > 0 && !isComplete) {
        filesInfo += `  ${chalk.dim('|')}  ${analyzed.toLocaleString()} analyzed`;
      }
      lines.push(this.pad(filesInfo, bc));
    }

    // ── Phase timeline ──
    if (this.state.phaseHistory.length > 1) {
      lines.push(bc(`├${'─'.repeat(w - 2)}┤`));
      const completedPhases = this.state.phaseHistory.filter(p => p.endTime && p.phase !== 'complete' && p.phase !== 'error');
      if (completedPhases.length > 0) {
        const timeline = completedPhases
          .map(p => {
            const dur = ((p.endTime! - p.startTime) / 1000).toFixed(1);
            const shortLabel = this.shortPhaseLabel(p.phase);
            return `${chalk.dim(shortLabel)} ${chalk.dim(dur + 's')}`;
          })
          .join(chalk.dim('  >  '));
        lines.push(this.pad(` ${timeline}`, bc));
      }
    }

    // ── Recent findings ──
    if (this.state.recentFindings.length > 0) {
      lines.push(bc(`├${'─'.repeat(w - 2)}┤`));
      lines.push(this.pad(` ${chalk.dim('Recent findings:')}`, bc));
      for (const finding of this.state.recentFindings) {
        lines.push(this.pad(finding, bc));
      }
    }

    // ── Bottom border ──
    lines.push(bc(`└${'─'.repeat(w - 2)}┘`));

    return lines;
  }

  // ── Layout helpers ─────────────────────────────────────────────────────

  /**
   * Pad a content string to fill the box width between left and right borders.
   */
  private pad(content: string, borderColor: (s: string) => string): string {
    const visWidth = displayWidth(content);
    const available = this.width - 2; // minus 2 border chars
    const padding = Math.max(0, available - visWidth);
    return borderColor('│') + content + ' '.repeat(padding) + borderColor('│');
  }

  /**
   * Create a row with left-aligned and right-aligned content.
   */
  private padRow(left: string, right: string, borderColor: (s: string) => string): string {
    const leftW = displayWidth(left);
    const rightW = displayWidth(right);
    const available = this.width - 2;
    const gap = Math.max(1, available - leftW - rightW);
    return borderColor('│') + left + ' '.repeat(gap) + right + borderColor('│');
  }

  private getPhaseDetail(): string {
    const s = this.state;
    switch (s.phase) {
      case 'discovering':
        return s.discoveredFiles > 0 ? chalk.dim(` — ${s.discoveredFiles.toLocaleString()} files found`) : '';
      case 'building-graph':
        return s.totalFiles > 0 ? chalk.dim(` — ${s.totalFiles.toLocaleString()} files`) : '';
      case 'building-summaries':
        return s.totalFiles > 0
          ? chalk.dim(` — ${s.currentFile}/${s.totalFiles} files`)
          : '';
      case 'analyzing':
        return s.totalFiles > 0
          ? chalk.dim(` — ${s.currentFile.toLocaleString()}/${s.totalFiles.toLocaleString()}`)
          : '';
      case 'resolving-flows':
        return chalk.dim(' — computing fixed point');
      case 'post-processing':
        return chalk.dim(' — filtering, scoring, deduplicating');
      case 'complete': {
        const total = s.finalCounts ? s.finalCounts.total : (s.issues.critical + s.issues.high + s.issues.medium);
        return chalk.dim(` — ${total} issues in ${this.formatElapsed()}`);
      }
      default:
        return '';
    }
  }

  private shortPhaseLabel(phase: AnalysisPhase): string {
    switch (phase) {
      case 'discovering': return 'disc';
      case 'loading-workspace': return 'load';
      case 'building-graph': return 'graph';
      case 'building-summaries': return 'taint';
      case 'resolving-flows': return 'flows';
      case 'analyzing': return 'scan';
      case 'post-processing': return 'post';
      default: return phase;
    }
  }

  private formatElapsed(): string {
    const ms = Date.now() - this.state.startTime;
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    const mins = Math.floor(ms / 60000);
    const secs = ((ms % 60000) / 1000).toFixed(0);
    return `${mins}m${secs}s`;
  }

  private shortenPath(filePath: string, maxLen: number): string {
    const cwd = process.cwd();
    let relative = filePath;
    if (filePath.startsWith(cwd)) {
      relative = filePath.slice(cwd.length + 1);
    }
    relative = relative.replace(/\\/g, '/');

    if (relative.length > maxLen) {
      return '...' + relative.slice(relative.length - maxLen + 3);
    }
    return relative;
  }
}

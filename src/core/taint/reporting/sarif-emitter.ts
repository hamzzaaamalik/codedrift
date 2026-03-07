/**
 * SarifEmitter — SARIF v2.1.0 output for GitHub Code Scanning, Azure DevOps,
 * and VS Code integration.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { TaintQueryResult, TraceStep } from '../query/taint-query.js';

// ---------------------------------------------------------------------------
// SARIF types (simplified, conforming to SARIF v2.1.0)
// ---------------------------------------------------------------------------

interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri?: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  properties: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: SarifLocation[];
  codeFlows?: SarifCodeFlow[];
  relatedLocations?: SarifLocation[];
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region: { startLine: number; startColumn?: number };
  };
  message?: { text: string };
}

interface SarifCodeFlow {
  threadFlows: SarifThreadFlow[];
}

interface SarifThreadFlow {
  locations: SarifThreadFlowLocation[];
}

interface SarifThreadFlowLocation {
  location: SarifLocation;
  kinds?: string[];
  nestingLevel?: number;
}

// ---------------------------------------------------------------------------
// Sink-kind -> rule mappings
// ---------------------------------------------------------------------------

const SINK_RULE_MAP: Record<string, { id: string; name: string; short: string; full: string; tags: string[] }> = {
  'db-query': { id: 'taint/sql-injection', name: 'SQL Injection', short: 'User input flows into a database query without sanitization', full: 'Tainted data from an external source reaches a database query API without proper parameterization or escaping.', tags: ['security', 'sql-injection', 'cwe-89'] },
  'db-mutation': { id: 'taint/sql-injection', name: 'SQL Injection', short: 'User input flows into a database mutation without sanitization', full: 'Tainted data from an external source reaches a database mutation API without proper parameterization or escaping.', tags: ['security', 'sql-injection', 'cwe-89'] },
  'command-execution': { id: 'taint/command-injection', name: 'Command Injection', short: 'User input flows into a shell command without sanitization', full: 'Tainted data reaches a command execution API enabling arbitrary command execution.', tags: ['security', 'command-injection', 'cwe-78'] },
  'file-read': { id: 'taint/path-traversal', name: 'Path Traversal', short: 'User input flows into a file read operation without validation', full: 'Tainted data reaches a file-system read API without path validation.', tags: ['security', 'path-traversal', 'cwe-22'] },
  'file-write': { id: 'taint/path-traversal', name: 'Path Traversal', short: 'User input flows into a file write operation without validation', full: 'Tainted data reaches a file-system write API without path validation.', tags: ['security', 'path-traversal', 'cwe-22'] },
  'html-output': { id: 'taint/xss', name: 'Cross-Site Scripting (XSS)', short: 'User input flows into HTML output without escaping', full: 'Tainted data is rendered as HTML without proper escaping.', tags: ['security', 'xss', 'cwe-79'] },
  'template-render': { id: 'taint/xss', name: 'Cross-Site Scripting (XSS)', short: 'User input flows into a template render without escaping', full: 'Tainted data is rendered through a template engine without proper escaping.', tags: ['security', 'xss', 'cwe-79'] },
  'redirect': { id: 'taint/open-redirect', name: 'Open Redirect', short: 'User input controls a redirect URL without validation', full: 'Tainted data controls a redirect destination without URL validation.', tags: ['security', 'open-redirect', 'cwe-601'] },
  'url-construction': { id: 'taint/ssrf', name: 'SSRF', short: 'User input flows into a URL construction without validation', full: 'Tainted data is used to construct a URL without host validation.', tags: ['security', 'ssrf', 'cwe-918'] },
  'eval': { id: 'taint/code-injection', name: 'Code Injection', short: 'User input flows into eval() or equivalent', full: 'Tainted data reaches eval() or a similar dynamic code execution API.', tags: ['security', 'code-injection', 'cwe-94'] },
  'dynamic-import': { id: 'taint/code-injection', name: 'Code Injection', short: 'User input controls a dynamic import specifier', full: 'Tainted data controls a dynamic import() specifier.', tags: ['security', 'code-injection', 'cwe-94'] },
  'http-request': { id: 'taint/ssrf', name: 'SSRF', short: 'User input flows into an HTTP request URL without validation', full: 'Tainted data is used in an outbound HTTP request without host validation.', tags: ['security', 'ssrf', 'cwe-918'] },
  'log-output': { id: 'taint/log-injection', name: 'Log Injection', short: 'User input flows into log output without sanitization', full: 'Tainted data is written to logs without sanitization.', tags: ['security', 'log-injection', 'cwe-117'] },
};

const DEFAULT_RULE = { id: 'taint/unknown', name: 'Taint Flow', short: 'User input flows to a potentially dangerous sink', full: 'Tainted data from an external source reaches a sink.', tags: ['security'] };

// ---------------------------------------------------------------------------
// SarifEmitter
// ---------------------------------------------------------------------------

export class SarifEmitter {
  emit(flows: TaintQueryResult[], projectRoot: string): SarifLog {
    const rules = this.generateRules(flows);
    const results: SarifResult[] = flows.map(flow => this.flowToResult(flow, projectRoot));

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'CodeDrift',
            version: '1.2.10',
            informationUri: 'https://github.com/codedrift/codedrift',
            rules,
          },
        },
        results,
      }],
    };
  }

  writeToFile(flows: TaintQueryResult[], projectRoot: string, outputPath: string): void {
    const sarif = this.emit(flows, projectRoot);
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
  }

  flowToResult(flow: TaintQueryResult, projectRoot: string): SarifResult {
    const rule = SINK_RULE_MAP[flow.sinkKind] ?? DEFAULT_RULE;
    const level = this.mapLevel(flow);

    // Primary location = the sink (last trace step or dedicated sink step)
    const sinkStep = flow.trace.find(s => s.propagation === 'sink') ?? flow.trace[flow.trace.length - 1];
    const primaryLocation = this.stepToLocation(sinkStep, projectRoot);

    const message = flow.isSanitized
      ? `Tainted data from ${flow.sourceKind} reaches ${flow.sinkCallee} (sanitized via ${flow.sanitizations.join(', ')})`
      : `Tainted data from ${flow.sourceKind} reaches ${flow.sinkCallee} unsanitized`;

    // Code flow: one threadFlow with all trace steps
    const threadFlowLocations: SarifThreadFlowLocation[] = flow.trace.map((step, index) => ({
      location: this.stepToLocation(step, projectRoot),
      kinds: this.stepKinds(step),
      nestingLevel: this.nestingLevel(index, flow.trace),
    }));

    // Related locations = source steps
    const relatedLocations: SarifLocation[] = flow.trace
      .filter(s => s.propagation === 'source')
      .map(s => this.stepToLocation(s, projectRoot));

    const result: SarifResult = {
      ruleId: rule.id,
      level,
      message: { text: message },
      locations: [primaryLocation],
      codeFlows: [{ threadFlows: [{ locations: threadFlowLocations }] }],
    };

    if (relatedLocations.length > 0) {
      result.relatedLocations = relatedLocations;
    }

    return result;
  }

  generateRules(flows: TaintQueryResult[]): SarifRule[] {
    const seen = new Map<string, SarifRule>();

    for (const flow of flows) {
      const ruleDef = SINK_RULE_MAP[flow.sinkKind] ?? DEFAULT_RULE;
      if (seen.has(ruleDef.id)) continue;

      seen.set(ruleDef.id, {
        id: ruleDef.id,
        name: ruleDef.name,
        shortDescription: { text: ruleDef.short },
        fullDescription: { text: ruleDef.full },
        defaultConfiguration: { level: this.defaultLevel(flow.sinkKind) },
        properties: { tags: ruleDef.tags },
      });
    }

    return Array.from(seen.values());
  }

  // -----------------------------------------------------------------------
  // Private helpers
  // -----------------------------------------------------------------------

  private stepToLocation(step: TraceStep, projectRoot: string): SarifLocation {
    const relativePath = path.relative(projectRoot, step.filePath).replace(/\\/g, '/');
    const location: SarifLocation = {
      physicalLocation: {
        artifactLocation: { uri: relativePath },
        region: { startLine: step.line },
      },
    };
    if (step.description) {
      location.message = { text: step.description };
    }
    return location;
  }

  private stepKinds(step: TraceStep): string[] {
    switch (step.propagation) {
      case 'source': return ['source'];
      case 'sink': return ['sink'];
      case 'call-arg': return ['call'];
      case 'return': return ['callReturn'];
      default: return ['pass'];
    }
  }

  private nestingLevel(index: number, trace: TraceStep[]): number {
    let level = 0;
    for (let i = 0; i < index; i++) {
      if (trace[i].propagation === 'call-arg') level++;
      if (trace[i].propagation === 'return') level--;
    }
    return Math.max(0, level);
  }

  private mapLevel(flow: TaintQueryResult): 'error' | 'warning' | 'note' {
    if (flow.isSanitized) return 'note';
    switch (flow.sinkKind) {
      case 'db-query': case 'db-mutation': case 'command-execution':
      case 'eval': case 'dynamic-import': case 'file-read': case 'file-write':
      case 'html-output': case 'template-render': case 'http-request':
      case 'url-construction':
        return 'error';
      default:
        return 'warning';
    }
  }

  private defaultLevel(sinkKind: string): 'error' | 'warning' | 'note' {
    switch (sinkKind) {
      case 'db-query': case 'db-mutation': case 'command-execution':
      case 'eval': case 'dynamic-import': case 'file-read': case 'file-write':
      case 'html-output': case 'template-render': case 'http-request':
      case 'url-construction':
        return 'error';
      default:
        return 'warning';
    }
  }
}

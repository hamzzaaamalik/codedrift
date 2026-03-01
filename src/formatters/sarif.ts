/**
 * SARIF 2.1.0 Formatter
 * Generates Static Analysis Results Interchange Format output
 * Compatible with GitHub Code Scanning and other SARIF-aware tooling
 */

import * as path from 'path';
import * as fs from 'fs';
import type { AnalysisResult, CodeDriftConfig, Issue } from '../types/index.js';
import { getEngineName } from './types.js';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  helpUri: string;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId: string;
    };
    region: {
      startLine: number;
      startColumn: number;
    };
  };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: SarifLocation[];
  fixes?: Array<{ description: { text: string } }>;
}

/**
 * Map CodeDrift severity to SARIF level
 */
function toSarifLevel(severity: Issue['severity']): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
      return 'note';
  }
}

/**
 * Convert an absolute file path to a SARIF-compatible URI (relative, forward slashes)
 */
function toSarifUri(filePath: string, cwd: string): string {
  const rel = path.relative(cwd, filePath);
  return rel.replace(/\\/g, '/');
}

/**
 * Build the SARIF rules array from unique engines in the result
 */
function buildRules(issues: Issue[]): SarifRule[] {
  const seen = new Set<string>();
  const rules: SarifRule[] = [];

  for (const issue of issues) {
    if (seen.has(issue.engine)) continue;
    seen.add(issue.engine);

    const level = toSarifLevel(issue.severity);
    rules.push({
      id: issue.engine,
      name: getEngineName(issue.engine).replace(/\s+/g, ''),
      shortDescription: { text: getEngineName(issue.engine) },
      defaultConfiguration: { level },
      helpUri: 'https://github.com/hamzzaaamalik/codedrift',
    });
  }

  return rules;
}

/**
 * Format analysis result as SARIF 2.1.0 JSON
 */
export function formatSARIF(result: AnalysisResult, _config: CodeDriftConfig): string {
  const cwd = process.cwd();

  // Read version from package.json (same pattern as cli.ts)
  let version = '0.0.0';
  try {
    const pkgPath = path.join(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Z]:)/, '$1')), '../../package.json');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    version = pkg.version || version;
  } catch {
    // ignore — version will stay as fallback
  }

  const rules = buildRules(result.issues);

  const sarifResults: SarifResult[] = result.issues.map((issue) => {
    const sarifResult: SarifResult = {
      ruleId: issue.engine,
      level: toSarifLevel(issue.severity),
      message: { text: issue.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: toSarifUri(issue.filePath, cwd),
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: issue.location.line,
              startColumn: issue.location.column,
            },
          },
        },
      ],
    };

    if (issue.suggestion) {
      sarifResult.fixes = [{ description: { text: issue.suggestion } }];
    }

    return sarifResult;
  });

  const sarif = {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeDrift',
            version,
            informationUri: 'https://github.com/hamzzaaamalik/codedrift',
            rules,
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

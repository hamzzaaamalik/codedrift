/**
 * Taint Specification Parser
 *
 * Parses YAML/JSON taint rule files (.codedrift-taint.yml / .codedrift-taint.json)
 * into structured TaintSpec objects. Provides pattern parsing and AST node matching.
 *
 * Implements a minimal YAML subset parser (no external dependency) covering:
 * - Key-value pairs, nested objects (indentation-based), lists (- prefix)
 * - Quoted/unquoted strings, numbers, booleans, comments (#)
 * - Multi-line strings (| and >)
 *
 * For complex YAML features, use the JSON fallback format.
 */

import * as ts from 'typescript';
import * as fs from 'fs';
import * as path from 'path';
import type {
  ParsedPattern,
  PatternArg,
  TaintPattern,
  TaintSourceSpec,
  TaintSinkSpec,
  TaintSanitizerSpec,
  TaintPropagatorSpec,
  TaintRule,
  TaintRuleSeverity,
  TaintSpec,
  TaintSpecLoadResult,
} from './spec-types.js';

// ─── Minimal YAML Parser ─────────────────────────────────────────────────────

interface YamlLine {
  indent: number;
  raw: string;
  trimmed: string;
  lineNumber: number;
}

/**
 * Minimal YAML parser supporting the subset needed for taint spec files.
 * Falls back to JSON parsing for .json files.
 */
function parseMinimalYaml(content: string): unknown {
  const lines = content.split(/\r?\n/);
  const parsed: YamlLine[] = [];

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const trimmed = raw.replace(/\s+$/, ''); // rtrim
    // Skip empty lines and comments
    if (trimmed.length === 0 || /^\s*#/.test(trimmed)) {
      // But keep blank lines — we need them for multi-line detection
      parsed.push({ indent: 0, raw, trimmed: '', lineNumber: i + 1 });
      continue;
    }
    const indent = raw.search(/\S/);
    parsed.push({ indent: indent >= 0 ? indent : 0, raw, trimmed: trimmed.trimStart(), lineNumber: i + 1 });
  }

  return parseYamlNode(parsed, 0, parsed.length, 0);
}

function parseYamlNode(
  lines: YamlLine[],
  start: number,
  end: number,
  baseIndent: number,
): unknown {
  // Skip blank lines at the start
  while (start < end && lines[start].trimmed === '') start++;
  if (start >= end) return null;

  const firstLine = lines[start];

  // Check if this is a list
  if (firstLine.trimmed.startsWith('- ') || firstLine.trimmed === '-') {
    return parseYamlList(lines, start, end, baseIndent);
  }

  // Otherwise it's an object (or a scalar on a single line)
  if (firstLine.trimmed.includes(':')) {
    return parseYamlObject(lines, start, end, baseIndent);
  }

  // Single scalar
  return parseYamlScalar(firstLine.trimmed);
}

function parseYamlList(
  lines: YamlLine[],
  start: number,
  end: number,
  baseIndent: number,
): unknown[] {
  const result: unknown[] = [];
  let i = start;

  while (i < end) {
    // Skip blank lines
    if (lines[i].trimmed === '') { i++; continue; }
    // If indentation is less than base, we've exited this list
    if (lines[i].indent < baseIndent) break;

    if (!lines[i].trimmed.startsWith('- ') && lines[i].trimmed !== '-') {
      break;
    }

    const listItemIndent = lines[i].indent;
    const afterDash = lines[i].trimmed.substring(2).trim(); // content after "- "

    // Find extent of this list item (lines indented deeper than the dash)
    const childIndent = listItemIndent + 2;
    let itemEnd = i + 1;
    while (itemEnd < end) {
      if (lines[itemEnd].trimmed === '') { itemEnd++; continue; }
      if (lines[itemEnd].indent < childIndent &&
          !(lines[itemEnd].indent === listItemIndent && lines[itemEnd].trimmed.startsWith('- '))) {
        break;
      }
      if (lines[itemEnd].indent === listItemIndent && lines[itemEnd].trimmed.startsWith('- ')) {
        break; // Next list item at same level
      }
      itemEnd++;
    }

    if (afterDash === '' || afterDash === undefined) {
      // Dash alone — child content is indented below
      result.push(parseYamlNode(lines, i + 1, itemEnd, childIndent));
    } else if (afterDash.includes(':')) {
      // Inline object start: "- key: value" possibly with continuation
      // Reconstruct as if the dash wasn't there
      const syntheticLines: YamlLine[] = [
        { indent: childIndent, raw: ' '.repeat(childIndent) + afterDash, trimmed: afterDash, lineNumber: lines[i].lineNumber },
      ];
      for (let j = i + 1; j < itemEnd; j++) {
        syntheticLines.push(lines[j]);
      }
      result.push(parseYamlNode(syntheticLines, 0, syntheticLines.length, childIndent));
    } else {
      // Simple scalar value
      result.push(parseYamlScalar(afterDash));
    }

    i = itemEnd;
  }

  return result;
}

function parseYamlObject(
  lines: YamlLine[],
  start: number,
  end: number,
  baseIndent: number,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  let i = start;

  while (i < end) {
    if (lines[i].trimmed === '') { i++; continue; }
    if (lines[i].indent < baseIndent) break;

    const line = lines[i].trimmed;
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) { i++; continue; }

    const key = line.substring(0, colonIndex).trim();
    const afterColon = line.substring(colonIndex + 1).trim();

    // Determine the child indent for nested content
    const currentIndent = lines[i].indent;
    let childEnd = i + 1;
    while (childEnd < end) {
      if (lines[childEnd].trimmed === '') { childEnd++; continue; }
      if (lines[childEnd].indent <= currentIndent) break;
      childEnd++;
    }

    if (afterColon === '' || afterColon === undefined) {
      // Value is on subsequent indented lines
      if (childEnd > i + 1) {
        // Find the indent of the first non-blank child line
        let firstChildIdx = i + 1;
        while (firstChildIdx < childEnd && lines[firstChildIdx].trimmed === '') firstChildIdx++;
        const childIndent = firstChildIdx < childEnd ? lines[firstChildIdx].indent : currentIndent + 2;
        result[key] = parseYamlNode(lines, i + 1, childEnd, childIndent);
      } else {
        result[key] = null;
      }
    } else if (afterColon === '|' || afterColon === '>') {
      // Multi-line string
      const fold = afterColon === '>';
      const blockLines: string[] = [];
      let j = i + 1;
      const blockIndent = currentIndent + 2;
      while (j < end) {
        if (lines[j].trimmed === '' && j + 1 < end) {
          blockLines.push('');
          j++;
          continue;
        }
        if (lines[j].trimmed !== '' && lines[j].indent < blockIndent) break;
        // Remove the block indentation prefix
        const content = lines[j].raw.length > blockIndent
          ? lines[j].raw.substring(blockIndent)
          : lines[j].trimmed;
        blockLines.push(content);
        j++;
      }
      if (fold) {
        result[key] = blockLines.join(' ').replace(/\s+$/, '');
      } else {
        result[key] = blockLines.join('\n').replace(/\n+$/, '');
      }
      childEnd = j;
    } else {
      // Inline value
      result[key] = parseYamlScalar(afterColon);
    }

    i = childEnd;
  }

  return result;
}

type YamlScalar = string | number | boolean | null;
type YamlValue = YamlScalar | YamlScalar[];

function parseYamlScalar(value: string): YamlValue {
  if (value === 'null' || value === '~') return null;
  if (value === 'true') return true;
  if (value === 'false') return false;

  // Strip inline comments: only if there's a space before # and it's not inside quotes
  if (!value.startsWith('"') && !value.startsWith("'")) {
    const commentIdx = value.indexOf(' #');
    if (commentIdx >= 0) {
      value = value.substring(0, commentIdx).trim();
    }
  }

  // Quoted strings
  if ((value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }

  // Numbers
  if (/^-?\d+$/.test(value)) return parseInt(value, 10);
  if (/^-?\d+\.\d+$/.test(value)) return parseFloat(value);

  // Inline list: [a, b, c]
  if (value.startsWith('[') && value.endsWith(']')) {
    const inner = value.slice(1, -1).trim();
    if (inner === '') return [] as YamlScalar[];
    return inner.split(',').map(s => {
      const v = parseYamlScalar(s.trim());
      return Array.isArray(v) ? String(v) : v;
    }) as YamlScalar[];
  }

  return value;
}

// ─── Pattern Parser ──────────────────────────────────────────────────────────

/** Extract all metavariable names (tokens starting with $) from a string */
function extractMetavars(str: string): string[] {
  const matches = str.match(/\$\w+/g);
  return matches ? [...new Set(matches)] : [];
}

/**
 * Parse a pattern string into a ParsedPattern.
 *
 * Pattern syntax:
 * - `req.body` — property access on identifier
 * - `req.body.**` — any nested field of req.body (** = wildcard depth)
 * - `$obj.query($sql)` — call with metavar object and named arg
 * - `$obj.query($sql, ...)` — call with at least one arg, rest ignored
 * - `parseInt($x)` — function call with metavar arg
 * - `@Body() $param` — decorator pattern
 * - `$x = $tainted` — assignment pattern
 */
function parsePatternImpl(pattern: string): ParsedPattern {
  const metavars = extractMetavars(pattern);
  const hasMetavars = metavars.length > 0;

  // Assignment pattern: "$x = $tainted"
  const assignMatch = pattern.match(/^(\$?\w+)\s*=\s*(\$?\w+.*)$/);
  if (assignMatch && !pattern.includes('(')) {
    return {
      kind: 'assignment',
      object: assignMatch[1],
      properties: [assignMatch[2]],
      hasMetavars,
      metavars,
    };
  }

  // Decorator pattern: "@Body() $param"
  if (pattern.startsWith('@')) {
    const decoMatch = pattern.match(/^@(\w+)\(([^)]*)\)\s*(\$?\w+)?$/);
    if (decoMatch) {
      const args = decoMatch[2]
        ? decoMatch[2].split(',').map(a => {
            const trimmed = a.trim();
            return { name: trimmed, isRest: trimmed === '...' } as PatternArg;
          })
        : [];
      return {
        kind: 'decorator',
        method: decoMatch[1],
        args: args.length > 0 ? args : undefined,
        properties: decoMatch[3] ? [decoMatch[3]] : undefined,
        hasMetavars,
        metavars,
      };
    }
  }

  // Call expression: "func($arg)" or "obj.method($arg, ...)"
  const callMatch = pattern.match(/^(.+?)\(([^)]*)\)\s*$/);
  if (callMatch) {
    const calleePart = callMatch[1];
    const argsPart = callMatch[2].trim();
    const args: PatternArg[] = [];

    if (argsPart.length > 0) {
      for (const raw of argsPart.split(',')) {
        const trimmed = raw.trim();
        if (trimmed === '...') {
          args.push({ name: '...', isRest: true });
        } else {
          args.push({ name: trimmed, isRest: false });
        }
      }
    }

    // Split callee on '.' to separate object and method
    const calleeParts = splitDotChain(calleePart);
    if (calleeParts.length === 1) {
      // Simple function call: parseInt($x)
      return {
        kind: 'call-expression',
        method: calleeParts[0],
        args,
        hasMetavars,
        metavars,
      };
    }

    // Object method call: $obj.query($sql)
    const method = calleeParts[calleeParts.length - 1];
    const objectPart = calleeParts[0];
    const midProperties = calleeParts.slice(1, -1);

    return {
      kind: 'call-expression',
      object: objectPart,
      properties: midProperties.length > 0 ? midProperties : undefined,
      method,
      args,
      hasMetavars,
      metavars,
    };
  }

  // Property access or identifier: "req.body.**" or "myVar"
  const parts = splitDotChain(pattern);
  if (parts.length === 1) {
    return {
      kind: 'identifier',
      object: parts[0],
      hasMetavars,
      metavars,
    };
  }

  return {
    kind: 'property-access',
    object: parts[0],
    properties: parts.slice(1),
    hasMetavars,
    metavars,
  };
}

/** Split a string on '.' but preserve "**" as a single token */
function splitDotChain(str: string): string[] {
  return str.split('.').reduce<string[]>((acc, part) => {
    if (part === '') {
      // Consecutive dots — shouldn't happen in valid patterns, skip
      return acc;
    }
    acc.push(part);
    return acc;
  }, []);
}

// ─── Spec Validation & Parsing ───────────────────────────────────────────────

const VALID_SEVERITIES = new Set<string>(['critical', 'high', 'medium', 'low', 'info']);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asStringArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
  return [];
}

function asNumberArray(v: unknown): number[] {
  if (Array.isArray(v)) return v.filter((x): x is number => typeof x === 'number');
  return [];
}

function buildPattern(raw: unknown): TaintPattern | null {
  if (typeof raw === 'string') {
    const parsed = parsePatternImpl(raw);
    return { pattern: raw, parsed };
  }
  if (isRecord(raw) && typeof raw['pattern'] === 'string') {
    const parsed = parsePatternImpl(raw['pattern'] as string);
    return { pattern: raw['pattern'] as string, parsed };
  }
  return null;
}

function parseSourceSpec(raw: unknown): TaintSourceSpec | null {
  if (!isRecord(raw)) return null;
  const pat = buildPattern(raw['pattern']);
  if (!pat) return null;
  return {
    pattern: pat,
    kind: typeof raw['kind'] === 'string' ? raw['kind'] : 'user-input',
    note: typeof raw['note'] === 'string' ? raw['note'] : undefined,
  };
}

function parseSinkSpec(raw: unknown): TaintSinkSpec | null {
  if (!isRecord(raw)) return null;
  const pat = buildPattern(raw['pattern']);
  if (!pat) return null;
  let taintedArgs: number[] = [];
  if (Array.isArray(raw['taintedArgs'])) {
    taintedArgs = asNumberArray(raw['taintedArgs']);
  } else if (typeof raw['taintedArgs'] === 'number') {
    taintedArgs = [raw['taintedArgs']];
  } else if (raw['tainted_args'] !== undefined) {
    // snake_case fallback
    taintedArgs = Array.isArray(raw['tainted_args'])
      ? asNumberArray(raw['tainted_args'])
      : typeof raw['tainted_args'] === 'number' ? [raw['tainted_args']] : [];
  }
  return {
    pattern: pat,
    taintedArgs,
    condition: typeof raw['condition'] === 'string' ? raw['condition'] : undefined,
    note: typeof raw['note'] === 'string' ? raw['note'] : undefined,
  };
}

function parseSanitizerSpec(raw: unknown): TaintSanitizerSpec | null {
  if (!isRecord(raw)) return null;
  const pat = buildPattern(raw['pattern']);
  if (!pat) return null;
  return {
    pattern: pat,
    sanitizationKind: typeof raw['sanitizationKind'] === 'string'
      ? raw['sanitizationKind']
      : typeof raw['sanitization_kind'] === 'string'
        ? raw['sanitization_kind']
        : undefined,
    condition: typeof raw['condition'] === 'string' ? raw['condition'] : undefined,
    note: typeof raw['note'] === 'string' ? raw['note'] : undefined,
  };
}

function parsePropagatorSpec(raw: unknown): TaintPropagatorSpec | null {
  if (!isRecord(raw)) return null;
  const pat = buildPattern(raw['pattern']);
  if (!pat) return null;
  return {
    pattern: pat,
    from: typeof raw['from'] === 'string' ? raw['from'] : '$this',
    to: typeof raw['to'] === 'string' ? raw['to'] : 'return',
    note: typeof raw['note'] === 'string' ? raw['note'] : undefined,
  };
}

function parseSpecArray<T>(
  arr: unknown,
  parseFn: (item: unknown) => T | null,
): T[] {
  if (!Array.isArray(arr)) return [];
  const result: T[] = [];
  for (const item of arr) {
    const parsed = parseFn(item);
    if (parsed) result.push(parsed);
  }
  return result;
}

// ─── TaintSpecParser ─────────────────────────────────────────────────────────

export class TaintSpecParser {
  /**
   * Parse a pattern string into a ParsedPattern.
   */
  parsePattern(pattern: string): ParsedPattern {
    return parsePatternImpl(pattern);
  }

  /**
   * Load a taint spec from a YAML string.
   * Validates structure, parses all patterns.
   */
  parseYaml(yamlContent: string, fileName: string): TaintSpec {
    let raw: unknown;

    // Try JSON first (also handles .json files)
    const trimmed = yamlContent.trim();
    if (trimmed.startsWith('{')) {
      try {
        raw = JSON.parse(trimmed);
      } catch {
        throw new Error(`Failed to parse JSON in ${fileName}`);
      }
    } else {
      // Parse as YAML subset
      try {
        raw = parseMinimalYaml(yamlContent);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`Failed to parse YAML in ${fileName}: ${msg}`);
      }
    }

    if (!isRecord(raw)) {
      throw new Error(`Taint spec ${fileName} must be an object at top level`);
    }

    const version = typeof raw['version'] === 'string' ? raw['version'] : '1';

    // Parse global definitions
    const globalSources = parseSpecArray(raw['globalSources'] ?? raw['global_sources'], parseSourceSpec);
    const globalSanitizers = parseSpecArray(raw['globalSanitizers'] ?? raw['global_sanitizers'], parseSanitizerSpec);
    const globalPropagators = parseSpecArray(raw['globalPropagators'] ?? raw['global_propagators'], parsePropagatorSpec);

    // Parse rules
    const rules: TaintRule[] = [];
    const rawRules = raw['rules'];
    if (Array.isArray(rawRules)) {
      for (const rawRule of rawRules) {
        if (!isRecord(rawRule)) continue;

        const id = typeof rawRule['id'] === 'string' ? rawRule['id'] : `rule-${rules.length}`;
        const message = typeof rawRule['message'] === 'string'
          ? rawRule['message']
          : `Taint rule ${id}`;

        let severity: TaintRuleSeverity = 'high';
        if (typeof rawRule['severity'] === 'string' && VALID_SEVERITIES.has(rawRule['severity'])) {
          severity = rawRule['severity'] as TaintRuleSeverity;
        }

        const enabled = rawRule['enabled'] !== false;

        const rule: TaintRule = {
          id,
          message,
          severity,
          enabled,
          sources: parseSpecArray(rawRule['sources'], parseSourceSpec),
          sinks: parseSpecArray(rawRule['sinks'], parseSinkSpec),
          sanitizers: parseSpecArray(rawRule['sanitizers'], parseSanitizerSpec),
          propagators: parseSpecArray(rawRule['propagators'], parsePropagatorSpec),
          tags: asStringArray(rawRule['tags']),
          cwe: asNumberArray(rawRule['cwe']),
          owasp: asStringArray(rawRule['owasp']),
        };

        rules.push(rule);
      }
    }

    return {
      version,
      globalSources: globalSources.length > 0 ? globalSources : undefined,
      globalSanitizers: globalSanitizers.length > 0 ? globalSanitizers : undefined,
      globalPropagators: globalPropagators.length > 0 ? globalPropagators : undefined,
      rules,
    };
  }

  /**
   * Load spec files from disk.
   * Looks for:
   * - .codedrift-taint.yml in project root
   * - .codedrift-taint.yaml
   * - .codedrift-taint.json
   * - Any files in .codedrift/taint-rules/*.yml, *.yaml, *.json
   */
  loadSpecs(projectRoot: string): TaintSpecLoadResult {
    const specs: TaintSpec[] = [];
    const errors: { file: string; message: string }[] = [];

    // Candidate spec file paths (in priority order)
    const candidates: string[] = [
      path.join(projectRoot, '.codedrift-taint.yml'),
      path.join(projectRoot, '.codedrift-taint.yaml'),
      path.join(projectRoot, '.codedrift-taint.json'),
    ];

    // Check for rules directory
    const rulesDir = path.join(projectRoot, '.codedrift', 'taint-rules');
    if (fs.existsSync(rulesDir)) {
      try {
        const entries = fs.readdirSync(rulesDir);
        for (const entry of entries) {
          if (/\.(ya?ml|json)$/i.test(entry)) {
            candidates.push(path.join(rulesDir, entry));
          }
        }
      } catch {
        errors.push({ file: rulesDir, message: 'Failed to read taint-rules directory' });
      }
    }

    // Load each file
    for (const filePath of candidates) {
      if (!fs.existsSync(filePath)) continue;
      try {
        const content = fs.readFileSync(filePath, 'utf-8');
        const spec = this.parseYaml(content, filePath);
        specs.push(spec);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        errors.push({ file: filePath, message: msg });
      }
    }

    return this.mergeSpecs(specs, errors);
  }

  /**
   * Merge multiple specs into a unified view.
   * Later specs override earlier ones (by rule ID).
   * Global sources/sinks/sanitizers are cumulative.
   */
  mergeSpecs(specs: TaintSpec[], existingErrors?: { file: string; message: string }[]): TaintSpecLoadResult {
    const ruleMap = new Map<string, TaintRule>();
    const allSources: TaintSourceSpec[] = [];
    const allSinks: TaintSinkSpec[] = [];
    const allSanitizers: TaintSanitizerSpec[] = [];
    const allPropagators: TaintPropagatorSpec[] = [];

    for (const spec of specs) {
      // Accumulate globals
      if (spec.globalSources) allSources.push(...spec.globalSources);
      if (spec.globalSanitizers) allSanitizers.push(...spec.globalSanitizers);
      if (spec.globalPropagators) allPropagators.push(...spec.globalPropagators);

      // Merge rules (later overrides earlier by ID)
      for (const rule of spec.rules) {
        ruleMap.set(rule.id, rule);
      }
    }

    const allRules = [...ruleMap.values()];

    // Collect per-rule sources/sinks/sanitizers/propagators
    for (const rule of allRules) {
      if (!rule.enabled) continue;
      allSources.push(...rule.sources);
      allSinks.push(...rule.sinks);
      allSanitizers.push(...rule.sanitizers);
      allPropagators.push(...rule.propagators);
    }

    return {
      specs,
      allRules,
      allSources,
      allSinks,
      allSanitizers,
      allPropagators,
      errors: existingErrors ?? [],
    };
  }

  // ─── AST Node Matching ──────────────────────────────────────────────────

  /**
   * Match an AST node against a parsed pattern.
   * Returns the metavariable bindings if matched, null if no match.
   */
  matchNode(node: ts.Node, pattern: ParsedPattern): Map<string, ts.Node> | null {
    const bindings = new Map<string, ts.Node>();

    switch (pattern.kind) {
      case 'identifier':
        return this._matchIdentifier(node, pattern, bindings);

      case 'property-access':
        return this._matchPropertyAccess(node, pattern, bindings);

      case 'call-expression':
        return this._matchCallExpression(node, pattern, bindings);

      case 'assignment':
        return this._matchAssignment(node, pattern, bindings);

      case 'decorator':
        return this._matchDecorator(node, pattern, bindings);

      default:
        return null;
    }
  }

  /**
   * Check if a call expression matches any sink pattern.
   */
  matchSink(node: ts.CallExpression, rules: TaintRule[]): {
    rule: TaintRule;
    sink: TaintSinkSpec;
    bindings: Map<string, ts.Node>;
  } | null {
    for (const rule of rules) {
      if (!rule.enabled) continue;
      for (const sink of rule.sinks) {
        if (!sink.pattern.parsed) continue;
        const bindings = this.matchNode(node, sink.pattern.parsed);
        if (bindings) {
          return { rule, sink, bindings };
        }
      }
    }
    return null;
  }

  /**
   * Check if a node matches any source pattern.
   */
  matchSource(node: ts.Node, rules: TaintRule[]): {
    rule: TaintRule;
    source: TaintSourceSpec;
    bindings: Map<string, ts.Node>;
  } | null {
    for (const rule of rules) {
      if (!rule.enabled) continue;
      for (const source of rule.sources) {
        if (!source.pattern.parsed) continue;
        const bindings = this.matchNode(node, source.pattern.parsed);
        if (bindings) {
          return { rule, source, bindings };
        }
      }
    }
    return null;
  }

  /**
   * Check if a node matches any sanitizer pattern.
   */
  matchSanitizer(node: ts.Node, rules: TaintRule[]): {
    rule: TaintRule;
    sanitizer: TaintSanitizerSpec;
    bindings: Map<string, ts.Node>;
  } | null {
    for (const rule of rules) {
      if (!rule.enabled) continue;
      for (const sanitizer of rule.sanitizers) {
        if (!sanitizer.pattern.parsed) continue;
        const bindings = this.matchNode(node, sanitizer.pattern.parsed);
        if (bindings) {
          return { rule, sanitizer, bindings };
        }
      }
    }
    return null;
  }

  // ─── Private Matching Helpers ───────────────────────────────────────────

  private _matchIdentifier(
    node: ts.Node,
    pattern: ParsedPattern,
    bindings: Map<string, ts.Node>,
  ): Map<string, ts.Node> | null {
    if (!pattern.object) return null;

    if (pattern.object.startsWith('$')) {
      // Metavariable matches any identifier
      if (ts.isIdentifier(node)) {
        bindings.set(pattern.object, node);
        return bindings;
      }
      return null;
    }

    // Literal identifier match
    if (ts.isIdentifier(node) && node.text === pattern.object) {
      return bindings;
    }
    return null;
  }

  private _matchPropertyAccess(
    node: ts.Node,
    pattern: ParsedPattern,
    bindings: Map<string, ts.Node>,
  ): Map<string, ts.Node> | null {
    if (!pattern.object || !pattern.properties || pattern.properties.length === 0) return null;

    // Flatten the node's property access chain
    const chain = this._flattenPropertyAccess(node);
    if (!chain) return null;

    const { root, properties: nodeProps } = chain;

    // Match root object
    if (!this._matchObjectPart(root, pattern.object, bindings)) return null;

    // Match properties
    return this._matchPropertyChain(nodeProps, pattern.properties, bindings) ? bindings : null;
  }

  private _matchCallExpression(
    node: ts.Node,
    pattern: ParsedPattern,
    bindings: Map<string, ts.Node>,
  ): Map<string, ts.Node> | null {
    if (!ts.isCallExpression(node)) return null;

    const callee = node.expression;

    if (pattern.object && pattern.method) {
      // Object method call: $obj.method($args) or obj.prop1.method($args)
      if (!ts.isPropertyAccessExpression(callee)) return null;
      const methodName = callee.name.text;

      // Match method name
      if (pattern.method.startsWith('$')) {
        bindings.set(pattern.method, callee.name);
      } else if (methodName !== pattern.method) {
        return null;
      }

      // Match the object chain (callee.expression)
      if (pattern.properties && pattern.properties.length > 0) {
        // Pattern like $obj.nested.method() — match intermediate chain
        const chain = this._flattenPropertyAccess(callee.expression);
        if (!chain) return null;
        if (!this._matchObjectPart(chain.root, pattern.object, bindings)) return null;
        if (!this._matchPropertyChain(chain.properties, pattern.properties, bindings)) return null;
      } else {
        // Simple: $obj.method()
        if (!this._matchObjectPart(callee.expression, pattern.object, bindings)) return null;
      }
    } else if (pattern.method) {
      // Simple function call: parseInt($x)
      if (pattern.method.startsWith('$')) {
        if (ts.isIdentifier(callee)) {
          bindings.set(pattern.method, callee);
        } else {
          return null;
        }
      } else {
        if (!ts.isIdentifier(callee) || callee.text !== pattern.method) return null;
      }
    } else {
      return null;
    }

    // Match arguments
    if (pattern.args && pattern.args.length > 0) {
      if (!this._matchArgs(node.arguments, pattern.args, bindings)) return null;
    }

    return bindings;
  }

  private _matchAssignment(
    node: ts.Node,
    pattern: ParsedPattern,
    bindings: Map<string, ts.Node>,
  ): Map<string, ts.Node> | null {
    if (!ts.isBinaryExpression(node)) return null;
    if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return null;
    if (!pattern.object || !pattern.properties || pattern.properties.length === 0) return null;

    const lhs = node.left;
    const rhs = node.right;
    const rhsPattern = pattern.properties[0];

    // Match LHS
    if (!this._matchObjectPart(lhs, pattern.object, bindings)) return null;

    // Match RHS
    if (rhsPattern.startsWith('$')) {
      bindings.set(rhsPattern, rhs);
    } else {
      if (!ts.isIdentifier(rhs) || rhs.text !== rhsPattern) return null;
    }

    return bindings;
  }

  private _matchDecorator(
    node: ts.Node,
    pattern: ParsedPattern,
    bindings: Map<string, ts.Node>,
  ): Map<string, ts.Node> | null {
    if (!ts.isDecorator(node)) return null;

    const expr = node.expression;
    if (!ts.isCallExpression(expr)) return null;

    const callee = expr.expression;
    if (!ts.isIdentifier(callee)) return null;
    if (!pattern.method) return null;

    if (callee.text !== pattern.method) return null;

    // Match args if pattern specifies them
    if (pattern.args && pattern.args.length > 0) {
      if (!this._matchArgs(expr.arguments, pattern.args, bindings)) return null;
    }

    // Bind the decorated parameter if pattern specifies one
    if (pattern.properties && pattern.properties.length > 0) {
      const paramName = pattern.properties[0];
      // The parameter node is the parent of the decorator
      const paramNode = node.parent;
      if (paramNode && paramName.startsWith('$')) {
        bindings.set(paramName, paramNode);
      }
    }

    return bindings;
  }

  /**
   * Flatten a property access chain into root + property names.
   * e.g., `req.body.name` => { root: req-node, properties: ["body", "name"] }
   */
  private _flattenPropertyAccess(
    node: ts.Node,
  ): { root: ts.Node; properties: string[] } | null {
    const props: string[] = [];
    let current = node;

    while (ts.isPropertyAccessExpression(current)) {
      props.unshift(current.name.text);
      current = current.expression;
    }

    // Also handle element access for computed properties like req["body"]
    while (ts.isElementAccessExpression(current)) {
      const arg = current.argumentExpression;
      if (ts.isStringLiteral(arg)) {
        props.unshift(arg.text);
      } else {
        return null; // Can't statically match computed access
      }
      current = current.expression;
    }

    if (props.length === 0 && !ts.isIdentifier(current)) return null;

    return { root: current, properties: props };
  }

  /** Match a node against an object part (identifier or metavar) */
  private _matchObjectPart(
    node: ts.Node,
    patternObj: string,
    bindings: Map<string, ts.Node>,
  ): boolean {
    if (patternObj.startsWith('$')) {
      bindings.set(patternObj, node);
      return true;
    }
    if (ts.isIdentifier(node) && node.text === patternObj) {
      return true;
    }
    return false;
  }

  /**
   * Match a list of actual property names against a pattern property chain.
   * Handles `**` wildcard that matches any depth.
   */
  private _matchPropertyChain(
    actual: string[],
    pattern: string[],
    bindings: Map<string, ts.Node>,
  ): boolean {
    let ai = 0;
    let pi = 0;

    while (pi < pattern.length && ai <= actual.length) {
      const pat = pattern[pi];

      if (pat === '**') {
        // ** matches zero or more properties
        if (pi === pattern.length - 1) {
          // ** at end — matches everything remaining
          return true;
        }
        // Try matching the rest of the pattern against each possible suffix
        for (let tryAi = ai; tryAi <= actual.length; tryAi++) {
          if (this._matchPropertyChain(actual.slice(tryAi), pattern.slice(pi + 1), bindings)) {
            return true;
          }
        }
        return false;
      }

      if (ai >= actual.length) return false;

      if (pat.startsWith('$')) {
        // Metavar matches any single property — we don't have a node for
        // individual property names, so we just accept the match
        pi++;
        ai++;
        continue;
      }

      if (pat !== actual[ai]) return false;

      pi++;
      ai++;
    }

    return pi === pattern.length && ai === actual.length;
  }

  /** Match actual call arguments against pattern args */
  private _matchArgs(
    actual: ts.NodeArray<ts.Expression>,
    patternArgs: PatternArg[],
    bindings: Map<string, ts.Node>,
  ): boolean {
    let ai = 0;
    for (let pi = 0; pi < patternArgs.length; pi++) {
      const pat = patternArgs[pi];

      if (pat.isRest) {
        // "..." matches zero or more remaining arguments — always succeeds
        return true;
      }

      if (ai >= actual.length) {
        // More pattern args than actual args (and no rest) — no match
        return false;
      }

      if (pat.name.startsWith('$')) {
        bindings.set(pat.name, actual[ai]);
      } else {
        // Literal arg matching — match against identifier name or string literal
        const argNode = actual[ai];
        if (ts.isIdentifier(argNode)) {
          if (argNode.text !== pat.name) return false;
        } else if (ts.isStringLiteral(argNode)) {
          if (argNode.text !== pat.name) return false;
        } else {
          return false;
        }
      }

      ai++;
    }

    // If no rest pattern, actual arg count must match exactly
    return ai === actual.length;
  }
}

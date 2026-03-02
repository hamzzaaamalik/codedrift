/**
 * Secret Detector — Layered Architecture
 *
 * Layer 1 : Prefix-based detection   — lookup table covering ~80% of providers.
 *           Adding a new provider = one line, no regex.
 * Layer 2 : URL-pattern detection    — connection strings and webhook URLs.
 * Layer 3 : Regex patterns           — non-prefix secrets with specific formats.
 * Layer 4 : Entropy + variable name  — entropy-based catch-all with context hints.
 *
 * Shared filter applied BEFORE all layers:
 *   shouldSkip() — file paths, safe call contexts, placeholders, known examples.
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import { calculateEntropy } from '../utils/file-utils.js';
import * as ts from 'typescript';

// ─── Interfaces ──────────────────────────────────────────────────────────────

interface PrefixEntry {
  provider: string;
  type: string;
  severity: 'error' | 'warning';
  /** Minimum total string length (prefix + body) required for a match. */
  minLength?: number;
  /** Regex tested against the body (value after the prefix). */
  bodyRegex?: RegExp;
}

interface UrlPatternEntry {
  regex: RegExp;
  provider: string;
  type: string;
  severity: 'error' | 'warning';
}

interface RegexPatternEntry {
  pattern: RegExp;
  provider: string;
  type: string;
  severity: 'error' | 'warning';
  /** Minimum Shannon entropy required — suppresses low-entropy false positives. */
  minimumEntropy?: number;
}

// ─── Layer 1 : Prefix table ──────────────────────────────────────────────────
// If it starts with the key, it's almost certainly that provider's secret.
// More specific (longer) prefixes are matched first via SORTED_PREFIXES.

const KEY_PREFIXES = new Map<string, PrefixEntry>([
  // Private key headers — longest & most distinctive, so listed first
  ['-----BEGIN RSA PRIVATE KEY-----',       { provider: 'Private Key', type: 'RSA',           severity: 'error' }],
  ['-----BEGIN EC PRIVATE KEY-----',        { provider: 'Private Key', type: 'EC',            severity: 'error' }],
  ['-----BEGIN PRIVATE KEY-----',           { provider: 'Private Key', type: 'PKCS#8',        severity: 'error' }],
  ['-----BEGIN OPENSSH PRIVATE KEY-----',   { provider: 'Private Key', type: 'OpenSSH',       severity: 'error' }],
  ['-----BEGIN PGP PRIVATE KEY BLOCK-----', { provider: 'Private Key', type: 'PGP',           severity: 'error' }],
  ['-----BEGIN DSA PRIVATE KEY-----',       { provider: 'Private Key', type: 'DSA',           severity: 'error' }],
  ['-----BEGIN ENCRYPTED PRIVATE KEY-----', { provider: 'Private Key', type: 'Encrypted',     severity: 'error' }],

  // Social
  ['AAAAAAAAAAAAAAAAAAAAAA', { provider: 'Twitter',  type: 'Bearer Token',  severity: 'error' }],
  ['EAACEdEose0cBA',         { provider: 'Facebook', type: 'Access Token',  severity: 'error' }],

  // Version control
  ['github_pat_',   { provider: 'GitHub', type: 'Fine-grained PAT',            severity: 'error' }],
  ['GR1348941',     { provider: 'GitLab', type: 'Runner Registration Token',   severity: 'error', minLength: 29 }],
  ['glptt-',        { provider: 'GitLab', type: 'Pipeline Trigger Token',      severity: 'error' }],
  ['glpat-',        { provider: 'GitLab', type: 'Personal Access Token',       severity: 'error' }],
  ['glrt-',         { provider: 'GitLab', type: 'Runner Token',                severity: 'error' }],
  ['ghp_',          { provider: 'GitHub', type: 'Personal Access Token',       severity: 'error' }],
  ['gho_',          { provider: 'GitHub', type: 'OAuth Token',                 severity: 'error' }],
  ['ghs_',          { provider: 'GitHub', type: 'App Installation Token',      severity: 'error' }],
  ['ghu_',          { provider: 'GitHub', type: 'App Token',                   severity: 'error' }],
  ['ghr_',          { provider: 'GitHub', type: 'App Refresh Token',           severity: 'error' }],

  // Payment
  ['whsec_',   { provider: 'Stripe',   type: 'Webhook Secret',          severity: 'error' }],
  ['sk_live_', { provider: 'Stripe',   type: 'Secret Key',              severity: 'error' }],
  ['sk_test_', { provider: 'Stripe',   type: 'Secret Key (Test)',       severity: 'error' }],
  ['rk_live_', { provider: 'Stripe',   type: 'Restricted Key',         severity: 'error' }],
  ['rk_test_', { provider: 'Stripe',   type: 'Restricted Key (Test)',  severity: 'error' }],
  ['pk_live_', { provider: 'Stripe',   type: 'Publishable Key',        severity: 'error' }],
  ['pk_test_', { provider: 'Stripe',   type: 'Publishable Key (Test)', severity: 'warning' }],
  ['rzp_live_',{ provider: 'Razorpay', type: 'Key ID',                 severity: 'error' }],
  ['rzp_test_',{ provider: 'Razorpay', type: 'Key ID (Test)',          severity: 'warning' }],
  ['sq0atp-',  { provider: 'Square',   type: 'Access Token',           severity: 'error' }],
  ['sq0csp-',  { provider: 'Square',   type: 'OAuth Secret',           severity: 'error' }],
  ['EAAAl',    { provider: 'Square',   type: 'Sandbox Token',          severity: 'error' }],
  ['EAAAE',    { provider: 'Square',   type: 'Production Token',       severity: 'error' }],

  // Cloud — AWS (AKIA/AIDA/AROA/APKA are always exactly 20 chars)
  ['FwoGZX', { provider: 'AWS', type: 'Session Token',     severity: 'error', minLength: 56 }],
  ['IQoJb3', { provider: 'AWS', type: 'Session Token',     severity: 'error', minLength: 56 }],
  ['AKIA',   { provider: 'AWS', type: 'Access Key ID',     severity: 'error', minLength: 20, bodyRegex: /^[0-9A-Z]{16}$/ }],
  ['AIDA',   { provider: 'AWS', type: 'IAM User ID',       severity: 'error', minLength: 20, bodyRegex: /^[0-9A-Z]{16}$/ }],
  ['AROA',   { provider: 'AWS', type: 'Role ID',           severity: 'error', minLength: 20, bodyRegex: /^[0-9A-Z]{16}$/ }],
  ['APKA',   { provider: 'AWS', type: 'App/CloudFront Key',severity: 'error', minLength: 20, bodyRegex: /^[0-9A-Z]{16}$/ }],

  // Cloud — Google
  ['GOCSPX-', { provider: 'Google', type: 'OAuth Secret', severity: 'error' }],
  ['ya29.',   { provider: 'Google', type: 'OAuth Token',  severity: 'error' }],
  ['AIza',    { provider: 'Google', type: 'API Key',      severity: 'error', minLength: 39, bodyRegex: /^[0-9A-Za-z\-_]{35}$/ }],

  // Cloud — Other
  ['dop_v1_', { provider: 'DigitalOcean', type: 'Personal Access Token', severity: 'error' }],
  ['doo_v1_', { provider: 'DigitalOcean', type: 'OAuth Token',           severity: 'error' }],
  ['ocid1.',  { provider: 'Oracle Cloud', type: 'Resource ID',           severity: 'error' }],
  ['LTAI',    { provider: 'Alibaba Cloud', type: 'Access Key',           severity: 'error', minLength: 16 }],

  // Communication
  ['xoxb-',  { provider: 'Slack', type: 'Bot Token',        severity: 'error' }],
  ['xoxp-',  { provider: 'Slack', type: 'User Token',       severity: 'error' }],
  ['xoxa-',  { provider: 'Slack', type: 'App Token',        severity: 'error' }],
  ['xoxr-',  { provider: 'Slack', type: 'Refresh Token',    severity: 'error' }],
  ['xapp-',  { provider: 'Slack', type: 'App-level Token',  severity: 'error' }],
  ['SG.',    { provider: 'SendGrid', type: 'API Key',        severity: 'error', minLength: 68 }],
  ['key-',   { provider: 'Mailgun', type: 'API Key',         severity: 'error', minLength: 36, bodyRegex: /^[0-9a-zA-Z]{32}$/ }],
  // Twilio API Key: SK + exactly 32 lowercase hex chars
  ['SK',     { provider: 'Twilio', type: 'API Key',          severity: 'error', minLength: 34, bodyRegex: /^[a-f0-9]{32}$/ }],

  // Adyen API Key: AQ + 30+ alphanumeric/dash/underscore
  ['AQ',     { provider: 'Adyen', type: 'API Key',           severity: 'error', minLength: 32, bodyRegex: /^[A-Za-z0-9\-_]{30,}$/ }],

  // Package registries
  ['npm_',   { provider: 'npm',   type: 'Access Token',  severity: 'error' }],
  ['pypi-',  { provider: 'PyPI',  type: 'API Token',     severity: 'error' }],
  ['oy2',    { provider: 'NuGet', type: 'API Key',       severity: 'error', minLength: 46 }],

  // Generic token formats
  // JWT: eyJ<base64> + two dot-separated sections (header.payload.signature)
  ['eyJ',    { provider: 'JWT',  type: 'Token',             severity: 'error', minLength: 50, bodyRegex: /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ }],
  // HTTP Basic auth header value
  ['Basic ', { provider: 'HTTP', type: 'Basic Auth Header', severity: 'error', minLength: 28 }],
]);

// Sort longest-first so more specific prefixes always win over shorter overlapping ones.
const SORTED_PREFIXES = [...KEY_PREFIXES.entries()].sort((a, b) => b[0].length - a[0].length);

// ─── Layer 2 : URL-pattern table ─────────────────────────────────────────────
// Credentials embedded in connection strings and webhook URLs.

const URL_PATTERNS: UrlPatternEntry[] = [
  { regex: /(?:postgres|postgresql):\/\/[^:]+:[^@\s]+@/,   provider: 'PostgreSQL',    type: 'Connection String', severity: 'error' },
  { regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@\s]+@/,         provider: 'MongoDB',       type: 'Connection String', severity: 'error' },
  { regex: /mysql:\/\/[^:]+:[^@\s]+@/,                     provider: 'MySQL',         type: 'Connection String', severity: 'error' },
  { regex: /redis:\/\/[^:]*:[^@\s]+@/,                     provider: 'Redis',         type: 'Connection String', severity: 'error' },
  { regex: /couchdb:\/\/[^:]+:[^@\s]+@/,                   provider: 'CouchDB',       type: 'Connection String', severity: 'error' },
  { regex: /https?:\/\/elastic:[^@\s]+@/,                   provider: 'Elasticsearch', type: 'Connection String', severity: 'error' },
  { regex: /jdbc:[a-z]+:\/\/[^:]+:[^@\s]+@/,               provider: 'JDBC',          type: 'Connection String', severity: 'error' },
  { regex: /DRIVER=\{[^}]+\};SERVER=[^;]+;DATABASE=[^;]+;UID=[^;]+;PWD=[^;]+/, provider: 'ODBC', type: 'Connection String', severity: 'error' },
  { regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, provider: 'Slack', type: 'Webhook URL', severity: 'error' },
  { regex: /https?:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/,      provider: 'Discord', type: 'Webhook URL', severity: 'error' },
  { regex: /https:\/\/[a-f0-9]{32}@[a-z0-9-]+\.ingest\.sentry\.io\/[0-9]+/,              provider: 'Sentry', type: 'DSN', severity: 'error' },
  { regex: /DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=/,            provider: 'Azure Storage', type: 'Connection String', severity: 'error' },
  { regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,   provider: 'Amazon MWS', type: 'Auth Token', severity: 'error' },
  { regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/,                        provider: 'PayPal', type: 'Access Token', severity: 'error' },
  { regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/,                       provider: 'Google', type: 'OAuth Client ID', severity: 'error' },
  { regex: /[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com/,                            provider: 'Google Cloud', type: 'Service Account', severity: 'error' },
];

// ─── Layer 3 : Regex patterns ─────────────────────────────────────────────────
// Non-prefix secrets with a recognisable overall format.

const REGEX_PATTERNS: RegexPatternEntry[] = [
  // Okta: starts with '00' — prefix too short alone, entropy guard required
  { pattern: /00[A-Za-z0-9\-_]{38}/, provider: 'Okta', type: 'API Token', severity: 'error', minimumEntropy: 3.5 },
  // Azure Storage Account Key — 88-char base64 blob, no distinctive prefix
  { pattern: /[a-zA-Z0-9+/]{88}==/, provider: 'Azure', type: 'Storage Account Key', severity: 'error' },
  // Telegram Bot Token — digits:body format
  { pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/, provider: 'Telegram', type: 'Bot Token', severity: 'error' },
];

// ─── Layer 4 : Sensitive variable name hint ───────────────────────────────────
const SENSITIVE_VAR_NAMES = /(?:secret|password|passwd|api_?key|token|auth|credential|private|apitoken|access_?key)/i;

// ─── Detector ─────────────────────────────────────────────────────────────────

export class SecretDetector extends BaseEngine {
  readonly name = 'hardcoded-secret';

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      if (ts.isStringLiteral(node)) {
        const issue = this.checkStringLiteral(node, context);
        if (issue) issues.push(issue);
      }
      // Template literals without interpolation are equivalent to string literals
      if (ts.isNoSubstitutionTemplateLiteral(node)) {
        const issue = this.checkTemplateLiteral(node, context);
        if (issue) issues.push(issue);
      }
      // Template literals with interpolation — check head for known prefixes
      if (ts.isTemplateExpression(node)) {
        const issue = this.checkTemplateHead(node, context);
        if (issue) issues.push(issue);
      }
    });

    return issues;
  }

  /**
   * Main detection pipeline for a string literal.
   * Layers are tried in order; first match wins.
   */
  private checkStringLiteral(node: ts.StringLiteral, context: AnalysisContext): Issue | null {
    const value = node.text;

    if (value.length < 8) return null;
    if (this.shouldSkip(value, node)) return null;

    // ── Layer 1 : Prefix match ─────────────────────────────────────────────
    for (const [prefix, entry] of SORTED_PREFIXES) {
      if (!value.startsWith(prefix)) continue;
      if (entry.minLength !== undefined && value.length < entry.minLength) continue;
      if (entry.bodyRegex && !entry.bodyRegex.test(value.slice(prefix.length))) continue;
      return this.buildIssue(context, node, entry.provider, entry.type, entry.severity, 'high');
    }

    // ── Layer 2 : URL patterns ─────────────────────────────────────────────
    for (const { regex, provider, type, severity } of URL_PATTERNS) {
      if (regex.test(value)) {
        return this.buildIssue(context, node, provider, type, severity, 'high');
      }
    }

    // ── Layers 3 & 4 need Shannon entropy ─────────────────────────────────
    const entropy = calculateEntropy(value);

    // ── Layer 3 : Regex patterns ───────────────────────────────────────────
    for (const { pattern, provider, type, severity, minimumEntropy } of REGEX_PATTERNS) {
      if (!pattern.test(value)) continue;
      if (minimumEntropy !== undefined && entropy < minimumEntropy) continue;
      return this.buildIssue(context, node, provider, type, severity, 'high', entropy);
    }

    // ── Layer 4 : Entropy + variable name ─────────────────────────────────
    if (value.length >= 20 && entropy > 4.5 && !/\s/.test(value)) {
      if (this.isTestValue(value)) return null;

      const varName = this.getVariableName(node);
      if (varName && SENSITIVE_VAR_NAMES.test(varName)) {
        const envVar = varName.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_|_$/g, '');
        return this.createIssue(
          context, node,
          `Potential hardcoded secret in variable '${varName}'`,
          {
            severity: 'warning',
            confidence: 'medium',
            suggestion: `Move the value to process.env.${envVar} or a secret manager`,
          },
        );
      }

      // Generic high-entropy fallback (no variable name context)
      if (value.length >= 32) {
        const charTypes = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^a-zA-Z0-9]/]
          .filter(r => r.test(value)).length;
        if (charTypes >= 2) {
          const issue = this.createIssue(
            context, node,
            `Potential secret detected (high entropy: ${entropy.toFixed(2)})`,
            {
              severity: 'warning',
              confidence: 'medium',
              suggestion: 'If this is a secret, use environment variables. Otherwise, add a codedrift-ignore comment.',
            },
          );
          if (issue?.metadata) issue.metadata.entropy = entropy;
          return issue;
        }
      }
    }

    return null;
  }

  /** Check a no-substitution template literal (backtick string without interpolation). */
  private checkTemplateLiteral(node: ts.NoSubstitutionTemplateLiteral, context: AnalysisContext): Issue | null {
    const value = node.text;
    if (value.length < 8) return null;
    if (this.shouldSkip(value, node as unknown as ts.StringLiteral)) return null;

    // Run the same detection pipeline as string literals
    // Layer 1: Prefix match
    for (const [prefix, entry] of SORTED_PREFIXES) {
      if (!value.startsWith(prefix)) continue;
      if (entry.minLength !== undefined && value.length < entry.minLength) continue;
      if (entry.bodyRegex && !entry.bodyRegex.test(value.slice(prefix.length))) continue;
      return this.buildIssue(context, node, entry.provider, entry.type, entry.severity, 'high');
    }

    // Layer 2: URL patterns
    for (const { regex, provider, type, severity } of URL_PATTERNS) {
      if (regex.test(value)) {
        return this.buildIssue(context, node, provider, type, severity, 'high');
      }
    }

    // Layer 3 & 4: Entropy-based
    const entropy = calculateEntropy(value);

    for (const { pattern, provider, type, severity, minimumEntropy } of REGEX_PATTERNS) {
      if (!pattern.test(value)) continue;
      if (minimumEntropy !== undefined && entropy < minimumEntropy) continue;
      return this.buildIssue(context, node, provider, type, severity, 'high', entropy);
    }

    // Layer 4: Entropy + variable name
    if (value.length >= 20 && entropy > 4.5 && !/\s/.test(value)) {
      if (this.isTestValue(value)) return null;
      // Reuse variable name extraction (parent structure is the same)
      const varName = this.getVariableName(node as unknown as ts.StringLiteral);
      if (varName && SENSITIVE_VAR_NAMES.test(varName)) {
        const envVar = varName.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_|_$/g, '');
        return this.createIssue(context, node, `Potential hardcoded secret in variable '${varName}'`, {
          severity: 'warning', confidence: 'medium',
          suggestion: `Move the value to process.env.${envVar} or a secret manager`,
        });
      }
    }

    return null;
  }

  /** Check the head of a template expression for known secret prefixes. */
  private checkTemplateHead(node: ts.TemplateExpression, context: AnalysisContext): Issue | null {
    const headText = node.head.text;
    if (headText.length < 4) return null;

    // Only check Layer 1 prefix matches — the full value is unknown at compile time
    for (const [prefix, entry] of SORTED_PREFIXES) {
      if (!headText.startsWith(prefix)) continue;
      // For template expressions, we can't check minLength/bodyRegex since the full value is unknown
      return this.buildIssue(context, node, entry.provider, entry.type, entry.severity, 'medium');
    }

    // Check URL patterns on the head text (connection strings often start in the head)
    for (const { regex, provider, type, severity } of URL_PATTERNS) {
      if (regex.test(headText)) {
        return this.buildIssue(context, node, provider, type, severity, 'medium');
      }
    }

    return null;
  }

  /** Build a labelled issue for a matched secret. */
  private buildIssue(
    context: AnalysisContext,
    node: ts.Node,
    provider: string,
    type: string,
    severity: 'error' | 'warning',
    confidence: 'high' | 'medium' | 'low',
    entropy?: number,
  ): Issue | null {
    const envVarName = `${provider}_${type}`
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, '_')
      .replace(/^_|_$/g, '');
    const issue = this.createIssue(
      context, node,
      `Hardcoded ${provider} ${type} detected`,
      {
        severity,
        confidence,
        suggestion: `Use process.env.${envVarName} instead of hardcoding this ${type}`,
      },
    );
    if (issue?.metadata && entropy !== undefined) issue.metadata.entropy = entropy;
    return issue;
  }

  /**
   * Extract the variable or property name the string is assigned to.
   * Returns null when the string is not in a recognisable assignment context.
   */
  private getVariableName(node: ts.StringLiteral): string | null {
    const parent = node.parent;
    if (!parent) return null;

    // const apiKey = 'secret'
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
    // { apiKey: 'secret' }
    if (ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
    // obj.password = 'secret'
    if (ts.isBinaryExpression(parent) && parent.right === node) {
      const left = parent.left;
      if (ts.isPropertyAccessExpression(left)) return left.name.text;
      if (ts.isIdentifier(left)) return left.text;
    }
    return null;
  }

  /** Returns true if the string should be skipped entirely. */
  private shouldSkip(value: string, node: ts.StringLiteral): boolean {
    return (
      this.isFilePath(value) ||
      this.isInSafeCallContext(node) ||
      this.isPlaceholder(value) ||
      this.isKnownSafeExample(value)
    );
  }

  /**
   * URL-form strings (https://, postgres://, etc.) are NEVER treated as file paths —
   * they may carry embedded credentials (Slack webhooks, DB URLs, Sentry DSNs).
   */
  private isFilePath(value: string): boolean {
    if (/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(value)) return false;
    if (value.includes('/') || value.includes('\\')) return true;
    // Relative path prefixes
    if (value.startsWith('./') || value.startsWith('../')) return true;
    const fileExtensions = /\.(sql|json|ts|tsx|js|jsx|py|rb|rs|go|java|cs|php|html|css|md|yml|yaml|xml|csv|txt|sh|bash|env|lock|toml|ini|cfg|conf|log)$/i;
    return fileExtensions.test(value);
  }

  /** True if the string is an argument to a known file/path function. */
  private isInSafeCallContext(node: ts.StringLiteral): boolean {
    const parent = node.parent;
    if (!parent || !ts.isCallExpression(parent)) return false;
    if (!parent.arguments.includes(node as ts.Expression)) return false;
    const expr = parent.expression;
    let funcName: string | null = null;
    if (ts.isIdentifier(expr)) funcName = expr.text;
    else if (ts.isPropertyAccessExpression(expr)) funcName = expr.name.text;
    if (!funcName) return false;
    const safeFileFunctions = new Set([
      // path module
      'join', 'resolve', 'relative', 'dirname', 'basename', 'extname',
      // fs module
      'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
      'appendFile', 'appendFileSync', 'existsSync', 'statSync',
      'mkdirSync', 'copyFile', 'rename', 'unlink',
      'access', 'accessSync', 'stat', 'lstat', 'lstatSync',
      'createReadStream', 'createWriteStream',
      // require / dynamic import
      'require',
      // migration and process execution
      'runMigration', 'migrate', 'execFile', 'spawn', 'exec',
      // glob/file search
      'glob',
    ]);
    return safeFileFunctions.has(funcName);
  }

  /** True if the string is a well-known placeholder (not a real secret). */
  private isPlaceholder(value: string): boolean {
    const lower = value.toLowerCase();

    // 'example' in a URL hostname (prod.example.com) is NOT a placeholder —
    // example.com is a legitimate test domain (RFC 2606).
    // Only flag 'example' in non-URL strings (e.g. "sk_live_example123").
    const isUrl = /^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(value);
    if (!isUrl && lower.includes('example')) return true;

    const placeholderSubstrings = [
      'placeholder', 'your_key', 'your-key', 'yourkey',
      'your_secret', 'your-secret',
      'xxx', '<key>', '<secret>', '<token>', '<password>', '<api_key>',
      'todo', 'fixme', 'dummy', 'fake', 'sample',
      'replace_me', 'replaceme', 'change_me', 'changeme',
      'insert_here', 'put_here', 'add_here',
    ];
    if (placeholderSubstrings.some(s => lower.includes(s))) return true;

    const placeholderPatterns = [
      /YOUR_.*_HERE/i,
      /REPLACE.*WITH/i,
      /CHANGE.*THIS/i,
      /\[INSERT.*\]/i,
      /\{.*PLACEHOLDER.*\}/i,
      /<YOUR.*>/i,
      /<REPLACE.*>/i,
      /\$\{.*\}/,
      /{{.*}}/,
      /^(YOUR|REPLACE|CHANGE|INSERT|ADD|PUT)_/i,
      /_(HERE|NOW|THIS)$/i,
      /\*{4,}/,
    ];
    if (placeholderPatterns.some(p => p.test(value))) return true;

    return /^(.)\1{5,}$/.test(value);
  }

  /** True if the value is a well-known AWS/Stripe documentation example key. */
  private isKnownSafeExample(value: string): boolean {
    return [
      'AKIAIOSFODNN7EXAMPLE',
      'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    ].includes(value);
  }

  /**
   * True if the value has obvious test/dev markers.
   * Only called by Layer 4 — specific pattern matches never consult this.
   */
  private isTestValue(value: string): boolean {
    const lower = value.toLowerCase();
    const indicators = ['test', 'dev', 'local', 'demo', 'sample', 'mock', 'dummy', 'fake', 'stub', 'fixture', 'sandbox'];
    if (indicators.some(i => lower.includes(i))) return true;
    if (/^(.)\1{5,}$/.test(value)) return true;
    if (/^(abc|123|xyz)+$/i.test(value)) return true;
    return false;
  }
}

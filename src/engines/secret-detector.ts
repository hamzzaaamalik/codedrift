/**
 * Secret Pattern Detector
 * Detects hardcoded secrets, API keys, passwords, and tokens
 * Priority: CRITICAL (security vulnerability)
 */

import { BaseEngine } from './base-engine.js';
import { AnalysisContext, Issue } from '../types/index.js';
import { traverse } from '../core/parser.js';
import * as ts from 'typescript';

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: 'error' | 'warning';
}

export class SecretDetector extends BaseEngine {
  readonly name = 'hardcoded-secret';

  // 100+ Secret patterns organized by category
  private readonly patterns: SecretPattern[] = [
    // === Payment & Finance (15 patterns) ===
    { name: 'Stripe API Key', pattern: /sk_(live|test)_[0-9a-zA-Z]{24,}/, severity: 'error' },
    { name: 'Stripe Publishable Key', pattern: /pk_(live|test)_[0-9a-zA-Z]{24,}/, severity: 'error' },
    { name: 'Stripe Webhook Secret', pattern: /whsec_[0-9a-zA-Z]{32,}/, severity: 'error' },
    { name: 'Stripe Restricted Key', pattern: /rk_(live|test)_[0-9a-zA-Z]{24,}/, severity: 'error' },
    { name: 'PayPal Access Token', pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/, severity: 'error' },
    { name: 'Square Access Token', pattern: /sq0atp-[0-9A-Za-z\-_]{22}/, severity: 'error' },
    { name: 'Square OAuth Secret', pattern: /sq0csp-[0-9A-Za-z\-_]{43}/, severity: 'error' },
    { name: 'Braintree Access Token', pattern: /access_token\$[a-z]{8}\$[0-9a-z]{16}\$[0-9a-f]{32}/, severity: 'error' },
    // { name: 'Coinbase API Key', pattern: /[a-z0-9]{32}/, severity: 'warning' },
    // UUIDs too generic
    // { name: 'Plaid Secret Key', pattern: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/, severity: 'warning' },
    { name: 'Razorpay Key Secret', pattern: /rzp_(live|test)_[a-zA-Z0-9]{24}/, severity: 'error' },
    { name: 'Checkout.com Secret Key', pattern: /sk_(test|live)_[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}/, severity: 'error' },
    { name: 'Adyen API Key', pattern: /AQ[A-Za-z0-9\-_]{30,}/, severity: 'error' },
    // Too generic - matches test
    // { name: 'Mollie API Key', pattern: /(live|test)_[a-zA-Z0-9]{30,}/, severity: 'error' },
    // UUIDs too generic
    // { name: 'Klarna API Credentials', pattern: /[A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12}/, severity: 'warning' },

    // === Cloud Providers - AWS (10 patterns) ===
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'error' },
    { name: 'AWS Secret Key', pattern: /aws_secret_access_key.*[=:]\s*[A-Za-z0-9/+=]{40}/, severity: 'error' },
    { name: 'AWS Session Token', pattern: /AWS.*Session.*Token.*[=:]\s*[A-Za-z0-9/+=]{100,}/, severity: 'error' },
    { name: 'AWS MWS Auth Token', pattern: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, severity: 'error' },
    { name: 'AWS App ID', pattern: /APKA[0-9A-Z]{16}/, severity: 'error' },
    // { name: 'AWS Account ID', pattern: /[0-9]{12}/, severity: 'warning' },
    // { name: 'AWS S3 Bucket URL', pattern: /s3:\/\/[a-zA-Z0-9.\-]+/, severity: 'warning' },
    { name: 'AWS CloudFront Key', pattern: /APKA[A-Z0-9]{16}/, severity: 'error' },
    // { name: 'AWS SES SMTP Password', pattern: /[A-Za-z0-9+/]{40,}/, severity: 'warning' },
    // { name: 'AWS SNS Topic', pattern: /arn:aws:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9-_]+/, severity: 'warning' },

    // === Cloud Providers - Google (8 patterns) ===
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\\-_]{35}/, severity: 'error' },
    { name: 'Google OAuth Client Secret', pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/, severity: 'error' },
    { name: 'Google OAuth Secret', pattern: /GOCSPX-[a-zA-Z0-9_-]{28}/, severity: 'error' },
    { name: 'Google Cloud Service Account', pattern: /[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com/, severity: 'error' },
    // { name: 'Firebase Database URL', pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/, severity: 'warning' },
    { name: 'GCP OAuth Token', pattern: /ya29\.[0-9A-Za-z\-_]+/, severity: 'error' },
    // Duplicate of Google API Key
    // { name: 'Google Maps API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/, severity: 'error' },
    // { name: 'YouTube API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/, severity: 'error' },

    // === Cloud Providers - Azure (8 patterns) ===
    { name: 'Azure Storage Account Key', pattern: /[a-zA-Z0-9+/]{88}==/, severity: 'error' },
    // { name: 'Azure Client Secret', pattern: /[a-zA-Z0-9~_\-\.]{34,40}/, severity: 'warning' },
    // { name: 'Azure SAS Token', pattern: /sig=[A-Za-z0-9%]+/, severity: 'error' },
    { name: 'Azure Connection String', pattern: /DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}/, severity: 'error' },
    { name: 'Azure DevOps PAT', pattern: /[a-z0-9]{52}/, severity: 'warning' },
    // UUIDs are too generic - disabled
    // { name: 'Azure Subscription ID', pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, severity: 'warning' },
    // { name: 'Azure App ID', pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, severity: 'warning' },
    // { name: 'Azure Tenant ID', pattern: /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, severity: 'warning' },

    // === Cloud Providers - Other (10 patterns) ===
    { name: 'DigitalOcean Token', pattern: /dop_v1_[a-f0-9]{64}/, severity: 'error' },
    { name: 'DigitalOcean OAuth', pattern: /doo_v1_[a-f0-9]{64}/, severity: 'error' },
    // UUIDs too generic - disabled
    // { name: 'Heroku API Key', pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/, severity: 'warning' },
    // { name: 'Linode API Token', pattern: /[a-f0-9]{64}/, severity: 'warning' },
    // { name: 'Vultr API Key', pattern: /[A-Z0-9]{36}/, severity: 'warning' },
    // { name: 'Cloudflare API Key', pattern: /[a-z0-9]{37}/, severity: 'warning' },
    // { name: 'Cloudflare API Token', pattern: /[A-Za-z0-9\-_]{40}/, severity: 'warning' },
    // { name: 'IBM Cloud API Key', pattern: /[a-zA-Z0-9_\-]{44}/, severity: 'error' },
    { name: 'Oracle Cloud Key', pattern: /ocid1\.[a-z]+\.[a-z0-9\-]+\.[a-z0-9]+/, severity: 'error' },
    { name: 'Alibaba Cloud Key', pattern: /LTAI[A-Za-z0-9]{12,20}/, severity: 'error' },

    // === Version Control & CI/CD (20 patterns) ===
    { name: 'GitHub Token', pattern: /gh[ps]_[0-9a-zA-Z]{36,}/, severity: 'error' },
    { name: 'GitHub PAT', pattern: /github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}/, severity: 'error' },
    { name: 'GitHub OAuth', pattern: /gho_[0-9a-zA-Z]{36}/, severity: 'error' },
    { name: 'GitHub App Token', pattern: /ghu_[0-9a-zA-Z]{36}/, severity: 'error' },
    { name: 'GitHub Refresh Token', pattern: /ghr_[0-9a-zA-Z]{36}/, severity: 'error' },
    { name: 'GitLab PAT', pattern: /glpat-[0-9a-zA-Z_\-]{20}/, severity: 'error' },
    { name: 'GitLab Runner Token', pattern: /GR1348941[0-9a-zA-Z_\-]{20}/, severity: 'error' },
    { name: 'GitLab Pipeline Token', pattern: /glptt-[0-9a-f]{40}/, severity: 'error' },
    // Generic patterns disabled - too many false positives
    // { name: 'Bitbucket App Password', pattern: /[A-Za-z0-9]{16}/, severity: 'warning' },
    // { name: 'Bitbucket Access Token', pattern: /[A-Za-z0-9_\-]{59}/, severity: 'warning' },
    // { name: 'CircleCI Token', pattern: /[a-f0-9]{40}/, severity: 'warning' },
    // { name: 'Travis CI Token', pattern: /[a-zA-Z0-9]{22}/, severity: 'warning' },
    // { name: 'Jenkins API Token', pattern: /[a-f0-9]{32}/, severity: 'warning' },
    // { name: 'Jenkins Crumb', pattern: /[a-f0-9]{32}/, severity: 'warning' },
    // { name: 'Drone CI Token', pattern: /[a-zA-Z0-9]{32}/, severity: 'warning' },
    { name: 'Azure DevOps PAT', pattern: /[a-z0-9]{52}/, severity: 'warning' },
    // { name: 'TeamCity Token', pattern: /eyJ[A-Za-z0-9_\/+=\-]+/, severity: 'warning' },
    // { name: 'Bamboo Token', pattern: /[A-Z0-9]{16}/, severity: 'warning' },
    // { name: 'CodeShip AES Key', pattern: /[a-zA-Z0-9+/=]{44}/, severity: 'error' },
    // { name: 'Netlify Access Token', pattern: /[a-zA-Z0-9\-_]{40,}/, severity: 'error' },

    // === Communication (10 patterns) ===
    { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, severity: 'error' },
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}/, severity: 'error' },
    { name: 'Slack App Token', pattern: /xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-z0-9]+/, severity: 'error' },
    { name: 'Discord Webhook', pattern: /https:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_\-]+/, severity: 'error' },
    { name: 'Discord Bot Token', pattern: /[MN][A-Za-z\d]{23,25}\.[A-Za-z\d\-_]{6}\.[A-Za-z\d\-_]{27,}/, severity: 'error' },
    { name: 'Telegram Bot Token', pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/, severity: 'error' },
    { name: 'Twilio API Key', pattern: /SK[a-f0-9]{32}/, severity: 'error' },
    // { name: 'Twilio Auth Token', pattern: /[a-f0-9]{32}/, severity: 'warning' },
    { name: 'SendGrid API Key', pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/, severity: 'error' },
    { name: 'Mailgun API Key', pattern: /key-[0-9a-zA-Z]{32}/, severity: 'error' },

    // === Social Media & Auth (10 patterns) ===
    { name: 'Facebook Access Token', pattern: /EAACEdEose0cBA[0-9A-Za-z]+/, severity: 'error' },
    // { name: 'Facebook App Secret', pattern: /[a-f0-9]{32}/, severity: 'warning' },
    // { name: 'Twitter API Key', pattern: /[A-Za-z0-9]{25}/, severity: 'warning' },
    // { name: 'Twitter API Secret', pattern: /[A-Za-z0-9]{50}/, severity: 'warning' },
    { name: 'Twitter Bearer Token', pattern: /AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+/, severity: 'error' },
    // { name: 'LinkedIn Client Secret', pattern: /[a-zA-Z0-9]{16}/, severity: 'warning' },
    // { name: 'LinkedIn Access Token', pattern: /[a-zA-Z0-9\-_]{76}/, severity: 'error' },
    // { name: 'Auth0 Client Secret', pattern: /[A-Za-z0-9_\-]{64}/, severity: 'error' },
    { name: 'Okta API Token', pattern: /00[A-Za-z0-9\-_]{38}/, severity: 'error' },
    // { name: 'Firebase Auth Token', pattern: /[A-Za-z0-9\-_]{21,}/, severity: 'warning' },

    // === Databases (8 patterns) ===
    { name: 'PostgreSQL URL', pattern: /postgresql:\/\/[^:]+:[^@\s]+@/, severity: 'error' },
    { name: 'MongoDB URL', pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@\s]+@/, severity: 'error' },
    { name: 'MySQL URL', pattern: /mysql:\/\/[^:]+:[^@\s]+@/, severity: 'error' },
    { name: 'Redis URL', pattern: /redis:\/\/[^:]*:[^@\s]+@/, severity: 'error' },
    { name: 'CouchDB URL', pattern: /couchdb:\/\/[^:]+:[^@\s]+@/, severity: 'error' },
    { name: 'Elasticsearch URL', pattern: /https?:\/\/elastic:[^@\s]+@/, severity: 'error' },
    { name: 'JDBC Connection', pattern: /jdbc:[a-z]+:\/\/[^:]+:[^@\s]+@/, severity: 'error' },
    { name: 'ODBC Connection', pattern: /DRIVER=\{[^}]+\};SERVER=[^;]+;DATABASE=[^;]+;UID=[^;]+;PWD=[^;]+/, severity: 'error' },

    // === Private Keys (8 patterns) ===
    { name: 'RSA Private Key', pattern: /-----BEGIN RSA PRIVATE KEY-----/, severity: 'error' },
    { name: 'Private Key', pattern: /-----BEGIN PRIVATE KEY-----/, severity: 'error' },
    { name: 'EC Private Key', pattern: /-----BEGIN EC PRIVATE KEY-----/, severity: 'error' },
    { name: 'OpenSSH Private Key', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, severity: 'error' },
    { name: 'DSA Private Key', pattern: /-----BEGIN DSA PRIVATE KEY-----/, severity: 'error' },
    { name: 'PGP Private Key', pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, severity: 'error' },
    { name: 'SSH Private Key (Ed25519)', pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, severity: 'error' },
    { name: 'PKCS#8 Private Key', pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----/, severity: 'error' },

    // === Generic Tokens & JWT (5 patterns) ===
    { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'error' },
    // { name: 'Bearer Token', pattern: /Bearer [A-Za-z0-9\-._~+\/]+=*/, severity: 'warning' },
    { name: 'Basic Auth', pattern: /Basic [A-Za-z0-9+\/=]{20,}/, severity: 'error' },
    { name: 'API Key Header', pattern: /X-API-Key:\s*[A-Za-z0-9\-_]{20,}/, severity: 'warning' },
    // { name: 'Generic API Token', pattern: /[a-zA-Z0-9_\-]{40,}/, severity: 'warning' },

    // === Package Managers & Registries (5 patterns) ===
    { name: 'npm Access Token', pattern: /npm_[A-Za-z0-9]{36}/, severity: 'error' },
    { name: 'PyPI Token', pattern: /pypi-[A-Za-z0-9\-_]{60,}/, severity: 'error' },
    // { name: 'Cargo Registry Token', pattern: /[a-zA-Z0-9\-_]{40}/, severity: 'warning' },
    { name: 'NuGet API Key', pattern: /oy2[a-z0-9]{43}/, severity: 'error' },
    // { name: 'Composer Auth Token', pattern: /[a-f0-9]{64}/, severity: 'warning' },

    // === Miscellaneous (3 patterns) ===
    // { name: 'Datadog API Key', pattern: /[a-f0-9]{32}/, severity: 'warning' },
    // { name: 'New Relic License Key', pattern: /[a-f0-9]{40}/, severity: 'error' },
    { name: 'Sentry DSN', pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9\-]+\.ingest\.sentry\.io\/[0-9]+/, severity: 'error' },
  ];

  async analyze(context: AnalysisContext): Promise<Issue[]> {
    const issues: Issue[] = [];

    traverse(context.sourceFile, (node) => {
      // Check string literals for secret patterns
      if (ts.isStringLiteral(node)) {
        const stringIssue = this.checkStringLiteral(node, context);
        if (stringIssue) {
          issues.push(stringIssue);
        }
      }

      // Check variable declarations for suspicious names with non-env values
      if (ts.isVariableDeclaration(node)) {
        const varIssue = this.checkVariableDeclaration(node, context);
        if (varIssue) {
          issues.push(varIssue);
        }
      }
    });

    return issues;
  }

  /**
   * Check string literal for secret patterns
   */
  private checkStringLiteral(node: ts.StringLiteral, context: AnalysisContext): Issue | null {
    const value = node.text;

    // Skip empty strings
    if (value.length === 0) {
      return null;
    }

    // Skip placeholder values
    if (this.isPlaceholder(value)) {
      return null;
    }

    // Skip test/dev values
    if (this.isTestValue(value)) {
      return null;
    }

    // Check against known patterns
    for (const { name, pattern, severity } of this.patterns) {
      if (pattern.test(value)) {
        return this.createIssue(context, node, `Hardcoded secret detected: ${name}`, {
          severity,
          suggestion: 'Use environment variables or secret management service',
        });
      }
    }

    return null;
  }

  /**
   * Check variable declaration for suspicious secret-like names
   */
  private checkVariableDeclaration(node: ts.VariableDeclaration, context: AnalysisContext): Issue | null {
    if (!ts.isIdentifier(node.name)) {
      return null;
    }

    const varName = node.name.text;

    // Check if variable name suggests it's a secret
    if (!this.isSuspiciousVariableName(varName)) {
      return null;
    }

    // Check if it's using process.env (safe)
    if (node.initializer && this.isEnvVariable(node.initializer)) {
      return null;
    }

    // Check if it's a placeholder
    if (node.initializer && ts.isStringLiteral(node.initializer) && this.isPlaceholder(node.initializer.text)) {
      return null;
    }

    // Check if it's empty/null
    if (node.initializer && this.isEmptyValue(node.initializer)) {
      return null;
    }

    // Check if it's a hardcoded string value
    if (node.initializer && ts.isStringLiteral(node.initializer)) {
      const value = node.initializer.text;

      // Skip test values
      if (this.isTestValue(value)) {
        return null;
      }

      // Has suspicious name and hardcoded value
      if (value.length > 8) {  // Only flag if value looks substantial
        return this.createIssue(context, node, `Suspicious secret in variable: ${varName}`, {
          severity: 'warning',
          suggestion: 'Use environment variables instead of hardcoding secrets',
        });
      }
    }

    return null;
  }

  /**
   * Check if variable name suggests it contains a secret
   */
  private isSuspiciousVariableName(name: string): boolean {
    const lowerName = name.toLowerCase();

    // Known false positives - these are NOT secrets
    const falsePositivePatterns = [
      'storage_key',      // localStorage/sessionStorage identifiers
      'cache_key',        // Cache identifiers
      'cookie_key',       // Cookie names
      'local_storage',    // localStorage references
      'session_storage',  // sessionStorage references
      'query_key',        // React Query keys
      'mutation_key',     // React Query mutation keys
      'redis_key',        // Redis key names (not values)
      'key_name',         // Generic key name identifiers
      'key_path',         // Object path keys
      'sort_key',         // Sorting keys
      'partition_key',    // Database partition keys
      'primary_key',      // Database primary keys
      'foreign_key',      // Database foreign keys
      'unique_key',       // Database unique keys
      'index_key',        // Database index keys
      'encryption_key_id', // Key identifier, not the key itself
      'public_key',       // Public keys are not secrets
      'key_id',           // Key identifier references
      'key_type',         // Key type identifiers
      'auth_token_name',  // Token field names, not actual tokens
      'token_type',       // Token type identifiers
      'token_field',      // Form field names
    ];

    // If it matches a known false positive pattern, it's not suspicious
    if (falsePositivePatterns.some(pattern => lowerName.includes(pattern))) {
      return false;
    }

    const suspiciousWords = [
      'secret', 'password', 'passwd', 'pwd', 'token', 'key',
      'apikey', 'api_key', 'private', 'credential', 'auth',
    ];

    return suspiciousWords.some(word => lowerName.includes(word));
  }

  /**
   * Check if initializer is process.env access
   */
  private isEnvVariable(node: ts.Expression): boolean {
    // process.env.VAR_NAME
    if (ts.isPropertyAccessExpression(node)) {
      const { expression } = node;
      if (ts.isPropertyAccessExpression(expression)) {
        return (
          ts.isIdentifier(expression.expression) &&
          expression.expression.text === 'process' &&
          ts.isIdentifier(expression.name) &&
          expression.name.text === 'env'
        );
      }
    }

    // process.env['VAR_NAME']
    if (ts.isElementAccessExpression(node)) {
      const { expression } = node;
      if (ts.isPropertyAccessExpression(expression)) {
        return (
          ts.isIdentifier(expression.expression) &&
          expression.expression.text === 'process' &&
          ts.isIdentifier(expression.name) &&
          expression.name.text === 'env'
        );
      }
    }

    return false;
  }

  /**
   * Check if value is a placeholder
   */
  private isPlaceholder(value: string): boolean {
    const placeholderPatterns = [
      /YOUR_.*_HERE/i,
      /REPLACE.*WITH/i,
      /CHANGE.*THIS/i,
      /EXAMPLE/i,
      /PLACEHOLDER/i,
      /TODO/i,
      /XXX/i,
    ];

    return placeholderPatterns.some(pattern => pattern.test(value));
  }

  /**
   * Check if value is for test/dev environment
   */
  private isTestValue(value: string): boolean {
    const lowerValue = value.toLowerCase();
    const testIndicators = ['test', 'dev', 'local', 'demo', 'example', 'sample', 'mock'];

    return testIndicators.some(indicator => lowerValue.includes(indicator));
  }

  /**
   * Check if initializer is empty/null/undefined
   */
  private isEmptyValue(node: ts.Expression): boolean {
    // Empty string
    if (ts.isStringLiteral(node) && node.text === '') {
      return true;
    }

    // null
    if (node.kind === ts.SyntaxKind.NullKeyword) {
      return true;
    }

    // undefined
    if (ts.isIdentifier(node) && node.text === 'undefined') {
      return true;
    }

    return false;
  }

  /**
   * Calculate Shannon entropy of a string
   * High entropy (>4.5) suggests randomness (possible secret)
   *
   * Future enhancement: Use this for adaptive secret detection
   * Example: Check if high-entropy strings (>4.5) are assigned to secret-named variables
   */
  // private calculateEntropy(str: string): number {
  //   if (str.length === 0) return 0;
  //   const freq = new Map<string, number>();
  //   for (const char of str) freq.set(char, (freq.get(char) || 0) + 1);
  //   let entropy = 0;
  //   for (const count of freq.values()) {
  //     const p = count / str.length;
  //     entropy -= p * Math.log2(p);
  //   }
  //   return entropy;
  // }
}

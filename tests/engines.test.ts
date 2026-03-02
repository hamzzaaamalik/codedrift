/**
 * Test suite for detection engines
 * Uses Node.js built-in test runner
 */

import { describe, test } from 'node:test';
import assert from 'node:assert';
import { parseSource } from '../src/core/parser.js';
import { HallucinatedDepsDetector } from '../src/engines/hallucinated-deps-detector.js';
import { StackTraceDetector } from '../src/engines/stack-trace-detector.js';
import { MissingAwaitDetector } from '../src/engines/missing-await-detector.js';
import { EmptyCatchDetector } from '../src/engines/empty-catch-detector.js';
import { SecretDetector } from '../src/engines/secret-detector.js';

// Helper to create analysis context
function createContext(code: string, filePath = 'test.ts', includePackageResolver = false) {
  const sourceFile = parseSource(code, filePath);
  const context: any = {
    sourceFile,
    filePath,
    content: code,
  };

  // Add mock package resolver if needed (for HallucinatedDepsDetector tests)
  if (includePackageResolver) {
    context.packageResolver = {
      packageExists: (name: string) => {
        // Mock: only allow common packages
        const knownPackages = ['express', 'react', 'lodash', 'typescript'];
        return knownPackages.includes(name);
      },
      packageExistsForFile: (name: string) => {
        const knownPackages = ['express', 'react', 'lodash', 'typescript'];
        return knownPackages.includes(name);
      },
    };
  }

  return context;
}

describe('HallucinatedDepsDetector', () => {
  const engine = new HallucinatedDepsDetector();

  test('should detect fake package imports', async () => {
    const code = `import { validator } from 'express-validator-pro';`;
    const context = createContext(code, 'test.ts', true); // Enable package resolver
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect hallucinated dependency');
    assert.ok(issues[0]?.message.includes('express-validator-pro'), 'Should mention package name');
    assert.ok(issues[0]?.confidence, 'Should have confidence field');
    assert.strictEqual(issues[0]?.confidence, 'high', 'Should have high confidence for production code');
  });

  test('should not flag Node.js built-ins', async () => {
    const code = `import * as fs from 'fs';`;
    const context = createContext(code, 'test.ts', true); // Enable package resolver
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag built-in modules');
  });

  test('should not flag relative imports', async () => {
    const code = `import { foo } from './utils';`;
    const context = createContext(code, 'test.ts', true); // Enable package resolver
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag relative imports');
  });
});

describe('StackTraceDetector', () => {
  const engine = new StackTraceDetector();

  test('should detect err.stack in response', async () => {
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.status(500).json({ error: err.stack });
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect stack trace exposure');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.confidence, 'Should have confidence field');
    assert.strictEqual(issue.confidence, 'high', 'Should have high confidence');
  });

  test('should detect shorthand error object', async () => {
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (error) {
          res.json({ error });
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect error object exposure');
  });

  test('should not flag safe error handling', async () => {
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.status(500).json({ error: 'Internal server error' });
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag safe handling');
  });
});

describe('MissingAwaitDetector', () => {
  const engine = new MissingAwaitDetector();

  test('should detect missing await on async function', async () => {
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        return fetchData(); // Missing await - return value used
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect missing await');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.confidence, 'Should have confidence field');
    assert.strictEqual(issue.confidence, 'high', 'Should have high confidence when return value is used');
  });

  test('should not flag properly awaited calls', async () => {
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        await fetchData();
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag awaited calls');
  });
});

describe('EmptyCatchDetector', () => {
  const engine = new EmptyCatchDetector();

  test('should detect empty catch blocks', async () => {
    const code = `
      try {
        riskyOperation();
      } catch (err) {
        // Empty
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect empty catch');
  });

  test('should detect useless re-throw', async () => {
    const code = `
      try {
        riskyOperation();
      } catch (e) {
        throw e;
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect useless re-throw');
  });

  test('should not flag proper error handling', async () => {
    const code = `
      try {
        riskyOperation();
      } catch (err) {
        console.error('Error:', err);
        throw new Error('Operation failed');
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag proper handling');
  });
});

describe('SecretDetector', () => {
  const engine = new SecretDetector();

  test('should detect hardcoded API keys', async () => {
    // Use pattern that matches Stripe format but won't trigger GitHub push protection
    const prefix = 'sk_live';
    const suffix = '_4eC39HqLyjWDarjtT1zdp7dc';
    const code = `const apiKey = '${prefix + suffix}';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect Stripe API key');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.confidence, 'Should have confidence field');
    assert.strictEqual(issue.confidence, 'high', 'Should have high confidence');
  });

  test('should detect GitHub tokens', async () => {
    const code = `const token = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    const validIssues = issues.filter(i => i !== null);
    assert.ok(validIssues.length > 0, 'Should detect GitHub token');
  });

  test('should detect private keys', async () => {
    const code = `const key = '-----BEGIN RSA PRIVATE KEY-----';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.ok(issues.length > 0, 'Should detect private key');
  });

  test('should not flag environment variables', async () => {
    const code = `const apiKey = process.env.API_KEY;`;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag env vars');
  });

  test('should not flag placeholder values', async () => {
    const code = `const apiKey = 'YOUR_API_KEY_HERE';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag placeholders');
  });
});

describe('SecretDetector - URL-form secrets', () => {
  const engine = new SecretDetector();

  test('should detect Slack webhook URL', async () => {
    const code = `const url = 'https://hooks.slack.com/services/TABCDE123/BABCDE123/abcdefghijklmnop123456';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect Slack webhook in URL string');
  });

  test('should detect Discord webhook URL', async () => {
    const code = `const url = 'https://discordapp.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect Discord webhook in URL string');
  });

  test('should detect PostgreSQL connection URL with credentials', async () => {
    const code = `const db = 'postgresql://admin:s3cr3tpassword@prod-host.example.com/mydb';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect PostgreSQL credentials in URL');
  });

  test('should detect MongoDB connection URL with credentials', async () => {
    const code = `const uri = 'mongodb+srv://user:hunter2@cluster.example.mongodb.net/mydb';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect MongoDB credentials in URL');
  });

  test('should detect Sentry DSN', async () => {
    const code = `const dsn = 'https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/1234567';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect Sentry DSN');
  });

  test('should detect Stripe test key (sk_test_)', async () => {
    const key = 'sk_test_' + '4eC39HqLyjWDarjtT1zdp7dc'; // split to avoid push-protection false positive
    const code = `const key = '${key}';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect sk_test_ Stripe key — test keys are still secrets');
  });

  test('should not flag a non-credential file path string', async () => {
    const code = `const file = 'src/migrations/001_create_users.sql';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should not flag plain file paths');
  });
});

describe('Suppression Comments', () => {
  const engine = new MissingAwaitDetector();

  test('should respect codedrift-disable-next-line', async () => {
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        // codedrift-disable-next-line
        fetchData();
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should suppress issue');
  });

  test('should respect inline disable', async () => {
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        fetchData(); // codedrift-disable-line
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);

    assert.strictEqual(issues.filter(i => i !== null).length, 0, 'Should suppress inline issue');
  });
});

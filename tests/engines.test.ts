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
import { UnsafeRegexDetector } from '../src/engines/unsafe-regex-detector.js';
import { MissingInputValidationDetector } from '../src/engines/missing-input-validation-detector.js';
import { IDORDetector } from '../src/engines/idor-detector.js';
import { ConsoleInProductionDetector } from '../src/engines/console-in-production-detector.js';
import { shouldAutoIgnore } from '../src/core/smart-filters.js';

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

// ═══════════════════════════════════════════════════════════════════════════════
// v1.3.0 Engine Improvement Tests
// ═══════════════════════════════════════════════════════════════════════════════

describe('UnsafeRegexDetector - Dynamic RegExp from user input', () => {
  const engine = new UnsafeRegexDetector();

  test('should detect new RegExp(req.query.search)', async () => {
    const code = `
      function handler(req, res) {
        const regex = new RegExp(req.query.search);
        const results = items.filter(i => regex.test(i.name));
        res.json(results);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect user input in RegExp constructor');
    assert.strictEqual(issues[0].severity, 'error', 'Should be CRITICAL severity');
    assert.strictEqual(issues[0].confidence, 'high', 'Should be high confidence');
  });

  test('should detect RegExp(req.body.pattern) without new keyword', async () => {
    const code = `
      function handler(req, res) {
        const regex = RegExp(req.body.pattern);
        res.json(regex.test('test'));
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect RegExp() without new keyword');
  });

  test('should detect user input via variable tracing', async () => {
    const code = `
      function handler(req, res) {
        const search = req.query.search;
        const regex = new RegExp(search);
        res.json(regex.test('test'));
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should trace variable back to req.query');
  });

  test('should detect user input via destructuring', async () => {
    const code = `
      function handler(req, res) {
        const { search } = req.query;
        const regex = new RegExp(search);
        res.json(regex.test('test'));
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should trace destructured variable back to req.query');
  });

  test('should detect user input in template literal', async () => {
    const code = `
      function handler(req, res) {
        const regex = new RegExp(\`^\${req.query.prefix}.*$\`);
        res.json(regex.test('test'));
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect user input in template literal');
  });

  test('should NOT flag static string patterns', async () => {
    const code = `
      const emailRegex = new RegExp('^[a-zA-Z0-9]+@[a-zA-Z]+\\\\.[a-zA-Z]+$');
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    // Should only flag if the static pattern is unsafe (ReDoS), not as user-input injection
    const dynamicIssues = issues.filter(i => i.message.includes('User-controlled'));
    assert.strictEqual(dynamicIssues.length, 0, 'Should not flag static string patterns as user input');
  });

  test('should still detect unsafe static regex patterns', async () => {
    const code = `const bad = new RegExp('(a+)+$');`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should still detect unsafe static regex via safe-regex2');
  });
});

describe('MissingInputValidationDetector - Middleware detection', () => {
  const engine = new MissingInputValidationDetector();

  test('should NOT flag routes with express-validator middleware', async () => {
    const code = `
      import { body, validationResult } from 'express-validator';
      app.post('/users', body('email').isEmail(), body('name').notEmpty(), (req, res) => {
        const { email, name } = req.body;
        db.users.create({ email, name });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag route with express-validator middleware');
  });

  test('should NOT flag routes with celebrate middleware', async () => {
    const code = `
      import { celebrate, Joi } from 'celebrate';
      app.post('/users', celebrate({ body: Joi.object({ email: Joi.string() }) }), (req, res) => {
        const { email } = req.body;
        db.users.create({ email });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag route with celebrate middleware');
  });

  test('should NOT flag routes with validateBody middleware', async () => {
    const code = `
      app.post('/users', validateBody(userSchema), (req, res) => {
        const { email } = req.body;
        db.users.create({ email });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag route with validateBody middleware');
  });

  test('should NOT flag routes with array-wrapped middleware', async () => {
    const code = `
      app.post('/users', [body('email').isEmail(), body('name').notEmpty()], (req, res) => {
        const { email, name } = req.body;
        db.users.create({ email, name });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag route with array-wrapped middleware');
  });

  test('should still flag routes WITHOUT validation middleware', async () => {
    const code = `
      app.post('/users', (req, res) => {
        const { email, role } = req.body;
        db.users.create({ email, role });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag route without any validation');
  });
});

describe('SecretDetector - Migration filename false positive', () => {
  const engine = new SecretDetector();

  test('should NOT flag migration filenames', async () => {
    const code = `runMigration('006_increase_blnk_reconciliation_id_length.sql');`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag migration filename');
  });

  test('should NOT flag file paths with extensions', async () => {
    const code = `const file = 'data/007_add_user_permissions_table.sql';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag file path with .sql extension');
  });

  test('should NOT flag strings in path.join()', async () => {
    const code = `const p = path.join('migrations', '008_update_account_settings.sql');`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag string argument to path.join');
  });

  test('should still detect real Okta tokens', async () => {
    // Real Okta tokens have high entropy (random alphanumeric)
    const code = `const token = '00AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should still detect high-entropy Okta-format tokens');
  });
});

describe('EmptyCatchDetector - Logger and monitoring recognition', () => {
  const engine = new EmptyCatchDetector();

  test('should NOT flag catch with logger.error(err)', async () => {
    const code = `
      try { riskyOperation(); }
      catch (err) {
        logger.error(err);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag catch with logger.error');
  });

  test('should NOT flag catch with Sentry.captureException(err)', async () => {
    const code = `
      try { riskyOperation(); }
      catch (err) {
        Sentry.captureException(err);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag catch with Sentry');
  });

  test('should NOT flag catch with newrelic.noticeError(err)', async () => {
    const code = `
      try { riskyOperation(); }
      catch (err) {
        newrelic.noticeError(err);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag catch with newrelic');
  });

  test('should NOT flag catch with error passed to any function', async () => {
    const code = `
      try { riskyOperation(); }
      catch (err) {
        handleError(err);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag catch with error passed to function');
  });

  test('should NOT flag catch with instanceof check', async () => {
    const code = `
      try { riskyOperation(); }
      catch (err) {
        if (err instanceof TypeError) {
          console.log('type error');
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag catch with instanceof check');
  });

  test('should NOT flag catch with wrapped rethrow', async () => {
    const code = `
      try { riskyOperation(); }
      catch (err) {
        throw new AppError('Operation failed', err);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag catch with wrapped rethrow');
  });

  test('should still flag truly empty catch with named binding', async () => {
    const code = `
      try { riskyOperation(); }
      catch (err) {
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should still flag empty catch with named binding');
  });
});

describe('MissingAwaitDetector - Framework context skips', () => {
  const engine = new MissingAwaitDetector();

  test('should NOT flag async calls inside setTimeout', async () => {
    const code = `
      async function fetchData() { return {}; }
      setTimeout(async () => {
        fetchData();
      }, 1000);
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag async call inside setTimeout');
  });

  test('should NOT flag async calls inside test callbacks', async () => {
    const code = `
      async function fetchData() { return {}; }
      it('should work', async () => {
        fetchData();
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag async call inside test callback');
  });

  test('should NOT flag async calls in Express route handlers', async () => {
    const code = `
      async function fetchData() { return {}; }
      app.get('/api/data', async (req, res) => {
        fetchData();
        res.json({});
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag async call in Express route handler');
  });

  test('should NOT flag async calls in event handlers', async () => {
    const code = `
      async function processEvent() { return {}; }
      emitter.on('data', async () => {
        processEvent();
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag async call in event handler');
  });

  test('should still flag missing await in regular async functions', async () => {
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        return fetchData();
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should still flag missing await in regular async functions');
  });
});

describe('IDORDetector - Expanded coverage', () => {
  const engine = new IDORDetector();

  test('should detect IDOR on delete operations', async () => {
    const code = `
      app.delete('/api/posts/:id', auth, async (req, res) => {
        await db.posts.deleteById(req.params.id);
        res.json({ success: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect IDOR on deleteById');
  });

  test('should detect IDOR on update operations', async () => {
    const code = `
      app.put('/api/posts/:id', auth, async (req, res) => {
        await db.posts.findByIdAndUpdate(req.params.id, req.body);
        res.json({ success: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect IDOR on findByIdAndUpdate');
  });

  test('should recognize tenantId as ownership field', async () => {
    const code = `
      app.get('/api/docs/:id', async (req, res) => {
        const doc = await db.docs.findById(req.params.id);
        if (doc.tenantId !== req.user.tenantId) return res.status(403).json({});
        res.json(doc);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should recognize tenantId as ownership check');
  });
});

// ─── Change 1: Spread Operator Detection ───
describe('Missing Input Validation - Spread Operator', () => {
  const engine = new MissingInputValidationDetector();

  test('should detect spread of req.body in object literal', async () => {
    const code = `
      app.post('/api/users', async (req, res) => {
        const user = await db.users.create({ ...req.body });
        res.json(user);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect spread of req.body');
    assert.ok(issues.some(i => i.message.includes('spread') || i.message.includes('req.body')));
  });

  test('should not flag spread when validation middleware is present', async () => {
    const code = `
      app.post('/api/users', validateBody(schema), async (req, res) => {
        const user = await db.users.create({ ...req.body });
        res.json(user);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag when validation middleware present');
  });
});

// ─── Change 2: req.files Detection ───
describe('Missing Input Validation - File Upload', () => {
  const engine = new MissingInputValidationDetector();

  test('should detect req.files without validation', async () => {
    const code = `
      app.post('/api/upload', async (req, res) => {
        const file = req.file;
        await saveFile(file);
        res.json({ ok: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect req.file without validation');
    assert.ok(issues.some(i => i.message.includes('req.file')));
  });

  test('should detect req.files without validation', async () => {
    const code = `
      app.post('/api/upload', async (req, res) => {
        const files = req.files;
        await processFiles(files);
        res.json({ ok: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect req.files without validation');
  });
});

// ─── Change 3: Console Config File Skip ───
describe('Console in Production - Config File Skip', () => {
  const engine = new ConsoleInProductionDetector();

  test('should skip console calls in config files', async () => {
    const code = `
      console.log('Building project...');
      console.info('Compilation complete');
    `;
    const context = createContext(code, 'webpack.config.ts');
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip config files');
  });

  test('should skip console calls in vite config', async () => {
    const code = `
      console.log('Vite config loaded');
    `;
    const context = createContext(code, 'vite.config.ts');
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip vite config');
  });
});

// ─── Change 4: Console Debug Method Distinction ───
describe('Console in Production - Debug Methods', () => {
  const engine = new ConsoleInProductionDetector();

  test('should flag console.table as info severity debug utility', async () => {
    const code = `
      function processData(data: any) {
        console.table(data);
        return data;
      }
    `;
    const context = createContext(code, 'src/service.ts');
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag console.table');
    assert.strictEqual(issues[0].severity, 'info', 'Should be info severity');
    assert.ok(issues[0].message.includes('debug utility'));
  });

  test('should flag console.time as info severity debug utility', async () => {
    const code = `
      function runTask() {
        console.time('task');
        doWork();
        console.timeEnd('task');
      }
    `;
    const context = createContext(code, 'src/service.ts');
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag console.time/timeEnd');
    assert.ok(issues.every(i => i.severity === 'info'), 'All should be info severity');
  });

  test('should still flag console.log as warning', async () => {
    const code = `
      function processData() {
        console.log('processing...');
      }
    `;
    const context = createContext(code, 'src/service.ts');
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag console.log');
    assert.ok(issues.some(i => i.severity === 'warning' || i.severity === 'error'), 'console.log should not be info');
  });
});

// ─── Change 5: NestJS Decorated Handlers for Missing Await ───
describe('Missing Await - NestJS Handlers', () => {
  const engine = new MissingAwaitDetector();

  test('should skip missing-await in NestJS @Get handler', async () => {
    const code = `
      class UserController {
        @Get('/users')
        async getUsers() {
          fetchExternalData();
          return [];
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip NestJS @Get handler');
  });

  test('should skip missing-await in NestJS @Post handler', async () => {
    const code = `
      class UserController {
        @Post('/users')
        async createUser() {
          saveToCache();
          return { ok: true };
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip NestJS @Post handler');
  });
});

// ─── Change 6: Promise.all Context Skip ───
describe('Missing Await - Promise.all Context', () => {
  const engine = new MissingAwaitDetector();

  test('should skip missing-await inside Promise.all', async () => {
    const code = `
      async function processAll(items: string[]) {
        await Promise.all(items.map(async (item) => {
          fetchData(item);
        }));
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip inside Promise.all');
  });

  test('should skip missing-await inside Promise.allSettled', async () => {
    const code = `
      async function tryAll(ids: string[]) {
        await Promise.allSettled(ids.map(async (id) => {
          loadItem(id);
        }));
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip inside Promise.allSettled');
  });
});

// ─── Change 7: Empty Catch Expected Error Patterns ───
describe('Empty Catch - Expected Error Patterns', () => {
  const engine = new EmptyCatchDetector();

  test('should skip empty catch for fs.access probe', async () => {
    const code = `
      async function fileExists(path: string) {
        try {
          await fs.access(path);
          return true;
        } catch (e) {
          return false;
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip fs.access probe pattern');
  });

  test('should skip empty catch for JSON.parse', async () => {
    const code = `
      function tryParse(str: string) {
        try {
          return JSON.parse(str);
        } catch (e) {
          return null;
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip JSON.parse probe pattern');
  });

  test('should skip empty catch for optional require', async () => {
    const code = `
      let optionalDep;
      try {
        optionalDep = require('optional-package');
      } catch (e) {
        optionalDep = null;
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip optional require pattern');
  });

  test('should still flag genuinely empty catch with no probe', async () => {
    const code = `
      async function doWork() {
        try {
          await saveData();
        } catch (e) {
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag empty catch for non-probe calls');
  });
});

// ─── Change 8: Stack Trace Development Guard ───
describe('Stack Trace - Development Guard', () => {
  const engine = new StackTraceDetector();

  test('should skip stack exposure inside NODE_ENV development guard', async () => {
    const code = `
      app.use((err, req, res, next) => {
        if (process.env.NODE_ENV !== 'production') {
          res.json({ message: err.message, stack: err.stack });
        } else {
          res.json({ message: 'Internal error' });
        }
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip stack exposure inside dev guard');
  });

  test('should still flag stack exposure without guard', async () => {
    const code = `
      app.use((err, req, res, next) => {
        res.json({ message: err.message, stack: err.stack });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag stack exposure without guard');
  });
});

// ─── Change 9: GraphQL formatError Stack Exposure ───
describe('Stack Trace - GraphQL formatError', () => {
  const engine = new StackTraceDetector();

  test('should detect stack trace in formatError', async () => {
    const code = `
      const server = new ApolloServer({
        typeDefs,
        resolvers,
        formatError: (err) => ({
          message: err.message,
          stack: err.stack,
        }),
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect stack in formatError');
    assert.ok(issues.some(i => i.message.includes('formatError') || i.message.includes('GraphQL')));
  });

  test('should detect spread of error in formatError', async () => {
    const code = `
      const server = new ApolloServer({
        formatError: (err) => ({
          ...err,
          code: 'SERVER_ERROR',
        }),
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect error spread in formatError');
  });

  test('should skip formatError with dev guard', async () => {
    const code = `
      if (process.env.NODE_ENV === 'development') {
        const server = new ApolloServer({
          formatError: (err) => ({
            message: err.message,
            stack: err.stack,
          }),
        });
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip formatError inside dev guard');
  });
});

// ─── Change 10: Raw SQL IDOR Detection ───
describe('IDOR - Raw SQL Detection', () => {
  const engine = new IDORDetector();

  test('should detect raw SQL IDOR with parameterized user input', async () => {
    const code = `
      app.get('/api/orders/:id', auth, async (req, res) => {
        const order = await db.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
        res.json(order);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect raw SQL IDOR');
  });

  test('should skip raw SQL with ownership clause', async () => {
    const code = `
      app.get('/api/orders/:id', auth, async (req, res) => {
        const order = await db.query('SELECT * FROM orders WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id]);
        res.json(order);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip SQL with ownership clause');
  });

  test('should detect raw SQL IDOR with template literal', async () => {
    const code = `
      app.get('/api/orders/:id', auth, async (req, res) => {
        const order = await db.query(\`SELECT * FROM orders WHERE id = \${req.params.id}\`);
        res.json(order);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect template literal SQL IDOR');
  });

  test('should not flag generic query calls without SQL', async () => {
    const code = `
      app.get('/api/orders/:id', auth, async (req, res) => {
        const order = await db.query({ where: { id: req.params.id } });
        res.json(order);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag ORM-style query without SQL keywords');
  });
});

// =============================================
// Fix #1: this.* async method detection
// =============================================
describe('MissingAwaitDetector - this.* async method calls', () => {
  const engine = new MissingAwaitDetector();

  test('should flag unawaited this.save() when save is async', async () => {
    const code = `
      class UserService {
        async save(data: any) {
          await db.insert(data);
        }

        async process(data: any) {
          this.save(data);
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag unawaited this.save() when save is declared async');
  });

  test('should not flag this.syncHelper() when method is not async', async () => {
    const code = `
      class UserService {
        formatData(data: any) {
          return { ...data, formatted: true };
        }

        async process(data: any) {
          this.formatData(data);
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag non-async this.* calls');
  });

  test('should not flag awaited this.asyncMethod()', async () => {
    const code = `
      class UserService {
        async save(data: any) {
          await db.insert(data);
        }

        async process(data: any) {
          await this.save(data);
        }
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag properly awaited this.* calls');
  });
});

// =============================================
// Fix #2: Smart filter - medium IDOR preservation
// =============================================
describe('Smart Filters - IDOR confidence handling', () => {
  test('should NOT auto-ignore medium confidence IDOR issues', () => {
    const mediumIDOR: any = {
      engine: 'idor',
      message: 'Database query using user-supplied ID without authorization check',
      filePath: 'src/routes/orders.ts',
      confidence: 'medium',
      severity: 'error',
      location: { line: 10, column: 5 },
    };
    const ignored = shouldAutoIgnore(mediumIDOR);
    assert.strictEqual(ignored, false, 'Medium confidence IDOR should NOT be auto-ignored');
  });

  test('should auto-ignore low confidence IDOR issues', () => {
    const lowIDOR: any = {
      engine: 'idor',
      message: 'Database query using user-supplied ID without authorization check',
      filePath: 'src/routes/orders.ts',
      confidence: 'low',
      severity: 'warning',
      location: { line: 10, column: 5 },
    };
    const ignored = shouldAutoIgnore(lowIDOR);
    assert.strictEqual(ignored, true, 'Low confidence IDOR should be auto-ignored');
  });
});

// =============================================
// Fix #3: Smart filter - update not fire-and-forget
// =============================================
describe('Smart Filters - update method not fire-and-forget', () => {
  test('should NOT auto-ignore missing-await for updateUser', () => {
    const updateIssue: any = {
      engine: 'missing-await',
      message: "Async function 'updateUser' called without await",
      filePath: 'src/services/user.ts',
      confidence: 'high',
      severity: 'error',
      location: { line: 20, column: 5 },
    };
    const ignored = shouldAutoIgnore(updateIssue);
    assert.strictEqual(ignored, false, 'updateUser missing-await should NOT be auto-ignored');
  });

  test('should still auto-ignore fire-and-forget log/track/emit patterns', () => {
    const logIssue: any = {
      engine: 'missing-await',
      message: "Async function 'logEvent' called without await",
      filePath: 'src/services/analytics.ts',
      confidence: 'medium',
      severity: 'warning',
      location: { line: 15, column: 5 },
    };
    const ignored = shouldAutoIgnore(logIssue);
    assert.strictEqual(ignored, true, 'logEvent should still be auto-ignored as fire-and-forget');
  });
});

// =============================================
// Fix #4: Bare id in service layer (not route handler)
// =============================================
describe('IDORDetector - bare id in service vs route handler', () => {
  const engine = new IDORDetector();

  test('should not flag bare id in service-layer function', async () => {
    const code = `
      async function getOrder(id: string) {
        const order = await db.findById(id);
        return order;
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag bare id in service-layer functions');
  });

  test('should flag bare id inside route handler with req/res params', async () => {
    const code = `
      app.get('/orders/:id', auth, async (req, res) => {
        const { id } = req.params;
        const order = await db.findById(id);
        res.json(order);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should flag id inside route handler');
  });
});

// =============================================
// Fix #5: Confidence boost before severity adjustment
// =============================================
describe('Analyzer - confidence boost ordering', () => {
  // This is a structural test - we verify the analyzer.ts pipeline order
  // by checking that the source code has the correct ordering
  test('confidence boost should appear before adjustSeverities call', async () => {
    const fs = await import('node:fs');
    const analyzerSrc = fs.readFileSync('src/core/analyzer.ts', 'utf-8');
    const boostIndex = analyzerSrc.indexOf('shouldBoostConfidence');
    const severityIndex = analyzerSrc.indexOf('adjustSeverities(');
    assert.ok(boostIndex > 0, 'shouldBoostConfidence should exist in analyzer.ts');
    assert.ok(severityIndex > 0, 'adjustSeverities should exist in analyzer.ts');
    assert.ok(boostIndex < severityIndex, 'Confidence boost should come BEFORE severity adjustment');
  });
});

// =============================================
// Fix #6: Per-field typeof validation
// =============================================
describe('MissingInputValidationDetector - per-field typeof validation', () => {
  const engine = new MissingInputValidationDetector();

  test('single typeof check should NOT suppress all field warnings', async () => {
    const code = `
      app.post('/api/users', async (req, res) => {
        if (typeof req.body.name === 'string') {
          // only name is validated
        }
        const { name, email, role } = req.body;
        await db.create({ name, email, role });
        res.json({ ok: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    // Should still report issues because email and role are NOT validated
    assert.ok(issues.length > 0, 'Should still flag unvalidated fields even when one field has typeof check');
  });

  test('all fields validated with typeof should suppress warning', async () => {
    const code = `
      app.post('/api/users', async (req, res) => {
        if (typeof req.body.name === 'string') {}
        if (typeof req.body.email === 'string') {}
        const { name, email } = req.body;
        await db.create({ name, email });
        res.json({ ok: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag when all accessed fields have typeof checks');
  });

  test('validation libraries should still suppress all warnings', async () => {
    const code = `
      app.post('/api/users', async (req, res) => {
        const validated = schema.validate(req.body);
        const { name, email, role } = validated;
        await db.create({ name, email, role });
        res.json({ ok: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Validation library should still suppress all warnings');
  });
});

// =============================================
// Medium #7: Template literal secret detection
// =============================================
describe('SecretDetector - template literal detection', () => {
  const engine = new SecretDetector();

  test('should detect secret in no-substitution template literal', async () => {
    const code = 'const key = `ghp_abc123def456ghi789jkl012mno345pqr678`;';
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect GitHub PAT in backtick string');
    assert.ok(issues[0].message.includes('GitHub'), 'Should identify as GitHub token');
  });

  test('should detect secret prefix in template expression head', async () => {
    const code = 'const url = `sk_live_${suffix}`;';
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect Stripe key prefix in template head');
  });

  test('should not flag template literals without secrets', async () => {
    const code = 'const msg = `Hello ${name}, welcome!`;';
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Normal template literals should not be flagged');
  });
});

// =============================================
// Medium #8: IDOR /model/i too broad
// =============================================
describe('IDORDetector - model regex precision', () => {
  const engine = new IDORDetector();

  test('should not flag viewModel.fetch() as database operation', async () => {
    const code = `
      app.get('/items/:id', auth, async (req, res) => {
        const item = await viewModel.fetch(req.params.id);
        res.json(item);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'viewModel should not be treated as a database model');
  });

  test('should still flag UserModel.fetch() as database operation', async () => {
    const code = `
      app.get('/users/:id', auth, async (req, res) => {
        const user = await UserModel.fetch(req.params.id);
        res.json(user);
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'UserModel should be treated as a database model');
  });
});

// =============================================
// Medium #9: isValidationIdentifier false match
// =============================================
describe('MissingInputValidationDetector - validation identifier precision', () => {
  const engine = new MissingInputValidationDetector();

  test('should not treat invalidateCache as validation middleware', async () => {
    const code = `
      app.post('/api/data', invalidateCache, async (req, res) => {
        const { name } = req.body;
        await db.create({ name });
        res.json({ ok: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'invalidateCache should not suppress validation warnings');
  });

  test('should still recognize validateBody as validation middleware', async () => {
    const code = `
      app.post('/api/data', validateBody(schema), async (req, res) => {
        const { name } = req.body;
        await db.create({ name });
        res.json({ ok: true });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'validateBody should still be recognized as validation');
  });
});

// =============================================
// Medium #10: e variable context-awareness
// =============================================
describe('StackTraceDetector - e variable context', () => {
  const engine = new StackTraceDetector();

  test('should not flag e.stack in event handler as stack trace exposure', async () => {
    const code = `
      app.get('/test', (req, res) => {
        element.addEventListener('click', (e) => {
          res.json({ data: e.stack });
        });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'e.stack in event handler should not be flagged');
  });

  test('should flag e.stack in catch clause as stack trace exposure', async () => {
    const code = `
      app.get('/test', (req, res) => {
        try {
          doSomething();
        } catch (e) {
          res.json({ stack: e.stack });
        }
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'e.stack in catch clause should be flagged');
  });
});

// =============================================
// Medium #11: err.toString() not a stack trace
// =============================================
describe('StackTraceDetector - err.toString() not stack trace', () => {
  const engine = new StackTraceDetector();

  test('should not flag err.toString() as stack trace exposure', async () => {
    const code = `
      app.get('/test', (req, res) => {
        try {
          doSomething();
        } catch (err) {
          res.json({ message: err.toString() });
        }
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'err.toString() returns message only, not stack trace');
  });
});

// =============================================
// Medium #13: Dead engine names in severity-adjuster
// =============================================
describe('Severity adjuster - engine name validity', () => {
  test('severity-adjuster should not reference non-existent engines', async () => {
    const fs = await import('node:fs');
    const src = fs.readFileSync('src/core/severity-adjuster.ts', 'utf-8');
    assert.ok(!src.includes("'secret-detector'"), 'secret-detector is not a valid engine name');
    assert.ok(!src.includes("'sql-injection-detector'"), 'sql-injection-detector does not exist');
    assert.ok(!src.includes("'xss-detector'"), 'xss-detector does not exist');
    assert.ok(src.includes("'hardcoded-secret'"), 'hardcoded-secret should be present');
  });
});

// =============================================
// Medium #14: Parallel engine execution
// =============================================
describe('Analyzer - parallel engine execution', () => {
  test('analyzer should use Promise.all for engine execution', async () => {
    const fs = await import('node:fs');
    const src = fs.readFileSync('src/core/analyzer.ts', 'utf-8');
    assert.ok(src.includes('Promise.all'), 'Engines should run in parallel with Promise.all');
  });
});

// =============================================
// Medium #15: RegExp() without new checked for ReDoS
// =============================================
describe('UnsafeRegexDetector - RegExp() call without new', () => {
  const engine = new UnsafeRegexDetector();

  test('should detect ReDoS in RegExp() call without new', async () => {
    const code = "const re = RegExp('(a+)+');";
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect ReDoS in RegExp() call without new keyword');
    assert.ok(issues[0].message.includes('ReDoS'), 'Should mention ReDoS');
  });

  test('should still detect ReDoS in new RegExp()', async () => {
    const code = "const re = new RegExp('(a+)+');";
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect ReDoS in new RegExp() too');
  });
});

// ─── LOW #16: Koa/Hapi framework detection ──────────────────────────────────

describe('IDOR Detector - Koa/Hapi framework support', () => {
  const engine = new IDORDetector();

  test('should detect IDOR with Koa ctx.params', async () => {
    const code = `
      router.get('/users/:id', auth, async (ctx) => {
        const user = await User.findById(ctx.params.id);
        ctx.body = user;
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect IDOR via ctx.params.id');
  });

  test('should detect IDOR with Hapi request.params', async () => {
    const code = `
      server.route({
        method: 'GET',
        path: '/orders/{id}',
        handler: async (request, h) => {
          const order = await Order.findById(request.params.id);
          return order;
        }
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect IDOR via request.params.id in Hapi');
  });

  test('should skip IDOR with Koa when ctx.state.user ownership check exists', async () => {
    const code = `
      router.get('/docs/:id', auth, async (ctx) => {
        const doc = await Doc.findById(ctx.params.id);
        if (doc.userId !== ctx.state.user.id) {
          ctx.status = 403;
          return;
        }
        ctx.body = doc;
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should skip when ctx.state.user ownership check exists');
  });
});

describe('Missing Input Validation - Koa/Hapi framework support', () => {
  const engine = new MissingInputValidationDetector();

  test('should detect missing validation with Koa ctx.request.body', async () => {
    const code = `
      router.post('/users', async (ctx) => {
        const user = await User.create(ctx.request.body);
        ctx.body = user;
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect unvalidated ctx.request.body');
  });

  test('should detect missing validation with Hapi request.payload', async () => {
    const code = `
      server.route({
        method: 'POST',
        path: '/users',
        handler: async (request, h) => {
          const user = await User.create(request.payload);
          return user;
        }
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect unvalidated request.payload in Hapi');
  });
});

// ─── LOW #17: Cross-file async detection heuristics ─────────────────────────

describe('Missing Await - Cross-file heuristics', () => {
  const engine = new MissingAwaitDetector();

  test('should detect likely async function by naming convention (fetchUsers)', async () => {
    const code = `
      import { fetchUsers } from './user-service';

      async function handler() {
        fetchUsers();
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect fetchUsers as likely async');
    assert.ok(issues.some(i => i.confidence === 'medium'), 'Should have medium confidence for heuristic');
  });

  test('should detect async function imported from service module', async () => {
    const code = `
      import { processOrder } from './order-service';

      async function handler() {
        processOrder(orderId);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    // processOrder doesn't match async naming but is from a -service module
    assert.ok(issues.length > 0, 'Should detect function from service module as likely async');
  });

  test('should detect async when function is awaited elsewhere in file', async () => {
    const code = `
      import { transform } from './utils';

      async function handler1() {
        const a = await transform(data);
        return a;
      }

      async function handler2() {
        transform(data);
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should detect missing await when function is awaited elsewhere');
  });

  test('should not flag getName as likely async (simple getter)', async () => {
    const code = `
      async function handler() {
        const name = getName();
        console.log(name);
      }

      function getName() {
        return 'test';
      }
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag getName as async');
  });
});

// ─── LOW #18: Global middleware validation suppression ───────────────────────

describe('Missing Input Validation - Global middleware detection', () => {
  const engine = new MissingInputValidationDetector();

  test('should suppress validation warnings when app.use(validate()) is present', async () => {
    const code = `
      app.use(validate());

      app.post('/users', (req, res) => {
        const { email, name } = req.body;
        res.json({ email, name });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should suppress when global validate() middleware exists');
  });

  test('should suppress validation warnings when app.use(celebrate()) is present', async () => {
    const code = `
      app.use(celebrate({ body: Joi.object({}) }));

      app.post('/items', (req, res) => {
        const { title } = req.body;
        res.json({ title });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should suppress when global celebrate() middleware exists');
  });

  test('should still flag when no global validation middleware', async () => {
    const code = `
      app.use(cors());
      app.use(express.json());

      app.post('/users', (req, res) => {
        const { email, name } = req.body;
        res.json({ email, name });
      });
    `;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should still flag when no global validation exists');
  });
});

// ─── LOW #19: calculateEntropy deduplication ────────────────────────────────

describe('Secret Detector - Uses shared calculateEntropy', () => {
  const engine = new SecretDetector();

  test('should still detect high-entropy secrets after deduplication', async () => {
    const code = `const API_KEY = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.ok(issues.length > 0, 'Should still detect high-entropy strings using shared calculateEntropy');
  });

  test('should not flag low-entropy strings', async () => {
    const code = `const greeting = 'hello world';`;
    const context = createContext(code);
    const issues = await engine.analyze(context);
    assert.strictEqual(issues.length, 0, 'Should not flag low-entropy strings');
  });
});

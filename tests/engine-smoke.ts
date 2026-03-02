/**
 * Smoke tests: every engine gets a "should fire" + "should not fire" case.
 * Covers engines that have no dedicated tests in engines.test.ts.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert';
import { parseSource } from '../src/core/parser.js';
import { HallucinatedDepsDetector }       from '../src/engines/hallucinated-deps-detector.js';
import { StackTraceDetector }             from '../src/engines/stack-trace-detector.js';
import { MissingAwaitDetector }           from '../src/engines/missing-await-detector.js';
import { AsyncForEachDetector }           from '../src/engines/async-foreach-detector.js';
import { EmptyCatchDetector }             from '../src/engines/empty-catch-detector.js';
import { SecretDetector }                 from '../src/engines/secret-detector.js';
import { ConsoleInProductionDetector }    from '../src/engines/console-in-production-detector.js';
import { MissingInputValidationDetector } from '../src/engines/missing-input-validation-detector.js';
import { UnsafeRegexDetector }            from '../src/engines/unsafe-regex-detector.js';
import { IDORDetector }                   from '../src/engines/idor-detector.js';

const mockResolver = {
  packageExists:        (pkg: string) => ['express', 'react', 'winston'].includes(pkg),
  packageExistsForFile: (pkg: string) => ['express', 'react', 'winston'].includes(pkg),
};

function ctx(code: string, filePath = 'app.ts', withPkg = false) {
  return {
    sourceFile: parseSource(code, filePath),
    filePath,
    content: code,
    packageResolver: withPkg ? (mockResolver as any) : undefined,
    metadata: { isTestFile: false },
  };
}

// ── HallucinatedDepsDetector ──────────────────────────────────────────────
describe('Smoke: HallucinatedDepsDetector', () => {
  const e = new HallucinatedDepsDetector();

  test('fires on missing package', async () => {
    const issues = await e.analyze(ctx(`import x from 'nonexistent-pkg';`, 'app.ts', true));
    assert.ok(issues.length > 0, 'Should flag missing package');
  });
  test('does not fire on installed package', async () => {
    const issues = await e.analyze(ctx(`import x from 'express';`, 'app.ts', true));
    assert.strictEqual(issues.length, 0, 'Should not flag installed package');
  });
  test('does not fire on @/ path alias', async () => {
    const issues = await e.analyze(ctx(`import x from '@/utils';`, 'app.ts', true));
    assert.strictEqual(issues.length, 0, 'Should not flag @/ alias');
  });
  test('does not fire on #components subpath import', async () => {
    const issues = await e.analyze(ctx(`import x from '#components/Button';`, 'app.ts', true));
    assert.strictEqual(issues.length, 0, 'Should not flag # subpath import');
  });
  test('does not fire on relative import', async () => {
    const issues = await e.analyze(ctx(`import x from './utils';`, 'app.ts', true));
    assert.strictEqual(issues.length, 0, 'Should not flag relative import');
  });
  test('does not fire on node built-in', async () => {
    const issues = await e.analyze(ctx(`import fs from 'fs';`, 'app.ts', true));
    assert.strictEqual(issues.length, 0, 'Should not flag node:fs built-in');
  });
});

// ── StackTraceDetector ────────────────────────────────────────────────────
describe('Smoke: StackTraceDetector', () => {
  const e = new StackTraceDetector();

  test('fires on err.stack sent in response', async () => {
    const code = `app.get('/x', (req, res) => { res.json({ trace: err.stack }); });`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag err.stack in response');
  });
  test('does not fire on err.stack only in logger', async () => {
    const code = `logger.error('Something failed', { stack: err.stack });`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag err.stack in logger');
  });
});

// ── MissingAwaitDetector ──────────────────────────────────────────────────
describe('Smoke: MissingAwaitDetector', () => {
  const e = new MissingAwaitDetector();

  test('fires on unawaited async call', async () => {
    const code = `async function saveUser() {}
async function handler() { saveUser(); }`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag missing await');
  });
  test('does not fire when properly awaited', async () => {
    const code = `async function saveUser() {}
async function handler() { await saveUser(); }`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag awaited call');
  });
  test('does not fire when assigned then awaited', async () => {
    const code = `async function saveUser() {}
async function handler() { const p = saveUser(); await p; }`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag assigned-then-awaited');
  });
});

// ── AsyncForEachDetector ──────────────────────────────────────────────────
describe('Smoke: AsyncForEachDetector', () => {
  const e = new AsyncForEachDetector();

  test('fires on async forEach callback', async () => {
    const code = `items.forEach(async (item) => { await db.save(item); });`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag async forEach');
  });
  test('does not fire on Promise.all(map(...))', async () => {
    const code = `await Promise.all(items.map(async (item) => { await db.save(item); }));`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag Promise.all wrapped map');
  });
  test('fires on async map without Promise.all', async () => {
    const code = `items.map(async (item) => { await db.save(item); });`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag un-awaited async map');
  });
});

// ── EmptyCatchDetector ────────────────────────────────────────────────────
describe('Smoke: EmptyCatchDetector', () => {
  const e = new EmptyCatchDetector();

  test('fires on completely empty catch block', async () => {
    const code = `try { doSomething(); } catch (e) {}`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag empty catch');
  });
  test('fires on catch with only a comment', async () => {
    const code = `try { doSomething(); } catch (e) { /* intentional */ }`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag comment-only catch');
  });
  test('flags bare rethrow as useless (adds no context)', async () => {
    // throw e with no logging/wrapping is a useless rethrow — engine correctly flags it
    const code = `try { doSomething(); } catch (e) { throw e; }`;
    const issues = await e.analyze(ctx(code));
    assert.ok(issues.length > 0, 'Bare rethrow should be flagged as useless (adds no context)');
    assert.ok(issues.some(i => i?.confidence === 'low'), 'Useless rethrow should have low confidence');
  });
  test('does not fire when error is logged and rethrown', async () => {
    const code = `try { doSomething(); } catch (e) { logger.error('failed', e); throw e; }`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag logged+rethrown catch');
  });
});

// ── SecretDetector ────────────────────────────────────────────────────────
describe('Smoke: SecretDetector', () => {
  const e = new SecretDetector();

  test('Layer 1: Stripe live key', async () => {
    const key = 'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc'; // split to avoid push-protection false positive
    assert.ok((await e.analyze(ctx(`const k = '${key}';`))).length > 0);
  });
  test('Layer 1: Stripe test key (not suppressed by isTestValue)', async () => {
    const key = 'sk_test_' + '4eC39HqLyjWDarjtT1zdp7dc'; // split to avoid push-protection false positive
    assert.ok((await e.analyze(ctx(`const k = '${key}';`))).length > 0);
  });
  test('Layer 1: GitHub PAT', async () => {
    assert.ok((await e.analyze(ctx(`const t = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';`))).length > 0);
  });
  test('Layer 1: AWS access key with bodyRegex', async () => {
    // Exactly 20 chars (4 prefix + 16 body of [0-9A-Z]); no placeholder keywords
    assert.ok((await e.analyze(ctx(`const k = 'AKIAIOSFODNN7ABCDEFG';`))).length > 0);
  });
  test('Layer 1: private key header', async () => {
    assert.ok((await e.analyze(ctx(`const k = '-----BEGIN RSA PRIVATE KEY-----';`))).length > 0);
  });
  test('Layer 2: PostgreSQL connection URL', async () => {
    assert.ok((await e.analyze(ctx(`const db = 'postgresql://admin:hunter2@db.prod.internal/mydb';`))).length > 0);
  });
  test('Layer 2: MongoDB connection URL', async () => {
    assert.ok((await e.analyze(ctx(`const db = 'mongodb+srv://user:pass123@cluster.mongodb.net/db';`))).length > 0);
  });
  test('Layer 2: Slack webhook URL', async () => {
    assert.ok((await e.analyze(ctx(`const u = 'https://hooks.slack.com/services/TABC123/BABC123/abcdefghijklmnop';`))).length > 0);
  });
  test('Layer 2: Sentry DSN', async () => {
    assert.ok((await e.analyze(ctx(`const d = 'https://abcdef1234567890abcdef1234567890@o123456.ingest.sentry.io/123';`))).length > 0);
  });
  test('Layer 4: high-entropy string in password variable', async () => {
    assert.ok((await e.analyze(ctx(`const password = 'xK9mP2vR8nQ5wL1zJ4tY7aB3cD6eF0g!';`))).length > 0);
  });
  test('No fire: placeholder value', async () => {
    assert.strictEqual((await e.analyze(ctx(`const k = 'YOUR_API_KEY_HERE';`))).length, 0);
  });
  test('No fire: env var reference', async () => {
    assert.strictEqual((await e.analyze(ctx(`const k = process.env.API_KEY;`))).length, 0);
  });
  test('No fire: file path string', async () => {
    assert.strictEqual((await e.analyze(ctx(`const f = 'src/config/settings.json';`))).length, 0);
  });
  test('No fire: known AWS example key', async () => {
    assert.strictEqual((await e.analyze(ctx(`const k = 'AKIAIOSFODNN7EXAMPLE';`))).length, 0);
  });
  test('No fire: postgres URL with example.com hostname', async () => {
    assert.ok(
      (await e.analyze(ctx(`const db = 'postgresql://admin:s3cr3tpassword@prod-host.example.com/mydb';`))).length > 0,
      'Should still flag credentials even when hostname contains example.com'
    );
  });
});

// ── ConsoleInProductionDetector ───────────────────────────────────────────
describe('Smoke: ConsoleInProductionDetector', () => {
  const e = new ConsoleInProductionDetector();

  test('fires on console.log in production file', async () => {
    const code = `export function handler() { console.log('debug info'); }`;
    assert.ok((await e.analyze(ctx(code, 'src/api/users.ts'))).length > 0);
  });
  test('does not fire in test file', async () => {
    const code = `console.log('test output');`;
    assert.strictEqual((await e.analyze(ctx(code, 'tests/user.test.ts'))).length, 0);
  });
  test('does not fire inside dev-only block', async () => {
    const code = `if (process.env.NODE_ENV === 'development') { console.log('dev only'); }`;
    assert.strictEqual((await e.analyze(ctx(code, 'src/api/users.ts'))).length, 0);
  });
  test('fires on console.log(req.body) even when file imports winston', async () => {
    const code = `import winston from 'winston';
export function handler(req: any) { console.log(req.body); }`;
    assert.ok((await e.analyze(ctx(code, 'src/api/users.ts'))).length > 0,
      'Sensitive console.log must be reported even when logger is imported');
  });
  test('does not fire on non-sensitive console in file that imports winston', async () => {
    const code = `import winston from 'winston';
export function handler() { console.log('starting up'); }`;
    assert.strictEqual((await e.analyze(ctx(code, 'src/api/users.ts'))).length, 0,
      'Non-sensitive console suppressed when proper logger is imported');
  });
  test('does not fire in CLI file', async () => {
    const code = `console.log('Usage: tool <options>');`;
    assert.strictEqual((await e.analyze(ctx(code, 'src/cli.ts'))).length, 0);
  });
});

// ── MissingInputValidationDetector ───────────────────────────────────────
describe('Smoke: MissingInputValidationDetector', () => {
  const e = new MissingInputValidationDetector();

  test('fires on route handler using req.body without validation', async () => {
    const code = `app.post('/user', (req, res) => { db.create(req.body); });`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag missing validation');
  });
  test('does not fire when schema.parse() is used', async () => {
    const code = `app.post('/user', (req, res) => {
  const data = schema.parse(req.body);
  db.create(data);
});`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag when schema.parse used');
  });
  test('does not fire when zod validate() is used', async () => {
    const code = `app.post('/user', (req, res) => {
  const result = userSchema.safeParse(req.body);
  if (!result.success) return res.status(400).json(result.error);
  db.create(result.data);
});`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0);
  });
});

// ── UnsafeRegexDetector ───────────────────────────────────────────────────
describe('Smoke: UnsafeRegexDetector', () => {
  const e = new UnsafeRegexDetector();

  test('fires on ReDoS-vulnerable regex (nested quantifiers)', async () => {
    const code = `const r = /(a+)+$/;`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag ReDoS regex');
  });
  test('fires on catastrophic backtracking pattern', async () => {
    // (x+x+)+ is genuinely catastrophic — safe-regex2 flags this
    const code = `const r = /(x+x+)+y/;`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag catastrophic backtracking');
  });
  test('does not fire on safe anchored regex', async () => {
    const code = `const r = /^[a-z0-9]+$/;`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag safe regex');
  });
  test('does not fire on simple literal regex', async () => {
    const code = `const r = /hello world/;`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag literal regex');
  });
});

// ── IDORDetector ──────────────────────────────────────────────────────────
describe('Smoke: IDORDetector', () => {
  const e = new IDORDetector();

  test('fires on direct req.params.id in findById without auth', async () => {
    const code = `app.get('/doc/:id', async (req, res) => {
  const doc = await db.findById(req.params.id);
  res.json(doc);
});`;
    assert.ok((await e.analyze(ctx(code))).length > 0, 'Should flag IDOR risk');
  });
  test('does not fire when ownership check is present', async () => {
    const code = `app.get('/doc/:id', async (req, res) => {
  const doc = await db.findById(req.params.id);
  if (doc.userId !== req.user.id) return res.status(403).send();
  res.json(doc);
});`;
    assert.strictEqual((await e.analyze(ctx(code))).length, 0, 'Should not flag when auth check present');
  });
});

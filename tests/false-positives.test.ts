/**
 * False-Positive Regression Suite
 *
 * 50+ code patterns that are known to NOT be bugs.
 * Every snippet must produce ZERO findings.
 * If a new engine change causes a regression, one of these tests will catch it.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert';
import { parseSource } from '../src/core/parser.js';
import { MissingAwaitDetector } from '../src/engines/missing-await-detector.js';
import { EmptyCatchDetector } from '../src/engines/empty-catch-detector.js';
import { SecretDetector } from '../src/engines/secret-detector.js';
import { UnsafeRegexDetector } from '../src/engines/unsafe-regex-detector.js';
import { ConsoleInProductionDetector } from '../src/engines/console-in-production-detector.js';
import { MissingInputValidationDetector } from '../src/engines/missing-input-validation-detector.js';
import { StackTraceDetector } from '../src/engines/stack-trace-detector.js';

function createContext(code: string, filePath = 'src/app.ts') {
  const sourceFile = parseSource(code, filePath);
  return { sourceFile, filePath, content: code } as any;
}

async function expectZero(detector: any, code: string, filePath?: string) {
  const ctx = createContext(code, filePath);
  const issues = await detector.analyze(ctx);
  assert.strictEqual(issues.length, 0, `Expected 0 issues but got ${issues.length}: ${issues.map((i: any) => i.message).join('; ')}`);
}

// ════════════════════════════════════════════════════════════════════
// Missing Await — false-positive regression
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Missing Await', () => {
  const detector = new MissingAwaitDetector();

  test('1. Sync function named fetchX that returns a plain value', async () => {
    await expectZero(detector, `
      function fetchVersion() { return '1.0.0'; }
      const v = fetchVersion();
    `);
  });

  test('2. Awaited async call', async () => {
    await expectZero(detector, `
      async function getData() { return 1; }
      async function main() { const d = await getData(); }
    `);
  });

  test('3. Promise.all wrapping multiple calls', async () => {
    await expectZero(detector, `
      async function a() { return 1; }
      async function b() { return 2; }
      async function main() { await Promise.all([a(), b()]); }
    `);
  });

  test('4. Returned promise (caller is responsible)', async () => {
    await expectZero(detector, `
      async function getData() { return 1; }
      function proxy() { return getData(); }
    `);
  });

  test('5. void operator explicit fire-and-forget', async () => {
    await expectZero(detector, `
      async function log() {}
      function main() { void log(); }
    `);
  });

  test('6. .then()/.catch() chain on async call', async () => {
    await expectZero(detector, `
      async function getData() { return 1; }
      function main() { getData().then(d => console.log(d)).catch(e => {}); }
    `);
  });

  test('7. Sync Array.map/filter/reduce', async () => {
    await expectZero(detector, `
      const items = [1, 2, 3];
      const doubled = items.map(x => x * 2);
      const filtered = items.filter(x => x > 1);
    `);
  });

  test('8. Sync .toString() on a string', async () => {
    await expectZero(detector, `
      const s = 'hello';
      const t = s.toString();
    `);
  });

  test('9. IIFE wrapping async call', async () => {
    await expectZero(detector, `
      async function getData() { return 1; }
      (async () => { await getData(); })();
    `);
  });

  test('10. Conditional await', async () => {
    await expectZero(detector, `
      async function getData() { return 1; }
      async function main(flag: boolean) {
        const result = flag ? await getData() : 0;
      }
    `);
  });

  test('11. Constructor (never async)', async () => {
    await expectZero(detector, `
      class Foo {
        constructor() { this.data = new Map(); }
      }
      const f = new Foo();
    `);
  });

  test('12. Array.from / Object.keys / Object.entries', async () => {
    await expectZero(detector, `
      const arr = Array.from([1, 2, 3]);
      const keys = Object.keys({ a: 1 });
      const entries = Object.entries({ a: 1 });
    `);
  });
});

// ════════════════════════════════════════════════════════════════════
// Empty Catch — false-positive regression
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Empty Catch', () => {
  const detector = new EmptyCatchDetector();

  test('13. Catch with logging', async () => {
    await expectZero(detector, `
      try { doSomething(); } catch (err) { logger.error(err); }
    `);
  });

  test('14. Catch with rethrow and context', async () => {
    await expectZero(detector, `
      try { doSomething(); }
      catch (err) { throw new Error('Operation failed: ' + err.message); }
    `);
  });

  test('15. Catch with custom error wrapping', async () => {
    await expectZero(detector, `
      try { doSomething(); }
      catch (err) { throw new AppError('Failed', { cause: err }); }
    `);
  });

  test('16. Catch with error passed to handler function', async () => {
    await expectZero(detector, `
      try { doSomething(); } catch (err) { errorHandler(err); }
    `);
  });

  test('17. Catch with codedrift-disable-next-line comment', async () => {
    await expectZero(detector, `
      try { doSomething(); }
      // codedrift-disable-next-line empty-catch
      catch (err) {}
    `);
  });

  test('18. Catch that sets error state', async () => {
    await expectZero(detector, `
      let lastError = null;
      try { doSomething(); } catch (err) { lastError = err; }
    `);
  });

  test('19. Catch with conditional instanceof and terminal else', async () => {
    await expectZero(detector, `
      try { doSomething(); }
      catch (err) {
        if (err instanceof TypeError) { handleTypeError(err); }
        else { throw err; }
      }
    `);
  });
});

// ════════════════════════════════════════════════════════════════════
// Secret Detector — false-positive regression
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Secret Detector', () => {
  const detector = new SecretDetector();

  test('20. File path string', async () => {
    await expectZero(detector, `
      const config = require('./config/database.json');
    `);
  });

  test('21. Placeholder API key', async () => {
    await expectZero(detector, `
      const apiKey = 'your_api_key_here';
    `);
  });

  test('22. Example AWS key from docs', async () => {
    await expectZero(detector, `
      const key = 'AKIAIOSFODNN7EXAMPLE';
    `);
  });

  test('23. Test/mock values', async () => {
    await expectZero(detector, `
      const token = 'test-token-for-local-development';
    `);
  });

  test('24. Short strings (< 8 chars)', async () => {
    await expectZero(detector, `
      const x = 'abc123';
      const y = 'hello';
    `);
  });

  test('25. Environment variable reference', async () => {
    await expectZero(detector, `
      const key = process.env.API_KEY;
    `);
  });

  test('26. Low-entropy repeated characters', async () => {
    await expectZero(detector, `
      const separator = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    `);
  });

  test('27. Known safe function contexts (path.join, require)', async () => {
    await expectZero(detector, `
      const p = path.join('/usr/local', 'bin', 'node');
      const m = require('lodash');
    `);
  });

  test('28. URL without credentials', async () => {
    await expectZero(detector, `
      const url = 'https://api.example.com/v1/users';
    `);
  });

  test('29. Template literal placeholder', async () => {
    await expectZero(detector, `
      const msg = \`Hello \${name}, your balance is \${balance}\`;
    `);
  });

  test('30. CSS/HTML content string', async () => {
    await expectZero(detector, `
      const style = 'background-color: rgba(255, 255, 255, 0.95)';
    `);
  });
});

// ════════════════════════════════════════════════════════════════════
// Console in Production — false-positive regression
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Console in Production', () => {
  const detector = new ConsoleInProductionDetector();

  test('31. Console in test file', async () => {
    await expectZero(detector, `
      console.log('test output');
    `, 'tests/unit.test.ts');
  });

  test('32. Console in CLI file', async () => {
    await expectZero(detector, `
      console.log('Usage: codedrift scan [options]');
    `, 'src/cli/main.ts');
  });

  test('33. Console inside development block', async () => {
    await expectZero(detector, `
      if (process.env.NODE_ENV === 'development') {
        console.log('Debug mode enabled');
      }
    `);
  });

  test('34. Console in logger class', async () => {
    await expectZero(detector, `
      class ConsoleLogger {
        log(msg: string) { console.log(msg); }
        error(msg: string) { console.error(msg); }
        warn(msg: string) { console.warn(msg); }
      }
    `);
  });

  test('35. Console in scripts directory', async () => {
    await expectZero(detector, `
      console.log('Running migration...');
    `, 'scripts/migrate.ts');
  });

  test('36. Console in logger.ts file', async () => {
    await expectZero(detector, `
      console.log('Logger initialized');
    `, 'src/logger.ts');
  });

  test('37. Console.log in dev utility', async () => {
    await expectZero(detector, `
      console.log('Starting dev server');
    `, 'src/dev/server.ts');
  });

  test('38. Console in config file', async () => {
    await expectZero(detector, `
      console.log('Loading config');
    `, 'webpack.config.ts');
  });
});

// ════════════════════════════════════════════════════════════════════
// Unsafe Regex — false-positive regression
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Unsafe Regex', () => {
  const detector = new UnsafeRegexDetector();

  test('39. Simple anchored regex', async () => {
    await expectZero(detector, `
      const emailRe = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
    `);
  });

  test('40. Regex with quantifier limits', async () => {
    await expectZero(detector, `
      const re = /^[a-z]{1,100}$/;
    `);
  });

  test('41. Simple alternation', async () => {
    await expectZero(detector, `
      const re = /^(yes|no|maybe)$/;
    `);
  });

  test('42. Non-overlapping character class', async () => {
    await expectZero(detector, `
      const re = /^[0-9]+$/;
    `);
  });
});

// ════════════════════════════════════════════════════════════════════
// Input Validation — false-positive regression
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Input Validation', () => {
  const detector = new MissingInputValidationDetector();

  test('43. Route with Zod validation', async () => {
    await expectZero(detector, `
      import { z } from 'zod';
      const schema = z.object({ name: z.string() });
      app.post('/users', (req, res) => {
        const data = schema.parse(req.body);
        db.create(data);
      });
    `);
  });

  test('44. Route with Joi validation', async () => {
    await expectZero(detector, `
      import Joi from 'joi';
      app.post('/users', (req, res) => {
        const { error, value } = Joi.validate(req.body, schema);
        if (error) return res.status(400).json(error);
        db.create(value);
      });
    `);
  });

  test('45. Route with express-validator middleware', async () => {
    await expectZero(detector, `
      app.post('/users',
        body('email').isEmail(),
        body('name').isString(),
        (req, res) => {
          const { email, name } = req.body;
          db.create({ email, name });
        }
      );
    `);
  });

  test('46. Fastify with schema validation', async () => {
    await expectZero(detector, `
      fastify.post('/users', { schema: { body: userSchema } }, (req, res) => {
        db.create(req.body);
      });
    `);
  });

  test('47. Route handler without request data usage', async () => {
    await expectZero(detector, `
      app.get('/health', (req, res) => {
        res.json({ status: 'ok' });
      });
    `);
  });

  test('48. Manual typeof validation (adequate)', async () => {
    await expectZero(detector, `
      app.post('/users', (req, res) => {
        const { name, age } = req.body;
        if (typeof name !== 'string') return res.status(400).json({ error: 'Invalid name' });
        if (typeof age !== 'number') return res.status(400).json({ error: 'Invalid age' });
        db.create({ name, age });
      });
    `);
  });

  test('49. tRPC with .input() schema', async () => {
    await expectZero(detector, `
      const createUser = publicProcedure
        .input(z.object({ name: z.string() }))
        .mutation(async ({ input }) => {
          return db.create(input);
        });
    `);
  });

  test('50. GraphQL resolver (built-in type validation)', async () => {
    await expectZero(detector, `
      @Resolver()
      class UserResolver {
        @Mutation()
        createUser(@Args() args: CreateUserInput) {
          return this.service.create(args);
        }
      }
    `);
  });
});

// ════════════════════════════════════════════════════════════════════
// Stack Trace Detector — false-positive regression
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Stack Trace', () => {
  const detector = new StackTraceDetector();

  test('51. Error logging without exposure', async () => {
    await expectZero(detector, `
      app.get('/test', (req, res) => {
        try { doSomething(); }
        catch (err) {
          logger.error(err);
          res.status(500).json({ error: 'Internal error' });
        }
      });
    `);
  });

  test('52. Custom error response (no stack)', async () => {
    await expectZero(detector, `
      app.get('/test', (req, res) => {
        try { doSomething(); }
        catch (err) {
          res.status(500).json({ error: err.message });
        }
      });
    `);
  });

  test('53. Error in development-only block', async () => {
    await expectZero(detector, `
      app.get('/test', (req, res) => {
        try { doSomething(); }
        catch (err) {
          if (process.env.NODE_ENV === 'development') {
            res.status(500).json({ error: err.stack });
          } else {
            res.status(500).json({ error: 'Internal error' });
          }
        }
      });
    `);
  });
});

// ════════════════════════════════════════════════════════════════════
// Cross-Engine Edge Cases
// ════════════════════════════════════════════════════════════════════

describe('FP Regression: Cross-Engine Edge Cases', () => {
  const awaitDetector = new MissingAwaitDetector();
  const secretDetector = new SecretDetector();
  const consoleDetector = new ConsoleInProductionDetector();

  test('54. JSON.parse (sync built-in)', async () => {
    await expectZero(awaitDetector, `
      const data = JSON.parse('{"a":1}');
    `);
  });

  test('55. Date/Math/String constructors', async () => {
    await expectZero(awaitDetector, `
      const d = new Date();
      const r = Math.random();
      const s = String(42);
      const n = Number('42');
    `);
  });

  test('56. console.log with process.env (not a secret)', async () => {
    await expectZero(secretDetector, `
      const dbUrl = process.env.DATABASE_URL;
    `);
  });

  test('57. UUID/CUID strings (not secrets)', async () => {
    await expectZero(secretDetector, `
      const id = 'cjld2cyuq0000t3rmniod1foy';
    `);
  });

  test('58. Base64-encoded non-secret', async () => {
    await expectZero(secretDetector, `
      const logo = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk';
    `);
  });

  test('59. console.error in file with logger import (LOW confidence suppressed)', async () => {
    await expectZero(consoleDetector, `
      import winston from 'winston';
      const logger = winston.createLogger({});
      console.log('debug info');
    `);
  });

  test('60. Regular expression in string (not a regex literal)', async () => {
    const regexDetector = new UnsafeRegexDetector();
    await expectZero(regexDetector, `
      const pattern = '^[a-z]+$';
    `);
  });
});

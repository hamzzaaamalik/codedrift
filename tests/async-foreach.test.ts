/**
 * Tests for AsyncForEachDetector — 10/10
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { parseSource } from '../src/core/parser.js';
import { AsyncForEachDetector } from '../src/engines/async-foreach-detector.js';

const detector = new AsyncForEachDetector();

test('AsyncForEachDetector', async (t) => {
  // ═══════════════════════════════════════════════════════════════
  // Existing tests (updated for new message format)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should detect forEach with async callback', async () => {
    const code = `
      const users = await getUsers();
      users.forEach(async (user) => {
        await sendEmail(user.email);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/api.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('forEach'));
    assert.ok(issues[0].message.includes('race conditions') || issues[0].message.includes('detached promises'));
    assert.ok(issues[0].confidence, 'Should have confidence field');
    assert.strictEqual(issues[0].confidence, 'high', 'Should have high confidence for production code');
    assert.ok(issues[0].metadata, 'Should have metadata');
    assert.strictEqual(issues[0].metadata.isTestFile, false, 'Should not be a test file');
  });

  await t.test('should detect map with async callback', async () => {
    const code = `
      items.map(async (item) => {
        return await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/utils.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('map'));
    assert.ok(issues[0].confidence, 'Should have confidence field');
  });

  await t.test('should detect filter with async callback', async () => {
    const code = `
      const active = items.filter(async (item) => {
        return await item.isActive();
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'test.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('filter'));
  });

  await t.test('should NOT flag forEach with sync callback', async () => {
    const code = `
      items.forEach((item) => {
        console.log(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'test.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should NOT flag map inside awaited Promise.all', async () => {
    const code = `
      const results = await Promise.all(
        items.map(async (item) => {
          return await process(item);
        })
      );
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'test.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should NOT flag regular function calls', async () => {
    const code = `
      const result = doSomething(async () => {
        await process();
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'test.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should downgrade confidence for test files', async () => {
    const code = `
      items.forEach(async (item) => {
        await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/api.test.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].confidence, 'Should have confidence field');
    assert.strictEqual(issues[0].confidence, 'medium', 'Should downgrade to medium for test files');
    assert.ok(issues[0].metadata, 'Should have metadata');
    assert.strictEqual(issues[0].metadata.isTestFile, true, 'Should be marked as test file');
  });

  // ═══════════════════════════════════════════════════════════════
  // Callback detection (5 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should flag forEach with named async function reference', async () => {
    const code = `
      async function processItem(item) {
        await save(item);
      }
      items.forEach(processItem);
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('forEach'));
  });

  await t.test('should flag map with variable holding async arrow', async () => {
    const code = `
      const handler = async (item) => {
        await process(item);
      };
      items.map(handler);
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('map'));
  });

  await t.test('should flag forEach with this.asyncMethod reference', async () => {
    const code = `
      class Processor {
        async processItem(item) {
          await save(item);
        }
        run(items) {
          items.forEach(this.processItem);
        }
      }
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('forEach'));
  });

  await t.test('should NOT flag forEach with named sync function reference', async () => {
    const code = `
      function processItem(item) {
        console.log(item);
      }
      items.forEach(processItem);
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should NOT flag map with sync variable reference', async () => {
    const code = `
      const transform = (item) => item.name;
      items.map(transform);
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  // ═══════════════════════════════════════════════════════════════
  // Method-specific severity (5 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should set error severity for filter with async callback', async () => {
    const code = `
      const active = items.filter(async (item) => {
        return await item.isActive();
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
    assert.strictEqual(issues[0].confidence, 'high');
  });

  await t.test('should set error severity for find with async callback', async () => {
    const code = `
      const found = items.find(async (item) => {
        return await checkItem(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
  });

  await t.test('should set error severity for some with async callback', async () => {
    const code = `
      const hasValid = items.some(async (item) => {
        return await validate(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
  });

  await t.test('should set error severity for every with async callback', async () => {
    const code = `
      const allValid = items.every(async (item) => {
        return await validate(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
  });

  await t.test('should set error severity for findIndex with async callback', async () => {
    const code = `
      const idx = items.findIndex(async (item) => {
        return await isMatch(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
  });

  // ═══════════════════════════════════════════════════════════════
  // Method-specific messages (4 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should include "always truthy" in filter message', async () => {
    const code = `
      items.filter(async (item) => {
        return await check(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('truthy'), `Expected "truthy" in message: ${issues[0].message}`);
  });

  await t.test('should include "first element" in find message', async () => {
    const code = `
      items.find(async (item) => {
        return await check(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('first element'), `Expected "first element" in message: ${issues[0].message}`);
  });

  await t.test('should include "race conditions" in forEach message', async () => {
    const code = `
      items.forEach(async (item) => {
        await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('race conditions'), `Expected "race conditions" in message: ${issues[0].message}`);
  });

  await t.test('should include "Promise[]" in map message', async () => {
    const code = `
      const results = items.map(async (item) => {
        return await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('Promise[]'), `Expected "Promise[]" in message: ${issues[0].message}`);
  });

  // ═══════════════════════════════════════════════════════════════
  // Map result tracking (5 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should flag discarded map result as error', async () => {
    const code = `
      async function process() {
        items.map(async (item) => {
          await save(item);
        });
      }
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
  });

  await t.test('should skip map result handled by Promise.all via variable', async () => {
    const code = `
      async function process() {
        const promises = items.map(async (item) => {
          return await transform(item);
        });
        await Promise.all(promises);
      }
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should skip map result returned from function', async () => {
    const code = `
      function getPromises() {
        const promises = items.map(async (item) => {
          return await transform(item);
        });
        return promises;
      }
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should flag map result assigned but never handled', async () => {
    const code = `
      async function process() {
        const results = items.map(async (item) => {
          return await transform(item);
        });
        console.log('done');
      }
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('map'));
  });

  await t.test('should skip map result used with for-await-of', async () => {
    const code = `
      async function process() {
        const promises = items.map(async (item) => {
          return await transform(item);
        });
        for await (const result of promises) {
          console.log(result);
        }
      }
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  // ═══════════════════════════════════════════════════════════════
  // Async-aware library skips (4 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should NOT flag Bluebird Promise.map', async () => {
    const code = `
      await Promise.map(items, async (item) => {
        return await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should NOT flag async.eachSeries', async () => {
    const code = `
      await async.eachSeries(items, async (item) => {
        await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should NOT flag async.mapSeries', async () => {
    const code = `
      const results = await async.mapSeries(items, async (item) => {
        return await transform(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should NOT flag RxJS pipe with concatMap', async () => {
    const code = `
      source$.pipe(
        concatMap(async (item) => {
          return await process(item);
        })
      ).subscribe();
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  // ═══════════════════════════════════════════════════════════════
  // Extended patterns (5 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should flag Array.from with async mapper', async () => {
    const code = `
      const results = Array.from(items, async (item) => {
        return await transform(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('Array.from'));
  });

  await t.test('should flag both levels of nested forEach', async () => {
    const code = `
      matrix.forEach(async (row) => {
        await processRow(row);
        row.forEach(async (cell) => {
          await processCell(cell);
        });
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 2, 'Should flag both outer and inner forEach');
    assert.ok(issues.every(i => i.message.includes('forEach')));
  });

  await t.test('should flag Object.keys().forEach with async callback', async () => {
    const code = `
      Object.keys(obj).forEach(async (key) => {
        await process(obj[key]);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('forEach'));
  });

  await t.test('should flag reduce with async callback', async () => {
    const code = `
      const total = items.reduce(async (acc, item) => {
        const val = await getAmount(item);
        return (await acc) + val;
      }, 0);
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('reduce'));
    assert.ok(issues[0].message.includes('accumulator'));
  });

  await t.test('should flag Object.values().map with async callback', async () => {
    const code = `
      Object.values(config).map(async (val) => {
        return await validate(val);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('map'));
  });

  // ═══════════════════════════════════════════════════════════════
  // Callback escalation (3 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should escalate forEach to error when callback has DB write', async () => {
    const code = `
      items.forEach(async (item) => {
        await db.save(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
    assert.strictEqual(issues[0].confidence, 'high');
  });

  await t.test('should escalate map to error when callback has payment op', async () => {
    const code = `
      items.map(async (order) => {
        await stripe.charge(order.amount);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.strictEqual(issues[0].severity, 'error');
  });

  await t.test('should NOT escalate when callback only has reads', async () => {
    const code = `
      items.forEach(async (item) => {
        const data = await fetch(item.url);
        console.log(data);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    // Should still be error (forEach base tier is HIGH), but confidence stays high (has await)
    assert.strictEqual(issues[0].severity, 'error');
    assert.strictEqual(issues[0].confidence, 'high');
  });

  // ═══════════════════════════════════════════════════════════════
  // Suggestions (2 tests)
  // ═══════════════════════════════════════════════════════════════

  await t.test('should suggest for...of loop for forEach', async () => {
    const code = `
      items.forEach(async (item) => {
        await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].suggestion?.includes('for...of'), `Expected "for...of" in suggestion: ${issues[0].suggestion}`);
  });

  await t.test('should suggest Promise.all wrapper for map', async () => {
    const code = `
      const results = items.map(async (item) => {
        return await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].suggestion?.includes('Promise.all'), `Expected "Promise.all" in suggestion: ${issues[0].suggestion}`);
  });

  // ═══════════════════════════════════════════════════════════════
  // Additional skip patterns
  // ═══════════════════════════════════════════════════════════════

  await t.test('should NOT flag Promise.allSettled wrapping map', async () => {
    const code = `
      const results = await Promise.allSettled(
        items.map(async (item) => {
          return await process(item);
        })
      );
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });

  await t.test('should NOT flag Promise.all(...).then(...) wrapping map', async () => {
    const code = `
      Promise.all(items.map(async (item) => process(item))).then(results => {
        console.log(results);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'src/app.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 0);
  });
});

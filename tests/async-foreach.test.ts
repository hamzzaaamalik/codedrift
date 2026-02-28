/**
 * Tests for AsyncForEachDetector
 */

import { test } from 'node:test';
import assert from 'node:assert';
import { parseSource } from '../src/core/parser.js';
import { AsyncForEachDetector } from '../src/engines/async-foreach-detector.js';

const detector = new AsyncForEachDetector();

test('AsyncForEachDetector', async (t) => {
  await t.test('should detect forEach with async callback', async () => {
    const code = `
      const users = await getUsers();
      users.forEach(async (user) => {
        await sendEmail(user.email);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'test.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('forEach'));
    assert.ok(issues[0].message.includes('out of order'));
  });

  await t.test('should detect map with async callback', async () => {
    const code = `
      items.map(async (item) => {
        return await process(item);
      });
    `;

    const sourceFile = parseSource(code);
    const issues = await detector.analyze({ filePath: 'test.ts', sourceFile, content: code });

    assert.strictEqual(issues.length, 1);
    assert.ok(issues[0].message.includes('map'));
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
});

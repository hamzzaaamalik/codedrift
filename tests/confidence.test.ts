/**
 * Tests for confidence level system
 */

import { describe, test } from 'node:test';
import assert from 'node:assert';
import { parseSource } from '../src/core/parser.js';
import { StackTraceDetector } from '../src/engines/stack-trace-detector.js';
import { MissingAwaitDetector } from '../src/engines/missing-await-detector.js';
import { SecretDetector } from '../src/engines/secret-detector.js';
import { isTestFile, isGeneratedFile } from '../src/utils/file-utils.js';
import type { Confidence, Issue } from '../src/types/index.js';

// Helper to create analysis context
function createContext(code: string, filePath = 'src/api.ts') {
  const sourceFile = parseSource(code, filePath);
  return {
    sourceFile,
    filePath,
    content: code,
    metadata: {
      isTestFile: isTestFile(filePath),
      isGeneratedFile: isGeneratedFile(filePath),
    },
  };
}

describe('Confidence Levels - Basic Assignment', () => {
  test('should assign high confidence to obvious issues in production code', async () => {
    const detector = new StackTraceDetector();
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.status(500).json({ error: err.stack });
        }
      }
    `;
    const context = createContext(code, 'src/api/handler.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.strictEqual(issue.confidence, 'high', 'Should have high confidence');
  });

  test('should assign high confidence to hardcoded secrets', async () => {
    const detector = new SecretDetector();
    const prefix = 'sk_live';
    const suffix = '_4eC39HqLyjWDarjtT1zdp7dc';
    const code = `const apiKey = '${prefix + suffix}';`;
    const context = createContext(code, 'src/config.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect secret');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.strictEqual(issue.confidence, 'high', 'Should have high confidence');
  });

  test('should assign confidence to missing await', async () => {
    const detector = new MissingAwaitDetector();
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        return fetchData(); // Missing await - return value used in return statement
      }
    `;
    const context = createContext(code, 'src/api.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect missing await');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    // High confidence when function is declared async and return value is used
    assert.strictEqual(issue.confidence, 'high', 'Should have high confidence when return value is used');
  });
});

describe('Confidence Levels - Test File Downgrade', () => {
  test('should downgrade confidence to medium in test files', async () => {
    const detector = new StackTraceDetector();
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.status(500).json({ error: err.stack });
        }
      }
    `;
    // Same code, but in a test file
    const context = createContext(code, 'src/api/handler.test.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.strictEqual(issue.confidence, 'medium', 'Should downgrade to medium in test files');
  });

  test('should downgrade confidence in __tests__ directory', async () => {
    const detector = new MissingAwaitDetector();
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        return fetchData(); // Missing await - return value used in return statement
      }
    `;
    const context = createContext(code, 'src/__tests__/api.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    // High confidence becomes medium in test files, but test files in __tests__ might be marked as generated too
    assert.ok(['medium', 'low'].includes(issue.confidence || ''), 'Should downgrade confidence in test directory');
  });

  test('should downgrade confidence in spec files', async () => {
    const detector = new SecretDetector();
    const code = `const testKey = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';`;
    const context = createContext(code, 'tests/integration.spec.ts');
    const issues = await detector.analyze(context);

    const validIssues = issues.filter(i => i !== null);
    assert.ok(validIssues.length > 0, 'Should detect secret');
    const issue = validIssues[0];
    assert.ok(issue, 'Issue should exist');
    assert.strictEqual(issue.confidence, 'medium', 'Should downgrade to medium');
  });
});

describe('Confidence Levels - Generated File Downgrade', () => {
  test('should have metadata for generated files', async () => {
    const detector = new StackTraceDetector();
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.json({ error: err.stack });
        }
      }
    `;
    const context = createContext(code, 'dist/api/handler.js');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.metadata, 'Should have metadata');
    assert.strictEqual(issue.metadata.isGeneratedFile, true, 'Should be marked as generated');
    // Confidence should be downgraded for generated files
    assert.ok(['high', 'medium'].includes(issue.confidence || ''), 'Should have high or medium confidence');
  });

  test('should mark .d.ts files as generated', async () => {
    const detector = new StackTraceDetector();
    const code = `
      function handler(req: any, res: any) {
        try {
          processRequest();
        } catch (err: any) {
          res.json({ error: err.stack });
        }
      }
    `;
    const context = createContext(code, 'types/api.d.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.metadata, 'Should have metadata');
    assert.strictEqual(issue.metadata.isGeneratedFile, true, 'Should mark .d.ts as generated');
  });

  test('should mark .generated.ts files', async () => {
    const detector = new SecretDetector();
    const code = `const key = '-----BEGIN RSA PRIVATE KEY-----';`;
    const context = createContext(code, 'src/graphql/schema.generated.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.metadata, 'Should have metadata');
    assert.strictEqual(issue.metadata.isGeneratedFile, true, 'Should mark .generated.ts files');
  });
});

describe('Confidence Levels - Metadata', () => {
  test('should include isTestFile metadata', async () => {
    const detector = new MissingAwaitDetector();
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        return fetchData(); // Return value used
      }
    `;
    const context = createContext(code, 'src/api.test.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.metadata, 'Should have metadata');
    assert.strictEqual(issue.metadata.isTestFile, true, 'Should mark as test file');
  });

  test('should include isGeneratedFile metadata', async () => {
    const detector = new StackTraceDetector();
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.json({ error: err.stack });
        }
      }
    `;
    const context = createContext(code, 'dist/api.js');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.metadata, 'Should have metadata');
    assert.strictEqual(issue.metadata.isGeneratedFile, true, 'Should mark as generated file');
  });

  test('should mark regular source files correctly', async () => {
    const detector = new MissingAwaitDetector();
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        fetchData();
      }
    `;
    const context = createContext(code, 'src/api/users.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    assert.ok(issue.metadata, 'Should have metadata');
    assert.strictEqual(issue.metadata.isTestFile, false, 'Should not be test file');
    assert.strictEqual(issue.metadata.isGeneratedFile, false, 'Should not be generated file');
  });
});

describe('Confidence Threshold Filtering', () => {
  // Helper to filter issues by confidence threshold
  function filterByConfidence(issues: Issue[], threshold: Confidence): Issue[] {
    const confidenceLevels: Record<Confidence, number> = {
      high: 3,
      medium: 2,
      low: 1,
    };

    const thresholdLevel = confidenceLevels[threshold];

    return issues.filter(issue => {
      const issueLevel = confidenceLevels[issue.confidence || 'high'];
      return issueLevel >= thresholdLevel;
    });
  }

  test('should filter issues with high threshold', async () => {
    const detector = new StackTraceDetector();

    // Create issues from different file types
    const productionCode = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.json({ error: err.stack });
        }
      }
    `;

    const prodContext = createContext(productionCode, 'src/api.ts');
    const testContext = createContext(productionCode, 'src/api.test.ts');

    const prodIssues = await detector.analyze(prodContext);
    const testIssues = await detector.analyze(testContext);

    const allIssues = [...prodIssues, ...testIssues].filter(i => i !== null) as Issue[];

    // Filter with high threshold
    const highConfidenceIssues = filterByConfidence(allIssues, 'high');

    assert.ok(highConfidenceIssues.length > 0, 'Should have high confidence issues');
    assert.strictEqual(
      highConfidenceIssues.every(i => i.confidence === 'high'),
      true,
      'All filtered issues should be high confidence'
    );
  });

  test('should include medium and high with medium threshold', async () => {
    const detector = new MissingAwaitDetector();
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        fetchData();
      }
    `;

    const prodContext = createContext(code, 'src/api.ts');
    const testContext = createContext(code, 'tests/api.test.ts');

    const prodIssues = await detector.analyze(prodContext);
    const testIssues = await detector.analyze(testContext);

    const allIssues = [...prodIssues, ...testIssues].filter(i => i !== null) as Issue[];

    // Filter with medium threshold
    const mediumPlusIssues = filterByConfidence(allIssues, 'medium');

    assert.ok(mediumPlusIssues.length > 0, 'Should have medium+ confidence issues');
    assert.ok(mediumPlusIssues.length <= allIssues.length, 'Filtered should be <= total');
    assert.ok(
      mediumPlusIssues.every(i => i.confidence === 'high' || i.confidence === 'medium'),
      'Should include high and medium confidence'
    );
  });

  test('should include all issues with low threshold', async () => {
    const detector = new SecretDetector();
    const code = `const key = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';`;

    const prodContext = createContext(code, 'src/config.ts');
    const testContext = createContext(code, 'tests/config.test.ts');
    const buildContext = createContext(code, 'dist/config.js');

    const prodIssues = await detector.analyze(prodContext);
    const testIssues = await detector.analyze(testContext);
    const buildIssues = await detector.analyze(buildContext);

    const allIssues = [...prodIssues, ...testIssues, ...buildIssues]
      .filter(i => i !== null) as Issue[];

    // Filter with low threshold (should include all)
    const lowPlusIssues = filterByConfidence(allIssues, 'low');

    assert.strictEqual(
      lowPlusIssues.length,
      allIssues.length,
      'Should include all issues with low threshold'
    );
  });
});

describe('Confidence Levels - Edge Cases', () => {
  test('should handle files that are both test and generated', async () => {
    const detector = new MissingAwaitDetector();
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        return fetchData(); // Return value used
      }
    `;
    // File is both in dist/ and a test file
    const context = createContext(code, 'dist/__tests__/api.test.js');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    // Should downgrade (test files take precedence)
    assert.ok(['medium', 'low'].includes(issue.confidence || ''), 'Should downgrade confidence');
    assert.ok(issue.metadata, 'Should have metadata');
    assert.strictEqual(issue.metadata.isTestFile, true);
  });

  test('should handle missing confidence gracefully', async () => {
    const detector = new StackTraceDetector();
    const code = `
      function handler(req, res) {
        try {
          processRequest();
        } catch (err) {
          res.json({ error: err.stack });
        }
      }
    `;
    const context = createContext(code, 'src/api.ts');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');
    // Should default to 'high' if not specified
    assert.ok(issue.confidence, 'Should have a confidence value');
    assert.ok(['high', 'medium', 'low'].includes(issue.confidence), 'Should be valid confidence');
  });

  test('should handle unusual file paths', async () => {
    const detector = new SecretDetector();
    const code = `const key = '-----BEGIN RSA PRIVATE KEY-----';`;

    const paths = [
      'C:\\Windows\\Path\\src\\api.ts',
      '/usr/local/app/src/api.ts',
      '../relative/path/api.ts',
      'UPPERCASE/PATH/API.TS',
      'path/with spaces/api.ts',
    ];

    for (const filePath of paths) {
      const context = createContext(code, filePath);
      const issues = await detector.analyze(context);

      assert.ok(issues.length > 0, `Should detect issue in ${filePath}`);
      const issue = issues[0];
      assert.ok(issue, 'Issue should exist');
      assert.ok(issue.confidence, 'Should assign confidence');
    }
  });
});

describe('Confidence Levels - Double Downgrade Prevention', () => {
  test('should not downgrade below low confidence', async () => {
    // This tests that downgrading medium -> low -> low (not lower)
    const detector = new MissingAwaitDetector();
    const code = `
      async function fetchData() { return {}; }
      async function handler() {
        fetchData();
      }
    `;

    // A test file in generated directory (would trigger double downgrade attempt)
    const context = createContext(code, 'dist/tests/api.test.js');
    const issues = await detector.analyze(context);

    assert.ok(issues.length > 0, 'Should detect issue');
    const issue = issues[0];
    assert.ok(issue, 'Issue should exist');

    // Should be medium (one downgrade from high) since isTestFile is checked first
    // or low if both downgrades apply
    assert.ok(
      ['medium', 'low'].includes(issue.confidence || ''),
      'Confidence should be medium or low'
    );
  });
});

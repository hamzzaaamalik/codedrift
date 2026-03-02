/**
 * Tests for file utility functions
 */

import { describe, test } from 'node:test';
import assert from 'node:assert';
import { isTestFile, isGeneratedFile, getFileCategory } from '../src/utils/file-utils.js';

describe('isTestFile', () => {
  test('should detect .test.ts files', () => {
    assert.strictEqual(isTestFile('src/utils/helper.test.ts'), true);
    assert.strictEqual(isTestFile('components/Button.test.tsx'), true);
  });

  test('should detect .spec.ts files', () => {
    assert.strictEqual(isTestFile('src/api/users.spec.ts'), true);
    assert.strictEqual(isTestFile('components/Header.spec.tsx'), true);
  });

  test('should detect .test.js files', () => {
    assert.strictEqual(isTestFile('legacy/app.test.js'), true);
    assert.strictEqual(isTestFile('utils/format.test.jsx'), true);
  });

  test('should detect .spec.js files', () => {
    assert.strictEqual(isTestFile('old/service.spec.js'), true);
    assert.strictEqual(isTestFile('components/Footer.spec.jsx'), true);
  });

  test('should detect files in __tests__ directory', () => {
    assert.strictEqual(isTestFile('src/__tests__/api.ts'), true);
    assert.strictEqual(isTestFile('components/__tests__/Button.tsx'), true);
    assert.strictEqual(isTestFile('__tests__/integration.js'), true);
  });

  test('should detect files in test/ directory', () => {
    assert.strictEqual(isTestFile('test/unit/api.ts'), true);
    assert.strictEqual(isTestFile('src/test/helpers.ts'), true);
  });

  test('should detect files in tests/ directory', () => {
    assert.strictEqual(isTestFile('tests/integration.ts'), true);
    assert.strictEqual(isTestFile('src/tests/unit/parser.ts'), true);
  });

  test('should detect files in spec/ directory', () => {
    assert.strictEqual(isTestFile('spec/api.ts'), true);
    assert.strictEqual(isTestFile('src/spec/unit.ts'), true);
  });

  test('should detect files in specs/ directory', () => {
    assert.strictEqual(isTestFile('specs/integration.ts'), true);
    assert.strictEqual(isTestFile('src/specs/e2e.ts'), true);
  });

  test('should NOT detect regular source files', () => {
    assert.strictEqual(isTestFile('src/utils/helper.ts'), false);
    assert.strictEqual(isTestFile('components/Button.tsx'), false);
    assert.strictEqual(isTestFile('api/users.ts'), false);
    assert.strictEqual(isTestFile('index.js'), false);
  });

  test('should be case-insensitive', () => {
    assert.strictEqual(isTestFile('src/API.TEST.TS'), true);
    assert.strictEqual(isTestFile('src/Component.Spec.Tsx'), true);
    assert.strictEqual(isTestFile('SRC/__TESTS__/HELPER.TS'), true);
  });

  test('should handle Windows-style paths', () => {
    assert.strictEqual(isTestFile('C:\\Users\\dev\\project\\src\\api.test.ts'), true);
    assert.strictEqual(isTestFile('D:\\code\\app\\__tests__\\unit.ts'), true);
  });

  test('should handle absolute Unix paths', () => {
    assert.strictEqual(isTestFile('/home/user/project/src/api.test.ts'), true);
    assert.strictEqual(isTestFile('/var/www/app/__tests__/unit.ts'), true);
  });

  test('should handle edge cases', () => {
    assert.strictEqual(isTestFile('test.ts'), false); // Not a test file pattern
    assert.strictEqual(isTestFile('mytest.ts'), false); // Doesn't match pattern
    assert.strictEqual(isTestFile('testing.ts'), false); // Doesn't match pattern
    assert.strictEqual(isTestFile('tests.ts'), false); // File named 'tests' but not in tests/ dir
  });
});

describe('isGeneratedFile', () => {
  test('should detect files in /generated/ directory', () => {
    assert.strictEqual(isGeneratedFile('src/generated/graphql.ts'), true);
    assert.strictEqual(isGeneratedFile('lib/generated/api.ts'), true);
  });

  test('should detect files in /__generated__/ directory', () => {
    assert.strictEqual(isGeneratedFile('src/__generated__/types.ts'), true);
    assert.strictEqual(isGeneratedFile('__generated__/schema.ts'), true);
  });

  test('should detect files in /.next/ directory', () => {
    assert.strictEqual(isGeneratedFile('.next/server/pages/api.js'), true);
    assert.strictEqual(isGeneratedFile('my-app/.next/static/chunks/main.js'), true);
  });

  test('should detect files in /dist/ directory', () => {
    assert.strictEqual(isGeneratedFile('dist/index.js'), true);
    assert.strictEqual(isGeneratedFile('packages/core/dist/main.js'), true);
  });

  test('should detect files in /build/ directory', () => {
    assert.strictEqual(isGeneratedFile('build/bundle.js'), true);
    assert.strictEqual(isGeneratedFile('client/build/app.js'), true);
  });

  test('should detect files in /out/ directory', () => {
    assert.strictEqual(isGeneratedFile('out/index.html'), true);
    assert.strictEqual(isGeneratedFile('project/out/static/main.js'), true);
  });

  test('should detect .generated.ts files', () => {
    assert.strictEqual(isGeneratedFile('src/api.generated.ts'), true);
    assert.strictEqual(isGeneratedFile('types/schema.generated.tsx'), true);
  });

  test('should detect .g.ts files', () => {
    assert.strictEqual(isGeneratedFile('src/proto.g.ts'), true);
    assert.strictEqual(isGeneratedFile('types/api.g.js'), true);
  });

  test('should detect .d.ts declaration files', () => {
    assert.strictEqual(isGeneratedFile('types/index.d.ts'), true);
    assert.strictEqual(isGeneratedFile('src/api.d.ts'), true);
  });

  test('should detect protobuf generated files', () => {
    assert.strictEqual(isGeneratedFile('src/messages.pb.ts'), true);
    assert.strictEqual(isGeneratedFile('protos/api_pb.js'), true);
  });

  test('should detect files in /migrations/ directory', () => {
    assert.strictEqual(isGeneratedFile('db/migrations/001_initial.ts'), true);
    assert.strictEqual(isGeneratedFile('src/migration/create_users.ts'), true);
  });

  test('should NOT detect regular source files', () => {
    assert.strictEqual(isGeneratedFile('src/utils/helper.ts'), false);
    assert.strictEqual(isGeneratedFile('components/Button.tsx'), false);
    assert.strictEqual(isGeneratedFile('api/users.ts'), false);
    assert.strictEqual(isGeneratedFile('index.ts'), false);
  });

  test('should be case-insensitive', () => {
    assert.strictEqual(isGeneratedFile('SRC/GENERATED/API.TS'), true);
    assert.strictEqual(isGeneratedFile('DIST/INDEX.JS'), true);
    assert.strictEqual(isGeneratedFile('TYPES/INDEX.D.TS'), true);
  });

  test('should handle files with @generated marker in path', () => {
    // This tests the pattern /@generated/i
    assert.strictEqual(isGeneratedFile('src/@generated/types.ts'), true);
  });

  test('should handle Windows-style paths', () => {
    assert.strictEqual(isGeneratedFile('C:\\project\\dist\\index.js'), true);
    assert.strictEqual(isGeneratedFile('D:\\app\\generated\\schema.ts'), true);
  });

  test('should handle absolute Unix paths', () => {
    assert.strictEqual(isGeneratedFile('/home/user/project/dist/index.js'), true);
    assert.strictEqual(isGeneratedFile('/var/www/app/build/bundle.js'), true);
  });
});

describe('getFileCategory', () => {
  test('should categorize test files', () => {
    assert.strictEqual(getFileCategory('src/api.test.ts'), 'test');
    assert.strictEqual(getFileCategory('components/__tests__/Button.tsx'), 'test');
    assert.strictEqual(getFileCategory('spec/integration.ts'), 'test');
  });

  test('should categorize generated files', () => {
    assert.strictEqual(getFileCategory('dist/index.js'), 'generated');
    assert.strictEqual(getFileCategory('src/generated/api.ts'), 'generated');
    assert.strictEqual(getFileCategory('types/schema.d.ts'), 'generated');
  });

  test('should categorize regular source files', () => {
    // The function returns 'production' for non-test, non-generated files
    assert.strictEqual(getFileCategory('src/utils/helper.ts'), 'production');
    assert.strictEqual(getFileCategory('components/Button.tsx'), 'production');
    assert.strictEqual(getFileCategory('api/users.ts'), 'production');
    assert.strictEqual(getFileCategory('index.ts'), 'production');
  });

  test('should prioritize test category over generated', () => {
    // If a file matches both test and generated patterns, test should win
    assert.strictEqual(getFileCategory('dist/utils.test.js'), 'test');
    assert.strictEqual(getFileCategory('build/__tests__/api.js'), 'test');
  });

  test('should handle edge cases', () => {
    assert.strictEqual(getFileCategory(''), 'production');
    assert.strictEqual(getFileCategory('README.md'), 'production');
    assert.strictEqual(getFileCategory('package.json'), 'production');
  });
});

describe('File Utils - Scoped Package Handling', () => {
  // The file-utils module doesn't have extractPackageName
  // but we document expected behavior if it's added
  test('should handle scoped packages if extractPackageName exists', () => {
    // This is a placeholder test for future functionality
    // extractPackageName is in hallucinated-deps-detector.ts
    // If moved to utils, this test documents expected behavior
    assert.ok(true, 'Scoped package handling should be implemented in utils');
  });
});

describe('File Utils - Performance', () => {
  test('should handle large file paths efficiently', () => {
    const longPath = 'a/'.repeat(100) + 'file.test.ts';
    const start = performance.now();
    const result = isTestFile(longPath);
    const duration = performance.now() - start;

    assert.strictEqual(result, true);
    assert.ok(duration < 10, 'Should process file path in under 10ms');
  });

  test('should handle many consecutive checks efficiently', () => {
    const paths = [
      'src/api.ts',
      'tests/api.test.ts',
      'dist/bundle.js',
      'components/Button.tsx',
      'generated/types.ts',
    ];

    const start = performance.now();
    for (let i = 0; i < 1000; i++) {
      paths.forEach(p => {
        isTestFile(p);
        isGeneratedFile(p);
        getFileCategory(p);
      });
    }
    const duration = performance.now() - start;

    assert.ok(duration < 500, 'Should process 15,000 checks in under 500ms');
  });
});

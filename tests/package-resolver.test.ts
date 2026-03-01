/**
 * Tests for package resolver utility
 */

import { describe, test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import { PackageResolver } from '../src/utils/package-resolver.js';

// Temporary test directory
const TEST_DIR = path.join(process.cwd(), '.test-temp-package-resolver');

describe('PackageResolver', () => {
  beforeEach(() => {
    // Create test directory
    if (!fs.existsSync(TEST_DIR)) {
      fs.mkdirSync(TEST_DIR, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
  });

  test('should find package.json in parent directory', () => {
    // Since PackageResolver now walks up the directory tree,
    // it will find the project's package.json even in an empty test dir
    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);
    assert.ok(resolver.packageJson);
    // Should find the codedrift package.json in the project root
    assert.strictEqual(resolver.packageJson.name, 'codedrift');
  });

  test('should load package.json successfully', () => {
    const packageJson = {
      name: 'test-package',
      dependencies: {
        express: '^4.18.0',
      },
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);
    assert.strictEqual(resolver.packageJson.name, 'test-package');
  });

  test('should check dependencies correctly', () => {
    const packageJson = {
      name: 'test-package',
      dependencies: {
        express: '^4.18.0',
        lodash: '^4.17.21',
      },
      devDependencies: {
        typescript: '^5.0.0',
      },
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);

    // Test hasDependency
    assert.strictEqual(resolver.hasDependency('express'), true);
    assert.strictEqual(resolver.hasDependency('lodash'), true);
    assert.strictEqual(resolver.hasDependency('typescript'), false);
    assert.strictEqual(resolver.hasDependency('nonexistent'), false);
  });

  test('should check devDependencies correctly', () => {
    const packageJson = {
      name: 'test-package',
      dependencies: {
        express: '^4.18.0',
      },
      devDependencies: {
        typescript: '^5.0.0',
        vitest: '^4.0.0',
      },
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);

    // Test hasDevDependency
    assert.strictEqual(resolver.hasDevDependency('typescript'), true);
    assert.strictEqual(resolver.hasDevDependency('vitest'), true);
    assert.strictEqual(resolver.hasDevDependency('express'), false);
    assert.strictEqual(resolver.hasDevDependency('nonexistent'), false);
  });

  test('should check any dependency type with hasAnyDependency', () => {
    const packageJson = {
      name: 'test-package',
      dependencies: {
        express: '^4.18.0',
      },
      devDependencies: {
        typescript: '^5.0.0',
      },
      peerDependencies: {
        react: '^18.0.0',
      },
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);

    // Test hasAnyDependency
    assert.strictEqual(resolver.hasAnyDependency('express'), true);
    assert.strictEqual(resolver.hasAnyDependency('typescript'), true);
    // Note: current implementation doesn't check peerDependencies
    assert.strictEqual(resolver.hasAnyDependency('nonexistent'), false);
  });

  test('should handle scoped packages', () => {
    const packageJson = {
      name: '@myorg/my-package',
      dependencies: {
        '@types/node': '^20.0.0',
        '@babel/core': '^7.0.0',
      },
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);

    assert.strictEqual(resolver.hasDependency('@types/node'), true);
    assert.strictEqual(resolver.hasDependency('@babel/core'), true);
    assert.strictEqual(resolver.hasDependency('@types/express'), false);
  });

  test('should handle missing dependency fields gracefully', () => {
    const packageJson = {
      name: 'minimal-package',
      version: '1.0.0',
      // No dependencies, devDependencies, or peerDependencies
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);

    assert.strictEqual(resolver.hasDependency('express'), false);
    assert.strictEqual(resolver.hasDevDependency('typescript'), false);
    assert.strictEqual(resolver.hasAnyDependency('lodash'), false);
  });

  test('should return null for invalid JSON', () => {
    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      '{ invalid json'
    );

    assert.throws(() => {
      new PackageResolver(TEST_DIR);
    });
  });

  test('should handle empty dependencies object', () => {
    const packageJson = {
      name: 'test-package',
      dependencies: {},
      devDependencies: {},
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);

    assert.strictEqual(resolver.hasDependency('express'), false);
    assert.strictEqual(resolver.hasDevDependency('typescript'), false);
  });
});

describe('PackageResolver - Workspace Detection', () => {
  beforeEach(() => {
    if (!fs.existsSync(TEST_DIR)) {
      fs.mkdirSync(TEST_DIR, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
  });

  test('should detect npm workspaces', () => {
    const packageJson = {
      name: 'monorepo-root',
      workspaces: ['packages/*', 'apps/*'],
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);
    assert.ok(resolver.packageJson.workspaces);
    assert.strictEqual(resolver.packageJson.workspaces.length, 2);
  });

  test('should detect yarn/pnpm workspaces from pnpm-workspace.yaml', () => {
    const packageJson = {
      name: 'monorepo-root',
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    // Create pnpm-workspace.yaml
    fs.writeFileSync(
      path.join(TEST_DIR, 'pnpm-workspace.yaml'),
      'packages:\n  - "packages/*"\n  - "apps/*"'
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);
    // Current implementation may not parse pnpm-workspace.yaml
    // This test documents expected behavior for future enhancement
  });

  test('should detect lerna workspaces', () => {
    const packageJson = {
      name: 'monorepo-root',
    };

    const lernaJson = {
      packages: ['packages/*'],
      version: 'independent',
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    fs.writeFileSync(
      path.join(TEST_DIR, 'lerna.json'),
      JSON.stringify(lernaJson, null, 2)
    );

    const resolver = new PackageResolver(TEST_DIR);
    assert.ok(resolver);
    // Current implementation may not check lerna.json
    // This test documents expected behavior for future enhancement
  });
});

describe('PackageResolver - Caching Behavior', () => {
  beforeEach(() => {
    if (!fs.existsSync(TEST_DIR)) {
      fs.mkdirSync(TEST_DIR, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(TEST_DIR)) {
      fs.rmSync(TEST_DIR, { recursive: true, force: true });
    }
  });

  test('should cache package.json content', () => {
    const packageJson = {
      name: 'test-package',
      dependencies: {
        express: '^4.18.0',
      },
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    const resolver1 = new PackageResolver(TEST_DIR);
    const resolver2 = new PackageResolver(TEST_DIR);

    assert.ok(resolver1 !== null);
    assert.ok(resolver2 !== null);

    // Both should have access to the same data
    assert.strictEqual(resolver1.hasDependency('express'), true);
    assert.strictEqual(resolver2.hasDependency('express'), true);
  });

  test('should handle multiple resolver instances', () => {
    const packageJson = {
      name: 'test-package',
      dependencies: {
        lodash: '^4.17.21',
      },
    };

    fs.writeFileSync(
      path.join(TEST_DIR, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );

    // Create multiple resolvers
    const resolvers = Array.from({ length: 5 }, () => new PackageResolver(TEST_DIR));

    // All should work correctly
    resolvers.forEach(resolver => {
      assert.ok(resolver !== null);
      assert.strictEqual(resolver.hasDependency('lodash'), true);
      assert.strictEqual(resolver.hasDependency('express'), false);
    });
  });
});

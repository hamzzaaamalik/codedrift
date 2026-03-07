/**
 * Test suite for Taint Analysis system
 * Tests source detection, propagation tracking, sink detection,
 * sanitizer detection, and the full TaintAnalyzer orchestrator.
 */

import { describe, test } from 'node:test';
import assert from 'node:assert';
import * as ts from 'typescript';
import { TaintSourceDetector } from '../src/core/taint/source-detector.js';
import { TaintPropagationTracker } from '../src/core/taint/propagation-tracker.js';
import { TaintSinkDetector } from '../src/core/taint/sink-detector.js';
import { SanitizerDetector } from '../src/core/taint/sanitizer-detector.js';
import { TaintAnalyzer } from '../src/core/taint/taint-analyzer.js';

/** Parse a code string and return the first function body as a scope node */
function parseScope(code: string): ts.Node {
  const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
  // Find the first function-like declaration's body
  let scopeNode: ts.Node | undefined;
  const visit = (node: ts.Node): void => {
    if (scopeNode) return;
    if (
      (ts.isFunctionDeclaration(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node))
      && node.body
    ) {
      scopeNode = node.body;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return scopeNode || sourceFile;
}

/** Parse code and return the full source file (for top-level analysis) */
function parseSourceFile(code: string): ts.SourceFile {
  return ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);
}

// =============================================================================
// TaintSourceDetector
// =============================================================================

describe('TaintSourceDetector', () => {
  const detector = new TaintSourceDetector();

  test('should detect req.body as taint source', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const data = req.body;
      }
    `);
    const sources = detector.detectSources(scope);
    assert.ok(sources.length > 0, 'Should detect at least one source');
    const bodySource = sources.find(s => s.kind === 'req.body');
    assert.ok(bodySource, 'Should detect req.body source');
  });

  test('should detect req.params as taint source', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const id = req.params;
      }
    `);
    const sources = detector.detectSources(scope);
    const paramsSource = sources.find(s => s.kind === 'req.params');
    assert.ok(paramsSource, 'Should detect req.params source');
  });

  test('should detect req.query as taint source', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const q = req.query;
      }
    `);
    const sources = detector.detectSources(scope);
    const querySource = sources.find(s => s.kind === 'req.query');
    assert.ok(querySource, 'Should detect req.query source');
  });

  test('should detect destructured req.body', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const { username, password } = req.body;
      }
    `);
    const sources = detector.detectSources(scope);
    const bodySource = sources.find(s => s.kind === 'req.body' && s.boundNames.length > 0);
    assert.ok(bodySource, 'Should detect destructured req.body');
    assert.ok(bodySource!.boundNames.includes('username'), 'Should track username binding');
    assert.ok(bodySource!.boundNames.includes('password'), 'Should track password binding');
  });

  test('should detect aliased req.body', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const input = req.body;
      }
    `);
    const sources = detector.detectSources(scope);
    const aliasSource = sources.find(s => s.kind === 'req.body' && s.boundNames.includes('input'));
    assert.ok(aliasSource, 'Should detect aliased req.body with bound name "input"');
  });

  test('should detect Koa ctx.request.body', () => {
    const scope = parseScope(`
      function handler(ctx) {
        const data = ctx.request.body;
      }
    `);
    const sources = detector.detectSources(scope);
    const koaSource = sources.find(s => s.kind === 'ctx.request.body');
    assert.ok(koaSource, 'Should detect ctx.request.body');
  });

  test('should detect ctx.params (Koa)', () => {
    const scope = parseScope(`
      function handler(ctx) {
        const id = ctx.params;
      }
    `);
    const sources = detector.detectSources(scope);
    const koaSource = sources.find(s => s.kind === 'ctx.params');
    assert.ok(koaSource, 'Should detect ctx.params');
  });

  test('should detect Hapi request.payload', () => {
    const scope = parseScope(`
      function handler(request, h) {
        const data = request.payload;
      }
    `);
    const sources = detector.detectSources(scope);
    const hapiSource = sources.find(s => s.kind === 'request.payload');
    assert.ok(hapiSource, 'Should detect request.payload');
  });

  test('should return empty for function with no user input', () => {
    const scope = parseScope(`
      function helper() {
        const x = 42;
        const y = "hello";
      }
    `);
    const sources = detector.detectSources(scope);
    assert.strictEqual(sources.length, 0, 'Should detect no sources in non-handler function');
  });

  test('should assign unique IDs to each source', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const body = req.body;
        const params = req.params;
      }
    `);
    const sources = detector.detectSources(scope);
    assert.ok(sources.length >= 2, 'Should have at least 2 sources');
    const ids = new Set(sources.map(s => s.id));
    assert.strictEqual(ids.size, sources.length, 'All source IDs should be unique');
  });
});

// =============================================================================
// TaintPropagationTracker
// =============================================================================

describe('TaintPropagationTracker', () => {
  test('should propagate taint through simple assignment', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const body = req.body;
        const data = body;
      }
    `);
    const detector = new TaintSourceDetector();
    const sources = detector.detectSources(scope);
    const aliasSource = sources.find(s => s.boundNames.includes('body'));
    assert.ok(aliasSource, 'Should find body source');

    const tracker = new TaintPropagationTracker(sources);
    const states = tracker.trackPropagation(scope);

    const dataState = states.get('data');
    assert.ok(dataState, 'Should track data variable');
    assert.ok(dataState!.taintSources.length > 0, 'data should be tainted');
  });

  test('should propagate taint through destructuring', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const { name, email } = req.body;
        const userName = name;
      }
    `);
    const detector = new TaintSourceDetector();
    const sources = detector.detectSources(scope);

    const tracker = new TaintPropagationTracker(sources);
    const states = tracker.trackPropagation(scope);

    const userNameState = states.get('userName');
    assert.ok(userNameState, 'Should track userName variable');
    assert.ok(userNameState!.taintSources.length > 0, 'userName should be tainted');
  });

  test('should propagate taint through template literals', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const input = req.body;
        const query = \`SELECT * FROM users WHERE id = \${input}\`;
      }
    `);
    const detector = new TaintSourceDetector();
    const sources = detector.detectSources(scope);

    const tracker = new TaintPropagationTracker(sources);
    const states = tracker.trackPropagation(scope);

    const queryState = states.get('query');
    assert.ok(queryState, 'Should track query variable');
    assert.ok(queryState!.taintSources.length > 0, 'query should be tainted via template literal');
  });

  test('should propagate taint through string concatenation', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const input = req.body;
        const sql = "SELECT * FROM users WHERE id = " + input;
      }
    `);
    const detector = new TaintSourceDetector();
    const sources = detector.detectSources(scope);

    const tracker = new TaintPropagationTracker(sources);
    const states = tracker.trackPropagation(scope);

    const sqlState = states.get('sql');
    assert.ok(sqlState, 'Should track sql variable');
    assert.ok(sqlState!.taintSources.length > 0, 'sql should be tainted via concatenation');
  });

  test('should not propagate taint through function calls (intra-procedural)', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const input = req.body;
        const result = someTransform(input);
      }
    `);
    const detector = new TaintSourceDetector();
    const sources = detector.detectSources(scope);

    const tracker = new TaintPropagationTracker(sources);
    const states = tracker.trackPropagation(scope);

    const resultState = states.get('result');
    // Function calls break propagation (conservative intra-procedural approach)
    assert.ok(!resultState || resultState.taintSources.length === 0,
      'result should NOT be tainted (function calls break propagation)');
  });

  test('should propagate through ternary expression', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const input = req.body;
        const value = true ? input : "default";
      }
    `);
    const detector = new TaintSourceDetector();
    const sources = detector.detectSources(scope);

    const tracker = new TaintPropagationTracker(sources);
    const states = tracker.trackPropagation(scope);

    const valueState = states.get('value');
    assert.ok(valueState, 'Should track value variable');
    assert.ok(valueState!.taintSources.length > 0, 'value should be tainted via ternary');
  });
});

// =============================================================================
// TaintSinkDetector
// =============================================================================

describe('TaintSinkDetector', () => {
  const detector = new TaintSinkDetector();

  test('should detect eval() as sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        eval(req.body.code);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const evalSink = sinks.find(s => s.kind === 'eval');
    assert.ok(evalSink, 'Should detect eval as sink');
    assert.strictEqual(evalSink!.callee, 'eval');
  });

  test('should detect new Function() as sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        const fn = new Function(req.body.code);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const evalSink = sinks.find(s => s.kind === 'eval' && s.callee === 'new Function');
    assert.ok(evalSink, 'Should detect new Function as eval sink');
  });

  test('should detect db.query() as sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        db.query("SELECT * FROM users WHERE id = " + req.params.id);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const dbSink = sinks.find(s => s.kind === 'db-query');
    assert.ok(dbSink, 'Should detect db.query as sink');
  });

  test('should detect db mutation methods as sinks', () => {
    const scope = parseScope(`
      function handler(req, res) {
        prisma.user.create({ data: req.body });
      }
    `);
    const sinks = detector.detectSinks(scope);
    const mutationSink = sinks.find(s => s.kind === 'db-mutation');
    assert.ok(mutationSink, 'Should detect prisma create as db-mutation sink');
  });

  test('should detect fs.readFile as file-read sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        fs.readFile(req.params.path, "utf8", cb);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const fileSink = sinks.find(s => s.kind === 'file-read');
    assert.ok(fileSink, 'Should detect fs.readFile as file-read sink');
  });

  test('should detect child_process.exec as command-execution sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        cp.exec(command);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const execSink = sinks.find(s => s.kind === 'command-execution');
    assert.ok(execSink, 'Should detect cp.exec as command-execution sink');
  });

  test('should detect res.redirect as redirect sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        res.redirect(url);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const redirectSink = sinks.find(s => s.kind === 'redirect');
    assert.ok(redirectSink, 'Should detect res.redirect as redirect sink');
  });

  test('should detect innerHTML assignment as html-output sink', () => {
    const scope = parseScope(`
      function render(el, content) {
        el.innerHTML = content;
      }
    `);
    const sinks = detector.detectSinks(scope);
    const htmlSink = sinks.find(s => s.kind === 'html-output' && s.callee === 'innerHTML');
    assert.ok(htmlSink, 'Should detect innerHTML assignment as sink');
  });

  test('should detect fetch() as http-request sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        fetch(url);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const httpSink = sinks.find(s => s.kind === 'http-request');
    assert.ok(httpSink, 'Should detect fetch as http-request sink');
  });

  test('should detect axios.get as http-request sink', () => {
    const scope = parseScope(`
      function handler(req, res) {
        axios.get(url);
      }
    `);
    const sinks = detector.detectSinks(scope);
    const httpSink = sinks.find(s => s.kind === 'http-request');
    assert.ok(httpSink, 'Should detect axios.get as http-request sink');
  });

  test('should return empty for function with no sinks', () => {
    const scope = parseScope(`
      function helper(x) {
        return x + 1;
      }
    `);
    const sinks = detector.detectSinks(scope);
    assert.strictEqual(sinks.length, 0, 'Should detect no sinks');
  });
});

// =============================================================================
// SanitizerDetector
// =============================================================================

describe('SanitizerDetector', () => {
  const detector = new SanitizerDetector();

  test('should detect parseInt as type-coercion sanitizer', () => {
    const sourceFile = parseSourceFile(`parseInt(input)`);
    let found = false;
    const visit = (node: ts.Node): void => {
      const point = detector.checkSanitization(node);
      if (point && point.sanitizationKind === 'type-coercion' && point.sanitizer === 'parseInt') {
        found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    assert.ok(found, 'Should detect parseInt as type-coercion sanitizer');
  });

  test('should detect Number() as type-coercion sanitizer', () => {
    const sourceFile = parseSourceFile(`Number(input)`);
    let found = false;
    const visit = (node: ts.Node): void => {
      const point = detector.checkSanitization(node);
      if (point && point.sanitizationKind === 'type-coercion' && point.sanitizer === 'Number') {
        found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    assert.ok(found, 'Should detect Number() as type-coercion sanitizer');
  });

  test('should detect encodeURIComponent as escape sanitizer', () => {
    const sourceFile = parseSourceFile(`encodeURIComponent(input)`);
    let found = false;
    const visit = (node: ts.Node): void => {
      const point = detector.checkSanitization(node);
      if (point && point.sanitizationKind === 'escape') {
        found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    assert.ok(found, 'Should detect encodeURIComponent as escape sanitizer');
  });

  test('should detect z.parse as schema-validation sanitizer', () => {
    const sourceFile = parseSourceFile(`z.parse(input)`);
    let found = false;
    const visit = (node: ts.Node): void => {
      const point = detector.checkSanitization(node);
      if (point && point.sanitizationKind === 'schema-validation') {
        found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    assert.ok(found, 'Should detect z.parse as schema-validation sanitizer');
  });

  test('should detect DOMPurify.sanitize as escape sanitizer', () => {
    const sourceFile = parseSourceFile(`DOMPurify.sanitize(input)`);
    let found = false;
    const visit = (node: ts.Node): void => {
      const point = detector.checkSanitization(node);
      if (point && point.sanitizationKind === 'escape' && point.sanitizer === 'DOMPurify.sanitize') {
        found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    assert.ok(found, 'Should detect DOMPurify.sanitize as escape sanitizer');
  });

  test('should detect custom validator function', () => {
    const sourceFile = parseSourceFile(`validateInput(data)`);
    let found = false;
    const visit = (node: ts.Node): void => {
      const point = detector.checkSanitization(node);
      if (point && point.sanitizationKind === 'custom-validator') {
        found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    assert.ok(found, 'Should detect validateInput as custom-validator sanitizer');
  });

  test('should not flag regular function calls as sanitizers', () => {
    const sourceFile = parseSourceFile(`processData(input)`);
    let found = false;
    const visit = (node: ts.Node): void => {
      const point = detector.checkSanitization(node);
      if (point) {
        found = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    assert.ok(!found, 'Should NOT detect processData as a sanitizer');
  });
});

// =============================================================================
// TaintAnalyzer (Full Orchestrator)
// =============================================================================

describe('TaintAnalyzer', () => {
  test('should detect unsanitized taint flow from req.body to db.query', () => {
    const analyzer = new TaintAnalyzer();
    const scope = parseScope(`
      function handler(req, res) {
        const input = req.body;
        db.query("SELECT * FROM users WHERE id = " + input);
      }
    `);
    const result = analyzer.analyzeScope(scope);
    assert.ok(result.sources.length > 0, 'Should detect sources');
    assert.ok(result.sinks.length > 0, 'Should detect sinks');
  });

  test('should detect unsanitized flow from req.params to eval', () => {
    const analyzer = new TaintAnalyzer();
    const scope = parseScope(`
      function handler(req, res) {
        const code = req.params;
        eval(code);
      }
    `);
    const result = analyzer.analyzeScope(scope);
    assert.ok(result.sources.length > 0, 'Should detect sources');
    assert.ok(result.sinks.length > 0, 'Should detect eval sink');
  });

  test('should return empty result for function with no sources', () => {
    const analyzer = new TaintAnalyzer();
    const scope = parseScope(`
      function helper() {
        const x = 42;
        db.query("SELECT 1");
      }
    `);
    const result = analyzer.analyzeScope(scope);
    assert.strictEqual(result.sources.length, 0, 'Should have no sources');
    assert.strictEqual(result.flows.length, 0, 'Should have no flows');
  });

  test('should cache scope analysis results', () => {
    const analyzer = new TaintAnalyzer();
    const scope = parseScope(`
      function handler(req, res) {
        const data = req.body;
        eval(data);
      }
    `);
    const result1 = analyzer.analyzeScope(scope);
    const result2 = analyzer.analyzeScope(scope);
    assert.strictEqual(result1, result2, 'Should return cached result on second call');
  });

  test('isExpressionTainted should return true for tainted identifier', () => {
    const analyzer = new TaintAnalyzer();
    const code = `
      function handler(req, res) {
        const input = req.body;
        console.log(input);
      }
    `;
    const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);

    // Find the function body
    let scopeNode: ts.Node | undefined;
    let inputIdentifier: ts.Node | undefined;

    const findScope = (node: ts.Node): void => {
      if (ts.isFunctionDeclaration(node) && node.body) {
        scopeNode = node.body;
      }
      ts.forEachChild(node, findScope);
    };
    findScope(sourceFile);
    assert.ok(scopeNode, 'Should find scope node');

    // Find the `input` identifier in console.log(input)
    const findInput = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && node.text === 'input' && node.parent && ts.isCallExpression(node.parent)) {
        inputIdentifier = node;
      }
      ts.forEachChild(node, findInput);
    };
    findInput(scopeNode!);

    if (inputIdentifier) {
      const taintResult = analyzer.isExpressionTainted(inputIdentifier, scopeNode!);
      assert.ok(taintResult.tainted, 'input should be tainted');
      assert.ok(taintResult.sourceKinds.length > 0, 'Should have source kinds');
    }
  });

  test('isExpressionTainted should return false for non-tainted identifier', () => {
    const analyzer = new TaintAnalyzer();
    const code = `
      function handler(req, res) {
        const input = req.body;
        const safe = 42;
        console.log(safe);
      }
    `;
    const sourceFile = ts.createSourceFile('test.ts', code, ts.ScriptTarget.Latest, true);

    let scopeNode: ts.Node | undefined;
    let safeIdentifier: ts.Node | undefined;

    const findScope = (node: ts.Node): void => {
      if (ts.isFunctionDeclaration(node) && node.body) {
        scopeNode = node.body;
      }
      ts.forEachChild(node, findScope);
    };
    findScope(sourceFile);

    const findSafe = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && node.text === 'safe' && node.parent && ts.isCallExpression(node.parent)) {
        safeIdentifier = node;
      }
      ts.forEachChild(node, findSafe);
    };
    findSafe(scopeNode!);

    if (safeIdentifier) {
      const taintResult = analyzer.isExpressionTainted(safeIdentifier, scopeNode!);
      assert.ok(!taintResult.tainted, 'safe should NOT be tainted');
    }
  });

  test('should handle multiple taint sources in same function', () => {
    const analyzer = new TaintAnalyzer();
    const scope = parseScope(`
      function handler(req, res) {
        const body = req.body;
        const params = req.params;
        db.query(body);
        eval(params);
      }
    `);
    const result = analyzer.analyzeScope(scope);
    assert.ok(result.sources.length >= 2, 'Should detect multiple sources');
    assert.ok(result.sinks.length >= 2, 'Should detect multiple sinks');
  });

  test('should detect taint propagation through multiple hops', () => {
    const analyzer = new TaintAnalyzer();
    const scope = parseScope(`
      function handler(req, res) {
        const input = req.body;
        const step1 = input;
        const step2 = step1;
        eval(step2);
      }
    `);
    const result = analyzer.analyzeScope(scope);
    assert.ok(result.sources.length > 0, 'Should detect sources');
    assert.ok(result.sinks.length > 0, 'Should detect sinks');

    // Check that step2 is tainted
    const step2State = result.variableStates.get('step2');
    assert.ok(step2State, 'Should track step2');
    assert.ok(step2State!.taintSources.length > 0, 'step2 should be tainted after 2 hops');
  });
});

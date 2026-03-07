/**
 * TaintSinkDetector — Identifies dangerous operations where tainted data
 * should not reach unsanitized.
 */

import * as ts from 'typescript';
import { TaintSink, TaintSinkKind } from './types.js';

// --- Sink pattern tables ---

const DB_QUERY_METHODS = new Set([
  'findById', 'findOne', 'findUnique', 'findFirst', 'findMany',
  'query', 'where', 'select', 'findByPk', 'aggregate',
]);

const DB_MUTATION_METHODS = new Set([
  'create', 'insert', 'update', 'delete', 'destroy', 'save',
  'upsert', 'remove', 'deleteOne', 'deleteMany', 'updateOne',
  'updateMany', 'insertMany',
]);

const FILE_READ_METHODS = new Set([
  'readFile', 'readFileSync', 'createReadStream', 'access',
]);

const FILE_WRITE_METHODS = new Set([
  'writeFile', 'writeFileSync', 'createWriteStream', 'unlink', 'rename',
]);

const COMMAND_EXEC_METHODS = new Set([
  'exec', 'execSync', 'spawn', 'spawnSync',
]);

const REDIRECT_METHODS = new Set([
  'redirect',
]);

const EVAL_FUNCTIONS = new Set([
  'eval', 'Function',
]);

const TIMER_WITH_STRING = new Set([
  'setTimeout', 'setInterval',
]);

const TEMPLATE_RENDER_METHODS = new Set([
  'render', 'compile',
]);

const TEMPLATE_CALLERS = new Set([
  'ejs', 'pug', 'handlebars',
]);

const SSRF_FUNCTIONS = new Set([
  'fetch', 'got',
]);

const SSRF_MODULES = new Set([
  'axios', 'http', 'https', 'undici',
]);

const SSRF_METHODS = new Set([
  'get', 'post', 'put', 'patch', 'delete', 'request', 'fetch',
]);

export class TaintSinkDetector {
  /**
   * Walk `scopeNode` and return every detected taint sink.
   */
  detectSinks(scopeNode: ts.Node): TaintSink[] {
    const sinks: TaintSink[] = [];
    const visit = (node: ts.Node): void => {
      // --- Assignment sinks (innerHTML) ---
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const left = node.left;
        if (ts.isPropertyAccessExpression(left) && left.name.text === 'innerHTML') {
          sinks.push(this.makeSink('html-output', node, 'innerHTML', node.getStart()));
        }
      }

      // --- Call expression sinks ---
      if (ts.isCallExpression(node)) {
        const sink = this.classifyCall(node);
        if (sink) {
          sinks.push(sink);
        }
      }

      // --- new Function() ---
      if (ts.isNewExpression(node)) {
        const expr = node.expression;
        if (ts.isIdentifier(expr) && expr.text === 'Function') {
          sinks.push(this.makeSink('eval', node, 'new Function', node.getStart()));
        }
      }

      ts.forEachChild(node, visit);
    };
    visit(scopeNode);
    return sinks;
  }

  // ---- Private helpers ----

  private classifyCall(node: ts.CallExpression): TaintSink | null {
    const callee = node.expression;

    // ---- Simple identifier calls ----
    if (ts.isIdentifier(callee)) {
      const name = callee.text;

      // eval()
      if (EVAL_FUNCTIONS.has(name)) {
        return this.makeSink('eval', node, name, node.getStart());
      }

      // setTimeout / setInterval with string first arg
      if (TIMER_WITH_STRING.has(name) && this.firstArgIsStringLike(node)) {
        return this.makeSink('eval', node, name, node.getStart());
      }

      // exec / execSync (imported directly)
      if (COMMAND_EXEC_METHODS.has(name)) {
        return this.makeSink('command-execution', node, name, node.getStart());
      }

      // fetch / got (global or imported)
      if (SSRF_FUNCTIONS.has(name)) {
        return this.makeSink('http-request', node, name, node.getStart());
      }

      // axios() as a direct call
      if (name === 'axios') {
        return this.makeSink('http-request', node, 'axios', node.getStart());
      }

      return null;
    }

    // ---- Property access calls: obj.method() ----
    if (ts.isPropertyAccessExpression(callee)) {
      return this.classifyPropertyAccess(node, callee);
    }

    return null;
  }

  private classifyPropertyAccess(
    node: ts.CallExpression,
    callee: ts.PropertyAccessExpression,
  ): TaintSink | null {
    const method = callee.name.text;
    const calleeText = callee.getText();
    const objText = callee.expression.getText();

    // --- DB query: prisma.*.find*, Model.find*, knex('table').where, db/pool/sequelize.query ---
    if (DB_QUERY_METHODS.has(method)) {
      return this.makeSink('db-query', node, calleeText, node.getStart());
    }

    // --- DB mutation ---
    if (DB_MUTATION_METHODS.has(method)) {
      return this.makeSink('db-mutation', node, calleeText, node.getStart());
    }

    // --- File read: fs.readFile etc. ---
    if (FILE_READ_METHODS.has(method) && this.looksLikeFsOrPath(objText)) {
      return this.makeSink('file-read', node, calleeText, node.getStart());
    }

    // --- File write: fs.writeFile etc. ---
    if (FILE_WRITE_METHODS.has(method) && this.looksLikeFsOrPath(objText)) {
      return this.makeSink('file-write', node, calleeText, node.getStart());
    }

    // --- Command execution: child_process.exec etc. ---
    if (COMMAND_EXEC_METHODS.has(method) && this.looksLikeChildProcess(objText)) {
      return this.makeSink('command-execution', node, calleeText, node.getStart());
    }

    // --- HTML output: res.send (with string arg), document.write ---
    if (method === 'send' && this.looksLikeResponse(objText)) {
      return this.makeSink('html-output', node, calleeText, node.getStart());
    }
    if (method === 'write' && objText === 'document') {
      return this.makeSink('html-output', node, calleeText, node.getStart());
    }

    // --- Template render: res.render, ejs.render, pug.render, handlebars.compile ---
    if (TEMPLATE_RENDER_METHODS.has(method)) {
      if (this.looksLikeResponse(objText) || TEMPLATE_CALLERS.has(objText)) {
        return this.makeSink('html-output', node, calleeText, node.getStart());
      }
    }

    // --- Redirect ---
    if (REDIRECT_METHODS.has(method) && this.looksLikeResponse(objText)) {
      return this.makeSink('redirect', node, calleeText, node.getStart());
    }

    // --- SSRF: axios.get, http.get, http.request, undici.fetch ---
    if (SSRF_MODULES.has(objText) && SSRF_METHODS.has(method)) {
      return this.makeSink('http-request', node, calleeText, node.getStart());
    }

    return null;
  }

  // ---- Heuristic helpers ----

  private looksLikeFsOrPath(name: string): boolean {
    return /^(fs|fsp|fsPromises|path)$/.test(name);
  }

  private looksLikeChildProcess(name: string): boolean {
    return /^(child_process|cp|childProcess)$/.test(name);
  }

  private looksLikeResponse(name: string): boolean {
    return /^(res|response|ctx|reply)$/.test(name);
  }

  private firstArgIsStringLike(node: ts.CallExpression): boolean {
    const firstArg = node.arguments[0];
    if (!firstArg) return false;
    return ts.isStringLiteral(firstArg)
      || ts.isTemplateExpression(firstArg)
      || ts.isNoSubstitutionTemplateLiteral(firstArg)
      || ts.isIdentifier(firstArg);
  }

  private makeSink(
    kind: TaintSinkKind,
    node: ts.Node,
    callee: string,
    position: number,
  ): TaintSink {
    return {
      kind,
      node,
      callee,
      taintedArgIndices: [],
      position,
    };
  }
}

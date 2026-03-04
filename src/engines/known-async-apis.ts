/**
 * Known Async API Database
 * Maps object/class names to their known-async method names.
 * Used by MissingAwaitDetector for high-confidence detection.
 */

import { SYNC_OBJECTS } from './known-sync-apis.js';

// ──────────────────── Method Databases ────────────────────

/** ORM query methods (shared across Sequelize, Mongoose, Prisma, TypeORM) */
const ORM_READ_METHODS = new Set([
  'find', 'findOne', 'findById', 'findByPk', 'findFirst', 'findUnique',
  'findAll', 'findMany', 'findOneBy', 'findAndCountAll', 'findOneOrFail',
  'findOneAndUpdate', 'findOneAndDelete', 'findByIdAndUpdate', 'findByIdAndDelete',
  'findFirstOrThrow', 'findUniqueOrThrow',
  'count', 'countDocuments', 'aggregate', 'groupBy',
  'max', 'min', 'sum', 'query',
  'reload', 'populate',
]);

/** ORM write methods */
const ORM_WRITE_METHODS = new Set([
  'create', 'createMany', 'bulkCreate', 'insertMany',
  'save', 'update', 'updateOne', 'updateMany', 'upsert',
  'delete', 'deleteOne', 'deleteMany', 'destroy', 'remove',
  'softDelete', 'softRemove', 'restore',
]);

/** All ORM methods combined */
const ORM_ALL_METHODS = new Set([...ORM_READ_METHODS, ...ORM_WRITE_METHODS, 'exec']);

/** JS built-in constructors and common non-ORM PascalCase classes — never ORM models */
const JS_BUILTINS = new Set([
  // JS/Node built-ins
  'Array', 'Map', 'Set', 'Object', 'String', 'Number', 'Boolean',
  'RegExp', 'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError',
  'Date', 'Math', 'JSON', 'Promise', 'Symbol', 'Proxy', 'Reflect',
  'WeakMap', 'WeakSet', 'Buffer', 'Int8Array', 'Uint8Array', 'Float32Array',
  'Float64Array', 'ArrayBuffer', 'SharedArrayBuffer', 'DataView',
  'Intl', 'URL', 'URLSearchParams', 'AbortController', 'AbortSignal',
  'TextEncoder', 'TextDecoder', 'FormData', 'Headers', 'Request', 'Response',

  // Math/BigNumber libraries (PascalCase but NOT ORM models)
  'BigNumber', 'Decimal', 'BN', 'Big', 'Fraction', 'Complex',

  // Date/time libraries
  'Duration', 'DateTime', 'Moment', 'Interval',

  // Node.js internals
  'EventEmitter', 'Stream', 'Transform', 'Readable', 'Writable',
  'Duplex', 'PassThrough', 'Socket', 'Server', 'Console',

  // Common non-ORM PascalCase classes (sync operations)
  'Scheduler', 'Pipeline', 'Container', 'Registry', 'Queue',
  'Stack', 'Counter', 'Timer', 'Iterator', 'Observer',
  'Emitter', 'Logger', 'Cache', 'Pool', 'Channel',
]);

/** Maps exact object names to their async method sets */
export const KNOWN_ASYNC_METHODS = new Map<string, Set<string>>([
  // ── Node.js fs/promises ──
  ['fs', new Set([
    'readFile', 'writeFile', 'unlink', 'mkdir', 'readdir', 'stat',
    'access', 'rename', 'copyFile', 'rm', 'chmod', 'chown',
    'appendFile', 'truncate', 'open', 'realpath', 'symlink', 'link',
    'lstat', 'mkdtemp', 'cp',
  ])],
  ['fsPromises', new Set([
    'readFile', 'writeFile', 'unlink', 'mkdir', 'readdir', 'stat',
    'access', 'rename', 'copyFile', 'rm', 'chmod', 'chown',
    'appendFile', 'truncate', 'open', 'realpath', 'symlink', 'link',
    'lstat', 'mkdtemp', 'cp',
  ])],

  // ── Prisma client ──
  ['prisma', new Set(['$transaction', '$queryRaw', '$executeRaw', '$connect', '$disconnect'])],

  // ── Knex ──
  ['knex', new Set(['select', 'insert', 'update', 'delete', 'raw', 'transaction', 'first'])],

  // ── Redis ──
  ['redis', new Set([
    'get', 'set', 'del', 'hget', 'hset', 'lpush', 'rpush', 'lrange',
    'sadd', 'smembers', 'zadd', 'zrange', 'publish', 'subscribe',
    'expire', 'ttl', 'exists', 'mget', 'mset', 'incr', 'decr',
    'setnx', 'setex', 'psetex', 'hdel', 'hgetall', 'hmset',
    'connect', 'disconnect', 'quit', 'ping',
    'lpop', 'rpop', 'srem', 'sismember', 'scard',
    'zrem', 'zscore', 'zcard', 'keys', 'scan', 'eval',
  ])],

  // ── HTTP clients ──
  ['axios', new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request'])],
  ['got', new Set(['get', 'post', 'put', 'delete', 'patch', 'head'])],
  ['superagent', new Set(['get', 'post', 'put', 'delete', 'patch'])],

  // ── Crypto ──
  ['bcrypt', new Set(['hash', 'compare', 'genSalt'])],

  // ── Image processing ──
  ['sharp', new Set(['toBuffer', 'toFile', 'metadata', 'stats'])],

  // ── Email ──
  ['transporter', new Set(['sendMail'])],
  ['nodemailer', new Set(['sendMail'])],
  ['mailer', new Set(['sendMail', 'send'])],

  // ── Stripe sub-objects (stripe.customers, stripe.charges, etc.) ──
  ['customers', new Set(['create', 'retrieve', 'update', 'del', 'list'])],
  ['charges', new Set(['create', 'retrieve', 'update', 'list', 'capture'])],
  ['paymentIntents', new Set(['create', 'retrieve', 'update', 'confirm', 'cancel', 'list'])],
  ['subscriptions', new Set(['create', 'retrieve', 'update', 'del', 'list'])],
  ['refunds', new Set(['create', 'retrieve', 'update', 'list'])],
  ['transfers', new Set(['create', 'retrieve', 'update', 'list'])],
  ['disputes', new Set(['retrieve', 'update', 'list', 'close'])],
  ['invoices', new Set(['create', 'retrieve', 'update', 'del', 'list', 'pay', 'sendInvoice', 'voidInvoice', 'finalizeInvoice'])],

  // ── Node.js streams (promisified) ──
  ['stream', new Set(['pipeline', 'finished'])],
]);

/** Standalone async functions (no object prefix) */
const KNOWN_ASYNC_STANDALONE = new Set<string>([
  'fetch',
]);

// ──────────────────── Category Classification ────────────────────

/** DB write method names */
const DB_WRITE_SET = new Set([
  'create', 'createMany', 'bulkCreate', 'insertMany',
  'save', 'update', 'updateOne', 'updateMany', 'upsert',
  'delete', 'deleteOne', 'deleteMany', 'destroy', 'remove',
  'softDelete', 'softRemove', 'restore',
  '$transaction', '$queryRaw', '$executeRaw',
  'insert', 'raw', 'transaction',
]);

/** DB read method names */
const DB_READ_SET = new Set([
  'find', 'findOne', 'findById', 'findByPk', 'findFirst', 'findUnique',
  'findAll', 'findMany', 'findOneBy', 'findAndCountAll', 'findOneOrFail',
  'findOneAndUpdate', 'findOneAndDelete', 'findByIdAndUpdate', 'findByIdAndDelete',
  'findFirstOrThrow', 'findUniqueOrThrow',
  'count', 'countDocuments', 'aggregate', 'groupBy', 'max', 'min', 'sum',
  'select', 'first', 'exec', 'reload', 'populate', 'query',
]);

/** File system method names */
const FS_SET = new Set([
  'readFile', 'writeFile', 'unlink', 'mkdir', 'readdir', 'stat',
  'access', 'rename', 'copyFile', 'rm', 'chmod', 'chown',
  'appendFile', 'truncate', 'open', 'realpath', 'symlink', 'link',
  'lstat', 'mkdtemp', 'cp',
]);

/** Cache method names */
const CACHE_SET = new Set([
  'get', 'set', 'del', 'expire', 'ttl', 'exists',
  'hget', 'hset', 'lpush', 'rpush', 'lrange',
  'sadd', 'smembers', 'zadd', 'zrange',
  'mget', 'mset', 'incr', 'decr', 'setnx', 'setex',
  'connect', 'disconnect', 'quit', 'ping',
]);

/** Payment objects */
const PAYMENT_OBJECTS = new Set([
  'customers', 'charges', 'paymentIntents', 'subscriptions',
  'refunds', 'transfers', 'disputes', 'invoices',
]);

// ──────────────────── Lookup Functions ────────────────────

/**
 * Check if objectName.methodName is a known async API.
 * Uses exact map lookup + heuristic for PascalCase / ORM-suffix objects.
 */
export function isKnownAsyncAPI(objectName: string | null, methodName: string): boolean {
  // Standalone functions (no object)
  if (!objectName) {
    return KNOWN_ASYNC_STANDALONE.has(methodName);
  }

  // Known sync objects — never async (BigNumber, Decimal, moment, lodash, etc.)
  if (SYNC_OBJECTS.has(objectName)) return false;

  // Exact match in the known methods map
  const methods = KNOWN_ASYNC_METHODS.get(objectName);
  if (methods && methods.has(methodName)) {
    return true;
  }

  // Heuristic: PascalCase object names are likely ORM models (User.findOne, Order.create)
  // BUT exclude JS built-in constructors (Array.find, Map.delete, Set.delete, etc.)
  if (/^[A-Z][a-zA-Z]+$/.test(objectName) && !JS_BUILTINS.has(objectName) && ORM_ALL_METHODS.has(methodName)) {
    return true;
  }

  // Heuristic: objects ending with common ORM suffixes
  const ormSuffixes = ['Model', 'Repository', 'Repo', 'Service', 'Client', 'Manager'];
  if (ormSuffixes.some(s => objectName.endsWith(s)) && ORM_ALL_METHODS.has(methodName)) {
    return true;
  }

  // Heuristic: lowercase model-like names like "db" or "database"
  const dbObjects = ['db', 'database', 'connection', 'pool', 'queryRunner', 'entityManager', 'em', 'repository', 'repo'];
  if (dbObjects.includes(objectName) && ORM_ALL_METHODS.has(methodName)) {
    return true;
  }

  return false;
}

/**
 * Classify the API category for severity determination.
 * Returns null if not a recognized API.
 */
export function getAPICategory(objectName: string | null, methodName: string): string | null {
  if (!objectName) {
    if (methodName === 'fetch') return 'http';
    return null;
  }

  // File system
  if ((objectName === 'fs' || objectName === 'fsPromises') && FS_SET.has(methodName)) {
    return 'fs';
  }

  // HTTP clients
  if (['axios', 'got', 'superagent'].includes(objectName)) {
    return 'http';
  }

  // Redis/Cache
  if (['redis', 'cache', 'memcached'].includes(objectName) && CACHE_SET.has(methodName)) {
    return 'cache';
  }

  // Payment
  if (PAYMENT_OBJECTS.has(objectName)) {
    return 'payment';
  }

  // Email
  if (['transporter', 'nodemailer', 'mailer'].includes(objectName) && (methodName === 'sendMail' || methodName === 'send')) {
    return 'email';
  }

  // Crypto
  if (objectName === 'bcrypt') {
    return 'crypto';
  }

  // DB write vs read (ORM patterns) — exclude JS builtins
  if (!JS_BUILTINS.has(objectName)) {
    if (DB_WRITE_SET.has(methodName)) {
      if (/^[A-Z]/.test(objectName) || ['db', 'database', 'connection', 'pool', 'knex', 'prisma', 'queryRunner', 'entityManager', 'em', 'repository', 'repo'].includes(objectName)
        || objectName.endsWith('Model') || objectName.endsWith('Repository') || objectName.endsWith('Repo') || objectName.endsWith('Service')) {
        return 'db-write';
      }
    }

    if (DB_READ_SET.has(methodName)) {
      if (/^[A-Z]/.test(objectName) || ['db', 'database', 'connection', 'pool', 'knex', 'prisma', 'queryRunner', 'entityManager', 'em', 'repository', 'repo'].includes(objectName)
        || objectName.endsWith('Model') || objectName.endsWith('Repository') || objectName.endsWith('Repo') || objectName.endsWith('Service')) {
        return 'db-read';
      }
    }
  }

  return null;
}

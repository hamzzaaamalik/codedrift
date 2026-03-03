/**
 * Known Sync API Database
 * Centralized database of objects, methods, and patterns that are always synchronous.
 * Used by MissingAwaitDetector to eliminate false positives from naming heuristics.
 *
 * Design: Combines explicit lists with pattern-based detection for comprehensive
 * coverage across any codebase without requiring hardcoded entries for every library.
 */

// ──────────────────── Sync Objects ────────────────────

/** Objects whose ALL methods are synchronous — never flag calls on these */
export const SYNC_OBJECTS = new Set([
  // ── JS Built-ins ──
  'console', 'Math', 'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean',
  'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'ReferenceError', 'SyntaxError',
  'Set', 'Map', 'WeakMap', 'WeakSet', 'WeakRef',
  'Symbol', 'Reflect', 'Proxy', 'Intl',
  'Int8Array', 'Uint8Array', 'Uint8ClampedArray', 'Int16Array', 'Uint16Array',
  'Int32Array', 'Uint32Array', 'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array',
  'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'TextEncoder', 'TextDecoder',
  'URL', 'URLSearchParams',

  // ── Node.js sync modules / globals ──
  'path', 'os', 'url', 'util', 'querystring', 'crypto',
  'Buffer', 'process', 'EventEmitter',

  // ── Math/BigNumber libraries ──
  'BigNumber', 'Decimal', 'BN', 'Big', 'Fraction', 'Complex',

  // ── Date/time libraries ──
  'moment', 'dayjs', 'luxon', 'DateTime', 'Duration', 'Interval',

  // ── Utility libraries ──
  '_', 'lodash', 'R', 'Ramda', 'fp', 'immutable',
  'Immutable', 'List', 'OrderedMap', 'Stack', 'Record',

  // ── FormData ──
  'formData', 'FormData',

  // ── Validation libraries ──
  'Joi', 'yup', 'zod', 'z', 'ajv', 'validator',

  // ── CLI / display ──
  'chalk', 'ora', 'kleur', 'picocolors', 'ansi', 'colors',
  'figures', 'logSymbols', 'cliProgress',

  // ── Config / env ──
  'config', 'dotenv', 'env',

  // ── Common utility patterns ──
  'EnumOps', 'Enum', 'UuidGenerator', 'uuid', 'nanoid', 'cuid',
  'classNames', 'clsx', 'cx',
]);

// ──────────────────── Sync Object Patterns ────────────────────

/**
 * Patterns for object names that suggest synchronous usage.
 * These catch common naming conventions without hardcoding every library.
 */
const SYNC_OBJECT_PATTERNS = [
  /^(Math|JSON|Object|Array|String|Number|Boolean|Date|RegExp|Error|Set|Map)/,
  /Utils?$/i,       // StringUtils, DateUtils, ArrayUtil
  /Helper$/i,       // ValidationHelper, FormatHelper
  /Builder$/i,      // QueryBuilder (sync builder pattern), StringBuilder
  /Factory$/i,      // UserFactory (factory pattern is sync)
  /Formatter$/i,    // DateFormatter, CurrencyFormatter
  /Parser$/i,       // CSVParser, URLParser (the parse method is sync)
  /Converter$/i,    // CurrencyConverter, UnitConverter
  /Validator$/i,    // EmailValidator, SchemaValidator
  /Mapper$/i,       // DTOMapper, EntityMapper
  /Transformer$/i,  // DataTransformer
  /Serializer$/i,   // JSONSerializer
  /Config$/i,       // AppConfig, DBConfig
  /Constants?$/i,   // AppConstants
  /Enum$/i,         // StatusEnum, RoleEnum
  /Schema$/i,       // UserSchema (schema definition is sync)
];

/**
 * Check if an object name matches sync patterns (beyond the explicit SYNC_OBJECTS set).
 */
export function matchesSyncObjectPattern(objectName: string): boolean {
  return SYNC_OBJECT_PATTERNS.some(pattern => pattern.test(objectName));
}

// ──────────────────── Sync Methods ────────────────────

/** Method names that are always synchronous regardless of object */
export const SYNC_METHODS = new Set([
  // ── Array mutators ──
  'push', 'pop', 'shift', 'unshift', 'slice', 'splice', 'sort', 'reverse',
  'fill', 'copyWithin', 'flat', 'at',
  // ── Array iterators (sync versions) ──
  'map', 'filter', 'reduce', 'reduceRight', 'forEach', 'find', 'some', 'every',
  'findIndex', 'findLast', 'findLastIndex', 'flatMap',
  // ── String methods ──
  'toString', 'toLowerCase', 'toUpperCase', 'trim', 'trimStart', 'trimEnd',
  'split', 'join', 'substring', 'substr', 'slice',
  'includes', 'startsWith', 'endsWith', 'indexOf', 'lastIndexOf',
  'match', 'matchAll', 'replace', 'replaceAll', 'search',
  'charAt', 'charCodeAt', 'codePointAt', 'padStart', 'padEnd', 'repeat',
  'normalize', 'localeCompare', 'concat', 'at',
  // ── Map/Set/WeakMap ──
  'add', 'set', 'get', 'has', 'delete', 'clear', 'keys', 'values', 'entries',
  'forEach', 'size',
  // ── Object statics ──
  'freeze', 'assign', 'create', 'defineProperty', 'defineProperties',
  'getOwnPropertyNames', 'getOwnPropertyDescriptor', 'getOwnPropertyDescriptors',
  'getOwnPropertySymbols', 'getPrototypeOf', 'setPrototypeOf',
  'fromEntries', 'isArray', 'from', 'of', 'is', 'isFrozen', 'isSealed', 'isExtensible',
  'preventExtensions', 'seal',
  // ── Type conversion / inspection ──
  'toJSON', 'valueOf', 'toFixed', 'toPrecision', 'toNumber', 'toLocaleString',
  'toISOString', 'toDateString', 'toTimeString', 'toUTCString', 'toLocaleDateString',
  'toLocaleTimeString', 'getTime', 'getFullYear', 'getMonth', 'getDate', 'getDay',
  'getHours', 'getMinutes', 'getSeconds', 'getMilliseconds', 'getTimezoneOffset',
  'setFullYear', 'setMonth', 'setDate', 'setHours', 'setMinutes', 'setSeconds',
  // ── JSON/encoding ──
  'stringify', 'parse', 'encode', 'decode',
  // ── BigNumber/Decimal ──
  'plus', 'minus', 'multipliedBy', 'dividedBy', 'dividedToIntegerBy', 'modulo',
  'exponentiatedBy', 'negated', 'squareRoot',
  'isEqualTo', 'isGreaterThan', 'isGreaterThanOrEqualTo', 'isLessThan', 'isLessThanOrEqualTo',
  'isZero', 'isNaN', 'isFinite', 'isNegative', 'isPositive', 'isInteger',
  'abs', 'ceil', 'floor', 'round', 'sqrt', 'pow', 'min', 'max',
  'toFixed', 'toPrecision', 'toNumber', 'toFormat',
  'dp', 'decimalPlaces', 'precision', 'shiftedBy',
  // ── Date/moment methods ──
  'format', 'startOf', 'endOf', 'isBefore', 'isAfter', 'isSame', 'isBetween',
  'isSameOrBefore', 'isSameOrAfter', 'diff', 'clone',
  'utc', 'local', 'unix', 'toDate', 'toObject', 'toArray',
  'year', 'month', 'date', 'day', 'hour', 'minute', 'second', 'millisecond',
  'daysInMonth', 'weeksInYear', 'isoWeeksInYear',
  'isValid', 'isDST', 'isLeapYear', 'locale', 'tz',
  // ── Path ──
  'resolve', 'basename', 'dirname', 'extname', 'isAbsolute', 'relative', 'sep',
  'normalize', 'parse', 'format',
  // ── FormData ──
  'getHeaders', 'getBoundary', 'getBuffer', 'getLengthSync', 'append',
  // ── Crypto (sync) ──
  'createHash', 'createHmac', 'randomUUID', 'digest', 'update',
  'createCipheriv', 'createDecipheriv',
  // ── Console/logging ──
  'log', 'warn', 'error', 'info', 'debug', 'trace', 'dir', 'table',
  'time', 'timeEnd', 'timeLog', 'count', 'countReset', 'group', 'groupEnd',
  'assert', 'clear', 'profile', 'profileEnd',
  // ── Process ──
  'exit', 'cwd', 'env', 'argv', 'pid', 'ppid', 'platform', 'arch',
  'memoryUsage', 'cpuUsage', 'uptime', 'hrtime', 'kill',
  // ── Chalk/color methods ──
  'bold', 'red', 'green', 'yellow', 'blue', 'cyan', 'magenta', 'white', 'gray',
  'grey', 'black', 'dim', 'italic', 'underline', 'inverse', 'strikethrough',
  'visible', 'hidden', 'reset', 'bgRed', 'bgGreen', 'bgYellow', 'bgBlue',
  'bgCyan', 'bgMagenta', 'bgWhite', 'bgBlack', 'hex', 'rgb', 'hsl',
  // ── URL methods ──
  'searchParams', 'pathname', 'hostname', 'protocol', 'port', 'hash', 'origin',
  // ── Validation (zod, joi, yup) ──
  'string', 'number', 'boolean', 'object', 'array', 'enum', 'union', 'intersection',
  'optional', 'nullable', 'required', 'default', 'describe', 'label',
  'min', 'max', 'length', 'email', 'url', 'uuid', 'regex', 'refine',
  'shape', 'extend', 'merge', 'pick', 'omit', 'partial', 'strict', 'passthrough',
  'safeParse', 'parseAsync',
  // ── Immutable.js ──
  'toJS', 'toJSON', 'toArray', 'toObject', 'toMap', 'toList', 'toSet',
  'getIn', 'setIn', 'updateIn', 'deleteIn', 'mergeIn', 'mergeDeepIn',
  'withMutations', 'asMutable', 'asImmutable',
  // ── Codedrift internal (prevent self-flagging) ──
  'createIssue', 'loadPackageJson', 'extractPackageName',
  'checkMissingAwait', 'checkResponseCall', 'checkLoggerCall',
  'containsStackTrace', 'containsSensitiveData',
  'getDefaultBaselinePath', 'saveBaseline', 'loadBaseline',
]);

// ──────────────────── Sync Prefixes ────────────────────

/**
 * Function name prefixes that suggest synchronous computation (not I/O).
 * Used to veto MEDIUM/LOW confidence async findings.
 *
 * IMPORTANT: Does NOT include async-leaning prefixes:
 * fetch*, find*, get*, load*, save*, send*, create*, update*, delete*, remove*, query*, request*
 */
const SYNC_PREFIXES = [
  // ── Data transformation ──
  'convert', 'format', 'parse', 'serialize', 'deserialize', 'transform',
  'stringify', 'marshal', 'unmarshal', 'coerce', 'cast',
  // ── Validation / predicates ──
  'validate', 'check', 'is', 'has', 'can', 'should', 'does', 'will',
  'assert', 'ensure', 'verify', 'require', 'expect', 'test',
  // ── Computation ──
  'calculate', 'compute', 'count', 'sum', 'average', 'total', 'aggregate',
  'min', 'max', 'clamp', 'interpolate', 'lerp', 'round',
  // ── Collection operations ──
  'merge', 'combine', 'concat', 'flatten', 'group', 'partition', 'zip', 'unzip',
  'chunk', 'batch', 'paginate', 'deduplicate', 'unique',
  // ── Duplication ──
  'clone', 'copy', 'duplicate', 'snapshot',
  // ── Sanitization ──
  'normalize', 'sanitize', 'clean', 'strip', 'trim', 'escape', 'unescape',
  'scrub', 'purify', 'whitelist', 'blacklist',
  // ── Composition ──
  'wrap', 'unwrap', 'extract', 'build', 'compose', 'pipe', 'apply',
  'bind', 'curry', 'partial', 'memoize', 'debounce', 'throttle',
  // ── Comparison ──
  'compare', 'diff', 'equals', 'match', 'matches',
  // ── Conversion prefixes ──
  'to', 'from', 'into', 'as',
  // ── Encoding ──
  'encode', 'decode', 'compress', 'decompress', 'encrypt', 'decrypt', 'hash',
  // ── Functional ──
  'map', 'reduce', 'filter', 'sort', 'order', 'rank',
  // ── Rendering (in-memory) ──
  'generate', 'render', 'template', 'compile',
  // ── String operations ──
  'capitalize', 'camelCase', 'snakeCase', 'kebabCase', 'titleCase',
  'pluralize', 'singularize', 'truncate', 'abbreviate',
  // ── Sizing / measurement ──
  'measure', 'size', 'width', 'height', 'length', 'area', 'volume',
  // ── Type narrowing ──
  'narrow', 'widen', 'infer', 'resolve', 'derive',
  // ── Structural ──
  'pick', 'omit', 'pluck', 'project', 'select', 'exclude',
  'restructure', 'reshape', 'reformat', 'remap',
];

/**
 * Check if a function name starts with a known sync computation prefix.
 * Returns true if the name strongly suggests a synchronous operation.
 *
 * Uses camelCase boundary check for short prefixes (<=4 chars) to avoid
 * matching unrelated words (e.g., "island" should not match "is*").
 */
export function matchesSyncPrefix(functionName: string): boolean {
  const lower = functionName.toLowerCase();
  for (const prefix of SYNC_PREFIXES) {
    if (lower.startsWith(prefix)) {
      // For very short prefixes (is, has, to, from, as, can), require the next char
      // to be uppercase to enforce camelCase boundary — prevents false matches
      // on words like "island", "hash", "total", "front", "asset", "candle"
      if (prefix.length <= 4 && functionName.length > prefix.length) {
        const nextChar = functionName[prefix.length];
        if (nextChar !== nextChar.toUpperCase() || nextChar === nextChar.toLowerCase()) {
          continue; // Next char is not uppercase — not a camelCase prefix match
        }
      }
      return true;
    }
  }
  return false;
}

// ──────────────────── Sync Method Patterns ────────────────────

/**
 * Method name patterns that suggest synchronous behavior.
 * Catches common naming conventions beyond the explicit SYNC_METHODS set.
 */
const SYNC_METHOD_PATTERNS = [
  /^get[A-Z]\w*(Name|Type|Value|Label|Text|Key|Id|Index|Count|Length|Size|Status|State|Mode|Kind|Category|Level|Priority|Score|Rank|Order|Position|Offset|Limit|Page|Version|Format|Style|Color|Font|Width|Height|Depth|Radius|Angle|Degree|Unit|Currency|Locale|Timezone|Pattern|Regex|Prefix|Suffix|Separator|Delimiter|Extension|Path|Dir|File|Url|Uri|Hash|Digest|Checksum|Signature)$/,
  /^(get|set|is|has|can|should|does|will)[A-Z]\w*$/,
  /^(to|from|as|into)[A-Z]\w*$/,
  /Sync$/,  // readFileSync, existsSync, etc. — explicitly sync
];

/**
 * Check if a method name matches sync patterns (beyond the explicit SYNC_METHODS set).
 */
export function matchesSyncMethodPattern(methodName: string): boolean {
  return SYNC_METHOD_PATTERNS.some(pattern => pattern.test(methodName));
}

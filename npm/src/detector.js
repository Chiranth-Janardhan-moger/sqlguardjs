const { IPRateLimiter } = require('./rateLimiter');
const crypto = require('crypto');

const DEFAULT_THRESHOLD = 0.5;
const DEFAULT_SUSPICIOUS_THRESHOLD = 0.2;
const DEFAULT_MAX_LOGS = 500;
const DEFAULT_MAX_PAYLOAD_LENGTH = 50000;
const DEFAULT_MAX_DECODE_ITERATIONS = 8;
const DEFAULT_MAX_DEPTH = 20;
const DEFAULT_MAX_FIELDS = 1000;
const DETECTION_LEVELS = Object.freeze({
  strict: Object.freeze({
    threshold: 0.25,
    suspiciousThreshold: 0.1,
    maxSuspiciousRequests: 2
  }),
  balanced: Object.freeze({
    threshold: DEFAULT_THRESHOLD,
    suspiciousThreshold: DEFAULT_SUSPICIOUS_THRESHOLD,
    maxSuspiciousRequests: 3
  }),
  permissive: Object.freeze({
    threshold: 0.85,
    suspiciousThreshold: 0.5,
    maxSuspiciousRequests: 5
  })
});
const SQL_IDENTIFIER = '(?:`[^`]+`|"[^"]+"|\\[[^\\]]+\\]|[A-Za-z_][\\w$]*)';
const SQL_WORD_BOOLEAN_OPERATOR = '(?:OR|AND|XOR)';
const SQL_SYMBOL_BOOLEAN_OPERATOR = '(?:\\|\\||&&)';
const SQL_BOOLEAN_OPERATOR = `(?:(?:\\b${SQL_WORD_BOOLEAN_OPERATOR}\\b)|${SQL_SYMBOL_BOOLEAN_OPERATOR})`;
const SQL_COMPARISON_OPERATOR = '(?:=|LIKE|!=|<>|<=|>=|<|>)';
const SQL_FUNCTION_CALL = `${SQL_IDENTIFIER}\\s*\\((?:[^()]|\\([^()]{0,120}\\)){0,240}\\)`;
const SQL_CONSTANT_VALUE = `(?:${SQL_FUNCTION_CALL}|\\d+(?:\\.\\d+)?|N?[\'"][^\'"]{0,80}[\'"]?|NULL)`;
const SQL_VALUE = `(?:${SQL_FUNCTION_CALL}|\\d+(?:\\.\\d+)?|N?[\'"][^\'"]{0,80}[\'"]?|[A-Za-z_][\\w.]*|NULL)`;
const SQL_CONSTANT_COMPARISON_EXPRESSION = `${SQL_CONSTANT_VALUE}\\s*${SQL_COMPARISON_OPERATOR}\\s*${SQL_CONSTANT_VALUE}`;
const SQL_COMPARISON_EXPRESSION = `${SQL_VALUE}\\s*${SQL_COMPARISON_OPERATOR}\\s*${SQL_VALUE}`;
const SQL_BETWEEN_EXPRESSION = `${SQL_VALUE}\\s+BETWEEN\\s+${SQL_VALUE}\\s+AND\\s+${SQL_VALUE}`;
const SQL_IS_EXPRESSION = `${SQL_VALUE}\\s+IS\\s+(?:NOT\\s+)?NULL`;
const SQL_EXISTS_EXPRESSION = `EXISTS\\s*\\(\\s*SELECT\\b`;
const SQL_BOOLEAN_LITERAL_EXPRESSION = '(?:TRUE|FALSE|UNKNOWN|NULL)';
const SQL_BOOLEAN_EXPRESSION = `(?:${SQL_COMPARISON_EXPRESSION}|${SQL_BETWEEN_EXPRESSION}|${SQL_IS_EXPRESSION}|${SQL_EXISTS_EXPRESSION}|${SQL_BOOLEAN_LITERAL_EXPRESSION})`;
const SQL_CONSTANT_BOOLEAN_EXPRESSION = `(?:${SQL_CONSTANT_COMPARISON_EXPRESSION}|${SQL_BETWEEN_EXPRESSION}|${SQL_IS_EXPRESSION}|${SQL_EXISTS_EXPRESSION}|${SQL_BOOLEAN_LITERAL_EXPRESSION})`;
const SQL_STACKED_STATEMENT_KEYWORD = '(?:SELECT|WITH|UNION|DROP|INSERT|UPDATE|DELETE|ALTER|CREATE|EXEC|EXECUTE|CALL|MERGE|TRUNCATE)';
const SQL_METADATA_OBJECT = '(?:information_schema(?:\\.[A-Za-z_][\\w$]*)?|sysobjects|sys\\.(?:tables|columns|objects|databases|schemas|indexes|all_columns)|sqlite_master|sqlite_schema|pg_catalog(?:\\.[A-Za-z_][\\w$]*)?|pg_(?:class|tables|namespace|attribute|database|user)|mysql\\.(?:innodb_table_stats|innodb_index_stats|user|db|tables_priv|columns_priv|proc|tables)|(?:all|user|dba)_(?:tables|tab_columns|objects|users|catalog|constraints|cons_columns|views))';
const SQL_METADATA_QUERY_CONTEXT = '(?:SELECT|FROM|JOIN|WHERE|COUNT\\s*\\(|EXISTS\\s*\\(|SHOW\\s+(?:FULL\\s+)?(?:TABLES|COLUMNS)|DESCRIBE|DESC)';
const HTTP_METHODS = ['all', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const DEFAULT_REDACT_KEYS = ['password', 'passwd', 'pwd', 'token', 'secret', 'authorization', 'cookie', 'api_key', 'apikey'];
const NAMED_ENTITIES = {
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  amp: '&',
  colon: ':',
  sol: '/',
  equals: '=',
  lpar: '(',
  rpar: ')',
  tab: '\t',
  newline: '\n',
  grave: '`'
};
const NAMED_ENTITY_PATTERN = new RegExp(`&(${Object.keys(NAMED_ENTITIES).sort((a, b) => b.length - a.length).join('|')});?`, 'gi');

const sqlWord = (word) => word.split('').join('[\\s\\u00a0]*');
const unionSelectPattern = (wordBuilder = word => word) => `\\b${wordBuilder('UNION')}(?:\\s+(?:${wordBuilder('ALL')}|${wordBuilder('DISTINCT')})\\s+|\\s+|\\s*\\(\\s*)${wordBuilder('SELECT')}\\b`;
const unionValuesPattern = (wordBuilder = word => word) => `\\b${wordBuilder('UNION')}(?:\\s+(?:${wordBuilder('ALL')}|${wordBuilder('DISTINCT')})\\s+|\\s+|\\s*\\(\\s*)${wordBuilder('VALUES')}\\s*\\(`;
const SQL_BOOLEAN_WORDS = new Set(['OR', 'AND', 'XOR']);
const SQL_COMPARISON_WORDS = new Set(['LIKE']);
const SQL_COMPARISON_OPERATORS = new Set(['=', '!=', '<>', '<=', '>=', '<', '>']);
const SQL_LITERAL_WORDS = new Set(['TRUE', 'FALSE', 'UNKNOWN', 'NULL']);
const SQL_STACKED_WORDS = new Set(['SELECT', 'WITH', 'UNION', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'ALTER', 'CREATE', 'EXEC', 'EXECUTE', 'CALL', 'MERGE', 'TRUNCATE']);
const SQL_QUERY_CONTEXT_WORDS = new Set(['SELECT', 'FROM', 'JOIN', 'WHERE', 'DESCRIBE', 'DESC', 'EXISTS']);
const SQL_PG_CATALOGS = new Set(['pg_class', 'pg_tables', 'pg_namespace', 'pg_attribute', 'pg_database', 'pg_user']);
const SQL_MYSQL_CATALOGS = new Set(['innodb_table_stats', 'innodb_index_stats', 'user', 'db', 'tables_priv', 'columns_priv', 'proc', 'tables']);
const SQL_SERVER_CATALOGS = new Set(['tables', 'columns', 'objects', 'databases', 'schemas', 'indexes', 'all_columns']);
const ORACLE_CATALOG_SUFFIXES = new Set(['tables', 'tab_columns', 'objects', 'users', 'catalog', 'constraints', 'cons_columns', 'views']);
const JS_EXECUTION_SINKS = new Set(['alert', 'confirm', 'prompt', 'eval', 'fetch', 'function', 'settimeout', 'setinterval']);
const JS_GLOBAL_OBJECTS = new Set(['window', 'globalthis', 'self', 'top', 'parent']);

function isAsciiLetter(ch) {
  return /[A-Za-z]/.test(ch);
}

function isAsciiDigit(ch) {
  return /[0-9]/.test(ch);
}

function isSqlWordStart(ch) {
  return isAsciiLetter(ch) || ch === '_' || ch === '$';
}

function isSqlWordPart(ch) {
  return isSqlWordStart(ch) || isAsciiDigit(ch);
}

function tokenizeSqlFragment(value) {
  const text = String(value);
  const tokens = [];
  let i = 0;

  while (i < text.length && tokens.length < 1200) {
    const ch = text[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    if (isSqlWordStart(ch)) {
      const start = i;
      i++;
      while (i < text.length && isSqlWordPart(text[i])) i++;
      const word = text.slice(start, i);
      tokens.push({ type: 'word', value: word, upper: word.toUpperCase() });
      continue;
    }

    if (isAsciiDigit(ch)) {
      const start = i;
      i++;
      while (i < text.length && /[0-9.]/.test(text[i])) i++;
      tokens.push({ type: 'number', value: text.slice(start, i) });
      continue;
    }

    if (ch === "'" || ch === '"' || ch === '`') {
      tokens.push({ type: 'quote', value: ch });
      i++;
      continue;
    }

    const twoChar = text.slice(i, i + 2);
    if (['!=', '<>', '<=', '>=', '||', '&&', '--'].includes(twoChar)) {
      tokens.push({ type: 'operator', value: twoChar });
      i += 2;
      continue;
    }

    if ('=<>!|&+-*/%'.includes(ch)) {
      tokens.push({ type: 'operator', value: ch });
      i++;
      continue;
    }

    if (';(),.[]{}'.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
      i++;
      continue;
    }

    i++;
  }

  return tokens;
}

function isSqlBooleanToken(token) {
  return (
    (token.type === 'word' && SQL_BOOLEAN_WORDS.has(token.upper)) ||
    (token.type === 'operator' && (token.value === '||' || token.value === '&&'))
  );
}

function isSqlComparisonToken(token) {
  return (
    (token.type === 'operator' && SQL_COMPARISON_OPERATORS.has(token.value)) ||
    (token.type === 'word' && SQL_COMPARISON_WORDS.has(token.upper))
  );
}

function isSqlValueLike(token) {
  return token && (
    token.type === 'word' ||
    token.type === 'number' ||
    token.type === 'quote' ||
    (token.type === 'punct' && token.value === ')')
  );
}

function isSqlConstantLike(token) {
  return token && (
    token.type === 'number' ||
    token.type === 'quote' ||
    (token.type === 'word' && SQL_LITERAL_WORDS.has(token.upper)) ||
    (token.type === 'punct' && token.value === ')')
  );
}

function isSqlConstantLikeAt(tokens, index) {
  const token = tokens[index];
  if (isSqlConstantLike(token)) return true;
  return token?.type === 'word' && nextToken(tokens, index)?.value === '(';
}

function previousToken(tokens, index) {
  return index > 0 ? tokens[index - 1] : null;
}

function nextToken(tokens, index) {
  return index + 1 < tokens.length ? tokens[index + 1] : null;
}

function hasSqlComparison(tokens, start, end, constantOnly = false) {
  for (let i = start; i < Math.min(tokens.length, end); i++) {
    if (!isSqlComparisonToken(tokens[i])) continue;
    const left = previousToken(tokens, i);
    const right = nextToken(tokens, i);
    if (constantOnly) {
      if (isSqlConstantLikeAt(tokens, i - 1) && isSqlConstantLikeAt(tokens, i + 1)) return true;
    } else if (isSqlValueLike(left) && isSqlValueLike(right)) {
      return true;
    }
  }
  return false;
}

function hasStrongSqlBreakoutContext(tokens, booleanIndex) {
  const start = Math.max(0, booleanIndex - 8);
  for (let i = start; i < booleanIndex; i++) {
    const token = tokens[i];
    if (token.type === 'quote') return true;
    if (token.type === 'punct' && [';', ')', '('].includes(token.value)) return true;
    if (token.type === 'operator' && ['||', '&&', '--'].includes(token.value)) return true;
  }
  return false;
}

function rightSideSqlPredicate(tokens, booleanIndex) {
  const start = booleanIndex + 1;
  const end = Math.min(tokens.length, booleanIndex + 18);
  let hasPredicate = false;
  let hasConstantPredicate = false;

  for (let i = start; i < end; i++) {
    const token = tokens[i];
    if (token.type !== 'word') continue;
    if (SQL_LITERAL_WORDS.has(token.upper)) {
      hasPredicate = true;
      hasConstantPredicate = true;
    }
    if (token.upper === 'EXISTS') {
      hasPredicate = true;
      hasConstantPredicate = true;
    }
    if (token.upper === 'BETWEEN') {
      hasPredicate = true;
      hasConstantPredicate = true;
    }
  }

  if (hasSqlComparison(tokens, start, end, true)) {
    hasPredicate = true;
    hasConstantPredicate = true;
  } else if (hasSqlComparison(tokens, start, end, false)) {
    hasPredicate = true;
  }

  return { hasPredicate, hasConstantPredicate };
}

function hasStructuralSqlBooleanAbuse(value) {
  const tokens = tokenizeSqlFragment(value);
  for (let i = 0; i < tokens.length; i++) {
    if (!isSqlBooleanToken(tokens[i])) continue;
    const right = rightSideSqlPredicate(tokens, i);
    if (!right.hasPredicate) continue;
    if (right.hasConstantPredicate) return true;
    if (hasStrongSqlBreakoutContext(tokens, i)) return true;
  }
  return false;
}

function hasStructuralSqlStackedStatement(value) {
  const tokens = tokenizeSqlFragment(value);
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].type !== 'punct' || tokens[i].value !== ';') continue;
    let j = i + 1;
    while (j < tokens.length && tokens[j].type === 'punct' && tokens[j].value === '(') j++;
    if (j < tokens.length && tokens[j].type === 'word' && SQL_STACKED_WORDS.has(tokens[j].upper)) return true;
  }
  return false;
}

function metadataNameAt(tokens, index) {
  if (!tokens[index] || tokens[index].type !== 'word') return null;
  const parts = [tokens[index].value.toLowerCase()];
  let end = index;
  let cursor = index + 1;

  while (
    cursor + 1 < tokens.length &&
    tokens[cursor].type === 'punct' &&
    tokens[cursor].value === '.' &&
    tokens[cursor + 1].type === 'word'
  ) {
    parts.push(tokens[cursor + 1].value.toLowerCase());
    end = cursor + 1;
    cursor += 2;
  }

  return { name: parts.join('.'), parts, end };
}

function isSqlMetadataName(nameInfo) {
  if (!nameInfo) return false;
  const { name, parts } = nameInfo;
  if (name === 'sysobjects' || name === 'sqlite_master' || name === 'sqlite_schema') return true;
  if (name === 'information_schema' || name.startsWith('information_schema.')) return true;
  if (name === 'pg_catalog' || name.startsWith('pg_catalog.') || SQL_PG_CATALOGS.has(name)) return true;
  if (parts[0] === 'sys' && SQL_SERVER_CATALOGS.has(parts[1])) return true;
  if (parts[0] === 'mysql' && SQL_MYSQL_CATALOGS.has(parts[1])) return true;
  if (['all', 'user', 'dba'].includes(parts[0]) && ORACLE_CATALOG_SUFFIXES.has(parts.slice(1).join('_'))) return true;
  for (const prefix of ['all', 'user', 'dba']) {
    const marker = `${prefix}_`;
    if (name.startsWith(marker) && ORACLE_CATALOG_SUFFIXES.has(name.slice(marker.length))) return true;
  }
  return false;
}

function isSqlQueryContext(tokens, index) {
  const token = tokens[index];
  if (!token || token.type !== 'word') return false;
  if (SQL_QUERY_CONTEXT_WORDS.has(token.upper)) return true;
  if (token.upper === 'COUNT' && nextToken(tokens, index)?.value === '(') return true;
  if (token.upper === 'SHOW') {
    const next = nextToken(tokens, index);
    const afterNext = nextToken(tokens, index + 1);
    return (
      next?.upper === 'TABLES' ||
      next?.upper === 'COLUMNS' ||
      (next?.upper === 'FULL' && (afterNext?.upper === 'TABLES' || afterNext?.upper === 'COLUMNS'))
    );
  }
  return false;
}

function hasStructuralSqlMetadataQuery(value) {
  const tokens = tokenizeSqlFragment(value);
  const queryContextIndexes = [];
  const metadataIndexes = [];

  for (let i = 0; i < tokens.length; i++) {
    if (isSqlQueryContext(tokens, i)) queryContextIndexes.push(i);
    const metadata = metadataNameAt(tokens, i);
    if (isSqlMetadataName(metadata)) {
      metadataIndexes.push(i);
      i = metadata.end;
    }
  }

  return metadataIndexes.some(metadataIndex =>
    queryContextIndexes.some(contextIndex => Math.abs(contextIndex - metadataIndex) <= 40)
  );
}

function tokenizeJsFragment(value) {
  const text = String(value);
  const tokens = [];
  let i = 0;

  while (i < text.length && tokens.length < 800) {
    const ch = text[i];
    if (/\s/.test(ch)) {
      i++;
      continue;
    }
    if (isSqlWordStart(ch)) {
      const start = i;
      i++;
      while (i < text.length && isSqlWordPart(text[i])) i++;
      tokens.push({ type: 'word', value: text.slice(start, i).toLowerCase() });
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      let valueText = '';
      i++;
      while (i < text.length) {
        if (text[i] === '\\') {
          valueText += text[i + 1] || '';
          i += 2;
          continue;
        }
        if (text[i] === quote) {
          i++;
          break;
        }
        valueText += text[i];
        i++;
      }
      tokens.push({ type: 'string', value: valueText.toLowerCase() });
      continue;
    }
    if ('[]().,:;+-*/%{}='.includes(ch)) {
      tokens.push({ type: 'punct', value: ch });
    }
    i++;
  }

  return tokens;
}

function javascriptUrlBodies(value) {
  const text = String(value);
  const bodies = [];
  const protocol = /javascript\s*:/ig;
  let match;

  while ((match = protocol.exec(text)) !== null) {
    bodies.push(text.slice(protocol.lastIndex, protocol.lastIndex + 300));
  }

  return bodies;
}

function hasStructuralJavascriptUrlSink(value) {
  for (const body of javascriptUrlBodies(value)) {
    const tokens = tokenizeJsFragment(body);
    let constructorReferences = 0;
    let hasCall = false;

    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      if (token.type === 'punct' && token.value === '(') hasCall = true;
      if ((token.type === 'word' || token.type === 'string') && token.value === 'constructor') constructorReferences++;

      if (token.type !== 'word') continue;
      if (JS_EXECUTION_SINKS.has(token.value) && tokens.slice(i + 1, i + 4).some(next => next.value === '(')) return true;
      if (token.value === 'document' && tokens.slice(i + 1, i + 3).some(next => next.value === '.')) return true;
      if (JS_GLOBAL_OBJECTS.has(token.value) && tokens.slice(i + 1, i + 3).some(next => next.value === '.' || next.value === '[')) return true;
    }

    if (constructorReferences >= 2 && hasCall) return true;
  }

  return false;
}

function hasRepeatedQuotedLiteralComparison(value) {
  const comparison = /(['"])([^'"]{1,80})\1\s*=\s*(['"])([^'"]{1,80})\3/g;
  let match;
  while ((match = comparison.exec(value)) !== null) {
    if (match[2] === match[4]) return true;
  }
  return false;
}

function sanitizeForLog(value) {
  return String(value)
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

function truncateForLog(value, maxLength = 500) {
  const text = sanitizeForLog(value);
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...[truncated ${text.length - maxLength} chars]`;
}

function readRequestProperty(obj, key, fallback = undefined) {
  try {
    const value = obj?.[key];
    return value === undefined ? fallback : value;
  } catch (_) {
    return fallback;
  }
}

function isURLSearchParams(value) {
  return typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams;
}

function isMap(value) {
  return value instanceof Map;
}

function isSet(value) {
  return value instanceof Set;
}

function collectionEntries(value) {
  if (isURLSearchParams(value) || isMap(value)) return [...value.entries()];
  if (isSet(value)) return [...value.values()].map((entryValue, index) => [String(index), entryValue]);
  return null;
}

function schemaKeys(source) {
  if (isURLSearchParams(source) || isMap(source)) {
    return [...new Set([...source.keys()].map(key => String(key)))];
  }
  return Object.keys(source);
}

function schemaHasKey(source, key) {
  if (isURLSearchParams(source)) return source.has(key);
  if (isMap(source)) return source.has(key);
  return Object.prototype.hasOwnProperty.call(source, key);
}

function getIp(req) {
  const ip = readRequestProperty(req, 'ip', null);
  if (ip) return ip;
  const connection = readRequestProperty(req, 'connection', null);
  return readRequestProperty(connection, 'remoteAddress', 'unknown') || 'unknown';
}

function getRequestUrl(req) {
  return readRequestProperty(req, 'originalUrl', null) || readRequestProperty(req, 'url', '') || '';
}

function getRoutePath(req) {
  const route = readRequestProperty(req, 'route', null);
  const routePathValue = route ? readRequestProperty(route, 'path', null) : null;
  if (routePathValue) {
    const routePath = Array.isArray(routePathValue) ? routePathValue.join('|') : String(routePathValue);
    return `${readRequestProperty(req, 'baseUrl', '') || ''}${routePath}`;
  }
  return readRequestProperty(req, 'path', null) || getRequestUrl(req).split('?')[0] || '';
}

function sanitizeRequestId(value) {
  if (value === null || value === undefined) return null;
  return truncateForLog(value, 128);
}

function defaultRawRequestId(req) {
  return req.id || req.requestId || req.headers?.['x-request-id'] || req.headers?.['x-correlation-id'] || null;
}

function callbackErrorMessage(error) {
  try {
    return sanitizeForLog(error && error.message ? error.message : String(error));
  } catch (_) {
    return '[unavailable]';
  }
}

function callbackErrorContext(error, context = {}) {
  return {
    type: 'sqlguardjs.callback_error',
    timestamp: new Date().toISOString(),
    hook: context.hook || 'unknown',
    message: callbackErrorMessage(error),
    eventType: context.event?.type || null,
    eventLabel: context.event?.label || null,
    eventPath: context.event?.path || null
  };
}

function isSensitivePath(path, redactKeys = DEFAULT_REDACT_KEYS) {
  const lowered = String(path || '').toLowerCase();
  return redactKeys.some(key => lowered.includes(String(key).toLowerCase()));
}

function payloadPreview(payload, path, options = {}) {
  if (isSensitivePath(path, options.redactKeys)) return '[redacted]';
  return truncateForLog(payload, options.maxLogPayloadLength ?? 300);
}

function payloadFingerprint(payload) {
  const normalized = String(payload)
    .toLowerCase()
    .replace(/[a-z]+/g, 'a')
    .replace(/\d+/g, '0')
    .replace(/\s+/g, ' ')
    .slice(0, 1000);
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

function createDetectionEvent(req, payload, detection, options = {}) {
  const matches = detection.matches || [];
  const action = options.dryRun ? 'observe' : (detection.action || 'block');
  return {
    type: 'sqlguardjs.threat',
    detected: true,
    timestamp: new Date().toISOString(),
    action,
    blocked: action === 'block',
    dryRun: options.dryRun === true,
    requestId: options.getRequestId(req),
    method: readRequestProperty(req, 'method', null),
    url: getRequestUrl(req),
    route: getRoutePath(req),
    ip: getIp(req),
    label: detection.label,
    confidence: detection.confidence,
    path: detection.path,
    matches,
    matchedSignalIds: matches.map(match => match.id),
    payloadPreview: payloadPreview(payload, detection.path, options),
    payloadLength: String(payload).length,
    reason: detection.reason || null
  };
}

function formatEvent(event, format = 'text') {
  if (format === 'json') return event;
  const safe = (value, fallback = '-') => {
    if (value === null || value === undefined || value === '') return fallback;
    return sanitizeForLog(value);
  };
  return `[SQLGuardJS] ${event.action === 'observe' ? 'Attack Observed' : 'Attack Blocked'}: ${safe(event.label)} from IP: ${safe(event.ip)} | requestId: ${safe(event.requestId)} | path: ${safe(event.path)} | confidence: ${safe(event.confidence)} | Payload: ${safe(event.payloadPreview)}`;
}

function createLearningEvent(req, payload, result, path, options = {}) {
  const matchedSignalIds = (result.matches || []).map(match => match.id);
  const fingerprint = payloadFingerprint(payload);
  return {
    type: 'sqlguardjs.learning',
    timestamp: new Date().toISOString(),
    requestId: options.getRequestId(req),
    method: readRequestProperty(req, 'method', null),
    url: getRequestUrl(req),
    route: getRoutePath(req),
    ip: getIp(req),
    label: result.label,
    confidence: result.confidence,
    path,
    matches: result.matches || [],
    matchedSignalIds,
    clusterKey: `${result.label}:${matchedSignalIds.join('+') || 'unknown'}:${fingerprint}`,
    payloadPreview: payloadPreview(payload, path, options),
    payloadLength: String(payload).length
  };
}

function normalizeDetectionLevel(level = 'balanced') {
  const normalized = String(level || 'balanced').toLowerCase();
  if (!DETECTION_LEVELS[normalized]) {
    throw new Error(`Unknown SQLGuardJS detection level: ${level}`);
  }
  return normalized;
}

function resolveDetectionSettings(options = {}) {
  const level = normalizeDetectionLevel(options.level ?? options.detectionLevel ?? 'balanced');
  const defaults = DETECTION_LEVELS[level];
  return {
    level,
    threshold: options.threshold ?? defaults.threshold,
    suspiciousThreshold: options.suspiciousThreshold ?? defaults.suspiciousThreshold,
    maxSuspiciousRequests: options.maxSuspiciousRequests ?? defaults.maxSuspiciousRequests
  };
}

function normalizeMode(mode) {
  if (mode === undefined || mode === null) return null;
  const normalized = String(mode).toLowerCase();
  if (['block', 'blocking', 'enforce', 'enforced'].includes(normalized)) return 'block';
  if (['log', 'observe', 'monitor', 'dry-run', 'dryrun'].includes(normalized)) return 'log';
  throw new Error(`Unknown SQLGuardJS mode: ${mode}`);
}

function toList(value) {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function mergeLists(...values) {
  return values.flatMap(toList);
}

function isPlainRecord(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && !(value instanceof RegExp);
}

function matchesPattern(pattern, value, req) {
  const text = String(value || '');
  if (typeof pattern === 'function') return pattern(text, req) === true;
  if (pattern instanceof RegExp) {
    pattern.lastIndex = 0;
    return pattern.test(text);
  }
  const expected = String(pattern);
  if (expected.endsWith('*')) return text.startsWith(expected.slice(0, -1));
  return text === expected;
}

function patternMatchesAny(patterns, value, req) {
  return patterns.some(pattern => matchesPattern(pattern, value, req));
}

function routeAllowPatterns(options = {}) {
  const allowlist = options.allowlist || {};
  return mergeLists(options.allowRoutes, options.allowedRoutes, allowlist.routes);
}

function paramAllowPatterns(req, options = {}) {
  const allowlist = options.allowlist || {};
  const values = mergeLists(
    options.allowParams,
    options.allowedParams,
    options.allowParameters,
    allowlist.params,
    allowlist.parameters
  );
  const patterns = [];

  for (const value of values) {
    if (isPlainRecord(value)) {
      for (const [routePattern, routePatterns] of Object.entries(value)) {
        if (requestMatchesPattern(req, routePattern)) patterns.push(...toList(routePatterns));
      }
    } else {
      patterns.push(value);
    }
  }

  return patterns;
}

function requestMatchesPattern(req, pattern) {
  return schemaCandidates(req).some(candidate => matchesPattern(pattern, candidate, req));
}

function isRouteAllowed(req, options = {}) {
  return routeAllowPatterns(options).some(pattern => requestMatchesPattern(req, pattern));
}

function isParamAllowed(req, path, options = {}) {
  return patternMatchesAny(paramAllowPatterns(req, options), path, req);
}

function routeDetectionMaps(options = {}) {
  const allowlist = options.allowlist || {};
  return [
    options.routeLevels,
    options.routeDetectionLevels,
    options.routeThresholds,
    allowlist.routeLevels
  ].filter(isPlainRecord);
}

function resolveRouteDetectionOverride(req, options = {}) {
  for (const map of routeDetectionMaps(options)) {
    for (const [pattern, override] of Object.entries(map)) {
      if (requestMatchesPattern(req, pattern)) return override;
    }
  }
  return null;
}

function resolveRequestDetectionSettings(req, options = {}, baseSettings = resolveDetectionSettings(options)) {
  const override = resolveRouteDetectionOverride(req, options);
  if (!override) return baseSettings;
  if (typeof override === 'string') return resolveDetectionSettings({ level: override });
  return resolveDetectionSettings(override);
}

function normalizeMaxLogs(maxLogs) {
  const numeric = Number(maxLogs ?? DEFAULT_MAX_LOGS);
  return Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : DEFAULT_MAX_LOGS;
}

function createMemoryLogStore(maxLogs = DEFAULT_MAX_LOGS) {
  const limit = normalizeMaxLogs(maxLogs);
  const entries = [];
  return {
    maxLogs: limit,
    add(event) {
      entries.push({ ...event });
      if (entries.length > limit) entries.splice(0, entries.length - limit);
    },
    list() {
      return entries.slice();
    },
    clear() {
      entries.length = 0;
    }
  };
}

function parsePositiveInteger(value, fallback = null) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

function createLogsHandler(logStore, options = {}) {
  return (req, res) => {
    const allLogs = logStore && typeof logStore.list === 'function' ? logStore.list() : [];
    const queryLimit = readRequestProperty(readRequestProperty(req, 'query', {}), 'limit', null);
    const limit = parsePositiveInteger(queryLimit, parsePositiveInteger(options.limit, null));
    const logs = limit ? allLogs.slice(-limit) : allLogs;
    return res.status(200).json(logs);
  };
}

function normalizeSchemaRule(rule) {
  if (!rule) return null;
  if (Array.isArray(rule)) return { allowed: rule, required: [], allowUnknown: false };
  const required = rule.required || [];
  return {
    allowed: rule.allowed || rule.fields || required,
    required,
    allowUnknown: rule.allowUnknown === true
  };
}

function pathnameFromRequest(req) {
  return (getRequestUrl(req).split('?')[0] || readRequestProperty(req, 'path', '') || '').replace(/\/+$/, '') || '/';
}

function schemaCandidates(req) {
  const method = String(readRequestProperty(req, 'method', '') || '').toUpperCase();
  const route = getRoutePath(req);
  const path = pathnameFromRequest(req);
  const candidates = [...new Set([route, path].filter(Boolean))];
  return [
    ...candidates.map(candidate => `${method} ${candidate}`),
    ...candidates
  ];
}

function resolveSchema(req, options = {}) {
  if (options.schema) return options.schema;
  if (!options.schemas) return null;
  for (const key of schemaCandidates(req)) {
    if (options.schemas[key]) return options.schemas[key];
  }
  return null;
}

function validateSchemaSource(sourceName, source, rule) {
  const normalized = normalizeSchemaRule(rule);
  if (!normalized || !source || typeof source !== 'object' || Buffer.isBuffer(source)) return null;

  let keys;
  try {
    keys = schemaKeys(source);
  } catch (_) {
    return {
      payload: `[Unreadable ${sourceName}]`,
      detection: {
        label: 'schema_violation',
        confidence: 1,
        path: sourceName,
        reason: 'unreadable_object',
        matches: [{ id: 'schema-unreadable-object', label: 'schema', confidence: 1 }]
      }
    };
  }
  const allowed = new Set(normalized.allowed);
  const required = new Set(normalized.required);

  if (!normalized.allowUnknown && allowed.size > 0) {
    for (const key of keys) {
      if (!allowed.has(key)) {
        return {
          payload: key,
          detection: {
            label: 'schema_violation',
            confidence: 1,
            path: `${sourceName}.${key}`,
            reason: 'unexpected_field',
            matches: [{ id: 'schema-unexpected-field', label: 'schema', confidence: 1 }]
          }
        };
      }
    }
  }

  for (const key of required) {
    if (!schemaHasKey(source, key)) {
      return {
        payload: key,
        detection: {
          label: 'schema_violation',
          confidence: 1,
          path: `${sourceName}.${key}`,
          reason: 'missing_required_field',
          matches: [{ id: 'schema-missing-required-field', label: 'schema', confidence: 1 }]
        }
      };
    }
  }

  return null;
}

function validateSchema(req, schema) {
  if (!schema) return null;
  return (
    validateSchemaSource('query', req.query, schema.query) ||
    validateSchemaSource('body', req.body, schema.body) ||
    validateSchemaSource('params', req.params, schema.params) ||
    validateSchemaSource('headers', req.headers, schema.headers) ||
    validateSchemaSource('cookies', req.cookies, schema.cookies)
  );
}

class Detector {
  constructor(options = {}) {
    this.maxPayloadLength = options.maxPayloadLength || DEFAULT_MAX_PAYLOAD_LENGTH;
    this.maxDecodeIterations = options.maxDecodeIterations ?? DEFAULT_MAX_DECODE_ITERATIONS;
    this.sqliSignals = [
      {
        id: 'union-select',
        confidence: 0.8,
        pattern: new RegExp(unionSelectPattern(), 'i')
      },
      {
        id: 'comment-fragmented-union-select',
        confidence: 0.8,
        pattern: new RegExp(unionSelectPattern(sqlWord), 'i')
      },
      {
        id: 'union-values',
        confidence: 0.8,
        pattern: new RegExp(unionValuesPattern(), 'i')
      },
      {
        id: 'comment-fragmented-union-values',
        confidence: 0.8,
        pattern: new RegExp(unionValuesPattern(sqlWord), 'i')
      },
      {
        id: 'mysql-versioned-comment',
        confidence: 0.55,
        pattern: /(?:\/\*!\d{0,6}|MYSQL_VERSIONED_COMMENT)/i
      },
      {
        id: 'sql-structural-boolean',
        confidence: 0.75,
        test: hasStructuralSqlBooleanAbuse
      },
      {
        id: 'boolean-tautology',
        confidence: 0.75,
        pattern: new RegExp(`['"\`)]\\s*${SQL_BOOLEAN_OPERATOR}\\s+(?:NOT\\s+)?${SQL_BOOLEAN_EXPRESSION}|${SQL_SYMBOL_BOOLEAN_OPERATOR}\\s+(?:NOT\\s+)?${SQL_BOOLEAN_EXPRESSION}|\\b${SQL_WORD_BOOLEAN_OPERATOR}\\b\\s+(?:NOT\\s+)?${SQL_CONSTANT_BOOLEAN_EXPRESSION}|\\b\\d+\\s+\\b${SQL_WORD_BOOLEAN_OPERATOR}\\b\\s+(?:NOT\\s+)?${SQL_CONSTANT_BOOLEAN_EXPRESSION}`, 'i')
      },
      {
        id: 'drop-table',
        confidence: 0.75,
        pattern: new RegExp(`(?:^|[;\\s])DROP\\s+TABLE\\s+(?:IF\\s+EXISTS\\s+)?${SQL_IDENTIFIER}\\s*(?:CASCADE\\s*|RESTRICT\\s*)?(?:;|--|#|$)`, 'i')
      },
      {
        id: 'insert-values',
        confidence: 0.7,
        pattern: new RegExp(`\\bINSERT\\s+INTO\\s+${SQL_IDENTIFIER}\\s*(?:\\([^)]*\\)\\s*)?VALUES\\s*\\(`, 'i')
      },
      {
        id: 'update-set',
        confidence: 0.7,
        pattern: new RegExp(`\\bUPDATE\\s+${SQL_IDENTIFIER}\\s+SET\\s+${SQL_IDENTIFIER}\\s*=`, 'i')
      },
      {
        id: 'delete-from',
        confidence: 0.65,
        pattern: new RegExp(`\\bDELETE\\s+FROM\\s+${SQL_IDENTIFIER}\\s*(?:WHERE\\b|;|--|#|$)`, 'i')
      },
      {
        id: 'stacked-sql-statement',
        confidence: 0.65,
        pattern: new RegExp(`;\\s*(?:\\(\\s*)*${SQL_STACKED_STATEMENT_KEYWORD}\\b`, 'i')
      },
      {
        id: 'sql-structural-stacked-statement',
        confidence: 0.65,
        test: hasStructuralSqlStackedStatement
      },
      {
        id: 'sql-comment-breakout',
        confidence: 0.55,
        pattern: /(?:['"`]\s*(?:--|#)(?:\s|$)|--\s*$|#\s*$)/i
      },
      {
        id: 'sql-unclosed-block-comment-breakout',
        confidence: 0.55,
        pattern: /(?:['"`)]\s*\/\*(?![\s\S]*\*\/)|\/\*\s*$)/i
      },
      {
        id: 'time-delay',
        confidence: 0.75,
        pattern: /\b(?:SLEEP\s*\(|WAITFOR\s+DELAY\b|BENCHMARK\s*\(|PG_SLEEP\s*\()/i
      },
      {
        id: 'nosql-operator',
        confidence: 0.65,
        pattern: /(?:^|[{,\s])["']?\$(?:where|ne|gt|lt|gte|lte|in|nin|regex|expr|or|and)["']?\s*:/i
      },
      {
        id: 'nosql-operator-key',
        confidence: 0.65,
        pattern: /^\$(?:where|ne|gt|lt|gte|lte|in|nin|regex|expr|or|and)$/i
      },
      {
        id: 'repeated-quoted-literal-comparison',
        confidence: 0.3,
        test: hasRepeatedQuotedLiteralComparison
      },
      {
        id: 'sql-metadata-probe',
        confidence: 0.45,
        pattern: new RegExp(`\\b${SQL_METADATA_OBJECT}\\b`, 'i')
      },
      {
        id: 'sql-metadata-query',
        confidence: 0.65,
        pattern: new RegExp(`\\b${SQL_METADATA_QUERY_CONTEXT}[\\s\\S]{0,240}\\b${SQL_METADATA_OBJECT}\\b|\\b${SQL_METADATA_OBJECT}\\b[\\s\\S]{0,240}\\b${SQL_METADATA_QUERY_CONTEXT}`, 'i')
      },
      {
        id: 'sql-structural-metadata-query',
        confidence: 0.65,
        test: hasStructuralSqlMetadataQuery
      }
    ];
    this.xssSignals = [
      {
        id: 'script-tag',
        confidence: 0.85,
        pattern: /<\s*script\b/i
      },
      {
        id: 'html-event-attribute',
        confidence: 0.75,
        pattern: /<[^>]+\bon\w+\s*=/i
      },
      {
        id: 'event-handler-payload',
        confidence: 0.75,
        pattern: /\bon\w+\s*=\s*["']?[^"'>]*(?:alert|confirm|prompt|document\.|window\.|eval|fetch|Function\s*\()/i
      },
      {
        id: 'javascript-url-with-sink',
        confidence: 0.75,
        pattern: /\bjavascript\s*:[\s\S]{0,240}(?:(?:alert|confirm|prompt|eval|fetch|Function|setTimeout|setInterval)\s*\(|document\s*\.|(?:window|globalThis|self|top|parent)\s*(?:\.|\[)|(?:\[\s*["']constructor["']\s*\]\s*){2})/i
      },
      {
        id: 'javascript-url-structural-sink',
        confidence: 0.75,
        test: hasStructuralJavascriptUrlSink
      },
      {
        id: 'javascript-url-attribute',
        confidence: 0.75,
        pattern: /\b(?:href|src|xlink:href|formaction|action)\s*=\s*["']?\s*javascript\s*:/i
      },
      {
        id: 'javascript-url',
        confidence: 0.3,
        pattern: /\bjavascript\s*:/i
      },
      {
        id: 'dangerous-html-container',
        confidence: 0.7,
        pattern: /<\s*(?:iframe|object|embed|applet)\b/i
      },
      {
        id: 'srcdoc-html',
        confidence: 0.65,
        pattern: /\bsrcdoc\s*=/i
      },
      {
        id: 'html-data-url',
        confidence: 0.65,
        pattern: /\bdata\s*:\s*text\/html/i
      },
      {
        id: 'svg-data-url',
        confidence: 0.65,
        pattern: /(?:\bdata\s*:\s*image\/svg\+xml|SVG_DATA_URI)/i
      }
    ];
  }

  decodeDeeply(payload) {
    return this.normalizePayload(payload, { sqlCommentMode: 'space' });
  }

  normalizePayload(payload, { sqlCommentMode = 'space' } = {}) {
    if (Buffer.isBuffer(payload)) payload = payload.toString('utf8');
    if (typeof payload !== 'string') return '';
    if (payload.length > this.maxPayloadLength) {
      const headLength = Math.ceil(this.maxPayloadLength / 2);
      const tailLength = Math.floor(this.maxPayloadLength / 2);
      payload = `${payload.slice(0, headLength)}\nSQLGUARDJS_TRUNCATED\n${tailLength > 0 ? payload.slice(-tailLength) : ''}`;
    }
    const decodeEntity = (match, hex, dec) => {
      const code = parseInt(hex || dec, hex ? 16 : 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    };
    const decodeCodePoint = (match, hex) => {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    };

    const normalize = (value) => {
      let normalized = value
        .replace(/%u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, decodeCodePoint)
        .replace(/\\u([0-9a-fA-F]{4})/g, decodeCodePoint)
        .replace(/\\x([0-9a-fA-F]{2})/g, decodeCodePoint)
        .replace(/&#x([0-9a-fA-F]+);?|&#(\d+);?/g, decodeEntity)
        .replace(NAMED_ENTITY_PATTERN, (match, name) => NAMED_ENTITIES[name.toLowerCase()] ?? match)
        .replace(/[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g, ' ')
        .replace(/[\u200b-\u200d\ufeff]/g, '')
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
      try {
        normalized = normalized.normalize('NFKC');
      } catch (e) {}
      return normalized;
    };
    const decodePrintableBase64 = (candidate) => {
      try {
        const b64Decoded = Buffer.from(candidate, 'base64').toString('utf8');
        const nonPrintableCount = b64Decoded.replace(/[\t\r\n\x20-\x7E]/g, '').length;
        const isMostlyPrintable = b64Decoded.length > 0 && nonPrintableCount / b64Decoded.length < 0.1;
        return isMostlyPrintable && b64Decoded !== candidate ? b64Decoded : null;
      } catch (e) {
        return null;
      }
    };

    // Iterate decoding to catch multi-layer encoding
    let decoded = normalize(payload);
    let previous = "";
    let iterations = 0;
    while (decoded !== previous && iterations < this.maxDecodeIterations) {
      previous = decoded;
      try { decoded = normalize(decodeURIComponent(decoded)); } catch (e) { decoded = normalize(decoded); }
      iterations++;
    }
    const base64Candidate = decoded;
    decoded = decoded.replace(/\bdata\s*:\s*([a-z0-9.+-]+\/[a-z0-9.+-]+)(?:;[a-z0-9=.+-]+)*;base64\s*,([A-Za-z0-9+/]+={0,2})/ig, (match, mimeType, data) => {
      if (!/^(?:text\/html|image\/svg\+xml|application\/xhtml\+xml)$/i.test(mimeType)) return match;
      const dataDecoded = decodePrintableBase64(data);
      const marker = /^image\/svg\+xml$/i.test(mimeType) ? '\nSVG_DATA_URI' : '';
      return dataDecoded ? `${match}${marker}\n${normalize(dataDecoded).replace(/\+/g, ' ')}` : match;
    });
    decoded = decoded.replace(/\+/g, ' ');
    if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64Candidate)) {
      const b64Decoded = decodePrintableBase64(base64Candidate);
      if (b64Decoded) decoded += `\n${normalize(b64Decoded).replace(/\+/g, ' ')}`;
    }
    if (sqlCommentMode === 'preserve') return decoded;
    // Preserve SQL block comments as separators so UNION/**/SELECT stays tokenized.
    // Detection also checks a removal variant to catch mid-keyword comment splits.
    decoded = decoded.replace(/\/\*!\d{0,6}\s*([\s\S]*?)\*\//g, (_, inner) => {
      const executableSql = inner.trim();
      if (sqlCommentMode === 'remove') return executableSql;
      return executableSql ? ` MYSQL_VERSIONED_COMMENT ${executableSql} ` : ' MYSQL_VERSIONED_COMMENT ';
    });
    decoded = decoded.replace(/\/\*[\s\S]*?\*\//g, sqlCommentMode === 'remove' ? '' : ' ');
    decoded = decoded.replace(/--[^\r\n]*(?=\r?\n|$)/g, ' ');
    decoded = decoded.replace(/#[^\r\n]*(?=\r?\n|$)/g, ' ');
    return decoded;
  }

  payloadVariants(payload) {
    const variants = [
      this.normalizePayload(payload, { sqlCommentMode: 'preserve' }),
      this.normalizePayload(payload, { sqlCommentMode: 'space' }),
      this.normalizePayload(payload, { sqlCommentMode: 'remove' })
    ];
    return [...new Set(variants.filter(Boolean))];
  }

  matchSignals(variants, signalDefinitions, label) {
    const matchesById = new Map();
    for (const variant of variants) {
      for (const signal of signalDefinitions) {
        const matched = signal.pattern ? signal.pattern.test(variant) : signal.test(variant);
        if (!matched || matchesById.has(signal.id)) continue;
        matchesById.set(signal.id, {
          id: signal.id,
          label,
          confidence: signal.confidence
        });
      }
    }
    return [...matchesById.values()];
  }

  combineConfidence(matches) {
    return Math.min(1.0, matches.reduce((total, match) => total + match.confidence, 0));
  }

  detect(payload) {
    const variants = this.payloadVariants(payload);
    const sqliMatches = this.matchSignals(variants, this.sqliSignals, 'sqli');
    const xssMatches = this.matchSignals(variants, this.xssSignals, 'xss');
    const sqliConfidence = this.combineConfidence(sqliMatches);
    const xssConfidence = this.combineConfidence(xssMatches);
    const confidence = Math.max(sqliConfidence, xssConfidence);
    const label = confidence === 0 ? 'benign' : (sqliConfidence >= xssConfidence ? 'sqli' : 'xss');

    return {
      label,
      confidence,
      scores: { sqli: sqliMatches.length, xss: xssMatches.length },
      matches: [...sqliMatches, ...xssMatches]
    };
  }
}

function expressMiddleware(options = {}) {
  const detector = options.detector || new Detector({
    maxPayloadLength: options.maxPayloadLength,
    maxDecodeIterations: options.maxDecodeIterations
  });
  const detectionSettings = resolveDetectionSettings(options);
  const learning = options.learning === true ? { enabled: true } : (options.learning || {});
  const mode = normalizeMode(options.mode);
  const dryRun = typeof options.dryRun === 'boolean'
    ? options.dryRun
    : (mode === 'log'
      ? true
      : (mode === 'block' ? false : (learning.enabled === true || options.learning === true || detectionSettings.level === 'permissive')));
  const maxSuspiciousRequests = detectionSettings.maxSuspiciousRequests;
  const maxRateLimitEventsPerKey = Math.max(options.maxRateLimitEventsPerKey ?? 1000, maxSuspiciousRequests);
  const rateLimiter = new IPRateLimiter(
    options.rateLimitWindowMs ?? 300000,
    options.maxRateLimitCapacity ?? 10000,
    maxRateLimitEventsPerKey
  );
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxFields = options.maxFields ?? DEFAULT_MAX_FIELDS;
  const blockStatus = options.blockStatus ?? 403;
  const scanQuery = options.scanQuery !== false;
  const scanBody = options.scanBody !== false;
  const scanHeaders = options.scanHeaders !== false;
  const scanCookies = options.scanCookies !== false;
  const scanParams = options.scanParams !== false;
  const scanKeys = options.scanKeys !== false;
  const scanRawBody = options.scanRawBody !== false;
  const skip = typeof options.skip === 'function' ? options.skip : null;
  const onThreat = typeof options.onThreat === 'function' ? options.onThreat : null;
  const onLearningEvent = typeof options.onLearningEvent === 'function'
    ? options.onLearningEvent
    : (typeof learning.onEvent === 'function' ? learning.onEvent : null);
  const learningEnabled = learning.enabled === true || options.learning === true || onLearningEvent !== null;
  const logFormat = options.logFormat || (options.jsonLogs ? 'json' : 'text');
  const logger = typeof options.logAttacks === 'function'
    ? options.logAttacks
    : (options.logAttacks ? console.warn : null);
  const requestIdGetter = typeof options.getRequestId === 'function' ? options.getRequestId : defaultRawRequestId;
  const rateLimitKeyGetter = typeof options.rateLimitKey === 'function' ? options.rateLimitKey : getIp;
  const onCallbackError = typeof options.onCallbackError === 'function' ? options.onCallbackError : null;
  const hasProvidedLogStore = Boolean(options.logStore);
  const logStore = options.logStore || createMemoryLogStore(options.maxLogs);
  const storeLogs = Boolean(
    options.logRequests ||
    options.logs ||
    options.exposeLogs ||
    options.storeLogs ||
    dryRun ||
    (hasProvidedLogStore && !options._internalLogStore) ||
    learningEnabled
  );

  const reportCallbackError = (error, context = {}) => {
    if (!onCallbackError) return;

    const safeContext = callbackErrorContext(error, context);
    try {
      const result = onCallbackError(error, safeContext);
      Promise.resolve(result).catch(() => {});
    } catch (_) {
      // User error reporting must never affect request handling.
    }
  };

  const safeCall = (hook, callback, args, context = {}) => {
    if (typeof callback !== 'function') return undefined;

    try {
      const result = callback(...args);
      Promise.resolve(result).catch(error => reportCallbackError(error, { ...context, hook }));
      return result;
    } catch (error) {
      reportCallbackError(error, { ...context, hook });
      return undefined;
    }
  };

  const safeRequestId = (req) => {
    try {
      return sanitizeRequestId(requestIdGetter(req));
    } catch (error) {
      reportCallbackError(error, { hook: 'getRequestId' });
      return null;
    }
  };

  const safeRateLimitKey = async (req, fallback) => {
    try {
      const key = rateLimitKeyGetter(req);
      const resolvedKey = await key;
      return String(resolvedKey || fallback || 'unknown');
    } catch (error) {
      reportCallbackError(error, { hook: 'rateLimitKey' });
      return String(fallback || 'unknown');
    }
  };

  const eventOptions = {
    dryRun,
    redactKeys: options.redactKeys || DEFAULT_REDACT_KEYS,
    maxLogPayloadLength: options.maxLogPayloadLength,
    getRequestId: safeRequestId
  };

  const writeLog = (event) => {
    if (storeLogs && logStore && typeof logStore.add === 'function') logStore.add(event);
    if (logger) safeCall('logAttacks', logger, [formatEvent(event, logFormat), event], { event });
  };

  const emitLearning = (req, payload, result, path) => {
    if (!learningEnabled) return;
    const event = createLearningEvent(req, payload, result, path, eventOptions);
    req.sqlguardjsLearning = req.sqlguardjsLearning || [];
    req.sqlguardjsLearning.push(event);
    if (storeLogs && logStore && typeof logStore.add === 'function') logStore.add(event);
    safeCall('onLearningEvent', onLearningEvent, [event, req], { event });
  };

  const middleware = async (req, res, next) => {
    if (skip) {
      try {
        const skipResult = skip(req);
        const shouldSkip = await skipResult;
        if (shouldSkip) return next();
      } catch (error) {
        reportCallbackError(error, { hook: 'skip' });
      }
    }

    if (isRouteAllowed(req, options)) return next();

    const ip = getIp(req);
    const rateLimitKey = await safeRateLimitKey(req, ip);
    const requestDetectionSettings = resolveRequestDetectionSettings(req, options, detectionSettings);
    const scannedSources = req.sqlguardjsScannedSources instanceof Set
      ? req.sqlguardjsScannedSources
      : new Set();
    req.sqlguardjsScannedSources = scannedSources;
    
    let scannedFields = 0;

    const reportDetection = (payload, detection) => {
      const event = createDetectionEvent(req, payload, detection, eventOptions);
      req.sqlguardjsDetections = req.sqlguardjsDetections || [];
      req.sqlguardjsDetections.push(event);
      req.sqlguardjs = req.sqlguardjs || event;
      safeCall('onThreat', onThreat, [event, req], { event });
      writeLog(event);
      return { isMalicious: true, label: detection.label };
    };

    const scanString = async (str, path) => {
      if (typeof str !== 'string' || str.length === 0) return false;
      if (isParamAllowed(req, path, options)) return false;
      const result = detector.detect(str);
      let finalLabel = result.label;
      let finalConfidence = result.confidence;
      let isMalicious = result.label !== 'benign' && result.confidence >= requestDetectionSettings.threshold;

      if (!isMalicious && result.label !== 'benign' && result.confidence >= requestDetectionSettings.suspiciousThreshold) {
        emitLearning(req, str, result, path);
        const suspiciousCount = rateLimiter.recordSuspicious(rateLimitKey);
        if (suspiciousCount >= requestDetectionSettings.maxSuspiciousRequests) {
          isMalicious = true;
          finalLabel = "rate_limit_escalation";
          finalConfidence = requestDetectionSettings.threshold;
          writeLog({
            type: 'sqlguardjs.rate_limit',
            timestamp: new Date().toISOString(),
            action: dryRun ? 'observe' : 'block',
            blocked: !dryRun,
            dryRun,
            requestId: eventOptions.getRequestId(req),
            method: readRequestProperty(req, 'method', null),
            url: getRequestUrl(req),
            route: getRoutePath(req),
            ip: getIp(req),
            label: finalLabel,
            confidence: finalConfidence,
            path,
            matches: result.matches || [],
            matchedSignalIds: (result.matches || []).map(match => match.id),
            payloadPreview: payloadPreview(str, path, eventOptions),
            payloadLength: String(str).length,
            reason: 'repeated_suspicious_probe'
          });
        }
      }

      if (isMalicious) {
        return reportDetection(str, {
          label: finalLabel,
          confidence: finalConfidence,
          path,
          matches: result.matches
        });
      }
      return false;
    };

    const deepScan = async (obj, path, currentDepth = 0, seen = new WeakSet()) => {
      if (!obj || typeof obj !== 'object') return false;
      if (currentDepth > maxDepth) {
         return reportDetection("[JSON Depth Exceeded]", { label: "dos", confidence: 1, path, reason: 'max_depth_exceeded' });
      }
      if (seen.has(obj)) return false;
      seen.add(obj);
      let attackFound = false;

      const scanEntry = async (key, val, childPath, scanKey = true) => {
        scannedFields++;
        if (scannedFields > maxFields) {
          return reportDetection("[Field Limit Exceeded]", { label: "dos", confidence: 1, path, reason: 'max_fields_exceeded' });
        }

        if (scanKey) {
          const keyAttack = scanKeys ? await scanString(String(key), `${childPath}.__key`) : false;
          if (keyAttack) {
            if (!dryRun) return keyAttack;
            attackFound = attackFound || keyAttack;
          }
        }

        if (typeof val === 'string') {
          const valAttack = await scanString(val, childPath);
          if (valAttack) {
            if (!dryRun) return valAttack;
            attackFound = attackFound || valAttack;
          }
        } else if (Buffer.isBuffer(val)) {
          const valAttack = await scanString(val.toString('utf8'), childPath);
          if (valAttack) {
            if (!dryRun) return valAttack;
            attackFound = attackFound || valAttack;
          }
        } else if (typeof val === 'object' && val !== null) {
          const nestedAttack = await deepScan(val, childPath, currentDepth + 1, seen);
          if (nestedAttack) {
            if (!dryRun) return nestedAttack;
            attackFound = attackFound || nestedAttack;
          }
        }

        return false;
      };

      let entries;
      try {
        entries = collectionEntries(obj);
      } catch (_) {
        return reportDetection("[Object Enumeration Failed]", {
          label: "dos",
          confidence: 1,
          path,
          reason: 'object_enumeration_failed',
          matches: [{ id: 'object-enumeration-failed', label: 'dos', confidence: 1 }]
        });
      }

      if (entries) {
        const scanEntryKeys = !isSet(obj);
        for (const [key, val] of entries) {
          const stringKey = String(key);
          const childPath = scanEntryKeys ? `${path}.${stringKey}` : `${path}[${stringKey}]`;
          const entryAttack = await scanEntry(stringKey, val, childPath, scanEntryKeys);
          if (entryAttack) {
            if (!dryRun) return entryAttack;
            attackFound = attackFound || entryAttack;
          }
        }
        return attackFound;
      }

      let keys;

      try {
        keys = Object.keys(obj);
      } catch (_) {
        return reportDetection("[Object Enumeration Failed]", {
          label: "dos",
          confidence: 1,
          path,
          reason: 'object_enumeration_failed',
          matches: [{ id: 'object-enumeration-failed', label: 'dos', confidence: 1 }]
        });
      }

      for (const key of keys) {
        const childPath = Array.isArray(obj) ? `${path}[${key}]` : `${path}.${key}`;
        let val;
        try {
          val = obj[key];
        } catch (_) {
          return reportDetection("[Object Property Access Failed]", {
            label: "dos",
            confidence: 1,
            path: childPath,
            reason: 'object_property_access_failed',
            matches: [{ id: 'object-property-access-failed', label: 'dos', confidence: 1 }]
          });
        }

        const entryAttack = await scanEntry(key, val, childPath);
        if (entryAttack) {
          if (!dryRun) return entryAttack;
          attackFound = attackFound || entryAttack;
        }
      }
      return attackFound;
    };

    let schemaResult;
    try {
      schemaResult = validateSchema(req, resolveSchema(req, options));
    } catch (_) {
      schemaResult = {
        payload: '[Schema Source Read Failed]',
        detection: {
          label: 'dos',
          confidence: 1,
          path: 'schema',
          reason: 'schema_source_read_failed',
          matches: [{ id: 'schema-source-read-failed', label: 'dos', confidence: 1 }]
        }
      };
    }

    if (schemaResult) {
      const attack = reportDetection(schemaResult.payload, schemaResult.detection);
      if (!dryRun) return res.status(blockStatus).json({
        error: 'Forbidden',
        message: 'Malicious payload detected by SQLGuardJS',
        details: { label: attack.label }
      });
    }

    const sources = [];
    const sourceReadFailures = [];
    const addSource = (enabled, sourceName, readSource, options = {}) => {
      if (!enabled) return;
      try {
        const source = readSource();
        if (options.skipUndefined && source === undefined) return;
        sources.push([sourceName, source]);
      } catch (_) {
        sourceReadFailures.push(sourceName);
      }
    };

    addSource(scanQuery, 'query', () => req.query);
    addSource(scanBody, 'body', () => req.body);
    addSource(scanRawBody, 'rawBody', () => req.rawBody, { skipUndefined: true });
    addSource(scanHeaders, 'headers', () => req.headers);
    addSource(scanParams, 'params', () => req.params);
    addSource(scanCookies, 'cookies', () => req.cookies);

    for (const sourceName of sourceReadFailures) {
      const attack = reportDetection(`[${sourceName} Source Read Failed]`, {
        label: 'dos',
        confidence: 1,
        path: sourceName,
        reason: 'source_read_failed',
        matches: [{ id: 'source-read-failed', label: 'dos', confidence: 1 }]
      });
      if (!dryRun) return res.status(blockStatus).json({
        error: 'Forbidden',
        message: 'Malicious payload detected by SQLGuardJS',
        details: { label: attack.label }
      });
    }

    for (const [sourceName, source] of sources) {
      if (scannedSources.has(sourceName)) continue;
      if (!source) continue;
      
      let attack = false;
      if (Buffer.isBuffer(source)) {
         attack = await scanString(source.toString('utf8'), sourceName);
      } else if (typeof source === 'string') {
         attack = await scanString(source, sourceName);
      } else if (typeof source === 'object') {
         attack = await deepScan(source, sourceName);
      }

      if (attack) {
        if (!dryRun) return res.status(blockStatus).json({
          error: 'Forbidden',
          message: 'Malicious payload detected by SQLGuardJS',
          details: { label: attack.label }
        });
      }
      scannedSources.add(sourceName);
    }
    next();
  };

  middleware.logStore = logStore;
  middleware.logsHandler = (handlerOptions = {}) => createLogsHandler(logStore, handlerOptions);
  return middleware;
}

function mergeOptions(base, override) {
  return { ...base, ...(override || {}) };
}

class SqlGuardJSQueryError extends Error {
  constructor(result) {
    super('Unsafe SQL query detected by SQLGuardJS');
    this.name = 'SqlGuardJSQueryError';
    this.result = result;
  }
}

function scanSqlQuery(query, options = {}) {
  if (typeof query !== 'string') {
    throw new TypeError('query must be a string');
  }
  const detector = options.detector || new Detector({
    maxPayloadLength: options.maxPayloadLength,
    maxDecodeIterations: options.maxDecodeIterations
  });
  return detector.detect(query);
}

function assertSafeSqlQuery(query, options = {}) {
  const result = scanSqlQuery(query, options);
  const { threshold } = resolveDetectionSettings(options);
  if (result.label === 'sqli' && result.confidence >= threshold) {
    throw new SqlGuardJSQueryError(result);
  }
  return result;
}

function samplePayload(sample) {
  if (typeof sample === 'string') return sample;
  if (!sample || typeof sample !== 'object') return '';
  return sample.payload ?? sample.text ?? sample.value ?? '';
}

function expectedMaliciousLabel(label) {
  if (label === undefined || label === null) return null;
  const normalized = String(label).toLowerCase();
  if (['benign', 'safe', 'normal', 'clean'].includes(normalized)) return false;
  if (['sqli', 'xss', 'nosql', 'malicious', 'attack', 'blocked'].includes(normalized)) return true;
  return null;
}

function evaluatePayloads(samples, options = {}) {
  if (!Array.isArray(samples)) {
    throw new TypeError('samples must be an array');
  }

  const detector = options.detector || new Detector({
    maxPayloadLength: options.maxPayloadLength,
    maxDecodeIterations: options.maxDecodeIterations
  });
  const { threshold } = resolveDetectionSettings(options);
  const results = [];
  const summary = {
    total: samples.length,
    blocked: 0,
    allowed: 0,
    labeled: 0,
    falsePositives: 0,
    falseNegatives: 0,
    truePositives: 0,
    trueNegatives: 0,
    falsePositiveRate: 0,
    falseNegativeRate: 0
  };

  for (const sample of samples) {
    const payload = String(samplePayload(sample));
    const expectedMalicious = typeof sample === 'object' && sample !== null
      ? expectedMaliciousLabel(sample.label ?? sample.expected ?? sample.kind)
      : null;
    const result = detector.detect(payload);
    const blocked = result.label !== 'benign' && result.confidence >= threshold;
    if (blocked) summary.blocked++;
    else summary.allowed++;

    if (expectedMalicious !== null) {
      summary.labeled++;
      if (blocked && expectedMalicious) summary.truePositives++;
      else if (blocked && !expectedMalicious) summary.falsePositives++;
      else if (!blocked && expectedMalicious) summary.falseNegatives++;
      else summary.trueNegatives++;
    }

    results.push({ payload, expectedMalicious, blocked, result });
  }

  const benignCount = summary.trueNegatives + summary.falsePositives;
  const maliciousCount = summary.truePositives + summary.falseNegatives;
  summary.falsePositiveRate = benignCount === 0 ? 0 : summary.falsePositives / benignCount;
  summary.falseNegativeRate = maliciousCount === 0 ? 0 : summary.falseNegatives / maliciousCount;

  return { threshold, summary, results };
}

function sqlguardjs(options = {}) {
  const logStore = options.logStore || createMemoryLogStore(options.maxLogs);
  const baseOptions = {
    ...options,
    logStore,
    _internalLogStore: !options.logStore,
    detector: options.detector || new Detector({
      maxPayloadLength: options.maxPayloadLength,
      maxDecodeIterations: options.maxDecodeIterations
    })
  };

  return {
    global(overrides = {}) {
      return expressMiddleware(mergeOptions(baseOptions, overrides));
    },
    route(overrides = {}) {
      return expressMiddleware(mergeOptions({
        ...baseOptions,
        scanParams: true
      }, overrides));
    },
    verify(overrides = {}) {
      return this.route(overrides);
    },
    middleware(overrides = {}) {
      return expressMiddleware(mergeOptions(baseOptions, overrides));
    },
    nestjs(overrides = {}) {
      return nestjsMiddleware(mergeOptions(baseOptions, overrides));
    },
    logs() {
      return logStore.list();
    },
    clearLogs() {
      logStore.clear();
    },
    logsHandler(handlerOptions = {}) {
      return createLogsHandler(logStore, handlerOptions);
    },
    mountLogs(app, path = baseOptions.logsPath || '/admin/sqlguard/logs', handlerOptions = {}) {
      if (!app || typeof app.get !== 'function') {
        throw new TypeError('mountLogs(app) requires an Express-compatible app with app.get().');
      }
      app.get(path, createLogsHandler(logStore, handlerOptions));
      return app;
    },
    logStore,
    detector: baseOptions.detector
  };
}

function nestjsMiddleware(options = {}) {
  return expressMiddleware(options);
}

function createNestMiddleware(options = {}) {
  const middleware = nestjsMiddleware(options);
  return class SqlGuardJSNestMiddleware {
    use(req, res, next) {
      return middleware(req, res, next);
    }
  };
}

function isPlainOptions(value) {
  return value && typeof value === 'object' && !Array.isArray(value) && typeof value !== 'function';
}

function secureRouter(options = {}) {
  let express;
  try {
    express = require('express');
  } catch (e) {
    throw new Error('secureRouter() requires express to be installed in the host application.');
  }

  const router = express.Router(options.routerOptions || {});
  const guard = sqlguardjs(options);
  router.use(guard.global({ ...(options.globalOptions || {}), scanParams: false }));
  if (options.exposeLogs) {
    router.get(options.logsPath || '/admin/sqlguard/logs', guard.logsHandler());
  }
  const routeGuard = (routeOptions = {}) => guard.route({
    ...routeOptions,
    schema: routeOptions.schema,
    scanQuery: false,
    scanBody: false,
    scanHeaders: false,
    scanCookies: false,
    scanRawBody: false,
    scanParams: routeOptions.scanParams !== false
  });
  const consumeRouteOptions = (handlers) => {
    let routeOptions = options.routeOptions || {};
    if (handlers.length > 0 && isPlainOptions(handlers[0])) {
      routeOptions = mergeOptions(routeOptions, handlers.shift());
    }
    return routeOptions;
  };

  for (const method of HTTP_METHODS) {
    const original = router[method].bind(router);
    router[method] = (path, ...handlers) => {
      const routeOptions = consumeRouteOptions(handlers);

      return original(
        path,
        routeGuard(routeOptions),
        ...handlers
      );
    };
  }

  router.sqlguardjs = guard;
  return router;
}

module.exports = {
  Detector,
  SqlGuardJSQueryError,
  assertSafeSqlQuery,
  createLogsHandler,
  createMemoryLogStore,
  createNestMiddleware,
  evaluatePayloads,
  expressMiddleware,
  nestjsMiddleware,
  scanSqlQuery,
  sqlguardjs,
  secureRouter
};

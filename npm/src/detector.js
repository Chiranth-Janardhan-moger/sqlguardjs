const { IPRateLimiter } = require('./rateLimiter');
const crypto = require('crypto');

const DEFAULT_THRESHOLD = 0.5;
const DEFAULT_SUSPICIOUS_THRESHOLD = 0.2;
const DEFAULT_MAX_PAYLOAD_LENGTH = 50000;
const DEFAULT_MAX_DEPTH = 20;
const DEFAULT_MAX_FIELDS = 1000;
const DEFAULT_MAX_ML_CALLS = 10;
const SQL_IDENTIFIER = '(?:`[^`]+`|"[^"]+"|\\[[^\\]]+\\]|[A-Za-z_][\\w$]*)';
const HTTP_METHODS = ['all', 'get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const DEFAULT_REDACT_KEYS = ['password', 'passwd', 'pwd', 'token', 'secret', 'authorization', 'cookie', 'api_key', 'apikey'];

const sqlWord = (word) => word.split('').join('[\\s\\u00a0]*');

function hasRepeatedQuotedLiteralComparison(value) {
  const comparison = /(['"])([^'"]{1,80})\1\s*=\s*(['"])([^'"]{1,80})\3/g;
  let match;
  while ((match = comparison.exec(value)) !== null) {
    if (match[2] === match[4]) return true;
  }
  return false;
}

function truncateForLog(value, maxLength = 500) {
  const text = String(value);
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...[truncated ${text.length - maxLength} chars]`;
}

function getIp(req) {
  return req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
}

function getRequestUrl(req) {
  return req.originalUrl || req.url || '';
}

function getRoutePath(req) {
  if (req.route && req.route.path) {
    const routePath = Array.isArray(req.route.path) ? req.route.path.join('|') : String(req.route.path);
    return `${req.baseUrl || ''}${routePath}`;
  }
  return req.path || getRequestUrl(req).split('?')[0] || '';
}

function defaultRequestId(req) {
  return req.id || req.requestId || req.headers?.['x-request-id'] || req.headers?.['x-correlation-id'] || null;
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
    type: 'sqlguard.threat',
    detected: true,
    timestamp: new Date().toISOString(),
    action,
    blocked: action === 'block',
    dryRun: options.dryRun === true,
    requestId: options.getRequestId(req),
    method: req.method || null,
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
  return `[SQLGuard] ${event.action === 'observe' ? 'Attack Observed' : 'Attack Blocked'}: ${event.label} from IP: ${event.ip} | requestId: ${event.requestId || '-'} | path: ${event.path} | confidence: ${event.confidence} | Payload: ${event.payloadPreview}`;
}

function createLearningEvent(req, payload, result, path, options = {}) {
  const matchedSignalIds = (result.matches || []).map(match => match.id);
  const fingerprint = payloadFingerprint(payload);
  return {
    type: 'sqlguard.learning',
    timestamp: new Date().toISOString(),
    requestId: options.getRequestId(req),
    method: req.method || null,
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

function normalizeSchemaRule(rule) {
  if (!rule) return null;
  if (Array.isArray(rule)) return { allowed: rule, required: [], allowUnknown: false };
  return {
    allowed: rule.allowed || rule.fields || [],
    required: rule.required || [],
    allowUnknown: rule.allowUnknown === true
  };
}

function pathnameFromRequest(req) {
  return (getRequestUrl(req).split('?')[0] || req.path || '').replace(/\/+$/, '') || '/';
}

function schemaCandidates(req) {
  const method = (req.method || '').toUpperCase();
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

  const keys = Object.keys(source);
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
    if (!Object.prototype.hasOwnProperty.call(source, key)) {
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
    this.sqliSignals = [
      {
        id: 'union-select',
        confidence: 0.8,
        pattern: /\bUNION\s+(?:ALL\s+)?SELECT\b/i
      },
      {
        id: 'comment-fragmented-union-select',
        confidence: 0.8,
        pattern: new RegExp(`\\b${sqlWord('UNION')}\\s+(?:${sqlWord('ALL')}\\s+)?${sqlWord('SELECT')}\\b`, 'i')
      },
      {
        id: 'boolean-tautology',
        confidence: 0.75,
        pattern: /(?:['"`)]\s*(?:OR|AND)\s+(?:\d+\s*(?:=|LIKE)\s*\d+|['"][^'"]{0,80}['"]\s*=\s*['"][^'"]{0,80}['"]?|[A-Za-z_][\w.]*\s*(?:=|LIKE)\s*['"\d])|\b\d+\s+(?:OR|AND)\s+\d+\s*=\s*\d+)/i
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
        pattern: /;\s*(?:SELECT|UNION|DROP|INSERT|UPDATE|DELETE|ALTER|CREATE|EXEC|EXECUTE)\b/i
      },
      {
        id: 'sql-comment-breakout',
        confidence: 0.55,
        pattern: /(?:['"`]\s*(?:--|#)(?:\s|$)|--\s*$|#\s*$)/i
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
        pattern: /\b(?:information_schema|sysobjects|sys\.tables|sqlite_master|pg_catalog)\b/i
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
        pattern: /\bjavascript\s*:\s*(?:alert|confirm|prompt|document\.|window\.|eval|fetch|Function\s*\()/i
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
      }
    ];
  }

  decodeDeeply(payload) {
    return this.normalizePayload(payload, { sqlCommentMode: 'space' });
  }

  normalizePayload(payload, { sqlCommentMode = 'space' } = {}) {
    if (Buffer.isBuffer(payload)) payload = payload.toString('utf8');
    if (typeof payload !== 'string') return '';
    if (payload.length > this.maxPayloadLength) payload = payload.substring(0, this.maxPayloadLength);
    const namedEntities = {
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
    const decodeEntity = (match, hex, dec) => {
      const code = parseInt(hex || dec, hex ? 16 : 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    };

    const normalize = (value) => {
      let normalized = value
        .replace(/%u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#x([0-9a-fA-F]+);?|&#(\d+);?/g, decodeEntity)
        .replace(/&([a-zA-Z][a-zA-Z0-9]+);/g, (match, name) => namedEntities[name.toLowerCase()] ?? match)
        .replace(/[\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g, ' ')
        .replace(/[\u200b-\u200d\ufeff]/g, '')
        .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
      try {
        normalized = normalized.normalize('NFKC');
      } catch (e) {}
      return normalized;
    };

    // Iterate decoding to catch multi-layer encoding
    let decoded = normalize(payload);
    let previous = "";
    let iterations = 0;
    while (decoded !== previous && iterations < 5) {
      previous = decoded;
      try { decoded = normalize(decodeURIComponent(decoded)); } catch (e) { decoded = normalize(decoded); }
      iterations++;
    }
    const base64Candidate = decoded;
    decoded = decoded.replace(/\+/g, ' ');
    if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64Candidate)) {
      try {
        const b64Decoded = Buffer.from(base64Candidate, 'base64').toString('utf8');
        const nonPrintableCount = b64Decoded.replace(/[\t\r\n\x20-\x7E]/g, '').length;
        const isMostlyPrintable = b64Decoded.length > 0 && nonPrintableCount / b64Decoded.length < 0.1;
        if (isMostlyPrintable && b64Decoded !== base64Candidate) {
          decoded += `\n${normalize(b64Decoded).replace(/\+/g, ' ')}`;
        }
      } catch (e) {}
    }
    // Preserve SQL block comments as separators so UNION/**/SELECT stays tokenized.
    // Detection also checks a removal variant to catch mid-keyword splits such as UN/**/ION.
    decoded = decoded.replace(/\/\*[\s\S]*?\*\//g, sqlCommentMode === 'remove' ? '' : ' ');
    return decoded;
  }

  payloadVariants(payload) {
    const variants = [
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
  const detector = options.detector || new Detector({ maxPayloadLength: options.maxPayloadLength });
  const threshold = options.threshold ?? DEFAULT_THRESHOLD;
  const suspiciousThreshold = options.suspiciousThreshold ?? DEFAULT_SUSPICIOUS_THRESHOLD;
  const mlEndpoint = options.mlEndpoint || null; 
  const rateLimiter = new IPRateLimiter(options.rateLimitWindowMs || 300000, options.maxRateLimitCapacity || 10000);
  const maxSuspiciousRequests = options.maxSuspiciousRequests || 3;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxFields = options.maxFields ?? DEFAULT_MAX_FIELDS;
  const maxMlCalls = options.maxMlCalls ?? DEFAULT_MAX_ML_CALLS;
  const blockStatus = options.blockStatus ?? 403;
  const dryRun = options.dryRun === true;
  const scanQuery = options.scanQuery !== false;
  const scanBody = options.scanBody !== false;
  const scanHeaders = options.scanHeaders !== false;
  const scanCookies = options.scanCookies !== false;
  const scanParams = options.scanParams !== false;
  const scanKeys = options.scanKeys !== false;
  const skip = typeof options.skip === 'function' ? options.skip : null;
  const onThreat = typeof options.onThreat === 'function' ? options.onThreat : null;
  const learning = options.learning === true ? { enabled: true } : (options.learning || {});
  const onLearningEvent = typeof options.onLearningEvent === 'function'
    ? options.onLearningEvent
    : (typeof learning.onEvent === 'function' ? learning.onEvent : null);
  const learningEnabled = learning.enabled === true || options.learning === true || onLearningEvent !== null;
  const logFormat = options.logFormat || (options.jsonLogs ? 'json' : 'text');
  const logger = typeof options.logAttacks === 'function'
    ? options.logAttacks
    : (options.logAttacks ? console.warn : null);
  const eventOptions = {
    dryRun,
    redactKeys: options.redactKeys || DEFAULT_REDACT_KEYS,
    maxLogPayloadLength: options.maxLogPayloadLength,
    getRequestId: typeof options.getRequestId === 'function' ? options.getRequestId : defaultRequestId
  };

  const writeLog = (event) => {
    if (!logger) return;
    logger(formatEvent(event, logFormat), event);
  };

  const emitLearning = (req, payload, result, path) => {
    if (!learningEnabled) return;
    const event = createLearningEvent(req, payload, result, path, eventOptions);
    req.sqlguardLearning = req.sqlguardLearning || [];
    req.sqlguardLearning.push(event);
    if (onLearningEvent) onLearningEvent(event, req);
  };

  return async (req, res, next) => {
    if (skip && skip(req)) return next();

    const ip = getIp(req);
    const sources = [];
    if (scanQuery) sources.push(['query', req.query]);
    if (scanBody) sources.push(['body', req.body]);
    if (scanHeaders) sources.push(['headers', req.headers]);
    if (scanParams) sources.push(['params', req.params]);
    if (scanCookies) sources.push(['cookies', req.cookies]);
    
    let mlCallCount = 0;
    let scannedFields = 0;

    const reportDetection = (payload, detection) => {
      const event = createDetectionEvent(req, payload, detection, eventOptions);
      req.sqlguard = event;
      if (onThreat) onThreat(event, req);
      writeLog(event);
      return { isMalicious: true, label: detection.label };
    };

    const scanString = async (str, path) => {
      if (typeof str !== 'string' || str.length === 0) return false;
      const result = detector.detect(str);
      let finalLabel = result.label;
      let finalConfidence = result.confidence;
      let isMalicious = result.label !== 'benign' && result.confidence >= threshold;

      if (!isMalicious && result.label !== 'benign' && result.confidence >= suspiciousThreshold) {
        emitLearning(req, str, result, path);
        const suspiciousCount = rateLimiter.recordSuspicious(ip);
        if (suspiciousCount >= maxSuspiciousRequests) {
           isMalicious = true;
           finalLabel = "rate_limit_escalation";
           finalConfidence = threshold;
           if (logger) logger(formatEvent({
             type: 'sqlguard.rate_limit',
             timestamp: new Date().toISOString(),
             action: dryRun ? 'observe' : 'block',
             blocked: !dryRun,
             dryRun,
             requestId: eventOptions.getRequestId(req),
             method: req.method || null,
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
           }, logFormat));
        } else if (mlEndpoint) {
          if (mlCallCount >= maxMlCalls) {
             // Fallback to strict heuristic if attacker is spamming borderline payloads
             isMalicious = true; 
             finalLabel = "rate_limit_sqli_heuristic";
             finalConfidence = threshold;
          } else {
            mlCallCount++;
            try {
              const mlRes = await fetch(mlEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: str })
              });
              if (mlRes.ok) {
                const mlData = await mlRes.json();
                if ((mlData.label && mlData.label !== 'benign') || mlData.isMalicious === true) {
                  isMalicious = true;
                  finalLabel = mlData.label || 'ml_detected';
                  finalConfidence = Math.max(finalConfidence, mlData.confidence || threshold);
                }
              }
            } catch (e) {
               if (logger) logger(logFormat === 'json'
                 ? { type: 'sqlguard.ml_error', timestamp: new Date().toISOString(), message: e.message, requestId: eventOptions.getRequestId(req) }
                 : `[SQLGuard] ML Bridge error: ${e.message}`);
            }
          }
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

      for (const [key, val] of Object.entries(obj)) {
        scannedFields++;
        if (scannedFields > maxFields) {
          return reportDetection("[Field Limit Exceeded]", { label: "dos", confidence: 1, path, reason: 'max_fields_exceeded' });
        }

        const childPath = Array.isArray(obj) ? `${path}[${key}]` : `${path}.${key}`;
        const keyAttack = scanKeys ? await scanString(key, `${childPath}.__key`) : false;
        if (keyAttack) return keyAttack;

        if (typeof val === 'string') {
          const valAttack = await scanString(val, childPath);
          if (valAttack) return valAttack;
        } else if (Buffer.isBuffer(val)) {
          const valAttack = await scanString(val.toString('utf8'), childPath);
          if (valAttack) return valAttack;
        } else if (typeof val === 'object' && val !== null) {
          const nestedAttack = await deepScan(val, childPath, currentDepth + 1, seen);
          if (nestedAttack) return nestedAttack;
        }
      }
      return false;
    };

    const schemaResult = validateSchema(req, resolveSchema(req, options));
    if (schemaResult) {
      const attack = reportDetection(schemaResult.payload, schemaResult.detection);
      if (dryRun) return next();
      return res.status(blockStatus).json({
        error: 'Forbidden',
        message: 'Malicious payload detected by SQLGuard ML',
        details: { label: attack.label }
      });
    }

    for (const [sourceName, source] of sources) {
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
        if (dryRun) return next();
        return res.status(blockStatus).json({
          error: 'Forbidden',
          message: 'Malicious payload detected by SQLGuard ML',
          details: { label: attack.label }
        });
      }
    }
    next();
  };
}

function mergeOptions(base, override) {
  return { ...base, ...(override || {}) };
}

function sqlguard(options = {}) {
  const baseOptions = {
    ...options,
    detector: options.detector || new Detector({ maxPayloadLength: options.maxPayloadLength })
  };

  return {
    global(overrides = {}) {
      return expressMiddleware(mergeOptions(baseOptions, overrides));
    },
    route(overrides = {}) {
      return expressMiddleware(mergeOptions({
        ...baseOptions,
        scanQuery: false,
        scanBody: false,
        scanHeaders: false,
        scanCookies: false,
        scanParams: true
      }, overrides));
    },
    verify(overrides = {}) {
      return this.route(overrides);
    },
    middleware(overrides = {}) {
      return expressMiddleware(mergeOptions(baseOptions, overrides));
    },
    detector: baseOptions.detector
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
  const guard = sqlguard(options);
  router.use(guard.global({ ...(options.globalOptions || {}), scanParams: false }));

  for (const method of HTTP_METHODS) {
    const original = router[method].bind(router);
    router[method] = (path, ...handlers) => {
      let routeOptions = options.routeOptions || {};
      if (handlers.length > 0 && isPlainOptions(handlers[0])) {
        routeOptions = mergeOptions(routeOptions, handlers.shift());
      }

      return original(
        path,
        guard.route({
          ...routeOptions,
          schema: routeOptions.schema,
          scanParams: routeOptions.scanParams !== false
        }),
        ...handlers
      );
    };
  }

  return router;
}

module.exports = { Detector, expressMiddleware, sqlguard, secureRouter };

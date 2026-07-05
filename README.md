# SQLGuardJS

[![npm version](https://img.shields.io/npm/v/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)
[![Tests](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml/badge.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml)
[![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/npm/l/sqlguardjs.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/blob/main/LICENSE)
[![npm downloads](https://img.shields.io/npm/dm/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)
[![package size](https://img.shields.io/bundlephobia/minzip/sqlguardjs)](https://bundlephobia.com/package/sqlguardjs)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)

Protect your Express app from SQL Injection, XSS, and NoSQL Injection in under a minute.

SQLGuardJS is an Express request verification layer for common SQL injection, NoSQL injection, and cross-site scripting payloads. It provides in-process normalization, structural token analysis, weighted signals, a secure router API, command-line scanner, structured admin logs, schema-aware route checks, safe learning events, and request-size safety limits.

SQLGuardJS is a defense-in-depth control. It does not replace parameterized SQL queries, safe ORM usage, context-aware output encoding, HTML sanitization, CSP, least-privilege database accounts, or application security testing.

## 30-Second Quick Start

Install:

```bash
npm install sqlguardjs
```

Use:

```javascript
const express = require('express');
const { sqlguardjs } = require('sqlguardjs');

const app = express();
const guard = sqlguardjs();

app.use(express.json());
app.use(guard.global());

app.post('/login', guard.route(), (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
```

Test a blocked request:

```bash
curl "http://localhost:3000/login?id=<security-test-string>"
```

For route schemas:

```javascript
app.post('/login', guard.route({
  schema: {
    body: {
      allowed: ['email', 'password'],
      required: ['email', 'password']
    },
    query: []
  }
}), loginHandler);
```

## How It Works

| Without SQLGuardJS | With SQLGuardJS |
|---|---|
| Request reaches the Express route directly. | Request is inspected before route logic runs. |
| Route handler receives raw query, body, params, headers, and cookies. | SQLGuardJS scans query, body, params, headers, cookies, and optional schemas. |
| Suspicious input can reach application logic, database queries, or HTML rendering. | Malicious input is blocked with `403`; safe input continues to the route. |
| Security depends entirely on every handler validating perfectly. | Middleware adds a shared defense-in-depth layer across protected routes. |
| Logging depends on custom application code. | Detections can be logged, reviewed in learning mode, or exposed through an admin log endpoint. |

```text
Client / Bot / Scanner
        |
        v
SQLGuardJS middleware
        |
        +-- normalize and decode input
        +-- run injection and XSS detector
        +-- check route schema and request limits
        +-- track repeated suspicious probes
        |
        v
Block with 403 or pass to Express route
```

```text
Browser / Mobile / Postman / curl / Bot / Scanner
        |
        v
SQLGuardJS
        |
        +-- Route schema
        +-- Detector
        +-- Rate limiter
        +-- Learning/log events
        |
        v
Application route
        |
        v
Database / renderer / downstream service
```

## Why `global()` and `route()` both exist

Express does not populate `req.params` until after a route is matched. SQLGuardJS therefore provides two guard points:

- `guard.global()` scans request bodies, query strings, headers, and cookies before route handlers run.
- `guard.route()` scans any request sources not already scanned, then checks `req.params` and optional route schemas after Express resolves the route.

Use both when you want all common request inputs inspected before your route logic runs.

## Performance

SQLGuardJS scans decoded request data in memory. It does not call a database or external service. Actual latency depends on payload size, nesting depth, enabled logging, and schema checks.

Default limits such as `maxPayloadLength`, `maxDepth`, and `maxFields` are included to keep worst-case request processing bounded.

For high-throughput bulk import endpoints, set route-specific schemas and lower `maxFields` or `maxPayloadLength` to match the largest valid request your endpoint should accept. If an endpoint intentionally accepts large files or raw technical content, validate that upload path separately and use `skip` for the scanner on that route.

Local benchmark, measured on Node.js v22.19.0, Windows, Intel Core i5-1335U, 5,000 iterations, benign payloads:

| Payload size | Avg detector latency |
| --- | ---: |
| 1 KB | 0.14 ms |
| 10 KB | 1.23 ms |
| 50 KB | 6.32 ms |

| Metric | Result |
| --- | ---: |
| Middleware throughput, 1 KB payload | 6,540 req/sec |
| Retained heap delta after 5,000 middleware requests | 0.06 MB |

Run `npm run benchmark` on your own target machine before using these numbers for capacity planning.

## Features

- Detects SQL injection patterns including boolean tautologies, union-query probes, stacked statements, destructive DDL, time-delay probes, and metadata enumeration.
- Uses structural SQL-fragment analysis for boolean predicates, stacked statements, and metadata enumeration instead of depending only on exact regular-expression payload strings.
- Handles SQL comment evasion and keyword splitting.
- Detects NoSQL operator probes such as `$where`, `$ne`, `$gt`, `$regex`, `$or`, and `$and`.
- Detects XSS payloads including script tags, event-handler attributes, JavaScript execution URLs, dangerous HTML containers, `srcdoc`, and `data:text/html`.
- Tokenizes JavaScript pseudo-protocol bodies to catch constructor-chain and global-object execution routes.
- Normalizes repeated URL encoding, `%uXXXX`, HTML entities, printable Base64, plus-separated query strings, Unicode spacing, zero-width characters, and control-character splitting.
- Scans `req.query`, `req.body`, `req.headers`, `req.params`, `req.cookies`, nested objects, arrays, object keys, strings, and Buffers.
- Supports a secure router API with `sqlguardjs().global()`, `sqlguardjs().route()`, and `secureRouter()`.
- Supports weighted confidence scoring, suspicious request escalation, schema-aware route checks, safe learning events, dry-run rollout, route skipping, structured admin logs, and request-size safety limits.
- Includes TypeScript definitions and real Express integration tests.

Node.js 18 or newer is required.

## Comparison

| Capability | SQLGuardJS | Helmet | express-validator |
| --- | --- | --- | --- |
| SQL injection request detection | Yes | No | No |
| XSS request detection | Yes | No | Partial, with custom validators |
| NoSQL operator detection | Yes | No | No |
| Schema-aware route checks | Yes | No | Yes |
| Learning/log-only rollout | Yes | No | No |
| Runtime Express middleware | Yes | Yes | Yes |
| Security headers | No | Yes | No |

Use Helmet for headers, express-validator for business input validation, and SQLGuardJS as a request-scanning defense-in-depth layer. They solve different problems.

## Express Usage

Register SQLGuardJS after body parsers and before protected routes. SQLGuardJS scans data that Express has exposed on `req.query`, `req.body`, `req.headers`, `req.params`, `req.cookies`, and `req.rawBody`, including plain objects, arrays, buffers, `URLSearchParams`, `Map`, and `Set` containers. It cannot inspect bytes that no upstream parser or capture middleware attaches to the request.

```javascript
const express = require('express');
const { sqlguardjs } = require('sqlguardjs');

const app = express();
const guard = sqlguardjs({
  threshold: 0.5,
  suspiciousThreshold: 0.2,
  logAttacks: true
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.text({ type: ['text/plain', 'application/*+json'], limit: '1mb' }));

// Global scanner checks body, query, headers, and cookies.
app.use(guard.global({ scanParams: false }));

// Route verifier checks any unscanned sources plus params after Express resolves them.
app.get('/users/:id', guard.route(), (req, res) => {
  res.json({ id: req.params.id });
});

app.post('/login', guard.route({
  schema: {
    body: {
      allowed: ['email', 'password'],
      required: ['email', 'password']
    },
    query: []
  }
}), (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
```

For webhook or custom-parser endpoints that parse the raw stream later, capture the raw body before SQLGuardJS and expose it as `req.rawBody`:

```javascript
app.use((req, res, next) => {
  let rawBody = '';
  req.setEncoding('utf8');
  req.on('data', chunk => { rawBody += chunk; });
  req.on('end', () => {
    req.rawBody = rawBody;
    next();
  });
  req.on('error', next);
});

app.use(guard.global());
```

For multipart endpoints, run your multipart parser or raw-body capture before SQLGuardJS if you need form fields inspected. File contents should usually be validated by file-specific controls, not by this request scanner.

You can also use `secureRouter()` when you want the router to handle both global request scanning and route-level parameter/schema checks automatically:

```javascript
const express = require('express');
const { secureRouter } = require('sqlguardjs');

const app = express();
const router = secureRouter({
  threshold: 0.5,
  suspiciousThreshold: 0.2
});

app.use(express.json({ limit: '1mb' }));

router.post('/login', {
  schema: {
    body: {
      allowed: ['email', 'password'],
      required: ['email', 'password']
    },
    query: []
  }
}, (req, res) => {
  res.json({ ok: true });
});

app.use('/api', router);
```

`secureRouter()` auto-wraps direct HTTP method registrations such as `get`, `post`, `put`, and `all`. For path-scoped `router.use()` or chained `router.route()` declarations, pass `guard.route()` explicitly.

## Real-World Integration Patterns

SQLGuardJS is middleware first, so the safest pattern is to put it before sensitive routes and keep normal framework validation in place.

| Use case | Pattern |
| --- | --- |
| Login API | `guard.global()` before routes plus `guard.route({ schema })` on `/login`. |
| GraphQL | Put `guard.global()` before the GraphQL HTTP handler; use `allowParams` for fields that intentionally carry query text. |
| Prisma / Drizzle / Sequelize | Keep parameterized ORM calls; add `assertSafeSqlQuery()` only around dynamic raw SQL sinks. |
| Mongoose | Use request scanning for inbound probes and keep schema validation/operator allowlists in Mongoose. |
| NestJS | Use `nestjsMiddleware()` or `createNestMiddleware()` with the same options as Express. |
| Fastify | Use `Detector` in a `preHandler` until a first-class Fastify adapter exists. |

Minimal GraphQL-style placement:

```javascript
app.use(express.json());
app.use(guard.global({ scanParams: false }));
app.use('/graphql', graphqlHttpHandler);
```

Raw SQL sink guard for ORM escape hatches:

```javascript
const { assertSafeSqlQuery } = require('sqlguardjs');

assertSafeSqlQuery(dynamicSql);
await db.execute(dynamicSql, params);
```

## Production Rollout

Start with `dryRun: true` on real traffic. This records detections without blocking requests.
In dry-run mode SQLGuardJS continues scanning the whole request after the first detection. The first detection is available as `req.sqlguardjs`, and all detections for the request are available as `req.sqlguardjsDetections`.

If your app is behind nginx, Cloudflare, a load balancer, or a platform proxy, configure Express `trust proxy` before relying on IP-based suspicious-request escalation. For authenticated APIs, prefer a stable application identity with `rateLimitKey`, such as user ID plus IP.

```javascript
app.set('trust proxy', 1);

app.use(guard.global({
  dryRun: true,
  rateLimitKey: req => req.user?.id ? `${req.user.id}:${req.ip}` : req.ip,
  logAttacks: event => {
    // Admins see these events in the application logs or wherever this function sends them.
    console.warn(JSON.stringify(event));
  },
  logFormat: 'json',
  onThreat(event, req) {
    console.warn({
      label: event.label,
      confidence: event.confidence,
      path: event.path,
      matchedSignalIds: event.matchedSignalIds,
      requestId: event.requestId,
      ip: req.ip
    });
  },
  onCallbackError(error, context) {
    console.error('SQLGuardJS callback failed', context);
  }
}));
```

If your app runs on Render, Railway, Fly.io, AWS, Azure, GCP, Docker, PM2, or a VPS, these events appear wherever your normal Node logs go. For a dashboard, pass `onThreat` and store the event in your database, logging platform, SIEM, or alerting system.

Use `logFormat: 'json'` for production log ingestion. Text logs escape carriage returns and newlines, but structured JSON is safer for line-oriented log parsers and SIEM pipelines.
Failures thrown by `logAttacks`, `onThreat`, and `onLearningEvent` are isolated from request handling. Use `onCallbackError` to monitor logging, alerting, or review-queue failures.

After reviewing logs and tuning any route exclusions, enable blocking.

```javascript
app.use(guard.global({
  dryRun: false,
  threshold: 0.5,
  skip: req => req.path === '/health'
}));
```

## Final SQL Query Guard

Request middleware cannot see a value after your app stores it and later concatenates it into a SQL string. For that second-order injection class, check the final SQL string at the database boundary:

```javascript
const { assertSafeSqlQuery } = require('sqlguardjs');

async function checkedQuery(db, sql, params) {
  assertSafeSqlQuery(sql);
  return db.query(sql, params);
}
```

This is still a guardrail, not a substitute for parameterized queries. Use it to fail closed if unsafe dynamic SQL reaches the sink.

## Schema-Aware Route Checks

Schemas let you define the fields a route expects. Unexpected fields and missing required fields are reported as `schema_violation`.

When a rule uses `required` without `allowed`, SQLGuardJS treats the required fields as the allowed fields. Set `allowUnknown: true` only when extra fields are intentionally accepted.

```javascript
router.post('/login', {
  schema: {
    body: {
      allowed: ['email', 'password'],
      required: ['email', 'password']
    },
    query: []
  }
}, handler);
```

Route schema keys can also be configured globally:

```javascript
const schemaGuard = sqlguardjs({
  schemas: {
    'POST /login': {
      body: ['email', 'password'],
      query: []
    }
  }
});

app.use(schemaGuard.global());
```

## Safe Learning Mode

Learning mode records suspicious payloads that are allowed because they are below the blocking threshold. It does not retrain or change rules automatically.

```javascript
app.use(guard.global({
  threshold: 0.9,
  learning: true,
  onLearningEvent(event) {
    console.info(event.clusterKey, event.label, event.payloadPreview);
  }
}));
```

Use learning events for review, clustering, and regression-test creation. Do not automatically train on live traffic because attackers can poison self-learning systems.

Learning mode only records payloads that match at least one signal and land below the blocking threshold. A zero-signal payload cannot be learned automatically; add adversarial tests for any confirmed bypass.

## Traffic Tuning

Use `evaluatePayloads()` against labeled production-like samples before tightening thresholds:

```javascript
const { evaluatePayloads } = require('sqlguardjs');

const report = evaluatePayloads([
  { payload: 'hello world', label: 'benign' },
  { payload: '<security-test-string>', label: 'sqli' }
]);

console.log(report.summary.falsePositiveRate);
```

Accepted safe labels are `benign`, `safe`, `normal`, and `clean`. Attack labels such as `sqli`, `xss`, `nosql`, `malicious`, and `attack` count as malicious for false-negative tracking.

## Thresholds

`threshold` is the confidence score at which a request is blocked. It is a weighted heuristic score, not a statistical probability.

- `0`: no signal matched.
- `0.2` to below `threshold`: suspicious. The request is allowed by default, but repeated suspicious requests from the same IP can escalate.
- `threshold` and above: blocked unless `dryRun` is enabled.

Defaults:

```javascript
guard.global({
  threshold: 0.5,
  suspiciousThreshold: 0.2
});
```

Tuning guidance:

- Keep `threshold: 0.5` for typical API protection.
- Raise it, for example to `0.7`, if your application accepts code snippets, HTML, SQL text, or other technical content.
- Lower it only on high-risk endpoints where blocking suspicious input is acceptable.
- Use `dryRun: true` before changing thresholds in production.

## Detector API

```javascript
const { Detector } = require('sqlguardjs');

const detector = new Detector();

console.log(detector.detect('<security-test-string>'));
console.log(detector.detect('normal search text'));
```

Example result:

```json
{
  "label": "sqli",
  "confidence": 1,
  "scores": {
    "sqli": 3,
    "xss": 0
  },
  "matches": [
    {
      "id": "union-select",
      "label": "sqli",
      "confidence": 0.8
    }
  ]
}
```

`matches` is useful for debugging and tests. Treat it as diagnostic output, not as a long-term policy API.

## Middleware Options

| Option | Default | Description |
| --- | --- | --- |
| `threshold` | `0.5` | Blocks when `result.confidence >= threshold`. |
| `suspiciousThreshold` | `0.2` | Starts learning events and repeated-probe tracking for non-benign results below `threshold`. |
| `rateLimitWindowMs` | `300000` | Sliding window for repeated suspicious probes per IP. |
| `maxSuspiciousRequests` | `3` | Suspicious requests per `rateLimitKey` before escalation blocks. |
| `maxRateLimitCapacity` | `10000` | Maximum IP entries stored in the in-memory limiter. |
| `maxRateLimitEventsPerKey` | `1000` | Maximum timestamps retained for one `rateLimitKey`; never lower than `maxSuspiciousRequests`. |
| `rateLimitKey` | `req.ip` | Function `(req) => string`; choose the identity used for suspicious-request escalation. Configure Express `trust proxy` before relying on `req.ip` behind proxies. |
| `dryRun` | `false` | Records detections across the full request and calls `next()` instead of blocking. |
| `logAttacks` | `false` | `true` logs to `console.warn`; a function receives the formatted log message. |
| `logFormat` | `text` | Use `json` to send structured events to `logAttacks`; recommended for production log pipelines. |
| `onThreat` | `undefined` | Callback receiving `(event, req)` for detections. |
| `onCallbackError` | `undefined` | Callback receiving `(error, context)` when a user hook fails. Hook failures are swallowed after reporting. |
| `learning` | `false` | Records suspicious allowed payloads without changing detector behavior. |
| `onLearningEvent` | `undefined` | Callback receiving learning candidates for human review. |
| `blockStatus` | `403` | HTTP status code used for blocked requests. |
| `skip` | `undefined` | Function `(req) => boolean`; return `true` to skip scanning. |
| `schema` | `undefined` | Route schema for expected query, body, params, headers, and cookies. |
| `schemas` | `undefined` | Map of route keys such as `POST /login` to schemas. |
| `scanHeaders` | `true` | Scan `req.headers`. |
| `scanCookies` | `true` | Scan `req.cookies` when present. |
| `scanParams` | `true` | Scan `req.params`. |
| `scanQuery` | `true` | Scan `req.query`. |
| `scanBody` | `true` | Scan `req.body`. |
| `scanRawBody` | `true` | Scan `req.rawBody` when an upstream parser or capture middleware provides it. |
| `scanKeys` | `true` | Scan object keys as well as values. |
| `maxDepth` | `20` | Maximum object nesting depth before the request is treated as a DoS probe. |
| `maxFields` | `1000` | Maximum object fields scanned per request before the request is treated as a DoS probe. |
| `maxPayloadLength` | `50000` | Maximum characters decoded and scanned per string. |
| `maxDecodeIterations` | `8` | Maximum repeated URL/entity normalization passes for nested encoded payloads. |
| `detector` | new `Detector()` | Optional preconfigured detector instance. |

## Blocked Response

```json
{
  "error": "Forbidden",
  "message": "Malicious payload detected by SQLGuardJS",
  "details": {
    "label": "sqli"
  }
}
```

Common labels:

- `sqli`
- `xss`
- `schema_violation`
- `rate_limit_escalation`
- `dos`

## CLI

```bash
sqlguardjs scan "<security-test-string>"
sqlguardjs scan-file payloads.txt --format csv
```

JSON is the default output. CSV output includes `payload,label,confidence`.
CSV output escapes row-breaking newlines and prefixes spreadsheet-formula-leading cells so attacker payloads cannot forge report rows or execute when opened in spreadsheet tools.

## Security Guidance

For SQL injection prevention, use parameterized queries, safe stored procedures where appropriate, allow-list validation for dynamic identifiers, and least-privilege database accounts.

For XSS prevention, use framework escaping, context-aware output encoding, HTML sanitization for rich content, safe DOM sinks, CSP, and Trusted Types where practical.

### OWASP Mapping

| OWASP area | SQLGuardJS coverage |
| --- | --- |
| A03 Injection | SQL injection request detection, NoSQL operator detection, and final SQL query guard. |
| A05 Security Misconfiguration | Schema-aware route checks and request-size safety limits reduce accidental exposure. |
| A07 Identification and Authentication Failures | Login and account routes can run stricter route-level scanning and repeated-probe escalation. |

SQLGuardJS helps with these controls, but it is not a complete OWASP compliance solution. Keep the underlying database, ORM, session, auth, and rendering controls in place.

### Security Model

SQLGuardJS assumes the attacker controls request inputs and may use encoding, nesting, repeated probes, and malformed objects. It does not assume access to your database, templates, sessions, or authorization rules.

Known boundaries:

- It scans data Express or your parser exposes on the request object.
- It cannot prove a query is safe if your app later constructs unsafe SQL outside the request path.
- It can produce false positives on endpoints that intentionally accept code, markup, or SQL-like text.
- It is an in-process control; persistent review, SIEM correlation, and long-term retention belong in your own logging stack.

See [SECURITY.md](SECURITY.md) for supported versions and vulnerability reporting.

References:

- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## GitHub Action Scan

Use the CLI in CI when you keep request fixtures or suspicious strings in a private test file:

```yaml
name: SQLGuardJS Scan

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  sqlguardjs-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g sqlguardjs
      - run: sqlguardjs scan-file requests.txt
```

## Testing

```bash
cd npm
npm test
```

The Node suite covers the detector, middleware, generated adversarial corpora, header/raw body scanning, rate limiting, CLI behavior, package metadata, and benign traffic false-positive checks.
It also includes real Express integration tests with `supertest` for query, body, params, schema checks, structured logs, and learning events.

Current result:

```text
Test Suites: 11 passed, 11 total
Tests: 165 passed, 165 total
```

Contributors should add new bypasses or false positives as tests before changing detector rules.

## Repository Layout

```text
npm/                  Node package, Express middleware, CLI, and Jest tests
npm/examples/         Minimal and production-style Express examples
python/               Python reference detector and model-training scripts
test_integration/     Local Express integration example
.github/workflows/    CI configuration
```

## License

MIT. See [LICENSE](LICENSE).

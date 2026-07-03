# SQLGuard

[![npm version](https://img.shields.io/npm/v/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)
[![Tests](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml/badge.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml)
[![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/npm/l/sqlguardjs.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/blob/main/LICENSE)
[![npm downloads](https://img.shields.io/npm/dm/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)

Protect your Express app from SQL Injection, XSS, and NoSQL Injection in under a minute.

SQLGuard is an Express request verification layer for common SQL injection, NoSQL injection, and cross-site scripting payloads. It provides an in-process heuristic detector, secure router API, command-line scanner, structured admin logs, schema-aware route checks, safe learning events, and request-size safety limits.

SQLGuard is a defense-in-depth control. It does not replace parameterized SQL queries, safe ORM usage, context-aware output encoding, HTML sanitization, CSP, least-privilege database accounts, or application security testing.

## 30-Second Quick Start

Install:

```bash
npm install sqlguardjs
```

Use:

```javascript
const express = require('express');
const { sqlguard } = require('sqlguardjs');

const app = express();
const guard = sqlguard();

app.use(express.json());
app.use(guard.global());

app.post('/login', guard.route(), (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
```

Test a blocked request:

```bash
curl "http://localhost:3000/login?id=1%20UNION%20SELECT%20password%20FROM%20users--"
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

## Before and After

Without SQLGuard:

```text
Attacker
  -> Express route
  -> Application logic
  -> Database or HTML rendering
```

With SQLGuard:

```text
Attacker
  -> SQLGuard
  -> Blocked with 403 if malicious, otherwise passed to the Express route.
```

## Why `global()` and `route()` both exist

Express does not populate `req.params` until after a route is matched. SQLGuard therefore provides two guard points:

- `guard.global()` scans request bodies, query strings, headers, and cookies before route handlers run.
- `guard.route()` scans `req.params` and applies optional route schemas after Express resolves the route.

Use both when you want all common request inputs inspected before your route logic runs.

## Performance

SQLGuard scans decoded request data in memory. It does not call a database or external service. Actual latency depends on payload size, nesting depth, enabled logging, and schema checks.

Default limits such as `maxPayloadLength`, `maxDepth`, and `maxFields` are included to keep worst-case request processing bounded.

## Features

- Detects SQL injection patterns including boolean tautologies, `UNION SELECT`, stacked statements, destructive DDL, time-delay probes, and metadata enumeration.
- Handles SQL comment evasion, including `UNION/**/SELECT` and `UN/**/ION SEL/**/ECT`.
- Detects NoSQL operator probes such as `$where`, `$ne`, `$gt`, `$regex`, `$or`, and `$and`.
- Detects XSS payloads including script tags, event-handler attributes, JavaScript execution URLs, dangerous HTML containers, `srcdoc`, and `data:text/html`.
- Normalizes repeated URL encoding, `%uXXXX`, HTML entities, printable Base64, plus-separated query strings, Unicode spacing, zero-width characters, and control-character splitting.
- Scans `req.query`, `req.body`, `req.headers`, `req.params`, `req.cookies`, nested objects, arrays, object keys, strings, and Buffers.
- Supports a secure router API with `sqlguard().global()`, `sqlguard().route()`, and `secureRouter()`.
- Supports weighted confidence scoring, suspicious request escalation, schema-aware route checks, safe learning events, dry-run rollout, route skipping, structured admin logs, and request-size safety limits.
- Includes TypeScript definitions and real Express integration tests.

Node.js 18 or newer is required.

## Express Usage

Register SQLGuard after body parsers and before protected routes.

```javascript
const express = require('express');
const { sqlguard } = require('sqlguardjs');

const app = express();
const guard = sqlguard({
  threshold: 0.5,
  suspiciousThreshold: 0.2,
  logAttacks: true
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Global scanner checks body, query, headers, and cookies.
app.use(guard.global({ scanParams: false }));

// Route verifier checks params after Express resolves them.
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

## Production Rollout

Start with `dryRun: true` on real traffic. This records detections without blocking requests.

```javascript
app.use(guard.global({
  dryRun: true,
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
  }
}));
```

If your app runs on Render, Railway, Fly.io, AWS, Azure, GCP, Docker, PM2, or a VPS, these events appear wherever your normal Node logs go. For a dashboard, pass `onThreat` and store the event in your database, logging platform, SIEM, or alerting system.

After reviewing logs and tuning any route exclusions, enable blocking.

```javascript
app.use(guard.global({
  dryRun: false,
  threshold: 0.5,
  skip: req => req.path === '/health'
}));
```

## Schema-Aware Route Checks

Schemas let you define the fields a route expects. Unexpected fields and missing required fields are reported as `schema_violation`.

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
app.use(sqlguard({
  schemas: {
    'POST /login': {
      body: ['email', 'password'],
      query: []
    }
  }
}).global());
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

console.log(detector.detect('1 UNION/**/SELECT password FROM users--'));
console.log(detector.detect('{"password"="abc123"}'));
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
| `maxSuspiciousRequests` | `3` | Suspicious requests per IP before escalation blocks. |
| `maxRateLimitCapacity` | `10000` | Maximum IP entries stored in the in-memory limiter. |
| `dryRun` | `false` | Records detections and calls `next()` instead of blocking. |
| `logAttacks` | `false` | `true` logs to `console.warn`; a function receives the formatted log message. |
| `logFormat` | `text` | Use `json` to send structured events to `logAttacks`. |
| `onThreat` | `undefined` | Callback receiving `(event, req)` for detections. |
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
| `scanKeys` | `true` | Scan object keys as well as values. |
| `maxDepth` | `20` | Maximum object nesting depth before the request is treated as a DoS probe. |
| `maxFields` | `1000` | Maximum object fields scanned per request before the request is treated as a DoS probe. |
| `maxPayloadLength` | `50000` | Maximum characters decoded and scanned per string. |
| `detector` | new `Detector()` | Optional preconfigured detector instance. |

## Blocked Response

```json
{
  "error": "Forbidden",
  "message": "Malicious payload detected by SQLGuard",
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
sqlguard scan "<script>alert(1)</script>"
sqlguard scan "1 UNION/**/SELECT password FROM users--"
sqlguard scan-file payloads.txt --format csv
```

JSON is the default output. CSV output includes `payload,label,confidence`.

## Security Guidance

For SQL injection prevention, use parameterized queries, safe stored procedures where appropriate, allow-list validation for dynamic identifiers, and least-privilege database accounts.

For XSS prevention, use framework escaping, context-aware output encoding, HTML sanitization for rich content, safe DOM sinks, CSP, and Trusted Types where practical.

References:

- OWASP SQL Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

## Testing

```bash
cd npm
npm test
```

The Node suite covers the detector, middleware, adversarial bypasses, header/raw body scanning, rate limiting, CLI behavior, package metadata, and benign traffic false-positive checks.
It also includes real Express integration tests with `supertest` for query, body, params, schema checks, structured logs, and learning events.

Current result:

```text
Test Suites: 9 passed, 9 total
Tests: 51 passed, 51 total
```

Contributors should add new bypasses or false positives as tests before changing detector rules.

## Repository Layout

```text
npm/                  Node package, Express middleware, CLI, and Jest tests
npm/examples/         Minimal and production-style Express examples
test_integration/     Local Express integration example
.github/workflows/    CI configuration
```

## License

MIT. See [LICENSE](LICENSE).

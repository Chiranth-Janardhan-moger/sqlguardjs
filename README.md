# SQLGuardJS

[![npm version](https://img.shields.io/npm/v/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)
[![Tests](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml/badge.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml)
[![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/npm/l/sqlguardjs.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/blob/main/LICENSE)
[![npm downloads](https://img.shields.io/npm/dm/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)
<!-- Add these two only once confirmed live - a broken badge is worse than no badge:
[![package size](https://img.shields.io/bundlephobia/minzip/sqlguardjs)](https://bundlephobia.com/package/sqlguardjs)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](SECURITY.md)
-->

A request-scanning middleware for Express that catches SQL injection, NoSQL injection, and XSS payloads before they reach your route handlers.

SQLGuardJS is a defense-in-depth layer, not a replacement for parameterized queries, safe ORM usage, output encoding, HTML sanitization, CSP, or least-privilege database accounts. Use it alongside those, not instead of them.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [How It Works](#how-it-works)
3. [Comparison to Other Tools](#comparison-to-other-tools)
4. [Core Setup](#core-setup)
5. [Real-World Integration Patterns](#real-world-integration-patterns)
6. [Detection Levels](#detection-levels)
7. [Log-Only / Learning Mode](#log-only--learning-mode)
8. [Security Event Log Endpoint](#security-event-log-endpoint)
9. [Reducing False Positives](#reducing-false-positives)
10. [Schema-Aware Route Checks](#schema-aware-route-checks)
11. [Final SQL Query Guard](#final-sql-query-guard)
12. [NestJS Support](#nestjs-support)
13. [Thresholds Reference](#thresholds-reference)
14. [Detector API](#detector-api)
15. [Full Middleware Options](#full-middleware-options)
16. [CLI](#cli)
17. [Benchmarking](#benchmarking)
18. [CI Integration](#ci-integration)
19. [Security Guidance](#security-guidance)
20. [Testing](#testing)
21. [Repository Layout](#repository-layout)

---

## Quick Start

Install:

```bash
npm install sqlguardjs
```

Wire it into an Express app:

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

Confirm it's blocking, using a SQL-injection-style test string of your own (see [CLI](#cli) for how the CLI's `scan` command frames the same kind of check without embedding a payload here):

```bash
curl "http://localhost:3000/login?id=<security-test-string>"
```

A malicious test string should come back `403 Forbidden`; ordinary input should pass through untouched.

---

## How It Works

| Without SQLGuardJS | With SQLGuardJS |
|---|---|
| Request reaches the Express route directly. | Request is inspected before route logic runs. |
| Route handler receives raw query, body, params, headers, and cookies. | SQLGuardJS scans query, body, params, headers, cookies, and optional schemas. |
| Suspicious input can reach application logic, database queries, or HTML rendering unchecked. | Malicious input is blocked with `403`; safe input continues to the route. |
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
Block with 403, or pass through to the Express route
```

### Why both `global()` and `route()` exist

Express doesn't populate `req.params` until after a route matches. So SQLGuardJS splits the work into two checkpoints:

| Method | Runs | Checks |
|---|---|---|
| `guard.global()` | Before route matching | Body, query string, headers, cookies |
| `guard.route()` | After route matching | Anything not already scanned, plus `req.params` and any route schema |

Use both together if you want every input source inspected before your handler runs.

---

## Comparison to Other Tools

These tools solve different problems - this isn't "pick one," it's "know which layer each one covers":

| Capability | SQLGuardJS | Helmet | express-validator |
|---|---|---|---|
| SQL injection request detection | Yes | No | No |
| XSS request detection | Yes | No | Partial, via custom validators |
| NoSQL operator detection | Yes | No | No |
| Schema-aware route checks | Yes | No | Yes |
| Learning/log-only rollout | Yes | No | No |
| Runtime Express middleware | Yes | Yes | Yes |
| Security headers | No | Yes | No |

Use Helmet for HTTP security headers, express-validator for business-logic input validation, and SQLGuardJS as a request-scanning defense-in-depth layer sitting alongside both.

---

## Core Setup

Register SQLGuardJS after your body parsers and before the routes you want protected.

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

app.use(guard.global({ scanParams: false }));

app.get('/users/:id', guard.route(), (req, res) => {
  res.json({ id: req.params.id });
});

app.post('/login', guard.route({
  schema: {
    body: { allowed: ['email', 'password'], required: ['email', 'password'] },
    query: []
  }
}), (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
```

Webhook / custom-parser endpoints: capture the raw body yourself and expose it as `req.rawBody` before SQLGuardJS runs, or the scanner has nothing to check:

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

Prefer a single router that handles everything? Use `secureRouter()` - it wraps global scanning and route-level schema checks together:

```javascript
const { secureRouter } = require('sqlguardjs');

const router = secureRouter({ threshold: 0.5, suspiciousThreshold: 0.2 });

router.post('/login', {
  schema: {
    body: { allowed: ['email', 'password'], required: ['email', 'password'] },
    query: []
  }
}, (req, res) => {
  res.json({ ok: true });
});

app.use('/api', router);
```

`secureRouter()` auto-wraps direct calls like `.get()`, `.post()`, `.put()`, `.all()`. For `router.use()` or chained `router.route()`, pass `guard.route()` explicitly - auto-wrapping doesn't reach those.

---

## Real-World Integration Patterns

SQLGuardJS is middleware first - the safest pattern is putting it in front of sensitive routes while keeping your normal framework-level validation exactly as it was.

| Use case | Pattern |
|---|---|
| Login API | `guard.global()` before routes, plus `guard.route({ schema })` on `/login` specifically. |
| GraphQL | Put `guard.global()` before the GraphQL HTTP handler; use `allowParams` for fields that intentionally carry free-text query content. |
| Prisma / Drizzle / Sequelize | Keep parameterized ORM calls as-is; add `assertSafeSqlQuery()` only around raw-SQL escape hatches. |
| Mongoose | Use request scanning for inbound probes; keep schema validation and operator allowlisting in Mongoose itself. |
| NestJS | Use `nestjsMiddleware()` or `createNestMiddleware()` with the same options object you'd pass to `sqlguardjs()` - see [NestJS Support](#nestjs-support). |
| Fastify | No first-class adapter yet - use the `Detector` class directly inside a `preHandler` hook. |

Minimal GraphQL-style placement:

```javascript
app.use(express.json());
app.use(guard.global({ scanParams: false }));
app.use('/graphql', graphqlHttpHandler);
```

Raw SQL sink guard for an ORM escape hatch:

```javascript
const { assertSafeSqlQuery } = require('sqlguardjs');

assertSafeSqlQuery(dynamicSql);
await db.execute(dynamicSql, params);
```

---

## Detection Levels

Rather than tuning raw threshold numbers, you can set a named sensitivity level:

```javascript
const guard = sqlguardjs({ level: 'balanced' });
```

| Level | Behavior |
|---|---|
| `strict` | Blocks on lower-confidence signals too. Use on high-risk endpoints (auth, admin, payments). |
| `balanced` | The default. Matches the standard `threshold: 0.5` behavior described below. |
| `permissive` | Logs and observes instead of blocking, unless a request is forced by an explicit rule. Use on endpoints that legitimately handle code, SQL, or markup as input. |

You can also override the level per route:

```javascript
const guard = sqlguardjs({
  level: 'balanced',
  routeLevels: {
    '/search': 'permissive'
  }
});
```

`routeLevels` takes priority over the global `level` for the routes it lists.

---

## Log-Only / Learning Mode

Before you block anything in production, you generally want to watch what SQLGuardJS would have blocked. Two mechanisms exist for this - they solve slightly different problems, so pick based on what you need.

### Option A - Query-able log endpoint (`mode: 'log'`)

Turns on in-memory event logging that you can query over HTTP later. Good for building your own admin view or exposing raw events to a dashboard.

```javascript
const guard = sqlguardjs({
  mode: 'log',
  logRequests: true,
  maxLogs: 500
});
```

See [Security Event Log Endpoint](#security-event-log-endpoint) below for how to read these back out.

### Option B - Callback-based review queue (`learning: true`)

Doesn't store anything for you to query - instead it hands each suspicious-but-allowed request to a callback you write, so you can push it into your own database, logger, or SIEM.

```javascript
app.use(guard.global({
  threshold: 0.9,
  learning: true,
  onLearningEvent(event) {
    console.info(event.clusterKey, event.label, event.payloadPreview);
  }
}));
```

Learning events only fire for payloads that matched at least one signal and landed below the blocking threshold - a request with zero signal matches is never captured, so don't rely on this to catch confirmed bypasses. Write adversarial tests for those separately.

Important: neither mode retrains or changes detection rules automatically. They're for human review. Don't wire either one into an auto-training loop - attackers can and will poison a system that learns from live traffic unsupervised.

### Recommended rollout order

1. Deploy with `dryRun: true` (see [Thresholds Reference](#thresholds-reference)) so nothing gets blocked yet.
2. Turn on `mode: 'log'` or `learning: true` to see what's being flagged.
3. Review the output, add `allowRoutes` / `allowParams` exceptions for known-good traffic (see [Reducing False Positives](#reducing-false-positives)).
4. Set `dryRun: false` once you're confident in the tuning.

---

## Security Event Log Endpoint

Once `logRequests: true` is set, SQLGuardJS keeps a bounded, in-memory list of security events (blocked and suspicious requests) that you can expose through your own admin routes.

```javascript
const { sqlguardjs } = require('sqlguardjs');

const guard = sqlguardjs({
  mode: 'log',
  logRequests: true,
  maxLogs: 500
});

app.use(guard.global());

// Mount manually with your own auth in front of it:
app.get('/admin/sqlguard/logs', requireAdmin, guard.logsHandler());
```

### `guard.mountLogs(app)`

A shortcut that registers the endpoint for you at the default path (`/admin/sqlguard/logs`):

```javascript
guard.mountLogs(app);
```

This is convenient for quick setups, but it does not add authentication. Anyone who can reach that path can read your security events. For anything beyond local development, mount it yourself with `guard.logsHandler()` behind your own `requireAdmin` (or equivalent) middleware, as shown above.

### Controlling the path

`logsPath` overrides the default path in either auto-mount case below - but the resulting URL depends on which one you use, so don't assume they're interchangeable:

| Approach | What it does | Resulting URL |
|---|---|---|
| `guard.logsHandler()` | Returns the handler only. You choose the route entirely - no path is assumed. | Whatever you register it at |
| `guard.mountLogs(app)` | Auto-mounts at `logsPath` if set, otherwise `/admin/sqlguard/logs`. Mounted at the app root. | `/admin/sqlguard/logs` or your `logsPath`, unprefixed |
| `secureRouter({ exposeLogs: true, logsPath })` | Mounts `logsPath` on that router, not the app. | `logsPath` prefixed by wherever you `app.use()` the router |

That last row matters in practice: if you mount the router under `/api`, `logsPath: '/security/logs'` ends up served at `/api/security/logs`, not `/security/logs`. If you're using `mountLogs(app)` directly instead, the same `logsPath` value serves from the app root with no prefix. Same config value, different final URL, depending on which mechanism carries it - check which one you're actually using before assuming a path is reachable where you expect.

`logsPath` set on its own - without `mountLogs(app)` or `secureRouter({ exposeLogs: true })` - has no effect. It doesn't create a route by itself. `guard.logsHandler()` also ignores `logsPath` entirely: it just returns a handler, and the URL is whatever you register it at with your own `app.get(...)`.

```javascript
// mountLogs(app) - served at /security/logs (app root)
const guard = sqlguardjs({ logsPath: '/security/logs' });
guard.mountLogs(app);

// secureRouter - served at /api/security/logs (prefixed by router mount point)
const router = secureRouter({
  exposeLogs: true,
  logsPath: '/security/logs'
});
app.use('/api', router);

// logsHandler() - logsPath is irrelevant here; you own the route entirely
app.get('/whatever/you/want', requireAdmin, guard.logsHandler());
```

### What's in the response

Logs are returned as JSON. Payload previews are redacted or truncated before storage - the raw attack payload isn't kept in full, so the log endpoint itself isn't a copy-pasteable exploit source.

### Memory behavior

The log store is bounded by `maxLogs` - it's a fixed-size buffer, not an unbounded array:

- Once you exceed `maxLogs`, the oldest entries are dropped as new ones come in. Memory doesn't grow without limit.
- Logs live only in process memory: they disappear on restart and aren't shared across instances if you're running more than one.
- `maxLogs: 500` or `maxLogs: 1000` are reasonable defaults for most apps.
- Setting `maxLogs` extremely high (e.g. `1000000`) defeats the point - you're back to unbounded memory growth in practice.
- For anything you need to keep long-term or correlate across instances, treat this endpoint as a debugging aid and ship events to your own database or SIEM via `onThreat` / `logAttacks` instead (see [Full Middleware Options](#full-middleware-options)).

---

## Reducing False Positives

Two tools exist for excluding known-good traffic from detection, at different levels of precision.

### Skip specific routes or fields entirely

```javascript
const guard = sqlguardjs({
  allowRoutes: ['/admin/search'],
  allowParams: ['query.q', 'body.description']
});
```

- `allowRoutes` exempts an entire route from scanning.
- `allowParams` exempts specific fields (dot-path notation) wherever they appear, without exempting the whole route.

### Adjust sensitivity per route

```javascript
const guard = sqlguardjs({
  routeLevels: {
    '/search': 'balanced'
  }
});
```

Use this when a route needs a different detection level than the rest of your app (see [Detection Levels](#detection-levels)) rather than being excluded outright. Setting `routeLevels: { '/search': 'permissive' }` only changes how sensitive that route is - it doesn't independently turn on the log endpoint or create any route. If you want to see what a permissive route is letting through, you still need `mode: 'log'` / `logRequests: true` and a mounted log endpoint, same as anywhere else.

Before tightening or loosening anything, run `evaluatePayloads()` against labeled samples to see the actual effect:

```javascript
const { evaluatePayloads } = require('sqlguardjs');

const report = evaluatePayloads([
  { payload: 'hello world', label: 'benign' },
  { payload: '<security-test-string>', label: 'sqli' }
]);

console.log(report.summary.falsePositiveRate);
```

Accepted safe labels: `benign`, `safe`, `normal`, `clean`. Attack labels: `sqli`, `xss`, `nosql`, `malicious`, `attack`.

---

## Schema-Aware Route Checks

Define exactly which fields a route should receive. Anything unexpected, or anything required that's missing, is reported as `schema_violation`.

```javascript
router.post('/login', {
  schema: {
    body: { allowed: ['email', 'password'], required: ['email', 'password'] },
    query: []
  }
}, handler);
```

If you set `required` without `allowed`, the required fields become the allowed fields - nothing else gets through. Set `allowUnknown: true` explicitly if extra fields are expected.

You can also define schemas globally by route key instead of inline per-route:

```javascript
const schemaGuard = sqlguardjs({
  schemas: {
    'POST /login': { body: ['email', 'password'], query: [] }
  }
});

app.use(schemaGuard.global());
```

---

## Final SQL Query Guard

Request-level scanning can't see a value that your app stores now and concatenates into a SQL string later - that's second-order injection. For that case, check the SQL string itself at the point it hits the database:

```javascript
const { assertSafeSqlQuery } = require('sqlguardjs');

async function checkedQuery(db, sql, params) {
  assertSafeSqlQuery(sql);
  return db.query(sql, params);
}
```

This is a fail-closed guardrail for when unsafe dynamic SQL reaches the sink - it doesn't replace parameterized queries.

---

## NestJS Support

SQLGuardJS ships a NestJS-compatible middleware that reuses the same Express middleware contract underneath - no extra dependency required.

```javascript
const { nestjsMiddleware, createNestMiddleware } = require('sqlguardjs');
```

Wire it in the same way you'd wire any NestJS middleware (via `configure()` in your module, or `app.use()` in `main.ts`), passing it the same options object you'd give `sqlguardjs()` for Express.

---

## Thresholds Reference

If you're configuring by raw `threshold` instead of named levels:

| Confidence score | Meaning |
|---|---|
| `0` | No signal matched. |
| `0.2` up to `threshold` | Suspicious. Allowed by default; repeated suspicious requests from the same source can escalate to a block. |
| `threshold` and above | Blocked, unless `dryRun` is on. |

```javascript
guard.global({
  threshold: 0.5,
  suspiciousThreshold: 0.2
});
```

Tuning guidance:

- `0.5` is a reasonable default for typical APIs.
- Raise it (e.g. `0.7`) for endpoints that legitimately accept code, HTML, or SQL-like text.
- Lower it only on high-risk endpoints where blocking suspicious input is an acceptable tradeoff.
- Always test with `dryRun: true` before changing thresholds in production.

### Production rollout with dry-run

```javascript
app.set('trust proxy', 1); // required if you're behind nginx, Cloudflare, or a load balancer

app.use(guard.global({
  dryRun: true,
  rateLimitKey: req => req.user?.id ? `${req.user.id}:${req.ip}` : req.ip,
  logAttacks: event => console.warn(JSON.stringify(event)),
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

In dry-run mode, the first detection for a request is on `req.sqlguardjs`; every detection for that request is on `req.sqlguardjsDetections`. `onThreat`, `logAttacks`, and `onLearningEvent` failures are caught internally and routed to `onCallbackError` - they won't crash the request.

Once you've reviewed the logs and tuned exclusions, flip to enforcing:

```javascript
app.use(guard.global({
  dryRun: false,
  threshold: 0.5,
  skip: req => req.path === '/health'
}));
```

Use `logFormat: 'json'` in production - plain-text logs escape newlines, but structured JSON is safer for log pipelines and SIEM ingestion.

---

## Detector API

For cases where you want to run detection directly instead of through Express middleware - batch jobs, custom pipelines, tests:

```javascript
const { Detector } = require('sqlguardjs');

const detector = new Detector();

console.log(detector.detect('normal search text'));
console.log(detector.detect(yourTestPayload));
```

Illustrative shape of a positive match (not the literal output of any specific string above - actual `label`, `confidence`, and `matches` depend entirely on what you pass in):

```json
{
  "label": "sqli",
  "confidence": 1,
  "scores": { "sqli": 3, "xss": 0 },
  "matches": [
    { "id": "union-select", "label": "sqli", "confidence": 0.8 }
  ]
}
```

Treat `matches` as diagnostic output for debugging and tests, not as a stable long-term policy API - the signal IDs inside it aren't a public contract.

---

## Full Middleware Options

| Option | Default | Description |
|---|---|---|
| `threshold` | `0.5` | Blocks when confidence >= this value. |
| `suspiciousThreshold` | `0.2` | Below `threshold` but above this starts learning events and repeated-probe tracking. |
| `level` | `'balanced'` | Named alternative to raw threshold tuning - see [Detection Levels](#detection-levels). |
| `routeLevels` | `undefined` | Per-route overrides for `level`. |
| `mode` | `undefined` | Set to `'log'` to observe detections instead of blocking. Setting `mode: 'log'` alone does not create the HTTP log endpoint - you still need `guard.mountLogs(app)`, `guard.logsHandler()`, or `secureRouter({ exposeLogs: true })` to query events over HTTP (see [Security Event Log Endpoint](#security-event-log-endpoint)). |
| `logRequests` | `false` | Enables in-memory event storage that the log endpoint reads from. |
| `maxLogs` | `500` | Maximum events retained in the log buffer. |
| `allowRoutes` | `undefined` | Routes fully exempted from scanning. |
| `allowParams` | `undefined` | Specific fields (dot-path) exempted from scanning. |
| `rateLimitWindowMs` | `300000` | Sliding window for repeated suspicious probes per key. |
| `maxSuspiciousRequests` | `3` | Suspicious requests per `rateLimitKey` before escalation blocks. |
| `maxRateLimitCapacity` | `10000` | Max IP entries stored in the in-memory limiter. |
| `maxRateLimitEventsPerKey` | `1000` | Max timestamps retained per key; never lower than `maxSuspiciousRequests`. |
| `rateLimitKey` | `req.ip` | Function `(req) => string` for identifying a client. Set `trust proxy` first if behind a proxy. |
| `dryRun` | `false` | Records detections but calls `next()` instead of blocking. |
| `logAttacks` | `false` | `true` logs to `console.warn`; a function receives the formatted log message. |
| `logFormat` | `'text'` | `'json'` for structured production logging. |
| `onThreat` | `undefined` | Callback `(event, req)` fired on detection. |
| `onCallbackError` | `undefined` | Callback `(error, context)` when a user hook throws. |
| `learning` | `false` | Records suspicious-but-allowed payloads for review. |
| `onLearningEvent` | `undefined` | Callback receiving learning candidates. |
| `blockStatus` | `403` | HTTP status for blocked requests. |
| `skip` | `undefined` | Function `(req) => boolean`; `true` skips scanning entirely. |
| `schema` | `undefined` | Route-level schema (query/body/params/headers/cookies). |
| `schemas` | `undefined` | Map of route keys (e.g. `'POST /login'`) to schemas. |
| `scanHeaders` | `true` | Scan `req.headers`. |
| `scanCookies` | `true` | Scan `req.cookies` when present. |
| `scanParams` | `true` | Scan `req.params`. |
| `scanQuery` | `true` | Scan `req.query`. |
| `scanBody` | `true` | Scan `req.body`. |
| `scanRawBody` | `true` | Scan `req.rawBody` when an upstream parser provides it. |
| `scanKeys` | `true` | Scan object keys, not just values. |
| `maxDepth` | `20` | Max object nesting depth before treating the request as a DoS probe. |
| `maxFields` | `1000` | Max fields scanned per request before treating it as a DoS probe. |
| `maxPayloadLength` | `50000` | Max characters decoded and scanned per string. |
| `maxDecodeIterations` | `8` | Max repeated URL/entity normalization passes for nested encoding. |
| `detector` | `new Detector()` | Optional preconfigured detector instance. |

A note on naming: you may see the `maxSuspiciousRequests` / `rateLimitWindowMs` mechanism referred to elsewhere as "request reputation logging." That overstates what it currently does - there's no reputation score, no decay weighting, no persistent storage across restarts, no global bad-IP list, and no per-user risk profile. What actually happens: a request scoring between `suspiciousThreshold` and `threshold` is allowed through the first `maxSuspiciousRequests` times for a given `rateLimitKey`. After that, further matching activity from the same key within `rateLimitWindowMs` is escalated and reported as `rate_limit_escalation` / `repeated_suspicious_probe`, then blocked or logged depending on `dryRun` and `mode`. It's repeated-suspicious-activity tracking, not a reputation system - treat any reference calling it "reputation" as aspirational, not a description of what ships today.

### Blocked response shape

```json
{
  "error": "Forbidden",
  "message": "Malicious payload detected by SQLGuardJS",
  "details": { "label": "sqli" }
}
```

Common `label` values: `sqli`, `xss`, `schema_violation`, `rate_limit_escalation`, `dos`.

---

## CLI

```bash
sqlguardjs scan "<security-test-string>"
sqlguardjs scan-file payloads.txt --format csv
```

JSON is the default output format. CSV output includes `payload,label,confidence` and escapes row-breaking newlines plus spreadsheet-formula-leading cells, so a malicious payload can't forge report rows or execute if the CSV is opened in a spreadsheet tool.

---

## Benchmarking

```bash
npm run benchmark
```

Reports detector and middleware latency/throughput. Run this after changing detector rules or middleware options to catch performance regressions before they ship - SQLGuardJS scans decoded request data in-process (no database or external calls), so latency is driven by payload size, nesting depth, and which options (logging, schema checks) are enabled.

For high-throughput endpoints, set route-specific schemas and lower `maxFields` / `maxPayloadLength` to match the largest valid request the endpoint should accept. If a route intentionally accepts large files or raw technical content, validate that path separately and `skip` it in the scanner.

Local benchmark measured on Node.js v22.19.0, Windows, Intel Core i5-1335U, 5,000 iterations, benign payloads. Run `npm run benchmark` on your own deployment target before using these numbers for capacity planning.

| Payload size | Avg detector latency |
|---|---:|
| 1 KB | 0.15 ms |
| 10 KB | 2.28 ms |
| 50 KB | 6.21 ms |

| Metric | Result |
|---|---:|
| Middleware throughput, 1 KB payload | 6,678 req/sec |
| Retained heap delta after 5,000 requests | 0.06 MB |

---

## CI Integration

Run the CLI as a CI gate against a private fixture file - useful if you keep known-bad request strings in a test file that isn't published with the package:

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

`requests.txt` should live outside the published package, for example in a CI-only fixtures path, not in `npm/`.

---

## Security Guidance

For SQL injection prevention: parameterized queries, safe stored procedures where appropriate, allow-list validation for dynamic identifiers, and least-privilege database accounts.

For XSS prevention: framework escaping, context-aware output encoding, HTML sanitization for rich content, safe DOM sinks, CSP, and Trusted Types where practical.

### OWASP Mapping

| OWASP area | SQLGuardJS coverage |
|---|---|
| A03 Injection | SQL injection detection, NoSQL operator detection, and the final SQL query guard. |
| A05 Security Misconfiguration | Schema-aware route checks and request-size safety limits reduce accidental exposure. |
| A07 Identification and Authentication Failures | Login and account routes can run stricter route-level scanning plus repeated-probe escalation. |

This maps coverage, not compliance - SQLGuardJS helps with these controls but isn't a complete OWASP compliance solution on its own. The underlying database, ORM, session, auth, and rendering controls still have to be correct independently.

### Security Model

SQLGuardJS assumes the attacker controls request inputs and may use encoding, nesting, repeated probes, and malformed objects. It does not assume access to your database, templates, sessions, or authorization rules - those are out of scope by design, not by oversight.

Known boundaries:

- It scans data Express or your parser exposes on the request object - nothing else.
- It cannot prove a query is safe if your app constructs unsafe SQL somewhere outside the request path (see [Final SQL Query Guard](#final-sql-query-guard) for that specific gap).
- It can produce false positives on endpoints that intentionally accept code, markup, or SQL-like text.
- It's an in-process control. Persistent review, SIEM correlation, and long-term retention belong in your own logging stack, not in this package's memory.

See [SECURITY.md](SECURITY.md) for supported versions and vulnerability reporting.

References:

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

## Testing

```bash
cd npm
npm test
```

The suite covers the detector, middleware, generated adversarial corpora, header/raw-body scanning, rate limiting, CLI behavior, package metadata, and benign-traffic false-positive checks, plus real Express integration tests (via `supertest`) for query, body, params, schema checks, structured logs, and learning events.

A dedicated detection corpus verifies detection rate against a labeled set of benign and adversarial samples - this is what `evaluatePayloads()` (see [Reducing False Positives](#reducing-false-positives)) is built on.

Current result:

```text
Test Suites: 11 passed, 11 total
Tests: 165 passed, 165 total
```

If you find a real bypass or false positive, add it as a test before changing any detector rule.

---

## Repository Layout

```text
npm/                  Node package, Express middleware, CLI, and Jest tests
npm/examples/         Minimal and production-style Express examples
python/               Python reference detector and model-training scripts
test_integration/     Local Express integration example
.github/workflows/    CI configuration
```

---

## License

MIT. See [LICENSE](LICENSE).

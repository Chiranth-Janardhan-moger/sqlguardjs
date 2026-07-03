# SQLGuardJS for Node.js

[![npm version](https://img.shields.io/npm/v/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)
[![Tests](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml/badge.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml)
[![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/npm/l/sqlguardjs.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/blob/main/LICENSE)
[![npm downloads](https://img.shields.io/npm/dm/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)

Protect your Express app from SQL Injection, XSS, and NoSQL Injection in under a minute.

SQLGuardJS is an Express request verification layer, middleware, and CLI scanner for common SQL injection, NoSQL injection, and XSS payloads. It runs in-process and does not call a database or external service.

## 30-Second Quick Start

```bash
npm install sqlguardjs
```

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
curl "http://localhost:3000/login?id=1%20UNION%20SELECT%20password%20FROM%20users--"
```

## Before and After

Without SQLGuardJS:

```text
Attacker -> Express route -> Application logic -> Database or HTML rendering
```

With SQLGuardJS:

```text
Attacker -> SQLGuardJS -> Blocked with 403 if malicious, otherwise passed to the Express route.
```

## Why `global()` and `route()` both exist

Express does not populate `req.params` until after a route is matched.

- `guard.global()` checks body, query, headers, and cookies before routes.
- `guard.route()` checks `req.params` and optional schemas after Express resolves a route.

## Performance

SQLGuardJS scans decoded request data in memory. Actual latency depends on payload size, nesting depth, logging, and schema checks.

For bulk endpoints, lower `maxFields` and `maxPayloadLength` to the largest valid request shape, or use `skip` and validate that upload path separately.

SQLGuardJS scans Express-visible data, including plain objects, arrays, buffers, `URLSearchParams`, `Map`, and `Set` containers. Register body parsers before the guard, and expose custom webhook or multipart bytes as `req.rawBody` if your route parses the raw stream later. Unparsed request streams are not visible to any middleware that only reads `req.body`.

## Secure Router

Use `secureRouter()` when you want the router to handle both global request scanning and route-level parameter/schema checks automatically.

```javascript
const { secureRouter } = require('sqlguardjs');

const router = secureRouter({
  logFormat: 'json',
  logAttacks: event => console.warn(JSON.stringify(event))
});

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
```

## Admin Logs

Admins can see detections by enabling `logAttacks` or `onThreat`. In production, send these events to your normal logger, cloud logs, SIEM, database, or alerting system.

```javascript
app.set('trust proxy', 1);

app.use(guard.global({
  rateLimitKey: req => req.user?.id ? `${req.user.id}:${req.ip}` : req.ip,
  logFormat: 'json',
  logAttacks: event => console.warn(JSON.stringify(event)),
  onThreat(event) {
    console.warn(event.requestId, event.label, event.confidence, event.matchedSignalIds);
  },
  onCallbackError(error, context) {
    console.error('SQLGuardJS callback failed', context);
  }
}));
```

Sensitive fields such as passwords and tokens are redacted in payload previews by default.
Use `logFormat: 'json'` for production log ingestion. Text logs escape carriage returns and newlines, but structured logs are safer for line-oriented parsers.
Failures thrown by `logAttacks`, `onThreat`, and `onLearningEvent` are isolated from request handling. Use `onCallbackError` to monitor logging, alerting, or review-queue failures.

In `dryRun` mode, SQLGuardJS scans the full request instead of stopping at the first detection. The first detection is stored on `req.sqlguardjs`; all detections are stored on `req.sqlguardjsDetections`.

## Safe Learning Mode

```javascript
app.use(guard.global({
  threshold: 0.9,
  learning: true,
  onLearningEvent(event) {
    console.info(event.clusterKey, event.payloadPreview);
  }
}));
```

Learning mode records suspicious allowed payloads for human review. It does not auto-train or mutate rules.

## CLI

```bash
sqlguardjs scan "1 UNION/**/SELECT password FROM users--"
sqlguardjs scan-file payloads.txt --format csv
```

CSV output escapes row-breaking newlines and prefixes spreadsheet-formula-leading cells for safer analyst reports.

This package is defense in depth. Keep using parameterized queries, safe ORM APIs, context-aware output encoding, HTML sanitization, CSP, and least-privilege database accounts.

Full documentation lives in the repository root README.

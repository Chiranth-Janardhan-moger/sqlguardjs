# SQLGuard for Node.js

[![npm version](https://img.shields.io/npm/v/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)
[![Tests](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml/badge.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/actions/workflows/ci.yml)
[![Node.js >=18](https://img.shields.io/badge/node-%3E%3D18.0.0-339933.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/npm/l/sqlguardjs.svg)](https://github.com/Chiranth-Janardhan-moger/sqlguardjs/blob/main/LICENSE)
[![npm downloads](https://img.shields.io/npm/dm/sqlguardjs.svg)](https://www.npmjs.com/package/sqlguardjs)

Protect your Express app from SQL Injection, XSS, and NoSQL Injection in under a minute.

SQLGuard is an Express request verification layer, middleware, and CLI scanner for common SQL injection, NoSQL injection, and XSS payloads. It runs in-process and does not call a database or external service.

## 30-Second Quick Start

```bash
npm install sqlguardjs
```

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

## Before and After

Without SQLGuard:

```text
Attacker -> Express route -> Application logic -> Database or HTML rendering
```

With SQLGuard:

```text
Attacker -> SQLGuard -> Blocked with 403 if malicious, otherwise passed to the Express route.
```

## Why `global()` and `route()` both exist

Express does not populate `req.params` until after a route is matched.

- `guard.global()` checks body, query, headers, and cookies before routes.
- `guard.route()` checks `req.params` and optional schemas after Express resolves a route.

## Performance

SQLGuard scans decoded request data in memory. Actual latency depends on payload size, nesting depth, logging, and schema checks.

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
app.use(guard.global({
  logFormat: 'json',
  logAttacks: event => console.warn(JSON.stringify(event)),
  onThreat(event) {
    console.warn(event.requestId, event.label, event.confidence, event.matchedSignalIds);
  }
}));
```

Sensitive fields such as passwords and tokens are redacted in payload previews by default.

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
sqlguard scan "1 UNION/**/SELECT password FROM users--"
sqlguard scan-file payloads.txt --format csv
```

This package is defense in depth. Keep using parameterized queries, safe ORM APIs, context-aware output encoding, HTML sanitization, CSP, and least-privilege database accounts.

Full documentation lives in the repository root README.

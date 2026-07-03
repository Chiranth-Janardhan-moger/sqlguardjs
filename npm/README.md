# SQLGuard ML for Node.js

Protect your Express app from SQL Injection, XSS, and NoSQL Injection in under a minute.

SQLGuard ML is an Express request verification layer, middleware, and CLI scanner for common SQL injection, NoSQL injection, and XSS payloads.

## 30-Second Quick Start

```bash
npm install sqlguard-ml
```

```javascript
const express = require('express');
const { sqlguard } = require('sqlguard-ml');

const app = express();
const guard = sqlguard();

app.use(express.json());
app.use(guard.global());

app.post('/login', guard.route(), (req, res) => {
  res.json({ ok: true });
});
```

## Before and After

Without SQLGuard ML:

```text
Attacker -> Express route -> Application logic -> Database or HTML rendering
```

With SQLGuard ML:

```text
Attacker -> SQLGuard ML -> Blocked with 403 or passed to Express route
```

## Why `global()` and `route()` both exist

Express does not populate `req.params` until after a route is matched.

- `guard.global()` checks body, query, headers, and cookies before routes.
- `guard.route()` checks `req.params` and optional schemas after Express resolves a route.

## Performance

SQLGuard ML scans decoded request data in memory and avoids network calls unless you configure `mlEndpoint`. For typical small API requests, the heuristic scan is designed to add very low overhead. Actual latency depends on payload size, nesting depth, logging, schema checks, and external ML calls.

## Secure router

```javascript
const { secureRouter } = require('sqlguard-ml');

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

## Admin logs

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

## Safe learning mode

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
sqlguard-ml scan "1 UNION/**/SELECT password FROM users--"
sqlguard-ml scan-file payloads.txt --format csv
```

This package is defense in depth. Keep using parameterized queries, safe ORM APIs, context-aware output encoding, HTML sanitization, CSP, and least-privilege database accounts.

Full documentation lives in the repository root README.

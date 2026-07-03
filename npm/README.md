# SQLGuard ML for Node.js

Express request verification, middleware, and CLI scanning for common SQL injection, NoSQL injection, and XSS payloads.

```bash
npm install sqlguard-ml
```

## Express verifier API

```javascript
const express = require('express');
const { sqlguard } = require('sqlguard-ml');

const app = express();
const guard = sqlguard({
  threshold: 0.5,
  suspiciousThreshold: 0.2,
  logAttacks: true
});

app.use(express.json({ limit: '1mb' }));
app.use(guard.global({ scanParams: false }));

app.get('/users/:id', guard.route(), (req, res) => {
  res.json({ id: req.params.id });
});
```

`guard.global()` checks body, query, headers, and cookies before routes. `guard.route()` checks `req.params` after Express resolves a route.

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

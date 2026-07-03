# SQLGuard ML for Node.js

Express middleware and CLI scanner for common SQL injection, NoSQL injection, and XSS payloads.

```bash
npm install sqlguard-ml
```

```javascript
const express = require('express');
const { expressMiddleware } = require('sqlguard-ml');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

app.use(expressMiddleware({
  threshold: 0.5,
  suspiciousThreshold: 0.2,
  logAttacks: true
}));
```

`threshold` is the confidence score that blocks a request. It is a weighted heuristic score, not a probability.

- `0`: benign.
- `0.2` to below `threshold`: suspicious, eligible for repeated-probe escalation or an optional `mlEndpoint`.
- `threshold` and above: blocked unless `dryRun: true`.

Useful options:

- `dryRun: true`: log and attach `req.sqlguard` without blocking.
- `onThreat(event, req)`: send detections to your logger or SIEM.
- `skip(req)`: skip health checks or trusted internal routes.
- `blockStatus`: change the response status.
- `maxDepth`, `maxFields`, `maxPayloadLength`: DoS safety limits.
- `scanHeaders`, `scanCookies`, `scanParams`, `scanKeys`: choose request surfaces.

CLI:

```bash
sqlguard-ml scan "1 UNION/**/SELECT password FROM users--"
sqlguard-ml scan-file payloads.txt --format csv
```

This package is defense in depth. Keep using parameterized queries, safe ORM APIs, context-aware output encoding, HTML sanitization, CSP, and least-privilege database accounts.

Full documentation lives in the repository root README.

# SQLGuard ML

SQLGuard ML is a Node.js and Express request-inspection package for common SQL injection, NoSQL injection, and cross-site scripting payloads. It provides a fast heuristic detector, Express middleware, a command-line scanner, and an optional HTTP bridge for a second-opinion model.

SQLGuard ML is a defense-in-depth control. It does not replace parameterized SQL queries, safe ORM usage, context-aware output encoding, HTML sanitization, CSP, least-privilege database accounts, or application security testing.

## Features

- Detects SQL injection patterns including boolean tautologies, `UNION SELECT`, stacked statements, destructive DDL, time-delay probes, and metadata enumeration.
- Handles SQL comment evasion, including `UNION/**/SELECT` and `UN/**/ION SEL/**/ECT`.
- Detects NoSQL operator probes such as `$where`, `$ne`, `$gt`, `$regex`, `$or`, and `$and`.
- Detects XSS payloads including script tags, event-handler attributes, JavaScript execution URLs, dangerous HTML containers, `srcdoc`, and `data:text/html`.
- Normalizes repeated URL encoding, `%uXXXX`, HTML entities, printable Base64, plus-separated query strings, Unicode spacing, zero-width characters, and control-character splitting.
- Scans `req.query`, `req.body`, `req.headers`, `req.params`, `req.cookies`, nested objects, arrays, object keys, strings, and Buffers.
- Supports weighted confidence scoring, suspicious request escalation, dry-run rollout, route skipping, structured detection callbacks, and request-size safety limits.

## Installation

```bash
npm install sqlguard-ml
```

Node.js 18 or newer is required.

## Express Usage

Register SQLGuard ML after body parsers and before protected routes.

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

app.post('/login', (req, res) => {
  res.json({ ok: true });
});

app.listen(3000);
```

## Production Rollout

Start with `dryRun: true` on real traffic. This records detections without blocking requests.

```javascript
app.use(expressMiddleware({
  dryRun: true,
  onThreat(event, req) {
    console.warn({
      label: event.label,
      confidence: event.confidence,
      path: event.path,
      ip: req.ip
    });
  }
}));
```

After reviewing logs and tuning any route exclusions, enable blocking.

```javascript
app.use(expressMiddleware({
  dryRun: false,
  threshold: 0.5,
  skip: req => req.path === '/health'
}));
```

## Thresholds

`threshold` is the confidence score at which a request is blocked. It is a weighted heuristic score, not a machine-learning probability.

- `0`: no signal matched.
- `0.2` to below `threshold`: suspicious. The request is allowed by default, but repeated suspicious requests can escalate, and `mlEndpoint` can provide a second opinion.
- `threshold` and above: blocked unless `dryRun` is enabled.

Defaults:

```javascript
expressMiddleware({
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
const { Detector } = require('sqlguard-ml');

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
| `suspiciousThreshold` | `0.2` | Starts ML checks and repeated-probe tracking for non-benign results below `threshold`. |
| `mlEndpoint` | `null` | Optional HTTP endpoint that receives `{ payload }` and can return `{ label, confidence }` or `{ isMalicious: true }`. |
| `maxMlCalls` | `10` | Maximum ML calls per request. If exceeded, the middleware fails closed for additional suspicious payloads in that request. |
| `rateLimitWindowMs` | `300000` | Sliding window for repeated suspicious probes per IP. |
| `maxSuspiciousRequests` | `3` | Suspicious requests per IP before escalation blocks. |
| `maxRateLimitCapacity` | `10000` | Maximum IP entries stored in the in-memory limiter. |
| `dryRun` | `false` | Records detections and calls `next()` instead of blocking. |
| `logAttacks` | `false` | `true` logs to `console.warn`; a function receives the formatted log message. |
| `onThreat` | `undefined` | Callback receiving `(event, req)` for detections. |
| `blockStatus` | `403` | HTTP status code used for blocked requests. |
| `skip` | `undefined` | Function `(req) => boolean`; return `true` to skip scanning. |
| `scanHeaders` | `true` | Scan `req.headers`. |
| `scanCookies` | `true` | Scan `req.cookies` when present. |
| `scanParams` | `true` | Scan `req.params`. |
| `scanKeys` | `true` | Scan object keys as well as values. |
| `maxDepth` | `20` | Maximum object nesting depth before the request is treated as a DoS probe. |
| `maxFields` | `1000` | Maximum object fields scanned per request before the request is treated as a DoS probe. |
| `maxPayloadLength` | `50000` | Maximum characters decoded and scanned per string. |
| `detector` | new `Detector()` | Optional preconfigured detector instance. |

## Blocked Response

```json
{
  "error": "Forbidden",
  "message": "Malicious payload detected by SQLGuard ML",
  "details": {
    "label": "sqli"
  }
}
```

Common labels:

- `sqli`
- `xss`
- `rate_limit_escalation`
- `rate_limit_sqli_heuristic`
- `dos`
- labels returned by your optional ML endpoint

## CLI

```bash
sqlguard-ml scan "<script>alert(1)</script>"
sqlguard-ml scan "1 UNION/**/SELECT password FROM users--"
sqlguard-ml scan-file payloads.txt --format csv
```

JSON is the default output. CSV output includes `payload,label,confidence`.

## Optional ML Bridge

The Node package works without Python. If you want a second opinion for suspicious-but-not-blocked payloads, run your own HTTP model endpoint and pass its URL as `mlEndpoint`.

Development stub:

```bash
cd python
python -m venv .venv
.venv\Scripts\activate
pip install -e .
python src/sqlguard_ml/train_stub.py
uvicorn sqlguard_ml.api:app --port 8000
```

Then configure:

```javascript
app.use(expressMiddleware({
  threshold: 0.6,
  suspiciousThreshold: 0.2,
  mlEndpoint: 'http://127.0.0.1:8000/api/detect'
}));
```

The included Python code is a reference pipeline. For production, train and operate your own model with representative data, versioning, latency limits, and monitoring.

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

Current result:

```text
Test Suites: 8 passed, 8 total
Tests: 44 passed, 44 total
```

Contributors should add new bypasses or false positives as tests before changing detector rules.

## Repository Layout

```text
npm/                  Node package, Express middleware, CLI, and Jest tests
python/               Optional Python reference service
test_integration/     Local Express integration example
.github/workflows/    CI configuration
```

## Publishing

NPM publishing is manual:

```bash
cd npm
npm login
npm publish
```

Python package publishing, if needed:

```bash
cd python
python -m build
twine upload dist/*
```

## License

MIT. See [LICENSE](LICENSE).

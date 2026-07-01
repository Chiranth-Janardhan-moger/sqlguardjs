# SQLGuard ML (Machine Learning Injection Detector)

<div align="center">
  <img src="https://img.shields.io/npm/v/sqlguard-ml?color=blue&style=for-the-badge" alt="NPM Version">
  <img src="https://img.shields.io/github/actions/workflow/status/Chiranth-Janardhan-moger/sqlguard-ml/ci.yml?branch=main&style=for-the-badge" alt="CI Status">
</div>

> **Hybrid SQL Injection (SQLi) and Cross-Site Scripting (XSS) detection engine.** Includes a Node.js heuristic scanner and an Express.js middleware that can bridge to a local Python FastAPI Machine Learning service.

---

## 🚀 Latest Release: v1.0.0

When I first started this project, the goal was simple: stop SQL Injection and XSS before it hits the database. Over the past few days, the project underwent intense iterative testing to catch and fix critical bypasses, moving it from a broken experimental package into a functional heuristic Web Application Firewall (WAF) for Express.js.

If you are running a Node/Express backend and want a plug-and-play heuristic engine to block common payload attacks, SQLGuard-ML now works end-to-end.

### 🛡️ What it actually does
We've fundamentally rewritten the core engine to ensure it catches real attacks without blocking benign text. The heuristic layer features:

* **Recursive multi-layer decoder** (URL, double-URL, Base64, HTML entities, %uXXXX, null bytes)
* **SQL inline comment stripping** before pattern matching
* **Header and raw Buffer body scanning**
* **34 self-tests passing** (covering all known adversarial bypasses we threw at it)
* **Tested against 20+ benign payloads** without false positives

*(Note: The repository also contains a Python ML bridge and IP rate limiter, but they act strictly as proof-of-concept stubs. Out of the box, this is a two-tier system: Benign or Blocked).*

## Quick Start (Node.js)

Install the package via NPM:

```bash
npm install sqlguard-ml
```

See the [Usage](#-usage) section below for how to integrate it into Express.js!

---

## Overview

**SQLGuard ML** is a cybersecurity tool for detecting SQL Injection (SQLi) and Cross-Site Scripting (XSS). 
The Node.js package (`npm`) operates using a fast heuristic (regex-based) scanner. If you need a Machine Learning second opinion for borderline payloads, you can spin up the included Python FastAPI server locally to run the CNN-LSTM deep learning model.

## Features

- **Hybrid AI Bridge**: Automatically queries a local Python Machine Learning engine for a second opinion on borderline payloads to reduce false positives (requires running the Python server).
- **Deep Payload Decoding**: Unravels multi-layer URL encoding, Hex, and Base64 payloads before scanning to catch obfuscated attacks.
- **Express.js Middleware**: Plug-and-play middleware that automatically scans `req.query`, `req.body`, and `req.headers`.
- **Intelligent Header Scanning**: Deeply scans headers like `User-Agent`, `Referer`, and `X-Forwarded-For`, as well as raw text buffers to catch evasion attempts.
- **IP Reputation & Rate Limiting**: Tracks IP behavior with a sliding window to escalate suspicion if an attacker spams multiple borderline/ambiguous payloads. *(Note: This uses an in-memory Map, so state resets on server restart and is not shared across Node.js clusters/Kubernetes pods).*
- **ReDoS Protection**: Enforces strict payload length caps to prevent Regular Expression Denial of Service.
- **Comment Stripping**: Removes SQL inline comments to prevent common obfuscation bypasses (e.g. `UN/**/ION`).

## Architectural Limitations (Please Read)

- **Rate Limiting in PM2/Kubernetes**: The IP rate limiter runs in-process via an in-memory Map. This means it **resets on every server restart** and **does not share state across multiple Node processes**. If you are running PM2 clusters, Kubernetes pods, or any multi-instance deployment, rate limiting will be silently isolated per-instance. For true distributed rate limiting, layer a WAF or Redis-backed solution upstream.
- **Two-Tier Reality (Out of the Box)**: Because the heuristic engine now returns a strict `0.5` confidence for single pattern matches and the default block threshold is `0.5`, the middleware effectively operates as a strict two-tier system (Benign `0.0` or Blocked `0.5+`). The "ambiguous zone" (`0.2` to `0.49`) is practically empty. This means the **ML Bridge and Rate Limiter escalation will never fire by default**. If you want to use the three-tier architecture, you must manually raise the `threshold` option to `0.6` or higher so that single-pattern heuristic matches fall into the ambiguous zone.
- **ML Bridge is a Reference Implementation**: The architecture for querying an ML model is real and fully functional, but the included Python "AI" half is currently a **stub / proof-of-concept**. If you enable the `mlEndpoint`, you are expected to bring your own trained, production-ready model. The out-of-the-box Python script is for demonstration purposes only.

---

## Installation

### Node.js / NPM (Heuristic Scanner)

To install the heuristic library in your project:
```bash
npm install sqlguard-ml
```

### Python (Machine Learning Detector)

Currently, the `sqlguard-ml` Python package provides a lightweight FastAPI stub model using Scikit-Learn for the Hybrid Bridge. You must build and install it locally from this repository.

```bash
cd python
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .
python src/sqlguard_ml/train_stub.py
uvicorn src.sqlguard_ml.api:app --reload
```

*(Note: This provides the 'second opinion' endpoint that the Node.js middleware bridges to).*

---

## Usage

### Using the NPM Package (`sqlguard-ml`)
Once installed, you can use the Node CLI from anywhere:

```bash
# Scan a single payload
sqlguard-ml scan "<script>alert('XSS')</script>"

# Scan a file of payloads and output as CSV
sqlguard-ml scan-file payloads.txt --format csv
```

**As a Node.js Library:**
```javascript
const { Detector } = require('sqlguard-ml');

const detector = new Detector();
const result = detector.detect("' OR 1=1 --");

console.log(result.label); // 'sqli'
console.log(result.confidence);
```

### Using as Express.js Middleware (Advanced)
You can easily protect your Express.js applications by plugging in the `expressMiddleware`. It supports a Hybrid AI bridge to reduce false positives.

```javascript
const express = require('express');
const { expressMiddleware } = require('sqlguard-ml');

const app = express();

app.use(expressMiddleware({
  threshold: 0.5,
  mlEndpoint: 'http://127.0.0.1:8000/api/detect' // Optional: Fallback to Python AI for borderline payloads
}));

app.get('/api/data', (req, res) => {
  res.send("If you see this, your request was safe!");
});

app.listen(3000);
```

### Using the Python ML Package (`sqlguard`)
Once installed via pip, the Python CLI is immediately available:

```bash
# Detect attacks using the CLI
sqlguard detect "admin' --"

# Run the Machine Learning API Backend
uvicorn sqlguard_ml.api:app --port 8000
```

---

## Publishing the Packages (For Maintainers)

Want to publish these to the official registries so that `npm i` and `pip install` work for the public? Here's how:

**Publish to NPM:**
```bash
cd npm
npm login
npm publish
```

**Publish to PyPI:**
```bash
cd python
pip install build twine
python -m build
twine upload dist/*
```

---



## Contributing
Contributions, issues, and feature requests are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License
Copyright © 2026. This project is [MIT](LICENSE) licensed.




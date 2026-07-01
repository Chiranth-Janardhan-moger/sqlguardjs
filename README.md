# SQLGuard ML (Machine Learning Injection Detector)

<div align="center">
  <img src="https://img.shields.io/npm/v/sqlguard-ml?color=blue&style=for-the-badge" alt="NPM Version">
  <img src="https://img.shields.io/github/actions/workflow/status/Chiranth-Janardhan-moger/sqlguard-ml/ci.yml?branch=main&style=for-the-badge" alt="CI Status">
</div>

> **Hybrid SQL Injection (SQLi) and Cross-Site Scripting (XSS) detection engine.** Includes a Node.js heuristic scanner and an Express.js middleware that can bridge to a local Python FastAPI Machine Learning service.

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
- **IP Reputation & Rate Limiting**: Tracks IP behavior with a sliding window to escalate suspicion if an attacker spams multiple borderline/ambiguous payloads.
- **ReDoS Protection**: Enforces strict payload length caps to prevent Regular Expression Denial of Service.
- **Comment Stripping**: Removes SQL inline comments to prevent common obfuscation bypasses (e.g. `UN/**/ION`).

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




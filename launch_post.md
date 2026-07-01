# 🚀 Launching SQLGuard-ML v1.0.0

Hey everyone,

I'm releasing **SQLGuard-ML v1.0.0**. 

When I first started this project, the goal was simple: stop SQL Injection and XSS before it hits the database. Over the past few days, the project underwent intense iterative testing to catch and fix critical bypasses, moving it from a broken experimental package into a functional heuristic Web Application Firewall (WAF) for Express.js.

If you are running a Node/Express backend and want a plug-and-play heuristic engine to block common payload attacks, SQLGuard-ML now works end-to-end.

## 🛡️ What it actually does

We've fundamentally rewritten the core engine to ensure it catches real attacks without blocking benign text. The heuristic layer features:

* **Recursive multi-layer decoder** (URL, double-URL, Base64, HTML entities, %uXXXX, null bytes)
* **SQL inline comment stripping** before pattern matching
* **Header and raw Buffer body scanning**
* **34 self-tests passing** (covering all known adversarial bypasses we threw at it)
* **Tested against 20+ benign payloads** without false positives

*(Note: The repository also contains a Python ML bridge and IP rate limiter, but they act strictly as proof-of-concept stubs. Out of the box, this is a two-tier system: Benign or Blocked).*

## 📦 How to Use It

It's designed to be a one-liner drop-in:

```javascript
const express = require('express');
const { expressMiddleware } = require('sqlguard-ml');

const app = express();
app.use(express.json());

// Drop it in globally
app.use(expressMiddleware({ 
  threshold: 0.5, 
  logAttacks: false // Opt-in logging to keep production clean
}));

app.get('/', (req, res) => res.send("You are protected."));
```

## 🤝 Open Source & Honest
We're keeping the heuristics engine 100% open source on NPM.

We just locked our test suite at 34/34 passing adversarial bypass tests. We'd love for the community to try and break it. 

Check out the repository here: [GitHub - SQLGuard-ML](https://github.com/Chiranth-Janardhan-moger/sqlguard-ml)
Install it via NPM: `npm i sqlguard-ml`

Let me know what you think, and PRs for new evasion payloads are always welcome!

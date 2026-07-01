# 🚀 Launching SQLGuard-ML v1.2.3: The Production-Ready Express WAF

Hey everyone,

I'm excited to announce the release of **SQLGuard-ML v1.2.3**! 🎉 

When I first started this project, the goal was simple: stop SQL Injection and XSS before it hits the database. Over the past few days, the project underwent a massive security audit and complete architectural overhaul to transition from an experimental package into a hardened, production-grade Web Application Firewall (WAF) for Express.js.

If you are running a Node/Express backend and want plug-and-play protection against the most common payload attacks, SQLGuard-ML provides a strict heuristic engine out-of-the-box (with an optional ML bridge for anomaly detection).

## 🛡️ What's New?

We've fundamentally rewritten the core engine to ensure it stands up to real-world, adversarial fuzzing. The heuristic layer is solid and now features:

* **Recursive multi-layer decoder** (URL, double-URL, Base64, HTML entities, %uXXXX, null bytes)
* **SQL inline comment stripping** before pattern matching
* **IP-based rate escalation** for repeated ambiguous probes
* **Header and raw Buffer body scanning**
* **34 passing tests** including adversarial bypasses
* **Zero false positives** on a 20+ benign payload benchmark

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
  maxSuspiciousRequests: 3,
  logAttacks: false // Opt-in logging to keep production clean
}));

app.get('/', (req, res) => res.send("You are protected."));
```

## 🤝 Open Source & Honest
We're keeping the heuristics engine 100% open source on NPM. (The Python ML bridge is available in the repository if you want to self-host the AI anomaly detection).

We just locked our test suite at 34/34 passing adversarial bypass tests. We'd love for the community to try and break it. 

Check out the repository here: [GitHub - SQLGuard-ML](https://github.com/Chiranth-Janardhan-moger/sqlguard-ml)
Install it via NPM: `npm i sqlguard-ml`

Let me know what you think, and PRs for new evasion payloads are always welcome!

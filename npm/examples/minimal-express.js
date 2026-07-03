const express = require('express');
const { sqlguard } = require('sqlguard-ml');

const app = express();
const guard = sqlguard({
  threshold: 0.5,
  suspiciousThreshold: 0.2,
  logAttacks: true
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Global scanner checks body, query, headers, and cookies before routes.
app.use(guard.global({ scanParams: false }));

// Route verifier checks req.params after Express resolves them.
app.get('/users/:id', guard.route(), (req, res) => {
  res.json({ id: req.params.id });
});

app.post('/login', guard.route({
  schema: {
    body: {
      allowed: ['email', 'password'],
      required: ['email', 'password']
    },
    query: []
  }
}), (req, res) => {
  res.json({ ok: true });
});

app.listen(3000, () => {
  console.log('Example API listening on http://localhost:3000');
});

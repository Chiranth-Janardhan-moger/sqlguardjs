const express = require('express');
const { sqlguardjs } = require('sqlguardjs');

const app = express();
const guard = sqlguardjs({
  level: 'balanced',
  logRequests: true,
  logAttacks: true
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Global scanner checks body, query, headers, and cookies before routes.
app.use(guard.global({ scanParams: false }));

function requireAdmin(req, res, next) {
  if (process.env.ADMIN_TOKEN && req.headers.authorization === `Bearer ${process.env.ADMIN_TOKEN}`) return next();
  return res.sendStatus(403);
}

app.get('/admin/sqlguard/logs', requireAdmin, guard.logsHandler());

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

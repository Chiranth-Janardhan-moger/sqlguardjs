const express = require('express');
const helmet = require('helmet');
const { secureRouter } = require('sqlguardjs');

// Install example dependencies with:
// npm install express helmet sqlguardjs

const app = express();

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

const router = secureRouter({
  threshold: 0.5,
  suspiciousThreshold: 0.2,
  logAttacks: event => {
    // Replace console.warn with your logger, SIEM, or cloud log sink.
    console.warn(JSON.stringify(event));
  },
  logFormat: 'json',
  getRequestId: req => req.headers['x-request-id'] || null,
  onThreat(event) {
    // Admins can persist this event in a database, send alerts, or increment metrics.
    // Payload previews are redacted for sensitive field names by default.
    console.warn('sqlguardjs_threat', event.label, event.confidence, event.path);
  },
  learning: {
    enabled: true,
    onEvent(event) {
      // Store for review. Do not automatically train on live traffic.
      console.info('sqlguardjs_learning_candidate', event.clusterKey);
    }
  }
});

router.post('/login', {
  schema: {
    body: {
      allowed: ['email', 'password'],
      required: ['email', 'password']
    },
    query: []
  }
}, async (req, res) => {
  // Still use prepared statements or safe ORM APIs here.
  res.json({ ok: true });
});

router.get('/users/:id', {
  schema: {
    params: {
      allowed: ['id'],
      required: ['id']
    }
  }
}, async (req, res) => {
  // Still validate authorization and query the database safely.
  res.json({ id: req.params.id });
});

app.use('/api', router);

app.listen(3000, () => {
  console.log('Production-style API listening on http://localhost:3000');
});

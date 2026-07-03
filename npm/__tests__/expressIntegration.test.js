const express = require('express');
const request = require('supertest');
const { expressMiddleware, secureRouter, sqlguard } = require('../src/detector');

describe('Express integration', () => {
  it('blocks route params after Express resolves them', async () => {
    const app = express();
    const guard = sqlguard();

    app.use(guard.global({ scanParams: false }));
    app.get('/users/:id', guard.route(), (req, res) => {
      res.json({ id: req.params.id });
    });

    await request(app)
      .get('/users/1%20UNION%20SELECT%20password%20FROM%20users')
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('sqli');
      });
  });

  it('secureRouter inserts global and route-level guards automatically', async () => {
    const app = express();
    const router = secureRouter();

    app.use(express.json());
    router.post('/login', (req, res) => res.json({ ok: true }));
    router.get('/users/:id', (req, res) => res.json({ id: req.params.id }));
    app.use('/api', router);

    await request(app)
      .post('/api/login')
      .send({ email: 'a@example.com', password: '<script>alert(1)</script>' })
      .expect(403);

    await request(app)
      .get('/api/users/1%20UNION%20SELECT%20password%20FROM%20users')
      .expect(403);
  });

  it('enforces route schemas for unexpected fields', async () => {
    const app = express();
    const router = secureRouter();

    app.use(express.json());
    router.post('/login', {
      schema: {
        body: {
          allowed: ['email', 'password'],
          required: ['email', 'password']
        },
        query: []
      }
    }, (req, res) => res.json({ ok: true }));
    app.use(router);

    await request(app)
      .post('/login')
      .send({ email: 'a@example.com', password: 'correct horse battery staple' })
      .expect(200);

    await request(app)
      .post('/login')
      .send({ email: 'a@example.com', password: 'pw', role: 'admin' })
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('schema_violation');
      });
  });

  it('emits structured JSON logs with redacted sensitive payload previews', async () => {
    const logs = [];
    const app = express();

    app.use(express.json());
    app.use(expressMiddleware({
      logAttacks: entry => logs.push(entry),
      logFormat: 'json'
    }));
    app.post('/login', (req, res) => res.json({ ok: true }));

    await request(app)
      .post('/login')
      .set('x-request-id', 'req-123')
      .send({ password: '<script>alert(1)</script>' })
      .expect(403);

    expect(logs).toHaveLength(1);
    expect(logs[0]).toEqual(expect.objectContaining({
      type: 'sqlguard.threat',
      requestId: 'req-123',
      method: 'POST',
      url: '/login',
      label: 'xss',
      blocked: true,
      payloadPreview: '[redacted]'
    }));
    expect(logs[0].matchedSignalIds).toContain('script-tag');
  });

  it('records suspicious allowed payloads in safe learning mode', async () => {
    const learningEvents = [];
    const app = express();

    app.use(expressMiddleware({
      threshold: 0.9,
      maxSuspiciousRequests: 999,
      learning: true,
      onLearningEvent: event => learningEvents.push(event)
    }));
    app.get('/redirect', (req, res) => res.json({ ok: true }));

    await request(app)
      .get('/redirect?next=javascript:')
      .expect(200);

    expect(learningEvents).toHaveLength(1);
    expect(learningEvents[0]).toEqual(expect.objectContaining({
      type: 'sqlguard.learning',
      label: 'xss',
      path: 'query.next'
    }));
    expect(learningEvents[0].clusterKey).toMatch(/^xss:/);
  });
});

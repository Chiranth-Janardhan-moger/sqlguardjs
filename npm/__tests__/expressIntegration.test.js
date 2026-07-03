const express = require('express');
const request = require('supertest');
const { expressMiddleware, secureRouter, sqlguardjs } = require('../src/detector');

function captureRawBody(req, res, next) {
  let body = '';
  req.setEncoding('utf8');
  req.on('data', chunk => {
    body += chunk;
  });
  req.on('end', () => {
    req.rawBody = body;
    next();
  });
  req.on('error', next);
}

describe('Express integration', () => {
  it('blocks route params after Express resolves them', async () => {
    const app = express();
    const guard = sqlguardjs();

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

  it.each(['put', 'patch', 'delete', 'options'])('secureRouter applies route guards to %s routes', async method => {
    const app = express();
    const router = secureRouter();

    router[method]('/items/:id', {
      schema: {
        params: {
          required: ['id']
        }
      }
    }, (req, res) => res.json({ ok: true }));
    app.use(router);

    await request(app)[method]('/items/1%20UNION%20SELECT%20password%20FROM%20users')
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('sqli');
      });
  });

  it('secureRouter applies route guards to all() routes', async () => {
    const app = express();
    const router = secureRouter();

    router.all('/all/:id', (req, res) => res.json({ ok: true }));
    app.use(router);

    await request(app)
      .post('/all/1%20UNION%20SELECT%20password%20FROM%20users')
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('sqli');
      });
  });

  it('secureRouter applies route guards to head() routes', async () => {
    const app = express();
    const router = secureRouter();

    router.head('/head/:id', (req, res) => res.status(204).end());
    app.use(router);

    await request(app)
      .head('/head/1%20UNION%20SELECT%20password%20FROM%20users')
      .expect(403);
  });

  it('secureRouter does not mistake decorated handler functions for route options', async () => {
    const app = express();
    const router = secureRouter();
    const handler = (req, res) => res.json({ ok: true });
    handler.required = ['not', 'route', 'options'];

    router.get('/decorated/:id', handler);
    app.use(router);

    await request(app)
      .get('/decorated/123')
      .expect(200)
      .expect(res => {
        expect(res.body.ok).toBe(true);
      });
  });

  it('handles attacker-controlled array-valued headers in integration', async () => {
    const app = express();

    app.use(expressMiddleware());
    app.get('/headers', (req, res) => res.json({ ok: true }));

    await request(app)
      .get('/headers')
      .set('x-forwarded-for', ['127.0.0.1', '<script>alert(1)</script>'])
      .expect(403);
  });

  it('scans duplicate query parameters instead of trusting one parsed value', async () => {
    const app = express();

    app.use(expressMiddleware());
    app.get('/search', (req, res) => res.json({ id: req.query.id }));

    await request(app)
      .get('/search?id=1&id=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
      .expect(403);
  });

  it('scans text/plain bodies when a text parser exposes them before the guard', async () => {
    const app = express();

    app.use(express.text({ type: 'text/plain' }));
    app.use(expressMiddleware());
    app.post('/webhook', (req, res) => res.json({ ok: true }));

    await request(app)
      .post('/webhook')
      .set('Content-Type', 'text/plain')
      .send('{"id":"1 UNION SELECT password FROM users"}')
      .expect(403);
  });

  it('scans req.rawBody for custom parser or webhook endpoints', async () => {
    const app = express();

    app.use(captureRawBody);
    app.use(expressMiddleware());
    app.post('/webhook', (req, res) => {
      JSON.parse(req.rawBody);
      res.json({ ok: true });
    });

    await request(app)
      .post('/webhook')
      .set('Content-Type', 'text/plain')
      .send('{"id":"1 UNION SELECT password FROM users"}')
      .expect(403);
  });

  it('can inspect raw multipart form-data when the app captures rawBody before custom parsing', async () => {
    const app = express();
    const boundary = 'sqlguardjsBoundary';
    const multipartBody = [
      `--${boundary}`,
      'Content-Disposition: form-data; name="comment"',
      '',
      '<script>alert(1)</script>',
      `--${boundary}--`,
      ''
    ].join('\r\n');

    app.use(captureRawBody);
    app.use(expressMiddleware());
    app.post('/upload', (req, res) => res.json({ ok: true }));

    await request(app)
      .post('/upload')
      .set('Content-Type', `multipart/form-data; boundary=${boundary}`)
      .send(multipartBody)
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

  it('treats required-only schemas as an allowlist unless allowUnknown is true', async () => {
    const app = express();
    const router = secureRouter();

    app.use(express.json());
    router.post('/login', {
      schema: {
        body: {
          required: ['username', 'password']
        }
      }
    }, (req, res) => res.json({ ok: true }));
    router.post('/profile', {
      schema: {
        body: {
          required: ['displayName'],
          allowUnknown: true
        }
      }
    }, (req, res) => res.json({ ok: true }));
    app.use(router);

    await request(app)
      .post('/login')
      .send({ username: 'a', password: 'b', isAdmin: true })
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('schema_violation');
      });

    await request(app)
      .post('/profile')
      .send({ displayName: 'A', theme: 'dark' })
      .expect(200);
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
      type: 'sqlguardjs.threat',
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
      type: 'sqlguardjs.learning',
      label: 'xss',
      path: 'query.next'
    }));
    expect(learningEvents[0].clusterKey).toMatch(/^xss:/);
  });
});

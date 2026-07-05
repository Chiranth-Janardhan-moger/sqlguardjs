const express = require('express');
const request = require('supertest');
const { createNestMiddleware, expressMiddleware, nestjsMiddleware, secureRouter, sqlguardjs } = require('../src/detector');

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

  it('guard.route blocks body and query payloads when used without guard.global', async () => {
    const app = express();
    const guard = sqlguardjs();

    app.use(express.json());
    app.post('/login', guard.route(), (req, res) => res.json({ ok: true }));

    await request(app)
      .post('/login?next=javascript:alert(1)')
      .send({ email: 'a@example.com', bio: 'hello' })
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('xss');
      });

    await request(app)
      .post('/login')
      .send({ email: 'a@example.com', bio: '<script>alert(1)</script>' })
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('xss');
      });
  });

  it('guard.route skips request sources already scanned by guard.global', async () => {
    const app = express();
    const onThreat = jest.fn();
    const guard = sqlguardjs({ dryRun: true, onThreat });

    app.use(express.json());
    app.use(guard.global({ scanParams: false }));
    app.post('/login/:id', guard.route(), (req, res) => res.json({ ok: true }));

    await request(app)
      .post('/login/123')
      .send({ bio: '<script>alert(1)</script>' })
      .expect(200);

    expect(onThreat).toHaveBeenCalledTimes(1);
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

  it('guard.route can be applied explicitly to router.route() declarations', async () => {
    const app = express();
    const router = express.Router();
    const guard = sqlguardjs();

    router.route('/users/:id')
      .get(guard.route(), (req, res) => res.json({ id: req.params.id }));
    app.use(router);

    await request(app)
      .get('/users/1%20UNION%20SELECT%20password%20FROM%20users')
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('sqli');
      });
  });

  it('guard.route can be applied explicitly to path-scoped use() handlers', async () => {
    const app = express();
    const router = express.Router();
    const guard = sqlguardjs();

    router.use('/users/:id', guard.route(), (req, res) => res.json({ id: req.params.id }));
    app.use(router);

    await request(app)
      .get('/users/1%20UNION%20SELECT%20password%20FROM%20users')
      .expect(403)
      .expect(res => {
        expect(res.body.details.label).toBe('sqli');
      });
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

  it('exposes a bounded log endpoint when the app mounts it', async () => {
    const app = express();
    const guard = sqlguardjs({
      mode: 'log',
      logRequests: true,
      maxLogs: 1
    });

    app.use(guard.global());
    app.get('/admin/security/logs', guard.logsHandler());
    app.get('/search', (req, res) => res.json({ ok: true }));

    await request(app)
      .get('/search?q=<script>alert(1)</script>')
      .expect(200);
    await request(app)
      .get('/search?q=UNION%20SELECT%20password%20FROM%20users')
      .expect(200);

    await request(app)
      .get('/admin/security/logs')
      .expect(200)
      .expect(res => {
        expect(res.body).toHaveLength(1);
        expect(res.body[0]).toEqual(expect.objectContaining({
          type: 'sqlguardjs.threat',
          action: 'observe',
          blocked: false,
          method: 'GET',
          url: expect.stringContaining('/search'),
          path: 'query.q'
        }));
      });
  });

  it('can expose logs from secureRouter when explicitly enabled', async () => {
    const app = express();
    const router = secureRouter({
      mode: 'log',
      logRequests: true,
      exposeLogs: true,
      logsPath: '/security/logs'
    });

    router.get('/search', (req, res) => res.json({ ok: true }));
    app.use(router);

    await request(app)
      .get('/search?q=<script>alert(1)</script>')
      .expect(200);

    await request(app)
      .get('/security/logs')
      .expect(200)
      .expect(res => {
        expect(res.body[0]).toEqual(expect.objectContaining({
          type: 'sqlguardjs.threat',
          action: 'observe',
          label: 'xss'
        }));
      });
  });

  it('records repeated suspicious activity escalation in endpoint logs', async () => {
    const app = express();
    const guard = sqlguardjs({
      mode: 'block',
      threshold: 0.6,
      maxSuspiciousRequests: 2,
      logRequests: true
    });

    app.use(guard.global());
    app.get('/admin/security/logs', guard.logsHandler());
    app.get('/redirect', (req, res) => res.json({ ok: true }));

    await request(app)
      .get('/redirect?next=javascript:')
      .expect(200);

    await request(app)
      .get('/redirect?next=javascript:')
      .expect(403);

    await request(app)
      .get('/admin/security/logs')
      .expect(200)
      .expect(res => {
        expect(res.body).toEqual(expect.arrayContaining([
          expect.objectContaining({
            type: 'sqlguardjs.rate_limit',
            label: 'rate_limit_escalation',
            reason: 'repeated_suspicious_probe'
          }),
          expect.objectContaining({
            type: 'sqlguardjs.threat',
            label: 'rate_limit_escalation'
          })
        ]));
      });
  });

  it('lets learning mode observe strong detections without blocking initially', async () => {
    const app = express();
    const guard = sqlguardjs({
      learning: true,
      logRequests: true
    });

    app.use(guard.global());
    app.get('/admin/security/logs', guard.logsHandler());
    app.get('/profile', (req, res) => res.json({ ok: true }));

    await request(app)
      .get('/profile?bio=<script>alert(1)</script>')
      .expect(200);

    await request(app)
      .get('/admin/security/logs')
      .expect(200)
      .expect(res => {
        expect(res.body[0]).toEqual(expect.objectContaining({
          action: 'observe',
          blocked: false,
          label: 'xss'
        }));
      });
  });

  it('supports strict, balanced, and permissive detection levels', async () => {
    const strictApp = express();
    strictApp.use(expressMiddleware({ level: 'strict' }));
    strictApp.get('/redirect', (req, res) => res.json({ ok: true }));

    await request(strictApp)
      .get('/redirect?next=javascript:')
      .expect(403);

    const balancedApp = express();
    balancedApp.use(expressMiddleware({ level: 'balanced' }));
    balancedApp.get('/redirect', (req, res) => res.json({ ok: true }));

    await request(balancedApp)
      .get('/redirect?next=javascript:')
      .expect(200);

    const middleware = expressMiddleware({
      level: 'permissive',
      logRequests: true
    });
    const permissiveAppWithLogs = express();
    permissiveAppWithLogs.use(middleware);
    permissiveAppWithLogs.get('/admin/security/logs', middleware.logsHandler());
    permissiveAppWithLogs.get('/search', (req, res) => res.json({ ok: true }));

    await request(permissiveAppWithLogs)
      .get('/search?q=<script>alert(1)</script>')
      .expect(200);
    await request(permissiveAppWithLogs)
      .get('/admin/security/logs')
      .expect(200)
      .expect(res => {
        expect(res.body[0]).toEqual(expect.objectContaining({
          action: 'observe',
          label: 'xss'
        }));
      });
  });

  it('suppresses known false positives by route or parameter', async () => {
    const app = express();

    app.use(expressMiddleware({
      allowRoutes: ['/admin/search'],
      allowParams: ['query.q']
    }));
    app.get('/admin/search', (req, res) => res.json({ ok: true }));
    app.get('/search', (req, res) => res.json({ ok: true }));

    await request(app)
      .get('/admin/search?term=<script>alert(1)</script>')
      .expect(200);

    await request(app)
      .get('/search?q=<script>alert(1)</script>')
      .expect(200);

    await request(app)
      .get('/search?other=<script>alert(1)</script>')
      .expect(403);
  });

  it('can lower sensitivity for selected routes', async () => {
    const app = express();

    app.use(expressMiddleware({
      level: 'strict',
      routeLevels: {
        '/redirect': 'balanced'
      }
    }));
    app.get('/redirect', (req, res) => res.json({ ok: true }));
    app.get('/strict', (req, res) => res.json({ ok: true }));

    await request(app)
      .get('/redirect?next=javascript:')
      .expect(200);

    await request(app)
      .get('/strict?next=javascript:')
      .expect(403);
  });

  it('reuses the Express middleware contract for NestJS functional and class middleware', async () => {
    const functionalApp = express();
    functionalApp.use(nestjsMiddleware({ mode: 'log' }));
    functionalApp.get('/profile', (req, res) => res.json({ ok: true }));

    await request(functionalApp)
      .get('/profile?bio=<script>alert(1)</script>')
      .expect(200);

    const NestGuard = createNestMiddleware({ mode: 'log' });
    const classApp = express();
    const nestGuard = new NestGuard();
    classApp.use(nestGuard.use.bind(nestGuard));
    classApp.get('/profile', (req, res) => res.json({ ok: true }));

    await request(classApp)
      .get('/profile?bio=<script>alert(1)</script>')
      .expect(200);
  });
});

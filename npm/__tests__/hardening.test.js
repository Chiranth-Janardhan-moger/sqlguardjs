const { Detector, expressMiddleware } = require('../src/detector');

function createMockResponse() {
  return {
    status: jest.fn().mockReturnThis(),
    json: jest.fn()
  };
}

function flushPromises() {
  return new Promise(resolve => setImmediate(resolve));
}

describe('Security hardening regressions', () => {
  let detector;

  beforeEach(() => {
    detector = new Detector();
  });

  it('detects SQL block comments used as whitespace between keywords', () => {
    const payload = '1 UNION/**/SELECT password FROM users--';
    const decoded = detector.decodeDeeply(payload);
    const result = detector.detect(payload);

    expect(decoded).toContain('UNION SELECT');
    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it('detects SQL block comments used to split keywords mid-word', () => {
    const result = detector.detect('UN/**/ION SEL/**/ECT * FROM users');

    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.matches.map(match => match.id)).toContain('comment-fragmented-union-select');
  });

  it('detects MySQL versioned comments without deleting executable SQL', () => {
    const payload = 'id=-1/*!50000UNION SELECT username,password FROM users*/';
    const result = detector.detect(payload);

    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.matches.map(match => match.id)).toEqual(expect.arrayContaining([
      'mysql-versioned-comment',
      'union-select'
    ]));
  });

  it.each([
    'id=-1 UNION#foo\nSELECT username,password FROM users',
    'id=-1 UNION-- foo\nSELECT username,password FROM users'
  ])('detects SQL line comments used as keyword separators: %s', payload => {
    const result = detector.detect(payload);

    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.matches.map(match => match.id)).toContain('union-select');
  });

  it.each([
    "1' || '1'='1",
    "1' && '1'='1",
    'id=1 OR 1>0',
    'id=1 OR 3!=4',
    "' OR 'a'<'b",
    "1' OR TRUE",
    "1' OR EXISTS(SELECT password FROM users)",
    "1' OR 1 BETWEEN 1 AND 2",
    "1' OR 1 IS NOT NULL"
  ])('detects broadened SQL boolean tautology syntax: %s', payload => {
    const result = detector.detect(payload);

    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.matches.map(match => match.id)).toContain('boolean-tautology');
  });

  it.each([
    '1 UNION(SELECT password FROM users)',
    '1 UNION DISTINCT SELECT password FROM users'
  ])('detects UNION SELECT variants: %s', payload => {
    const result = detector.detect(payload);

    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.matches.map(match => match.id)).toContain('union-select');
  });

  it.each([
    ['JavaScript unicode escaped script tag', '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e', 'xss'],
    ['JavaScript hex escaped script tag', '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e', 'xss'],
    ['JavaScript unicode escaped pseudo-protocol', 'java\\u0073cript:alert(1)', 'xss'],
    ['JavaScript hex escaped pseudo-protocol', 'java\\x73cript:alert(1)', 'xss'],
    ['JavaScript unicode escaped SQL keyword', 'UN\\u0049ON SELECT password FROM users', 'sqli']
  ])('normalizes %s', (_name, payload, label) => {
    const result = detector.detect(payload);

    expect(result.label).toBe(label);
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it('decodes and detects base64 SVG data URI XSS payloads', () => {
    const payload = 'data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+';
    const result = detector.detect(payload);

    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.matches.map(match => match.id)).toEqual(expect.arrayContaining([
      'svg-data-url',
      'html-event-attribute'
    ]));
  });

  it('detects payloads through deeper nested URL encoding', () => {
    const encoded = Array.from({ length: 6 }).reduce(
      value => encodeURIComponent(value),
      '<script>alert(1)</script>'
    );
    const result = detector.detect(encoded);

    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it.each([
    ['fullwidth SQL keywords', 'ＵＮＩＯＮ　ＳＥＬＥＣＴ password FROM users', 'sqli'],
    ['fullwidth script tag', '＜script＞alert(1)＜/script＞', 'xss'],
    ['HTML entity encoded event handler', '&#x3c;img src=x onerror=alert(1)&#x3e;', 'xss']
  ])('normalizes %s', (_name, payload, label) => {
    const result = detector.detect(payload);

    expect(result.label).toBe(label);
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it('keeps long pathological-looking inputs within a broad timing budget', () => {
    const samples = [
      'a'.repeat(50000),
      "'".repeat(2000) + ' OR ' + '1='.repeat(2000),
      '<'.repeat(20000) + 'script'.repeat(1000),
      'data:image/svg+xml;base64,' + 'A'.repeat(50000)
    ];
    const startedAt = Date.now();

    for (const sample of samples) {
      expect(() => detector.detect(sample)).not.toThrow();
    }

    expect(Date.now() - startedAt).toBeLessThan(5000);
  });

  it('detects bare destructive DDL without requiring a semicolon', () => {
    const result = detector.detect('DROP TABLE users');

    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
  });

  it('does not treat ordinary prose containing "drop table" as DDL', () => {
    expect(detector.detect('Drop table near the window.').label).toBe('benign');
  });

  it('does not block a JSON-ish quoted equals value as SQLi', async () => {
    const middleware = expressMiddleware();
    const req = {
      ip: '4.4.4.4',
      body: { payload: '{"password"="abc123"}' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    expect(detector.detect(req.body.payload).label).toBe('benign');

    await middleware(req, res, next);

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('keeps weak single-signal findings below the default block threshold', () => {
    const result = detector.detect('javascript:');

    expect(result.label).toBe('xss');
    expect(result.confidence).toBeGreaterThanOrEqual(0.2);
    expect(result.confidence).toBeLessThan(0.5);
  });
});

describe('Express middleware hardening options', () => {
  it('records detections without blocking when dryRun is enabled', async () => {
    const onThreat = jest.fn();
    const middleware = expressMiddleware({ dryRun: true, onThreat });
    const req = {
      ip: '5.5.5.5',
      body: { q: 'UNION SELECT password FROM users' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.sqlguardjs).toEqual(expect.objectContaining({
      detected: true,
      dryRun: true,
      label: 'sqli'
    }));
    expect(onThreat).toHaveBeenCalledWith(req.sqlguardjs, req);
  });

  it('continues scanning all sources in dryRun mode after the first detection', async () => {
    const onThreat = jest.fn();
    const middleware = expressMiddleware({ dryRun: true, onThreat });
    const req = {
      query: { a: "1' OR '1'='1" },
      body: { comment: '<script>alert(1)</script>' },
      cookies: { next: 'javascript:alert(1)' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.sqlguardjsDetections).toHaveLength(3);
    expect(req.sqlguardjsDetections.map(event => event.path)).toEqual(expect.arrayContaining([
      'query.a',
      'body.comment',
      'cookies.next'
    ]));
    expect(onThreat).toHaveBeenCalledTimes(3);
  });

  it('continues scanning request signals after a dryRun schema violation', async () => {
    const onThreat = jest.fn();
    const middleware = expressMiddleware({
      dryRun: true,
      onThreat,
      schema: {
        body: {
          required: ['username', 'password']
        }
      }
    });
    const req = {
      body: {
        username: 'a',
        password: 'b',
        isAdmin: true,
        bio: '<script>alert(1)</script>'
      }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
    expect(req.sqlguardjsDetections.map(event => event.label)).toEqual(expect.arrayContaining([
      'schema_violation',
      'xss'
    ]));
    expect(onThreat).toHaveBeenCalledTimes(2);
  });

  it('records multiple suspicious learning candidates in one dryRun request', async () => {
    const learningEvents = [];
    const middleware = expressMiddleware({
      dryRun: true,
      threshold: 0.9,
      maxSuspiciousRequests: 999,
      learning: true,
      onLearningEvent: event => learningEvents.push(event)
    });
    const req = {
      query: { next: 'javascript:' },
      body: { link: 'javascript:' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
    expect(learningEvents.map(event => event.path)).toEqual(expect.arrayContaining([
      'query.next',
      'body.link'
    ]));
  });

  it('scans prototype-pollution-shaped keys without mutating object prototypes', async () => {
    const middleware = expressMiddleware();
    const req = {
      body: JSON.parse('{"__proto__":"<script>alert(1)</script>","constructor":{"prototype":{"polluted":"UNION SELECT password FROM users"}}}')
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect({}.polluted).toBeUndefined();
    expect(next).not.toHaveBeenCalled();
  });

  it('blocks instead of throwing when request objects cannot be enumerated', async () => {
    const middleware = expressMiddleware();
    const req = {
      query: new Proxy({}, {
        ownKeys() {
          throw new Error('ownKeys failed');
        }
      })
    };
    const res = createMockResponse();
    const next = jest.fn();

    await expect(middleware(req, res, next)).resolves.toBeUndefined();

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      details: { label: 'dos' }
    }));
    expect(next).not.toHaveBeenCalled();
    expect(req.sqlguardjs.reason).toBe('object_enumeration_failed');
  });

  it('blocks instead of throwing when request object properties throw on access', async () => {
    const middleware = expressMiddleware();
    const body = {};
    Object.defineProperty(body, 'q', {
      enumerable: true,
      get() {
        throw new Error('getter failed');
      }
    });
    const req = { body };
    const res = createMockResponse();
    const next = jest.fn();

    await expect(middleware(req, res, next)).resolves.toBeUndefined();

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      details: { label: 'dos' }
    }));
    expect(next).not.toHaveBeenCalled();
    expect(req.sqlguardjs.reason).toBe('object_property_access_failed');
  });

  it('reports schema violations instead of throwing when schema sources cannot be enumerated', async () => {
    const middleware = expressMiddleware({
      schema: {
        body: { allowed: ['email'] }
      }
    });
    const req = {
      body: new Proxy({}, {
        ownKeys() {
          throw new Error('schema ownKeys failed');
        }
      })
    };
    const res = createMockResponse();
    const next = jest.fn();

    await expect(middleware(req, res, next)).resolves.toBeUndefined();

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      details: { label: 'schema_violation' }
    }));
    expect(next).not.toHaveBeenCalled();
    expect(req.sqlguardjs.reason).toBe('unreadable_object');
  });

  it('blocks instead of throwing when request source getters throw', async () => {
    const middleware = expressMiddleware();
    const req = {};
    Object.defineProperty(req, 'query', {
      enumerable: true,
      get() {
        throw new Error('query getter failed');
      }
    });
    const res = createMockResponse();
    const next = jest.fn();

    await expect(middleware(req, res, next)).resolves.toBeUndefined();

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      details: { label: 'dos' }
    }));
    expect(next).not.toHaveBeenCalled();
    expect(req.sqlguardjs.reason).toBe('source_read_failed');
  });

  it('blocks instead of throwing when schema source getters throw', async () => {
    const middleware = expressMiddleware({
      schema: {
        query: { allowed: ['q'] }
      }
    });
    const req = {};
    Object.defineProperty(req, 'query', {
      enumerable: true,
      get() {
        throw new Error('schema query getter failed');
      }
    });
    const res = createMockResponse();
    const next = jest.fn();

    await expect(middleware(req, res, next)).resolves.toBeUndefined();

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      details: { label: 'dos' }
    }));
    expect(next).not.toHaveBeenCalled();
    expect(req.sqlguardjs.reason).toBe('schema_source_read_failed');
  });

  it('escapes newlines in text logs and request IDs', async () => {
    const logs = [];
    const middleware = expressMiddleware({
      logAttacks: message => logs.push(message)
    });
    const req = {
      headers: {
        'x-request-id': 'req-123\n[SQLGuardJS] forged request'
      },
      query: {
        q: "1' OR '1'='1\n[SQLGuardJS] Attack Blocked: forged_entry from IP: 127.0.0.1"
      }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(logs).toHaveLength(1);
    expect(logs[0]).not.toContain('\n');
    expect(logs[0]).toContain('req-123\\n[SQLGuardJS] forged request');
    expect(logs[0]).toContain("'1'='1\\n[SQLGuardJS] Attack Blocked: forged_entry");
  });

  it('supports skip callbacks and custom block status codes', async () => {
    const skipped = expressMiddleware({ skip: req => req.path === '/health' });
    const blocked = expressMiddleware({ blockStatus: 406 });
    const healthReq = {
      path: '/health',
      body: { q: '<script>alert(1)</script>' }
    };
    const attackReq = {
      path: '/login',
      body: { q: '<script>alert(1)</script>' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await skipped(healthReq, res, next);
    await blocked(attackReq, res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).toHaveBeenCalledWith(406);
  });

  it('does not let a throwing log callback break attack blocking', async () => {
    const onCallbackError = jest.fn();
    const middleware = expressMiddleware({
      logAttacks: () => {
        throw new Error('siem unavailable');
      },
      onCallbackError
    });
    const req = {
      query: { q: "1' OR '1'='1" }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    expect(onCallbackError).toHaveBeenCalledTimes(1);
    expect(onCallbackError.mock.calls[0][1]).toEqual(expect.objectContaining({
      type: 'sqlguardjs.callback_error',
      hook: 'logAttacks',
      message: 'siem unavailable',
      eventType: 'sqlguardjs.threat',
      eventLabel: 'sqli'
    }));
  });

  it('does not let an async log callback rejection break attack blocking', async () => {
    const onCallbackError = jest.fn();
    const middleware = expressMiddleware({
      logAttacks: () => Promise.reject(new Error('async siem unavailable')),
      onCallbackError
    });
    const req = {
      query: { q: "1' OR '1'='1" }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);
    await flushPromises();

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    expect(onCallbackError).toHaveBeenCalledWith(expect.any(Error), expect.objectContaining({
      hook: 'logAttacks',
      message: 'async siem unavailable'
    }));
  });

  it('does not let the callback-error reporter break attack blocking', async () => {
    const middleware = expressMiddleware({
      logAttacks: () => {
        throw new Error('primary logger failed');
      },
      onCallbackError: () => {
        throw new Error('secondary reporter failed');
      }
    });
    const req = {
      query: { q: "1' OR '1'='1" }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  it('does not let a throwing onThreat callback break attack blocking', async () => {
    const onCallbackError = jest.fn();
    const middleware = expressMiddleware({
      onThreat: () => {
        throw new Error('alert sink unavailable');
      },
      onCallbackError
    });
    const req = {
      body: { q: '<script>alert(1)</script>' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    expect(onCallbackError).toHaveBeenCalledWith(expect.any(Error), expect.objectContaining({
      hook: 'onThreat',
      message: 'alert sink unavailable',
      eventLabel: 'xss'
    }));
  });

  it('does not let a throwing learning callback block an allowed suspicious request', async () => {
    const onCallbackError = jest.fn();
    const middleware = expressMiddleware({
      threshold: 0.9,
      maxSuspiciousRequests: 999,
      learning: true,
      onLearningEvent: () => {
        throw new Error('review queue unavailable');
      },
      onCallbackError
    });
    const req = {
      query: { next: 'javascript:' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(1);
    expect(onCallbackError).toHaveBeenCalledWith(expect.any(Error), expect.objectContaining({
      hook: 'onLearningEvent',
      message: 'review queue unavailable',
      eventType: 'sqlguardjs.learning'
    }));
  });

  it('continues scanning when a skip callback throws', async () => {
    const onCallbackError = jest.fn();
    const middleware = expressMiddleware({
      skip: () => {
        throw new Error('skip policy failed');
      },
      onCallbackError
    });
    const req = {
      path: '/login',
      body: { q: '<script>alert(1)</script>' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    expect(onCallbackError).toHaveBeenCalledWith(expect.any(Error), expect.objectContaining({
      hook: 'skip',
      message: 'skip policy failed'
    }));
  });

  it('falls back safely when request ID or rate-limit key callbacks throw', async () => {
    const onCallbackError = jest.fn();
    const middleware = expressMiddleware({
      getRequestId: () => {
        throw new Error('bad request id source');
      },
      rateLimitKey: () => {
        throw new Error('bad rate key source');
      },
      onCallbackError
    });
    const req = {
      ip: '203.0.113.10',
      body: { q: 'UNION SELECT password FROM users' }
    };
    const res = createMockResponse();
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    expect(req.sqlguardjs.requestId).toBeNull();
    expect(req.sqlguardjs.ip).toBe('203.0.113.10');
    expect(onCallbackError.mock.calls.map(call => call[1].hook)).toEqual(expect.arrayContaining([
      'getRequestId',
      'rateLimitKey'
    ]));
  });
});

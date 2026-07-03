const { Detector, expressMiddleware } = require('../src/detector');

function createMockResponse() {
  return {
    status: jest.fn().mockReturnThis(),
    json: jest.fn()
  };
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
    "' OR 'a'<'b"
  ])('detects broadened SQL boolean tautology syntax: %s', payload => {
    const result = detector.detect(payload);

    expect(result.label).toBe('sqli');
    expect(result.confidence).toBeGreaterThanOrEqual(0.5);
    expect(result.matches.map(match => match.id)).toContain('boolean-tautology');
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
});

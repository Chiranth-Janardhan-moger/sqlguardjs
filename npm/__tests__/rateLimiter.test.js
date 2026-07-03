const { expressMiddleware } = require('../src/detector');
const { IPRateLimiter } = require('../src/rateLimiter');

describe('IPRateLimiter class', () => {
  it('should clean up old timestamps based on windowMs', () => {
    const limiter = new IPRateLimiter(100, 1000);
    expect(limiter.recordSuspicious('1.1.1.1')).toBe(1);
    
    // mock date
    const realDateNow = Date.now.bind(global.Date);
    global.Date.now = jest.fn(() => realDateNow() + 200);
    
    expect(limiter.recordSuspicious('1.1.1.1')).toBe(1);
    global.Date.now = realDateNow;
  });

  it('should enforce maxCapacity', () => {
    const limiter = new IPRateLimiter(10000, 10);
    for (let i = 0; i < 15; i++) {
      limiter.recordSuspicious(`192.168.0.${i}`);
    }
    expect(limiter.ips.size).toBe(10);
    expect(limiter.ips.has('192.168.0.0')).toBe(false); // First elements get deleted
  });

  it('should cap retained timestamps for a single key', () => {
    const limiter = new IPRateLimiter(10000, 10, 3);

    for (let i = 0; i < 10; i++) {
      limiter.recordSuspicious('1.1.1.1');
    }

    expect(limiter.recordSuspicious('1.1.1.1')).toBe(3);
    expect(limiter.ips.get('1.1.1.1')).toHaveLength(3);
  });

  it('should prune expired keys before evicting active keys', () => {
    const limiter = new IPRateLimiter(100, 2);
    const realDateNow = Date.now.bind(global.Date);
    global.Date.now = jest.fn(() => 1000);
    limiter.recordSuspicious('old');
    global.Date.now = jest.fn(() => 1200);
    limiter.recordSuspicious('active');
    limiter.recordSuspicious('new');
    global.Date.now = realDateNow;

    expect(limiter.ips.has('old')).toBe(false);
    expect(limiter.ips.has('active')).toBe(true);
    expect(limiter.ips.has('new')).toBe(true);
  });

  it('should evict the least recently used key when full', () => {
    const limiter = new IPRateLimiter(10000, 2);
    limiter.recordSuspicious('a');
    limiter.recordSuspicious('b');
    limiter.recordSuspicious('a');
    limiter.recordSuspicious('c');

    expect(limiter.ips.has('a')).toBe(true);
    expect(limiter.ips.has('b')).toBe(false);
    expect(limiter.ips.has('c')).toBe(true);
  });
});

describe('Rate Limiter Middleware Integration', () => {
  let mockNext;
  let mockRes;

  beforeEach(() => {
    mockNext = jest.fn();
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
  });

  it('should block an IP after multiple ambiguous payloads', async () => {
    const middleware = expressMiddleware({ maxSuspiciousRequests: 3, threshold: 0.6 });
    const createReq = () => ({
      ip: '2.2.2.2',
      query: { q: 'javascript:' }
    });

    for (let i = 0; i < 2; i++) {
      await middleware(createReq(), mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(i + 1);
      expect(mockRes.status).not.toHaveBeenCalled();
    }

    // 3rd time should block
    await middleware(createReq(), mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
      message: 'Malicious payload detected by SQLGuardJS',
      details: { label: 'rate_limit_escalation' }
    }));
  });

  it('should support custom rate limit keys for users behind the same proxy', async () => {
    const middleware = expressMiddleware({
      maxSuspiciousRequests: 2,
      threshold: 0.6,
      rateLimitKey: req => req.headers['x-user-id'] || req.ip
    });

    const firstUserReq = () => ({
      ip: '10.0.0.10',
      headers: { 'x-user-id': 'user-a' },
      query: { q: 'javascript:' }
    });
    const secondUserReq = {
      ip: '10.0.0.10',
      headers: { 'x-user-id': 'user-b' },
      query: { q: 'javascript:' }
    };

    await middleware(firstUserReq(), mockRes, mockNext);
    await middleware(secondUserReq, mockRes, mockNext);

    expect(mockRes.status).not.toHaveBeenCalled();
    expect(mockNext).toHaveBeenCalledTimes(2);

    await middleware(firstUserReq(), mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
      details: { label: 'rate_limit_escalation' }
    }));
  });

  it('should not leak suspicious counts across concurrent requests with different keys', async () => {
    const middleware = expressMiddleware({
      maxSuspiciousRequests: 2,
      threshold: 0.6,
      rateLimitKey: req => req.headers['x-user-id']
    });
    const responses = Array.from({ length: 3 }, () => ({
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    }));
    const nexts = Array.from({ length: 3 }, () => jest.fn());
    const requests = ['user-a', 'user-b', 'user-c'].map(userId => ({
      headers: { 'x-user-id': userId },
      query: { q: 'javascript:' }
    }));

    await Promise.all(requests.map((req, index) => middleware(req, responses[index], nexts[index])));

    for (const res of responses) {
      expect(res.status).not.toHaveBeenCalled();
    }
    for (const next of nexts) {
      expect(next).toHaveBeenCalledTimes(1);
    }
  });

  it('should not make external calls for suspicious payloads', async () => {
    const realFetch = global.fetch;
    const mockFetch = jest.fn();
    global.fetch = mockFetch;

    const middleware = expressMiddleware({
      threshold: 0.6,
      maxSuspiciousRequests: 999
    });
    const req = {
      ip: '3.3.3.3',
      body: { link: 'javascript:' }
    };

    try {
      await middleware(req, mockRes, mockNext);
    } finally {
      global.fetch = realFetch;
    }

    expect(mockFetch).not.toHaveBeenCalled();
    expect(mockRes.status).not.toHaveBeenCalled();
    expect(mockNext).toHaveBeenCalledTimes(1);
  });
});

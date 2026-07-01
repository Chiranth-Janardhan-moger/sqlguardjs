const { expressMiddleware } = require('../src/detector');
const { IPRateLimiter } = require('../src/rateLimiter');

describe('IPRateLimiter class', () => {
  it('should clean up old timestamps based on windowMs', () => {
    const limiter = new IPRateLimiter(100, 1000);
    limiter.recordSuspicious('1.1.1.1');
    expect(limiter.getCount('1.1.1.1')).toBe(1);
    
    // mock date
    const realDateNow = Date.now.bind(global.Date);
    global.Date.now = jest.fn(() => realDateNow() + 200);
    
    expect(limiter.getCount('1.1.1.1')).toBe(0);
    global.Date.now = realDateNow;
  });

  it('should enforce maxCapacity', () => {
    const limiter = new IPRateLimiter(10000, 10);
    for (let i = 0; i < 15; i++) {
      limiter.recordSuspicious(`192.168.0.${i}`);
    }
    // Should have pruned some elements
    expect(limiter.ips.size).toBeLessThanOrEqual(15);
    expect(limiter.ips.has('192.168.0.0')).toBe(false); // First elements get deleted
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
    const middleware = expressMiddleware({ maxSuspiciousRequests: 3 });
    const req = {
      ip: '2.2.2.2',
      query: { q: 'union' } // 'union' scores 0.35 if it hits some sub-heuristic or 0.2? Wait, the regex is union select. 
      // Let's just use something we know triggers 0.2 - 0.7.
      // Wait, let's look at detector.js: 
      // 'UNION' alone won't trigger sqliScore because regex is \b(?:UNION\s+(?:ALL\s+)?SELECT|...
    };
    
    // To trigger an ambiguous payload, we need a confidence between 0.2 and 0.5.
    // Each matched pattern adds 1 to the score, so maxScore * 0.35.
    // maxScore = 1 => 0.35.
    // Let's match one xss pattern: javascript:
    req.query.q = 'javascript:'; 

    for (let i = 0; i < 2; i++) {
      await middleware(req, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledTimes(i + 1);
      expect(mockRes.status).not.toHaveBeenCalled();
    }

    // 3rd time should block
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockRes.json).toHaveBeenCalledWith(expect.objectContaining({
      message: 'Malicious payload detected by SQLGuard ML',
      details: { label: 'rate_limit_escalation' }
    }));
  });
});

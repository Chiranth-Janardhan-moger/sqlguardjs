const { expressMiddleware } = require('../src/detector');

describe('Adversarial Bypasses', () => {
  let mockNext;
  let mockRes;
  let middleware;

  beforeEach(() => {
    mockNext = jest.fn();
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    middleware = expressMiddleware({ threshold: 0.2 });
  });

  it('should detect double URL-encoded XSS', async () => {
    const req = {
      query: { q: '%253Cscript%253Ealert(1)%253C%252Fscript%253E' }
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
  });

  it('should detect Base64 encoded XSS', async () => {
    const req = {
      body: { data: 'PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==' }
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
  });

  it('should detect SQLi obfuscated with inline comments', async () => {
    const req = {
      body: 'UN/**/ION SEL/**/ECT * FROM users'
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
  });

  it('should detect mixed encoding obfuscation in headers', async () => {
    const req = {
      headers: {
        'x-forwarded-for': '127.0.0.1, %55%4e%49%4f%4e%20%53%45%4c%45%43%54' // UNION SELECT url encoded
      }
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
  });

  it('should detect attribute injection without wrapping tag', async () => {
    const req = {
      query: { q: 'onmouseover="alert(1)' }
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
  });

  it('should detect SQL block comment breakout probes', async () => {
    const req = {
      body: { username: "admin'/*" }
    };

    await middleware(req, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(403);
  });

  it('should detect union values extraction probes', async () => {
    const req = {
      query: { q: "%' UNION VALUES(1, (SELECT flag_value FROM flags))/*" }
    };

    await middleware(req, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(403);
  });

  it('should detect payloads hidden beyond the scan prefix', async () => {
    const req = {
      body: {
        username: `fake_user'${' '.repeat(50000)} UNION SELECT 1, flag_value, 'dummy', 'dummy' FROM flags--`
      }
    };

    await middleware(req, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(403);
  });
});

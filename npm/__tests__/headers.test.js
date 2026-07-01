const { expressMiddleware } = require('../src/detector');

describe('Header and Raw Body Scanning', () => {
  let mockNext;
  let mockRes;

  beforeEach(() => {
    mockNext = jest.fn();
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
  });

  it('should block SQLi in User-Agent header', async () => {
    const middleware = expressMiddleware({ threshold: 0.2 });
    const req = {
      headers: {
        'user-agent': "Mozilla/5.0' OR '1'='1"
      }
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should block XSS in X-Forwarded-For array header', async () => {
    const middleware = expressMiddleware({ threshold: 0.2 });
    const req = {
      headers: {
        'x-forwarded-for': ['127.0.0.1', '<script>alert(1)</script>']
      }
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should scan raw text string body', async () => {
    const middleware = expressMiddleware({ threshold: 0.2 });
    const req = {
      body: "plain text with SQLi DROP TABLE users;" 
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should scan Buffer body (e.g. express.raw)', async () => {
    const middleware = expressMiddleware({ threshold: 0.2 });
    const req = {
      body: Buffer.from("<script>alert(1)</script>", "utf8")
    };
    await middleware(req, mockRes, mockNext);
    expect(mockRes.status).toHaveBeenCalledWith(403);
    expect(mockNext).not.toHaveBeenCalled();
  });
});

class Detector {
  constructor() {
    this.sqliPatterns = [
      /(?:')|(?:--)|(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|TRUNCATE)\b)/i,
      /(?:\b(OR|AND)\b\s+['"\d\w]+\s*[=<>]\s*['"\d\w]+)/i,
      /;\s*(?:SLEEP|DELAY)\s*\(/i
    ];
    this.xssPatterns = [
      /<script\b[^>]*>([\s\S]*?)<\/script>/i,
      /<[^>]+(on\w+)\s*=/i,
      /javascript:/i,
      /<(?:iframe|object|embed|applet)\b/i
    ];
  }

  decodeDeeply(payload) {
    if (typeof payload !== 'string') return '';
    // Prevent ReDoS by capping length
    if (payload.length > 50000) payload = payload.substring(0, 50000);
    
    let decoded = payload;
    try { decoded = decodeURIComponent(decoded); } catch (e) {}
    
    // Attempt basic Base64 decode if it matches base64 chars
    if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(decoded)) {
      try {
        const b64Decoded = Buffer.from(decoded, 'base64').toString('utf8');
        if (b64Decoded.length > 0 && b64Decoded !== decoded) {
          decoded = b64Decoded;
        }
      } catch (e) {}
    }
    return decoded;
  }

  detect(payload) {
    const decodedPayload = this.decodeDeeply(payload);
    
    const sqliScore = this.sqliPatterns.filter(p => p.test(decodedPayload)).length;
    const xssScore = this.xssPatterns.filter(p => p.test(decodedPayload)).length;

    const maxScore = Math.max(sqliScore, xssScore);
    const confidence = Math.min(1.0, maxScore * 0.35); // simple heuristic confidence

    const label = sqliScore > xssScore ? 'sqli' : xssScore > 0 ? 'xss' : 'benign';

    return {
      label,
      confidence,
      scores: {
        sqli: sqliScore,
        xss: xssScore
      }
    };
  }
}
}

function expressMiddleware(options = {}) {
  const detector = new Detector();
  const threshold = options.threshold || 0.5;

  return (req, res, next) => {
    // Check query params, body, and headers
    const sources = [req.query, req.body, req.headers];
    
    for (const source of sources) {
      if (!source) continue;
      for (const key of Object.keys(source)) {
        const val = source[key];
        if (typeof val === 'string') {
          const result = detector.detect(val);
          if (result.label !== 'benign' && result.confidence >= threshold) {
            return res.status(403).json({
              error: 'Forbidden',
              message: 'Malicious payload detected by SQLGuard ML',
              details: { label: result.label }
            });
          }
        }
      }
    }
    next();
  };
}

module.exports = { Detector, expressMiddleware };

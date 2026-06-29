class Detector {
  constructor() {
    this.sqliPatterns = [
      /(?:')|(?:--)|(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|TRUNCATE)\b)/i,
      /(?:\b(OR|AND)\b\s+['"\d\w]+\s*[=<>]\s*['"\d\w]+)/i,
      /;\s*(?:SLEEP|DELAY)\s*\(/i,
      /(?:\$where|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$regex)/i
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
    if (payload.length > 50000) payload = payload.substring(0, 50000);
    let decoded = payload;
    try { decoded = decodeURIComponent(decoded); } catch (e) {}
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
    const confidence = Math.min(1.0, maxScore * 0.35);
    const label = sqliScore > xssScore ? 'sqli' : xssScore > 0 ? 'xss' : 'benign';
    return { label, confidence, scores: { sqli: sqliScore, xss: xssScore } };
  }
}

function expressMiddleware(options = {}) {
  const detector = new Detector();
  const threshold = options.threshold || 0.5;
  const mlEndpoint = options.mlEndpoint || null; 

  const logAttack = (ip, payload, label) => {
    console.warn(`[SQLGuard] Attack Blocked: ${label} from IP: ${ip} | Payload: ${payload}`);
  };

  const deepScan = async (obj, ip) => {
    if (!obj || typeof obj !== 'object') return false;
    for (const key of Object.keys(obj)) {
      const val = obj[key];
      if (typeof val === 'string') {
        const result = detector.detect(val);
        let finalLabel = result.label;
        let isMalicious = result.label !== 'benign' && result.confidence >= threshold;

        if (!isMalicious && result.confidence >= 0.2 && mlEndpoint) {
          try {
            const mlRes = await fetch(mlEndpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ payload: val })
            });
            if (mlRes.ok) {
              const mlData = await mlRes.json();
              if (mlData.prediction && mlData.prediction !== 'benign') {
                isMalicious = true;
                finalLabel = mlData.prediction;
              } else if (mlData.label && mlData.label !== 'benign') {
                isMalicious = true;
                finalLabel = mlData.label;
              }
            }
          } catch (e) {
             console.error("[SQLGuard] ML Bridge error:", e.message);
          }
        }

        if (isMalicious) {
          logAttack(ip, val, finalLabel);
          return { isMalicious: true, label: finalLabel };
        }
      } else if (typeof val === 'object' && val !== null) {
        const nestedResult = await deepScan(val, ip);
        if (nestedResult) return nestedResult;
      }
    }
    return false;
  };

  return async (req, res, next) => {
    const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
    const sources = [req.query, req.body, req.headers];
    
    for (const source of sources) {
      if (!source) continue;
      const attack = await deepScan(source, ip);
      if (attack) {
        return res.status(403).json({
          error: 'Forbidden',
          message: 'Malicious payload detected by SQLGuard ML',
          details: { label: attack.label }
        });
      }
    }
    next();
  };
}

module.exports = { Detector, expressMiddleware };

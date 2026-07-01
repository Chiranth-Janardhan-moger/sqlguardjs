const { IPRateLimiter } = require('./rateLimiter');

class Detector {
  constructor() {
    this.sqliPatterns = [
      // Fixed: Removed bare single quote. Using more robust patterns.
      /(?:\b(?:OR|AND)\b\s+['"\d\w]+\s*[=<>]\s*['"\d\w]+)/i,
      /\b(?:UNION\s+(?:ALL\s+)?SELECT|DROP\s+TABLE|INSERT\s+INTO|UPDATE\s+\w+\s+SET)\b/i,
      /;\s*(?:SLEEP|DELAY|WAITFOR)\s*(?:\(|\s)/i,
      /(?:\$where|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin|\$regex)/i,
      /['"]\s*=\s*['"]/i,
      // Catch comment-terminated auth bypasses (e.g., admin'--, admin' #)
      /(?:['"]\s*(?:--|#)(?:\s|$))/i
    ];
    this.xssPatterns = [
      /<script\b/i,
      /<[^>]+(on\w+)\s*=/i,
      /\bon\w+\s*=\s*["']?[^"'>]*(?:alert|document\.|window\.|eval|fetch)/i,
      /javascript:/i,
      /<(?:iframe|object|embed|applet)\b/i
    ];
  }

  decodeDeeply(payload) {
    if (typeof payload !== 'string') return '';
    if (payload.length > 50000) payload = payload.substring(0, 50000);
    // Iterate decoding to catch multi-layer encoding
    let decoded = payload;
    let previous = "";
    let iterations = 0;
    while (decoded !== previous && iterations < 5) {
      previous = decoded;
      try { decoded = decodeURIComponent(decoded); } catch (e) {}
      iterations++;
    }
    if (/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(decoded)) {
      try {
        const b64Decoded = Buffer.from(decoded, 'base64').toString('utf8');
        if (b64Decoded.length > 0 && b64Decoded !== decoded) {
          decoded = b64Decoded;
        }
      } catch (e) {}
    }
    // Remove SQL inline comments (e.g. /**/) to prevent UN/**/ION bypasses
    decoded = decoded.replace(/\/\*[\s\S]*?\*\//g, '');
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
  const rateLimiter = new IPRateLimiter(options.rateLimitWindowMs || 300000, options.maxRateLimitCapacity || 10000);
  const maxSuspiciousRequests = options.maxSuspiciousRequests || 3;

  const logAttack = (ip, payload, label) => {
    console.warn(`[SQLGuard] Attack Blocked: ${label} from IP: ${ip} | Payload: ${payload}`);
  };

  return async (req, res, next) => {
    const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
    // BUG FIX 1: Scan params and cookies too!
    const sources = [req.query, req.body, req.headers, req.params, req.cookies];
    
    // BUG FIX 3: Prevent ML-driven Resource Exhaustion DoS
    let mlCallCount = 0;
    const MAX_ML_CALLS = 10;

    const scanString = async (str) => {
      const result = detector.detect(str);
      let finalLabel = result.label;
      let isMalicious = result.label !== 'benign' && result.confidence >= threshold;

      if (!isMalicious && result.confidence >= 0.2) {
        const suspiciousCount = rateLimiter.recordSuspicious(ip);
        if (suspiciousCount >= maxSuspiciousRequests) {
           isMalicious = true;
           finalLabel = "rate_limit_escalation";
           console.warn(`[SQLGuard] IP ${ip} blocked due to repeated ambiguous probes.`);
        } else if (mlEndpoint) {
          if (mlCallCount >= MAX_ML_CALLS) {
             // Fallback to strict heuristic if attacker is spamming borderline payloads
             isMalicious = true; 
             finalLabel = "rate_limit_sqli_heuristic";
          } else {
            mlCallCount++;
            try {
              const mlRes = await fetch(mlEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: str })
              });
              if (mlRes.ok) {
                const mlData = await mlRes.json();
                if (mlData.label && mlData.label !== 'benign') {
                  isMalicious = true;
                  finalLabel = mlData.label;
                }
              }
            } catch (e) {
               console.error("[SQLGuard] ML Bridge error:", e.message);
            }
          }
        }
      }

      if (isMalicious) {
        logAttack(ip, str, finalLabel);
        return { isMalicious: true, label: finalLabel };
      }
      return false;
    };

    // BUG FIX 2: Add Depth Limit to prevent Stack Overflow DoS
    const deepScan = async (obj, currentDepth = 0) => {
      if (!obj || typeof obj !== 'object') return false;
      if (currentDepth > 20) {
         logAttack(ip, "[JSON Depth Exceeded]", "dos");
         return { isMalicious: true, label: 'dos' };
      }

      for (const [key, val] of Object.entries(obj)) {
        const keyAttack = await scanString(key);
        if (keyAttack) return keyAttack;

        if (typeof val === 'string') {
          const valAttack = await scanString(val);
          if (valAttack) return valAttack;
        } else if (Buffer.isBuffer(val)) {
          const valAttack = await scanString(val.toString('utf8'));
          if (valAttack) return valAttack;
        } else if (typeof val === 'object' && val !== null) {
          const nestedAttack = await deepScan(val, currentDepth + 1);
          if (nestedAttack) return nestedAttack;
        }
      }
      return false;
    };

    for (const source of sources) {
      if (!source) continue;
      
      let attack = false;
      if (Buffer.isBuffer(source)) {
         attack = await scanString(source.toString('utf8'));
      } else if (typeof source === 'string') {
         attack = await scanString(source);
      } else if (typeof source === 'object') {
         attack = await deepScan(source);
      }

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

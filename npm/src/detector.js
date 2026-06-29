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

  detect(payload) {
    const decodedPayload = decodeURIComponent(payload);
    
    let sqliScore = 0;
    for (const p of this.sqliPatterns) {
      if (p.test(decodedPayload)) {
        sqliScore += 1;
      }
    }

    let xssScore = 0;
    for (const p of this.xssPatterns) {
      if (p.test(decodedPayload)) {
        xssScore += 1;
      }
    }

    const maxScore = Math.max(sqliScore, xssScore);
    const confidence = Math.min(1.0, maxScore * 0.35); // simple heuristic confidence

    let label = 'benign';
    if (sqliScore > xssScore && sqliScore > 0) {
      label = 'sqli';
    } else if (xssScore >= sqliScore && xssScore > 0) {
      label = 'xss';
    }

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

module.exports = { Detector };

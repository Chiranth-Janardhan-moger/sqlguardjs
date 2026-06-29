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

module.exports = { Detector };

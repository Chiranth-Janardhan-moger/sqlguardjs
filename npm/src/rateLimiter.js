class IPRateLimiter {
  constructor(windowMs = 300000, maxCapacity = 10000, maxEventsPerKey = 1000) {
    this.windowMs = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 300000;
    this.maxCapacity = Number.isFinite(maxCapacity) && maxCapacity > 0 ? maxCapacity : 10000;
    this.maxEventsPerKey = Number.isFinite(maxEventsPerKey) && maxEventsPerKey > 0 ? maxEventsPerKey : 1000;
    this.ips = new Map();
  }

  pruneExpired(now) {
    for (const [ip, timestamps] of this.ips) {
      const validTimestamps = timestamps.filter(t => now - t < this.windowMs);
      if (validTimestamps.length === 0) {
        this.ips.delete(ip);
      } else {
        this.ips.set(ip, validTimestamps);
      }
    }
  }
  
  recordSuspicious(ip) {
    const now = Date.now();
    if (!this.ips.has(ip)) {
      if (this.ips.size >= this.maxCapacity) {
        this.pruneExpired(now);
      }
      if (this.ips.size >= this.maxCapacity) {
        this.ips.delete(this.ips.keys().next().value);
      }
      this.ips.set(ip, []);
    }
    const timestamps = this.ips.get(ip);
    
    // Cleanup old timestamps for this IP
    const validTimestamps = timestamps.filter(t => now - t < this.windowMs);
    validTimestamps.push(now);
    if (validTimestamps.length > this.maxEventsPerKey) {
      validTimestamps.splice(0, validTimestamps.length - this.maxEventsPerKey);
    }
    this.ips.delete(ip);
    this.ips.set(ip, validTimestamps);
    return validTimestamps.length;
  }

}

module.exports = { IPRateLimiter };

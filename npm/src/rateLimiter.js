class IPRateLimiter {
  constructor(windowMs = 300000, maxCapacity = 10000) {
    this.windowMs = windowMs;
    this.maxCapacity = maxCapacity;
    this.ips = new Map();
  }
  
  recordSuspicious(ip) {
    const now = Date.now();
    if (!this.ips.has(ip)) {
      if (this.ips.size >= this.maxCapacity) {
        // Simple cleanup: remove oldest 10%
        const keysToDelete = Array.from(this.ips.keys()).slice(0, Math.floor(this.maxCapacity / 10));
        keysToDelete.forEach(k => this.ips.delete(k));
      }
      this.ips.set(ip, []);
    }
    const timestamps = this.ips.get(ip);
    timestamps.push(now);
    
    // Cleanup old timestamps for this IP
    const validTimestamps = timestamps.filter(t => now - t < this.windowMs);
    this.ips.set(ip, validTimestamps);
    return validTimestamps.length;
  }
  
  getCount(ip) {
    if (!this.ips.has(ip)) return 0;
    const now = Date.now();
    const timestamps = this.ips.get(ip);
    const validTimestamps = timestamps.filter(t => now - t < this.windowMs);
    this.ips.set(ip, validTimestamps);
    return validTimestamps.length;
  }
}

module.exports = { IPRateLimiter };

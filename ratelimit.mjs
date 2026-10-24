// Token bucket: `rate` tokens/sec refill, `burst` capacity.
export class TokenBucket {
  constructor(rate, burst = rate){ this.rate = rate; this.burst = burst; this.tokens = burst; this.t = Date.now(); }
  take(n = 1){
    const now = Date.now();
    this.tokens = Math.min(this.burst, this.tokens + ((now - this.t) / 1000) * this.rate); this.t = now;
    if (this.tokens < n) return false;
    this.tokens -= n; return true;
  }
}
// Keyed buckets with bounded memory (oldest keys evicted).
export class KeyedLimiter {
  constructor(rate, burst, maxKeys = 10_000){ this.rate = rate; this.burst = burst; this.maxKeys = maxKeys; this.m = new Map(); }
  take(key, n = 1){
    let b = this.m.get(key);
    if (!b){ if (this.m.size >= this.maxKeys) this.m.delete(this.m.keys().next().value); b = new TokenBucket(this.rate, this.burst); this.m.set(key, b); }
    return b.take(n);
  }
}

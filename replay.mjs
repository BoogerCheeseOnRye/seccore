// Bounded, persisted replay/dedupe set. Envelopes older than the relay age window are rejected
// by timestamp anyway, so ids only need to be remembered for that window (x2 for clock skew).
import fs from 'node:fs';

export class ReplayStore {
  constructor({ file, windowMs = 600_000, max = 50_000, flushMs = 500 } = {}){
    this.file = file; this.windowMs = windowMs; this.max = max; this.flushMs = flushMs; this.m = new Map();
    if (file && fs.existsSync(file)){
      try {
        const now = Date.now(), o = JSON.parse(fs.readFileSync(file, 'utf8'));
        for (const [id, ts] of Object.entries(o)) if (typeof ts === 'number' && now - ts < windowMs && /^[0-9a-f]{32}$/.test(id)) this.m.set(id, ts);
      } catch { /* corrupt file: start empty (timestamps still bound replay to the window) */ }
    }
  }
  // true if new (and records it), false if seen.
  add(id, now = Date.now()){
    if (this.m.has(id)) return false;
    if (this.m.size >= this.max) this._prune(now, true);
    this.m.set(id, now); this._dirty();
    return true;
  }
  has(id){ return this.m.has(id); }
  _prune(now, force){
    // Map keeps insertion (= time) order, so the oldest go first.
    for (const [k, t] of this.m){
      if (now - t > this.windowMs || (force && this.m.size >= this.max)) this.m.delete(k); else break;
    }
  }
  _dirty(){ if (!this.file || this.t) return; this.t = setTimeout(() => { this.t = null; this.flush(); }, this.flushMs); this.t.unref?.(); }
  flush(){
    if (!this.file) return;
    clearTimeout(this.t); this.t = null;
    this._prune(Date.now(), false);
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.m)), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }
}

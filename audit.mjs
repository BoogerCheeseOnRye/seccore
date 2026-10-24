// Tamper-evident append-only audit log (JSONL). Each entry carries seq, prev (hash of the previous
// entry) and hash = SHA-256(prev ‖ canonical entry). With a key, mac = HMAC(key, hash) so an attacker
// who can edit the file but lacks the key can't rebuild a valid chain.
import crypto from 'node:crypto';
import fs from 'node:fs';

const GENESIS = '0'.repeat(64);
const canon = (o) => JSON.stringify(Object.keys(o).sort().reduce((a, k) => { a[k] = o[k]; return a; }, {}));

export class AuditLog {
  constructor(file, { key } = {}){
    this.file = file; this.key = key; this.prev = GENESIS; this.seq = 0;
    if (fs.existsSync(file)){
      const lines = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
      if (lines.length){ const last = JSON.parse(lines[lines.length - 1]); this.prev = last.hash; this.seq = last.seq + 1; }
    }
  }
  append(event){
    const e = { seq: this.seq, ts: new Date().toISOString(), prev: this.prev, ...event };
    const hash = crypto.createHash('sha256').update(this.prev + '|' + canon(e)).digest('hex');
    const line = { ...e, hash, ...(this.key ? { mac: crypto.createHmac('sha256', this.key).update(hash).digest('hex') } : {}) };
    fs.appendFileSync(this.file, JSON.stringify(line) + '\n', { mode: 0o600 });
    this.prev = hash; this.seq++;
    return line;
  }
}
export function verifyAudit(file, { key } = {}){
  if (!fs.existsSync(file)) return { ok: true, entries: 0 };
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++){
    let o; try { o = JSON.parse(lines[i]); } catch { return { ok: false, entries: lines.length, brokenAt: i, reason: 'unparseable line' }; }
    const { hash, mac, ...e } = o;
    if (e.seq !== i || e.prev !== prev) return { ok: false, entries: lines.length, brokenAt: i, reason: 'chain broken (deleted/reordered entry)' };
    const want = crypto.createHash('sha256').update(prev + '|' + canon(e)).digest('hex');
    if (want !== hash) return { ok: false, entries: lines.length, brokenAt: i, reason: 'entry modified' };
    if (key){
      const m = crypto.createHmac('sha256', key).update(hash).digest();
      if (typeof mac !== 'string' || mac.length !== 64 || !crypto.timingSafeEqual(m, Buffer.from(mac, 'hex'))) return { ok: false, entries: lines.length, brokenAt: i, reason: 'bad mac' };
    }
    prev = hash;
  }
  return { ok: true, entries: lines.length, head: prev };
}
// Per-node audit key derived from the identity (so only this device can extend/verify the MAC chain).
export function auditKey(identity){
  const seed = Buffer.from(identity.privateKey.export({ format: 'jwk' }).d, 'base64url');
  return Buffer.from(crypto.hkdfSync('sha256', seed, Buffer.from('seccore-audit'), Buffer.from('seccore-audit v1'), 32));
}

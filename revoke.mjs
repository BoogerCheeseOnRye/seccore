// Signed revocation notices. A notice for `target` is applied when it carries a valid signature by
//  - the target itself (self-revoke, e.g. "this phone was stolen" from a backup of its key), or
//  - any configured admin fingerprint, or
//  - at least `quorum` distinct currently-trusted mesh peers (co-signatures merge as the notice gossips).
// Applied revocations are persisted and permanent (re-pair with a fresh key to come back).
import crypto from 'node:crypto';
import fs from 'node:fs';
import * as sc from './seccore.mjs';

const FP_RE = /^[0-9a-f]{4}(:[0-9a-f]{4}){9}$/;
const msg = (target) => Buffer.from('seccore-revoke v1|' + target);

export function signRevocation(identity, target, reason = ''){
  if (!FP_RE.test(target)) throw new Error('bad target fingerprint');
  return { target, reason: String(reason).slice(0, 200), sigs: [{ ed: Buffer.from(identity.raw).toString('base64'), sig: crypto.sign(null, msg(target), identity.privateKey).toString('base64') }] };
}
function validSigners(n){
  const out = new Map();
  for (const s of (Array.isArray(n.sigs) ? n.sigs : []).slice(0, 64)){
    try {
      const ed = Buffer.from(String(s.ed), 'base64');
      if (crypto.verify(null, msg(n.target), sc.edPubFromRaw(ed), Buffer.from(String(s.sig), 'base64'))) out.set(sc.fingerprint(ed), s);
    } catch {}
  }
  return out;
}

export class RevocationStore {
  constructor({ file, admins = [], quorum = 0 } = {}){
    this.file = file; this.admins = new Set(admins); this.quorum = quorum;
    this.revoked = new Map(); this.partial = new Map();
    if (file && fs.existsSync(file)){
      for (const n of JSON.parse(fs.readFileSync(file, 'utf8'))) if (this._decide(n, validSigners(n), null)) this.revoked.set(n.target, n);
    }
  }
  has(fp){ return this.revoked.has(fp); }
  _decide(n, signers, trusted){
    if (signers.has(n.target)) return 'self';
    for (const f of signers.keys()) if (this.admins.has(f)) return 'admin';
    if (this.quorum > 0 && trusted){ let k = 0; for (const f of signers.keys()) if (trusted.has(f) && f !== n.target) k++; if (k >= this.quorum) return 'quorum'; }
    // Notices persisted on disk were already decided; accept them on reload if they still verify.
    if (trusted === null && signers.size) return 'persisted';
    return null;
  }
  // Returns { status: 'applied'|'pending'|'known'|'invalid', notice }
  add(notice, trusted){
    if (!notice || typeof notice.target !== 'string' || !FP_RE.test(notice.target)) return { status: 'invalid' };
    if (this.revoked.has(notice.target)) return { status: 'known', notice: this.revoked.get(notice.target) };
    const prev = this.partial.get(notice.target);
    const merged = { target: notice.target, reason: String(prev?.reason || notice.reason || '').slice(0, 200), sigs: [...(prev?.sigs || []), ...(Array.isArray(notice.sigs) ? notice.sigs : [])] };
    const signers = validSigners(merged);
    if (!signers.size) return { status: 'invalid' };
    merged.sigs = [...signers.values()];
    const why = this._decide(merged, signers, trusted);
    if (why){
      merged.why = why; this.revoked.set(merged.target, merged); this.partial.delete(merged.target); this._save();
      return { status: 'applied', notice: merged };
    }
    const grew = !prev || merged.sigs.length > prev.sigs.length;
    if (this.partial.size < 1000 || prev) this.partial.set(merged.target, merged);
    return { status: grew ? 'pending' : 'known', notice: merged };
  }
  all(){ return [...this.revoked.values(), ...this.partial.values()]; }
  _save(){ if (this.file) fs.writeFileSync(this.file, JSON.stringify([...this.revoked.values()], null, 1), { mode: 0o600 }); }
}

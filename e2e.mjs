// End-to-end sealed envelopes for multi-hop relay, with forward secrecy.
//
// Each node publishes a signed *node record*: { ed, seq, ts, pk: {id, x, kem, exp}, nbrs }.
//  - pk is a medium-term prekey (X25519 + ML-KEM-768) that rotates (default hourly). Its private
//    halves live only in memory and are destroyed after a short grace window, so a later theft of
//    the device (identity key included) cannot decrypt envelopes captured earlier.
//  - nbrs lists the node's directly-connected trusted peers (link-state routing input).
// Envelopes: ephemeral X25519 ⊕ ML-KEM encapsulation to the recipient prekey → HKDF → ChaCha20-Poly1305,
// header as AAD, the whole thing signed by the sender's Ed25519 identity.
import crypto from 'node:crypto';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import * as sc from './seccore.mjs';

const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s, max = 1 << 16) => { if (typeof s !== 'string' || s.length > max) throw new Error('bad field'); return Buffer.from(s, 'base64'); };
const FP_RE = /^[0-9a-f]{4}(:[0-9a-f]{4}){9}$/;
export const KEM_EK_LEN = 1184, KEM_CT_LEN = 1088;

function xPub(raw){
  if (raw.length !== 32) throw new Error('bad x25519 key');
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') }, format: 'jwk' });
}

// ── rotating prekeys (memory only) ────────────────────────────────────────
export class PrekeyStore {
  constructor({ rotateMs = 3600_000, keep = 2 } = {}){ this.rotateMs = rotateMs; this.keep = keep; this.keys = []; this.rotate(); }
  rotate(){
    const x = crypto.generateKeyPairSync('x25519'), kem = ml_kem768.keygen();
    const k = { id: crypto.randomBytes(8).toString('hex'), xPriv: x.privateKey, xRaw: sc.rawPub(x.publicKey), kemSk: kem.secretKey, kemEk: Buffer.from(kem.publicKey), created: Date.now() };
    this.keys.unshift(k);
    while (this.keys.length > 1 + this.keep) this._destroy(this.keys.pop());
    return k;
  }
  _destroy(k){ k.kemSk.fill(0); k.xPriv = null; k.kemSk = null; }
  current(){ return this.keys[0]; }
  get(id){ return this.keys.find((k) => k.id === id && k.kemSk); }
  destroyAll(){ for (const k of this.keys) this._destroy(k); this.keys = []; }
  publicInfo(){ const k = this.current(); return { id: k.id, x: b64(k.xRaw), kem: b64(k.kemEk), exp: k.created + this.rotateMs * (1 + this.keep) }; }
}

// ── signed node records ──────────────────────────────────────────────────
export function makeRecord(identity, { seq, prekey, nbrs }){
  const body = JSON.stringify({ v: 2, ed: b64(identity.raw), seq, ts: Date.now(), pk: prekey, nbrs: nbrs.slice(0, 64) });
  return { body, sig: b64(crypto.sign(null, Buffer.from('seccore-rec v2|' + body), identity.privateKey)) };
}
export function verifyRecord(rec){
  if (!rec || typeof rec.body !== 'string' || rec.body.length > 8192) throw new Error('bad record');
  const o = JSON.parse(rec.body);
  const ed = unb64(o.ed);
  if (o.v !== 2 || !Number.isSafeInteger(o.seq) || !o.pk || typeof o.pk.id !== 'string' || !/^[0-9a-f]{16}$/.test(o.pk.id)) throw new Error('bad record fields');
  if (!crypto.verify(null, Buffer.from('seccore-rec v2|' + rec.body), sc.edPubFromRaw(ed), unb64(rec.sig))) throw new Error('bad record signature');
  const x = unb64(o.pk.x), kem = unb64(o.pk.kem);
  if (x.length !== 32 || kem.length !== KEM_EK_LEN) throw new Error('bad prekey');
  if (!Array.isArray(o.nbrs) || o.nbrs.length > 64 || !o.nbrs.every((f) => typeof f === 'string' && FP_RE.test(f))) throw new Error('bad nbrs');
  return { fp: sc.fingerprint(ed), ed, seq: o.seq, ts: o.ts, pk: { id: o.pk.id, x, kem, exp: o.pk.exp }, nbrs: o.nbrs, rec };
}

// ── envelopes ─────────────────────────────────────────────────────────────
function sigInput(hdr, eph, kemct, nonce, ct){ return Buffer.concat([Buffer.from('seccore-e2e v2|' + hdr + '|'), eph, kemct, nonce, ct]); }
function kdf(xss, kss, eph, xRecip, kemct){
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.concat([xss, Buffer.from(kss)]), Buffer.concat([eph, xRecip, crypto.createHash('sha256').update(kemct).digest()]), Buffer.from('seccore-e2e v2'), 32));
}
export function seal({ identity, dstFp, prekey, body, id, ts = Date.now() }){
  const hdr = JSON.stringify({ v: 2, id, src: sc.fingerprint(identity.raw), dst: dstFp, pk: prekey.id, ts });
  const eph = crypto.generateKeyPairSync('x25519'), ephRaw = sc.rawPub(eph.publicKey);
  const xss = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: xPub(prekey.x) });
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(prekey.kem);
  const kemct = Buffer.from(cipherText);
  const key = kdf(xss, sharedSecret, ephRaw, prekey.x, kemct);
  const nonce = crypto.randomBytes(12);                  // fresh key per envelope, so nonce reuse is impossible anyway
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(hdr));
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(body))), c.final(), c.getAuthTag()]);
  const sig = crypto.sign(null, sigInput(hdr, ephRaw, kemct, nonce, ct), identity.privateKey);
  return { hdr, srcEd: b64(identity.raw), eph: b64(ephRaw), kct: b64(kemct), nonce: b64(nonce), ct: b64(ct), sig: b64(sig) };
}
export function open(sealed, identity, prekeys){
  if (!sealed || typeof sealed.hdr !== 'string' || sealed.hdr.length > 1024) throw new Error('bad envelope');
  const h = JSON.parse(sealed.hdr);
  const srcEd = unb64(sealed.srcEd), eph = unb64(sealed.eph), kemct = unb64(sealed.kct), nonce = unb64(sealed.nonce), ct = unb64(sealed.ct, 1 << 21);
  if (h.v !== 2 || typeof h.id !== 'string') throw new Error('bad envelope version');
  if (h.dst !== sc.fingerprint(identity.raw)) throw new Error('envelope not for me');
  if (sc.fingerprint(srcEd) !== h.src) throw new Error('sender key/fingerprint mismatch');
  if (eph.length !== 32 || kemct.length !== KEM_CT_LEN || nonce.length !== 12 || ct.length < 16) throw new Error('bad envelope lengths');
  if (!crypto.verify(null, sigInput(sealed.hdr, eph, kemct, nonce, ct), sc.edPubFromRaw(srcEd), unb64(sealed.sig))) throw new Error('bad envelope signature');
  const k = prekeys.get(h.pk);
  if (!k) throw new Error('prekey ' + String(h.pk).slice(0, 16) + ' unknown or already destroyed (forward secrecy)');
  const xss = crypto.diffieHellman({ privateKey: k.xPriv, publicKey: xPub(eph) });
  const kss = ml_kem768.decapsulate(kemct, k.kemSk);
  const key = kdf(xss, kss, eph, k.xRaw, kemct);
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAAD(Buffer.from(sealed.hdr)); d.setAuthTag(ct.subarray(ct.length - 16));
  const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  return { id: h.id, src: h.src, ts: h.ts, body: JSON.parse(pt.toString()) };
}

// ── link-state routing ───────────────────────────────────────────────────
// Edge a–b counts only if BOTH signed records list each other (one forged claim can't create a path).
export function nextHop(selfFp, myNbrs, records, dstFp, maxNodes = 1000){
  const adj = (fp) => {
    if (fp === selfFp) return myNbrs;
    const r = records.get(fp); if (!r) return [];
    return r.nbrs.filter((n) => n === selfFp ? myNbrs.includes(fp) : records.get(n)?.nbrs.includes(fp));
  };
  const prev = new Map([[selfFp, null]]), q = [selfFp];
  while (q.length && prev.size <= maxNodes){
    const u = q.shift();
    if (u === dstFp) break;
    for (const v of adj(u)) if (!prev.has(v)){ prev.set(v, u); q.push(v); }
  }
  if (!prev.has(dstFp) || dstFp === selfFp) return null;
  let cur = dstFp; while (prev.get(cur) !== selfFp) cur = prev.get(cur);
  return cur;
}

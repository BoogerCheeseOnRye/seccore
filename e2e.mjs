// End-to-end sealed envelopes for multi-hop relay. Relays see only routing metadata.
// Each node has a static X25519 "box" key derived from its Ed25519 identity and published
// in a self-signed announcement, so anyone who knows a node's fingerprint can verify its box key.
import crypto from 'node:crypto';
import * as sc from './seccore.mjs';

const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => { if (typeof s !== 'string') throw new Error('bad field'); return Buffer.from(s, 'base64'); };

export function boxKeyFromIdentity(identity){
  const seed = Buffer.from(identity.privateKey.export({ format: 'jwk' }).d, 'base64url');
  const xs = Buffer.from(crypto.hkdfSync('sha256', seed, Buffer.from('seccore-box-salt'), Buffer.from('seccore-box v1'), 32));
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, xs]), format: 'der', type: 'pkcs8' });
  return { privateKey, raw: sc.rawPub(crypto.createPublicKey(privateKey)) };
}
function xPub(raw){
  if (raw.length !== 32) throw new Error('bad x25519 key');
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') }, format: 'jwk' });
}
export function makeAnnouncement(identity, box){
  const sig = crypto.sign(null, Buffer.concat([Buffer.from('seccore-ann v1|'), box.raw]), identity.privateKey);
  return { ed: b64(identity.raw), x: b64(box.raw), sig: b64(sig) };
}
export function verifyAnnouncement(ann){
  const ed = unb64(ann?.ed), x = unb64(ann?.x);
  if (!crypto.verify(null, Buffer.concat([Buffer.from('seccore-ann v1|'), x]), sc.edPubFromRaw(ed), unb64(ann.sig))) throw new Error('bad announcement signature');
  if (x.length !== 32) throw new Error('bad box key');
  return { fp: sc.fingerprint(ed), ed, x };
}

export function seal({ identity, dstFp, dstX, body, id, ts = Date.now() }){
  const hdr = JSON.stringify({ v: 1, id, src: sc.fingerprint(identity.raw), dst: dstFp, ts });
  const eph = crypto.generateKeyPairSync('x25519'), ephRaw = sc.rawPub(eph.publicKey);
  const ss = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: xPub(dstX) });
  const key = Buffer.from(crypto.hkdfSync('sha256', ss, Buffer.concat([ephRaw, dstX]), Buffer.from('seccore-e2e v1'), 32));
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(hdr));
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(body))), c.final(), c.getAuthTag()]);
  const sig = crypto.sign(null, sigInput(hdr, ephRaw, nonce, ct), identity.privateKey);
  return { hdr, srcEd: b64(identity.raw), eph: b64(ephRaw), nonce: b64(nonce), ct: b64(ct), sig: b64(sig) };
}
function sigInput(hdr, eph, nonce, ct){ return Buffer.concat([Buffer.from('seccore-e2e v1|' + hdr + '|'), eph, nonce, ct]); }

export function open(sealed, identity, box){
  const h = JSON.parse(sealed.hdr);
  const srcEd = unb64(sealed.srcEd), eph = unb64(sealed.eph), nonce = unb64(sealed.nonce), ct = unb64(sealed.ct);
  if (h.v !== 1) throw new Error('bad envelope version');
  if (h.dst !== sc.fingerprint(identity.raw)) throw new Error('envelope not for me');
  if (sc.fingerprint(srcEd) !== h.src) throw new Error('sender key/fingerprint mismatch');
  if (!crypto.verify(null, sigInput(sealed.hdr, eph, nonce, ct), sc.edPubFromRaw(srcEd), unb64(sealed.sig))) throw new Error('bad envelope signature');
  if (nonce.length !== 12 || ct.length < 16) throw new Error('bad envelope');
  const ss = crypto.diffieHellman({ privateKey: box.privateKey, publicKey: xPub(eph) });
  const key = Buffer.from(crypto.hkdfSync('sha256', ss, Buffer.concat([eph, box.raw]), Buffer.from('seccore-e2e v1'), 32));
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAAD(Buffer.from(sealed.hdr)); d.setAuthTag(ct.subarray(ct.length - 16));
  const pt = Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
  return { id: h.id, src: h.src, ts: h.ts, body: JSON.parse(pt.toString()) };
}

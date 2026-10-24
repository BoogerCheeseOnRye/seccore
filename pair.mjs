// Pairing bundles: a compact, copy/paste/QR-friendly string with a node's name, fingerprint
// and (optionally) address. It contains NO secrets: never the canary secret or private keys.
// Authenticity comes from comparing the short pairing code on both screens.
import crypto from 'node:crypto';

const PREFIX = 'SECCORE1:';
const FP_RE = /^[0-9a-f]{4}(:[0-9a-f]{4}){9}$/;

export function makeBundle({ name, fingerprint, host, port }){
  const o = { n: name, f: fingerprint };
  if (host && host !== '127.0.0.1' && host !== '0.0.0.0' && port) Object.assign(o, { h: host, p: port });
  const body = Buffer.from(JSON.stringify(o)).toString('base64url');
  const ck = crypto.createHash('sha256').update(body).digest('base64url').slice(0, 6);
  return PREFIX + body + '.' + ck;
}
export function parseBundle(s){
  s = String(s).trim();
  if (!s.startsWith(PREFIX)) throw new Error('not a seccore pairing bundle');
  const [body, ck] = s.slice(PREFIX.length).split('.');
  if (crypto.createHash('sha256').update(body).digest('base64url').slice(0, 6) !== ck) throw new Error('bundle checksum mismatch (typo or truncated)');
  const o = JSON.parse(Buffer.from(body, 'base64url').toString());
  if (typeof o.n !== 'string' || !/^[a-zA-Z0-9_.-]{1,32}$/.test(o.n)) throw new Error('bad name in bundle');
  if (!FP_RE.test(o.f)) throw new Error('bad fingerprint in bundle');
  if (o.h != null && (typeof o.h !== 'string' || !/^[a-zA-Z0-9.:-]{1,253}$/.test(o.h) || !Number.isInteger(o.p) || o.p < 1 || o.p > 65535)) throw new Error('bad address in bundle');
  return { name: o.n, fingerprint: o.f, ...(o.h ? { host: o.h, port: o.p } : {}) };
}
// Short authentication string over BOTH fingerprints: identical on both devices iff each
// imported the other's genuine key. 6 digits = 1-in-a-million chance for a swapped bundle to match.
export function pairingCode(fpA, fpB){
  const [x, y] = [fpA, fpB].sort();
  const n = crypto.createHash('sha256').update('seccore-sas v1|' + x + '|' + y).digest().readUInt32BE(0) % 1_000_000;
  return String(n).padStart(6, '0').replace(/(\d{3})(\d{3})/, '$1-$2');
}

// Android Keystore unlock via Termux:API `termux-keystore`.
// The passphrase is wrapped with a key derived from an RSA PKCS#1 v1.5 signature (deterministic)
// made by a non-exportable hardware-backed key. The wrapped file alone is useless off-device;
// unwrapping needs this app's keystore key on this device.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

export const ALIAS = 'seccore-unlock';
const bin = () => process.env.SECCORE_KEYSTORE_BIN || 'termux-keystore';
function run(args, input){
  const r = spawnSync(bin(), args, { input, timeout: 20_000, maxBuffer: 1 << 20 });
  if (r.error) throw new Error('termux-keystore unavailable: ' + r.error.message);
  if (r.status !== 0) throw new Error('termux-keystore ' + args[0] + ' failed: ' + String(r.stderr || r.stdout).slice(0, 200));
  return r.stdout;
}
export function available(){ try { run(['list']); return true; } catch { return false; } }
function sign(alias, data){
  const s = run(['sign', alias, 'SHA256withRSA'], data);
  if (s.length < 256) throw new Error('keystore signature too short');
  return s;
}
function deriveKey(alias, challenge){
  const s1 = sign(alias, challenge), s2 = sign(alias, challenge);
  if (!s1.equals(s2)) throw new Error('keystore signature not deterministic (need an RSA key)');
  return Buffer.from(crypto.hkdfSync('sha256', s1, challenge, Buffer.from('seccore-keystore-wrap v1'), 32));
}
export function wrap(passphrase, file, { alias = ALIAS } = {}){
  const list = run(['list']).toString();
  if (!list.includes(alias)) run(['generate', alias, '-a', 'RSA', '-s', '2048']);
  const challenge = crypto.randomBytes(32), nonce = crypto.randomBytes(12);
  const key = deriveKey(alias, challenge);
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(alias));
  const ct = Buffer.concat([c.update(Buffer.from(passphrase)), c.final(), c.getAuthTag()]);
  fs.writeFileSync(file, JSON.stringify({ v: 1, alias, challenge: challenge.toString('base64'), nonce: nonce.toString('base64'), ct: ct.toString('base64') }), { mode: 0o600 });
}
export function unwrap(file){
  const o = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (o.v !== 1 || typeof o.alias !== 'string') throw new Error('bad keystore file');
  const key = deriveKey(o.alias, Buffer.from(o.challenge, 'base64'));
  const ct = Buffer.from(o.ct, 'base64');
  const d = crypto.createDecipheriv('chacha20-poly1305', key, Buffer.from(o.nonce, 'base64'), { authTagLength: 16 });
  d.setAAD(Buffer.from(o.alias)); d.setAuthTag(ct.subarray(ct.length - 16));
  try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]).toString(); }
  catch { throw new Error('keystore unwrap failed (different device/key?)'); }
}

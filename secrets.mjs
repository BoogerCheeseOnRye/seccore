// Passphrase-encrypted secrets at rest: scrypt(passphrase, salt) -> key, ChaCha20-Poly1305.
import crypto from 'node:crypto';
import fs from 'node:fs';

export const KDF_DEFAULT = { N: 1 << 15, r: 8, p: 1 };   // ~32 MiB RAM, fine on phones

export function seal(plaintext, passphrase, kdf = KDF_DEFAULT, label = 'seccore-secret'){
  if (!passphrase) throw new Error('passphrase required');
  const salt = crypto.randomBytes(16), nonce = crypto.randomBytes(12);
  const key = crypto.scryptSync(String(passphrase).normalize('NFKC'), salt, 32, { ...kdf, maxmem: 256 * kdf.N * kdf.r + 1024 * 1024 });
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(Buffer.from(label));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final(), c.getAuthTag()]);
  return { v: 1, kdf: 'scrypt', ...kdf, label, salt: salt.toString('base64'), nonce: nonce.toString('base64'), ct: ct.toString('base64') };
}

export function open(box, passphrase){
  if (!box || box.v !== 1 || box.kdf !== 'scrypt') throw new Error('unsupported secret box');
  if (!passphrase) throw new Error('locked: passphrase required (set SECCORE_PASSPHRASE or run interactively)');
  const salt = Buffer.from(box.salt, 'base64'), nonce = Buffer.from(box.nonce, 'base64'), ct = Buffer.from(box.ct, 'base64');
  const kdf = { N: box.N, r: box.r, p: box.p };
  if (!(kdf.N >= 1024 && kdf.N <= 1 << 20 && kdf.r <= 32 && kdf.p <= 16)) throw new Error('kdf params out of range');
  const key = crypto.scryptSync(String(passphrase).normalize('NFKC'), salt, 32, { ...kdf, maxmem: 256 * kdf.N * kdf.r + 1024 * 1024 });
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  d.setAAD(Buffer.from(box.label || 'seccore-secret')); d.setAuthTag(ct.subarray(ct.length - 16));
  try { return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]); }
  catch { throw new Error('wrong passphrase or corrupted secret'); }
}

// Overwrite then unlink (best effort; flash storage may keep old blocks — use device encryption too).
export function shred(file){
  try { const n = fs.statSync(file).size; fs.writeFileSync(file, crypto.randomBytes(n)); } catch {}
  try { fs.unlinkSync(file); } catch {}
}

// Read a passphrase: env first, then a hidden TTY prompt.
export async function getPassphrase(prompt = 'seccore passphrase: ', { confirm = false } = {}){
  if (process.env.SECCORE_PASSPHRASE) return process.env.SECCORE_PASSPHRASE;
  if (!process.stdin.isTTY) return null;
  const ask = (q) => new Promise((resolve) => {
    process.stderr.write(q);
    const stdin = process.stdin; let s = '';
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const on = (ch) => {
      if (ch === '\r' || ch === '\n' || ch === '\u0004'){ stdin.setRawMode(false); stdin.pause(); stdin.off('data', on); process.stderr.write('\n'); resolve(s); }
      else if (ch === '\u0003'){ process.stderr.write('\n'); process.exit(130); }
      else if (ch === '\u007f'){ s = s.slice(0, -1); }
      else s += ch;
    };
    stdin.on('data', on);
  });
  const p = await ask(prompt);
  if (confirm && (await ask('again: ')) !== p) throw new Error('passphrases differ');
  return p;
}

// seccore — authenticated, encrypted peer-to-peer channel over TCP.
// Primitives: Ed25519 identities, X25519 + ML-KEM-768 hybrid key exchange,
// HKDF-SHA256 with transcript binding, ChaCha20-Poly1305 framed transport.
// All randomness comes from the OS CSPRNG (node:crypto / WebCrypto). No Math.random.
import crypto from 'node:crypto';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { EventEmitter } from 'node:events';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import * as secrets from './secrets.mjs';

export const VERSION = 'seccore-v1';
const MAX_FRAME = 1 << 20;            // 1 MiB
const HS_TIMEOUT_MS = 10_000;
export const DEFAULTS = { rekeyMessages: 1 << 20, rekeyBytes: 1 << 30 };
const T_DATA = 1, T_REKEY = 2, T_CONFIRM = 3;

const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => { if (typeof s !== 'string') throw new Error('bad field'); return Buffer.from(s, 'base64'); };
const sha256 = (...parts) => { const h = crypto.createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
const hkdf = (ikm, salt, info, len = 32) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info), len));

// ── identities ────────────────────────────────────────────────────────────
export function defaultDir(){ return process.env.SECCORE_HOME || path.join(os.homedir(), '.seccore'); }
export function rawPub(pubKey){ return Buffer.from(pubKey.export({ format: 'jwk' }).x, 'base64url'); }
export function edPubFromRaw(raw){
  if (raw.length !== 32) throw new Error('bad ed25519 key');
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(raw).toString('base64url') }, format: 'jwk' });
}
export function fingerprint(raw){
  return sha256(Buffer.from('seccore-fp'), raw).subarray(0, 20).toString('hex').match(/.{4}/g).join(':');
}
export function generateIdentity(){
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKey, raw: rawPub(publicKey) };
}
export function saveIdentity(id, dir = defaultDir()){
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const f = path.join(dir, 'identity.pem');
  fs.writeFileSync(f, id.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
  return f;
}
export function saveIdentityEncrypted(id, passphrase, dir = defaultDir(), kdf){
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const f = path.join(dir, 'identity.pem.enc');
  const pem = id.privateKey.export({ type: 'pkcs8', format: 'pem' });
  fs.writeFileSync(f, JSON.stringify(secrets.seal(pem, passphrase, kdf, 'seccore-identity')), { mode: 0o600, flag: 'wx' });
  return f;
}
export function identityIsEncrypted(dir = defaultDir()){ return !fs.existsSync(path.join(dir, 'identity.pem')) && fs.existsSync(path.join(dir, 'identity.pem.enc')); }
// Loads identity.pem, or identity.pem.enc unlocked with `passphrase` (or $SECCORE_PASSPHRASE).
export function loadIdentity(dir = defaultDir(), passphrase = process.env.SECCORE_PASSPHRASE){
  const enc = path.join(dir, 'identity.pem.enc');
  const pem = fs.existsSync(path.join(dir, 'identity.pem')) ? fs.readFileSync(path.join(dir, 'identity.pem'))
    : fs.existsSync(enc) ? secrets.open(JSON.parse(fs.readFileSync(enc, 'utf8')), passphrase) : fs.readFileSync(path.join(dir, 'identity.pem'));
  const privateKey = crypto.createPrivateKey(pem);
  const publicKey = crypto.createPublicKey(privateKey);
  return { privateKey, publicKey, raw: rawPub(publicKey) };
}

// Pin store: fingerprint -> label. Used for TOFU or pre-shared out-of-band pins.
export class PinStore {
  constructor(file){ this.file = file; this.pins = file && fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {}; }
  has(fp){ return Object.hasOwn(this.pins, fp); }
  add(fp, label = ''){ this.pins[fp] = label; if (this.file) fs.writeFileSync(this.file, JSON.stringify(this.pins, null, 2), { mode: 0o600 }); }
}

// ── framing ───────────────────────────────────────────────────────────────
class FrameReader {
  constructor(sock, onFrame, onError){
    this.buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      while (this.buf.length >= 4){
        const len = this.buf.readUInt32BE(0);
        if (len > MAX_FRAME || len === 0) return onError(new Error('bad frame length'));
        if (this.buf.length < 4 + len) break;
        const f = this.buf.subarray(4, 4 + len); this.buf = this.buf.subarray(4 + len);
        try { onFrame(f); } catch (e) { return onError(e); }
      }
    });
  }
}
const frame = (payload) => { const h = Buffer.alloc(4); h.writeUInt32BE(payload.length); return Buffer.concat([h, payload]); };

// ── AEAD direction state ──────────────────────────────────────────────────
class Direction {
  constructor(key){ this.key = key; this.ctr = 0n; this.msgs = 0; this.bytes = 0; }
  nonce(ctr){ const n = Buffer.alloc(12); n.writeBigUInt64BE(ctr, 4); return n; }
  rekey(){ this.key = hkdf(this.key, Buffer.alloc(0), VERSION + ' rekey'); this.ctr = 0n; this.msgs = 0; this.bytes = 0; }
  seal(type, pt){
    if (this.ctr >= 0xffffffffffffffffn) throw new Error('counter exhausted');
    const hdr = Buffer.alloc(9); hdr[0] = type; hdr.writeBigUInt64BE(this.ctr, 1);
    const c = crypto.createCipheriv('chacha20-poly1305', this.key, this.nonce(this.ctr), { authTagLength: 16 });
    c.setAAD(hdr);
    const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
    this.ctr++; this.msgs++; this.bytes += pt.length;
    return Buffer.concat([hdr, ct]);
  }
  open(f){
    if (f.length < 9 + 16) throw new Error('short frame');
    const hdr = f.subarray(0, 9), type = hdr[0], ctr = hdr.readBigUInt64BE(1);
    // TCP is ordered, so the only valid counter is exactly the next one: rejects replay, reorder, drop.
    if (ctr !== this.ctr) throw new Error('replay/reorder detected');
    const d = crypto.createDecipheriv('chacha20-poly1305', this.key, this.nonce(ctr), { authTagLength: 16 });
    d.setAAD(hdr); d.setAuthTag(f.subarray(f.length - 16));
    const pt = Buffer.concat([d.update(f.subarray(9, f.length - 16)), d.final()]); // throws on tamper
    this.ctr++; this.msgs++; this.bytes += pt.length;
    return { type, pt };
  }
}

// ── secure channel ────────────────────────────────────────────────────────
export class SecureChannel extends EventEmitter {
  constructor(sock, sendKey, recvKey, peerRaw, opts){
    super();
    this.sock = sock; this.tx = new Direction(sendKey); this.rx = new Direction(recvKey);
    this.peerKey = peerRaw; this.peerFingerprint = fingerprint(peerRaw);
    this.opts = { ...DEFAULTS, ...opts }; this.closed = false;
  }
  _start(reader){
    reader.onFrame = (f) => {
      let r;
      try { r = this.rx.open(f); } catch (e) { return this.fail(e); }
      if (r.type === T_REKEY) this.rx.rekey();
      else if (r.type === T_DATA) this.emit('message', r.pt);
      else this.fail(new Error('unknown frame type'));
    };
    const queued = reader.q.splice(0); for (const f of queued) reader.onFrame(f);
    this.sock.on('close', () => { this.closed = true; this.emit('close'); });
    this.sock.on('error', (e) => this.fail(e));
  }
  send(data){
    if (this.closed) throw new Error('channel closed');
    const pt = Buffer.from(data);
    this.sock.write(frame(this.tx.seal(T_DATA, pt)));
    if (this.tx.msgs >= this.opts.rekeyMessages || this.tx.bytes >= this.opts.rekeyBytes) this.rekey();
  }
  rekey(){ this.sock.write(frame(this.tx.seal(T_REKEY, Buffer.alloc(0)))); this.tx.rekey(); this.emit('rekey'); }
  fail(err){ if (this.closed) return; this.closed = true; this.emit('error', err); this.sock.destroy(); }
  close(){ this.closed = true; this.sock.end(); }
}

// Handshake (client = initiator I, server = responder R):
//  1. I→R  {v, ex_I, kem_ek, n_I}
//  2. R→I  {ex_R, kem_ct, id_R, n_R, sig_R}   sig_R = Ed25519(id_R, "server"‖H(m1‖m2*))
//  3. I→R  {id_I, sig_I}                        sig_I = Ed25519(id_I, "client"‖H(m1‖m2‖id_I))
//  keys = HKDF(ikm = X25519‖ML-KEM, salt = H(full transcript), info = direction)
function hsReader(sock){
  const q = []; let waiter = null; let err = null;
  const reader = new FrameReader(sock, (f) => {
    if (reader.onFrame) return reader.onFrame(f);
    q.push(f); if (waiter){ const w = waiter; waiter = null; w(); }
  }, (e) => { err = e; sock.destroy(); if (waiter){ const w = waiter; waiter = null; w(); } });
  sock.on('close', () => { err ??= new Error('connection closed during handshake'); if (waiter){ const w = waiter; waiter = null; w(); } });
  reader.q = q;
  reader.next = async () => {
    while (!q.length){ if (err) throw err; await new Promise((r) => { waiter = r; }); }
    return q.shift();
  };
  return reader;
}
const parse = (f) => { const o = JSON.parse(f.toString('utf8')); if (!o || typeof o !== 'object') throw new Error('bad msg'); return o; };
const enc = (o) => frame(Buffer.from(JSON.stringify(o)));
function x25519(){
  const kp = crypto.generateKeyPairSync('x25519');
  return { kp, raw: rawPub(kp.publicKey) };
}
function x25519Shared(priv, peerRaw){
  if (peerRaw.length !== 32) throw new Error('bad x25519 key');
  const pub = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: peerRaw.toString('base64url') }, format: 'jwk' });
  const ss = crypto.diffieHellman({ privateKey: priv, publicKey: pub });
  if (ss.every((b) => b === 0)) throw new Error('low-order x25519 point');
  return ss;
}
function checkPin(peerRaw, opts){
  const fp = fingerprint(peerRaw);
  if (opts.peerFingerprint) { if (fp !== opts.peerFingerprint) throw new Error('peer fingerprint mismatch: got ' + fp); return; }
  if (opts.pins?.has(fp)) return;
  if (opts.tofu && opts.pins) { opts.pins.add(fp, 'tofu ' + new Date().toISOString()); return; }
  throw new Error('peer not pinned: ' + fp);
}
function withTimeout(p, sock){
  let t; return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => { sock.destroy(); rej(new Error('handshake timeout')); }, HS_TIMEOUT_MS); })]).finally(() => clearTimeout(t));
}
function deriveKeys(xss, kss, th){
  const ikm = Buffer.concat([xss, Buffer.from(kss)]);
  return { c2s: hkdf(ikm, th, VERSION + ' c2s'), s2c: hkdf(ikm, th, VERSION + ' s2c') };
}

export async function clientHandshake(sock, identity, opts = {}){
  const r = hsReader(sock);
  return withTimeout((async () => {
    const ex = x25519(); const kem = ml_kem768.keygen();
    const m1 = Buffer.from(JSON.stringify({ v: VERSION, ex: b64(ex.raw), ek: b64(kem.publicKey), n: b64(crypto.randomBytes(32)) }));
    sock.write(frame(m1));
    const m2f = await r.next(); const m2 = parse(m2f);
    const idR = unb64(m2.id);
    const m2star = Buffer.from(JSON.stringify({ ex: m2.ex, ct: m2.ct, id: m2.id, n: m2.n }));
    const th2 = sha256(m1, m2star);
    if (!crypto.verify(null, Buffer.concat([Buffer.from(VERSION + ' server'), th2]), edPubFromRaw(idR), unb64(m2.sig))) throw new Error('server signature invalid');
    checkPin(idR, opts);
    const xss = x25519Shared(ex.kp.privateKey, unb64(m2.ex));
    const kss = ml_kem768.decapsulate(unb64(m2.ct), kem.secretKey);
    const th3 = sha256(m1, m2f, identity.raw);
    const sig = crypto.sign(null, Buffer.concat([Buffer.from(VERSION + ' client'), th3]), identity.privateKey);
    sock.write(enc({ id: b64(identity.raw), sig: b64(sig) }));
    const k = deriveKeys(xss, kss, th3);
    const ch = new SecureChannel(sock, k.c2s, k.s2c, idR, opts);
    // Key confirmation: server proves it accepted our identity before we report success.
    const conf = ch.rx.open(await r.next());
    if (conf.type !== T_CONFIRM) throw new Error('missing key confirmation');
    ch._start(r);
    return ch;
  })(), sock).catch((e) => { sock.destroy(); throw e; });
}

export async function serverHandshake(sock, identity, opts = {}){
  const r = hsReader(sock);
  return withTimeout((async () => {
    const m1 = await r.next(); const o1 = parse(m1);
    if (o1.v !== VERSION) throw new Error('version mismatch');
    const ex = x25519();
    const xss = x25519Shared(ex.kp.privateKey, unb64(o1.ex));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(unb64(o1.ek));
    const body = { ex: b64(ex.raw), ct: b64(cipherText), id: b64(identity.raw), n: b64(crypto.randomBytes(32)) };
    const th2 = sha256(m1, Buffer.from(JSON.stringify(body)));
    const sig = crypto.sign(null, Buffer.concat([Buffer.from(VERSION + ' server'), th2]), identity.privateKey);
    const m2f = Buffer.from(JSON.stringify({ ...body, sig: b64(sig) }));
    sock.write(frame(m2f));
    const o3 = parse(await r.next());
    const idI = unb64(o3.id);
    const th3 = sha256(m1, m2f, idI);
    if (!crypto.verify(null, Buffer.concat([Buffer.from(VERSION + ' client'), th3]), edPubFromRaw(idI), unb64(o3.sig))) throw new Error('client signature invalid');
    checkPin(idI, opts);
    const k = deriveKeys(xss, sharedSecret, th3);
    const ch = new SecureChannel(sock, k.s2c, k.c2s, idI, opts);
    sock.write(frame(ch.tx.seal(T_CONFIRM, Buffer.alloc(0))));
    ch._start(r);
    return ch;
  })(), sock).catch((e) => { sock.destroy(); throw e; });
}

export function listen({ host = '127.0.0.1', port, identity, ...opts }, onChannel, onError = () => {}){
  const { gate, ...hsOpts } = opts;
  const srv = net.createServer((sock) => {
    // Optional pre-handshake gate (e.g. per-IP rate limit) so floods never reach the crypto.
    if (gate && !gate(sock)){ sock.destroy(); return; }
    serverHandshake(sock, identity, hsOpts).then(onChannel, onError);
  });
  srv.listen(port, host);
  return srv;
}
export function connect({ host = '127.0.0.1', port, identity, ...opts }){
  return new Promise((res, rej) => {
    const sock = net.connect(port, host, () => clientHandshake(sock, identity, opts).then(res, rej));
    sock.once('error', rej);
  });
}

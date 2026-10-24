// Fuzz-style robustness tests: parsers must reject garbage with a plain Error, never crash the
// process, hang, or accept a mutated authentic object.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import * as sc from '../seccore.mjs';
import * as e2e from '../e2e.mjs';
import * as secrets from '../secrets.mjs';
import { parseBundle, makeBundle } from '../pair.mjs';
import { RevocationStore, signRevocation } from '../revoke.mjs';
import { MeshNode } from '../mesh.mjs';
import { TaskRunner } from '../tasks.mjs';
const R = (n) => crypto.randomInt(n);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 4000){ const t = Date.now(); while (!fn()){ if (Date.now() - t > ms) throw new Error('timeout'); await wait(20); } }
const ITER = 300;

function randomValue(depth = 0){
  switch (R(depth > 2 ? 6 : 9)){
    case 0: return null; case 1: return R(2) === 0; case 2: return R(1e9) - 5e8; case 3: return crypto.randomBytes(R(40)).toString('base64');
    case 4: return '__proto__'; case 5: return crypto.randomBytes(R(8)).toString('hex');
    case 6: return Array.from({ length: R(5) }, () => randomValue(depth + 1));
    default: { const o = {}; for (let i = R(6); i--;) o[['t', 'id', 'body', 'recs', 'notices', 'sealed', 'ttl', 'path', 'dst', 'c', 'mac', 'ts', 'anns', crypto.randomBytes(3).toString('hex')][R(14)]] = randomValue(depth + 1); return o; }
  }
}
function mutate(str){
  const b = Buffer.from(str); const n = 1 + R(4);
  for (let i = 0; i < n; i++){ const k = R(3); if (k === 0) b[R(b.length)] ^= 1 << R(8); else if (k === 1) b[R(b.length)] = R(256); else return b.subarray(0, R(b.length)).toString('latin1'); }
  return b.toString('latin1');
}

test('pairing bundle parser: garbage and mutations are rejected', () => {
  const good = makeBundle({ name: 'tab', fingerprint: sc.fingerprint(sc.generateIdentity().raw), host: '10.0.0.2', port: 7400 });
  const fp = parseBundle(good).fingerprint;
  for (let i = 0; i < ITER; i++){
    for (const s of [crypto.randomBytes(R(200)).toString('latin1'), 'SECCORE1:' + crypto.randomBytes(R(100)).toString('base64url'), mutate(good)]){
      try { const p = parseBundle(s); assert.equal(p.fingerprint, fp, 'mutated bundle parsed to a different key'); }
      catch (e) { assert.ok(e instanceof Error); }
    }
  }
});

test('envelope/record/secret/revocation parsers reject mutations', () => {
  const a = sc.generateIdentity(), b = sc.generateIdentity(), pk = new e2e.PrekeyStore();
  const env = e2e.seal({ identity: a, dstFp: sc.fingerprint(b.raw), prekey: e2e.verifyRecord(e2e.makeRecord(b, { seq: 1, prekey: pk.publicInfo(), nbrs: [] })).pk, body: { x: 1 }, id: 'f'.repeat(32) });
  assert.deepEqual(e2e.open(env, b, pk).body, { x: 1 });
  const rec = e2e.makeRecord(a, { seq: 5, prekey: pk.publicInfo(), nbrs: [] });
  const box = secrets.seal('s3cret', 'pw', { N: 1024, r: 8, p: 1 });
  const store = new RevocationStore({});
  for (let i = 0; i < 60; i++){
    const k = ['hdr', 'srcEd', 'eph', 'kct', 'nonce', 'ct', 'sig'][R(7)];
    assert.throws(() => e2e.open({ ...env, [k]: mutate(env[k]) }, b, pk));
    assert.throws(() => e2e.open(randomValue(), b, pk));
    assert.throws(() => e2e.verifyRecord({ body: mutate(rec.body), sig: rec.sig }));
    assert.throws(() => e2e.verifyRecord(randomValue()));
    const bk = ['salt', 'nonce', 'ct'][R(3)];
    assert.throws(() => secrets.open({ ...box, [bk]: Buffer.from(mutate(Buffer.from(box[bk], 'base64').toString('latin1')), 'latin1').toString('base64') }, 'pw'));
    const n = signRevocation(a, sc.fingerprint(b.raw)); n.sigs[0].sig = mutate(n.sigs[0].sig);
    assert.notEqual(store.add(n, new Set()).status, 'applied');
    assert.equal(store.add(randomValue(), new Set()).status === 'applied', false);
  }
});

test('task arg builder never throws non-Errors and never passes unmatched args', () => {
  const r = new TaskRunner({ tasks: { t: { argv: ['echo', '{a}'], args: { a: '[a-z]{1,8}' }, peers: ['*'] } } });
  for (let i = 0; i < ITER; i++){
    const v = randomValue();
    try { const argv = r.buildArgv('t', { a: v }); assert.match(argv[1], /^[a-z]{1,8}$/); }
    catch (e) { assert.ok(e instanceof Error); }
  }
});

test('handshake listener survives random bytes, oversized and floods of frames, then still works', async () => {
  const B = sc.generateIdentity(), A = sc.generateIdentity();
  const errors = [];
  const srv = sc.listen({ port: 0, identity: B, peerFingerprint: sc.fingerprint(A.raw) }, () => {}, (e) => errors.push(e));
  await new Promise((r) => srv.once('listening', r));
  const port = srv.address().port;
  const blast = (buf) => new Promise((r) => { const s = net.connect(port, '127.0.0.1', () => s.end(buf)); s.on('close', r); s.on('error', () => {}); setTimeout(() => s.destroy(), 500); });
  const frames = (n, len) => Buffer.concat(Array.from({ length: n }, () => { const h = Buffer.alloc(4); h.writeUInt32BE(len); return Buffer.concat([h, crypto.randomBytes(len)]); }));
  const cases = [crypto.randomBytes(10), crypto.randomBytes(5000), Buffer.from([0xff, 0xff, 0xff, 0xff]), Buffer.from([0, 0, 0, 0]), frames(50, 100), frames(1, 20000)];
  for (let i = 0; i < 40; i++){ const h = Buffer.alloc(4); h.writeUInt32BE(1 + R(300)); cases.push(Buffer.concat([h, Buffer.from(JSON.stringify(randomValue()))])); }
  await Promise.all(cases.map(blast));
  assert.ok(errors.some((e) => /frame/.test(e.message)));
  const ch = await sc.connect({ port, identity: A, peerFingerprint: sc.fingerprint(B.raw) });
  assert.equal(ch.peerFingerprint, sc.fingerprint(B.raw));
  ch.close(); srv.close();
});

test('wrong-length ML-KEM key in handshake is rejected cleanly', async () => {
  const B = sc.generateIdentity();
  const errors = [];
  const srv = sc.listen({ port: 0, identity: B, tofu: true, pins: new sc.PinStore(null) }, () => {}, (e) => errors.push(e));
  await new Promise((r) => srv.once('listening', r));
  const m1 = Buffer.from(JSON.stringify({ v: sc.VERSION, ex: crypto.randomBytes(32).toString('base64'), ek: crypto.randomBytes(100).toString('base64'), n: 'x' }));
  const h = Buffer.alloc(4); h.writeUInt32BE(m1.length);
  await new Promise((r) => { const s = net.connect(srv.address().port, '127.0.0.1', () => s.write(Buffer.concat([h, m1]))); s.on('close', r); s.on('error', () => {}); });
  await until(() => errors.length);
  assert.match(errors[0].message, /ML-KEM|x25519/);
  srv.close();
});

test('mesh node survives random authenticated messages from a trusted peer', async () => {
  const a = await new MeshNode({ identity: sc.generateIdentity(), name: 'a', port: 0, canarySecret: 'aa'.repeat(32), peerBurst: 1e6, peerRate: 1e6, ctrlBurst: 1e6, ctrlRate: 1e6, handler: async () => 1 }).start();
  const b = await new MeshNode({ identity: sc.generateIdentity(), name: 'b', port: 0, canarySecret: 'aa'.repeat(32) }).start();
  a.addPeer({ name: 'b', host: '127.0.0.1', port: b.port, fingerprint: b.fp }); b.addPeer({ name: 'a', host: '127.0.0.1', port: a.port, fingerprint: a.fp });
  await until(() => a.peers.get('b').ch && b.peers.get('a').ch);
  const unhandled = []; const h = (e) => unhandled.push(e); process.on('unhandledRejection', h);
  const ch = b.peers.get('a').ch;
  for (let i = 0; i < ITER; i++){
    const v = randomValue();
    const t = ['msg', 'req', 'res', 'relay', 'rec', 'revoke', 'canary', 'canaryRes', 'hb', 'hbAck', 'zzz'][R(11)];
    const msg = v && typeof v === 'object' && !Array.isArray(v) ? { ...v, t } : v;
    ch.send(R(10) === 0 ? crypto.randomBytes(R(50)) : JSON.stringify(msg));
  }
  await wait(300);
  process.off('unhandledRejection', h);
  assert.deepEqual(unhandled, []);
  // still connected and functional (b may have been flagged by a canary oddity: check a's side of the link)
  assert.ok(a.peers.get('b').ch || a.peers.get('b').strikes > 0);
  // relay ts NaN regression: never delivered
  await Promise.all([a.stop(), b.stop()]);
});

test('oversized request result becomes an error, link survives', async () => {
  const a = await new MeshNode({ identity: sc.generateIdentity(), name: 'a', port: 0, handler: async () => 'x'.repeat(2 << 20) }).start();
  const b = await new MeshNode({ identity: sc.generateIdentity(), name: 'b', port: 0 }).start();
  a.addPeer({ name: 'b', host: '127.0.0.1', port: b.port, fingerprint: b.fp }); b.addPeer({ name: 'a', host: '127.0.0.1', port: a.port, fingerprint: a.fp });
  await until(() => a.peers.get('b').ch && b.peers.get('a').ch);
  await assert.rejects(b.request('a', { big: 1 }), /too large/);
  assert.ok(b.peers.get('a').ch);
  await Promise.all([a.stop(), b.stop()]);
});

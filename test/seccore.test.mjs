import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import * as sc from '../seccore.mjs';

const A = sc.generateIdentity(), B = sc.generateIdentity(), M = sc.generateIdentity();
const fp = (id) => sc.fingerprint(id.raw);
const once = (em, ev) => new Promise((r) => em.once(ev, r));

function server(identity, peerFingerprint, extra = {}){
  return new Promise((res) => {
    const out = { channels: [], errors: [] };
    out.srv = sc.listen({ port: 0, identity, peerFingerprint, ...extra },
      (ch) => { out.channels.push(ch); ch.on('message', (m) => ch.send(m)); ch.on('error', (e) => out.errors.push(e)); },
      (e) => out.errors.push(e));
    out.srv.on('listening', () => { out.port = out.srv.address().port; res(out); });
  });
}
// Byte-level proxy; `mut(dir, frameIndex, frame)` returns array of frames to forward.
function proxy(target, mut = (d, i, f) => [f], log = []){
  return new Promise((res) => {
    const p = net.createServer((c) => {
      const s = net.connect(target, '127.0.0.1');
      const pipe = (from, to, dir) => { let buf = Buffer.alloc(0), i = 0;
        from.on('data', (d) => { log.push(d); buf = Buffer.concat([buf, d]);
          while (buf.length >= 4 && buf.length >= 4 + buf.readUInt32BE(0)){
            const n = buf.readUInt32BE(0), f = Buffer.from(buf.subarray(0, 4 + n)); buf = buf.subarray(4 + n);
            for (const o of mut(dir, i, f)) to.write(o); i++;
          } });
        from.on('close', () => to.destroy()); from.on('error', () => {}); };
      pipe(c, s, 'c2s'); pipe(s, c, 's2c');
    }).listen(0, '127.0.0.1', () => res(p));
  });
}

test('handshake + echo, keys bound to identities', async () => {
  const s = await server(B, fp(A));
  const ch = await sc.connect({ port: s.port, identity: A, peerFingerprint: fp(B) });
  assert.equal(ch.peerFingerprint, fp(B));
  ch.send('hello seccore'); const m = await once(ch, 'message');
  assert.equal(m.toString(), 'hello seccore');
  ch.close(); s.srv.close();
});

test('wrong pinned key is rejected (both directions)', async () => {
  const s = await server(B, fp(A));
  await assert.rejects(sc.connect({ port: s.port, identity: A, peerFingerprint: fp(M) }), /fingerprint mismatch/);
  await assert.rejects(sc.connect({ port: s.port, identity: M, peerFingerprint: fp(B) }));
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(s.errors.some((e) => /fingerprint mismatch/.test(e.message)));
  s.srv.close();
});

test('active MITM with its own identity is rejected', async () => {
  const real = await server(B, fp(A));
  // Mallory terminates the client's handshake with her own key and opens her own to B.
  const mitm = await server(M, undefined, { tofu: true, pins: new sc.PinStore(null) });
  await assert.rejects(sc.connect({ port: mitm.port, identity: A, peerFingerprint: fp(B) }), /fingerprint mismatch/);
  await assert.rejects(sc.connect({ port: real.port, identity: M, peerFingerprint: fp(B) }));
  real.srv.close(); mitm.srv.close();
});

test('MITM splicing a signature onto its own ephemeral key fails', async () => {
  const s = await server(B, fp(A));
  const p = await proxy(s.port, (dir, i, f) => {
    if (dir === 's2c' && i === 0){ // swap server ephemeral; signature no longer matches transcript
      const o = JSON.parse(f.subarray(4).toString()); o.ex = Buffer.alloc(32, 9).toString('base64');
      const b = Buffer.from(JSON.stringify(o)), h = Buffer.alloc(4); h.writeUInt32BE(b.length); return [Buffer.concat([h, b])];
    }
    return [f];
  });
  await assert.rejects(sc.connect({ port: p.address().port, identity: A, peerFingerprint: fp(B) }), /signature invalid/);
  p.close(); s.srv.close();
});

test('tampered ciphertext closes the channel', async () => {
  const s = await server(B, fp(A));
  const p = await proxy(s.port, (dir, i, f) => { if (dir === 'c2s' && i === 2){ f[f.length - 20] ^= 1; } return [f]; });
  const ch = await sc.connect({ port: p.address().port, identity: A, peerFingerprint: fp(B) });
  let got = false; ch.on('message', () => { got = true; }); ch.on('error', () => {});
  ch.send('attack at dawn');
  await once(ch, 'close');
  assert.equal(got, false);
  assert.ok(s.errors.some((e) => /authenticate|auth/i.test(e.message)), s.errors.map(String).join());
  p.close(); s.srv.close();
});

test('replayed frame is rejected', async () => {
  const s = await server(B, fp(A));
  const p = await proxy(s.port, (dir, i, f) => (dir === 'c2s' && i === 2 ? [f, f] : [f]));
  const ch = await sc.connect({ port: p.address().port, identity: A, peerFingerprint: fp(B) });
  const msgs = []; ch.on('message', (m) => msgs.push(m.toString())); ch.on('error', () => {});
  ch.send('pay 10');
  await once(ch, 'close');
  assert.ok(msgs.length <= 1);
  assert.ok(s.errors.some((e) => /replay/.test(e.message)));
  p.close(); s.srv.close();
});

test('rekey after N messages keeps working and changes keys', async () => {
  const s = await server(B, fp(A), { rekeyMessages: 3 });
  const ch = await sc.connect({ port: s.port, identity: A, peerFingerprint: fp(B), rekeyMessages: 3 });
  const k0 = Buffer.from(ch.tx.key); let rekeys = 0; ch.on('rekey', () => rekeys++);
  const got = []; ch.on('message', (m) => got.push(m.toString()));
  for (let i = 0; i < 10; i++) ch.send('m' + i);
  while (got.length < 10) await once(ch, 'message');
  assert.deepEqual(got, Array.from({ length: 10 }, (_, i) => 'm' + i));
  assert.ok(rekeys >= 3); assert.notDeepEqual(ch.tx.key, k0);
  ch.close(); s.srv.close();
});

test('passive wire observer cannot recover plaintext', async () => {
  const s = await server(B, fp(A)); const wire = [];
  const p = await proxy(s.port, undefined, wire);
  const ch = await sc.connect({ port: p.address().port, identity: A, peerFingerprint: fp(B) });
  const secret = 'TOP-SECRET-' + 'x'.repeat(64);
  ch.send(secret); await once(ch, 'message');
  const all = Buffer.concat(wire);
  assert.equal(all.indexOf(secret), -1);
  assert.equal(all.indexOf('TOP-SECRET'), -1);
  // Everything an observer sees: public keys, KEM ciphertext, signatures. Try naive key guesses.
  assert.notEqual(all.indexOf(Buffer.from(ch.tx.key).toString('base64')), 0);
  assert.equal(all.indexOf(ch.tx.key), -1);
  ch.close(); p.close(); s.srv.close();
});

test('identity and fingerprint stable; no Math.random in source', async () => {
  const fs = await import('node:fs');
  const src = fs.readFileSync(new URL('../seccore.mjs', import.meta.url), 'utf8');
  assert.ok(!/Math\.random\(/.test(src));
  assert.equal(sc.fingerprint(A.raw), sc.fingerprint(sc.edPubFromRaw(A.raw).export({ format: 'jwk' }) && A.raw));
});

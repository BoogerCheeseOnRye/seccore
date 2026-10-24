import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { TokenBucket, KeyedLimiter } from '../ratelimit.mjs';
import * as sc from '../seccore.mjs';
import { MeshNode } from '../mesh.mjs';
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 4000){ const t = Date.now(); while (!fn()){ if (Date.now() - t > ms) throw new Error('timeout'); await wait(20); } }

test('token bucket refills', async () => {
  const b = new TokenBucket(20, 2);
  assert.ok(b.take()); assert.ok(b.take()); assert.ok(!b.take());
  await wait(120); assert.ok(b.take());
  const k = new KeyedLimiter(1, 1, 2); assert.ok(k.take('a')); assert.ok(!k.take('a')); assert.ok(k.take('b'));
});

test('per-peer request flood is limited; handshake flood per IP is cut off', async () => {
  const opts = { peerRate: 1, peerBurst: 3, handshakeRate: 0.1, handshakeBurst: 4, heartbeatMs: 1000, deadMs: 5000 };
  const a = await new MeshNode({ identity: sc.generateIdentity(), name: 'a', port: 0, ...opts, handler: async () => 'ok' }).start();
  const b = await new MeshNode({ identity: sc.generateIdentity(), name: 'b', port: 0, ...opts }).start();
  a.addPeer({ name: 'b', host: '127.0.0.1', port: b.port, fingerprint: b.fp });
  b.addPeer({ name: 'a', host: '127.0.0.1', port: a.port, fingerprint: a.fp });
  await until(() => a.peers.get('b').ch && b.peers.get('a').ch);
  const rs = await Promise.allSettled(Array.from({ length: 10 }, () => b.request('a', { x: 1 }, 2000)));
  const ok = rs.filter((r) => r.status === 'fulfilled').length;
  assert.ok(ok >= 3 && ok <= 4, 'ok=' + ok);
  assert.ok(rs.some((r) => r.status === 'rejected' && /rate limited/.test(r.reason.message)));
  assert.ok(a.alerts.some((x) => x.kind === 'peer-rate' && x.peer === 'b'));
  // handshake flood from one IP: after the burst, sockets are closed before any handshake bytes
  let closedEarly = 0;
  for (let i = 0; i < 8; i++){
    await new Promise((r) => { const s = net.connect(a.port, '127.0.0.1'); let got = false; s.write('x'); s.on('data', () => { got = true; }); s.on('close', () => { if (!got) closedEarly++; r(); }); s.on('error', () => {}); setTimeout(() => s.destroy(), 300); });
  }
  assert.ok(a.alerts.some((x) => x.kind === 'handshake-rate'));
  await Promise.all([a.stop(), b.stop()]);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as sc from '../seccore.mjs';
import { MeshNode, startControl } from '../mesh.mjs';

const fast = { heartbeatMs: 100, deadMs: 600, backoffMinMs: 50, backoffMaxMs: 200, canaryMs: 60_000, canaryTimeoutMs: 500 };
const SECRET = crypto.randomBytes(32).toString('hex');
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 4000){ const t = Date.now(); while (!fn()){ if (Date.now() - t > ms) throw new Error('timeout waiting'); await wait(20); } }

// Build a full 3-node mesh in-process; ports are picked by the OS.
async function mesh(names = ['a', 'b', 'c'], extra = {}, waitUp = true){
  const nodes = {};
  for (const n of names) nodes[n] = await new MeshNode({ identity: sc.generateIdentity(), name: n, port: 0, peers: [], ...fast, canarySecret: SECRET, ...(extra[n] || {}) }).start();
  for (const n of names) for (const m of names) if (m !== n) nodes[n].addPeer({ name: m, host: '127.0.0.1', port: nodes[m].port, fingerprint: nodes[m].fp });
  if (waitUp) await until(() => names.every((n) => [...nodes[n].peers.values()].every((s) => s.ch)));
  return { nodes, stop: () => Promise.all(Object.values(nodes).map((x) => x.stop())) };
}

test('3-node mesh: send, broadcast, request/response', async () => {
  const handler = async (body, from) => ({ ran: body.task, by: 'b', from });
  const { nodes, stop } = await mesh(['a', 'b', 'c'], { b: { handler } });
  const got = { b: [], c: [] };
  nodes.b.on('message', (m) => got.b.push(m)); nodes.c.on('message', (m) => got.c.push(m));
  nodes.a.send('b', { hello: 1 });
  assert.deepEqual(nodes.a.broadcast({ all: true }).sort(), ['b', 'c']);
  await until(() => got.b.length === 2 && got.c.length === 1);
  assert.deepEqual(got.b[0], { from: 'a', body: { hello: 1 } });
  assert.equal(got.c[0].from, 'a');
  assert.deepEqual(await nodes.c.request('b', { task: 'X' }), { ran: 'X', by: 'b', from: 'c' });
  await assert.rejects(nodes.b.request('a', { task: 'Y' }), /no handler/);
  await until(() => nodes.a.status().peers.every((p) => p.rttMs != null));
  assert.ok(nodes.a.status().peers.every((p) => p.alive && p.trusted));
  await stop();
});

test('peer reconnects after its link drops', async () => {
  const { nodes, stop } = await mesh(['a', 'b']);
  const dialer = nodes.a._shouldDial('b') ? nodes.a : nodes.b;
  const other = dialer === nodes.a ? 'b' : 'a';
  const first = dialer.peers.get(other).ch;
  first.sock.destroy();                                      // simulate network drop
  await until(() => dialer.peers.get(other).ch && dialer.peers.get(other).ch !== first);
  const got = []; nodes[other].on('message', (m) => got.push(m));
  dialer.send(other, 'back');
  await until(() => got.length === 1);
  await stop();
});

test('unpinned peer is rejected', async () => {
  const { nodes, stop } = await mesh(['a', 'b']);
  const stranger = sc.generateIdentity();
  await assert.rejects(sc.connect({ port: nodes.a.port, identity: stranger, peerFingerprint: nodes.a.fp }));
  await until(() => nodes.a.alerts.some((x) => x.kind === 'handshake-rejected' && /not pinned/.test(x.detail)));
  assert.equal(nodes.a.status().peers.length, 1);
  await stop();
});

test('canary failure flags peer untrusted', async () => {
  const bad = crypto.randomBytes(32).toString('hex');
  const { nodes, stop } = await mesh(['a', 'b'], { b: { canarySecret: bad } }, false); // b lacks the mesh secret
  await until(() => !nodes.a.peers.get('b').trusted);
  assert.ok(nodes.a.alerts.some((x) => x.kind === 'peer-untrusted' && x.peer === 'b'));
  assert.throws(() => nodes.a.send('b', 'x'), /untrusted/);
  await wait(400);                                           // no reconnection to an untrusted peer
  assert.equal(nodes.a.peers.get('b').ch, null);
  await stop();
});

test('decoy listener raises an alert', async () => {
  const id = sc.generateIdentity();
  const n = await new MeshNode({ identity: id, name: 'solo', decoyPort: 0, peers: [] }).start();
  const net = await import('node:net');
  await new Promise((r) => net.connect(n.decoyPort, '127.0.0.1').on('close', r).on('error', r));
  await until(() => n.alerts.some((a) => a.kind === 'decoy-touched'));
  await n.stop();
});

test('control interface requires the token', async () => {
  const n = await new MeshNode({ identity: sc.generateIdentity(), name: 'solo', peers: [] }).start();
  const token = crypto.randomBytes(32).toString('hex');
  const srv = await startControl(n, { port: 0, token });
  const url = 'http://127.0.0.1:' + srv.address().port + '/status';
  assert.equal((await fetch(url)).status, 401);
  assert.equal((await fetch(url, { headers: { authorization: 'Bearer wrong' } })).status, 401);
  const ok = await fetch(url, { headers: { authorization: 'Bearer ' + token } });
  assert.equal(ok.status, 200); assert.equal((await ok.json()).name, 'solo');
  assert.throws(() => startControl(n, { token: '' }), /token required/);
  assert.equal(srv.address().address, '127.0.0.1');
  await n.stop();
});

test('mesh source never uses Math.random', async () => {
  const fs = await import('node:fs');
  for (const f of ['../mesh.mjs', '../seccore.mjs', '../cli.mjs']) assert.ok(!/Math\.random\(/.test(fs.readFileSync(new URL(f, import.meta.url), 'utf8')), f);
});

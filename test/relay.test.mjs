import test from 'node:test';
import assert from 'node:assert/strict';
import * as sc from '../seccore.mjs';
import * as e2e from '../e2e.mjs';
import { MeshNode } from '../mesh.mjs';
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 4000){ const t = Date.now(); while (!fn()){ if (Date.now() - t > ms) throw new Error('timeout'); await wait(20); } }
const fast = { heartbeatMs: 200, deadMs: 2000 };

// Build nodes; `links` = pairs that are directly paired; `known` = pairs pinned for e2e only (no direct link).
async function topo(names, links, known = [], extra = {}){
  const n = {};
  for (const x of names) n[x] = await new MeshNode({ identity: sc.generateIdentity(), name: x, port: 0, ...fast, handler: async (b, from) => ({ echo: b, from, at: x }), ...(extra[x] || {}) }).start();
  for (const [x, y] of links){ n[x].addPeer({ name: y, host: '127.0.0.1', port: n[y].port, fingerprint: n[y].fp }); n[y].addPeer({ name: x, host: '127.0.0.1', port: n[x].port, fingerprint: n[x].fp }); }
  for (const [x, y] of known){ n[x].addPeer({ name: y, fingerprint: n[y].fp }); n[y].addPeer({ name: x, fingerprint: n[x].fp }); }
  await until(() => links.every(([x, y]) => n[x].peers.get(y).ch && n[y].peers.get(x).ch));
  await until(() => names.every((x) => names.every((y) => x === y || n[x].directory.has(n[y].fp))));
  return { n, stop: () => Promise.all(Object.values(n).map((x) => x.stop())) };
}

test('message and request reach a non-adjacent node through a relay', async () => {
  const { n, stop } = await topo(['a', 'b', 'c'], [['a', 'b'], ['b', 'c']], [['a', 'c']]);
  const got = []; n.c.on('message', (m) => got.push(m));
  n.a.send('c', { task: 'hi' });
  await until(() => got.length === 1);
  assert.equal(got[0].from, 'a'); assert.equal(got[0].via, 'b'); assert.deepEqual(got[0].body, { task: 'hi' });
  assert.deepEqual(await n.a.request('c', { op: 'x' }), { echo: { op: 'x' }, from: 'a', at: 'c' });
  await stop();
});

test('relay cannot read or alter the payload', async () => {
  const { n, stop } = await topo(['a', 'b', 'c'], [['a', 'b'], ['b', 'c']], [['a', 'c']]);
  const seenAtB = [];
  const orig = n.b._forward.bind(n.b);
  n.b._forward = (frame, from) => { seenAtB.push(JSON.parse(JSON.stringify(frame))); return orig(frame, from); };
  const got = []; n.c.on('message', (m) => got.push(m));
  n.a.send('c', { secret: 'launch-code-42' });
  await until(() => got.length === 1);
  const f = seenAtB[0];
  assert.ok(!JSON.stringify(f).includes('launch-code-42'));
  assert.throws(() => e2e.open(f.sealed, n.b.id, n.b.box), /not for me/);
  // now tamper in transit
  n.b._forward = (frame, from) => { const ct = Buffer.from(frame.sealed.ct, 'base64'); ct[0] ^= 1; return orig({ ...frame, sealed: { ...frame.sealed, ct: ct.toString('base64') } }, from); };
  n.a.send('c', { secret: 'second' });
  await until(() => n.c.alerts.some((x) => x.kind === 'relay-open-failed'));
  assert.equal(got.length, 1);
  await stop();
});

test('dedupe + loop prevention in a ring; TTL limits hops', async () => {
  // ring a-b-c-d-a; a and c not adjacent. Flood reaches c via b and d: delivered once.
  const { n, stop } = await topo(['a', 'b', 'c', 'd'], [['a', 'b'], ['b', 'c'], ['c', 'd'], ['d', 'a']], [['a', 'c']]);
  const got = []; n.c.on('message', (m) => got.push(m));
  n.a.send('c', 1); n.a.send('c', 2);
  await until(() => got.length >= 2); await wait(200);
  assert.deepEqual(got.map((m) => m.body).sort(), [1, 2]);
  // hop limit of 1: frame can't leave the first relay
  n.a.o.maxHops = 1;
  const drops = []; n.b.on('relay-dropped', (id, why) => drops.push(why)); n.d.on('relay-dropped', (id, why) => drops.push(why));
  n.a.send('c', 3); await wait(300);
  assert.equal(got.length, 2); assert.ok(drops.includes('ttl'));
  await stop();
});

test('e2e message from an unpaired sender is dropped', async () => {
  // c knows b (link) but has not pinned a, even though a pinned c.
  const { n, stop } = await topo(['a', 'b', 'c'], [['a', 'b'], ['b', 'c']]);
  n.a.addPeer({ name: 'c', fingerprint: n.c.fp });
  const got = []; n.c.on('message', (m) => got.push(m));
  n.a.send('c', 'spam');
  await until(() => n.c.alerts.some((x) => x.kind === 'relay-unknown-sender'));
  assert.equal(got.length, 0);
  await stop();
});

test('forged announcement is rejected', () => {
  const id = sc.generateIdentity(), other = sc.generateIdentity();
  const ann = e2e.makeAnnouncement(id, e2e.boxKeyFromIdentity(id));
  assert.equal(e2e.verifyAnnouncement(ann).fp, sc.fingerprint(id.raw));
  const forged = { ...ann, x: e2e.makeAnnouncement(other, e2e.boxKeyFromIdentity(other)).x };
  assert.throws(() => e2e.verifyAnnouncement(forged), /signature/);
});

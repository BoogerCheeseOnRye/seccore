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
  assert.throws(() => e2e.open(f.sealed, n.b.id, n.b.prekeys), /not for me/);
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

test('forged or tampered node record is rejected', () => {
  const id = sc.generateIdentity(), pk = new e2e.PrekeyStore();
  const rec = e2e.makeRecord(id, { seq: 1, prekey: pk.publicInfo(), nbrs: [] });
  assert.equal(e2e.verifyRecord(rec).fp, sc.fingerprint(id.raw));
  const o = JSON.parse(rec.body); o.nbrs = ['aaaa:bbbb:cccc:dddd:eeee:ffff:0000:1111:2222:3333'];
  assert.throws(() => e2e.verifyRecord({ body: JSON.stringify(o), sig: rec.sig }), /signature/);
  const other = new e2e.PrekeyStore(); o.nbrs = []; o.pk = other.publicInfo();
  assert.throws(() => e2e.verifyRecord({ body: JSON.stringify(o), sig: rec.sig }), /signature/);
});

test('forward secrecy: captured envelope is undecryptable after prekey rotation, even with the identity key', async () => {
  const { n, stop } = await topo(['a', 'b', 'c'], [['a', 'b'], ['b', 'c']], [['a', 'c']]);
  const captured = [];
  const orig = n.b._forward.bind(n.b);
  n.b._forward = (frame, from) => { captured.push(JSON.parse(JSON.stringify(frame))); return orig(frame, from); };
  const got = []; n.c.on('message', (m) => got.push(m));
  n.a.send('c', { secret: 'past-message' });
  await until(() => got.length === 1);
  const env = captured[0].sealed;
  assert.equal(e2e.open(env, n.c.id, n.c.prekeys).body.body.secret, 'past-message');   // still in grace window
  for (let i = 0; i < 3; i++) n.c.prekeys.rotate();                                    // keep=2: old key destroyed
  // Attacker steals c's identity key AND all live prekey state now:
  assert.throws(() => e2e.open(env, n.c.id, n.c.prekeys), /forward secrecy/);
  // and the destroyed key material really is gone
  assert.ok(n.c.prekeys.keys.every((k) => k.id !== JSON.parse(env.hdr).pk));
  await stop();
});

test('learned link-state routes: unicast along the path, no flooding', async () => {
  // line a-b-c-d plus a side branch b-e; a→d must go a→b→c→d and never visit e.
  const { n, stop } = await topo(['a', 'b', 'c', 'd', 'e'], [['a', 'b'], ['b', 'c'], ['c', 'd'], ['b', 'e']], [['a', 'd']]);
  await until(() => ['a', 'b', 'c'].every((x) => e2e.nextHop(n[x].fp, n[x]._myNbrs(), n[x].directory, n.d.fp)));
  const ev = []; for (const x of ['a', 'b', 'c']){ n[x].on('routed', (id, hop) => ev.push(x + '>' + hop)); n[x].on('flooded', () => ev.push(x + ':flood')); }
  let eSaw = 0; const oe = n.e._onRelay.bind(n.e); n.e._onRelay = (...a) => { eSaw++; return oe(...a); };
  const got = []; n.d.on('message', (m) => got.push(m));
  n.a.send('d', 'routed!');
  await until(() => got.length === 1); await wait(100);
  assert.deepEqual(ev, ['a>b', 'b>c']);         // c→d is a direct neighbour delivery
  assert.equal(eSaw, 0);
  await stop();
});

test('one-sided adjacency claims do not create routes', () => {
  const mk = () => { const id = sc.generateIdentity(); return { id, fp: sc.fingerprint(id.raw), pk: new e2e.PrekeyStore() }; };
  const [me, x, y] = [mk(), mk(), mk()];
  const recs = new Map();
  // x claims to neighbour y, but y does not list x
  recs.set(x.fp, e2e.verifyRecord(e2e.makeRecord(x.id, { seq: 1, prekey: x.pk.publicInfo(), nbrs: [me.fp, y.fp] })));
  recs.set(y.fp, e2e.verifyRecord(e2e.makeRecord(y.id, { seq: 1, prekey: y.pk.publicInfo(), nbrs: [] })));
  assert.equal(e2e.nextHop(me.fp, [x.fp], recs, y.fp), null);
  recs.set(y.fp, e2e.verifyRecord(e2e.makeRecord(y.id, { seq: 2, prekey: y.pk.publicInfo(), nbrs: [x.fp] })));
  assert.equal(e2e.nextHop(me.fp, [x.fp], recs, y.fp), x.fp);
});

test('envelope with non-numeric timestamp is rejected (stale-check bypass regression)', async () => {
  const { n, stop } = await topo(['a', 'b', 'c'], [['a', 'b'], ['b', 'c']], [['a', 'c']]);
  const got = []; n.c.on('message', (m) => got.push(m));
  const id = 'e'.repeat(32);
  const sealed = e2e.seal({ identity: n.a.id, dstFp: n.c.fp, prekey: n.a.directory.get(n.c.fp).pk, body: { k: 'msg', body: 'old' }, id, ts: 'not-a-number' });
  n.c._onRelay('b', { t: 'relay', id, dst: n.c.fp, ttl: 3, path: [n.a.fp, n.b.fp], sealed });
  assert.equal(got.length, 0);
  assert.ok(n.c.alerts.some((x) => x.kind === 'relay-stale'));
  await stop();
});

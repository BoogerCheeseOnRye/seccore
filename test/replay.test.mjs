import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as sc from '../seccore.mjs';
import { MeshNode } from '../mesh.mjs';
import { ReplayStore } from '../replay.mjs';
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 4000){ const t = Date.now(); while (!fn()){ if (Date.now() - t > ms) throw new Error('timeout'); await wait(20); } }
const id = (i) => i.toString(16).padStart(32, '0');

test('store: persists across instances, expires by window, bounded', () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'rp-')), 'r.json');
  const a = new ReplayStore({ file: f, windowMs: 1000, max: 5 });
  assert.ok(a.add(id(1))); assert.ok(!a.add(id(1)));
  a.add(id(2), Date.now() - 5000); a.flush();
  const b = new ReplayStore({ file: f, windowMs: 1000, max: 5 });
  assert.ok(b.has(id(1))); assert.ok(!b.has(id(2)));            // expired id dropped on load
  for (let i = 10; i < 30; i++) b.add(id(i));
  assert.ok(b.m.size <= 5);
  fs.writeFileSync(f, '{garbage'); assert.equal(new ReplayStore({ file: f }).m.size, 0);
});

test('relayed envelope replayed after recipient restart is rejected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rp2-'));
  const replayFile = path.join(dir, 'replay.json');
  const ids = { a: sc.generateIdentity(), b: sc.generateIdentity(), c: sc.generateIdentity() };
  const mk = (x, extra = {}) => new MeshNode({ identity: ids[x], name: x, port: 0, heartbeatMs: 200, deadMs: 2000, ...extra }).start();
  const n = { a: await mk('a'), b: await mk('b'), c: await mk('c', { replayFile }) };
  const link = (x, y) => { n[x].addPeer({ name: y, host: '127.0.0.1', port: n[y].port, fingerprint: n[y].fp }); n[y].addPeer({ name: x, host: '127.0.0.1', port: n[x].port, fingerprint: n[x].fp }); };
  link('a', 'b'); link('b', 'c'); n.a.addPeer({ name: 'c', fingerprint: n.c.fp }); n.c.addPeer({ name: 'a', fingerprint: n.a.fp });
  await until(() => n.a.directory.has(n.c.fp));
  const captured = []; const orig = n.b._forward.bind(n.b);
  n.b._forward = (f, from) => { captured.push(JSON.parse(JSON.stringify(f))); return orig(f, from); };
  const got = []; n.c.on('message', (m) => got.push(m));
  n.a.send('c', 'once'); await until(() => got.length === 1);
  // c restarts; its prekeys are new, so keep the old store object to show *dedupe* (not just FS) blocks it
  const oldPrekeys = n.c.prekeys; oldPrekeys.destroyAll = () => {};
  await n.c.stop();
  const c2 = await mk('c', { replayFile });
  c2.prekeys = oldPrekeys;
  const frame = { ...captured[0], ttl: captured[0].ttl - 1, path: [...captured[0].path, n.b.fp] };
  const got2 = []; c2.on('message', (m) => got2.push(m));
  c2.peers.set('a', { cfg: { name: 'a', fingerprint: n.a.fp }, trusted: true }); c2.byFp.set(n.a.fp, 'a');
  c2._onRelay('b', frame);
  assert.equal(got2.length, 0);
  // control: same frame to a node WITHOUT the persisted store is accepted, so dedupe is what blocked it
  const c3 = await mk('c'); c3.prekeys = oldPrekeys;
  c3.peers.set('a', { cfg: { name: 'a', fingerprint: n.a.fp }, trusted: true }); c3.byFp.set(n.a.fp, 'a');
  const got3 = []; c3.on('message', (m) => got3.push(m));
  c3._onRelay('b', frame);
  assert.equal(got3.length, 1);
  await Promise.all([n.a.stop(), n.b.stop(), c2.stop(), c3.stop()]);
});

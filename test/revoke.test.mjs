import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as sc from '../seccore.mjs';
import { MeshNode } from '../mesh.mjs';
import { signRevocation, RevocationStore } from '../revoke.mjs';
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 4000){ const t = Date.now(); while (!fn()){ if (Date.now() - t > ms) throw new Error('timeout'); await wait(20); } }

async function full(names, extra = {}){
  const n = {};
  for (const x of names) n[x] = await new MeshNode({ identity: sc.generateIdentity(), name: x, port: 0, heartbeatMs: 200, deadMs: 2000, backoffMinMs: 30, backoffMaxMs: 60, ...(extra[x] || {}) }).start();
  for (const x of names) for (const y of names) if (x !== y) n[x].addPeer({ name: y, host: '127.0.0.1', port: n[y].port, fingerprint: n[y].fp });
  await until(() => names.every((x) => names.every((y) => x === y || n[x].peers.get(y).ch)));
  return { n, stop: () => Promise.all(Object.values(n).map((x) => x.stop())) };
}

test('self-revocation propagates, disconnects everywhere, and blocks reconnects', async () => {
  const { n, stop } = await full(['a', 'b', 'c']);
  n.c.revoke('self', 'stolen phone');
  await until(() => n.a.isRevoked(n.c.fp) && n.b.isRevoked(n.c.fp));
  await until(() => !n.a.peers.get('c').ch && !n.b.peers.get('c').ch);
  await wait(300);
  assert.equal(n.a.peers.get('c').ch, null);
  assert.throws(() => n.a.send('c', 'x'), /revoked/);
  assert.equal(n.a.retrust('c'), false);
  await assert.rejects(sc.connect({ port: n.a.port, identity: n.c.id, peerFingerprint: n.a.fp }));
  await stop();
});

test('a single non-admin cannot revoke; quorum of 2 can; admin can alone', async () => {
  const adminId = sc.generateIdentity(), adminFp = sc.fingerprint(adminId.raw);
  const rev = { revocation: { quorum: 2, admins: [adminFp] } };
  const { n, stop } = await full(['a', 'b', 'c', 'd', 'e'], { a: rev, b: rev, c: rev, d: rev, e: rev });
  n.a.revoke(n.d.fp, 'suspicious');
  await wait(200);
  assert.ok(!n.e.isRevoked(n.d.fp) && n.e.peers.get('d').ch);
  n.b.revoke(n.d.fp);                                     // second co-signer: quorum reached everywhere
  await until(() => ['a', 'b', 'c', 'e'].every((x) => n[x].isRevoked(n.d.fp)));
  // admin key (not even a mesh member) revokes e alone; delivered by any node
  n.a._ingestRevocation(signRevocation(adminId, n.e.fp, 'admin'), null);
  await until(() => ['b', 'c'].every((x) => n[x].isRevoked(n.e.fp)));
  await stop();
});

test('forged revocation is ignored and alerts; revocations persist across restart', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scr-'));
  const file = path.join(dir, 'revoked.json');
  const { n, stop } = await full(['a', 'b'], { a: { revokedFile: file } });
  const notice = signRevocation(sc.generateIdentity(), n.b.fp);
  notice.sigs[0].ed = Buffer.from(n.b.id.raw).toString('base64');     // claim b signed it
  n.a._onRevoke('b', { notices: [notice] });
  assert.ok(!n.a.isRevoked(n.b.fp)); assert.ok(n.a.alerts.some((x) => x.kind === 'bad-revocation'));
  n.b.revoke('self');
  await until(() => n.a.isRevoked(n.b.fp));
  await stop();
  const st = new RevocationStore({ file });
  assert.ok(st.has(n.b.fp));
  const a2 = await new MeshNode({ identity: n.a.id, name: 'a', port: 0, revokedFile: file, peers: [{ name: 'b', fingerprint: n.b.fp }] }).start();
  assert.equal(a2.status().peers[0].revoked, true);
  await assert.rejects(sc.connect({ port: a2.port, identity: n.b.id, peerFingerprint: a2.fp }));
  await a2.stop();
});

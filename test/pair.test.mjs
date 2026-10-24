import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { makeBundle, parseBundle, pairingCode } from '../pair.mjs';
const CLI = new URL('../cli.mjs', import.meta.url).pathname;
const FP = 'aaaa:bbbb:cccc:dddd:eeee:ffff:0000:1111:2222:3333';

test('bundle roundtrip, checksum catches typos, no loopback address leaked', () => {
  const b = makeBundle({ name: 'tab', fingerprint: FP, host: '192.168.1.20', port: 7400 });
  assert.deepEqual(parseBundle(b), { name: 'tab', fingerprint: FP, host: '192.168.1.20', port: 7400 });
  const typo = b.slice(0, 15) + (b[15] === 'A' ? 'B' : 'A') + b.slice(16);
  assert.throws(() => parseBundle(typo), /checksum|bad/);
  assert.equal(parseBundle(makeBundle({ name: 'p', fingerprint: FP, host: '127.0.0.1', port: 1 })).host, undefined);
  assert.throws(() => parseBundle('hello'), /not a seccore/);
});

test('pairing code is symmetric and changes with a swapped key', () => {
  const B = 'bbbb:bbbb:cccc:dddd:eeee:ffff:0000:1111:2222:3333';
  assert.equal(pairingCode(FP, B), pairingCode(B, FP));
  assert.match(pairingCode(FP, B), /^\d{3}-\d{3}$/);
  assert.notEqual(pairingCode(FP, B), pairingCode(FP, 'cccc:bbbb:cccc:dddd:eeee:ffff:0000:1111:2222:3333'));
});

test('CLI pair export/import between two homes; bundle has no canary secret', () => {
  const h = [0, 1].map(() => fs.mkdtempSync(path.join(os.tmpdir(), 'scp-')));
  const run = (d, args) => execFileSync(process.execPath, [CLI, ...args, '--home', d], { env: { ...process.env, PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  run(h[0], ['keygen']); run(h[1], ['keygen']);
  run(h[0], ['mesh-init', '--name', 'box', '--host', '10.0.0.5']); run(h[1], ['mesh-init', '--name', 'phone']);
  const b0 = run(h[0], ['pair']).split('\n')[0], b1 = run(h[1], ['pair']).split('\n')[0];
  const canary = JSON.parse(fs.readFileSync(path.join(h[0], 'mesh.json'))).canarySecret;
  assert.ok(!Buffer.from(b0.slice(9).split('.')[0], 'base64url').toString().includes(canary));
  const o1 = run(h[1], ['pair', '--import', b0, '--yes']), o0 = run(h[0], ['pair', '--import', b1, '--yes']);
  const code = (s) => s.match(/PAIRING CODE: (\S+)/)[1];
  assert.equal(code(o1), code(o0));
  const m1 = JSON.parse(fs.readFileSync(path.join(h[1], 'mesh.json')));
  assert.deepEqual(m1.peers.map((p) => [p.name, p.host, p.port]), [['box', '10.0.0.5', 7400]]);
  const m0 = JSON.parse(fs.readFileSync(path.join(h[0], 'mesh.json')));
  assert.equal(m0.peers[0].name, 'phone'); assert.equal(m0.peers[0].host, undefined);
});

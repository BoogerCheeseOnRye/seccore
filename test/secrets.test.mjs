import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import * as secrets from '../secrets.mjs';
import * as sc from '../seccore.mjs';
const KDF = { N: 1 << 12, r: 8, p: 1 };
const CLI = new URL('../cli.mjs', import.meta.url).pathname;

test('seal/open roundtrip; wrong passphrase and tampering fail', () => {
  const box = secrets.seal('hello', 'pw', KDF);
  assert.equal(secrets.open(box, 'pw').toString(), 'hello');
  assert.throws(() => secrets.open(box, 'nope'), /wrong passphrase/);
  const t = { ...box, ct: Buffer.from(Buffer.from(box.ct, 'base64').map((b, i) => (i === 0 ? b ^ 1 : b))).toString('base64') };
  assert.throws(() => secrets.open(t, 'pw'), /wrong passphrase/);
  assert.throws(() => secrets.open(box, ''), /locked/);
  assert.ok(!JSON.stringify(box).includes('hello'));
});

test('encrypted identity loads only with passphrase', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scs-'));
  const id = sc.generateIdentity(); sc.saveIdentityEncrypted(id, 'pw', dir, KDF);
  assert.ok(sc.identityIsEncrypted(dir));
  assert.throws(() => sc.loadIdentity(dir, undefined), /locked/);
  assert.equal(sc.fingerprint(sc.loadIdentity(dir, 'pw').raw), sc.fingerprint(id.raw));
  assert.ok(!fs.readFileSync(path.join(dir, 'identity.pem.enc'), 'utf8').includes('PRIVATE KEY'));
});

test('CLI migration encrypts identity + canary; node config unlocks with env', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scm-'));
  const run = (args, env = {}) => execFileSync(process.execPath, [CLI, ...args, '--home', dir], { env: { ...process.env, SECCORE_PASSPHRASE: '', ...env }, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  run(['keygen']); const fp = run(['fingerprint']).trim();
  run(['mesh-init', '--name', 'x']);
  const before = JSON.parse(fs.readFileSync(path.join(dir, 'mesh.json'))).canarySecret;
  run(['encrypt-secrets'], { SECCORE_PASSPHRASE: 'correct horse' });
  assert.ok(!fs.existsSync(path.join(dir, 'identity.pem')));
  const m = JSON.parse(fs.readFileSync(path.join(dir, 'mesh.json')));
  assert.equal(m.canarySecret, undefined);
  assert.equal(secrets.open(m.canarySecretEnc, 'correct horse').toString(), before);
  assert.equal(run(['fingerprint'], { SECCORE_PASSPHRASE: 'correct horse' }).trim(), fp);
  assert.throws(() => run(['fingerprint'], { SECCORE_PASSPHRASE: 'wrong' }));
});

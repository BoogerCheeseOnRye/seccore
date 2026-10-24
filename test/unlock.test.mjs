import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import * as keystore from '../keystore.mjs';
const CLI = new URL('../cli.mjs', import.meta.url).pathname;
const FAKE = new URL('./fixtures/fake-termux-keystore.mjs', import.meta.url).pathname;
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('keystore wrap/unwrap is device-bound', () => {
  const d = tmp('ks-'), f = path.join(d, 'p.ks');
  process.env.SECCORE_KEYSTORE_BIN = FAKE; process.env.FAKE_KS_DIR = path.join(d, 'dev1');
  assert.ok(keystore.available());
  keystore.wrap('hunter2', f);
  assert.equal(keystore.unwrap(f), 'hunter2');
  assert.ok(!fs.readFileSync(f, 'utf8').includes('hunter2'));
  process.env.FAKE_KS_DIR = path.join(d, 'dev2');                  // another device: no such key
  assert.throws(() => keystore.unwrap(f));
  fs.mkdirSync(process.env.FAKE_KS_DIR, { recursive: true }); fs.writeFileSync(path.join(process.env.FAKE_KS_DIR, 'seccore-unlock.key'), Buffer.alloc(32));
  assert.throws(() => keystore.unwrap(f), /unwrap failed/);
  delete process.env.SECCORE_KEYSTORE_BIN;
});

test('CLI: encrypted identity unlocks at boot through the keystore, no plaintext passphrase stored', () => {
  const home = tmp('ksc-');
  const env = { ...process.env, SECCORE_KEYSTORE_BIN: FAKE, FAKE_KS_DIR: path.join(home, 'hw'), SECCORE_PASSPHRASE: '' };
  const run = (args, e = {}) => execFileSync(process.execPath, [CLI, ...args, '--home', home], { env: { ...env, ...e }, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  run(['keygen', '--encrypt'], { SECCORE_PASSPHRASE: 'pw-123' });
  assert.throws(() => run(['fingerprint']));                         // locked, no TTY
  run(['keystore-setup'], { SECCORE_PASSPHRASE: 'pw-123' });
  assert.match(run(['fingerprint']), /^[0-9a-f]{4}:/);                // unlocked via keystore
  for (const f of fs.readdirSync(home)) if (fs.statSync(path.join(home, f)).isFile()) assert.ok(!fs.readFileSync(path.join(home, f), 'utf8').includes('pw-123'), f);
});

test('locked daemon accepts `seccore unlock` with the right passphrase only', async () => {
  const home = tmp('lk-'); const env = { ...process.env, SECCORE_PASSPHRASE: '' };
  const run = (args, e = {}) => execFileSync(process.execPath, [CLI, ...args, '--home', home], { env: { ...env, ...e }, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  run(['keygen', '--encrypt'], { SECCORE_PASSPHRASE: 'right' });
  run(['mesh-init', '--name', 'lk', '--port', '0', '--control-port', String(47800 + Math.floor(Math.random() * 100))]);
  const child = spawn(process.execPath, [CLI, 'node', '--home', home], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = ''; child.stdout.on('data', (d) => { out += d; }); child.stderr.on('data', (d) => { out += d; });
  try {
    for (let i = 0; i < 100 && !out.includes('LOCKED'); i++) await wait(50);
    assert.match(out, /LOCKED/);
    assert.match(run(['status']), /"locked": true/);
    assert.throws(() => run(['unlock'], { SECCORE_PASSPHRASE: 'wrong' }));
    assert.match(run(['unlock'], { SECCORE_PASSPHRASE: 'right' }), /unlocked/);
    for (let i = 0; i < 100 && !/node lk fp/.test(out); i++) await wait(50);
    assert.match(out, /node lk fp/);
    let st = ''; for (let i = 0; i < 40; i++){ try { st = run(['status']); if (!st.includes('"locked"')) break; } catch {} await wait(50); }
    assert.match(st, /"name": "lk"/); assert.ok(!st.includes('"locked"'));
  } finally { child.kill(); }
});

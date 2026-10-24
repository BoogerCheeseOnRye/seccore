import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { TaskRunner, validateTasks } from '../tasks.mjs';
import { AuditLog, verifyAudit } from '../audit.mjs';
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));

test('path args are confined to allowed roots (traversal + symlink escape refused)', async () => {
  const root = tmp('sbx-'), work = path.join(root, 'work'), outside = path.join(root, 'secret');
  fs.mkdirSync(work); fs.mkdirSync(outside);
  fs.writeFileSync(path.join(work, 'ok.txt'), 'fine\n'); fs.writeFileSync(path.join(outside, 'key'), 'SECRET');
  fs.symlinkSync(path.join(outside, 'key'), path.join(work, 'link'));
  const r = new TaskRunner({ tasks: { cat: { argv: ['cat', '{f}'], args: { f: '[^\\u0000]{1,200}' }, pathArgs: { f: { roots: [work], type: 'file' } }, cwd: work, peers: ['*'] } } });
  const j = r.submit('p', 'cat', { f: 'ok.txt' });
  assert.equal((await r.wait('p', j.id)).stdout, 'fine\n');
  for (const bad of ['../secret/key', path.join(outside, 'key'), 'link', '/etc/passwd']) assert.throws(() => r.submit('p', 'cat', { f: bad }), /outside the allowed roots/, bad);
  assert.throws(() => r.submit('p', 'cat', { f: 'missing.txt' }), /does not exist/);
  assert.throws(() => r.submit('p', 'cat', { f: '.' }), /must be a file/);
});

test('dedicated cwd enforced; wrapper must be literal and not a shell', () => {
  assert.throws(() => validateTasks({ tasks: { t: { argv: ['ls'], cwd: '/', peers: ['*'] } } }), /cwd "\/"/);
  assert.throws(() => validateTasks({ tasks: { t: { argv: ['ls'], sandbox: { wrapper: ['bash', '-c'] }, peers: ['*'] } } }), /wrapper/);
  assert.throws(() => validateTasks({ tasks: { t: { argv: ['ls'], limits: { memoryMB: -1 }, peers: ['*'] } } }), /bad limit/);
  const r = new TaskRunner({ tasks: { t: { argv: ['ls'], cwd: '/nonexistent-dir-xyz', peers: ['*'] } } });
  assert.throws(() => r.submit('p', 't', {}), /does not exist/);
});

test('resource limits via prlimit when available', { skip: spawnSync('prlimit', ['--version']).status !== 0 && 'prlimit missing' }, async () => {
  const d = tmp('lim-');
  const r = new TaskRunner({ tasks: {
    big: { argv: ['head', '-c', '5000000', '/dev/zero'], limits: { fileSizeMB: 1 }, cwd: d, peers: ['*'], maxOutput: 10_000_000 },
    nofile: { argv: ['cat', '/dev/null'], limits: { nofile: 2 }, cwd: d, peers: ['*'] },
  } });
  const j = r.submit('p', 'nofile', {});
  const res = await r.wait('p', j.id);
  assert.equal(r.jobs.get(j.id).sandbox.limits, 'prlimit');
  assert.notEqual(res.state, 'done');                                 // can't even open the file with nofile=2… (stdio uses 0-2)
});

test('timeout kills the whole process tree', async () => {
  const d = tmp('tree-'), marker = path.join(d, 'm');
  // `timeout` (coreutils) spawns sleep as a child; with process groups both die.
  const r = new TaskRunner({ tasks: { t: { argv: ['timeout', '30', 'sleep', '30'], cwd: d, peers: ['*'], timeoutMs: 200 } } });
  const j = r.submit('p', 't', {});
  const res = await r.wait('p', j.id);
  assert.equal(res.state, 'timeout');
  const ps = spawnSync('pgrep', ['-f', 'sleep 30']).stdout.toString().trim();
  assert.equal(ps, '', 'orphaned children: ' + ps);
  void marker;
});

test('audit log records submit/refuse/end and detects tampering', async () => {
  const d = tmp('aud-'), f = path.join(d, 'audit.log'), key = Buffer.alloc(32, 7);
  const r = new TaskRunner({ tasks: { e: { argv: ['echo', '{w}'], args: { w: '[a-z]+' }, cwd: d, peers: ['box'] } } }, { audit: new AuditLog(f, { key }) });
  const j = r.submit('box', 'e', { w: 'hi' }); await r.wait('box', j.id);
  assert.throws(() => r.submit('phone', 'e', { w: 'hi' }));
  const lines = fs.readFileSync(f, 'utf8').trim().split('\n').map(JSON.parse);
  assert.deepEqual(lines.map((l) => [l.event, l.peer]), [['start', 'box'], ['end', 'box'], ['refused', 'phone']]);
  assert.equal(lines[1].exitCode, 0);
  assert.ok(verifyAudit(f, { key }).ok);
  // continuing after reopen keeps the chain
  new AuditLog(f, { key }).append({ event: 'note' }); assert.ok(verifyAudit(f, { key }).ok);
  const raw = fs.readFileSync(f, 'utf8').split('\n');
  fs.writeFileSync(f, raw[0].replace('"box"', '"evil"') + '\n' + raw.slice(1).join('\n'));
  assert.equal(verifyAudit(f, { key }).reason, 'entry modified');
  fs.writeFileSync(f, raw.slice(1).join('\n'));
  assert.match(verifyAudit(f, { key }).reason, /chain broken/);
  // attacker rebuilding the chain without the key fails the MAC check
  const forged = new AuditLog(path.join(d, 'f.log')); forged.append({ event: 'start', peer: 'evil' });
  assert.equal(verifyAudit(path.join(d, 'f.log'), { key }).reason, 'bad mac');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { TaskRunner, validateTasks, taskHandler, loadTasks } from '../tasks.mjs';

const cfg = {
  maxConcurrent: 1,
  tasks: {
    echo: { argv: ['echo', 'hi', '{word}'], args: { word: '[a-z]{1,10}' }, peers: ['box'] },
    sleep: { argv: ['sleep', '{s}'], args: { s: '[0-9]' }, peers: ['*'], timeoutMs: 300 },
    big: { argv: ['head', '-c', '100000', '/dev/zero'], peers: ['*'], maxOutput: 1000 },
  },
};

test('allowlisted task runs with argv only; result fetched by job id', async () => {
  const r = new TaskRunner(cfg);
  const j = r.submit('box', 'echo', { word: 'there' });
  const res = await r.wait('box', j.id);
  assert.equal(res.state, 'done'); assert.equal(res.stdout, 'hi there\n');
  assert.equal(r.result('box', j.id).stdout, 'hi there\n');
  assert.throws(() => r.status('phone', j.id), /no such job/);       // other peers can't see it
});

test('injection attempts and unauthorized peers are refused', () => {
  const r = new TaskRunner(cfg);
  assert.throws(() => r.submit('box', 'echo', { word: 'x; rm -rf ~' }), /pattern/);
  assert.throws(() => r.submit('box', 'echo', { word: 'abc\nrm' }), /pattern/);   // anchored
  assert.throws(() => r.submit('box', 'echo', { word: 'ok', extra: '1' }), /unexpected arg/);
  assert.throws(() => r.submit('phone', 'echo', { word: 'ok' }), /not permitted/);
  assert.throws(() => r.submit('box', 'nope', {}), /not permitted/);
});

test('shells/interpreters are disabled by default; partial placeholders refused', () => {
  assert.throws(() => validateTasks({ tasks: { s: { argv: ['bash', '-c', 'id'], peers: ['*'] } } }), /interpreter/);
  assert.throws(() => validateTasks({ tasks: { s: { argv: ['/usr/bin/sh', '-c', 'id'], peers: ['*'] } } }), /interpreter/);
  assert.throws(() => validateTasks({ tasks: { s: { argv: ['echo', '--x={v}'], args: { v: '.*' }, peers: ['*'] } } }), /whole argv/);
  assert.throws(() => validateTasks({ tasks: { s: { argv: ['{p}'], peers: ['*'] } } }), /literal/);
  assert.throws(() => validateTasks({ tasks: { s: { argv: ['echo'] } } }), /peers/);
  assert.ok(validateTasks({ allowInterpreters: true, tasks: { s: { argv: ['bash', '-c', 'id'], allowInterpreter: true, peers: ['box'] } } }));
});

test('timeout, cancel, output cap, concurrency cap', async () => {
  const r = new TaskRunner(cfg);
  const a = r.submit('x', 'sleep', { s: '5' });
  assert.throws(() => r.submit('x', 'sleep', { s: '1' }), /busy/);
  assert.equal((await r.wait('x', a.id)).state, 'timeout');
  const b = r.submit('x', 'sleep', { s: '5' });
  r.cancel('x', b.id); assert.equal((await r.wait('x', b.id)).state, 'cancelled');
  const c = r.submit('x', 'big', {});
  const res = await r.wait('x', c.id);
  assert.ok(res.truncated); assert.ok(res.stdout.length <= 1000);
});

test('env is scrubbed', async () => {
  process.env.SECCORE_TEST_SECRET = 'leak';
  const r = new TaskRunner({ tasks: { env: { argv: ['printenv'], peers: ['*'] } } });
  const j = r.submit('p', 'env', {});
  const res = await r.wait('p', j.id);
  assert.ok(!res.stdout.includes('leak')); assert.ok(res.stdout.includes('PATH='));
});

test('handler ops: list, submit/status/result, run', async () => {
  const h = taskHandler(new TaskRunner(cfg));
  assert.deepEqual((await h({ op: 'task.list' }, 'phone')).map((t) => t.name), ['sleep', 'big']);
  const j = await h({ op: 'task.submit', task: 'echo', args: { word: 'yo' } }, 'box');
  await new Promise((r) => setTimeout(r, 200));
  assert.equal((await h({ op: 'task.result', id: j.id }, 'box')).stdout, 'hi yo\n');
  assert.equal((await h({ op: 'task.run', task: 'echo', args: { word: 'z' } }, 'box')).stdout, 'hi z\n');
  await assert.rejects(h({ op: 'rm' }, 'box'), /unsupported/);
});

test('example tasks.json validates', () => {
  const t = loadTasks(new URL('../examples/tasks.json', import.meta.url).pathname);
  assert.deepEqual(Object.keys(t.tasks), ['opencode', 'uptime', 'git-pull']);
});

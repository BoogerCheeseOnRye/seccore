import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
const root = new URL('..', import.meta.url).pathname;

function walk(d, out = []){ for (const e of fs.readdirSync(d, { withFileTypes: true })){ const p = path.join(d, e.name); if (e.isDirectory()) walk(p, out); else out.push(p); } return out; }

test('no native addons in dependencies (Android/Termux safe)', () => {
  const files = walk(path.join(root, 'node_modules'));
  assert.deepEqual(files.filter((f) => f.endsWith('.node') || f.endsWith('binding.gyp')), []);
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json')));
  assert.deepEqual(Object.keys(pkg.dependencies), ['@noble/post-quantum']);
  for (const f of files.filter((f) => f.endsWith('package.json'))){
    const p = JSON.parse(fs.readFileSync(f)); assert.ok(!p.gypfile && !p.scripts?.install && !p.scripts?.postinstall, f);
  }
});

test('only node: builtins + noble imported by our modules; no Math.random', () => {
  for (const f of fs.readdirSync(root).filter((f) => f.endsWith('.mjs'))){
    const src = fs.readFileSync(path.join(root, f), 'utf8');
    for (const m of src.matchAll(/^import .* from '([^']+)'/gm)) assert.ok(/^(node:|\.\/|@noble\/post-quantum)/.test(m[1]), f + ' imports ' + m[1]);
    assert.ok(!/Math\.random\(/.test(src), f);
  }
});

test('termux script exists and is executable', () => {
  const s = fs.statSync(path.join(root, 'scripts/termux-setup.sh'));
  assert.ok(s.mode & 0o100);
});
